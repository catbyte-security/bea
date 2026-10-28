# Architecture

BEA is one TypeScript (ESM, Node ^24.11, the 24.x line only) package with two faces: `bea mcp` runs an MCP server, and every other
`bea` command is a short-lived CLI process that builds the same application, runs one tool or a scenario, and tears
everything down. One contract registry drives MCP registration, the generated CLI, the generated docs and the
contract tests. The authoritative design is the revision-2 BEA v0.1 design; [decisions.md](decisions.md) holds its
decision table.

## Processes

```
 MCP client ──stdio / 127.0.0.1 HTTP──▶ BEA server (node)                       one per client connection
                                        │  application: contracts → handlers → services
                                        │  Frida host (own DeviceManager, lazy import)
                                        │  evidence runtime: ledger, streams, blobs under BEA_HOME\runs\<run>
                                        │
          ┌─────────────────────────────┼───────────────────────────────┬──────────────────────────────┐
          ▼                             ▼                               ▼                              ▼
  owned target (spawned)        attached target                 bea-jobhost.exe helpers        Python emulator bridge
  frida-agent.dll + BEA agent   frida-agent.dll + BEA agent     adopt: owns the kill-on-close   one per emulation session
  inside a kernel Job Object    never killed by BEA             job of an owned target;         (Unicorn + Capstone),
  (killed with its tree at      exit observed by a watcher      watch: exit code of an          stdin/stdout protocol,
  close_session or BEA exit)    helper                          attached target                 self-capped memory
```

- **Server.** One application per server process (stdio or HTTP) and one per CLI command. Stdout is the MCP channel;
  logs and progress go to stderr.
- **Frida host** (`src/providers/frida`). Frida 17.23.2 is imported lazily on first use, with BEA's own
  `DeviceManager`. Spawn: preflight → refusal policy → environment allowlist → `device.spawn` (suspended) →
  `bea-jobhost adopt` → attach → load the agent (QJS runtime) → handshake (`bea-agent/1`, build id) → paused session.
  Attach: refusal policy → `bea-jobhost watch` → attach → load → handshake → running session.
- **Agent** (`src/agent`, compiled by `frida.Compiler` at build time into `dist/agent/bea-agent.js`). One RPC surface
  (40 methods), batched event streams with drop counters and flow control, one exception dispatcher (debug-register
  hits, guard-page traps, oracle-call faults, first-chance exceptions), feature modules for hooks, API profiles,
  watches, Stalker traces, scans, oracle calls, writes, overrides and dumps.
- **Job helper** (`native/jobhost/bea-jobhost.c`, built with gcc into `dist/native/win32-x64/bea-jobhost.exe`).
  Protocol 1 over its stdio. The helper holds the job handle; because the helper is itself tied to the server, the
  target tree dies with the session, the server, or a killed server.
- **Emulator bridge** (`bridge/emu/bea_emu_bridge.py`). One Python process per emulation session, started directly
  (no job helper), speaking `bea-emu/0.1` over stdin/stdout, with a self-applied memory cap; stdin EOF ends it.

## Source layering

```
shared ← domain ← ports ← contracts ← application ← {providers, server, cli} ← main
```

| Layer             | Contents                                                                                                                                                            | Rules                                                                |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| `src/shared`      | host↔agent wire types (`agentProtocol.ts`, call plans, limits, binary layouts)                                                                                      | ES2022 only; no Node types, no zod; also compiled into the agent     |
| `src/domain`      | pure model: results, errors (closed catalog), ids, canonical JSON, evidence records and limitations, address grammar, call model, config, gates, output-path policy | no I/O                                                               |
| `src/ports`       | every cross-package interface (sessions, agent RPC, job host, evidence, PE, address, emulator, recordings, handles, dumps, provisioner)                             | frozen after the scaffold                                            |
| `src/contracts`   | one `defineTool` contract per tool in 12 area files; schemas; effects → MCP hints                                                                                   | strict zod; bounded integers; `maxInputBytes`                        |
| `src/application` | `invokeTool`, handlers per area, services, `sessionAccess`, lifecycle, admission, gate policy, status, doctor registry                                              | sessions only through `sessionAccess.ts`                             |
| `src/providers`   | Frida, process (job host), evidence store, PE reader, emulator bridge client                                                                                        | the only code that touches Frida, child processes or the disk layout |
| `src/server`      | MCP server construction, advertised schemas, result delivery (`_meta` provenance), progress, HTTP transport                                                         |                                                                      |
| `src/cli`         | argv generated from contracts, runners, scenarios, setup, doctor, help                                                                                              |                                                                      |
| `src/main`        | composition roots for stdio, HTTP and the CLI                                                                                                                       |                                                                      |

`scripts/verify-module-boundaries.mjs` enforces the layering and the special rules (no `child_process` outside the
process and emulator providers, no `AbortSignal.any` outside `domain/abort.ts`, no direct Frida process enumeration or
kills outside the Frida provider).

## One tool call

```
MCP tools/call ─┐
CLI command  ───┼─▶ invokeTool(contract)
scenario step ──┘     1. size guard (contract.maxInputBytes, before parsing)
                      2. zod parse (defaults applied; refines give corrective messages)
                      3. "always" gate check (write_memory, override_function, run_script)
                      4. deadline (≤ 120 s) + client cancellation, composed with composeSignal
                      5. admission (per-session FIFO: exclusive for agent RPCs, concurrent for reads)
                      6. handler → sessionAccess (liveOp / emuOp / anySessionOp) → services → ports → providers
                      7. output self-check against the contract's output schema
                 ◀─── result envelope (or the closed error projection)
```

- **Results** are a spread envelope: result fields plus reserved keys `evidence_id`, `predicate_type`,
  `confidence`, `authority`, `coverage`, `limitations`, `instance_id`, `module_map_id`, `observed_at`,
  `perturbation`, `effects_applied`, `redactions`, `next`. Polls carry `evidence_id: null`. MCP text is the compact
  JSON of `structuredContent`; target-bearing results add `_meta.provenance.untrusted_content`.
- **Errors** are `{error:{code, category, message, retryable, remediation, recovery?, details}}` from one closed
  catalog (23 tags → 22 codes, 9 categories; [errors.md](errors.md)).
- **Effects → hints.** Each contract declares effect flags (reads memory, injects, instruments, executes, suspends,
  launches, kills, writes files, …). MCP annotations are derived from them (`readOnlyHint`, `destructiveHint`,
  `idempotentHint`, `openWorldHint`), and `_meta["bea/effects"]` publishes the flags.

## Sessions

| Kind           | States (visible)                        | Created by       |
| -------------- | --------------------------------------- | ---------------- |
| live, owned    | `paused → running → exited → closed`    | `spawn_process`  |
| live, attached | `running → exited \| detached → closed` | `attach_process` |
| emulation      | `ready \| lost → closed`                | `emu_open`       |

Caps: 4 live sessions (3 with captured output), 4 emulation sessions, 16 instruments, 4 debug-register slots and 8
scans per session, 16 queued operations per session. Closed sessions keep a tombstone so `session_status` and
`close_session` stay idempotent.

`close_session`: owned → kill the job first, then drain and finalize; attached → agent shutdown with revert (an
unreverted effect keeps the session in `cleanup_pending` for a retry) → unload → detach; emulation → close the
bridge. Server shutdown runs one lifecycle with four phases (stop admission 50 ms, tear down targets 1300 ms,
finalize evidence 200 ms, release Frida 250 ms) and a hard-exit timer armed at the first trigger.

## Instruments and recordings

Every instrument (`hook_function`, `trace_api`, `watch_memory`, `trace_execution`, `override_function`) produces
exactly one recording whose id (`rec_…`) is the handle. Each live session also has built-in recordings: `exceptions`,
`modules`, and `output` for owned targets with captured output.

- The agent batches events per stream; the host turns batches into ledger stream frames, counts drops, and stores
  rows as NDJSON chunks.
- `RecordingRegistry` keeps lifetimes; per-kind specs (`src/application/instruments/kinds/*`) decode events and
  build bounded summaries; `query_events` runs `summary | rows | group | stats` views over the stored rows.
- Duration clocks of instruments installed on a paused target start at `resume_process`.
- `HandleRegistry` lets scans (`scan_…`) and writes (`fx_…`) share `wait`, `stop_instrumentation` and
  `session_status` with recordings.

## Evidence

Under `BEA_HOME\runs\<run_id>\`: an append-only ledger of records whose ids are SHA-256 content addresses over
canonical JSON (RFC 8785), stream files for recordings, a blob store for large payloads, effect, instance, module-map
and unknown registries, and `exports\` for files tools write. Records carry confidence, authority, coverage,
limitations and perturbation. Quotas (ledger, streams, blobs) are enforced with a lifecycle reserve. `get_evidence`
reads the ledger, `export_evidence` writes a bundle (directory or zip), `import_evidence` verifies and imports one.

## Addresses

One `AddrExpr` string everywhere (runtime VA, module+RVA, export, ordinal, static `module:0xVA[/0xBASE]`, `$main`).
`AddressService` resolves against the session's module map (epoch-tracked through module load events), reads
preferred bases from the PE file on disk, verifies live bytes against the relocated file image (masking BEA's own
patches and Frida's footprint), and renders outputs as `AddressRef` or compact `{va, at, static, func, sym}`.

## Oracle calls and emulation

`call_function`, `emu_call` and `diff_function` share a flattened call model (signature, buffers with
`init_from`, columns, generators, FP environment). The host classifies the call once into a plan; the live leg runs it
through an exact-bits register-file thunk registered as an SEH frame in the target, the emulation leg through the
bridge. `diff_function` resolves the FP environment once, runs the emulation leg first, then the live leg over the
same vector range, compares bit for bit and returns `equivalent-on-tested-inputs | differ | unknown`.

## Build and layout

`npm run build` (serialized on a cross-process build lock) produces:

| Output                                         | From                                                                                                                                   |
| ---------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `dist/**` (host JavaScript)                    | `tsc -p tsconfig.build.json`                                                                                                           |
| `dist/agent/bea-agent.{js,json}`               | `scripts/build-agent.mjs`: stage `src/agent` + `src/shared`, compile with `frida.Compiler`, manifest `bea.agent-build/1` with build id |
| `dist/native/win32-x64/bea-jobhost.{exe,json}` | `scripts/build-native.mjs`: gcc, `-static`, manifest `bea.native-build/1`                                                              |
| `dist/bridge-manifest.json`                    | `scripts/build-bridge.mjs`: bridge and lock file digests                                                                               |
| `dist/skills/**`                               | `scripts/build-skill.mjs`: `skills/` plus generated `metadata.tool_count` and `metadata.bea_version`                                   |

`src/application/distLayout.ts` resolves every runtime artifact relative to the running build's own `dist`, so a
snapshot of `dist` (`scripts/snapshot-dist.mjs`) is self-contained. Generated files (`npm run generate`: per-area
golden catalog slices, `docs/tools/<area>.md`, `docs/errors.md`, the error-contract schema, package metadata) are
committed, and `npm run check` fails on drift.

## Extension points

Area code plugs into shared registries from its own files, so shared files never change: handler tables per area,
recording kinds, handle kinds (scans, writes), limitation sentences per area, `bea_status` contributors and doctor
checks registered by service factories, lifecycle closers. New cross-package interfaces go through the integrator's
change procedure (recorded in [decisions.md](decisions.md)).
