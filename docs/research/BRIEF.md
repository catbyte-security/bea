# BEA: consolidated design brief (draft v0)

> **What this is.** A decision-oriented synthesis for **BEA**, a dynamic-binary-analysis MCP server and CLI
> modeled on REA (`https://github.com/morluto/rea`; local read-only clone `<rea-checkout>`).
> Written 2026-10-28 from the nine research notes in this directory.
>
> **No new experiments were run for this brief.** Every factual statement cites a note as `[key §section]` and
> inherits that note's VERIFIED / BELIEVED label. Statements tagged **[proposal]** are this brief's own design
> synthesis. They are recommendations, not facts, and need review.

**Sources** (all in `<scratch>/bea-research/`; lab artifacts are in the sibling `bea-lab/<key>/` directories)

| Key | File | Covers |
|---|---|---|
| `rea-mcp` | `rea-mcp.md` | REA's MCP layer on SDK 2.3.1: contracts, effects, delivery, errors, sessions, schema budget; SDK probe lab |
| `rea-evidence` | `rea-evidence.md` | REA Evidence and error algebra, ledger, bundles, redaction; proposed BEA evidence model; stream-hash bench |
| `rea-runtime` | `rea-runtime.md` | REA's Frida/GDB/Rizin/LLDB runtime code; Windows Frida lifecycle lab |
| `rea-process` | `rea-process.md` | REA process ownership, Windows Job Objects; `jobhost` helper lab |
| `rea-cli` | `rea-cli.md` | dispatcher, CLI, TOON, setup, doctor, skill, packaging; TOON measurement |
| `rea-testing` | `rea-testing.md` | REA test strategy and harnesses; BEA-shaped Vitest lab; Windows lifecycle hazards |
| `ext-landscape` | `ext-landscape.md` | other dynamic-analysis MCP servers, research papers, gaps, pitfalls |
| `ext-frida` | `ext-frida.md` | Frida 17.23.2 on Windows x64: verified host and agent API |
| `ext-backends` | `ext-backends.md` | Unicorn bridge prototype (`bea-emu/0.1`), speakeasy, Qiling, WinDbg/TTD/x64dbg/GDB/LLDB |

**How to read it.** §0 lists the decisions. §1 covers the REA patterns to mirror, §2 the Frida facts, §3 the
backends, §4 the landscape, §5 the risks and open questions, and §6 the draft tool catalog.

---

## 0. Decisions at a glance

| # | Decision | Recommendation | Basis | Status |
|---|---|---|---|---|
| D1 | Product shape | A separate MCP server and CLI named `bea`, registered next to REA. Agents send static work to REA and runtime work to BEA | REA has no plugin API and no MCP-client mode [ext-landscape §1.3]; REA's dynamic side is thin and almost absent on Windows [rea-runtime §0] | proposal |
| D2 | Stack | TypeScript ESM on Node 24.18; `@modelcontextprotocol/server` + `client` 2.3.1; zod 4.4.3; `frida` 17.23.2 pinned exactly as a **regular** dependency but **imported lazily**; TypeScript 7.0.2; Vitest 5.0.3; oxlint, oxfmt, knip | [rea-mcp §9]; [rea-cli §1.1, §9.1]; [rea-testing §9] | proposal; every component VERIFIED working on this host |
| D3 | Contract-first | One `ToolContract` registry (zod input/output, effects, derived annotations, untrusted flag, validated examples, CLI mapping) drives MCP registration, CLI generation, docs and contract tests | [rea-mcp §2]; [rea-cli §9.3] | adopt (REA pattern, VERIFIED in source) |
| D4 | Surface size | 36 tools in the draft (§6), hard cap 40. Flat strict input schemas with bounded numbers, lean output schemas, and a CI test that pins catalog bytes | REA: 213 tools and about 2.68 MB of output schemas [rea-mcp §3.5]; Gemini rejects 209 tools [ext-landscape §12.4]; glslang's CI budgets [ext-landscape §3.3] | proposal |
| D5 | `readOnlyHint` meaning | Ignore BEA's own ledger and handle state, and reads through an agent that is already injected. Injection is declared on `spawn_process` / `attach_process` | [rea-mcp §1.5, §9.2]; [rea-cli §9.7] | **decision needed** |
| D6 | Errors | Keep REA's wire projection `{code, category, message, retryable, remediation:{action}, recovery?, details?}`. Errors are plain-data tagged unions. `effects_applied` is always projected. A fault inside a called or emulated function is a **result**, not an error | [rea-evidence §2.3, §10.1]; [ext-backends §9.2] | proposal |
| D7 | Evidence | Keep REA's semantics: content-addressed IDs, observed/derived/inferred, authority, limitations, coverage, unknowns, atomic bundles, explicit redaction. Add process-instance identity, a time anchor, Effect records, on-disk streams and a disk ledger with quotas. Deliver a compact result envelope | [rea-evidence §10] | proposal |
| D8 | Long-running work | Pull model: handles, plus `wait` (running out of time is a poll), plus `query_events` cursors. Every instrument is bounded (duration, max hits) and listed in status. Progress only when a token exists. The MCP Tasks extension is optional and later | [ext-landscape §3.3, §8, §12.2]; [rea-mcp §1.8] | proposal |
| D9 | Process ownership (Windows) | One `bea-jobhost.exe` per spawned target, owning an unnamed `KILL_ON_JOB_CLOSE` + `DIE_ON_UNHANDLED_EXCEPTION` job. Sequence: Frida spawn (suspended), adopt, attach, load agent, resume. Attached processes never join a job and cannot be killed by BEA | [rea-process §8; lab F1, P, H] | VERIFIED in lab |
| D10 | Cleanup order | Kill owned targets first (whole shutdown in 2 s). Then revert and detach attached targets. Then disconnect signal handlers and await `DeviceManager.close()` | [rea-testing §0.5]; [rea-runtime §7 #18, §8] | hazards VERIFIED |
| D11 | Agent | One versioned BEA agent in TypeScript, compiled with `frida.Compiler` at build time. Typed `rpc.exports`, a `send({bea:'ready'})` handshake, `logHandler` always set. QJS by default, CModule for per-event work. Raw scripts only behind a gate | [ext-frida §1.6, §1.8, §5]; [rea-runtime §17] | proposal on a VERIFIED basis |
| D12 | Event transport and storage | The agent batches events (binary arrays flushed every 50 ms, or a CModule ring) with explicit dropped counters. The host stores the raw batches as hash-chained chunk files and canonicalizes on query. A stream-manifest Evidence summarizes each stream | [ext-frida §1.9]; [rea-evidence §8, §10.6] | proposal |
| D13 | Emulation | Unicorn 2.1.4 behind a Python `bea-emu/0.1` JSON-lines bridge (`python -I -X utf8`) in a BEA-owned venv. FPCW/MXCSR forced to 0x027F/0x1F80, ISA guard on, batching by default, dump-backed sessions designed in | [ext-backends §0, §8, §9] | prototype VERIFIED |
| D14 | Differential ground truth | The in-process Frida `NativeFunction` call is the bit-exact reference. Unicorn is the tracer and batch engine. A diff can only conclude `equivalent-on-tested-inputs`, `differ` or `unknown` | [ext-backends §2.4 #3, §10 Q4]; [rea-evidence §10.9]; [rea-testing §10] | proposal on a VERIFIED basis |
| D15 | Address model | Every address output carries the runtime VA, module+RVA, the static VA with the source of its base, and the module-map ID. The preferred ImageBase comes from the PE **on disk**. Mapping requires an image-hash match and can verify bytes | [ext-frida §3.14]; [rea-evidence §10.2]; [ext-landscape §13] | formula VERIFIED |
| D16 | Safety posture | Untrusted-content marker on by default. Target writes, overrides and raw scripts require opt-in. `call_function` is allowed on targets BEA spawned and needs opt-in on attached ones. User mode only. No support claims for anti-cheat or protected targets. stdio transport only in v1 | [ext-landscape §1.3, §12.2, §12.4]; [rea-cli §11]; [rea-mcp §10] | proposal |
| D17 | CLI | One `bea` dispatcher with commands generated from contracts, in three tiers: stateless one-shots, `bea run scenario.json`, and HTTP later. TOON output by default, `--json` compact when piped. Exit codes 0/1/130/143/141 | [rea-cli §2, §4, §9.3] | proposal |
| D18 | Setup and doctor | Direct, transactional edits to config files for 5–7 clients, with pinned registrations. A read-only `bea doctor` with a jobhost probe and an opt-in injection probe. `bea mcp doctor` starts the real server | [rea-cli §5, §6, §9.4–9.5]; [rea-process §12] | proposal |
| D19 | Testing | REA's test layering. Three MCP harnesses: in-memory, stdio subprocess, and in-process stdio. A fake DeviceManager with gates. Real-Frida acceptance tests on gcc fixtures with an owned-PID ledger. A Unicorn differential lane. retry 0, named skips | [rea-testing §11] | proposal (lab VERIFIED) |
| D20 | v1 scope | Windows x64 user-mode targets on the local device only. No HTTP, prompts or resources. No WoW64 until it has been tested | [rea-mcp §10]; [rea-runtime §19 Q5]; [ext-backends §2.5] | proposal |

---

## 1. What REA is and the patterns BEA must mirror

### 1.1 REA in one paragraph

REA ("Reverse Engineer Anything") is a TypeScript project of about 400K lines [rea-testing §9.5]. It exposes
the same workflows through an MCP server and a one-shot CLI, and both share application services and zod contracts
[rea-cli §0]. Its recorded catalog has 213 MCP tools, 6 prompts and 160 CLI commands [rea-mcp §3.5]. It runs
locally and is evidence-first. Each successful observation becomes a content-addressed Evidence record that
separates observed, derived and inferred facts, carries limitations and coverage, and links to "residual
unknowns" [rea-evidence §0].

REA is overwhelmingly static, and its dynamic side is thin [rea-runtime §0, §8 #10]:
- Frida is exposed as generic sessions that run caller-written JS: 8 session tools plus the one-shot
  `instrument_with_frida`.
- GDB and Rizin are raw consoles that refuse to start on non-Linux hosts.
- The only structured tracer is the LLDB `observe_native_calls`, and it runs on macOS only.
- pwndbg handles core files only.
- On Windows, the Frida session tools are REA's only live capability. REA's own real-Frida verification lane
  runs only on Linux.

REA has no structured primitive for memory, modules, scanning, hooks, Stalker, watchpoints, oracle calls, dumps,
crashes or ASLR rebasing. Its `staticRuntimeCorrelation` correlates hypotheses between Evidence records; it does not
map addresses. REA's static providers do expose `image_base`, which BEA can use for rebasing [rea-runtime §13, §15].
**Implication:** BEA copies REA's engineering patterns (below) almost wholesale and builds the dynamic primitives
REA lacks.

### 1.2 Layering

```
contracts (zod; MCP + CLI schemas)                      src/contracts/fridaToolContracts.ts
   |
adapters   MCP: src/server/registerFridaTools.ts        CLI: src/cli/fridaCommands.ts
   |
application service (shared workflows, builds Evidence) src/application/frida/FridaInstrumentationService.ts
   |  depends on
port (interface, no frida types, returns Result)        src/application/frida/FridaInstrumentationPort.ts
   |  implemented by
provider (frida handles)                                src/frida/FridaInstrumentationManager.ts
```
[rea-runtime §2]. The MCP server keeps one manager for its whole lifetime. Each CLI command constructs a
disposable manager and awaits `closeAll()` [rea-runtime §2]. Lint enforces the layering: application tests may not
import server/cli/main, and composition tests may not import `child_process`, `net` or `http` [rea-testing §2].

Proposed BEA tree [proposal assembled from rea-process §12, rea-testing §11.1, rea-cli §9, rea-runtime §18,
ext-backends §8]:

```
bea/
  scripts/bea.mjs                  dispatcher: mcp | mcp doctor | CLI                 [rea-cli §2, §9.2]
  src/identity.ts                  PRODUCT_IDENTITY, generated from package.json       [rea-cli §1.3]
  src/contracts/                   ToolContract registry, effects, shared schemas     [rea-mcp §2]
  src/domain/                      Result, errors, evidence, ids, address math        [rea-evidence §10]
  src/application/                 services shared by MCP and CLI                     [rea-runtime §2]
  src/ports/                       DynamicSessionPort, AgentRpc, EmuPort, OwnedTargetPort
  src/frida/                       session manager, agent loader, capture             [rea-runtime §18]
  src/process/                     OwnedTarget (jobhost), BoundedCapture, Deadline, shutdown  [rea-process §12]
  src/emu/                         EmuBridge client for bea-emu/0.1                   [ext-backends §9.13]
  src/evidence/                    disk ledger, blobs, streams, bundles               [rea-evidence §10.7]
  src/server/                      createServer, Delivery, progress, registration     [rea-mcp §9]
  src/cli/                         contract-generated commands, scenario runner       [rea-cli §9.3]
  agent/                           Frida agent (TypeScript, built with frida.Compiler)[ext-frida §1.8]
  bridge/emu/bea_emu_bridge.py     Unicorn bridge, one self-contained file            [ext-backends §8]
  native/jobhost/jobhost.c         Windows Job Object helper (~200 lines C)           [rea-process §8.1]
  skills-src/bea-dynamic-analysis/ authored agent skill                               [rea-cli §9.6]
  tests/                           layering in §1.16
```

### 1.3 Tool contracts as the single source of truth

- **Shape.** `ToolContract {name, title, description, kind, inputSchema, outputSchema, effects, annotations
  (derived), returnsTargetContent (derived), examples}` [rea-mcp §2.1]. Each family array ends with
  `] as const satisfies readonly ToolContract[]`, and `toolContract("name")` returns the literal type, so a
  handler's input is fully typed [rea-mcp §2.3].
- **Registration.** Use the SDK v2 signature
  `server.registerTool(name, {title, description, inputSchema, outputSchema, annotations}, async (input, ctx) => CallToolResult)`.
  The raw-shape overload is deprecated [rea-mcp §1.3]. The SDK converts zod ≥4.2 schemas to JSON Schema draft
  2020-12 [rea-mcp §1.4].
- **Input conventions.**
  - Use `z.strictObject` everywhere; it becomes `additionalProperties:false`.
  - Keep object roots flat, because the Anthropic API rejects a root `anyOf`/`oneOf`/`allOf`.
  - Express mode exclusivity with `.refine(…, "human-readable correction")` plus prose in the description.
  - Give every number explicit bounds. A bare `z.number().int()` advertises ±2^53.

  [rea-mcp §1.4, §2.4, §3.1]
- **Examples** are parsed through the real input schema, so they are always valid [rea-mcp §2.6].
- **Pass-through validation.** `applicationToolRegistrationOptions` replaces `~standard.validate` with a
  pass-through. The handler then emits the canonical `invalid_request` error instead of the SDK's text diagnostic,
  and the advertised schema stays the same [rea-mcp §1.3]. Use this instead of REA's transport rewriting
  (`ErrorEvidenceTransport`, `EvidenceMcpServerCore.ts:288-699`) [rea-mcp §5.4].
- **Contract lint tests from day one** [rea-mcp §2.8]:
  - every tool is audited exactly once;
  - annotations are derived, including the destructive flag;
  - examples parse;
  - schema size and depth stay under budget.

SDK behaviour confirmed by the probe (VERIFIED) [rea-mcp §1.3, §8]:

| Case | Wire result |
|---|---|
| bad arguments | `isError:true`, text `Input validation error: Invalid arguments for tool … : <zod issues>` |
| unknown tool | JSON-RPC error `-32602` (client throws `ProtocolError`) |
| handler throws | `isError:true`, the message as text |
| output schema declared but `structuredContent` missing | `isError:true`, `Output validation error: …` |
| zod `.default(256)` | the default is applied before the handler runs |

Contract sketch (from [rea-mcp §9.3], trimmed):

```ts
export const MEMORY_TOOLS = [{
  ...meta("read_memory"),            // name, title, effects, derived annotations, returnsTargetContent
  description: "Read up to 64 KiB of live process memory. Unreadable pages end the read; check complete and returned_bytes. Bytes are target content.",
  inputSchema: z.strictObject({
    session_id: sessionId,
    address: runtimeAddress,          // z.string().regex(/^0x[0-9a-fA-F]{1,16}$/u)
    size: z.number().int().min(1).max(65536).default(256),
    format: z.enum(["hex", "base64"]).default("hex"),
  }),
  outputSchema: z.strictObject({ /* address, requested_bytes, returned_bytes, complete, data, module, module_offset, evidence_id */ }),
  examples: [{ title: "Read 64 bytes", input: { session_id: "00000000-0000-4000-8000-000000000001", address: "0x7ff6a0001000", size: 64 } }],
}] as const satisfies readonly ToolContract[];
```

### 1.4 Effects audit and derived MCP annotations

**REA.** Each tool has an audited `ToolEffects` record: `mutatesTarget`, `mutatesSession`, `writesFilesystem`,
`launchesProcess`, `accessesNetwork`, `changesUiState`, `mayDiscardData`, `executesForeignCode`, `mutatesDevice` and
`idempotent`. `toolContractMetadata(name)` throws "Missing effect audit" when a tool has no row, and annotations
are only ever derived from the record [rea-mcp §1.5, §2.2]:

```ts
readOnlyHint:    !(mutatesTarget || mutatesSession || writesFilesystem || launchesProcess ||
                   accessesNetwork || changesUiState || mayDiscardData || executesForeignCode || mutatesDevice),
destructiveHint: mayDiscardData || executesForeignCode || mutatesDevice,
idempotentHint:  idempotent,
openWorldHint:   launchesProcess || accessesNetwork,
```

REA counts additive Evidence recording as `mutatesSession`, so almost no REA tool is `readOnlyHint:true`. This is
intentional [rea-mcp §1.5]. Custom `_meta` such as `{"bea/effects": […]}` is echoed verbatim in `tools/list`
(VERIFIED) [rea-mcp §1.5].

**BEA vocabulary** [proposal merging rea-mcp §9.2, rea-cli §9.7, rea-evidence §10.5]:

| Flag | Meaning |
|---|---|
| `readsTargetMemory` | reads target memory, registers or module state through the agent |
| `injectsCode` | loads the BEA agent or a script into the target (footprint: frida-agent.dll plus 24 DLLs [ext-frida §4]) |
| `instrumentsTarget` | reversible observation changes: hooks, debug registers, guard pages, Stalker |
| `writesTargetMemory` | changes target data or code semantics: writes, patches, argument or return overrides |
| `executesTargetCode` | makes target code run: resume, in-process call, raw script |
| `suspendsTarget` | leaves the target paused (spawn) |
| `launchesProcess` | starts a target process. BEA's own helpers (jobhost, emulator bridge) do not count |
| `killsProcess` | terminates a target. Only targets BEA owns |
| `writesFilesystem` | writes caller-visible files (dumps, exports, coverage) |
| `mayDiscardData` | can overwrite existing files |
| `accessesNetwork` | remote Frida devices (deferred) |
| `mutatesSession` | appends to BEA's ledger or creates handles. Almost every tool |
| `idempotent` | repeating the call has no further effect |

```ts
// [proposal] D5: mutatesSession and readsTargetMemory are deliberately NOT in readOnlyHint
readOnlyHint    = !(injectsCode || instrumentsTarget || writesTargetMemory || executesTargetCode ||
                    suspendsTarget || launchesProcess || killsProcess || writesFilesystem || accessesNetwork);
destructiveHint = writesTargetMemory || executesTargetCode || killsProcess || mayDiscardData;
idempotentHint  = idempotent;
openWorldHint   = launchesProcess || accessesNetwork;
```

Rationale for D5:
- The agent is injected once, by `spawn_process` or `attach_process`, and those tools carry `injectsCode`. Later
  reads through the loaded agent inject nothing new.
- CLI one-shots that attach for a single read **do** inject, and their help text must say so [rea-cli §9.7].
- If REA's stricter meaning is preferred, put `mutatesSession` back into the formula. That makes every
  evidence-recording tool non-read-only, which is REA's current behaviour.

### 1.5 Result delivery and the response budget

- **Success.** The same JSON goes in `content[0].text` and in `structuredContent`, with no TOON on MCP. Session-kind
  tools wrap the value as `{result}`, and Evidence tools return the full record [rea-mcp §1.6, §2.1, §4.1].
- **Failure.** `isError:true` with text `{"error":{…}}` and **no** `structuredContent` on the wire, because output
  schemas describe successes only and the SDK skips output validation on `isError` [rea-mcp §1.7].
- **Untrusted content.** Results get
  `_meta: {provenance: {untrusted_content: true, source: "analysis_target"}}`. The marker is on by default (success
  and error) with an allow-list of exceptions. The server `instructions` add a sentence telling the agent to treat
  such content as data [rea-mcp §1.2, §4.6]. For BEA, memory bytes, strings, module names and hooked arguments are
  all attacker-controlled.
- **Response budget.**
  - `STDIO_DEFAULT_MAX_BUFFER_SIZE` = 10,485,760 (VERIFIED); the budget is that minus 1 KiB for the envelope.
  - Success is counted roughly twice (structured plus escaped text).
  - Over budget, the result becomes `resource_constraint` with `details.resource:"transport"`, an
    `evidence_reference` and, where possible, a ready-to-call paging `continuation`. Results are never truncated
    silently [rea-mcp §4.2].
- **Record before deliver.** If the ledger write fails, the tool returns that error instead of the success
  [rea-evidence §2.5, §4].
- **Logging.** Log only the tool name, duration and ok/error, never the caller's input. Logs go to stderr through
  pino, because stdout is the JSON-RPC channel [rea-mcp §2.7, §9.8].

**BEA compact success envelope** [rea-evidence §10.11]. `detail:"complete"` returns the full record, and
delivery-only arguments never enter the Evidence identity [rea-evidence §5.2]:

```json
{
  "evidence_id": "ev_…", "predicate_type": "bea.memory.read", "instance_id": "pi_…",
  "observed_at": { "seq": 412, "effect_epoch": 3, "module_map_epoch": 2 },
  "confidence": "observed", "coverage": { "status": "complete" },
  "truncation": { "truncated": false, "dropped": 0, "reasons": [] },
  "perturbation": { "active_effect_ids": ["fx_…"], "instrumentation": "passive" },
  "effects_applied": [], "result": { "...": "operation-specific" }, "limitations": [],
  "evidence_reference": { "kind": "retained-evidence", "evidence_id": "ev_…" }
}
```

### 1.6 Errors

- `Result<T,E> = {ok:true,value} | {ok:false,error}` with `ok()`/`err()`. There are no map/flatMap helpers; callers
  branch with `if (!r.ok) return r;`. Throws are kept for programmer and schema errors and are wrapped at
  application boundaries [rea-evidence §2.1].
- **REA's errors** are classes extending `AnalysisError`, each with a literal `_tag` from a closed list of 27.
  A table checked at compile time with `satisfies` maps them to 20 wire **codes** in 10 **categories**
  [rea-evidence §2.2, §2.3]; [rea-mcp §5.1]. Projection rules [rea-evidence §2.3]:
  - Unresolved cleanup overrides the code to `cleanup_incomplete`, and `details.execution_failure` keeps the
    original code.
  - Retryable codes include `artifact_changed`, `provider_timeout`, `cancelled`, `revision_conflict` and
    `provider_unavailable`.
  - `recovery` is one of `inspect_input_contract` or `inspect_timeout_state`.
  - A partial observation travels as `details.partial_observation: {kind:"retained-evidence", evidence_id}`.
- **Messages are curated.** No raw provider text appears in `message`. `remediation.action` names a concrete next
  step, for example "Correct the listed fields, then retry. Do not repeat the unchanged call." [rea-evidence §2.4].
- **BEA changes** [rea-evidence §10.1]:
  - Errors are **plain-data** tagged unions, so they cross the Frida RPC boundary unchanged.
  - The wire shape stays exactly REA's, so agents that know REA transfer directly.
  - New recovery kinds: `reattach`, `refresh_module_map` and `revert_effects`.
  - **Effects applied before a failure are always projected** in `details.effects_applied`.
  - `target_exited` is not retryable for the same instance.
- **Outcomes versus errors** [proposal; resolves a conflict between notes]. The emulator bridge treats faults,
  exceptions, exhausted budgets and unhandled imports as **results with a `status`** [ext-backends §9.2], while
  rea-evidence proposes a `CallFaulted` *error* tag for in-process calls [rea-evidence §10.1]. Use the bridge rule
  for both `call_function` and `emu_call`. A fault on given inputs is an observation, and `diff_function` needs to
  compare outcome classes. Errors are reserved for "could not attempt the call".

Draft BEA error codes [proposal reconciling rea-mcp §9.1 and rea-evidence §10.1; the categories are from
rea-evidence §10.1]:

| Code | Category | Retryable | Recovery | Typical cause |
|---|---|---|---|---|
| `invalid_request` | invalid_input | no | inspect_input_contract | schema or refine failure |
| `configuration_invalid` | invalid_input | no | (none) | bad `BEA_*` environment value |
| `session_not_found` | invalid_input | no | (none) | unknown or closed session ID |
| `target_exited` | target_state | no (same instance) | reattach | process ended |
| `instance_mismatch` | target_state | no | reattach | pid reused or restarted (start time differs) |
| `address_unmapped` | target_state | after refresh | refresh_module_map | stale module map, unloaded module |
| `memory_access_failed` | target_state | no | (none) | access violation or protection on read/write |
| `instrumentation_failed` | execution_failure | no | (none) | hook install failed, hook conflict, no free DR slot |
| `effect_unreverted` | target_state | yes | revert_effects | a hook or patch could not be removed |
| `access_denied` | unavailable | no | (none) | elevation needed, protected process |
| `unsupported_target` | unsupported | no | (none) | WoW64, non-PE, unsupported ISA |
| `capability_unavailable` | unavailable | sometimes | (none) | gate off, frida binding failed to load, bridge missing |
| `provider_timeout` | timeout | yes | inspect_timeout_state | agent RPC or bridge deadline |
| `cancelled` | cancelled | yes | (none) | MCP cancellation |
| `resource_constraint` | resource_constraint | capacity: yes | (none) | capacity, transport, disk, events, memory |
| `evidence_integrity_mismatch` | integrity_mismatch | no | (none) | ID recompute mismatch, conflicting record |
| `revision_conflict` | integrity_mismatch | yes | (none) | unknown CAS lost |
| `file_operation_failed` | execution_failure | no | (none) | export or import or blob I/O |
| `cleanup_incomplete` | execution_failure | no | (none) | overrides the code; original kept in `details.execution_failure` |
| `execution_failure` | execution_failure | no | (none) | internal or provider failure |

Wire example:
`{"error":{"code":"target_exited","category":"target_state","message":"…","retryable":false,"remediation":{"action":"Spawn or attach again; this creates a new process instance."},"recovery":{"kind":"reattach","previous_instance_id":"pi_…"},"details":{"effects_applied":["fx_…"],"partial_observation":{"kind":"retained-evidence","evidence_id":"ev_…"}}}}`

### 1.7 Evidence model

**What REA does.**
- **Record.** `{evidence_id, subject, provider, analysis_profile, predicate_type, operation, parameters, raw_result,
  normalized_result, confidence (observed|derived|inferred), authority, environment, limitations[],
  relationship_coverage, locations[], evidence_links[]}` [rea-evidence §3.1].
- **ID.** `ev_` plus the SHA-256 of an RFC 8785 canonical *semantic projection*. Only the subject's name and
  local path are left out. The ID is re-checked on every parse, so tampered records are rejected
  [rea-evidence §3.2].
- **Missing subject.** If there is no subject, a limitation saying so is added, and it enters the ID
  [rea-evidence §3.3].
- **Separate axes.** confidence × authority × limitations × coverage. Absent coverage means unknown, and gaps
  yield truncated or unknown, never equivalence [rea-evidence §3.5].
- **Residual unknowns.** A hash-linked revision chain with `expected_revision` compare-and-swap. A "verified"
  resolution needs supporting evidence that meets the required authority and confidence. Every mutation of an
  unknown produces mutation Evidence [rea-evidence §3.6].
- **Ledger.** Per connection, in memory, idempotent; it rejects a record whose ID matches but whose content
  differs; imports are atomic; **there is no quota** [rea-evidence §4].
- **Bundles.** Canonical and atomically published. `get_evidence_bundle` accepts filters **only** with
  `detail:"summary"` [rea-evidence §5].
- **Redaction.** Explicit literal values only. Declarations are never persisted (only their count), and matching
  fields are dropped whole rather than rewritten with a marker [rea-evidence §7].

**What breaks for dynamic analysis** [rea-evidence §9.2]:
1. Two reads at different times with identical bytes get the same content ID and merge into one record.
2. REA's Frida Evidence has no subject, no start time and no module map, so pid reuse cannot be detected
   [rea-evidence §3.4].
3. There are no Effect records.
4. The unbounded in-memory ledger cannot hold hook streams. Measured: 200k synthetic events ≈ 29 MiB of canonical
   JSONL, about 152 B per event, and about 2.74 µs per event for canonicalization plus SHA-256 [rea-evidence §8].
5. REA's replay snapshots assume determinism, which a live process does not have.

**BEA model** [rea-evidence §10; proposal]:

| ID prefix | Identifies | Identity input |
|---|---|---|
| `ev_` | Evidence | canonical projection *including* the time anchor (`seq`, `effect_epoch`, `module_map_epoch`); wall clock and blob paths excluded |
| `pi_` | process instance | `{device_id, pid, start_time, image{path, sha256, …}}`; `launched_by_bea` governs kill authority |
| `mm_` | module-map epoch | `instance_id` + modules sorted by base; epoch bumps on load/unload |
| `fx_` | Effect | `{instance_id, seq, kind, target, params}`; lifecycle `active → reverted / revert-failed / implicit-end` |
| `st_` | event stream | allocation scheme open |
| `unk_` | residual unknown | question, domain, scope = image sha256 (survives restarts) |
| `query_` | replay cache, **emulation and static only** | image sha256, function RVA, initial-state digest, emulator version, hooks digest |

Key rules [rea-evidence §10.2–10.9]:
- **Authority** is one of `live-process`, `emulation`, `static-artifact`, `imported` or `analyst-inference`.
- **Perturbation.** Every record carries `perturbation.active_effect_ids`, so a reader can tell "observed while hook
  fx_… was rewriting arg 2" apart from an unperturbed observation. An irreversible effect (function called, process
  killed, write without a before-blob) taints the instance with a fixed limitation.
- **Blobs.** Large binary data (dumps, coverage files) lives in content-addressed blobs. Blob digests enter the ID;
  blob paths do not.
- **Streams.** Hook, Stalker, watchpoint and exception events go to hash-chained chunk files on disk. A
  **stream-manifest Evidence** records counts, dropped events and reasons, chunk digests, the head digest and the
  end reason. Coverage is `complete` only if nothing was dropped and the stream ended normally. Queries and
  aggregations produce derived Evidence that links to the manifest.
- **Storage.** An append-only ledger in `%LOCALAPPDATA%/bea/sessions/<session_id>/` (`ledger.jsonl`, `blobs/`,
  `streams/`) with an in-memory index and quotas. Hitting a quota gives `resource_constraint{resource:"disk"}`,
  which is retryable after export or prune.
- **Bundles** are a directory or zip containing a manifest, `records.jsonl`, blobs and streams. Export and import
  are atomic, and the manifest is recomputed and compared on import.
- **Differential Evidence.** `bea.call.oracle` (live), `bea.emu.run` (emulation; stubbed imports are limitations
  and make coverage partial) and a derived `bea.diff` whose verdict is only `equivalent-on-tested-inputs`, `differ`
  or `unknown`.

Synthesis points [proposal]:
- **Where `start_time` comes from.**
  - Owned targets: jobhost reports `creationTime100ns` from `GetProcessTimes` [rea-process §8.1].
  - Attached targets: Frida `enumerateProcesses({scope:'metadata', pids:[pid]})` returns `started` as an ISO
    string [ext-frida §1.3]. Its precision is unverified.
  - This partly answers rea-evidence open question 1.
- **Stream throughput mismatch.** The agent can deliver 1.0–1.2M events/s in batches [ext-frida §1.9], but
  per-event canonical JSON plus hashing on the host costs about 2.74 µs, roughly 365k events/s [rea-evidence §8].
  So store **raw binary batches** as hash-chained chunks with a schema descriptor, and canonicalize only when a
  query reads them.
- **REA interop.** Projecting BEA records into REA's strict schema (BEA fields carried in
  `normalized_result`/`parameters`) looks possible but is untested [rea-evidence §13 Q6]. Until then, ledgers that
  cite both tools prefix IDs `rea:` and `bea:`, as frida-mobile-mcp does [ext-landscape §1.3].

### 1.8 Sessions and lifecycle

REA's manager mechanics to copy [rea-runtime §4; rea-mcp §6]:
- **IDs and capacity.** Sessions are keyed by UUID and capped. GDB allows 8 sessions and 16 pending commands, and
  each refusal says what to do next and states "This release has no runtime override." [rea-mcp §6.2].
- **Admission gate.** An operation registry (`#withOperation`) refuses new work once closing and re-checks the abort
  signal at dispatch [rea-runtime §4.2].
- **Per-session lock.** A promise-chain mutex serializes all mutating work per session, and concurrent closes are
  deduplicated [rea-runtime §4.2, §4.9].
- **Subscribe, then reconcile.** Connect `session.detached` first, then check `session.isDetached()`, so an early
  detach is not lost [rea-runtime §4.4].
- **Partial startups.** A `PendingStartupCleanup` record keeps every acquired handle until it is released. The
  primary error stays primary, and the cleanup failure goes in `cleanup.reason` [rea-runtime §4.4].
- **Script states.** `active → cleanup-pending → released`. A failed unload keeps ownership, and resume is refused
  while cleanup is pending [rea-runtime §4.6, §4.7].
- **Capture before load.** The capture buffer and message handler exist before `load()`, and messages emitted during
  load come back inline [rea-runtime §4.5].
- **Bounded capture.**
  - A 16 MiB session budget with oldest-first eviction.
  - Caps per field, 250k JSON nodes, depth 64, cycle detection.
  - Named truncation reasons, and a limitation only when data was actually dropped.
  - Look-alike flags inside caller payloads are never trusted.

  [rea-runtime §5]
- **closeAll.** Memoized and retryable: it drains admitted operations, then pending startups, then sessions, and it
  resets its memo on failure [rea-runtime §4.10].
- **Server wiring.** Cleanup runs from `server.server.onclose` **and** from an overridden `server.close()`
  [rea-mcp §6.4].
- **Process triggers.** SIGINT, SIGTERM, and stdin `end`/`close`. Exit codes are 130 and 143 [rea-mcp §6.5].
  `OwnedMcpServers` tracks every instance, because `serveStdio`'s factory may be called more than once
  [rea-mcp §1.10].

What BEA must add (each a VERIFIED hazard):
1. **Set `script.logHandler` right after `createScript`.** By default agent `console.log` prints to host stdout,
   which would corrupt a stdio MCP stream [rea-runtime §7 #6, §8.1]; [ext-frida §1.6].
2. **Use a ready handshake.** `load()` resolves even when the agent throws at top level, and any `type:'error'`
   message during load must fail the load [rea-runtime §4.5]; [ext-frida §1.6].
3. **Record the detach `reason`.** On Windows `crash` is always null and `processCrashed` never fires, so crash
   details have to come from the agent [ext-frida §1.5].
4. **Disconnect every signal handler and `await DeviceManager.close()`.** Otherwise Node does not exit
   [rea-runtime §7 #18].
5. **Track owned versus attached targets.** `device.kill` kills only the root process and returns before the process
   is gone [rea-process §7 F2]; [rea-runtime §7 #15]. Owned targets are killed through jobhost.
6. **Kill first, within 2 s.** The SDK's `StdioClientTransport.close()` ends stdin, waits 2 s, then sends SIGTERM,
   which on Windows is `TerminateProcess`, so no JS runs. With an unload → detach → kill order, 6 of 6 targets
   leaked; with kill first, close took 20 ms and nothing leaked [rea-testing §0.5].
7. **Have a hard-kill backstop.** A Frida-spawned target is a direct child of the server and survives `taskkill /F`
   of the server [rea-testing §0.5]. jobhost's job-handle chain kills the whole tree when the server's parent is
   killed [rea-process §7 H].

Proposed shutdown order [proposal derived from points 4–7 above]:
1. Stop admitting work, abort in-flight operations (signals), and drain them.
2. Owned targets: send `kill` on jobhost's control pipe or end its stdin. The tree is gone in about 105 ms
   [rea-process §7 G1, G3].
3. Attached targets: revert effects (unhook, disarm debug registers), unload the agent, and detach.
4. Finalize stream manifests and flush the ledger.
5. Disconnect every signal handler, then `await DeviceManager.close()`.
6. Stop the emulator bridge: send `bridge.shutdown`, or let stdin EOF make it exit [ext-backends §9.1].

Assert that the whole sequence takes under 2 s [rea-testing §11.4].

Capacity [proposal]:
- At most 4 live sessions, matching glslang/windbg-mcp [ext-landscape §3.3] and frida-mobile-mcp's `maxSessions=4`
  [ext-landscape §1.3].
- At most 3 concurrently spawned `stdio:'pipe'` targets, because of the anomaly that starts at the 4th
  [rea-testing §0.6].
- At most 16 queued commands per session (REA's GDB cap) [rea-mcp §6.2].

### 1.9 Progress, cancellation and long-running work

- **Progress.** Send it only when `ctx.mcpReq._meta?.progressToken` exists. `progress` is a strictly increasing
  sequence, the phase goes in `message`, no `total` is invented, updates are rate-limited to 100 ms, and terminal
  updates are always sent [rea-mcp §1.8].
- **Cancellation.** `ctx.mcpReq.signal` fires with the client's reason (VERIFIED) [rea-mcp §1.9].
  - Check the signal at dispatch and after every await; the first observed failure stays primary.
  - On cancel, close what you created and return partial Evidence with explicit `instrumentation_cleanup` and
    `target_liveness_after_cleanup` fields [rea-runtime §6].
  - After a cancellation the SDK suppresses the reply, so the partial Evidence must be findable later through the
    ledger [rea-mcp §1.9].
  - Frida native calls accept a `frida.Cancellable`. REA never passes one; BEA should [rea-runtime §6];
    [ext-frida §1.7].
- **Async protocol** (glslang/windbg-mcp) [ext-landscape §3.3, §12.2]:
  - `start_*`-style tools return a handle immediately.
  - A `wait` that runs out of time is a poll, not a failure.
  - "A stop is read, not taken": it can be re-read.
  - Stop reasons are an enum.
  - Every run has a `max_run` cap, and runs can be cancelled.
- **Lifetimes.** Undo's experience is that persistent breakpoints confuse LLMs. So every BEA instrument has
  `duration_ms` and `max_hits` bounds and appears in `session_status` [ext-landscape §8, §12.4].
- **MCP Tasks** (`io.modelcontextprotocol/tasks`) became an extension in spec 2026-07-28 and client support varies.
  Design so that polling works without it [ext-landscape §12.4].

### 1.10 Large results and paging

- `detail: complete|summary`. A summary keeps the complete Evidence in the ledger and returns a derived summary
  whose `parent_evidence_id` points at it [rea-mcp §4.4]. Filters are valid only with a summary [rea-evidence §5.2].
- Paging uses `offset`/`limit` → `next_offset` (`number | null`), plus `total`. Descriptions say "exhausting pages
  does not prove absence" [rea-mcp §4.5].
- Return the count first and the results by handle. Scans return only `{scan_id, count}`; PyMemoryEditor describes
  a 40,000-hit first scan as costing "only a few tokens" [ext-landscape §7.1, §7.3]. Lists return counts next to
  the page, so a page cannot be mistaken for the full table [ext-landscape §3.3].
- Bulk data (dumps, traces, drcov) always goes to files with `{path, bytes, sha256}` and a bounded inline preview
  [rea-cli §9.3].

### 1.11 Context budget

- **REA's catalog** (VERIFIED from `dist/mcp-catalog*.json`):
  - 213 tools;
  - 112,581 description characters;
  - input schemas: 102,256 B compact, 754,974 B full;
  - **output schemas: 2,675,441 B**;
  - the largest single description is 12,210 characters (`inspect_analysis_view`).

  REA mitigates this with a compact input profile (13 KiB per-schema cap, refs inlined, depth ≤ 10, annotations
  stripped), opt-in omission of output schemas, and a recorded catalog [rea-mcp §3.3–3.6, §7].
- **Why the limits matter.**
  - Moonshot/Kimi reject any single tool schema above about 13.7–15 KB.
  - Gemini rejects `dependentRequired`.
  - Strict clients reject a depth above 10 [rea-mcp §3.1].
  - Gemini rejects 209 tools, and clients cap at about 90–100 [ext-landscape §12.4].
- **Precedents.**
  - glslang/windbg-mcp:
    - CI ceilings (model-visible, wire, worst tool) against a golden `tool_budget.json`;
    - removing prose from `outputSchema` shrank the wire size from 391 KB to 178 KB;
    - `structuredContent` ≤ 20× the text rendering;
    - vector registers are trimmed by default.

    [ext-landscape §3.3]
  - frida-mobile-mcp's core+compact profile is 17% of its full `tools/list` [ext-landscape §1.3].
- **BEA plan** [proposal]:
  - Keep schemas small. REA's Frida tools already have inputs of 370–1,343 B [rea-mcp §3.5].
  - Strip descriptions from output schemas.
  - Add a contract test that fails above a golden total and on any schema deeper than 10.
  - Skip the compact profile and the recorded catalog until the measurements say they are needed [rea-mcp §10].

### 1.12 CLI and MCP parity

- **Dispatcher.** `scripts/rea.mjs` sends `mcp`, `mcp --http` and `mcp doctor` to the MCP runtime *before* it loads
  the CLI framework; everything else goes to Incur 0.6.1 [rea-cli §2]. Details worth keeping:
  - an actionable message when the compiled runtime is missing;
  - deleting an empty `USERPROFILE` (a Windows quirk);
  - exit code 141 when the stdout reader closes early;
  - an invalid log level blocks every command except doctor.
- **Naming.** CLI kebab-case maps to MCP snake_case. Exceptions go in an alias table, and an MCP-only list holds
  every stateful session tool. A test checks that every tool is either reachable from the CLI or listed as
  MCP-only [rea-cli §3.2].
- **Stateful work in REA's CLI** is done as one-shot commands (`instrument-with-frida`) or declarative scenario
  files validated with the **same** zod schema as the MCP tool. Progress goes to stderr as JSON lines
  [rea-cli §3.1, §3.2].
- **BEA's three tiers** [rea-cli §9.3]:
  1. Stateless one-shots: attach → do → detach inside one process.
  2. `bea run scenario.json`: a list of MCP tool calls against an implicit session, producing one Evidence bundle.
  3. Later: `bea mcp --http` plus a thin `bea call` client.

  Generate the CLI from the contracts instead of maintaining REA's roughly 50 hand-written command files
  [rea-cli §10].
- **Output.**
  - TOON is the default. Measured with tokenx estimates: 40 modules 1215 → 862 tokens (−29%); 50 hook hits
    1869 → 935 (−50%) [rea-cli §4.2]. Addresses as `0x` strings, numbers as numbers.
  - Exit codes: 0 completed (possibly partial), 1 failed, 130/143 after cleanup, 141 closed pipe
    [rea-cli §4.4].

Scenario sketch (from [rea-cli §9.3]):

```json
{ "target": { "mode": "spawn", "program": "C:/lab/demo.exe", "argv": [] },
  "steps": [
    { "tool": "hook_function", "input": { "address": "demo.exe+0x1450", "capture": { "args": ["rcx","rdx","xmm0:f32"], "ret": "rax" } } },
    { "tool": "resume" },
    { "tool": "wait", "input": { "hook_hits": 100, "timeout_ms": 10000 } },
    { "tool": "read_memory", "input": { "address": "demo.exe+0x8000", "size": 64 } } ],
  "teardown": { "kill_spawned": true } }
```

### 1.13 Setup and doctor

- **Edit client config files directly.** REA never shells out to `claude mcp add` or `add-mcp` [rea-cli §5]. The
  transaction is:
  1. format-aware parse that keeps comments (strict JSON for `~/.claude.json`, `jsonc-parser` for JSONC, a
     targeted TOML table edit);
  2. a plan showing the exact path, operation and backup path;
  3. explicit approval;
  4. a one-time `<file>.bea.backup`;
  5. a temp file in the same directory (O_EXCL), then fsync, then rename (update) or link (create);
  6. read back and verify, rolling back on failure.

  Existing entries are classified owned, foreign or unknown. The ambient environment is never copied into a
  registration [rea-cli §5.4, §5.5, §9.4].
- **Clients for v1** [rea-cli §9.4]:
  - Claude Code: `mcpServers.bea` in `~/.claude.json`, honouring `CLAUDE_CONFIG_DIR`.
  - Codex: `[mcp_servers.bea]` in `~/.codex/config.toml` with `startup_timeout_sec = 30` and
    `tool_timeout_sec` = longest BEA blocking time + 120 s.
  - Cursor: `~/.cursor/mcp.json`.
  - Gemini CLI: `~/.gemini/settings.json`.
  - VS Code: `%APPDATA%/Code/User/mcp.json`, `servers.bea` with `type:"stdio"`.
  - Claude Desktop: `%APPDATA%/Claude/claude_desktop_config.json` (quit the app first).
  - Windsurf.
- **Registered command, pinned to the exact version.**
  - Via npx: `["cmd.exe","/d","/c","npx","-y","<pkg>@<ver>","mcp"]` on win32.
  - From a global install: `[node.exe, "<abs>/scripts/bea.mjs", "mcp"]`. This route is recommended on Windows for
    startup speed [rea-cli §5.5, §9.4].
- **`bea doctor`** is read-only and scoped by `--client`, `--skill`, `--backend` and `--target`. Its report shape
  copies REA's (`healthy`, `environment_healthy`, `scope_checks`, `informational_checks`, `identity`)
  [rea-cli §6.1, §9.5]. Checks:
  - Node version;
  - config;
  - `frida:binding` and `frida:local-device`;
  - an opt-in `--probe` that injects only into a child BEA spawned itself;
  - `bea-jobhost probe`: report containment only if a real job was created, assigned and terminated
    [rea-process §12];
  - Python with unicorn/capstone;
  - registrations and skill identity.
- **`bea mcp doctor`** starts the real stdio server through the SDK `StdioClientTransport`. It has a 30 s deadline
  and keeps up to 64 KiB of stderr. It runs `initialize` → `tools/list` → an inventory diff against the contracts →
  one call that needs no target → close [rea-cli §6.2, §9.5].

### 1.14 Agent skill

REA ships `reverse-engineer-anything` (SKILL.md of 403 lines plus 6 on-demand references). Its frontmatter
`description` says both when to use it and when to skip it. Its rules [rea-cli §7]:
- connect only when needed, with a recovery ladder;
- route by target first;
- ask for the summary before the full result;
- keep observations, inferences and unknowns separate and cite Evidence IDs;
- for broad work, keep a checklist and a finding ledger.

The build injects `tool_count` and pins `<pkg>@latest` to `<pkg>@<version>`. The ownership marker is the
frontmatter `name:` line [rea-cli §5.7].

BEA skill `bea-dynamic-analysis` [rea-cli §9.6]:
- **When to use it.** Runtime claims only. Static questions go to REA or Ghidra.
- **Safety rules, fail-closed.** Act only on a process the user named or BEA spawned. Confirm pid ↔ image path ↔
  SHA-256 before attaching. No system, security or anti-cheat targets. State a mutation before making it.
- **Routing table.**
  - "What does f(x) return?" → `call_function` / `emu_call`.
  - "Who writes this address?" → `watch_memory`.
  - "Which code runs during X?" → `trace_execution`.
  - "Where is value V?" → the scan tools.
  - "Is my Ghidra address right?" → `map_address`, then `disassemble`.
- **Investigation loop.**
  1. Anchor on a static address.
  2. Rebase it and **verify the bytes**.
  3. Observe within a bounded window.
  4. Form a hypothesis.
  5. Test it with an oracle call or emulation.
  6. Run a differential.
  7. Record the result in a function ledger.

Carry workflows such as the Cheat-Engine "walk-back" recipe (watch writes → analyse the accessing instruction →
struct base → pointer scan → validate chains) as skill references rather than as more tools [ext-landscape §7.1,
§12.2].

The user's existing harnesses use an `Emu` object with `alloc()` and `call(addr, ints, floats)` under the Win64
ABI, plus a function-ledger TSV, so BEA's `emu_call` contract and its ledger guidance should map onto that 1:1
[rea-cli §9.6]; [ext-backends §3].

### 1.15 Process supervision on Windows

REA owns Windows children through a Node-API addon (`rea-windows-x64.node`, about 880 KB) that uses unnamed Job
Objects with `KILL_ON_JOB_CLOSE`, no breakaway, assignment while suspended via `PROC_THREAD_ATTRIBUTE_JOB_LIST`, and
an `IsProcessInJob` check before resuming. REA's Frida spawns bypass all of this and are never killed
[rea-process §0, §2, §5].

Lab results (VERIFIED) [rea-process §7]:

| Case | Mechanism | Result |
|---|---|---|
| A | Node `spawn` (not detached), parent exits | only the direct child dies |
| B | Node `spawn` with `detached:true`, parent exits | everything survives |
| E | `taskkill /T /F`, tree intact | about 97 ms |
| F | `taskkill /T /F` after the root exited | **fails with exit 128 and leaks the rest of the tree** |
| C, D, G1–G3, H | jobhost | kills **everything** in about 105 ms (orphaned, `DETACHED_PROCESS`, breakaway-attempting), whether triggered by a `kill` line, by stdin EOF, by the helper being terminated, or by the parent Node being `TerminateProcess`ed |
| I | jobhost with `DIE_ON_UNHANDLED_EXCEPTION`, target crashes | exit code `0xC0000005` in about 250 ms, no WER dialog hang |
| F1, P | Frida spawn → `jobhost adopt <pid>` → resume | full containment; output arrives via `device.output`, exit code via jobhost |
| S | `jobhost run --suspended`, then Frida attach | works |
| (helper bug) | CRT `fgets` in a helper thread plus CRT `exit()` | **deadlocks**; use raw `ReadFile` and `ExitProcess` |

Helper contract [rea-process §8.1]:

```
bea-jobhost.exe run [--suspended] [--keep-tree] [--mem-limit BYTES] -- <exe> [args...]
bea-jobhost.exe adopt <pid> [--expect-creation-time <100ns>]
bea-jobhost.exe probe
fd0 control: "resume" | "kill" ; EOF => kill tree     fd1/fd2: target stdout/stderr pass-through
fd3 status NDJSON: hello | started{pid,creationTime100ns} | adopted{wasInJob} | resumed | root-exit{code,activeAfterRoot}
                   | killed | memory-limit | settled{active:0} | error{stage,win32}
exit code: the root's code (an NTSTATUS for crashes), or 0xBEA when BEA terminated the job
```

Build flags: MinGW `-D_WIN32_WINNT=0x0A00 -municode` (without them `PROC_THREAD_ATTRIBUTE_JOB_LIST` is undeclared)
[rea-process §7].

Node side [rea-process §8.2]:
- Spawn the helper **not detached** with stdio `['pipe','pipe','pipe','pipe']`.
- Separate `exit` (the root's lifetime) from `close` (the job has settled and the pipes hit EOF, so the output is
  complete).
- Capture output head+tail, always drain it, report observed versus retained bytes, and treat truncation as
  evidence rather than failure.
- Compose one absolute deadline with the caller's signal.

Evidence fields per process: `ownership`, `pid`, `creationTime100ns`, `containment{kind, breakawayAllowed:false,
killOnClose, assignedBeforeFirstInstruction, crashSafe}`, `termination{reason, method, activeBefore, settled}` and
`exit{code, codeHex, kind}`, plus a limitation that brokered launches (COM, WMI, Steam relaunch, UAC) escape the job
[rea-process §10].

Linux and macOS come later: a subreaper helper on Linux, and on macOS a process-group kill reported as best-effort
[rea-process §9].

### 1.16 Testing

Philosophy, copied as written [rea-testing §0, §3]:
- Prefer real public CLI/MCP workflows, then production-boundary integration, then goldens from real producers.
- A missing engine is a **named skip** (`it.skipIf(reason)`), never a silent `if (!available) return`.
- `retry: 0`.
- Synchronize on markers, gates or `client.ping()`. Fixed sleeps are not synchronization.

Harnesses (VERIFIED in REA's source; the BEA version passed in the lab):
1. **In-memory:** `InMemoryTransport.createLinkedPair()` against the production `createServer()` plus a Vitest
   fixture that closes in `finally` [rea-testing §4.1].
2. **Real stdio subprocess:** `StdioClientTransport(process.execPath, [entry,'mcp'])` with a minimal env (plus
   `SystemRoot`, `TEMP`, `TMP` on Windows), Ajv2020 meta-schema validation of every advertised schema, and per-call
   output validation via `toolDefinition` [rea-testing §4.2].
3. **In-process stdio:** `serveStdio(factory, {transport: new StdioServerTransport(stdin, stdout)})` over
   `PassThrough`, for shutdown tests, with `registerShutdown`, `setExitCode` and `writeStderr` injected
   [rea-testing §4.4].
4. **Fake Frida:** a fake `DeviceManager` injected through the manager's constructor, with `gate()` barriers to pin
   interleavings, as in REA's `fridaLifecycleMcp.test.ts` [rea-testing §6].
5. **BEA addition:** an owned-target PID ledger (pid plus creation time) with a leak assertion after close
   [rea-testing §11.3].

The BEA lab (VERIFIED) passed 7 tests in about 7 s on 3 stable reruns with 0 leaks [rea-testing §10]. They
covered:
- runtime export address = module base + the static RVA from the PE;
- in-process `NativeFunction` oracle calls;
- **Unicorn emulation matching the in-process call bit-for-bit**;
- cancellation reaching `ctx.mcpReq.signal`;
- target exit observed as a detach;
- stdin-EOF cleanup.

Measured in the same lab: connect 140 ms, first Frida spawn+attach+load+resume 680–720 ms, later spawns 16 ms,
RPC about 1 ms, kill-first close 20 ms [rea-testing §10].

Fixtures [rea-testing §11.2]:
- C sources selected by an argv mode (`serve`, `hold`, `exit`, `crash`, `threads`, `dll-load`) with `READY pid=`
  markers.
- Exports with exactly recomputable semantics: pure int/float functions, a single-writer global, a marker string,
  a pointer chain.
- gcc `-O0 -g -fno-inline -fno-omit-frame-pointer -Wl,--no-insert-timestamp`, which is **byte-reproducible**
  (VERIFIED).
- A manifest holding expectations parsed from the PE itself: export RVAs, imageBase, the RVA of the single writer.
- **MSVC cannot be used on this host**: there is no `vcvarsall.bat` and no Windows SDK. MSVC is a named-skip lane
  [rea-testing §0.7].

Lanes [rea-testing §11.6]:

| Lane | Contents |
|---|---|
| `check` | `tsc --noEmit`, oxlint, `oxfmt --check`, knip, `verify:test-discovery` |
| `test:fast` | fake-Frida MCP boundary tests |
| `test:acceptance` | real Frida + gcc fixtures, serial |
| `verify:frida:windows` | JSON receipt; CLI and MCP runs give the same pointer-free projection |
| `verify:emulation` | Unicorn versus in-process, bit-exact |

Copy from REA: the tsconfig pair (strict, `exactOptionalPropertyTypes`, `noUncheckedIndexedAccess`, NodeNext,
`verbatimModuleSyntax`), `.oxlintrc.json`, oxfmt, knip with all rules set to error, husky + lint-staged, and test
ownership through `test-projects.mjs` [rea-testing §9]. Defer Turbo, tsrs, Stryker, jscpd and sharding
[rea-testing §11.7].

---

## 2. Verified Frida 17.23.2 facts (Windows 11 x64)

Unless marked otherwise, everything below was VERIFIED in the ext-frida lab:
- binding: frida-node 17.23.2, used read-only from REA's `node_modules`;
- fixtures: gcc 16.1, DWARF only, no PDB;
- both QJS and V8 were tested [ext-frida intro].

Rows marked **other lab** come from rea-runtime, rea-process or rea-testing (also on this host and binding).
**UNVERIFIED** rows must not be relied on without a lab. frida-mobile-mcp already tracks `^17.24.3`
[ext-landscape §1.3], so BEA pins 17.23.2 *exactly* and re-runs the lab suite before any upgrade [proposal].

### 2.1 Host API

| Topic | Facts | Source |
|---|---|---|
| Import | ESM. `const m = await import("frida"); const frida = m.default ?? m;`. The default export has 160 keys, and named exports also exist | [ext-frida §1.1] |
| Types | `build/src/frida.d.ts` re-exports `frida_binding.d.ts`. Line ranges: Device 182–241, Session 516–531, Script 535–559, Compiler 710–725, SessionOptions 922–931, SpawnOptions 1984–1992, Message 2001–2020 | [ext-frida §1.1] |
| Devices | The first `enumerateDevices()` takes 556 ms and returns `local`, `socket` and `barebone`. `getLocalDevice()` takes 0.2 ms after init. `querySystemParameters()` → `{arch:'x64', platform:'windows', os:{id:'windows', version:'10.0.26200'}, access:'full'}` | [ext-frida §1.2] |
| Processes | `enumerateProcesses({scope, pids})`, measured over 183 processes: `minimal` 1.9 ms; `metadata` 33.7 ms (adds `path, user, argv, ppid` (**BigInt**) and `started` (ISO string)); `full` 531 ms (adds icons). `getProcess(glob)` throws "Ambiguous name" when several match | [ext-frida §1.3] |
| Spawn | `device.spawn(programOrArgv, {argv, env, envp, cwd, stdio, …aux})`. An array argument is the whole argv with `[0]` as the program. `env` *merges*; `envp` *replaces*. Spawn takes 6.5 ms and resume 0.2 ms | [ext-frida §1.4] |
| argv | `argv:[program, ...argv]` round-trips spaces and embedded quotes | other lab [rea-runtime §7 #2] |
| stdio | `stdio:'pipe'` delivers output through `device.output.connect((pid, fd, data) => …)`, where a zero-length Buffer means EOF. `device.input(pid, buf)` writes to stdin. The default `inherit` produces no output events | [ext-frida §1.4] |
| Early instrumentation | spawn → attach → `createScript`/`load` → resume. At that point the main thread is at `ntdll!RtlUserThreadStart`, `main` has not run, 29 modules are loaded, and the first call of a hooked function is caught | [ext-frida §1.4] |
| Attach | The first attach in a host process takes about 90 ms; later attaches take 10–12 ms | [ext-frida §1.5] |
| Detach and crash | `session.detached(reason, crash)`. A detach gives `application-requested`. Kill, normal exit and crash all give `process-terminated`. **`crash` is always null and `device.processCrashed` never fired** | [ext-frida §1.5] |
| SessionOptions | Accepted: `realm:'native'`, `exceptor:'full'` or `'handler-only'`, `persistTimeout`, `exitMonitor:false`, `threadSuspendMonitor:false`, `unwindBroker:false`. `realm:'emulated'` → "not supported on this OS". **`exceptor:'off'` makes any agent fault kill the target** | [ext-frida §1.5] |
| Scripts | `session.createScript(src, {name, runtime:'qjs' or 'v8'})`. QJS is the default. Create+load: QJS 1.2+0.9 ms, V8 8.7+3 ms. A syntax error rejects `createScript` | [ext-frida §1.6] |
| load() | **Resolves even if the top-level code throws.** The throw arrives as a `{type:'error', description, stack, fileName, lineNumber, columnNumber}` message | [ext-frida §1.6]; other lab [rea-runtime §7 #8] |
| Logs | Agent `console.*` goes to `script.logHandler(level, text)` with levels `info`, `warning` and `error`, never to `message`. **The default handler prints to host stdout** | [ext-frida §1.6]; other lab [rea-runtime §7 #6] |
| Messages | `send(obj, ArrayBuffer)` arrives on the host as `(message, data:Buffer)`. `script.post(obj, Buffer)` arrives in the agent as `recv('type', (msg, data) => …)` | [ext-frida §1.6] |
| Bytecode and snapshots | QJS supports `compileScript` + `createScriptFromBytes`. V8 supports `snapshotScript`. `eternalize()` works | [ext-frida §1.6] |
| Destroy | `unload()` emits `destroyed`. An RPC after unload, or one pending at detach, rejects with "Script is destroyed" | [ext-frida §1.6] |
| RPC | `rpc.exports` appear on the host as Promise-returning functions. Mapping: `undefined` → `null`, NativePointer → `"0x…"` string, ArrayBuffer → Buffer. **BigInt arguments throw on the host.** Errors keep name, message and stack. A missing method gives "unable to find method". Round trip 300–350 µs; 200 parallel calls take 13–15 ms | [ext-frida §1.7] |
| Cancellation | Pass a `frida.Cancellable` as the last argument; `cancel()` → "Operation was cancelled" after about 200 ms, and the script stays usable | [ext-frida §1.7] |
| Agent thread | **One JS thread serves every script in the target**, across sessions and runtimes. A 400 ms RPC delayed every other script by 400 ms | [ext-frida §1.7] |
| Compiler | `new frida.Compiler()` and `build(entry, {projectRoot, bundleFormat:'esm' or 'iife', typeCheck:'full' or 'none', sourceMaps, compression:'none' or 'terser'})`. Uses built-in GumJS typings with no tsconfig or `@types`. Cold build 167 ms, warm 13–20 ms. A type error gives "Compilation failed" and the `diagnostics` signal carries `{category, code (BigInt), file{path, line (BigInt, 0-based), character}, text}`. esbuild IIFE output also loads | [ext-frida §1.8] |
| Kill | `device.kill(pid)` kills **only the root process** and resolves before the process is gone. Frida-spawned targets **outlive the Node host** | other lab [rea-process §7 F2, F3]; [rea-runtime §7 #15] |
| Pipe zombie | A `stdio:'pipe'` target that has exited is still returned by `enumerateProcesses({pids})`. **Not a liveness check** | [ext-frida §1.3] |
| Many piped targets | From the 4th concurrently attached `stdio:'pipe'` target in one host process, spawn takes 1.8–2.7 s and every RPC 340–680 ms. With `inherit`, 6 targets stay at about 16 ms per spawn and 1 ms per RPC. Root cause unknown | other lab [rea-testing §0.6, §10] |
| Clean exit | Node hangs while device or session signal handlers are still connected, even after `manager.close()`. Disconnect them, then `await manager.close()` | other lab [rea-runtime §7 #18] |
| Parentage and jobs | A local Frida spawn makes the target a direct child of the host Node process [rea-testing §0.5]. A suspended Frida-spawned target is in no job and can be assigned to one before `resume` [rea-process §7 F1] | other lab |

### 2.2 Agent API presence in 17.23.2

- **Removed** (`typeof === 'undefined'`): every `Memory.read*`/`write*`, static `Module.findBaseAddress`,
  `Module.enumerateExports`, `Module.getExportByName`, `Module.ensureInitialized`, `Process.enumerateModulesSync`.
  The only static members of `Module` are `load`, `findGlobalExportByName` and `getGlobalExportByName`
  [ext-frida §2].
- **Present:**
  - `Process`: `get/findFunctionRange`, `get/findThreadById`, `runOnThread`, `attachThreadObserver`,
    `attachModuleObserver`;
  - `Memory.findPointers`, `ControlFlowGraph`, `Profiler` with samplers;
  - `Interceptor.replaceFast`, `Interceptor.defaults`, and the `InstrumentationTarget` object form (`relocation`,
    `scenario`);
  - `MemoryAccessMonitor`, `readVolatile`/`writeVolatile`, `ArrayBuffer.wrap`;
  - `Worker`, `Cloak`, `SqliteDatabase`, `Checksum`, `File`, `ApiResolver`, `ModuleMap`, `CModule`, `Kernel`.

  [ext-frida §2]
- **Typed in `@types/frida-gum` 19.12.0 but absent at runtime:** `RustModule` [ext-frida §2].
- **`Module` instance methods:** `enumerateImports/Exports/Symbols/Ranges/Sections/Dependencies`,
  `find/getExportByName`, `find/getSymbolByName`, `ensureInitialized` [ext-frida §2].

### 2.3 Agent cheat-sheet by task

| Task | How (VERIFIED) | Caveats | Source |
|---|---|---|---|
| Modules | `Process.mainModule`, `Process.enumerateModules()` (frida-agent.dll is cloaked), `getModuleByName` (case-insensitive; `get*` throws, `find*` returns null), `Process.findModuleByAddress`, `ModuleMap` | `module.version` is null; `enumerateDependencies()` is `[]`; gcc long section names come back as `/4`, `/14` | [ext-frida §3.1] |
| Exports and imports | `enumerateExports()` → `{type:'function' or 'variable', name, address}` with no size. `enumerateImports()` → `{type, name, module, address, slot}`, where **slot is the IAT entry** | `enumerateSymbols()` on a PE returns exports only, with data mistyped as functions and sizes equal to the gap to the next symbol; `findSymbolByName` returned null | [ext-frida §3.1] |
| Function bounds | `Process.findFunctionRange(addr)` → `{base, size}` from `.pdata`, **exact** (181 B and 8 B matched objdump) | `getFunctionRange` throws when there is no range | [ext-frida §3.12] |
| Memory ranges | `Process.enumerateRanges('rw-')` or `{protection, coalesce:true}`; `module.enumerateRanges`; `get/findRangeByAddress` → `{base, size, protection}`; `enumerateMallocRanges()` found 5663 blocks in 2 ms | **There is no `file` field on Windows**: attribute ranges via `findModuleByAddress`. A `Memory.alloc` block gives `findRangeByAddress === null` | [ext-frida §3.2] |
| Read and write | `p.readFloat/readDouble/readS32/readU32/readU64/readPointer/readByteArray(n)/readUtf8String/readUtf16String/readVolatile`. Accessors take an offset argument (`car.readS32(4)`). Writes chain | A bad address throws a plain `Error("access violation accessing 0x10")` and the target survives. Writing code needs `Memory.protect` first | [ext-frida §3.3] |
| Scan | `Memory.scanSync(base, size, pattern)` supports exact bytes, `??`, nibble wildcards, the r2 `: mask` form and `/regex/`; async `Memory.scan`; `Memory.findPointers(ranges, [values])`. A Cheat-Engine-style first scan, then an "increased" re-read of the hit list, was verified | Wrap each range in try/catch, because an unreadable range throws; a bad pattern throws "invalid match pattern" | [ext-frida §3.4] |
| Alloc, protect, patch | `Memory.alloc(n, {protection:'rwx', near, maxDistance})`, `Memory.protect`, `Memory.queryProtection`, `Memory.patchCode(addr, n, code => new X86Writer(code, {pc}))` (protection stays `r-x`), `Memory.copy`, `Memory.dup` | (none) | [ext-frida §3.5] |
| Hook | `Interceptor.attach(target, {onEnter(args), onLeave(retval)})`. `this.context` exposes `pc, sp, rax…r15, rip, xmm0..xmm15`, each xmm a **16-byte ArrayBuffer**, readable and writable. Also `this.returnAddress`, `this.threadId`, `this.depth`, `this.lastError`. Instruction probes mid-function work | No rflags, ymm, segment or debug registers. In QJS the context fields are accessors, so `Object.keys` is empty, and xmm serializes as `{}`: serialize from an explicit register list | [ext-frida §3.6] |
| Win64 arguments | Integers from `args[i]`. f32/f64 from `new Float32Array(ctx.xmmN)[0]` / `Float64Array`, by **positional slot** (the 2nd parameter is `xmm1`, and `args[1]` is garbage for a float). Stack arguments from `args[4+]` (Frida accounts for the shadow space). Float returns from `ctx.xmm0` in `onLeave` (`retval` is rax) | (none) | [ext-frida §3.6] |
| Modify | `args[0] = ptr(5)`, `retval.replace(ptr(123))`, `this.context.xmm0 = ab` (float return), and writes to `rcx` or a stack argument all worked in both runtimes | (none) | [ext-frida §3.6] |
| Tiny functions | A 4-byte function fails with "unable to intercept function … please file a bug" for `attach`, `replace` and `replaceFast`. **`Interceptor.attach({target, relocation:'forced'}, cbs)` works.** `checked` and `unchecked` relocation still fail | (none) | [ext-frida §3.6]; other lab [rea-runtime §7 #7] |
| Commit | Changes are pending until the JS turn ends, `send`/RPC returns, or **`Interceptor.flush()`** is called. One late `onEnter` arrived after `detachAll()`: guard handlers with a `detached` flag | `Instruction.parse` at a hooked address returns the hook's `jmp` | [ext-frida §3.6] |
| Replace and IAT | `Interceptor.replace(target, NativeCallback)` calls the original through a `NativeFunction`; `revert` restores it; a second replace throws. `replaceFast` returns a trampoline. IAT hook: set the slot page to `rw-`, then `slot.writePointer(cb)` | `replaceFast` once got 0 callbacks while the agent thread was in `Thread.sleep` (flaky) | [ext-frida §3.6] |
| Oracle call | `new NativeFunction(addr, 'float', ['pointer','float'])` and similar returned exact results on a **scratch copy** of the struct. By default exceptions are **stolen**: a crash becomes a JS `Error` with `type`, `address`, `memory` and `context`, and the target survives. `Process.runOnThread(tid, fn)` runs on the game thread (about 15 ms latency) | By-value struct arguments were not exercised. Calls into thread-control APIs need `{scheduling:'exclusive'}` (the cooperative default deadlocked V8) | [ext-frida §3.7] |
| Per-call coverage | Create the function with `{traps:'all'}` and wrap the call in `Stalker.follow(currentTid, {events:{compile:true}})`: this gives the exact block coverage of that call | (none) | [ext-frida §3.7] |
| Threads | `Process.enumerateThreads()` → `{id, state, context, entrypoint{routine}}`; `attachThreadObserver({onAdded, onRemoved})`, where `onAdded` **runs on the new thread** and is also called for existing threads; `attachModuleObserver` | `state` reads `'running'` for sleeping threads; `name` is undefined | [ext-frida §3.13] |
| Backtrace | `Thread.backtrace(this.context, Backtracer.ACCURATE)` gives return addresses (callers); prepend the faulting pc yourself | Without a context it returns frida-agent frames. `FUZZY` adds false positives | [ext-frida §3.11, §3.13] |
| Symbols | `DebugSymbol.fromAddress` on a non-PDB binary returns the nearest preceding export with no displacement, and **`moduleName` is wrong for system DLLs**. `ApiResolver('module')` returns `exports:`, `imports:` and `sections:` with the full module path | Use exports, REA/Ghidra symbols and `.pdata` ranges instead. PDB behaviour is **UNVERIFIED** | [ext-frida §3.12] |
| CFG and decode | `new ControlFlowGraph(fn)` gives blocks with successors and dominators, and they matched objdump. `Instruction.parse(p)` → `{address, next, size, mnemonic, opStr, groups, operands, regsAccessed}` | Immediates are decimal strings. RIP-relative `disp` is relative to `insn.next` | [ext-frida §3.12] |
| ASLR | `runtime = module.base + (staticVA - preferredImageBase)`. Read the **preferred base from the file on disk** (`new File(path,'rb').readBytes(0x400)` works in the agent) | The loader rewrites the in-memory `ImageBase` to the actual base | [ext-frida §3.14] |
| Dumps | `module.base.readByteArray(module.size)` reads a whole image (ntdll, 2.5 MB, in 9 ms); `send(meta, buf)` delivered 135 KB | The image is in mapped layout, not file layout | [ext-frida §3.14] |
| Profiling | `new Profiler().instrument(fn, new CycleSampler(), {describe})` → an XML report with calls, durations and worst cases | (none) | [ext-frida §3.15] |
| Extra JS | `Script.evaluate(name, src)`; `await Script.load(name, esmSrc)` returns the module namespace | (none) | [ext-frida §3.15] |
| CModule | TinyCC with `<glib.h>`, `<gum/gumstalker.h>`, `<gum/guminterceptor.h>`; `extern` symbols are passed as pointers in the 2nd constructor argument | QJS frees a CModule eagerly (lifetime hazard, §2.6) | [ext-frida §3.15] |

### 2.4 Stalker, hardware traps and the page-guard monitor

**Stalker** [ext-frida §3.8]:
- **Defaults and events.** `queueCapacity` is 16384 events, `queueDrainInterval` 250 ms, and each event is 32 B.
  Events: `call`, `ret`, `exec`, `block`, `compile`. `Stalker.parse(ab, {annotate, stringify})`.
- **Silent loss at default settings.** About 65K events/s is the ceiling. Fix: set
  `Stalker.queueCapacity = 1<<21; Stalker.queueDrainInterval = 50;` before `follow`. After that, 64,000 of 64,000
  expected events arrived.
- **Cheap coverage.** Compile events (one per block) found 481 unique blocks in 600 ms with no measurable FPS cost.
  Exact hit counts come from a CModule transform with `gum_stalker_iterator_*` and `put_callout`.
- **Expensive modes.** Call events on call-heavy code slowed it by **about 90x**. QJS JS callouts run at about
  6M/s and V8 at about 0.85M/s.
- **Block shape.** Stalker blocks split after a `call` and not at join points. Map them to static CFG blocks by
  range overlap.
- **Lifetimes.** Keep CModules and NativeCallbacks referenced (`globalThis.keep = […]`) until after `unfollow`,
  `flush` and `garbageCollect`. QJS freed an out-of-scope CModule and crashed the target in 2 of 2 runs.
- **Hooks versus following.** A hook added after a followed thread compiled the block is invisible. Detaching a
  hook while the thread is followed crashed the target in 1 of 4 runs. Fix both with `Stalker.invalidate(tid, addr)`.
- **Best-effort data.** `onCallSummary` came back empty in one light-workload run, so do not rely on it for
  counts.

**Hardware breakpoints and watchpoints** [ext-frida §3.9]. These are `ThreadDetails` *instance methods*:
`t.setHardwareWatchpoint(id, addr, size, 'w' or 'rw' or 'r')`, `t.setHardwareBreakpoint(id, addr)`, and the
matching `unset*`.
- **Delivery.** Hits arrive in `Process.setExceptionHandler` as `type:'single-step'` (never `'breakpoint'`), with
  `memory:null`.
- **Data traps report the next instruction.** Recover the accessing instruction by sweeping `Instruction.parse`
  from `Process.findFunctionRange(pc).base` until `insn.next.equals(pc)`. This found the writer correctly.
- **Which slot fired.** Read DR6 from `nativeContext`. Windows x64 `CONTEXT` offsets: `ContextFlags +0x30`,
  `EFlags +0x44`, `Dr0..Dr3 +0x48 / +0x50 / +0x58 / +0x60`, `Dr6 +0x68`, `Dr7 +0x70`.
- **No validation at all.** An id ≥ 4 corrupts DR7 silently. Misaligned addresses are aligned down. `'r'` behaves
  as `'rw'`. Sizes 3 and 16 "succeed". The 4 slots are shared between breakpoints and watchpoints. **BEA must
  validate:** id 0–3, size 1/2/4/8, alignment to size.
- **Per thread.** A watchpoint armed only on the game thread saw 0 of the worker thread's writes. Arm every thread,
  and arm new ones from `attachThreadObserver.onAdded`.
- **The unset race.** `unset*` called from the agent JS thread failed 3–5 times out of 8 while traps were frequent.
  The reliable disarm is to zero DR7 and Dr0–3 in `nativeContext` inside the handler, *and* call `unset*` for
  threads that are not trapping, then verify with `GetThreadContext` through a NativeFunction marked
  `{scheduling:'exclusive'}`.
- **Execute breakpoints loop forever** unless the handler sets RF:
  `nc.add(0x44).writeU32(nc.add(0x44).readU32() | 0x10000)`. Alternatively, clear DR7 for a one-shot breakpoint.

**MemoryAccessMonitor** [ext-frida §3.10]. `MemoryAccessMonitor.enable({base, size}, {onAccess(d)})`:
- It is page-granular and fires once per page per enable.
- It covers **all threads**, including execute access on code pages.
- It reports the **faulting instruction itself** (`d.from`), plus `operation`, `address` and `threadId`.
- Re-arming through `setImmediate` gave about 43 events/s. Filter by `d.address`, because other data on the same
  page also triggers it.

### 2.5 Exceptions, crashes and the injection footprint

- `Process.setExceptionHandler(d => …)` sees `access-violation` (with `address`, `memory{operation, address}`,
  `context` and `nativeContext`), `illegal-instruction` and `single-step`. **It also sees first-chance exceptions
  that the app handles itself.** Returning `false` passes them to the app's SEH, and the app continued
  [ext-frida §3.11].
- **Report before death:** `send(info); recv('ack', () => {}).wait(); return false;` with the host posting
  `{type:'ack'}`. The wait took 0–1 ms locally. This is the **only** path by which crash details reached the host
  on Windows [ext-frida §3.11]; other lab [rea-runtime §7 #16, #17].
- **Recover:** set `d.context.pc` past the faulting instruction (`d.address.add(Instruction.parse(d.address).size)`)
  and return `true` [ext-frida §3.11].
- **Footprint.** Attaching loads frida-agent.dll (visible to `tasklist /M`, hidden from GumJS) plus 24 system DLLs
  and 3 ntdll pool threads. After `detach`, **11 DLLs stay loaded**. Detach is not a full restore, and protected
  games may react; that was not tested [ext-frida §4].

### 2.6 Throughput and cost figures

| Measurement | Value | Source |
|---|---|---|
| `send()` host receipt, small messages | about 8.2K msg/s; **no backpressure**. Sending once per call from a 2M calls/s hook grew the target to **about 21 GB** | [ext-frida §1.9] |
| Binary attachments | 603 MB/s (QJS), 579 MB/s (V8) | [ext-frida §1.9] |
| Hook event delivery | JSON batches 1.01M/s; binary `Int32Array` batches 1.20M/s; CModule ring drained into binary `send` 5.4M/s (QJS); zero loss in each | [ext-frida §1.9] |
| Hook overhead | empty JS `onEnter` 0.44 µs (QJS) or 1.1 µs (V8); CModule `onEnter` writing a ring 0.19 µs | [ext-frida §3.6, §1.9] |
| Scanning | `scanSync` about 1.8 GB/s; `findPointers` about 30 GB/s; tolerance float scan in QJS JS 33 MB/s, in V8 1.17 GB/s, in a CModule 1.0 GB/s | [ext-frida §3.4] |
| RPC | 300–350 µs round trip | [ext-frida §1.7] |

### 2.7 Consolidated gotchas

These are numbered for reference from §6. Each was observed in a lab.

1. `load()` resolves on a top-level throw. Treat any `error` message during load as a failure [ext-frida §6 #2].
2. With the default `logHandler`, agent logs go to host **stdout**, which is fatal for stdio MCP [rea-runtime §8.1].
3. `processCrashed` never fires and `detached` gives `crash=null`. Crash details come only from the agent handler
   with a blocking ack [ext-frida §6 #3].
4. `send()` has no backpressure. Batch, bound, and count dropped events [ext-frida §6 #5].
5. One JS thread per target. Keep RPC handlers short and split scans into chunks with `setImmediate`
   [ext-frida §6 #6].
6. `JSON.stringify` throws on BigInt (`ppid`, compiler diagnostics) [ext-frida §6 #1].
7. A `stdio:'pipe'` zombie still appears in a pid-filtered `enumerateProcesses` [ext-frida §6 #4].
8. Functions under 5 bytes need `relocation:'forced'` [ext-frida §6 #8].
9. Interceptor changes take effect only after the JS turn or `flush()`, and late callbacks can arrive after detach
   [ext-frida §6 #9].
10. Floats live in `xmmN`. `args[i]` for a float is garbage, and `retval` is rax [ext-frida §6 #10].
11. QJS context objects have no own keys [ext-frida §6 #11].
12. Stalker's default queue drops events above about 65K/s [ext-frida §6 #12].
13. Stalker call events cost about 90x on call-heavy code [ext-frida §6 #13].
14. QJS frees an unreferenced CModule eagerly and crashed the target [ext-frida §6 #14].
15. Hook changes while a thread is followed are invisible or crash the target. Use `Stalker.invalidate`
    [ext-frida §6 #15].
16. Hardware traps report `single-step`, `memory:null`, and the pc after the access [ext-frida §6 #16].
17. Hardware set/unset calls validate nothing [ext-frida §6 #17].
18. `unset*` from the JS thread can lose a race. Disarm through `nativeContext` [ext-frida §6 #18].
19. Execute breakpoints re-trigger forever without RF [ext-frida §6 #19].
20. Thread-control calls need `{scheduling:'exclusive'}` [ext-frida §6 #20].
21. `DebugSymbol` and `enumerateSymbols` are wrong or partial without a PDB [ext-frida §6 #21, #22].
22. Ranges have no `file` field, `enumerateDependencies` is `[]`, `module.version` is null [ext-frida §6 #23].
23. The in-memory `ImageBase` equals the runtime base. Read the preferred base from disk [ext-frida §6 #24].
24. `exceptor:'off'` makes any agent fault kill the target [ext-frida §6 #25].
25. `Thread.state` reads `running` for sleeping threads [ext-frida §6 #26].
26. Instruction immediates are decimal strings, and RIP-relative `disp` is relative to `next` [ext-frida §6 #28].
27. The injection leaves 11 DLLs loaded after detach [ext-frida §6 #29].
28. Do not block the agent thread (`Thread.sleep`) [ext-frida §6 #30].
29. `device.kill` kills only the root process and returns early. Frida targets outlive the host
    [rea-process §7 F2, F3].
30. Four or more concurrent `stdio:'pipe'` targets make spawns and RPCs slow [rea-testing §0.6].

### 2.8 Not verified (BELIEVED or untested)

- PDB symbolization through dbghelp. There are no MSVC libraries or SDK here, and `symsrv.dll` is absent
  [ext-frida §8]; [ext-backends §1].
- `Worker`, `Compiler.watch`, `LanguageServer`, `PatternCompiler` (an ImHex-style decoder that could suit struct
  views), `Script.enableDebugger`, `snapshotTransport:'shared-memory'` [ext-frida §8].
- By-value struct arguments to `NativeFunction` [ext-frida §8].
- Behaviour against anti-debug, anti-tamper or anti-cheat targets [ext-frida §4, §8].
- Why the V8 CModule-ring run never delivered its final message, and whether `onCallSummary` loses data under queue
  pressure [ext-frida §8].
- A Lighthouse/drcov round trip of compile-event coverage [ext-frida §8].
- WoW64 (32-bit) targets from 64-bit Frida [rea-runtime §19 Q5].
- Whether `exceptor:'handler-only'` changes how the target's own SEH/VEH behave [rea-runtime §19 Q2].
- Whether more than one `Process.setExceptionHandler` can coexist in one agent. BEA should assume no, and route
  crashes and hardware traps through **one** dispatcher [proposal].

---

## 3. Backend recommendations

### 3.1 Frida: the primary live backend (v0.1)

Why Frida:
- It is the only live dynamic capability REA has on Windows [rea-runtime §0].
- It is verified on this host for every primitive BEA needs: spawn and attach, memory, scans, hooks with float
  arguments, Stalker, hardware watchpoints, the page-guard monitor, in-process oracle calls, crash capture and dumps
  [ext-frida §0].
- In-process `NativeFunction` calls returned the exact expected values (for example `physics_step(scratch, 0.5)` =
  14.905 = 10 + 9.81 × 0.5), and a fault inside the call is stolen into a JS exception while the target survives
  [ext-frida §3.7]. Unicorn emulation of a fixture function matched the in-process call bit-for-bit
  [rea-testing §10].

How BEA uses it [proposal grounded in the cited facts]:
- **Binding.** Pin `frida@17.23.2` exactly as a **regular dependency**, because it is BEA's core engine
  [rea-cli §9.1]. This overrides the optional-dependency pattern described in [rea-runtime §3] and
  [rea-testing §6.1]. Keep REA's loading mechanics:
  - only `import type` at module top;
  - an injectable `deviceManagerLoader = async () => (await import("frida")).getDeviceManager()`;
  - a single-flight load that remembers its failure and reports it through `bea_status`.

  [rea-runtime §3]
- **Types.** Type against the package's bundled `frida.d.ts` [ext-frida §1.1]. Fakes implement BEA's own narrow
  port interfaces (`DynamicSessionPort`, `AgentRpc { call(method, args, signal) }`), not the Frida types
  [rea-testing §11.4].
- **Spawn path.** Path 1:
  1. `device.spawn([exe, ...args], {cwd, env, stdio:'pipe'})`
  2. `bea-jobhost adopt <pid>` (verifies the creation time)
  3. `device.attach(pid)` with the default exceptor
  4. `createScript(agentBundle, {name, runtime:'qjs'})`
  5. set `logHandler`, connect `message`
  6. `load()` and wait for `ready` (fail if an `error` message arrives)
  7. `device.resume(pid)`

  Output comes through `device.output`, and the exit code from jobhost [rea-process §8.3]; [ext-frida §7].
  Path 2 (`jobhost run --suspended`, then attach) is the fallback when Frida's stdio pipe is a problem; it was
  VERIFIED with node.exe [rea-process §8.3].
- **Agent.** A BEA-owned TypeScript agent compiled by `frida.Compiler` at **build time** into a shipped bundle, so
  nothing compiles at runtime. Its typings are version-locked to GumJS, and esbuild IIFE is the fallback
  [ext-frida §1.8]. The agent's RPC surface mirrors the tool catalog (§6), and it ends top-level code with
  `send({bea:'ready', version, apis})` [rea-runtime §8.2].
- **Runtime.** QJS by default for cheaper hooks and callouts. Any per-event or per-byte work goes in a CModule. V8
  only for agents that do heavy JS compute [ext-frida §5].
- **Streaming.** Binary batches (`Int32Array(16384)` flushed every 50 ms) for up to about 1M events/s; a CModule
  ring above that. Every stream carries an explicit dropped counter [ext-frida §1.9, §7].
- **One exception dispatcher in the agent** [proposal]:
  - It routes `single-step` traps to the watchpoint and breakpoint managers.
  - It records every other exception as a **first-chance event**, with a blocking ack only for crash-class types.
  - It returns `false` for anything BEA did not cause.
  - A crash is a *derived* conclusion: the last exception events, plus jobhost's NTSTATUS exit code, plus the
    `process-terminated` detach.

  This is needed because first-chance exceptions that the app handles are delivered to the same handler
  [ext-frida §3.11].
- **Remote devices** (frida-server, tokens, certificates): defer. REA's refcounted remote handling can be copied
  later [rea-runtime §4.3].

### 3.2 Process runner: `bea-jobhost.exe` (v0.1)

- One small C helper per spawned target, as specified in §1.15 [rea-process §8].
- Prebuilt and shipped with a SHA-256 check at load, which is the cheap part of REA's addon loader
  [rea-process §8]. Unsigned-exe behaviour with Defender and SmartScreen is untested [rea-process §13 Q5].
- Also used to own BEA's other children, such as the emulator bridge, with `--mem-limit` from `JOB_MEMORY`
  [proposal; rea-process §11 #13; ext-backends §8].
- Linux: a `bea-reaper` using `PR_SET_CHILD_SUBREAPER`, a process group and pdeathsig. macOS: a process-group kill,
  reported as best-effort. Both are later work [rea-process §9].

Do not use:
- a Node-API addon (ABI, packaging and build-lane overhead);
- `taskkill /T /F` as the primary mechanism (it leaks orphans);
- PowerShell or CIM tree walks (370+ ms);
- `device.kill` for trees (it kills the root only)

[rea-process §8].

### 3.3 Emulator: Unicorn 2.1.4 through the `bea-emu/0.1` Python bridge (v0.1)

**Prototype.** `bea-lab/ext-backends/bea_emu_bridge.py` (about 1,900 lines). It supports:
- PE64 loading and relocation;
- Win64 calls with typed arguments (scalars, f32/f64 by value or by `bits`, arrays, out-buffers, structs with
  nested pointers, symbols);
- HLE import stubs with per-session overrides;
- TEB, PEB and static TLS;
- fault diagnostics, snapshots and batching;
- import, block and memory tracing;
- cancellation, a watchdog and an ISA guard.

A Node 24 client drove it end to end, and results were bit-exact against native execution for SSE code
[ext-backends §0, §2].

**Gotchas that shape the design** (VERIFIED on unicorn 2.1.4 and Python 3.14.6) [ext-backends §2.4]:
1. Unicorn starts with **FPCW=0 and MXCSR=0**, where Windows uses 0x027F and 0x1F80. Unfixed, x87
   `sqrt`/`exp`/`pow` were wrong in 1500 of 1500 cases. Set both at session open **and on every call**, and record
   them in provenance.
2. **VEX.128 instructions run silently wrong**: `vaddss xmm0,xmm1,xmm2` executes as `addss` and gave 102 instead of
   3. VEX.256 and FMA are rejected, and CPUID reports no AVX for every CPU model. BMI1/BMI2 are fine.
   → An **ISA guard** pre-scans `.pdata` ranges plus the gaps between them, and stops at VEX/EVEX instructions.
3. x87 transcendentals are inexact even with the correct FPCW: up to 19,737 ulp for `sin(±1e6)` and 88 ulp for
   `pow`. Tag them as `x87_transcendental_inexact`.
4. Code and block hooks added after a block was translated fire 0 times, and the `count=` budget is not enforced on
   cached blocks. Call `ctl_flush_tb()` whenever the hook set or the budget mode changes.
5. `emu_start(timeout=)` costs about 15 ms per call, which caps throughput at 66 calls/s. Use a polling watchdog
   thread with `emu_stop()` instead (33 µs).
6. Mapping or unmapping memory after a CPU+memory snapshot and then restoring causes a native access violation.
   Freeze the layout, or use `snapshots:"manual"`.
7. A daemon thread blocked on buffered stdin crashed interpreter shutdown with `0xC0000005`. Read with
   `os.read(0)` and exit with `os._exit`.
8. `pefile.get_memory_mapped_image()` drops sections past 256 MiB and returns a `bytearray` after relocation.

**Performance** [ext-backends §2.6]:

| Measure | Value |
|---|---|
| raw speed, no hooks | about 186–203 M instructions/s |
| raw speed with a `count` budget | about 65 M/s |
| bridge batch, chained state | 35.8–38.7k calls/s |
| bridge batch, snapshot restored per vector | 16.3–18.2k calls/s |
| single requests | 4.6–5.4k calls/s sequential; 13–15k calls/s pipelined |
| bridge start to `ready` | 225–380 ms |
| Python hook callback | about 0.36 µs each |

**Batching is mandatory.**

**Protocol** [ext-backends §9]:
- One JSON object per line, frames `{id, method, params}` → `{id, result}`, `{id, error:{code, message, data}}` or
  `{id, event}`, plus an unsolicited `ready` event.
- Methods: `bridge.hello`, `session.open`, `session.info`, `session.close`, `session.snapshot`, `session.restore`,
  `mem.read`, `mem.write`, `mem.disassemble`, `emu.call`, `emu.callBatch`, `bridge.cancel`, `bridge.shutdown`.
- **Emulation outcomes are results** with a `status`: `returned`, `fault`, `cpu_exception`, `invalid_instruction`,
  `unsupported_instruction`, `unhandled_import`, `budget_exhausted`, `timeout`, `cancelled`, `engine_error`.
- 64-bit values and addresses are hex strings. Floats are `{value, bits}`, and `{bits}` is accepted as input.
  Batches can return columns (`{status[], value[], bits[]}` plus sparse `faults[]`).
- Every result carries provenance: engine versions, image sha256, preferred and mapped base, the target, and
  FPCW/MXCSR.
- Emulated results are **derivations**, not runtime observations. `deviations[]` lists HLE imports, inexact math and
  TLS callbacks or DllMain that did not run.

**Packaging** [ext-backends §8]; [rea-cli §11]:
- Ship the single `.py` file.
- On first use, `bea setup` or `bea doctor` creates a **BEA-owned venv** (uv or `python -m venv`) under BEA's data
  directory, with the user's approval, containing pinned, hash-locked `unicorn==2.1.4 capstone==5.0.9
  pefile==2024.8.26`. Never touch global site-packages.
- Spawn it as `python -I -X utf8`. The `-I` matters: the user's tools folder has a local `dis.py` that shadows the
  stdlib [ext-backends §3].
- Re-run the probe suite on every engine version change.

**Dump-backed sessions, designed in now** [ext-backends §9.11]:
- Frida captures the modules (`enumerateModules`), the regions (`enumerateRanges` plus `readByteArray`; whole images
  read in milliseconds [ext-frida §3.14]), and the thread or TEB context.
- Unicorn then runs against the real initialized state.
- This fixes the "file-image `.data` differs from the runtime value" problem in the user's harnesses
  [ext-backends §3].
- Still open: what happens on an access to memory that was not captured (fault with diagnostics, or fetch lazily
  through Frida).

**Differential testing.** The native in-process oracle (`call_function`) is the bit-exact reference, and Unicorn
supplies tracing, coverage and very cheap batches. Expect last-bit differences where native code dispatches to AVX
or FMA paths through CPUID while the emulator takes SSE paths [ext-backends §2.4 #2, §10 Q4].

### 3.4 Later and optional backends

| Backend | When | Why / evidence |
|---|---|---|
| speakeasy 2.0.0b9 (MIT) | v0.2, optional extra | Runs DllMain and TLS callbacks, has about 1,044 API handlers, SEH/VEH and a GDB stub. Installs on CPython 3.13 in an isolated uv env. But it manages **about 14 calls/s**, and its report reached 81 MB after about 310 calls. Use it for initialization paths, not as the oracle. 1.5.11 is broken on Python ≥3.12 [ext-backends §4] |
| GDB (MI3 or DAP) | v0.2 | WinLibs GDB 17.2 on this host drives hardware watchpoints headless: `awatch` reports every access, `watch` only value changes, and the stop pc is *after* the access. REA's MI3 code is reusable. This is the Windows fallback and the basis of a Linux provider [ext-backends §6.4, §7] |
| cdb/DbgEng (+ Pybag) | v0.2 | Minidump triage (`!analyze -v`) and `dx` queries. Needs a WinDbg or SDK install, and no `symsrv.dll` is present [ext-backends §6.1] |
| TTD.exe + replay | v0.3 | The gold standard for "every write to X". **Needs admin** and slows the target 5–20x. The replay API is experimental. The in-box `tttracer.exe` license **forbids automation** [ext-backends §6.2] |
| x64dbg-automate | interop only | GUI-centric, and ships its own MCP server [ext-backends §6.3] |
| LLDB (SB API) | v0.3, macOS | REA's tracer pattern applies. lldb-mcp is unauthenticated across discovered sessions [ext-backends §7] |
| Qiling | **no** | GPLv2, needs a rootfs of real Windows DLLs, no PyPI release since 2023 [ext-backends §5] |

**Provider interface** [ext-backends §7]. Define BEA's runtime primitives once: spawn/attach,
modules/exports/maps, read/write, hook with structured capture, hardware watchpoint, call-as-oracle, dump. Implement
Frida first. Run any later adapter as a child process speaking a JSON-lines protocol shaped like `bea-emu/0.1`
(same framing, errors and provenance; different methods).

---

## 4. Landscape and BEA's differentiation

### 4.1 Who does what

The field is crowded but shallow. Dozens of Frida, x64dbg, GDB, LLDB, WinDbg and Cheat Engine MCP servers proxy
raw commands (`attach`, `execute_command`, `read_memory`, `get_messages`). Stars do not track quality: the
most-starred Frida MCP, dnakov at about 460 stars, has 5 commits and 13 tools [ext-landscape §0, §1.1]. Five
projects are serious:

| Project | Strongest at | Steal for BEA |
|---|---|---|
| glslang/windbg-mcp (Rust, DbgEng, 78–89 tools) | runtime plumbing | One worker process per target; `continue_async`/`wait_for_stop` ("a wait that runs out is a poll", "a stop is read, not taken"); `debug_batch` with assertions; token budgets in CI; honest limitations ("results are evidence, not verdicts"; sound versus best-effort) [ext-landscape §3.3] |
| monkeywave/frida-mobile-mcp (TS, 71 tools) | evidence envelope (REA-aligned, mobile only) | `evidence_id`, coverage, limitations, untrusted provenance, effects in `_meta`, a persisted store, safety flags off by default, TOON output, core+compact profile at 17%, the `module+0x<offset>` convention, and a `docs/rea.md` routing guide [ext-landscape §1.3] |
| miscusi-peek/cheatengine-mcp-bridge (1.7k stars, about 180 tools) | Cheat-Engine-style UX | Scans return a count; results are paged; named persistent scans; hardware breakpoints that log hits without stopping the target; a documented walk-back recipe [ext-landscape §7.1] |
| mq1n/GhostMCP (Rust, injected DLL, experimental) | in-process breadth | 12-mode scanner, pointer scanner with stability scores, an API-trace ring buffer with a declared backpressure policy, capability scopes, safety tokens with a TTL, patch preview and undo [ext-landscape §7.2] |
| Microsoft WinDbg MCP (WinDbg 1.2610.1001.0, Oct 2026) | safety | Secure Mode, prompt-injection screening of debugger output via sampling (which Claude Code and Codex do not support), AI actions logged in the UI [ext-landscape §3.1] |

Others worth noting [ext-landscape §1.2–§1.6, §2.3, §4.1, §6.1, §6.4, §10]:
- bethington/ghidra-mcp: the **only** `debugger_static_to_dynamic` / `_dynamic_to_static` tools, GUI-only.
- ida-pro-mcp: debugger tools hidden behind `?ext=dbg`. Its rebasing request #449 was **closed as not planned**.
- frida-game-hacking-mcp: one global scan, no handles.
- dryfryce/frida-mcp: the only Stalker tool found, and reviewers found its overlapping hook tools confusing.
- Ipiano/gdb-mcp: a separately permissioned `gdb_call_function`.
- bromoket/x64dbg_mcp: mega-tools with an action enum, on port 27042, which **collides with Frida's default**.
- sarks0/binary-mcp: fail-closed allowlists for raw commands.

### 4.2 Gaps nobody fills, and BEA's angle

| Gap | State of the art | BEA's angle |
|---|---|---|
| Evidence for dynamic facts | frida-mobile's envelope (mobile); glslang's "evidence, not verdicts"; Project Ire's chain of evidence (research) | REA's semantics plus process identity, time anchor, effects and streams (§1.7) [ext-landscape §12.3] |
| Iterative Cheat-Engine-style scans | CE bridge (needs CE and Lua); GhostMCP (experimental); frida-game-hacking (one scan) | Frida-native scan handles: all value types including float epsilon, unknown-initial, relative operations, results kept on the server [ext-landscape §12.3] |
| "What writes this address" | CE debugger/DBVM, GhostMCP, x64dbg | Debug-register or page-guard watch with a non-breaking hit log, the writer instruction, module+offset and the static address [ext-landscape §12.3]; mechanics VERIFIED [ext-frida §3.9, §3.10] |
| Coverage export (drcov) | **No MCP server**, and no DynamoRIO/PIN MCP at all; the `stalker-coverage` library emits drcov | Stalker compile-event coverage → a drcov v2 file (module-relative, so independent of ASLR) plus a per-function summary [ext-landscape §9] |
| Static↔runtime mapping | bethington, GUI-only; ida-pro-mcp #449 rejected | First-class, two-way, batch, with an image-hash check and byte verification. Every address output carries all forms [ext-landscape §6.1, §12.3] |
| In-process oracle calls | GhostMCP, CE `execute_method`, Ipiano `gdb_call_function` | Typed Win64 calls with scratch structs, stolen faults, per-call coverage and batches (§2.3) [ext-landscape §12.3] |
| Emulation-based differential testing | **Nobody.** Unicorn MCP is raw; Ghidra `emulate_function` uses P-code | Same inputs through Unicorn and the live oracle, compared bit-exact, with a limited verdict (D14) [ext-landscape §0 #5] |
| Record, then query | TTD, Undo, rr (none on this host) | Bounded hook and Stalker recordings stored as streams and queried afterwards (`query_events`) [ext-landscape §8] |
| Structured *desktop* Frida | Every rich Frida MCP is mobile; desktop ones are thin | BEA is the structured desktop Frida server [ext-landscape §12.3] |

Research support [ext-landscape §11]:
- Project Ire validates report claims against a chain of evidence.
- ADI (FSE 2026) shows whole-function "frame lifetime traces" beat line stepping: 63.8% on SWE-bench Verified. This
  supports per-call frames in hooks.
- EnIGMA documents models hallucinating tool observations ("soliloquizing"). This supports verifiable evidence IDs.
- Naptime's breakpoint-plus-expression primitive matches a structured hook.
- An agentic-RE survey flags timing checks against slow LLM round trips. Hooks must run without waiting on the
  model.

### 4.3 Pitfalls in the wild, and BEA's mitigation

| Pitfall | Seen in | BEA mitigation |
|---|---|---|
| Token blowup from raw debugger text | The pwndbg-mcp author now recommends tmux; x64dbgMCP suggests a compression proxy [ext-landscape §4.2, §2.1] | Bounded structured results, counts with pages, files for bulk, TOON in the CLI, CI token ceilings |
| Tool-count limits | Gemini rejects 209 tools; clients cap at 90–100 [ext-landscape §12.4] | 36 tools (§6) |
| Blocking calls | GDB busy while running, LLDB async surprises, CE `generate_signature` blocking for minutes, an IDA main-thread deadlock, Ghidra modal dialogs [ext-landscape §12.4] | Handles plus `wait` as a poll; per-call deadlines; cancellation |
| Bool results that only mean "submitted" | AgentSmithers x64dbg [ext-landscape §2.2] | Every mutation returns read-back state |
| Persistent breakpoints confusing the model | Undo [ext-landscape §8] | Mandatory lifetimes; instrumentation listed in `session_status` |
| Destructive message reads | nonsleepr frida-mcp.ts [ext-landscape §1.2] | Cursors and stored streams; reads never consume |
| Target crash ends the session | frida-mobile `SESSION_LOST` [ext-landscape §1.3] | Crash recorded as evidence; recent detaches shown in status |
| Ctrl-C killing the target | pwndbg-mcp [ext-landscape §4.2] | API-only interruption, never console signals |
| Fixed ports, open listeners | bromoket on 27042; AgentSmithers on 0.0.0.0 [ext-landscape §12.4] | stdio only in v1; if HTTP comes later, loopback plus a token |
| Prompt injection through target content | Microsoft WinDbg MCP [ext-landscape §3.1] | `_meta.provenance.untrusted_content` plus server instructions |
| Kernel features, BSODs | CE DBK/DBVM [ext-landscape §7.1] | User mode only in v1 |
| Anti-debug and anti-Frida | frida-mobile crashes; timing checks [ext-landscape §12.4] | Detect and report as evidence; never promise stealth |

### 4.4 Position relative to REA

- REA has no plugin API and no MCP-client mode, so BEA is registered next to it and the agent routes between them.
  frida-mobile-mcp works this way too, with the rule "never hold one PID in sessions on both servers"
  [ext-landscape §1.3].
- BEA's skill states the routing [rea-cli §9.6]:
  - static questions → REA or Ghidra;
  - runtime claims → BEA;
  - anchor addresses come from REA or Ghidra, with the image sha256.
- Interop paths, in order of effort:
  1. BEA accepts REA addresses and image digests as input to `map_address`.
  2. BEA's bundles cite REA Evidence IDs (prefixed).
  3. A projection makes BEA Evidence importable by `rea evidence-import`. This needs a spike
     [rea-evidence §13 Q6, Q7].

---

## 5. Risks, unknowns and open questions

### 5.1 Risk register

| # | Risk | Evidence | Mitigation | Residual |
|---|---|---|---|---|
| R1 | A hard-killed server orphans Frida-spawned targets | VERIFIED [rea-testing §0.5]; [rea-process §7 F3] | jobhost adopt before resume; the job dies with the helper (VERIFIED H) | Brokered relaunches (Steam/Epic) escape the job [rea-process §11 #9] |
| R2 | The SDK's 2 s cleanup budget leaks targets when cleanup is slow | VERIFIED: 6 of 6 leaked [rea-testing §0.5] | Kill first; acceptance test asserts close < 2 s with exit code 0 for 6 or more targets | Real clients' shutdown policy unknown [rea-testing §12] |
| R3 | `stdio:'pipe'` slowdown from the 4th target | VERIFIED [rea-testing §0.6] | Cap at 3 piped targets; Path 2 as a fallback; root-cause it | Cause unknown |
| R4 | No backpressure on `send()` → unbounded target memory (21 GB) | VERIFIED [ext-frida §1.9] | Batches, a CModule ring, hard caps, dropped counters | (none) |
| R5 | Stalker silent loss, 90x slowdown, crashes when hooks change during a follow | VERIFIED [ext-frida §3.8] | Queue tuning, compile events or a CModule transform, `invalidate`, CModule lifetime pinning, mode exclusivity | Behaviour on large real games is unmeasured |
| R6 | Hardware watchpoint traps: no validation, the unset race, infinite execute breakpoints | VERIFIED [ext-frida §3.9] | Validation layer, disarm in the handler, RF for execute, verify via `GetThreadContext` | (none) |
| R7 | Wrong symbols on non-PDB binaries; PDB path untested | VERIFIED / UNVERIFIED [ext-frida §3.12, §8] | Symbolize from exports, `.pdata` and REA/Ghidra; `DebugSymbol` as a hint only | MSVC/PDB fixtures cannot be built here [rea-testing §0.7] |
| R8 | Injection footprint, anti-cheat reaction, ban risk | VERIFIED footprint [ext-frida §4]; the reaction is untested | State the footprint as a limitation; scope out protected targets; detect and report | **Product policy needed** (Q5) |
| R9 | Silent emulator divergence (VEX, x87, FP environment) | VERIFIED [ext-backends §2.4] | ISA guard, forced FP environment, deviations recorded, live oracle as ground truth | Unknown divergences on MSVC game code [ext-backends §2.5] |
| R10 | Unicorn licensing: the wheel says BSD, the core is believed GPLv2 | [ext-backends §10 Q1] (BELIEVED) | Install into a user venv on first use; do not vendor `unicorn.dll` | Legal review |
| R11 | One agent JS thread per target → head-of-line blocking (400 ms) | VERIFIED [ext-frida §1.7] | Short RPC handlers, `setImmediate` chunking, long scans as background jobs with handles | (none) |
| R12 | Crash capture depends on a blocking ack, and first-chance exceptions also reach the handler | VERIFIED [ext-frida §3.11] | Single dispatcher; ack only for crash-class types; crash as derived evidence | Interplay with `DIE_ON_UNHANDLED_EXCEPTION` is BELIEVED, not tested [rea-process §11 #8] |
| R13 | Context-budget creep | REA has 213 tools [rea-mcp §3.5] | Cap at 40 tools; CI golden of the catalog size | (none) |
| R14 | Evidence volume and host throughput (29 MiB per 200k events; about 365k/s canonicalization) | VERIFIED [rea-evidence §8]; [ext-frida §1.9] | Raw chunk storage, quotas, manifests, derived queries | Quota defaults undecided (Q14) |
| R15 | Prompt injection through target strings | [rea-mcp §4.6]; [ext-landscape §3.1] | Untrusted marker on by default plus instructions | Clients may ignore `_meta` |
| R16 | Liveness false positive (pipe zombie); pid reuse | VERIFIED [ext-frida §1.3] | Liveness from detach events, jobhost status and creation time; never the pid filter | Precision of `started` for attached processes is unknown |
| R17 | Elevated targets: `requireAdministrator` fails `CreateProcessW` (740) | BELIEVED [rea-process §11 #10] | Report `access_denied`; never `runas` (it would escape the job) | (none) |
| R18 | Unsigned prebuilt `bea-jobhost.exe` against Defender/SmartScreen | untested [rea-process §13 Q5] | SHA-256 check; optional local build with gcc | Distribution decision |
| R19 | WoW64 32-bit games | untested [rea-runtime §19 Q5]; the emulator has no 32-bit mode [ext-backends §2.5] | Report `unsupported_target` in v1 | Scope decision (Q9) |
| R20 | QJS CModule lifetime crash; `exceptor:'off'` is fatal | VERIFIED [ext-frida §3.8, §1.5] | Pin references; never expose `exceptor` | (none) |

### 5.2 Questions already answered by another note

| Question raised in | Answer | From |
|---|---|---|
| Does `Process.attachThreadObserver` exist for arming new threads? [rea-runtime §19 Q4] | Yes. `onAdded` runs **on the new thread** and is also called for existing threads | [ext-frida §3.9, §3.13] |
| Frida hardware watchpoint API, or a native debug-register helper? [ext-landscape §7.1] | The Frida API works on Windows, with validation, race and RF caveats | [ext-frida §3.9] |
| Agent as TypeScript via `frida.Compiler`, or a plain JS string? [rea-runtime §19 Q7] | `frida.Compiler` exists in 17.23.2 and works (167 ms cold), with built-in typings | [ext-frida §1.8] |
| Does `device.processCrashed` fire on Windows? [rea-runtime §19 Q3] | It never fired in any crash run. Plan on the agent handler | [ext-frida §1.5] |
| Effect of `SessionOptions.exceptor`? [rea-runtime §19 Q2] | `full` and `handler-only` behave like the default; `off` makes agent faults kill the target. The effect on the target's own SEH/VEH is still untested | [ext-frida §1.5] |
| Windows process start time via Frida? [rea-evidence §13 Q1] | The `metadata` scope returns `started` (ISO). For owned targets, jobhost reports `creationTime100ns` | [ext-frida §1.3]; [rea-process §8.1] |
| Hook transport: JSON batches or a binary ring? [rea-evidence §13 Q3] | Binary batches 1.2M/s; CModule ring 5.4M/s (QJS); JSON batches 1.0M/s; all loss-free | [ext-frida §1.9] |
| Hooking tiny functions? [rea-runtime §8 #8] | `{target, relocation:'forced'}` works | [ext-frida §3.6] |
| Job Object backstop design? [rea-testing §12] | Per-target jobhost; a hard kill of the parent kills the tree (VERIFIED) | [rea-process §7 H, §8] |
| Emulation backend: Python bridge or a Node binding? [rea-cli §11] | The Python bridge prototype works. No maintained Node binding is known (BELIEVED) | [ext-backends §9, §10 Q8] |
| Can Frida capture enough state for dump-backed emulation? [ext-backends §10 Q3] | Whole module images in milliseconds, ranges and malloc ranges, TEB via `gs:[0x30]`. The policy for uncaptured memory is still open | [ext-frida §3.2, §3.14]; [ext-backends §9.11] |

### 5.3 Open questions that need a user or product decision

1. **Package name.** Plain `bea` on npm is very likely taken (unverified). Candidates: `bea-agents`, `bea-mcp`; the
   bin stays `bea` [rea-cli §11].
2. **D5, the meaning of `readOnlyHint`.** Ignore BEA's own ledger writes (proposed) or follow REA's strict rule
   [rea-mcp §9.2]?
3. **Gating policy.** Should `write_memory`, `override_function` and `run_script` be opt-in through configuration,
   and `call_function` opt-in only for attached targets (proposed)? Or rely on client approval alone, as REA does
   [rea-cli §11]?
4. **REA interop depth.** Emit REA-importable Evidence projections? Accept REA Evidence (inline or bundle) as
   `map_address` input and check `subject.digest.sha256` [rea-evidence §13 Q6, Q7]?
5. **Anti-cheat and protected targets.** Out of scope for v1. Check the anti-cheat status of the motivating game
   before writing any attach guidance for it [rea-cli §11]; [ext-frida §4].
6. **Elevation policy.** Elevated targets, and any later TTD use (which needs admin) [ext-backends §10 Q6].
7. **Python provisioning and licensing.** A uv-managed venv under BEA's data directory, created with approval
   (proposed), or the user's Python? Pin unicorn at exactly 2.1.4? Unicorn license review [ext-backends §10 Q1, Q2].
8. **MSVC toolchain.** Install the VS "Desktop development with C++" workload plus a Windows SDK so that MSVC/PDB
   fixtures (closer to real game binaries) build locally, or keep MSVC to CI only [rea-testing §12]?
9. **WoW64 in v1?** [rea-cli §11]; [ext-backends §2.5].
10. **Owned-target policies.**
    - When the root exits with stragglers: kill them (current default) or keep the tree?
    - `keep_alive` and re-adoption across server restarts?
    - Forward target stdin?

    [rea-process §13 Q1–Q3]
11. **CLI framework.** Incur 0.6.1 (TOON, `--llms`, `--schema` for free, but it pulls
    `@modelcontextprotocol/server 2.0.0-alpha.4`) or a hand-rolled `parseArgs` plus `@toon-format/toon`
    [rea-cli §9.3]?
12. **HTTP transport or persistent CLI sessions in v1?** Proposed: no; scenario files instead [rea-cli §11].
13. **Milestone order.** Live-first (as drafted in §6) or emulation-first? The user's current workflow is static
    analysis plus Unicorn harnesses [ext-backends §3].
14. **Ledger durability and quotas.**
    - fsync per batch, and how large a loss window is acceptable?
    - Default byte quotas for the ledger, blobs, each stream, and events per second?
    - Configurable at runtime, or fixed with REA-style "no runtime override" sentences?

    [rea-evidence §13 Q4]
15. **Maximum blocking time per call.** Proposed: `wait` ≤ 60 s, so Codex `tool_timeout_sec = 180`. Claude Code's
    timeout is believed to come from `MCP_TOOL_TIMEOUT` [rea-cli §11].
16. **Text format inside MCP results.** JSON, as REA does, or TOON, as frida-mobile does? Measure first
    [rea-mcp §1.6]; [ext-landscape §1.3, §12.2].

### 5.4 Open technical questions (lab work before committing)

| # | Question | Source |
|---|---|---|
| L1 | Root cause of the `stdio:'pipe'` slowdown at 4+ targets; does Path 2 avoid it? Report it upstream? | [rea-testing §12] |
| L2 | Precision of Frida's `started` against `GetProcessTimes`; identity rules for attached targets | [ext-frida §1.3]; [rea-evidence §13 Q1] |
| L3 | Agent exception handler versus `DIE_ON_UNHANDLED_EXCEPTION` ordering; `handler-only` versus the target's own SEH/VEH | [rea-process §11 #8]; [rea-runtime §19 Q2] |
| L4 | Can several `Process.setExceptionHandler` callers coexist, or must there be one dispatcher? | [proposal] (§2.8) |
| L5 | PDB symbolization through dbghelp; symbol server without `symsrv.dll` | [ext-frida §8] |
| L6 | drcov v2 round trip into Lighthouse or Cartographer | [ext-frida §8]; [ext-landscape §9] |
| L7 | `onCallSummary` losses; the missing final message in the V8 CModule-ring run | [ext-frida §8] |
| L8 | Path 2 (CREATE_SUSPENDED + attach) fidelity with TLS callbacks, anti-debug, .NET | [rea-process §8.3] |
| L9 | WoW64 injection from 64-bit Frida | [rea-runtime §19 Q5] |
| L10 | Linux Frida-spawn containment under a reaper | [rea-process §13 Q4] |
| L11 | Self-job alternative: the server puts itself in a kill-on-close job | [rea-testing §12] |
| L12 | Shutdown policies of real MCP clients (Claude Code, Codex) compared with the SDK's 2 s | [rea-testing §12] |
| L13 | Unit-testing the agent: bundle it with a fake `Process`/`Memory` API, or acceptance only? | [rea-testing §11.5] |
| L14 | Unicorn on MSVC game code: /GS, CFG, SEH, delay-load, statically linked CRT math | [ext-backends §2.5] |
| L15 | Dump-backed sessions: capture granularity; fault or lazy fetch on uncaptured memory | [ext-backends §10 Q3] |
| L16 | Frida injection on GitHub `windows-latest` runners (Defender) | [rea-testing §12] |
| L17 | Is `PatternCompiler` usable for struct views? Is `Worker` usable for heavy agent jobs? | [ext-frida §8] |

---

## 6. Draft tool catalog

### 6.0 Conventions [proposal]

- **Names.** snake_case verbs with no `bea_` prefix; clients already namespace by server. The one exception is
  `bea_status`, which avoids a generic `status`.
- **Sessions.** `session_id` is a UUID returned by `spawn_process`, `attach_process` or `emu_open`. Live and
  emulation sessions share one manager, so `session_status`, `close_session`, `read_memory` and `disassemble`
  accept either kind; the bridge implements `mem.read` and `mem.disassemble` [ext-backends §9.4].
- **Address input.** One `address` string:
  - `0x7ff6…` for a runtime VA;
  - `module.exe+0x1760` for module+RVA;
  - `module.exe!export` for an export.

  Alternatively, `static_va` plus an optional `static_base` (defaulting to the preferred base from the on-disk PE)
  and `module`. A refine requires exactly one form. Root schemas stay flat [rea-mcp §3.1]; the `module+0x` form
  follows frida-mobile [ext-landscape §1.3].
- **Address output.** `{va, module, rva, static_va, static_base, static_base_source: pe-header | caller |
  rea-evidence, module_map_id, image_sha256}` on every address [ext-landscape §13]; [rea-evidence §10.2].
- **Lifetimes.** Every instrument has a bounded `duration_ms` and `max_events`/`max_hits`, plus an optional
  `sample`. Lifetimes are visible in `session_status` [ext-landscape §12.4].
- **Bulk data.** `detail: summary|complete`; `offset`/`limit` → `next_offset` and `total`. Bulk goes to blobs or
  files with `{path, bytes, sha256}`.
- **Results.** The compact envelope of §1.5. Target-derived results carry `_meta.provenance.untrusted_content`.
- **Effect classes**, the five requested:
  - **observe**: no target change beyond the already-loaded agent; may append to BEA's ledger;
  - **execute-target**: target code runs;
  - **instrument**: reversible observation changes (agent, hooks, debug registers, guard pages, Stalker);
  - **mutate-target**: changes target state or semantics, or kills it;
  - **write-files**: writes caller-visible files.
- **Flag abbreviations** (§1.4): RM readsTargetMemory, IJ injectsCode, IN instrumentsTarget, WM
  writesTargetMemory, EX executesTargetCode, SU suspendsTarget, LP launchesProcess, KP killsProcess, WF
  writesFilesystem, DD mayDiscardData, Id idempotent. `mutatesSession` is set on almost every tool and is left out
  of the formula under D5.
- **Derived hints**: RO readOnly, DE destructive, IP idempotent, OW openWorld, using the §1.4 formula.
- **Phases**: P1 is the live core (20 tools), P2 adds depth (12), P3 is gated or extended (4).

### 6.1 A. Sessions, discovery and lifecycle (7)

| Tool | Purpose (one line) | Effect class | Flags | Hints | Phase | Notes |
|---|---|---|---|---|---|---|
| `bea_status` | Report backend availability (frida binding and local device, jobhost probe state, emulator bridge), gates, limits, live sessions and their instrumentation inventory | observe | Id | RO, IP | P1 | Needs no target, so it is `bea mcp doctor`'s call [rea-cli §6.2]. Reports cached load failures [rea-runtime §3] |
| `list_processes` | List local processes (pid, name, path, ppid, start time, user) with a name filter and paging; never attaches | observe | Id | RO, IP | P1 | Uses `enumerateProcesses` with scope `metadata`; converts BigInt `ppid`; never used as a liveness check [ext-frida §1.3] |
| `spawn_process` | Launch a program suspended under BEA ownership (jobhost job), attach, load the BEA agent and confirm `ready`. Returns `session_id`, process instance `pi_` and module map `mm_`. The target stays paused until `resume_process` | instrument | LP, SU, IJ | OW | P1 | Path 1 sequence (§3.1). argv/env stored as counts and basenames [rea-evidence §10.10]. stdout/stderr captured head+tail. Max 3 piped targets |
| `attach_process` | Attach to a running pid the user named and load the agent. Returns identity (pid, start time, image path and sha256). BEA will never kill it | instrument | IJ | (none) | P1 | Refuses system-critical or protected processes [proposal; GhostMCP blocklist, ext-landscape §7.2]. Footprint limitation [ext-frida §4] |
| `resume_process` | Resume a paused spawned target once instrumentation is in place | execute-target | EX, Id | DE, IP | P1 | Refused while any script cleanup is pending [rea-runtime §4.6] |
| `session_status` | Liveness, detach reason, exit code (NTSTATUS name), ownership and containment, active effects and instruments with remaining lifetimes, stream counters (recorded and dropped), recent exceptions, output tail | observe | Id | RO, IP | P1 | Cheap poll that is not recorded as Evidence unless `detail:"complete"` [rea-evidence §10.6] |
| `close_session` | End a session. Owned targets are killed through jobhost (unless `keep_alive`); attached targets get effects reverted, the agent unloaded and are detached. Reports per-effect revert status and final target state | instrument, mutate-target | KP, IN, Id | DE, IP | P1 | Kill first for owned targets; reverting before a kill is pointless (§1.8). A failed revert gives `effect_unreverted` and the session is kept for retry [rea-runtime §4.9] |

### 6.2 B. Inspection and address mapping (5)

| Tool | Purpose | Effect class | Flags | Hints | Phase | Notes |
|---|---|---|---|---|---|---|
| `list_modules` | Modules with base, size, path, on-disk sha256, preferred ImageBase from disk and PE timestamp; emits a module-map epoch | observe | RM, Id | RO, IP | P1 | Preferred base read from the file, not memory [ext-frida §3.14] |
| `list_module_symbols` | Exports, imports (with IAT slot) and `.pdata` function ranges for one module (live or an on-disk PE); filter and paging | observe | RM, Id | RO, IP | P1 | Names come from the PE or from REA, never from `DebugSymbol` [ext-frida §3.12] |
| `list_memory_ranges` | Memory map: base, size, protection, module attribution, optional malloc ranges; filter by protection or module; coalesce | observe | RM, Id | RO, IP | P1 | Attribution is done by BEA because Windows has no `file` field [ext-frida §3.2] |
| `list_threads` | Threads with id, entry routine as module+RVA, optional register subset (vector registers off by default) | observe | RM, Id | RO, IP | P2 | `state` is unreliable and is reported as a limitation [ext-frida §3.13] |
| `map_address` | Convert in a batch between runtime VA, module+RVA and static VA (with an explicit static base or the on-disk preferred base). Checks the image hash, and optionally that N bytes in the file at that RVA equal live memory | observe | RM, Id | RO, IP | P1 | Derived Evidence linking the module map and any static Evidence. A hash mismatch makes the result `inferred` [rea-evidence §10.2]. A pure-arithmetic mode works with no session (CLI `bea rebase`) |

### 6.3 C. Memory and code (4)

| Tool | Purpose | Effect class | Flags | Hints | Phase | Notes |
|---|---|---|---|---|---|---|
| `read_memory` | Bounded read (≤64 KiB inline, larger into a blob) as hex/base64 or typed values (u8–u64, f32/f64, ptr, utf8/utf16) with optional pointer-chain dereference. Reports `returned_bytes` and `complete` | observe | RM, Id | RO, IP | P1 | An access violation stops the read [ext-frida §3.3]. Explicit-literal redaction checks UTF-8 and UTF-16LE spellings [rea-evidence §10.10] |
| `disassemble` | Disassemble N instructions or a whole `.pdata` function, using the original bytes where BEA has hooked. RIP-relative operands are resolved to absolute and static addresses | observe | RM, Id | RO, IP | P1 | Gotcha 26 and the hooked-`jmp` issue [ext-frida §3.6, §3.12] |
| `dump_memory` | Dump a module image (mapped layout) or a range to a content-addressed blob with sha256. Optionally captures regions plus the thread/TEB context for a dump-backed emulation session | observe, write-files | RM, WF | (none) | P2 | Never overwrites. Layout note [ext-frida §3.14]. Feeds `emu_open` [ext-backends §9.11] |
| `write_memory` | Write bytes or typed values (code via `patchCode`). Records an Effect with the before-bytes for revert, and reads back to verify | mutate-target | WM | DE | P3, gated | Off unless opted in [ext-landscape §1.3]. Read-back avoids "bool means submitted" [ext-landscape §2.2] |

### 6.4 D. Cheat-Engine-style scanning (3)

| Tool | Purpose | Effect class | Flags | Hints | Phase | Notes |
|---|---|---|---|---|---|---|
| `scan_memory` | Start a named scan handle over filtered ranges: exact value (int, float/double with epsilon, bytes with wildcards, string), unknown-initial snapshot, or pointers-to (`findPointers`). Returns only `{scan_id, count}` | observe | RM | RO | P2 | `scanSync` for exact, `findPointers` for pointers, CModule for tolerance [ext-frida §3.4]. Snapshots live in BEA's state directory |
| `scan_next` | Narrow a scan: exact, changed, unchanged, increased, decreased, increased_by, decreased_by, between (with epsilon). Returns the remaining count | observe | RM | RO | P2 | Re-reads the stored hit list [ext-frida §3.4]. Scans run as background jobs because of the single JS thread [ext-frida §1.7] |
| `scan_results` | Page a scan's hits (offset, limit, next_offset, total) with current values and all address forms | observe | RM, Id | RO, IP | P2 | Pointer scan with depth and stability scores is deferred [ext-landscape §7.2] |

### 6.5 E. Instrumentation and recordings (7)

| Tool | Purpose | Effect class | Flags | Hints | Phase | Notes |
|---|---|---|---|---|---|---|
| `hook_function` | Install a bounded observation hook. Typed Win64 argument specs (int/ptr registers, xmm f32/f64 by slot, stack slots, dereferences and struct fields), return capture (rax or xmm0), ACCURATE backtrace as module+RVA, lifetime and sampling. Calls stream into a recording | instrument | IN | (none) | P1 | Tiny functions retry with `relocation:'forced'`; on failure, `instrumentation_failed` suggests watch, Stalker or the caller site [ext-frida §3.6]. Call `Interceptor.flush` after install, use a `detached` guard, invalidate Stalker if a thread is followed |
| `watch_memory` | Non-breaking "what reads/writes this address". `method:"debug-register"`: ≤4 slots, validated size and alignment, all threads plus new threads, writer recovered from the trap-after pc, disarmed in the handler. `method:"page-guard"`: MemoryAccessMonitor, all threads, exact instruction, filtered by address. Hits stream into a recording | instrument | IN | (none) | P2 | Mechanics VERIFIED [ext-frida §3.9, §3.10]. Hit record: tid, writer instruction (all address forms, disassembly), register subset. CE-bridge style [ext-landscape §7.1] |
| `trace_execution` | Stalker recording on chosen threads for a bounded window. `mode: coverage` (compile events), `block_counts` (CModule transform) or `calls` (summary). Queue tuned before `follow` | instrument | IN | (none) | P2 | Gotchas 12–15. Excludes or warns on hooked code [ext-frida §3.8] |
| `wait` | Block up to `timeout_ms` (≤60 s) until a handle's condition holds: N hits, recording ended, process exited, scan or batch done. Running out of time returns a poll result, and reading never consumes the stop | observe | Id | RO, IP | P1 | glslang semantics [ext-landscape §3.3] |
| `stop_instrumentation` | Remove a hook, watch, trace or override by handle (or all of them), verify the revert, and finalize the recording's manifest Evidence | instrument | IN, Id | IP | P1 | Disarm debug registers through the handler [ext-frida §3.9]. Manifest with drop counts [rea-evidence §10.6] |
| `query_events` | Query or aggregate a recording (hook calls, watch hits, trace blocks, exceptions, stdout): filters, `group_by` (caller, writer pc, thread, argument value), offset and limit | observe | Id | RO, IP | P1 | Derived Evidence linked to the manifest [rea-evidence §10.6]. "Not observed in the window" is not absence |
| `export_coverage` | Write a drcov v2 file (module-relative) plus a per-function hit summary from a trace or emulation coverage recording | write-files | WF, DD, Id | DE, IP | P2 | drcov layout is BELIEVED [ext-landscape §9]; round trip untested (L6). Refuses an existing path unless `overwrite` |

### 6.6 F. Execution and modification (3)

| Tool | Purpose | Effect class | Flags | Hints | Phase | Notes |
|---|---|---|---|---|---|---|
| `call_function` | Call a target function in-process via `NativeFunction` (Win64). Typed arguments including f32/f64 `bits`, buffers and struct scratch copies; typed return; thread choice (agent thread or `runOnThread(tid)`); faults returned as a result status; optional per-call block coverage; batch vectors | execute-target, mutate-target | EX, WM | DE | P1 | Allowed on owned targets; opt-in for attached ones [proposal, D16]. Records an irreversible `function-called` Effect that taints the instance [rea-evidence §10.5]. Mechanics [ext-frida §3.7] |
| `override_function` | Change behaviour at a function for a bounded lifetime: rewrite arguments or return (including xmm0), or replace it with a constant return. A reversible Effect | instrument, mutate-target | IN, WM | DE | P3, gated | Built on Interceptor modify/replace [ext-frida §3.6]. Seen elsewhere as `replace_function` [ext-landscape §1.4] |
| `run_script` | Escape hatch: run caller-written Frida JS in an isolated script for a bounded duration, with bounded message capture | execute-target, instrument, mutate-target | IJ, IN, WM, EX | DE | P3, gated | REA's `load_frida_script` capture rules [rea-runtime §5]. Off by default [ext-landscape §1.3]. Shares the agent's JS thread [ext-frida §1.7] |

### 6.7 G. Emulation and differential testing (3)

| Tool | Purpose | Effect class | Flags | Hints | Phase | Notes |
|---|---|---|---|---|---|---|
| `emu_open` | Open a Unicorn session from an on-disk PE64 or from a `dump_memory` capture. Runs the ISA scan (cached by sha256), sets up import models and FP environment, and returns `session_id` (kind `emulation`) with image identity and loader deviations | observe (sandboxed emulator, no target effect) | (none) | RO | P2 | [ext-backends §9.4]. The bridge is a BEA-owned child under jobhost with a memory limit |
| `emu_call` | Emulate a single call or a batch of vectors (columnar). Typed Win64 arguments, `maxInstructions` budget, FPCW/MXCSR, opt-in trace (imports, blocks, memory), isolation `snapshot` or `chain`, named snapshot save and restore. Outcomes are statuses | observe (sandboxed) | (none) | RO | P2 | Results are **derivations** with `deviations[]` [ext-backends §9.7]. Large batches go to a file [ext-backends §10 Q5] |
| `diff_function` | Run the same input vectors through the live oracle and the emulator (or against expected values or a recorded call stream) and compare bit-exactly with ulp statistics. Verdict: `equivalent-on-tested-inputs`, `differ` or `unknown`. Records an unknown on divergence | execute-target, mutate-target (live leg) | EX, WM | DE | P2 | [rea-evidence §10.9]. Expect AVX/FMA and x87 differences [ext-backends §2.4] |

### 6.8 H. Evidence and unknowns (4)

| Tool | Purpose | Effect class | Flags | Hints | Phase | Notes |
|---|---|---|---|---|---|---|
| `get_evidence` | Summary rows with exact filters (instance, operation, predicate, effect, seq window) or one complete record; paging | observe | Id | RO, IP | P1 | Filters only with a summary [rea-evidence §5.2] |
| `export_evidence` | Atomically export the session ledger as a bundle directory or zip (manifest, records.jsonl, blobs, stream chunks or manifests only) | write-files | WF, DD, Id | DE, IP | P1 | Staged, then renamed; refuses an existing path unless `overwrite` [rea-evidence §10.7] |
| `import_evidence` | Validate and import a BEA bundle atomically (data only). Imported live Evidence keeps its IDs and is shown with authority `imported` | observe (ledger only) | Id | RO, IP | P3 | [rea-evidence §10.7] |
| `record_unknown` | Create, or update with `expected_revision` compare-and-swap, a residual unknown: question, severity, supporting and contradicting Evidence, recommended probes, resolution | observe (ledger only) | (none) | RO | P2 | Simplified REA registry. "Verified" needs qualifying authority [rea-evidence §10.8] |

**Totals:** 36 tools, of which P1 = 20, P2 = 12 and P3 = 4. Four of them (`write_memory`, `override_function`,
`run_script`, and `call_function` on attached targets) sit behind opt-in gates. This is within the 25–40 band
[rea-mcp §10].

### 6.9 CLI mapping [proposal from rea-cli §9.3]

| Tier | Commands | Maps to |
|---|---|---|
| Stateless one-shots | `bea ps`; `bea modules <pid>`; `bea symbols <pid or pe-path> <module>`; `bea maps <pid>`; `bea read <pid> <address> <size> [--out]`; `bea disasm <pid> <address>`; `bea dump <pid> <module or range> --out`; `bea rebase --image <pe> --static-va … --runtime-base …`; `bea emulate req.json`; `bea evidence export/import/show` | the same contracts. Help text states that an attach injects the agent and leaves 11 DLLs loaded [ext-frida §4] |
| Scenario | `bea run scenario.json [--evidence-out DIR]` | any session-bound tools as ordered steps with teardown; one bundle out |
| MCP-only (reason: "session state cannot cross CLI processes") | `spawn_process`, `attach_process`, `resume_process`, `session_status`, `close_session`, `wait`, `stop_instrumentation`, `query_events`, `scan_next`, `scan_results`, `hook_function`, `watch_memory`, `trace_execution`, `override_function`, `run_script` | reachable from the CLI only through a scenario |
| Later | `bea mcp --http` (loopback plus token) and `bea call <tool> --input req.json --server …` | (none) |

A contract test asserts that each tool is either CLI-exposed or `mcp-only` with a reason [rea-cli §9.3].

### 6.10 Deliberately excluded or deferred, with reasons

- **Hundreds of fine-grained tools, mega-tools with an action enum, overlapping hook tools.** These cause context
  blowup and confusion [ext-landscape §1.5, §12.4].
- **A raw debugger console (GDB/cdb/LLDB `command`).** Token blowup, and lldb-mcp has no authentication
  [ext-landscape §4.2]; [ext-backends §7]. The only escape hatch is the gated `run_script`.
- **Pointer scanner with depth and stability scores; minidump writing; IAT rebuild.** Defer to v0.2
  [ext-landscape §7.2].
- **TTD record and query; speakeasy init emulation; GDB watchpoint fallback; remote Frida; child gating.** See §3.4;
  the remote mechanics are in [rea-runtime §4.3].
- **MCP prompts, resources, completions and HTTP** in v1. REA uses no resources, and its HTTP mode is about 1,000
  lines of extra logic [rea-mcp §1.11, §10].
- **Kernel, driver or DBVM features.** BSOD risk and admin rights [ext-landscape §7.1].
- **Anti-debug stealth features.** Detect and report instead [ext-landscape §12.4].

---

## Appendix A. Lab artifacts referenced by the notes

| Lab | Path (under `…/scratchpad/bea-lab/`) | Highlights |
|---|---|---|
| rea-mcp | `rea-mcp/sdk-probe.mjs`, `stdio-server.mjs`, `stdio-client.mjs` | SDK 2.3.1 behaviour, progress, cancellation, era negotiation [rea-mcp §8] |
| rea-evidence | `rea-evidence/stream_digest_bench.mjs` | 200k-event canonicalization and hash bench [rea-evidence §8] |
| rea-runtime | `rea-runtime/target.c`, `lab.mjs`, `lab-inherit.mjs`, `stderr-*.txt` | Frida lifecycle, crash, watchpoint, logHandler [rea-runtime §20] |
| rea-process | `rea-process/jobhost.c`, `sleeper.c`, `exp.mjs`, `frida2.mjs`, `hard.mjs` | Job Object containment, Frida adopt [rea-process §7] |
| rea-cli | `rea-cli/toon_demo.mjs` | TOON vs JSON token estimates [rea-cli §4.2] |
| rea-testing | `rea-testing/server.mjs`, `fixtures/bea_fixture.c`, `fixtures/build.mjs`, `tests/*.test.mjs`, `emu_step.py` | BEA-shaped server, 7 Vitest tests, Unicorn differential [rea-testing §10] |
| ext-frida | `ext-frida/fixture.c`, `run_agent.mjs`, `h1..h21*.mjs`, `a1..a17*.js`, `out_*.json` | the Frida 17.23.2 API reference runs [ext-frida intro] |
| ext-backends | `ext-backends/bea_emu_bridge.py`, `bridge_client.mjs`, `probe.py`, `x87diff.py`, `bench.py`, `transcript.jsonl`, `gdbtest/` | Unicorn bridge prototype and probes [ext-backends §1] |
