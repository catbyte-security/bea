# CRITIC — integration review of `bea-design/DESIGN.md`

**Lens:** can 18 parallel agents implement BEA v0.1 from DESIGN.md without editing one another's files, and is everything
owned and wired? Checked: the §4 shared core, ownership and registries, end-to-end wiring of all 37 tools,
dependencies and waves, acceptance testability on this host, scope, and a dry run of the 7 investigations.

**Result:** the design is strong and mostly complete. The §4 core compiles and is internally consistent. Registries
remove most file contention. The weak spots are a set of **cross-WP interfaces that the prose relies on but that are
missing from the frozen ports**, plus **frozen §4 files that contradict one another**. Because §4 freezes after WP0 and
change requests are applied only at wave boundaries (Appendix A.3), each of these would stall a WP for a whole wave.
They are cheap to fix **before** the freeze. A tested patch is supplied (the WP0 delta in §8).

| Severity | Count | IDs |
|---|---|---|
| Blocking (breaks implementation, a WP's "done", or a motivating workflow) | 8 | B1–B8 |
| Important (wrong behaviour, a cross-WP stall, or a wave-plan defect) | 15 | I1–I15 |
| Minor (inconsistency, missing owner, doc drift) | 26 | M1–M26 |

Citations: `[D §x]` = DESIGN.md, `[S1 §x]`…`[S6 §x]` = specialist designs, `[lab]` = my lab
`bea-lab/design-critic-integration/` (absolute: `<scratch>/bea-lab/design-critic-integration/`).

---

## 0. What I verified on this host (VERIFIED unless marked)

| # | Check | Result |
|---|---|---|
| V1 | Extracted all 153 `#### path` + code blocks of [D §4.2] (`extract.mjs`) and diffed them against `bea-lab/design-integrate/ts` | **identical** (153/153, ignoring trailing whitespace); the lab tree also holds S1's HTTP and setup seeds, which are not in §4 |
| V2 | Re-ran the lab's `tsc -p tsconfig.check.json --noEmit` and `tsc -p tsconfig.shared.json` | exit 0 / exit 0, so §4's compile claim holds |
| V3 | Built the call-model tool inputs from the **§4 fragments only** (`measure.mjs`, same zod 4.4.3 instance) and applied the frozen `contractInvariants.test.ts` metrics | `call_function` 5,691 B, depth 10, **7 unbounded numbers**; `emu_call` **8,329 B** (> the frozen 8,192 B cap), depth 10, 8 unbounded; `diff_function` 7,711 B, **depth 11** (> 10), 8 unbounded; `query_events` 1 unbounded. These are lower bounds: no per-field descriptions |
| V4 | Fed the frozen `src/cli/argv.ts` the catalog's `bea map <addresses…>` shape (`argv-probe.mjs`) | `bea map +0x1000 --pid 1234` → `addresses:"+0x1000"`, a string, so the contract rejects it; two positionals → `Unexpected positional argument`. Only repeated `--addresses` flags work |
| V5 | Listed §4 day-0 files that nothing imports (`unimported.mjs`), with knip entries per [S1 §2.5] | 9 files: `instruments/kinds/index.ts`, `cli/output.ts`, `schemas/callModel.ts`, `schemas/shared.ts`, `domain/artifacts.ts`, `evidence/limitations.ts`, `ports/sink.ts`, `shared/apiProfiles.ts`, `shared/binaryLayouts.ts` |
| V6 | Line widths of §4 files vs `.oxfmtrc.json` printWidth 80 [S1 §2.5] | `agentProtocol.ts` has 43 lines > 120 chars, `emuProtocol.ts` 41, `ports/evidence.ts` 22, `agentErrorMap.ts` 18, `config.ts` 18 … The lab never ran oxfmt, oxlint or knip (none are installed in `design-integrate/ts`) |
| V7 | Host: gcc 16.1.0 WinLibs, objdump 2.46.1, `py -3` 3.14.6; S6 fixture sources exist in `bea-lab/design-S6-catalog/fixtures/` | OK. `fixtures/emu/live_fixture.c` and `bea_emu_fixture.c` **do not exist anywhere** yet |
| V8 | Anti-cheat processes and services on this host (read-only `Get-Process`/`Get-Service`) | `FACEITService` is installed (Stopped, Manual). No AC process is running |
| V9 | **WP0 delta** (§8): applied 35 file changes to a copy of the §4 tree (`wp0delta/`, node_modules by junction) | `tsc` host exit 0, `tsc` shared exit 0; re-measured: **0 unbounded numbers, diff_function depth 10**, sizes 6,452 / 9,159 / 8,529 B (fit 12 KiB); argv probe: `bea map a b --pid N` → `["a","b"]`; the existing §4 tests pass **17/17** under vitest 5.0.3 |

---

## 1. Blocking findings

### B1. Frozen §4 schema fragments fail the frozen §4 invariant test (unbounded numbers)
- **Where:** `contracts/schemas/callModel.ts` (`scalarInputSchema` = `z.union([z.number(), …])`; `distributionSchema.min/max`
  = `z.number()`), and `contracts/schemas/shared.ts` (`whereSchema.value`). `tests/contracts/contractInvariants.test.ts`
  asserts `unboundedNumbers(input) === []` for every tool, and zod's `z.number()` advertises no minimum or maximum.
- **Effect (VERIFIED V3):** every tool that uses these fragments fails `npm test`: `call_function`, `emu_call`,
  `diff_function`, `query_events`, plus `write_memory`, `override_function`, `scan_memory` and `emu_open` patches
  (`value: scalar`). Five WPs (CALL, EMU, HOOK, MODIFY, SCAN) cannot reach "done" [D §9.1 rule 5] without editing WP0
  files.
- **Fix (pick one, before the freeze):**
  - (A, preferred: no schema bytes) Limit the invariant to `type:"integer"`. The S1 rationale was "a bare int
    advertises ±2^53", and non-integer doubles have no such problem.
  - (B, VERIFIED in V9) Bound the doubles: `finiteNumberSchema = z.number().min(-Number.MAX_VALUE).max(Number.MAX_VALUE)`
    used by `scalarInputSchema`, `nullableScalarInputSchema`, `distributionSchema.min/max` and `whereSchema.value`.
    This costs about 70 B per occurrence. If budget is tight (B2), choose A.

### B2. Per-tool input ceilings contradict each other, and the spec'd `diff_function` breaks the depth limit
- **Where:** D-INT-10 / [D §6.0] say 4 KiB per tool and **12 KiB** for `call_function`, `emu_call`, `diff_function`.
  The frozen `contractInvariants.test.ts` caps **every** tool at `8 * 1024`. S5 estimated `emu_call` ≈ 9 KiB and
  `diff_function` ≈ 11 KiB [S5 §8 "Schema budget"].
- **Effect (VERIFIED V3):** `emu_call` is already 8,329 B as a lower bound, so the 12 KiB allowance can never be used.
  `diff_function` as specified in [D §6.2 #33] (`expected.columns: Record<column,(scalar|null)[]>` built with
  `scalarInputSchema.nullable()`) reaches **depth 11** and violates D-INT-10 itself.
- **Fix:** in `contractInvariants.test.ts`, use `MAX_INPUT_SCHEMA_BYTES_DEFAULT = 4 * 1024` with overrides
  `{call_function, emu_call, diff_function: 12 * 1024}`, matching `catalog-budget.json`. In `callModel.ts`, add
  `nullableScalarInputSchema = z.union([num, str, bool, z.null()])` (one `anyOf` level). §6.2 uses it for
  `call_function.args`, `diff_function.expected.columns` and every "(scalar|null)" position. Result (V9): depth 10.
  Also state the S5 trim order as the action when a WP measures above 12 KiB with descriptions.

### B3. No port delivers agent job results or assembled blobs, so `dump_memory` and `emu_open{live_session_id}` cannot be built
- **Where:** [D §5.1] AgentChannel says "`blob` → blob assembler (sha256 recomputed), `job` → job waiters". No port
  exposes either. `LiveSession` has only `agent`, `streams`, `output`, `lastCrash`, `liveness()` and `waitFor()`. The
  `jobStatus` RPC returns `JobInfo` without the result. A `DumpManifest` arrives only inside a `JobMessage`, and its
  regions reference agent `BlobId`s. There is also no port from EMU to DUMP's bundle writer
  (`application/dump/DumpBundleWriter.ts` is DUMP-internal). Yet `emu_open{live_session_id}` must "capture a
  bea.dump/1 bundle" (D-INT-29).
- **Effect:** WP13 cannot turn `dumpStart` output into files (investigation 7). WP14 cannot implement the live-capture
  path (investigation 3, and the WP14 acceptance "dump-backed physics_step equals live"). A `readMemory` loop is a
  possible fallback but diverges from the design.
- **Fix (WP0 delta):** add `LiveSession.jobs: AgentJobsPort` with
  `await(jobId, op, timeoutMs) → AgentJobOutcome {info, result: ScanStatus|DumpManifest|null, error, blobs: Map<BlobId,
  BlobRef|{redacted}|{failed}>}`. SESS implements it: the AgentChannel stores blobs through `EvidenceRuntime.blobs.put`.
  Add `src/ports/dumps.ts` `DumpCapturePort.captureBundle(session, BundleCaptureRequest, op)`, slot
  `BeaServices.dumps`, stub `src/application/dump/createDumpService.ts` (owner DUMP), and inject `dumps` into
  `createEmulatorService`. Exact text in §8.

### B4. `run_script` has no port: WP12 cannot create a user Frida script
- **Where:** [D §5.3] and [D §6.2 #29] say "host-side separate script (never the BEA agent)… fingerprint before/after".
  Only `providers/frida/**` (SESS) may touch Frida objects (module-boundary table). `LiveSession` exposes the typed
  `AgentRpc` only.
- **Effect:** `src/application/modify/RunScriptService.ts` (MODIFY) has no way to call `session.createScript`.
- **Fix:** `LiveSession.scripts: UserScriptPort` with
  `run({source, runtime, durationMs, maxMessages, rpcMethod?, rpcArgs}, op) → {messages, errors, rpcResult?, truncated,
  unloaded}`, implemented by SESS (e.g. `providers/frida/userScript.ts`). MODIFY keeps the gate, the `fingerprint` RPC
  before and after, the `script-run` effect and the `bea.script.run` evidence.

### B5. Emulation sessions cannot be reached by the WPs that own the emulation branches of shared tools
- **Where:** `read_memory`, `disassemble` and `list_modules` (INSPECT, "live + emulation via EmuPort"), `map_address`
  and `list_module_symbols` (ADDR, "sessions live, emulation, none"), and `session_status`'s `emulation` block (SESS).
  `EmuPort` methods take an `EmuSessionHandle {sessionId, generation}`, but no method maps a session id to a handle
  (only EMU's runtime knows the generation). `EmuPort` has no module table and no `session.info`. The integrated
  `ExternalSessionDriver` replaced S3's `status()` with `summary()` and has no detail. [D §9 WP5] says emulation
  address resolution goes "via a resolver hook WP14 fills", but no such hook exists. `composeServices` builds `address`
  **before** `emulator` and never passes it in.
- **Fix (WP0 delta, VERIFIED compile):** `EmuPort.lookup(sessionId) → EmuSessionHandle|null`,
  `EmuPort.modules(h) → EmuModuleView[]` (cached from `OpenResult`), and `EmuPort.info(h, o)` (bridge `session.info`).
  Add `ExternalSessionDriver.detail(level, op) → JsonObject`. `createAddressService` gets `emulator: () => EmuPort`, a
  late-bound getter that `composeServices` fills after composing the emulator.

### B6. Scan and write handles are invisible to the WPs that must wait on, stop, or list them
- **Where:** `wait.ids` accepts `scan_…`; `stop_instrumentation.ids` accepts `scan_…` and `fx_…` ("reverts write
  effects, releases scans"); `session_status` lists `scans[] ≤ 8`. Owners: HOOK (wait/stop) and SESS (status). Scan
  handles, job ids and hit stores live in SCAN's `ScanService`. The mapping from write `fx_` to `write_id` lives in
  MODIFY's `WriteService`. Neither is a `BeaServices` slot. There is also no session-ended notification, so host hit
  stores leak after `close_session`.
- **Effect:** HOOK (wave 4) cannot implement `wait{ids:[scan_…]}` or `stop_instrumentation{ids:[scan_…|fx_…]}`
  without importing other WPs' unfrozen internals. MODIFY lands later still (wave 5). SESS cannot list scans.
- **Fix (WP0 delta):** add `src/ports/handles.ts` with `HandleKindSpec {kind, owns, list, get, doneCondition → WaitCondition|null,
  stop(session,id,op)}` and `HandleRegistry {register, find, list}`. WP0 implements the registry fully, in 20 lines
  (`application/handles/createHandleRegistry.ts`), as slot `BeaServices.handles`. SCAN and MODIFY call
  `app.services.handles.register(…)` from their handler factories. Add `DynamicSessionPort.onSessionEnded(listener)` so
  host stores release state.

### B7. The scenario model cannot express `diff_function`, so investigation 3 and recipe R3 fail WP18/WP17 acceptance
- **Where:** [S1 §7.5 algorithm step 2] says "A step's tier must not be `scenario-target` (spawn, attach, emu_open belong to
  `target`)", and a scenario has exactly one target [D §5.8]. `diff_function` needs `live_session_id` **and**
  `emu_session_id`, and its CLI tier is `scenario` "(reason: needs two sessions)". Session injection only covers a
  field named `session_id`.
- **Effect:** WP18 must run "the seven S6 §1 investigations as `bea run scenario.json`", and WP17 promises "every
  recipe is a passing scenario". Investigation 3 and R3 (oracle → emulate → diff) cannot be written at all.
- **Fix:** allow `emu_open` (and `attach_process`/`spawn_process`, optionally) as **steps** with `save_as`. The runner
  tracks every session it created and tears all of them down. Reference the target as `${target.session_id}`. Injection
  rule: inject `session_id` only when the contract has that field and the step omits it. Never inject
  `live_session_id`/`emu_session_id`; those come from `${…}`. Update the WP15 owner text and the S1 algorithm (annex
  errata, I15).

### B8. WP0's own acceptance (`npm run check` passes) cannot pass as specified
- **Where:** [D §9 WP0 acceptance (1)] requires `generate --check`, `tsc`, oxlint, **oxfmt `--check`**, **knip** and
  test discovery to pass. S1 §2.5 fixes `printWidth 80` and knip "all rules error" with entries
  `main/{mcp,cli,mcpDoctor}.ts` + `agent/index.ts` + scripts + globalSetup.
- **Effect (VERIFIED V5, V6):** byte-for-byte §4 copies violate printWidth 80 on hundreds of lines. Nine day-0 files
  are imported by nothing, and many exports are unused until area WPs land (`isPredicateType`, `USER_VA_MAX`,
  `BINARY_LAYOUTS`, …). Neither tool ran in the integration lab. Every WP's "done" also includes `npm run check`.
- **Fix:** (1) WP0 runs `npm run format` once after copying §4. Frozen means semantically frozen; record the formatter
  version. Alternatively set `printWidth: 120` and accept the reflow. (2) Day-0 knip config:
  `"rules": {"files":"warn","exports":"warn","types":"warn","dependencies":"error"}` plus
  `"ignore": ["src/ports/**","src/shared/**","src/domain/**","src/contracts/schemas/**","src/application/instruments/kinds/index.ts"]`.
  WP18 restores `error` at release (add this to the §10.3 checklist). (3) Add `src/main/mcpHttpEntry.ts` to the knip
  entries; it is reached only through dynamic `import()`.

---

## 2. Important findings

### I1. Acceptance rows create cycles across waves, so early WPs cannot be "done" in their wave
[D §8.4] makes S6 §10.8 normative with "owner = the WP whose tool it is", and [D §9.1 rule 5] defines done as passing
those rows. Many rows exercise tools from **later** waves:

| WP (wave) | Assertion (source) | Needs | Move to / rewrite |
|---|---|---|---|
| WP1 (1) | `get_evidence` "after read and diff"; `record_unknown` "after a diff"; `export_evidence` "after the above" [S6 §10.8] | INSPECT (4), EMU (5) | WP1 asserts on records produced through `Recorder` directly; the tool-chained versions move to WP18 `tests/acceptance/integration/` |
| WP4 (2) | `spawn_process` "after resume, `wait{until:"output"}` READY"; `resume_process` "hook installed before resume → frame==0"; `close_session` "physics_step bytes equal the file in a fresh session"; WP4 card: crash `pc.at` = manifest site | HOOK (4), INSPECT (4), ADDR (3) | use `LiveSession.output.contains` / `waitFor` and raw `readMemory` in SESS tests; the `pc.at` assertion moves to WP5 |
| WP5 (3) | `map_address` "after hooking, `bytes_match` still true; gated write → false"; [D §8.4] "after a write effect still `match` with `own_effects_restored > 0`" | HOOK (4), MODIFY (5) | move to WP7 (hook variant) and WP12 (write variant) |
| WP6 (4) | `disassemble` "with a hook installed … `hooked_bytes_restored:true`" | HOOK (4, sibling) | move to WP7 |
| WP7 (4) | `stop_instrumentation` "a DR watch stopped", "a scan released"; `wait` "a scan id handle" | WATCH (5), SCAN (4, sibling) | move to WP9 / WP10, which consume HOOK's tools |
| WP10 (4) | `scan_next` "after `wait{until:"output","RAMP"}`" | HOOK (4, sibling) | `LiveSession.waitFor({kind:"output-contains"})` in-test, or order WP10 after WP7 |
| WP9 (5) | `export_coverage` "trace, call **and emu** evidence" | EMU (5, sibling) | emu part to WP14 |
| WP11 (4) | 12-vector set "on `live_fixture`" | fixture owned by WP14 (5) | see I8 |

Also add a rule to [D §9.1]: *an acceptance assertion may use only tools of earlier waves, raw agent RPCs, or fakes;
cross-WP assertions live in WP18.* The critical path of 48 d [D §9.2] assumes these WPs finish in their own wave.

### I2. The flattened call model dropped S6's live-struct copy (`from`), which investigation 3 depends on
- S6's `call_function` took `{"type":"struct","from":"0x1f3a5c40","size":512}`. "The host reads struct bytes **once**
  and feeds the identical bytes to both legs" [S6 §1.3; S6 §4.33 algorithm step 2]. The integrated `bufferSchema` has only
  `init_hex | init_fill` [D §4 callModel.ts]. Yet the `call_function` description (S6 text verbatim, [D §6.0]) still
  promises "struct scratch copies (from a live address or hex)", and the normative acceptance row asserts "`from:<car>`
  returns 20.0 exactly" [S6 §10.8].
- Effect: the agent must first `read_memory` 512 B and paste 1,024 hex chars, so investigation 3 is no longer 3 calls.
  Passing the live pointer instead makes the live leg mutate the real object, which breaks the diff.
- **Fix (WP0 delta, VERIFIED compile):** `bufferSchema.init_from?: AddrExpr`, with at most one of
  `init_hex | init_fill | init_from`. Semantics: read `size` bytes once per call. For `diff_function`, read once from
  the live leg when present, else from the emulator through `mem.read`. Add the corresponding sentence to the CALL and
  EMU cards.

### I3. "Duration starts at resume" (S6 A7) cannot be implemented: the agent arms timers at install
- The agent: "Deadline. `setTimeout(() => stop(id,"duration"), duration_ms)`" at install [S4 §5.7]. `Lifetime` has no
  clock option, and `HostPost` is only `ack | flow`. The host side, `RecordingRegistry.startsAtResume/onResumed`, is
  EVID code that has no agent access (it is composed before sessions), so nothing can stop the agent instrument at
  resume + duration.
- Effect: investigation 4 (install `trace_api` on a paused spawn, then resume) loses the install-to-resume delta, and
  an instrument can expire before the target ever runs.
- **Fix (WP0 delta):** `Lifetime.clock?: "install" | "resume"` and `HostPost | {type:"resumed"}`. SESS posts it right
  after `device.resume`. WP3's instrument registry arms "resume" timers on that post. Instrument WPs send
  `clock:"resume"` when `LiveSession.paused`. The registry keeps `ends_in_ms` for display only.

### I4. Generated artifacts owned by WP0 are rewritten by every area WP, which guarantees merge conflicts
`tests/golden/catalog.json`, `docs/tools.md` (and `docs/errors.md`) are `WP0 [gen]`. `npm run check` runs
`generate --check`, so **every** contract change in any area must regenerate and commit WP0's files, in all 12 areas
and in parallel. **Fix:** split the generated slices per area, as `tests/golden/catalog/<area>.json` and
`docs/tools/<area>.md` (each owned by its area WP), plus a WP0 index file that only lists the 12 slices. Alternatively,
declare `[gen]` files "owned by the generator" with a merge rule ("never hand-resolve; rerun `npm run generate`").
Either way, write the rule into [D §9.1].

### I5. Frozen limitation and reason registries force change requests for routine sentences
- `LIMITATIONS` and `REASONS` are WP0-frozen [D §3], but the file comment says "additions … owned by the WP that
  introduces the reason". Sentences the catalog promises are missing: `trace_api`'s six "Limitations always" (direct
  syscalls, brokered actions, children not instrumented, pre-existing handles, payloads, late modules) [D §6.2 #22];
  `spawn_process`'s "argv/env recorded as counts" and "stdin is an open empty pipe"; the Linux `posix-best-effort`
  text [D §5.1]; the crash `pc:null` text [D §5.1].
- Agent `DropReason`s `instrument_cap, agent_memory, ring_overrun, torn_record, decode_error, stopped, per_api_cap` have
  **no** `REASONS` code, and the envelope test requires every emitted reason to be registered [D §8.3].
- **Fix (WP0 delta, VERIFIED compile):** `domain/evidence/limitations/<area>.ts` (12 stubs, one owner each) plus a
  pre-wired `limitations/index.ts`, merged as `LIMITATIONS = {...CORE_LIMITATIONS, ...AREA_LIMITATIONS}`, with a
  collision unit test. Add the missing reason codes and a total
  `DROP_REASON_CODES: {[R in DropReason]: ReasonCode}` map in `coverage.ts`.

### I6. `query_events` cannot page the row streams that emulation, diff and calls produce
[D §6.2 #21] claims "Also pages `emu-batch`, `emu-sweep`, `diff` row streams", but its only input is `recording_id`
(`rec_…`). Those streams are not recordings, and `RecordingKind` has no such kinds. `call_function` batches above
`inline_limit` return a `stream_id` too, but `StreamSourceKind` has no call kind. **Fix:** `query_events` takes exactly
one of `recording_id | stream_id` (`st_` + 64 hex; `streamIdInputSchema` in the delta). Host `ndjson` streams decode
generically: one row per line, fields from the first page. Add `StreamSourceKind "call-batch"` (delta). S5's
`query_events(stream_id)` design [S5 §9.3.3] becomes real.

### I7. CLI and EMU share an interface that is not frozen, and the lint rules forbid the code that must exist
- `bea setup --emulator` uses `EmulatorProvisioner` [S1 §7.9.7], which `src/main/cli.ts` (CLI, **wave 1**) injects from
  `providers/emulator/venvProvisioner.ts` (EMU, **wave 5**). The type is not in `src/ports`.
  **Fix (delta):** `src/ports/provisioner.ts` (path `<BEA_HOME>/emu/venv` per D-INT-28; S1's draft says
  `<BEA_HOME>/venv`) plus a WP0 stub `createEmulatorProvisioner({config})`.
- The lint rule allows `node:child_process` only in `providers/process/**` plus `EmuBridge.ts` and `pythonResolver.ts`
  [D §4.1]. But `venvProvisioner.ts` must run uv, python and pip, and S1's `host:elevation` doctor check runs
  `whoami /groups` [S1 §7.8]. **Fix:** add `venvProvisioner.ts` to the exception list. Have PROC register
  `host:elevation` on `core.doctor` from `bea-jobhost inspect <self>` (which returns `elevated` and `integrityRid`), so
  CLI needs no child process.

### I8. The emulator fixtures are unowned for WP11 and have no build path
`fixtures/emu/{bea_emu_fixture.c, live_fixture.c}` are WP14-owned (wave 5) and **do not exist yet** (V7). WP11's
acceptance (wave 4) runs the S5 §9.6 12-vector set "on `live_fixture`". `build-fixtures.mjs` (WP0) builds only the five
S6 fixtures, and S5 says the emu fixtures are "built in globalSetup" (WP0-owned). **Fix:** WP0 owns and authors both
sources: the ext-frida fixture plus `bea_dispatch`/`bea_vec_sum`, and the ext-backends `fixture.c` plus the S5 §14.2
additions. `build-fixtures.mjs` builds them with S5's flags and manifest invariants. WP14 may extend them by change
request.

### I9. The derived crash report is SESS-internal but must be returned by HOOK's `wait`
`resume_process` and `session_status` (SESS) and **`wait` (HOOK)** all return `crash: CrashReport|null` in tool shape
[D §6.2 #19]. The derivation (`application/sessions/crashDerivation.ts`, which needs the jobhost root exit, the last
report within 2 s, and `describeCode`) is SESS code, and `LiveSession` exposes only the raw agent `lastCrash`.
**Fix (delta):** `LiveSession.crash(op) → DerivedCrash|null`. It is recorded as `bea.process.crash` before it returns,
and has the same fields as `crashReportSchema`.

### I10. `AddressService` cannot fill the `static` form synchronously and cannot verify bytes for other WPs
`describe(space, va): Addr` is synchronous, but `static` needs each module's **preferred** base from the on-disk PE,
which requires I/O (the in-memory header is rewritten by the loader [D §4 agentProtocol `PeFacts.mapped_image_base`]).
`RecordingKindSpec.decode` calls `ctx.frame()` synchronously too. Separately, `hook_function` outputs
`bytes_match_file`, but byte verification exists only inside ADDR's `map_address`.
**Fix (delta):** `AddressService.prepare(space, vas, op)` warms preferred bases and digests; `describe` returns
`static:null` for unprepared modules (documented). Add `AddressService.verify(space, va, len, op) → ByteVerification`
(the S2 §18.3 result shape used by `map_address` rows).

### I11. Frozen `argv.ts` cannot express three documented CLI commands
- **Variadic positional (VERIFIED V4):** `bea map <addresses…>` is broken. **Fix (delta, VERIFIED):** a list-typed
  last positional is variadic, and single values are wrapped in an array.
- **`--pe` dual mode** for `bea symbols` / `bea map` [D §5.8]: session tiers *require* exactly one of
  `--pid/--name/--spawn` (`parseCommandArgs`), so `bea map … --pe-path X` fails with `missing_argument`. **Fix:**
  `CliMapping` gains `offlineField?: "pe_path"`. When it is given, the target requirement is waived and the command
  runs as `oneshot`.
- **`bea script <file.js>`**: the only positional must be an input field, and the field is `source` (the JS text), so
  a path would be executed as code. Also `dump <module or address>` cannot map to one field. **Fix:** an `@file`
  convention in `argv.ts` (`--source @file.js` reads the file), and `dump`'s positional = `module`, with
  `--address/--size` for raw dumps.

### I12. The D-INT-1 anti-cheat heuristic is machine-global and will refuse unrelated targets
`antiCheatSignals.ts` refuses when "running EAC/BattlEye/vgc/FACEIT/… processes" exist anywhere [D §5.1].
`vgc` (Vanguard) runs at boot wherever Valorant is installed. FACEIT is installed on this host (V8). With either
running, **every** spawn and attach, including the gcc fixtures in acceptance runs, is refused unless the user sets
`BEA_ALLOW_ANTI_CHEAT=1`, which then stamps `ANTI_CHEAT_ALLOWED` on all evidence. **Fix:** make the refusal
target-scoped. Use AC directories next to the image or its parent, an AC launcher as the target's parent, and an AC
module already loaded in the target (attach; via jobhost inspect or Frida enumerate). Report global AC services as an
informational `bea_status` note, not a refusal. Acceptance should pin the environment (assert no AC process at test
start, or use a named skip).

### I13. The stream checkpoint "flush barrier" has no path to the agent, and manifest ids are lost
`StreamWriter.checkpoint()` (EVID) is specified as "agent flush → frames up to last seq → seal" [D §5.4], but EVID never
holds a session. `RecordingRegistry.events()` must "checkpoint a live stream first", yet the registry has no agent
access either. `StreamBinder.end()` returns `void` and `CloseReport.streamsFinalized` holds `st_` ids, but
`stop_instrumentation.stopped[].manifest_evidence_id` and `close_session.manifests: ev_[]` must be filled.
**Fix (delta):** `StreamSpec.flush?: (signal) => Promise<void>`, supplied by `StreamBinder.bind` (SESS) and called by
`checkpoint()`; `StreamBinder.end` returns `Result<RecordedEvidence<JsonObject>, BeaError>`. Optionally add
`manifest_evidence_id` to `InstrumentStateView`.

### I14. Session-kind dispatch is left to 10 WPs, so error behaviour will diverge
`ToolContract.sessionKinds` is metadata only. `invokeTool` never checks it, and there is no shared helper for
"admit → `kindOf` → `withSession`/`EmuPort.lookup` → wrong kind/closed/unknown errors". Each area WP will write its own,
with differing codes for "emulation id passed to `hook_function`", tombstones, and `exited` vs `detached`.
**Fix:** a WP0 helper `src/application/sessionAccess.ts`:
`liveOp(app, ctx, sessionId, mode, fn)` and `emuOp(app, ctx, sessionId, fn)`. It returns `session_not_found`,
`invalid_request{wrong_session_kind, expected}`, `target_exited`, and `capability_unavailable(agent-gone)` per
[D §5.1 "Ops per state"], and is enforced by a contract test that every handler of a `session_id` tool uses it.

### I15. The annex errata list is incomplete, and implementers will follow superseded annex text
§8.4 corrects some S6 §10.8 rows but misses these:
- `call_function` "`from:<car>`" (no `from`; I2);
- `emu_open` "`capture` replays with the same sha256" (the `capture` source was removed, D-INT-29);
- `bea_status` "`frida.available`; `jobhost.containment:"proven"`" (the shape is now `backends[]` rows);
- `emu_call` "`trace_blocks`" (now `trace.blocks/coverage`);
- `resume_process` "on an attached target → `invalid_request`" vs [D §6.2 #5] `invalid_state`;
- `get_evidence` "a cancelled `wait` leaves findable partial evidence" (`wait` is a poll and records nothing);
- the S6 §1 investigation inputs, which WP18 must re-express (`emu_open{source:"live",…}`, `diff_function{session_id,args,…}`).

**Fix:** one consolidated "Annex errata" table in Appendix A.

---

## 3. Minor findings

| # | Finding | Fix |
|---|---|---|
| M1 | §4 labels `src/server/createMcpServer.ts` and `src/application/createApplication.ts` "*(stub)*" (generator regex `create[A-Z]…`), while §3 says WP0 `[§4]`. Agents may think another WP owns them. `createApplication.ts` also refers to a non-existent `createServices` | drop the label; fix the comment to `composeServices` |
| M2 | §3 tree omits `src/agent/pure/**` (prefix-owned), `src/application/inspect/**` (WP6) and `tests/golden/{callModel,emu}/**`; shows `application/emu/…diff/` while the WP14 card says `application/diff/**` | update the tree; pick one diff path |
| M3 | `tests/support/drcov.ts` (WP9 acceptance "drcov parses with tests/support/drcov.ts") has no owner | WP9 owns `tests/support/drcov.ts` |
| M4 | `server.json` is a WP0 file with no specified content | specify it (MCP registry manifest) or drop it for the private package |
| M5 | WP18 writes `docs/limitations.md` and `docs/decisions.md` [D §10.3], which WP17 owns | give WP18 ownership of both from wave 6, or have WP17 do a final pass |
| M6 | D-INT-28 puts the ISA cache under `<home>/emu/cache/isa/`, but the `BeaLayout.cacheDir` comment says `<home>/cache` holds "ISA scan results" | fix the comment |
| M7 | `config.json` `python` and `emu.python` add a Python source that F7's order lacks; `PythonStatus.source` has no `"config"` | keep one key, place it after `BEA_PYTHON`, and add `"config"` to the enum (or drop the keys) |
| M8 | `errorSamples.fixture.ts` uses retired handle forms (`sc_0000000000000001`, `hk_…`), and `docs/errors.md` is generated from it | use `scan_0000000a` / `rec_0000000b` |
| M9 | `session_status` abbreviates effect ids (`fx_` + 12 hex), but `stop_instrumentation` requires 64 hex | do not abbreviate, or accept a unique ≥ 12-hex prefix |
| M10 | D-INT-18 says "`mutatesSession` on every tool except `bea_status`", but §6.1 gives `get_evidence` (Id) and `export_evidence` (WF) no MS | align the table or the decision |
| M11 | `diff_function.from_dump_call` and `DumpManifestV1.capture.mode "at_hook"` cannot be produced: `dump_memory.bundle.mode` is `running|suspended`, and §1.3 lists capture-at-hook as a non-goal | drop `from_dump_call` from v0.1 or add the at_hook mode |
| M12 | `WatchRow` has `text` and `regs` but no structured memory operand. `struct_base`/`disp` and "base register written" (S6 R5 `regsAccessed.written`) would need parsing of Intel text | add `mem: {base, index, scale, disp, size, base_written} | null` to `WatchRow` (agent decodes with `Instruction.parse`) |
| M13 | Tool `bool` vs agent `bool8 | bool32` has an unspecified width (Win32 `BOOL` is 4 bytes, C++ `bool` 1) | define `bool` = `bool8` and add `bool32`, or document the mapping per tool |
| M14 | WP10 acceptance "a 1 GiB scan … ≤ 50 ms RPC latency" cannot be produced with `game_sim` (no allocation flag) | add `--ballast-mb N` to `game_sim.c` (WP0 fixture) |
| M15 | Command name `emulate` is both the generated `emu_call` emu-oneshot command and S5's built-in `bea emulate request.json` | keep only one (generated, with `--input request.json`) |
| M16 | `ProcessInfo.platform: "windows"` and `arch: "x64"` are literals, so the "Linux best effort" agent cannot satisfy the protocol | widen to `"windows" | "linux"` or state that Linux is host-only |
| M17 | EVID's "status contributor (usage vs quotas)" has nowhere to put data: `statusOutputSchema` has no storage block and `backends[].id` has no `evidence` | add `storage{run_dir, usage_mb, quotas_mb}` to `statusOutputSchema` |
| M18 | `src/domain/dumpBundle.ts` "verifyDumpBundle" (DUMP) reads a bundle, but `domain/**` may not import `node:fs` | keep the zod schema in domain; put verification in `application/dump/` |
| M19 | A `*.test.ts` under `src/agent/**` would be staged into the frida.Compiler build (filter excludes only `tsconfig.json`) and fail it, yet the vitest `unit` project includes `src/**/*.test.ts` | lint rule "no tests under src/agent", or filter `.test.ts` in `build-agent.mjs` |
| M20 | Factory contract says "no target contact … all lazy" but not "no filesystem writes", while WP15 asserts `bea doctor` creates nothing under BEA_HOME | add "no filesystem writes at construction" to every factory stub comment |
| M21 | D-INT-6 promises a hard-exit safety timer at 1,900 ms, but `runStdio` calls `forceExitAfterMs(code, 500)` only **after** cleanup (worst case about 2.3 s > the SDK's 2 s) | arm `forceExitAfterMs(1, 1900)` when shutdown starts |
| M22 | `notImplementedPort` returns async functions for every property, so sync members misbehave in fakes (`DynamicSessionPort.closing` is truthy; `EvidenceRuntime.literals()` returns a Promise) | throw the `CapabilityUnavailable` BeaError synchronously (`invokeTool.mapThrown` passes BeaErrors through) and document "methods only" |
| M23 | The cap of 16 instruments per session in `bea_status` is enforced nowhere (`RecordingRegistry.create` cannot fail; agent default `max_instruments` = 128) | SESS sends `hello.limits.max_instruments = 16` (agent `ResourceLimit` → `resource_constraint`) |
| M24 | The WP2 card "Provides … `ProcessInspectorPort`" names a type that does not exist (`JobHostFactory.inspect` does) | rename in the card |
| M25 | Several same-name types in different modules (`FunctionRange`, `ModuleInfo`, `HelloResult` in agent vs emu; `CloseReport` in ports vs lifecycle; `SessionSummary` ×2; `ExitKind` ×2) invite wrong imports by parallel agents | prefix the emu ones (`Emu…`) and rename lifecycle's to `LifecycleReport` |
| M26 | Investigation call-count bounds (WP18) ignore scenario sync steps (`wait{until:"output","RAMP"}` in inv. 1) and the now-required `scan_id`. Inv. 5 expects `sym:"crash_write"`, but `sym` is set only for an exact export and gcc's `crashy.exe` exports nothing | count only analysis calls; export the crash functions in `crashy.c` or assert `func` |

---

## 4. §4 shared-core audit

**Type completeness and consistency.** No undefined or dangling types (`tsc` clean, V2). The semantic mismatches that
compile but break implementation are B1–B6, I3, I9, I10 and I13. Notable smaller ones are listed in M12, M13, M16 and
M25.

**Frozen-file contradictions** (two frozen files disagree): B1 (fragments vs invariant), B2 (8 KiB vs D-INT-10), B8
(verbatim vs format/knip), M21 (D-INT-6 vs `runStdio`).

**Registries — is each sufficient so no two WPs edit one file?**

| Registry (WP0) | Pre-wired | Sufficient? |
|---|---|---|
| `contracts/index.ts` (12 areas) | yes | yes |
| `handlers/index.ts` (12 factories) | yes | yes |
| `agent/index.ts` (15 feature files, `_noExtra`) | yes | yes |
| `instruments/kinds/index.ts` (9 kinds) | yes | no for row streams (I6: not kinds; solved by `stream_id`) |
| `services/index.ts` + `composeServices.ts` (8 slots) | yes | **no**: missing `handles` (B6) and `dumps` (B3); emulator late binding (B5) |
| lifecycle / status / doctor (runtime registration) | yes | status lacks a storage slot (M17) |
| `limitations.ts`, `coverage.ts REASONS` | no | **no** (I5) |
| generated golden and docs | no | **no** (I4) |
| `.oxlintrc.json` exceptions | n/a | **no** (I7) |
| `src/cli/shorthands.ts` (HOOK) used by the CLI router (CLI, wave 1) | **not stubbed** | **no**: WP0 must create a stub `expandCliShorthands(contract, argv) => argv` that HOOK fills; CLI calls it from day 1 |

---

## 5. Ownership audit

- **Disjointness:** all directory and file claims in [D §3] and the §9 cards are disjoint. The exceptions are
  sequential handovers (WP0 → INT for `catalog-budget.json` measured values, WP0 stubs → owners) and the overlaps in
  M5 and I4.
- **Unowned planned files:** `tests/support/drcov.ts` (M3), the content of `server.json` (M4), the `run_script`
  provider file (B4), the emu fixtures' build path (I8), and `src/cli/shorthands.ts` day-0 content (§4 table).
- **Owned but missing from the tree:** M2.
- **Mislabelled:** M1.

---

## 6. End-to-end wiring of the 37 tools

Hop owners: contract + handler = area WP; app service / port; provider; agent RPC (`agentProtocol.ts`) or bridge
method (`emuProtocol.ts`). Status refers to the findings.

| # | Tool | Area WP | Service / port hops | Agent RPC / bridge | Status |
|---|---|---|---|---|---|
| 1 | bea_status | SESS (seed WP0) | StatusRegistry ← SESS, PROC, EMU contributors | — | OK (M17) |
| 2 | list_processes | SESS | `DynamicSessionPort.processes` | Frida metadata enum | OK |
| 3 | spawn_process | SESS | spawn → JobHostFactory.adopt (PROC) → InstanceRegistry/EffectRegistry (EVID) → RecordingRegistry built-ins | hello, listModules | OK (I12; acceptance I1) |
| 4 | attach_process | SESS | attach → jobhost inspect/watch | hello, listModules | OK (I12) |
| 5 | resume_process | SESS | resume → `RecordingRegistry.onResumed` → crash derivation | post `resumed` (I3) | **I3** |
| 6 | session_status | SESS | list/kindOf/external, EffectRegistry.active, RecordingRegistry.list, **scans**, **emulation detail** | status | **B6, B5** |
| 7 | close_session | SESS | close / ExternalSessionDriver.close | shutdown | OK (I13 manifests; B6 onSessionEnded) |
| 8 | list_modules | INSPECT | withSession; pe.images (preferred base); **EmuPort modules** | listModules | **B5** (emulation) |
| 9 | list_memory_ranges | INSPECT | withSession | listRanges | OK |
| 10 | list_threads | INSPECT | withSession; AddressService.describeCode | listThreads | OK |
| 11 | read_memory | INSPECT | withSession; **EmuPort.lookup + readMemory** | readMemory, readTyped; `mem.read` | **B5** (emulation) |
| 12 | disassemble | INSPECT | withSession; **EmuPort** | disassemble (+ AGENT disasm core); `mem.disassemble` | **B5**; acceptance I1 |
| 13 | list_module_symbols | ADDR | PeImageCache, AddressService (emulation via **B5**) | listImports | **B5** (emulation) |
| 14 | map_address | ADDR | AddressService, EffectRegistry.originalBytes, UnknownRegistry | readMemory, resolveTargets, listModules | OK live; **B5** emulation; acceptance I1 |
| 15 | scan_memory | SCAN | ScanService + **HandleRegistry** | scanStart, jobStatus/scanStatus (or `jobs.await`, B3) | OK after B6 |
| 16 | scan_next | SCAN | same | scanNext | OK |
| 17 | scan_results | SCAN | same; AddressService.prepare/describe | scanResults | OK (I10) |
| 18 | hook_function | HOOK | StreamBinder.bind, RecordingRegistry.create, EffectRegistry.apply, AddressService(.verify) | hookInstall | OK (I10) |
| 19 | wait | HOOK | waitFor; RecordingRegistry; **HandleRegistry**; **LiveSession.crash** | — | **B6, I9** |
| 20 | stop_instrumentation | HOOK | RecordingRegistry.end; StreamBinder.end; **HandleRegistry.stop** (scanClose / revertWrite in owner kinds) | instrumentStop | **B6, I13** |
| 21 | query_events | HOOK | RecordingRegistry.events + QueryEngine; **StreamStore.reader(st_)** | flush via `StreamSpec.flush` | **I6, I13** |
| 22 | trace_api | BEHAV | as hook; API_KIND | profileInstall | OK (I3, I5) |
| 23 | watch_memory | WATCH | as hook; WATCH/POLL kinds | watchInstall (+ AGENT dispatcher hooks) | OK (M12) |
| 24 | trace_execution | WATCH | as hook; TRACE kind | traceStart | OK |
| 25 | export_coverage | WATCH | RecordingRegistry.events; EvidenceQuery + BlobStore | — | OK |
| 26 | call_function | CALL | OracleCallPort (CALL), AddressService; row stream "call-batch" | callFunction | OK (I2, I6) |
| 27 | write_memory | MODIFY | WriteService + **HandleRegistry kind "write"** | writeMemory / revertWrite | OK after B6 |
| 28 | override_function | MODIFY | RecordingRegistry (override kind) | overrideInstall | OK |
| 29 | run_script | MODIFY | RunScriptService → **LiveSession.scripts** | fingerprint | **B4** |
| 30 | dump_memory | DUMP | PE/bundle writers → **LiveSession.jobs** | dumpStart (+ blobs), captureThreadState | **B3** |
| 31 | emu_open | EMU | EmuPort.open, registerExternal, **DumpCapturePort** | `session.open` | **B3** |
| 32 | emu_call | EMU | EmuPort.call/batch/sweep, AddressService (emulation **B5**) | `emu.call/batch/sweep` | OK after B5 |
| 33 | diff_function | EMU | OracleCallPort + EmuPort + RecordingRegistry.events | callFunction; `emu.batch` | OK after B5 (B7, I2) |
| 34 | get_evidence | EVID | EvidenceQuery | — | OK |
| 35 | export_evidence | EVID | BundleService | — | OK |
| 36 | import_evidence | EVID | BundleService | — | OK |
| 37 | record_unknown | EVID | UnknownRegistry | — | OK |

Every hop has an owning WP once B3–B6 are applied. Tests are owned per area (`tests/{unit,boundary/mcp,acceptance}/<area>`).

---

## 7. Dependencies, waves, WP0 sufficiency, testability, scope

- **Build-level DAG:** acyclic as drawn [D §9.2]. Ports plus fakes let waves start early.
- **Acceptance-level cycles:** see I1. Also note that WP17's "`bea doctor --skill` after `bea setup --skill`" depends
  on WP15 (same wave), so order them inside the wave.
- **WP0 sufficiency:** not sufficient as written. It needs the delta in §8 (B3–B6, I3, I5, I6, I7, I9, I10, I13), the
  config fixes (B8, I7), the invariant fixes (B1, B2), the argv fix (I11), the emu fixtures (I8), and a
  `cli/shorthands.ts` stub. All of this is about 1 extra day for WP0, against a likely stall of one full wave per
  missing port under A.3.
- **Change procedure:** A.3 makes WP18 the integrator "at each wave boundary", but WP18 is scheduled only in wave 6
  (5 d). Name an integrator role that is active from wave 1, with time budgeted per wave.
- **Testable on this host (gcc only, no MSVC):** yes for every listed lane, with these caveats.
  - L-S6-6 (Ghidra/REA loads the realigned PE) is a manual receipt.
  - The 1 GiB scan needs a ballast fixture (M14).
  - The anti-cheat heuristic makes acceptance environment-dependent (I12; FACEIT is installed here).
  - The native-tier throughput criterion is hardware-dependent (a fallback is specified).
  - MSVC-specific code paths are untested, which matters for the motivating game: `.pdata` chains, `__chkstk`
    prologues for hooking/relocation, CFG thunks, and VEX use (R9, OI-3).
- **Scope realism:** 37 tools at about 115 d is ambitious. WP3 (7 d: dispatcher, UEF/exit flush, events/flow control,
  CModule core, threads, StalkerCo, 13 core RPCs), WP4 (8 d) and WP14 (15 d) are each optimistic. With I1, the 48 d
  critical path stretches, because WP4 and WP5 cannot be "done" until waves 4–5. **Recommend a declared cut line**
  with triggers. If WP14 exceeds 15 d, ship image-backed emulation and defer `emu_call.sweep`,
  `diff_function.from_dump_call`/`from_recording`, and dump-backed sessions to v0.1.1. P3 tools (`write_memory`,
  `override_function`, `run_script`, `import_evidence`) can slip without touching the motivating workflows.

---

## 8. The WP0 delta (apply before freeze; VERIFIED: tsc host + shared exit 0, vitest 17/17)

Full unified diff (35 files, 908 lines):
`<scratch>/bea-lab/design-critic-integration/wp0delta.patch`
(the patched tree is in `…/design-critic-integration/wp0delta/src`). Key interfaces, verbatim from the compiled delta:

```ts
// src/ports/sessions.ts (additions)
export interface AgentJobOutcome {
  readonly info: JobInfo;
  readonly result: ScanStatus | DumpManifest | null;
  readonly error: AgentError | null;
  readonly blobs: ReadonlyMap<string, BlobRef | { readonly redacted: true } | { readonly failed: string }>;
}
export interface AgentJobsPort {
  await(jobId: string, op: OperationContext, timeoutMs: number): Promise<Result<AgentJobOutcome, BeaError>>;
}
export interface UserScriptRequest {
  readonly source: string; readonly runtime: "qjs" | "v8"; readonly durationMs: number; readonly maxMessages: number;
  readonly rpcMethod?: string; readonly rpcArgs: readonly JsonValue[];
}
export interface UserScriptOutcome {
  readonly messages: readonly JsonValue[];
  readonly errors: readonly { readonly description: string; readonly line: number | null }[];
  readonly rpcResult?: JsonValue; readonly truncated: boolean; readonly unloaded: boolean;
}
export interface UserScriptPort { run(req: UserScriptRequest, op: OperationContext): Promise<Result<UserScriptOutcome, BeaError>> }
export interface DerivedCrash {            // == contracts/schemas/shared.ts crashReportSchema
  readonly type: string; readonly ntstatus: string | null; readonly thread_id: number | null; readonly pc: Loc | null;
  readonly insn: string | null; readonly memory: { readonly op: "read" | "write" | "execute"; readonly address: string } | null;
  readonly registers: Readonly<Record<string, string>>; readonly backtrace: readonly Loc[];
  readonly first_chance_count: number; readonly evidence_id: EvId | null;
}
// LiveSession += readonly jobs: AgentJobsPort; readonly scripts: UserScriptPort;
//                 crash(op: OperationContext): Promise<Result<DerivedCrash | null, BeaError>>;
// ExternalSessionDriver += detail(level: "summary" | "complete", op: OperationContext): Promise<Result<JsonObject, BeaError>>;
// DynamicSessionPort += onSessionEnded(listener: (event: SessionEndedEvent) => void): () => void;
export interface SessionEndedEvent {
  readonly sessionId: SessionId; readonly kind: "live" | "emulation"; readonly reason: "closed" | "exited" | "detached" | "shutdown";
}
// StreamBinder.end(...) now returns Promise<Result<RecordedEvidence<JsonObject>, BeaError>>

// src/ports/emu.ts (additions)
export interface EmuModuleView {
  readonly name: string; readonly path: string | null; readonly sha256: string | null; readonly base: Hex;
  readonly size: number; readonly preferredBase: Hex | null; readonly primary: boolean;
}
// EmuPort += lookup(sessionId: string): EmuSessionHandle | null;
//            modules(h: EmuSessionHandle): readonly EmuModuleView[];
//            info(h: EmuSessionHandle, o: EmuRequestOptions): Promise<Result<OpenResult & { readonly state: SessionStateInfo }, BeaError>>;

// src/ports/address.ts (additions)
export interface ByteVerification {
  readonly status: "match" | "mismatch" | "partial" | "not-applicable" | "skipped";
  readonly compared: number; readonly equal: number; readonly excluded_loader: number; readonly own_effects_restored: number;
  readonly differences: readonly { readonly rva: Hex; readonly size: number; readonly class: "unexplained" | "foreign-or-agent-patch" }[];
}
// AddressService += prepare(space, vas: readonly bigint[], op): Promise<void>;
//                   verify(space, va: bigint, len: number, op): Promise<Result<ByteVerification, BeaError>>;

// src/ports/handles.ts (new; registry implemented by WP0 in src/application/handles/createHandleRegistry.ts)
export type HandleKind = "scan" | "write";
export interface HandleView { readonly id: string; readonly kind: HandleKind; readonly sessionId: SessionId;
  readonly state: "running" | "ready" | "active" | "released" | "reverted" | "failed"; readonly summary: JsonObject }
export interface HandleStopOutcome { readonly id: string; readonly kind: HandleKind;
  readonly status: "released" | "reverted" | "already_ended" | "revert-failed" }
export interface HandleKindSpec {
  readonly kind: HandleKind; owns(id: string): boolean; list(sessionId: SessionId): readonly HandleView[];
  get(id: string): HandleView | undefined; doneCondition(id: string): WaitCondition | null;
  stop(session: LiveSession, id: string, op: OperationContext): Promise<Result<HandleStopOutcome, BeaError>>;
}
export interface HandleRegistry { register(spec: HandleKindSpec): () => void; find(id: string): HandleKindSpec | undefined;
  list(sessionId: SessionId): readonly HandleView[] }

// src/ports/dumps.ts (new; stub src/application/dump/createDumpService.ts owned by WP-DUMP)
export interface DumpCapturePort {
  captureBundle(session: LiveSession, req: BundleCaptureRequest, op: OperationContext): Promise<Result<BundleCaptureResult, BeaError>>;
}
// src/ports/provisioner.ts (new; stub src/providers/emulator/venvProvisioner.ts owned by WP-EMU) — EmulatorProvisioner

// src/application/services/index.ts: BeaServices += handles: HandleRegistry; dumps: DumpCapturePort
// src/main/composeServices.ts: address(evidence, pe, emulator: late getter) … handles … dumps(evidence, address)
//                              … emulator(evidence, sessions, pe, dumps); emulatorRef = emulator

// src/shared/agentProtocol.ts
export interface Lifetime { duration_ms: number; max_hits: number; clock?: "install" | "resume" }
// HostPost += | { type: "resumed" }

// src/contracts/schemas/callModel.ts
export const finiteNumberSchema = z.number().min(-Number.MAX_VALUE).max(Number.MAX_VALUE);   // or B1 option A
export const scalarInputSchema = z.union([finiteNumberSchema, z.string().max(300), z.boolean()]);
export const nullableScalarInputSchema = z.union([finiteNumberSchema, z.string().max(300), z.boolean(), z.null()]);
// bufferSchema += init_from: addrExprSchema.optional()  (≤ 1 of init_hex | init_fill | init_from); distribution min/max bounded
// src/contracts/schemas/shared.ts: whereSchema.value bounded; streamIdInputSchema = /^st_[a-f0-9]{64}$/
// src/domain/evidence/coverage.ts: + agent_memory, ring_overrun, torn_record, decode_error, per_api_cap, stopped_early;
//                                  DROP_REASON_CODES: { readonly [R in DropReason]: ReasonCode }
// src/domain/evidence/limitations/{index,<12 areas>}.ts; LIMITATIONS = { ...CORE_LIMITATIONS, ...AREA_LIMITATIONS }
// src/ports/evidence.ts: StreamSourceKind += "call-batch"; StreamSpec += flush?: (signal: AbortSignal) => Promise<void>
// src/cli/argv.ts: list-typed last positional is variadic
// tests/contracts/contractInvariants.test.ts: 4 KiB default, 12 KiB for call_function / emu_call / diff_function
// tests/support/fakes/fakeServices.ts: + handles (real registry), dumps (not-implemented)
```

These are **not** in the patch and must be added to WP0's card: B8 configs (oxfmt run or printWidth 120; day-0 knip
rules and ignores; knip entry `src/main/mcpHttpEntry.ts`); I7 oxlint exception (`venvProvisioner.ts`); I8 emu fixture
sources and build; I14 `sessionAccess.ts` helper; a `src/cli/shorthands.ts` stub; M21 1,900 ms exit timer; M22
`notImplementedPort` throws.

---

## 9. Dry run of the seven investigations against the integrated design

| Inv. | Steps → hops | Gaps found |
|---|---|---|
| **1 speed variable** (attached game) | `list_processes` (SESS) → `attach_process{pid, expect_sha256}` (SESS; jobhost inspect/watch) → `scan_memory{f32, between}` (SCAN; agent job; maxBlockingMs ≥ 60 s) → `scan_next` ×2 (needs `scan_id`) → `scan_results` (`describe` → `at`/`static`) → `watch_memory{write}` (attached ⇒ `auto` = page_guard; TF engine; summary writer + `struct_base`/`disp`) → `scan_memory{pointer_to, kind:image}` → `scan_results` → `read_memory{deref:[452], view:f32}` (readTyped chain) → `close_session` (attached revert/detach) | I12 (a running FACEIT/vgc would refuse the attach); I10 (`static` needs `prepare`); M12 (operand from text); B6 (scan host store not released at close without `onSessionEnded`). Risk: page_guard on a hot heap page in a real game traps every access on that page, a heavy perturbation for 2 s (DR would be cheaper; the trade-off is documented as R6) |
| **2 rebase + float hook** | `map_address{["game.exe:0x1401234ab"], verify_bytes:16, expected_image_sha256}` (ADDR; disk preferred base; verify) → `hook_function{capture: car arg0 ptr, dt arg1 f32 (xmm1), speed_in arg0 f32 deref[452] both; returns f32; wait_ms 3500}` (HOOK) → `query_events{group_by:[dt, ret]}` (HOOK QueryEngine) | Works. I10 (`bytes_match_file` needs `verify`); state the capture-class rule explicitly in §6.2 #18 (`deref` ⇒ int register; f32/f64 without deref ⇒ xmm by position) |
| **3 oracle + emulate + diff** | `call_function{buffers:[{name:car, size:512, init_from:"0x…"}]…}` → `emu_open{live_session_id, capture_regions}` → `diff_function{live_session_id, emu_session_id, address:"game.exe+0x…"}` | **B3** (no capture path), **B5** (emulation address resolution), **I2** (without `init_from`: extra `read_memory`, and the 3-call claim fails), **B7** (cannot be a scenario). The attached game needs the user's `call_attached` gate (by design) |
| **4 behavior triage** | `spawn_process` (paused, job) → `trace_api{6 profiles, duration 30 s}` (BEHAV; lazy installs) → `resume_process{wait_ms 35000}` (returns finished `instruments[]` with ApiSummary via `RecordingRegistry.summary` → `API_KIND`) → `close_session` | **I3** (the duration clock starts at install); **I5** (six "always" limitations missing); `resume_process.maxBlockingMs` must be ≥ 35 s plus margin |
| **5 crash** | `spawn_process crashy av-write` → `resume_process{until:"exit", wait_ms}` (jobhost root exit `0xC0000005` + first-chance blocking report + ack → derived `CrashReport` with `pc: Loc` via `describeCode`) → `close_session` | Works with SESS + ADDR. M26 (`sym` needs an export). Acceptance coupling I1 (`pc.at` needs WP5) |
| **6 one-call coverage** | `trace_execution{on_call, invocations:1, mode:coverage}` (WATCH; L-S6-4 BELIEVED) → `export_coverage{recording_id}` (drcov) | Works. Alternatives (`call_function{coverage}`, `emu_call{trace.coverage}`) work through `evidence_id` |
| **7 module dump** | `dump_memory{format:pe, module, layout:pe_realigned, rebase_to:preferred}` → agent `dumpStart` job + blob messages → PE writer | **B3** (DUMP cannot obtain the bytes as designed; fallback: a `readMemory` loop). L-S6-6 is a manual receipt |

---

## Appendix — lab artifacts (`bea-lab/design-critic-integration/`)

`extract.mjs` (extract §4.2), `extracted/` (153 files), `measure.mjs` / `measure-patched.mjs` (schema size, depth and
bounds), `argv-probe.mjs` (CLI parser), `unimported.mjs` (knip candidates), `wp0delta/` (patched tree; `node_modules`
is a junction to `design-integrate/ts/node_modules`; `tsconfig.emit.json`), `wp0delta.patch`. I started no long-lived
processes. vitest and tsc runs exited normally. I touched no other process.
