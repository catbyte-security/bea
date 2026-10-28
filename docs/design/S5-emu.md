# S5-emu: BEA emulation and differential testing (design, implementation-ready)

> **Subsystem:** Unicorn emulation (`emu_open`, `emu_call`), differential testing (`diff_function`), the
> `bea-emu/0.1` Python bridge, its TypeScript client, Python provisioning (`bea setup --emulator`, doctor), and
> dump-backed emulation sessions.
> **Repo:** `<repo>` (future; paths below are relative to it).
> **Date:** 2026-10-28. **Inputs:** BRIEF.md (D1–D20 + orchestrator resolutions), the nine research notes, the
> prototype `bea-lab/ext-backends/bea_emu_bridge.py` (1,905 lines, read in full) and `bridge_client.mjs`.
>
> **Legend.**
> - **[V]**: verified. Either cited from a note's VERIFIED fact or re-verified in this design's own lab.
> - **[V lab:S5-Ex]**: verified in *this* design phase. Scripts and outputs are in
>   `<scratch>/bea-lab/design-S5-emu/`
>   (Appendix A).
> - **[B]**: believed. This is an assumption and has to be checked in the lab before anyone relies on it.
> - **[P]**: this document's design decision.
>
> Citations look like `[ext-backends §2.4 #7]`, where the key is the research note.

---

## 0. Decisions at a glance

| # | Decision | Basis | Status |
|---|---|---|---|
| S5-D1 | The bridge is **one self-contained file**, `bridge/emu/bea_emu_bridge.py` (about 3,200 lines). It runs as `"<python>" -I -X utf8 "<abs path>" --mem-limit <bytes> [--cache-dir <dir>]` on Python ≥ 3.10 and imports nothing outside the stdlib except unicorn, capstone and pefile | prototype is one file [ext-backends §1]; `-I` defeats the user's `dis.py` shadowing [ext-backends §3]; BRIEF D13 | [P] on [V] prototype |
| S5-D2 | Protocol `bea-emu/0.1` is **frozen as specified in §4**. It keeps the prototype's framing and outcome-as-result rule. Methods are renamed or added: `state.*`, `emu.batch`, `emu.sweep`, `mem.regions`, `bridge.ping`, and a dump source. **TypeScript computes the Win64 call plan and normalizes every value to raw bits.** The bridge (and the live agent) only executes plans | [ext-backends §9]; keeps one source of truth for ABI classification across the live and emulated legs | [P] |
| S5-D3 | **One bridge process per emulation session**, at most 4 sessions. A bridge that dies is restarted lazily, and its session is re-opened from the recorded open parameters (generation + 1; named snapshots are lost and reported) | a native engine crash poisons the whole process [ext-backends §2.4 #11; V lab:S5-E8]. Avoids head-of-line blocking between sessions | [P] |
| S5-D4 | **No jobhost for the bridge.** Lifetime comes from a non-detached spawn, stdin EOF ending the bridge, and `child.kill()`. Memory is capped by the bridge itself: it assigns itself to a Job Object with `JOB_OBJECT_LIMIT_PROCESS_MEMORY` before it imports unicorn | jobhost gives its target a NUL stdin [rea-process §8.1, §13 Q1]. Launchers (WindowsApps alias, `py`, venvlauncher) propagate kills, including when the server is hard-killed [V lab:S5-E2/E2b]. A self-applied job works inside libuv's job, and Unicorn fails cleanly at the cap with `UC_ERR_NOMEM` [V lab:S5-E5] | [V] |
| S5-D5 | **Snapshots v2.** A Unicorn CPU+memory (COW) context is used only for (a) the baseline and (b) **one temporary context per batch**. Named snapshots are **host copies** of the writable extents plus a CPU-only context. The bridge never restores a COW context that is newer than the last one it restored | Unicorn COW contexts behave as a **stack**: restoring an older context and then a newer one is a native access violation in unicorn.dll, while LIFO and repeated restores are fine [V lab:S5-E8]. The hybrid is correct for every ordering [V lab:S5-E8b] | [V] |
| S5-D6 | **ISA guard v2.** VEX/EVEX sites inside `.pdata` ranges get their first byte **patched to INT3** in emulator memory, and the original bytes are kept in an overlay. Gap sites get per-address hooks (≤ 256). x87 transcendental and FP-status-reader sites get tagging hooks (≤ 512). Global INSN hooks cover `cpuid` and `syscall`. The scan is cached by a digest of the scanned bytes | per-address hooks cost translation time ∝ hooks × translated instructions: 10,000 hooks took 2.8 s cold against 36 ms with none. INT3 stops cleanly at RIP = site + 1 [V lab:S5-E4] | [V] mechanism |
| S5-D7 | A **shared call model** (`src/domain/callModel.ts`) serves `emu_call`, `call_function` (batch) and `diff_function`. It has positional Win64 slots, named **buffers** with typed fields (arena model, no recursion), **column-oriented vectors**, seeded generators, and field codecs. Every float crosses every boundary as **bits** | the user's harness needs [ext-backends §3]; JSON cannot carry NaN or -0 | [P] |
| S5-D8 | The **live oracle leg uses an exact-bits register-file thunk.** Raw GPR and XMM bits go in, raw RAX and XMM0 bits come out, and MXCSR and FPCW are set per call. This is a requirement on call_function's batch RPC | 12 of 12 vectors were bit-exact against the emulator: qNaN payload, sNaN quieting, -0, denormals under RN and FTZ/DAZ, RN vs RZ, stack args, struct in/out. A fault inside the target was stolen and the target survived [V lab:S5-E6] | [V] |
| S5-D9 | **MXCSR is compared on control bits only** (`& 0xFFC0`). Unicorn does not set the MXCSR status flags | live MXCSR after a call showed IE/DE/UE/PE flags (`0x1f81`, `0x1fa2`, `0x1fa0`) while the emulator showed `0x1f80` [V lab:S5-E6] | [V] |
| S5-D10 | **Verdict rule with outcome attribution** (target vs harness). Strict by default: any inconclusive vector gives `unknown`. The verdict is bit-exact, and ulp statistics are reported separately. An unknown is recorded whenever the verdict is not `equivalent-on-tested-inputs` | [rea-evidence §3.5, §10.9]; BRIEF D14; orchestrator decision | [P] |
| S5-D11 | **Dump bundle `bea.dump/1`**: a directory with a canonical `manifest.json`, content-addressed `regions/<sha256>.bin`, a **readable-only** memory map, threads with TEB, TLS and context, and resolved IAT entries. dump_memory produces it and `emu_open` consumes it. Modules are mapped at their **runtime** base. An access to uncaptured memory is a fault classified `not-captured-mapped-live` or `unmapped-live`. Lazy live fetch is deferred | the dump-backed run was bit-exact against the live call on runtime state (the runtime `g_car` differs from the file `.data`), and the fault classification worked [V lab:S5-E7]. `enumerateRanges('---')` also returns free VA as huge `---` ranges [V lab:S5-E7] | [V] mechanism |
| S5-D12 | **Python resolution** (fixed order): `BEA_PYTHON`, then the BEA venv, then `python`/`py -3` (Windows) or `python3`/`python` (Linux). Each candidate is checked by running **the bridge itself** with `--probe`. BEA spawns the resolved command as is, because launchers are safe | orchestrator decision; [V lab:S5-E2] | [V] |
| S5-D13 | **`bea setup --emulator`** creates `<BEA_HOME>/emu/venv` with `uv venv` plus `uv pip install`, or with `python -m venv` plus `pip`. It uses a **hash-locked, binary-only** `bridge/emu/requirements.lock` (exact hashes in §6.5), builds in a staging directory, verifies with `--probe` and `--selftest`, writes an ownership marker, and needs approval | uv: 154 ms venv + 5.35 s install; pip: 5.95 s; probe and bridge `ready` in about 180 ms [V lab:S5-E3] | [V] |
| S5-D14 | Batch results are **inline up to 64 rows**. Larger results become a **stream of rows** (paged by `query_events`) plus an inline summary. Coverage becomes a `bea.coverage/1` blob that `export_coverage` turns into drcov | BRIEF §1.10, D12 | [P] |
| S5-D15 | Long work uses **a deadline plus a continuation** (`vector_offset`), not async jobs. A tool call takes at most 110 s, inside the fixed 120 s ceiling | orchestrator decision (any call ≤ 120 s) | [P] |
| S5-D16 | **Dump-session import policy `auto`** (default): HLE for builtin non-math models; LLE (the captured real code) for everything else whose target was captured; HLE-inexact math when the math target was not captured; an `unhandled_import` stop otherwise. IAT slots are rebound in emulator memory | [ext-backends §9.11] | [P] |
| S5-D17 | **Every call starts from a deterministic CPU environment.** MXCSR (flags cleared), FPCW, FPSW = 0, FPTAG = all empty, RFLAGS = 0x202, and every non-argument GPR is zeroed. A budget stop is a **status, never a value** | [ext-backends §2.4 #1]. The user's harness returns stale `xmm0` when `count=` runs out | [P]; FPTAG encoding [B] (selftest item) |

### 0.1 New verified facts from this design's lab (Appendix A has the scripts)

| ID | Fact | Consequence |
|---|---|---|
| S5-E2 | `python` and `py` on PATH are WindowsApps execution aliases. Each spawn has a launcher process in front of the interpreter. **The venv `Scripts\python.exe` from both `python -m venv` and `uv venv` is `venvlauncher.exe`** (sha256 `199ce15a…`), with the real interpreter running as a child. In every route, `child.kill()` of the launcher also killed the interpreter, and stdin EOF ended both with exit 0. Interpreter start (`-c` without imports): real 32–35 ms, venv launcher 39–78 ms, alias 90–100 ms | a launcher in between is safe. Record `childPid` and `bridgePid` (from `ready.pid`) separately |
| S5-E2b | `TerminateProcess` of the server stand-in (Node) killed the launcher and the interpreter for a venv launcher, the real interpreter and the `python` alias | no orphaned bridges after a hard server kill. jobhost is not needed for the bridge's lifetime |
| S5-E3 | uv 0.13.1: `uv venv` 154 ms; `uv pip install --require-hashes --only-binary :all: --no-deps -r requirements.lock` 5.35 s; venv 68 MB. The pip fallback with the same lock took 5.95 s. The bridge reached `ready` 176–184 ms after spawn from the venv launcher and from the real interpreter | `bea setup --emulator` is feasible in about 6 s plus the download |
| S5-E4 | Per-address `UC_HOOK_CODE` hooks over a 90k-instruction cold run: 0 hooks 36 ms, 100 hooks 48 ms, 1,000 hooks 241 ms, 4,096 hooks 885 ms, 10,000 hooks 2,797 ms. Warm runs slowed from 0.23 to 0.99 ms. INT3 replacing a VEX lead byte: `UC_HOOK_INTR` intno 3, RIP = site + 1, clean stop, earlier instructions ran | INT3 patching scales to game-sized VEX counts. Hooks stay for small site sets only |
| S5-E5 | A process can assign **itself** to a new job with `JOB_OBJECT_LIMIT_PROCESS_MEMORY` (512 MiB), even when it is already inside libuv's job. Unicorn `mem_map` commits memory up front: 448 MiB of 64 MiB maps succeeded, then `UcError UC_ERR_NOMEM`. Python allocations raised `MemoryError`. Peak 467 MiB. No crash | `--mem-limit` is enforced inside the bridge. Map `UC_ERR_NOMEM` and `MemoryError` to `resource_exhausted` |
| S5-E6 | A hand-assembled 171-byte **register-file thunk** called through `NativeFunction('void',['pointer'])` in the fixture process matched the prototype bridge **bit for bit on 12 of 12 returning vectors** (§9.6 lists them). The MXCSR status flags differed: live `0x1f81` (sNaN), `0x1fa2` (denormal), `0x1fa0` (inexact); the emulator showed `0x1f80`. A NULL-pointer call through the thunk was stolen as `access-violation` (read 0x0) and the emulator reported `fault read_unmapped` (null page). After the stolen fault the agent thread's MXCSR was back to `0x1fa0` and did not leak the per-call `0x9fc0`. **QJS freed a `Memory.alloc` code page held only by a local variable** (execute AV at the stub on the next RPC) | the live leg is exact and controllable. Keep every allocation referenced from module scope |
| S5-E7 | Dump capture through Frida: the module ranges (`module.enumerateRanges('---')` plus `readByteArray`), the main thread's **TEB from `OpenThread(0x800)` plus `NtQueryInformationThread(ThreadBasicInformation)`, `TebBaseAddress` at +8**, the TEB range from `findRangeByAddress`, and KUSER_SHARED_DATA: 12 regions, 225 KB. Loaded into Unicorn at the **runtime** addresses with GS_BASE = TEB and the TEB stack bounds rewritten to a synthetic stack, `physics_step(&g_car_runtime, 0.016)` equalled the live thunk call on a scratch copy of the same bytes: return `0x4020ba20` and the 32-byte struct, with runtime `g_car` speed 2.3544 and counter 15 where the file image has zeros. An access to a live `rw-` range that was not captured classified as `not-captured-mapped-live`; address 0x10 classified as `unmapped-live` (null page). **`Process.enumerateRanges('---')` includes free address space** as huge `---` ranges, for example `0x2a0fa720000` + `0x7d53ad530000` | the dump-backed design works. The memory map must exclude `---` ranges. Pick the synthetic window against readable ranges only |
| S5-E8 | Unicorn 2.1.4 CPU+memory contexts: LIFO restores (S2 → S1 → BASE) are correct, and repeated restores of the same context (×3, ×4) are correct. **Restoring a context newer than the last-restored one** (BASE → S1, S1 → S2) raises `OSError: exception: access violation reading 0x38` from unicorn.dll. Writes by the host and writes by emulated code behave the same | the prototype's arbitrary named snapshots are unsafe, hence S5-D5 |
| S5-E8b | The hybrid scheme (COW baseline + host-copy named snapshots with the context mode toggled to CPU-only around save and restore + a temporary COW context per batch) was correct for B, N2, N1, B, N2, a batch from N1, B, N1, T2 and B. 20k baseline restores plus a run took 18.6 µs per iteration | adopted as S5-D5 |

---

## 1. Scope, boundaries and dependencies

**In scope.**
- The bridge: process model, protocol, loader, HLE, ISA guard, call engine, snapshots, tracing and coverage,
  diagnostics, batches, sweeps, probe and self-test.
- The TypeScript bridge client, the Python resolver, `bea setup --emulator`, and the emulation doctor checks.
- The shared call model.
- The tools `emu_open`, `emu_call` and `diff_function`: contracts, services and evidence.
- How the shared tools (`session_status`, `close_session`, `read_memory`, `disassemble`, `export_coverage`,
  `query_events`) behave on emulation sessions.
- The **consumer side** of `bea.dump/1` and the **schema** of `bea.dump/1`. The producer is a requirement on
  dump_memory.

**Out of scope here, owned elsewhere** (interfaces below):
- the live agent's `call_function` implementation (S5 gives the thunk spec and the RPC contract it needs);
- `dump_memory`'s capture logic (S5 gives the bundle schema and the verified capture recipe);
- the evidence store, streams and blobs;
- the session manager core, the CLI framework, setup for other clients, and the drcov writer inside
  `export_coverage`.

### 1.1 Interfaces this subsystem provides

| Name | File | Consumers |
|---|---|---|
| `CallSignature`, `BufferDecl`, `VectorsInput`, `GenerateInput`, `CallPlan`, `NormalizedVectors`, `TypedValue`, `CallOutcomeColumns`, the zod schemas, `classifyWin64()`, `normalizeVectors()`, `decodeOutcome()` | `src/domain/callModel.ts` | emu_call, diff_function, **call_function (live)**, scenario runner |
| `floatBits`, `ulpDistance()`, `compareBits()` | `src/domain/floatBits.ts` | diff, tests |
| `bea-emu/0.1` wire types (`EmuMethod`, `EmuParams`, `EmuResult`, `Frame`) | `src/emu/protocol.ts` | the bridge (Python mirrors it), tests, future provider adapters (same framing) |
| `EmuPort` (application-facing; fakeable) | `src/ports/EmuPort.ts` | EmulationService, DiffService |
| `EmuBridge` (process plus protocol client) | `src/emu/EmuBridge.ts` | EmuSessionRuntime |
| `PythonResolver` + `ResolvedPython` | `src/emu/pythonResolver.ts` | EmuBridge, doctor, setup |
| `bea.dump/1` zod schema + `verifyDumpBundle()` | `src/emu/dumpBundle.ts` | emu_open, **dump_memory** (producer validates its own output) |
| `bea.coverage/1` schema + builder | `src/emu/coverage.ts` | **export_coverage** (drcov writer), trace_execution (Stalker coverage can reuse it) |
| The `EMULATION_TOOLS` contracts (`emu_open`, `emu_call`, `diff_function`) | `src/contracts/emulationTools.ts` | MCP registration, CLI generation, docs |
| The bridge's `--probe` and `--selftest` JSON | bridge | doctor, setup, `bea_status` |
| A thunk spec and block layout for exact-bit live calls (§9.5) | this document | the live agent designer |

### 1.2 Interfaces this subsystem requires

| Need | From | Exact requirement |
|---|---|---|
| A session registry shared with live sessions | core | `SessionManager` with `kind: "live" \| "emulation"`, a per-session promise lock, capacity accounting per kind, and `closeAll` ordering hooks (§5.7) |
| The evidence store | evidence | `record(evidence)`, `putBlob(bytes, mediaType) → {sha256, path}`, `openStream(kind, schema) → StreamWriter{append(rows), close(endReason) → manifest ev}`, `recordUnknown(...)` with CAS |
| The live oracle batch | live/Frida | `OracleCallPort.callPlanBatch()` (§9.4), executing the **same `CallPlan`** with the thunk semantics (§9.5), returning `CallOutcomeColumns`, registering a `function-called` Effect, and honouring the attached-target gate |
| Module map and address resolution for live sessions | live/mapping | `resolveAddress(session, AddressInput) → {va, module, rva, module_sha256}` and `moduleIdentity(session, module) → {file_sha256, preferred_base}` |
| Dump capture | dump_memory | it writes `bea.dump/1` bundles (§10.2) and records `bea.dump.capture` evidence. The thread-time TEB/TLS capture and the readable-only memory map are required |
| Recordings as vectors (optional, P2) | hooks/streams | `query_events(stream_id)` rows exposing typed captured args and returns as bits (§9.3.3) |
| A coverage writer | export_coverage | accepts `{source: evidence_id}` whose result references a `bea.coverage/1` blob (§11.4) |
| Config | core | `BEA_HOME`, the parsed `config.json`, and env parsing (`configuration_invalid` on bad values) |
| Gates | core | `gates.call_attached` (the call_function attached-target gate) is reused for diff_function's live leg |

---

## 2. Repository layout (emulation-related files only)

```
bridge/emu/bea_emu_bridge.py        the bridge, a single file (S5-D1); its sha256 is recorded in dist/bridge-manifest.json
bridge/emu/requirements.lock        hash-locked pins (§6.5); its sha256 is recorded in the venv marker
bridge/emu/README.md                protocol pointer, licensing note (unicorn wheel "BSD License"; core believed GPLv2, so it is never vendored)
src/domain/callModel.ts             shared call model: zod schemas, Win64 classification, normalization, codecs, generators
src/domain/floatBits.ts             f32/f64 bit helpers, ordered-int ulp distance (BigInt for f64)
src/ports/EmuPort.ts                application port (open, call, batch, sweep, state, memory, close, status)
src/ports/OracleCallPort.ts         what diff_function needs from the live provider
src/emu/protocol.ts                 bea-emu/0.1 TypeScript types (canonical spec; the Python mirrors it)
src/emu/framing.ts                  NDJSON Buffer splitter and encoder (64 MiB cap)
src/emu/EmuBridge.ts                one bridge process: spawn, hello and version check, request/response, events, cancel, deadline, ping, shutdown
src/emu/EmuSessionRuntime.ts        per-session bridge lifecycle, generation, auto-reopen, state lineage digests, named-snapshot table
src/emu/EmuAdapter.ts               implements EmuPort over EmuSessionRuntime
src/emu/pythonResolver.ts           resolution order, probe, cache
src/emu/bridgeLocator.ts            locate bridge/emu/*.py in the package; verify sha256 against dist/bridge-manifest.json
src/emu/errors.ts                   bridge error code → BeaError mapping (§12)
src/emu/dumpBundle.ts               bea.dump/1 zod schema, manifest digest (RFC 8785), file-hash verification
src/emu/coverage.ts                 bea.coverage/1 schema and builder (bridge coverage → blob)
src/emu/limitations.ts              deviation kind → curated limitation sentence (§11.5)
src/emu/selftestExpectations.ts     expected gotcha facts per engine version (§3.16)
src/application/emu/EmulationService.ts   emu_open and emu_call workflows (evidence, streams, blobs, continuation)
src/application/diff/DiffService.ts       diff_function workflow (legs, alignment, evidence, unknowns)
src/application/diff/compare.ts           comparator, ulp statistics, verdict, hints (pure; unit-tested)
src/application/diff/generators.ts        seeded vector generation (xoshiro128**; §7.6)
src/contracts/emulationTools.ts     EMULATION_TOOLS contracts (§8)
src/cli/setupEmulator.ts            `bea setup --emulator [--repair|--remove] [--dry-run] [--yes] [--python PATH] [--json]`
src/cli/doctorEmulation.ts          doctor checks emulation:* (§6.6)
tests/emu/fakeBridge.mjs            protocol-faithful fake bridge in Node (client tests without Python)
tests/emu/*.test.ts                 lanes in §14
tests/fixtures/emu/bea_emu_fixture.c   the ext-backends fixture (14 exports) + additions (§14.2)
tests/fixtures/emu/live_fixture.c      the ext-frida fixture (physics_step, mix_args, four_floats, car_energy) + additions
tests/golden/emu/*.json             canonical result goldens (bits only)
scripts/verify-emulation.mjs        verify:emulation lane receipt (live vs emulator, dump-backed)
```

Packaging: `package.json` `files` includes `bridge/emu/bea_emu_bridge.py`, `bridge/emu/requirements.lock` and
`bridge/emu/README.md` [rea-cli §9.1]. At build time, `dist/bridge-manifest.json` is written as
`{bea_emu_bridge.py: sha256, requirements.lock: sha256, protocol: "bea-emu/0.1", bridge_version}`. The bridge
version equals the package version, and the same string is stamped into the `.py` file at build time
(`BRIDGE_VERSION = "…"`, checked by a build test).

---

## 3. The bridge: `bridge/emu/bea_emu_bridge.py`

The prototype is the starting point and keeps every verified behaviour [ext-backends §2.2].
- **Kept:** the PE loader, HLE stubs, TEB/PEB/static TLS, the watchdog, `os.read` framing, the
  `ctl_flush_tb` discipline, the fast scalar batch path and the diagnostics.
- **Changed:** six things.
  - Arguments arrive as a **call plan with raw bits** (S5-D2), so `materialize()`, `argTemplates`, codecs and
    ABI classification move to TypeScript.
  - Snapshots v2 (S5-D5).
  - ISA guard v2 (S5-D6).
  - Dump sources (§10).
  - Stop attribution.
  - A self-applied memory limit.

### 3.1 Process model and startup

```
"<python>" [launcher prefix args e.g. -3] -I -X utf8 "<abs>/bridge/emu/bea_emu_bridge.py"
           --mem-limit <bytes> [--cache-dir "<BEA_HOME>/emu/cache"] [--probe | --selftest]
```

Startup order in `main()`:
1. Keep the binary stdout as the frame channel and point `sys.stdout` at `sys.stderr`, so stray prints cannot
   corrupt frames [ext-backends §9.1].
2. Parse argv. A bad flag exits with code 2 and a one-line message on stderr.
3. **Apply the memory limit before importing unicorn** (§3.1.1).
4. Import unicorn, capstone and pefile. On failure, emit `{"event":{"type":"fatal","code":"engine_unavailable",
   "message":…,"data":{"missing":[…],"errors":{…}}}}` and exit 3. `--probe` prints its probe line with `ok:false`
   instead.
5. Compute `BRIDGE_SHA256` from the bytes of `__file__`.
6. `--probe`: print one JSON line (§6.3) and exit 0. `--selftest`: print one JSON line (§3.16) and exit 0.
7. Server mode:
   - start the watchdog thread and the reader thread;
   - emit the `ready` event (§4.2) as the **first stdout line**;
   - run the dispatch loop.

Threads:

| Thread | Role |
|---|---|
| main | dispatch plus emulation. Requests run strictly one at a time, in arrival order |
| reader | `os.read(0, 65536)` framing [V ext-backends §2.4 #8]. It answers `bridge.cancel` and `bridge.ping` **immediately**, forwards everything else to an unbounded queue, and turns EOF into a `None` sentinel. It never touches Unicorn except for `emu_stop()` |
| watchdog | 5 ms polling; per-call deadline tuple; re-issues `emu_stop()` while the active request is flagged cancelled [V ext-backends §2.2] |

Frame writes are serialized by `_OUT_LOCK`, because the reader writes cancel and ping replies concurrently.

Exit codes: 0 normal (`bridge.shutdown` or stdin EOF); 2 usage; 3 engine unavailable; 70 an unexpected exception
escaped the dispatch loop (a bug; the host sees exit plus stderr). The process always exits through `os._exit()`
after flushing [V ext-backends §2.4 #8].

#### 3.1.1 Memory limit (self-applied)

- **win32** [V lab:S5-E5]:
  - `CreateJobObjectW(NULL, NULL)`, then `SetInformationJobObject(JobObjectExtendedLimitInformation = 9)` with
    `LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY (0x100) | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION (0x400)` and
    `ProcessMemoryLimit = <bytes>`, then `AssignProcessToJobObject(job, GetCurrentProcess())`.
  - The handle is never closed.
  - The 0x400 flag avoids a WER dialog if `unicorn.dll` crashes natively. That flag's behaviour inside a nested job
    is [B].
  - Result: `memoryLimit = {applied: true, bytes, mechanism: "win32-job"}`. On failure it is
    `{applied: false, error: <win32>}`; the bridge keeps running and the host records the limitation
    "Emulator memory is not capped".
- **linux** (best effort):
  - `resource.setrlimit(RLIMIT_DATA, (bytes, bytes))`, plus `prctl(PR_SET_PDEATHSIG = 1, SIGKILL = 9)` through
    `ctypes.CDLL(None)`.
  - `RLIMIT_DATA` rather than `RLIMIT_AS`, because QEMU/TCG reserves large address ranges [B].
  - `mechanism: "linux-rlimit-data"`.
- **Defaults:** `--mem-limit` = `BEA_EMU_MEMORY_LIMIT_MB` (default 4096) × 2^20. Unicorn commits mapped memory up
  front [V lab:S5-E5], so the limit bounds image, heap, scratch, stack and snapshots together.

### 3.2 Internal structure of the single file (sections, in order)

| § | Section | Main symbols |
|---|---|---|
| A | constants, layout offsets, status, cause and attribution tables | `PROTOCOL = "bea-emu/0.1"`, `BRIDGE_VERSION` (build-stamped), `LAYOUT` |
| B | value helpers | `parse_hex`, `u64`, `f32_bits`/`bits_f32` (only for HLE math and the matcher) |
| C | I/O: `FrameReader` (os.read + split, 64 MiB cap), `write_frame()` (compact JSON, `allow_nan=False`, `_OUT_LOCK`) | |
| D | process hygiene: `apply_memory_limit()`, `linux_pdeathsig()` | |
| E | `MappedImage`: a parser over **mapped-layout** bytes (headers, sections, `.pdata`, exports, imports with INT names and IAT RVAs, TLS directory) | §3.5 |
| F | loaders: `ImageSource` (pefile, on disk) and `DumpSource` (`bea.dump/1`) | §3.4, §10.3 |
| G | `Layout`: synthetic window selection, the region registry, `describe(addr)` | §3.3 |
| H | HLE: model table, `ImportBinder` (static stubs, 256 dynamic stub slots, overrides, dump IAT policy) | §3.6 |
| I | `IsaGuard`: scan, cache, install (INT3, hooks, INSN hooks), overlay | §3.7 |
| J | `Snapshots`: COW baseline and temporary context, host-copy named snapshots, HLE state | §3.11 |
| K | `CallEngine`: plan execution, CPU environment reset, budget and TB discipline, run, decode stop | §3.8–§3.10 |
| L | `Tracer`: dynamic hooks keyed by signature; coverage aggregation | §3.12 |
| M | `Diagnostics`: registers, overlay-aware disassembly, stack scan, `pc_function()` | §3.13 |
| N | `BatchEngine`: fast, medium and full paths; columns; progress; deadline; aggregation | §3.14 |
| O | `Sweep` + `KnownFunctions` | §3.15 |
| P | `probe()`, `selftest()` | §3.16 |
| Q | `Server`: reader, queue, dispatch, cancel and ping, error mapping, `main()` | §3.17 |

### 3.3 Memory layout

All synthetic regions live in a 1 GiB **synthetic window** at base `S`, so addresses identify themselves in
diagnostics [ext-backends §2.2].

| Offset from S | Size | Region | Notes |
|---|---|---|---|
| +0x0000 | 0x1000 | TEB | image sessions only. Dump sessions use the captured TEB (§10.3) |
| +0x1000 | 0x1000 | PEB | image sessions only |
| +0x2000 | 0x2000 | misc | TLS slot array at +0x2000; errno cell at +0x2800 |
| +0x4000 | ≤ 0xFC000 | static TLS block | image sessions with a TLS directory |
| +0x10_0000 | (n_static + 256) × 16 | import stubs | `C3` + `CC` padding. 256 **dynamic** slots for `GetProcAddress` (§3.6.3), mapped up front so the layout stays frozen |
| +0x20_0000 | 0x1000 | return sentinel | `F4` × 16 (hlt). `emu_start(until = S + 0x20_0000)` |
| +0x1000_0000 | heap_mb (≤ 256 MiB) | HLE heap | bump allocator plus a live map |
| +0x2000_0000 | scratch_mb (≤ 256 MiB) | argument scratch | reset per vector |
| +0x3000_0000 | stack_kb (≤ 16 MiB) | stack | the frame is built at `stack_top − 0x1000` [ext-backends §2.2] |
| `0x7FFE0000` (absolute) | 0x1000 | KUSER_SHARED_DATA | synthetic and `r--` in image sessions; **captured** in dump sessions |

**Choosing S** (`Layout.choose_window(occupied)`), where `occupied` holds:
- the image range (image sessions), or
- every captured region **and** every memory-map range with `protection != "---"` (dump sessions) [V lab:S5-E7].

```python
def choose_window(occupied, size=0x4000_0000):
    cand = 0x7E00_0000_0000
    while cand >= 0x0200_0000_0000:                      # stay well inside the 47-bit user space
        if all(e <= cand or b >= cand + size for b, e in occupied):
            return cand
        cand -= 0x100_0000_0000                         # 1 TiB steps
    raise BridgeError("layout_conflict", "no free 1 GiB window for synthetic regions")
```

S is reported in `session.open` as `layout.syntheticBase`. Every region is recorded as
`(start, end, name, kind, module?, capture?)` for `describe()` (§3.13).

### 3.4 Image source (on-disk PE64)

The prototype's `_load_pe` [ext-backends §2.2] stays, with these changes:
- **Machine check.**
  - `0x8664` is accepted.
  - `0x14c` (PE32) → `unsupported_image` with `data: {machine: "x86", reason: "wow64_unsupported_v0.1"}`; the
    host maps this to `unsupported_target` (orchestrator decision).
  - `0xAA64` and anything else → `unsupported_image`.
  - A COR20 header with `ILONLY` → load anyway, plus the loader deviation `managed_image` (no CLR).
- **Parse.** `pefile.PE(data=…, fast_load=True)`, then `parse_data_directories` for IMPORT, EXPORT, BASERELOC, TLS
  and DELAY_IMPORT. `.pdata` is read raw, not through pefile's exception parser [V ext-backends §2.2].
- **Import, export and TLS addresses** are captured as RVAs **before** `relocate_image` [V ext-backends §2.4 #10].
- **Mapping.** Map `SizeOfImage` rounded up to a page. Write the headers and each section as
  `bytes(raw[:min(len(raw), VirtualSize)])` [V ext-backends §2.4 #10]. Never use `get_memory_mapped_image()`, which
  drops sections past 256 MiB [V ext-backends §2.4 #8].
- **Protections.** `protections: "sections"` (default) makes the headers `r--` and each section follow its
  characteristics. `"rwx"` maps the whole image RWX and installs the code-dirty write hook (§3.10).
- **Relocation.** `image.base` must be 64 KiB aligned and requires `.reloc`; otherwise `relocation_unavailable`.
- **Progress.** Images over 32 MiB emit progress events with phase `load`.

### 3.5 `MappedImage` (mapped-layout parser, used for dump modules and `.pdata`)

`MappedImage(read: Callable[[int, int], bytes], base: int)` parses an image **as loaded**, where RVA = offset
from `base`:
- **Headers.**
  - DOS `e_lfanew` at +0x3C; the NT signature `PE\0\0`.
  - FileHeader: `Machine` (+4), `NumberOfSections` (+6), `SizeOfOptionalHeader` (+20).
  - OptionalHeader64 at +24: `SizeOfImage` at +56, `NumberOfRvaAndSizes` at +108, `DataDirectory[16]` at +112.
  - In memory, `ImageBase` (+24) holds the **runtime** base [V ext-frida §3.14]. The preferred base therefore comes
    from the on-disk file or from the bundle's `modules[].preferred_base`.
- **Section headers** (40 bytes each): `Name[8]`, `VirtualSize`, `VirtualAddress`, …, `Characteristics` at +36.
- **`.pdata`** (dir 3): `struct.iter_unpack("<III")` → `(begin, end, unwind)`; drop entries with `begin == 0` or
  `end <= begin`; sort and deduplicate.
- **Exports** (dir 0): `NumberOfFunctions` (+20), `NumberOfNames` (+24), `AddressOfFunctions` (+28),
  `AddressOfNames` (+32), `AddressOfNameOrdinals` (+36). A forwarder is a function RVA that falls inside the
  export directory; it is skipped.
- **Imports** (dir 1): 20-byte descriptors `(OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk)`.
  Names come from the INT (`OriginalFirstThunk`; bit 63 set means an ordinal). The IAT is `FirstThunk`, and **in a
  loaded image its slots hold resolved pointers.**
- **TLS** (dir 9), 64-bit: `StartAddressOfRawData`, `EndAddressOfRawData`, `AddressOfIndex`,
  `AddressOfCallBacks` (VAs at the runtime base), then `SizeOfZeroFill`.

Every read is bounds-checked against the mapped module range. A malformed structure yields a loader deviation
(`malformed_<dir>`) and empty data, never an exception.

### 3.6 HLE import model

#### 3.6.1 Builtin models

The prototype's table [ext-backends §2.2] stays, with these corrections [P]:

| Group | Imports | Model |
|---|---|---|
| heap | malloc, calloc, realloc, free, `_aligned_malloc`, `_aligned_free` | `builtin`. Bump allocator plus live map; invalid or double frees produce `events[]` |
| memory, string | memcpy, memmove, memset, memcmp, strlen, strcmp, wcslen | `builtin` (exact). `GuestFault` on unusable guest memory → `fault`, attribution **target**, `cause: "import_arg"` |
| errno, last-error, ids | `_errno`, GetLastError, SetLastError, GetCurrentThreadId, GetCurrentProcessId, GetCurrentProcess, GetCurrentThread | `builtin` |
| TLS, sync | TlsAlloc, TlsGetValue, TlsSetValue, TlsFree, InitializeCriticalSection(AndSpinCount), Enter/Leave/Delete/TryEnterCriticalSection, InitializeSRWLock, AcquireSRWLock*, ReleaseSRWLock* | `builtin` (no-ops or slot table) |
| time | QueryPerformanceCounter (+1000 per call), QueryPerformanceFrequency (10,000,000), GetTickCount(64) (+1 per call), Sleep (no-op), GetSystemTimeAsFileTime (fixed epoch + 10,000 per call) | `builtin` (deterministic; the counters are HLE state and are snapshotted) |
| CPU features | IsProcessorFeaturePresent | `builtin`. Returns **1** for features the emulated CPU has (winnt.h constants): PF_MMX 3, PF_XMMI 6, PF_RDTSC 8, PF_XMMI64 10, PF_SSE_DAZ_MODE 11 (DAZ is honoured [V lab:S5-E6]), PF_NX 12, PF_SSE3 13, PF_COMPARE_EXCHANGE128 14, PF_FASTFAIL 23, PF_SSSE3 36, PF_SSE4_1 37, PF_SSE4_2 38. Returns **0** for XSAVE 17, AVX/AVX2/AVX512 (39, 40, 41) and everything else. This agrees with the emulated CPUID, which reports no AVX [V ext-backends §2.4 #2]. (The prototype returned 0 for everything, which pushes `__report_gsfailure` onto a non-fastfail path) |
| exact math | sqrt, sqrtf, floor(f), ceil(f), fabs(f), fmod(f), trunc(f), copysign(f) | `builtin` (IEEE-exact: f32 variants compute in double and round once, which is exact for these operations) |
| inexact math | sin, cos, tan, asin, acos, atan, atan2, exp, log, log10, pow, sinh, cosh, tanh (and the `f` variants) | `builtin-inexact` (host double libm; deviation `inexact_import_model`) |
| terminate | abort, `_assert`, `_amsg_exit`, exit, `_exit`, ExitProcess, TerminateProcess (pseudo-handle −1) | status `terminated` (target) |
| raise | RaiseException, `_CxxThrowException` | status `raised` (**harness**: SEH and C++ dispatch are not modeled [ext-backends §2.5]) |
| loader | LoadLibraryA/W/ExA/ExW, GetModuleHandleA/W, GetProcAddress, FreeLibrary | `builtin` (§3.6.3) |

#### 3.6.2 Binding precedence (per import)

For each import:
1. `overrides["dll!name"]`, where the dll is lowercased and the name matched exactly.
2. `overrides["name"]`.
3. Builtin HLE (case-insensitive name), when `imports.builtin` is true.
4. Unhandled.

Override actions:

| Action | Behaviour |
|---|---|
| `{action:"return", returns:{type, bits}}` | sets RAX, or the XMM0 low bits for f32/f64 |
| `{action:"stop"}` | status `unhandled_import`, cause `override_stop` |
| `{action:"model", model:"<builtin name>"}` | aliases the import to a builtin model, e.g. a renamed sqrtf |

The `imports.unhandled` policy decides what happens with no binding:
- `"stop"` (default): status `unhandled_import` (harness), with the import key, caller and caller RVA, the 4 GPR
  args and the 4 XMM low halves [V ext-backends §9.5].
- `"return_zero"`: RAX = 0, XMM0 = 0, plus the deviation `unhandled_import_returned_zero` listing the import names.

#### 3.6.3 Dynamic imports (delay-load, GetProcAddress) [P, B]

- `LoadLibrary*` and `GetModuleHandle*(name)` return a fake `HMODULE = S + 0x0F00_0000 + 0x10000 × k`, one per
  case-insensitive name. `GetModuleHandle(NULL)` returns the primary module's base.
- `GetProcAddress(h, name|ordinal)` binds the next free dynamic stub slot to the model the name resolves to under
  §3.6.2 and returns that slot's VA. If no slot is free, it returns 0 and records the event
  `dynamic_stub_exhausted`.
- MSVC delay-load (`__delayLoadHelper2` in the image) resolves through these models. Every dynamic resolution is
  listed in the call's `deviations` as `dynamic_import_resolved{names}`.
- The dynamic slot table belongs to the HLE state, so it is snapshotted.

#### 3.6.4 Dump sessions: IAT binding policy (`imports.dumpPolicy`)

For every captured module that has an import directory, read each IAT slot's resolved target from captured
memory, then:

| Policy | Rule per slot |
|---|---|
| `auto` (default, S5-D16) | builtin **non-math** model exists → rebind to the HLE stub. Otherwise, target inside a captured region → **LLE** (leave the slot). Otherwise, a math model exists → HLE (inexact). Otherwise → rebind to an unhandled stub, so the stop names the import instead of showing a raw fetch fault |
| `hle_known` | builtin model → HLE; otherwise → LLE if captured, else the unhandled stub |
| `lle` | leave every slot as it is. An uncaptured target faults with `capture: "not-captured-mapped-live"` and its module name |
| `stop_all` | every slot → unhandled stub (pure-function analysis) |

Rebinding writes the stub VA into the **emulator copy** of the IAT before the baseline. The loader deviation
`iat_rebound{hle, lle, stop}` reports the counts.

Rationale: LLE runs the real CRT bit-exactly when its instructions are supported. But the real CRT's
feature-dispatch state was initialized on the real CPU, so LLE memcpy and math may take AVX or FMA paths that the
ISA guard stops [ext-backends §2.5 (B)]. HLE is semantically identical for the memory and string family, so
`auto` prefers HLE there.

### 3.7 ISA guard v2

**Scan** (`IsaGuard.scan(module)`, for every module whose code may execute):
- **Ranges.** Raw `.pdata` function ranges, clipped to executable sections and sorted, plus the **gaps** between
  them inside executable sections. Gaps matter because leaf and asm functions have no `.pdata`; a pdata-only scan
  found 1 of 6 x87 sites [V ext-backends §2.2]. Captured executable regions outside any module count as gaps.
- **Disassembly.** Capstone `disasm_lite` with `skipdata = True`.
- **Encoding test.** Skip prefixes `{26 2E 36 3E 64 65 67}`. A lead byte of `C4`/`C5` (VEX) or `62` (EVEX) is an
  AVX-class encoding in 64-bit mode.

Site kinds:

| Kind | Members | Handling |
|---|---|---|
| `vex` / `evex` | lead byte C4/C5/62, mnemonic **not** in the BMI allow-list {andn, bextr, blsi, blsmsk, blsr, bzhi, mulx, pdep, pext, rorx, sarx, shlx, shrx} [V ext-backends §2.4 #2] | **inside `.pdata`:** patch the first byte to `0xCC`; overlay `{addr: (orig, mnemonic, encoding)}`. **In a gap:** per-address `UC_HOOK_CODE`, at most 256 sites; beyond that, loader deviation `isa_guard_incomplete{unguarded}` |
| `x87_inexact` | fsin, fcos, fsincos, fptan, fpatan, f2xm1, fyl2x, fyl2xp1 | per-address tag hook → call deviation `x87_transcendental_inexact` [V ext-backends §2.4 #3] |
| `fp_status` | stmxcsr, fnstsw, fstsw, fnstenv, fstenv, fnsave, fsave, fxsave, fxsave64, fnclex | per-address tag hook → `fp_status_flags_unmodeled`, because Unicorn does not set the MXCSR flags [V lab:S5-E6] |
| `cpuid` | cpuid | one global `UC_HOOK_INSN(UC_X86_INS_CPUID)`. It records leaf and subleaf and returns 0, so the engine executes the instruction. Call deviation `cpuid_executed{leaves}`; diff hint `cpuid_dispatch` |
| `syscall` | syscall, sysenter, `int 0x2e` | `UC_HOOK_INSN(UC_X86_INS_SYSCALL)`; `int 0x2e` arrives through the INTR hook. Status `syscall` (harness) with `number = eax` |
| `tsc` | rdtsc, rdtscp | if the self-test reports `insnHookRdtsc`: `UC_HOOK_INSN`, set `edx:eax` from a virtual TSC (start `2^32`, +1000 per read, snapshotted), skip the instruction, deviation `virtualized_tsc` [B]. Otherwise a per-address tag → `nondeterministic_tsc` and `deterministic: false` |
| `rng` | rdrand, rdseed | per-address tag → `nondeterministic_rng`; `deterministic: false` [B on Unicorn support] |

- The tag hook budget is ≤ 512 hooks in total. Over budget → `x87_tagging_incomplete` or
  `fp_status_tagging_incomplete`. **INT3 has no cap** [V lab:S5-E4].
- **INT3 handling in `UC_HOOK_INTR`.** When `intno == 3 and (rip − 1) in overlay`, it stops with
  `unsupported_instruction`:
  `{isa:{mnemonic, encoding, rva, reason: "VEX/EVEX: Unicorn 2.1.x rejects 256-bit/FMA forms and silently
  mis-executes VEX.128 [ext-backends §2.4 #2]"}}`, attribution **harness**, `pc = rip − 1`. Any other int3 is a
  genuine `#BP`, so `cpu_exception` with attribution **target**.
- **Overlay transparency.** `mem.read`, `mem.disassemble`, fault disassembly and the stack scan's `pre`-bytes check
  restore the original bytes from the overlay. A host `mem.write` that covers a patched site removes that site from
  the overlay and adds the deviation `isa_overlay_overwritten`. The guard is not re-applied.
- **Caching.**
  - Key: `sha256("bea-isa/1|" + capstone_dist_version + "|" + concat(rva_le8 + len_le8 + bytes for each scanned
    range, pre-patch))`.
  - File: `<cacheDir>/isa/<key>.json` = `{schema:"bea.isa-scan/1", key, ranges:n, sites:{kind:[[rva, mnemonic,
    in_pdata]…]}, instructions, scanMs}`.
  - Written to a temporary file, then `os.replace`. A corrupt or mismatched file means a rescan.
  - For dump modules, the key covers the **captured** bytes, so runtime-patched code is scanned as it really is.
- **Cost** [B, extrapolated from 12.8k instructions in about 12 ms, i.e. about 1 M instructions/s
  [ext-backends §2.2]]: a 40 MB `.text` (roughly 10–15 M instructions) takes about 10–20 s **once**, with progress
  events (phase `isa-scan`); later opens hit the cache.
- **`isaGuard: "off"`.** No VEX patches or hooks. The other tags stay. Loader deviation `isa_guard_off` ("VEX.128
  may silently mis-execute").

### 3.8 Call engine: executing a `CallPlan`

TypeScript sends a fully classified plan (§7.4). Per vector, the engine runs these steps:

```python
def run_vector(plan, vec_index, cols, opts):
    self.scratch_top = SCRATCH                                    # 1. scratch resets per vector
    addrs, datas = {}, {}
    for b in plan["buffers"]:                                     # 2. materialize buffers in declaration order
        data = bytearray(b["template"])                           #    template = init + defaults + codec, built by TS
        for c in b["columns"]:                                    #    per-vector overrides (raw bits, codec applied by TS)
            put_bits(data, c["offset"], c["width"], c["count"], cols[c["column"]][vec_index])
        addrs[b["name"]] = self.alloc(b["size"], b["align"], b["placement"])   # scratch | HLE heap
        datas[b["name"]] = data
    for b in plan["buffers"]:                                     # 3. pointer fields (any order, may be cyclic)
        for p in b["ptrFields"]:
            struct.pack_into("<Q", datas[b["name"]], p["offset"], addrs[p["buffer"]] + p["plus"])
    for name, data in datas.items():                              # 4. one mem_write per buffer
        uc.mem_write(addrs[name], bytes(data))
    regs, stack = [], []
    for s in plan["slots"]:                                       # 5. register and stack plan
        v = slot_value(s, cols, vec_index, addrs, datas)          #    column bits (zero/sign-extended by TS) | addr+offset | byval | const
        if s["reg"] == "stack": stack.append(v)
        else: regs.append((REG[s["reg"]], v))
        if s.get("dupGpr"): regs.append((REG[s["dupGpr"]], v & MASK64))   # variadic duplication
    entry_rsp = build_frame(stack)                                # [sentinel][shadow 0x20][stack args…], rsp 16-aligned before the push
    reset_cpu(opts, zero_gprs=not self.just_restored)             # 6. §3.9
    uc.reg_write_batch(regs + [(RSP, entry_rsp)])
    return self.run(plan["target"], opts)                         # 7. §3.10; returns the raw outcome and stop
```

- Slot values arrive **pre-extended to 64 bits** for integers. Floats arrive as raw bits in the XMM low lane with
  the upper lanes zero. Stack slots are 8 bytes, and an f32 occupies the low 4 bytes.
- The bridge does no ABI reasoning. Classification is `classifyWin64()` in TypeScript (§7.4), and the live thunk
  runs the identical plan (§9.5).
- Outputs per vector:
  - `rax` (64-bit) and `xmm0` (128-bit for single calls, low 64 bits in batches);
  - `mxcsr` and `fpcw` after the call;
  - the bytes of each `out` buffer (≤ 1 MiB for single calls, ≤ 4 KiB per buffer per vector in batches);
  - `buffers: {name: address}` (single calls).

### 3.9 CPU and FP environment per call (S5-D17)

| Register | Value written before **every** vector |
|---|---|
| MXCSR | `opts.mxcsr & 0xFFC0` (status flags cleared). Default `0x1F80` [V ext-backends §2.4 #1] |
| FPCW | `opts.fpcw`. Default `0x027F` [V ext-backends §2.4 #1] |
| FPSW | `0` (TOP = 0, flags clear) |
| FPTAG | `0xFFFF`, all empty. **[B]** QEMU maps a 2-bit tag value of 3 to empty; the self-test item `x87_reset` verifies it |
| EFLAGS | `0x202` (DF = 0 as the Win64 ABI requires; IF; reserved bit 1) |
| GPRs other than args and RSP; RBP; unused arg GPRs; XMM4–XMM15; unused arg XMMs | `0`, **unless the vector began with a context restore**, in which case the snapshot's CPU state already makes it deterministic and the zeroing is skipped to save about 4 µs per vector |

`opts.mxcsr` and `opts.fpcw` are recorded in provenance [ext-backends §9.7]. The engine reads back MXCSR, FPCW and
FPSW after the call. They are reported, but they never enter a verdict except through the MXCSR control bits
(S5-D9).

### 3.10 Budgets, TB-cache discipline, watchdog, cancellation, deadlines

- **Budget.** `maxInstructions` (`u64`; `0` = unbudgeted fast mode) maps to `emu_start(count = n)`. A stop with
  `rip != sentinel`, no stop record, no timeout and no cancel is **`budget_exhausted`** (harness, deterministic).
  This is never returned as a value, unlike harness code that reads `xmm0` regardless.
- **TB discipline** [V ext-backends §2.4 #4, #5]. The engine keeps `tb_key = (dynamic_hook_signature,
  budget_mode)` and calls `uc.ctl_flush_tb()` whenever the key changes (about 0.54 ms). It also flushes after:
  - a host write into an executable range (`mem.write`, `state.writes`, or a host-copy restore that touches code):
    `uc.ctl_remove_cache(start, end)` when the binding exposes it [B], otherwise `ctl_flush_tb()`;
  - in `protections: "rwx"` sessions, a COW restore when the code-dirty flag is set. A `UC_HOOK_MEM_WRITE` bounded
    to the executable ranges sets that flag, and it also adds the deviation `self_modifying_code`.
  - The flush counter appears in `metrics.tbFlushes`.
- **Watchdog** (`timeoutMs` per vector; default 0 = off). The prototype design is kept: a lock-protected tuple
  swap, a sequence guard, and 5 ms resolution [V ext-backends §2.2]. Never `emu_start(timeout=…)`, which costs
  about 15 ms per call [V ext-backends §2.4 #6]. The result is `timeout` (harness), `deterministic: false`.
- **Cancellation.** `bridge.cancel{requestId}` on the reader thread sets that request's `Event` and calls
  `emu_stop()` if it is the active request. The watchdog re-issues the stop every period [V, 0.4–0.6 ms
  ext-backends §2.6].
  - If the request is still **queued**, it is marked; when dequeued, `emu.*` returns `{status:"cancelled"}` (or a
    batch with `completed: 0, cancelled: true`) and any other method returns the error `cancelled`.
  - A cancelled vector gets status `cancelled` (harness). A batch returns its completed prefix.
- **Deadline** (batch, sweep, open). `params.deadlineMs` is relative to dequeue time.
  - Checked between vectors.
  - The watchdog also arms `deadline + 250 ms` against the current vector. A vector stopped that way becomes
    `timeout` with `cause: "deadline"`.
  - The result carries `summary.deadlineReached = true`, and TypeScript issues a continuation (§8.2.3).
- **Determinism flag.** `deterministic = not (timeout fired or cancelled or nondeterministic_tsc or
  nondeterministic_rng)`.

### 3.11 Snapshots v2 (S5-D5)

```
COW contexts (UC_CTL_CONTEXT_CPU|MEMORY):
  B  baseline   taken once at the end of session.open (after binding, patches, ISA install, TB flush)
  T  temporary  taken at batch start when isolation = "snapshot" and from ≠ "baseline"; T := None at batch end
Rules (enforced in Snapshots): only B or the current T is ever passed to context_restore;
  restoring B sets T := None                       # T is newer than B: never restore it afterwards [V lab:S5-E8]
Named snapshot N (host copy):
  N.mem      = [(addr, bytes(uc.mem_read(addr, n))) for (addr, n) in extents()]
  N.cpu      = context_save() taken with UC_CTL_CONTEXT_MODE temporarily set to CPU only   [V lab:S5-E8b]
  N.hle      = deepcopy(hle_state)        # heap tops/live map, TLS slots, counters, dynamic stubs, virtual TSC
  N.meta     = {scratch_high, heap_high, automapped_count, code_dirty}
restore(N):  mem_write every extent; TB flush if an executable extent changed; CPU-only context_restore;
             hle := deepcopy(N.hle); T := None
extents():   image sessions: writable image sections (the whole image if protections = "rwx")
                             + TEB/PEB/misc/static TLS + heap[0:high] + scratch[0:high] + stack + stub pages
             dump sessions:  all captured regions whose protection has "w" (all captured regions under "rwx")
                             + synthetic heap[0:high] + scratch[0:high] + stack + stub pages
```

- **Positioning a call or batch at `from`:**
  - `baseline`: restore B (per vector under snapshot isolation; once under chain).
  - `<name>`: **restore B first**, which discards every COW level above B and frees its copied pages. Then
    `restore(N)` (host copy). Under snapshot isolation, take T and restore T per vector. This order (B, then the
    host-copy N, then T) is the verified sequence [V lab:S5-E8b].
  - `current`: under snapshot isolation take T and restore T per vector.
- **Level compaction.**
  - Every `context_save` adds a Unicorn snapshot level. Copied-on-write pages of abandoned temporaries are freed
    only when an older context (B) is restored.
  - The bridge therefore counts the levels created since the last B restore. Before taking a new T while that
    count exceeds 8 (only possible through repeated `from: "current"` batches), it compacts:
    1. host-copy the current state into an internal N′;
    2. restore B;
    3. restore N′;
    4. drop N′.
  - The resulting state is identical, and the levels are freed. [B: the memory per level is proportional to the
    pages dirtied; not measured]
- **Limits.** At most 16 named snapshots per session. Total host-copy bytes ≤ `snapshot_bytes_limit` (default
  512 MiB, config `emu.snapshot_bytes_limit_mb`). Exceeding either → `resource_exhausted` (resource `memory`).
- **`snapshots: "manual"` sessions**, required by `faultPolicy: "map_zero"` [V ext-backends §2.4 #7]: B, T and N
  are all host copies. Restores unmap pages auto-mapped after the snapshot. This is the prototype's manual path
  [ext-backends §2.2], and per-vector cost scales with the extents.
- **Cost.** COW restore plus run is about 18.6 µs per vector for a small working set [V lab:S5-E8b]. A host-copy
  restore costs about the extent size divided by memory bandwidth [B: about 1 ms per 10 MB].

### 3.12 Tracing and coverage (opt-in, bounded)

| Option | Single call | Batch | Mechanism | Cost |
|---|---|---|---|---|
| `imports` | `full` (default): `{import, model, callerRva, args[4], ret}` up to `maxEvents` | `counts` (default): `{key: {calls, model}}` | stub hook (always installed) | none extra |
| `blocks` | ordered block VA list (≤ `maxEvents`) plus the last 16 blocks for faults | rejected (use `coverage`) | `UC_HOOK_BLOCK` | about 0.36 µs per block [V ext-backends §2.6] |
| `coverage` | `{(va, size): hits}` | aggregated over all vectors | the same block hook | same |
| `countInstructions` | block-granular count (capstone instruction count per TB, cached) | `instructions` column | the same block hook | same |
| `memory` | `reads`/`writes`/`all`: `{pc, access, address, size, value}` up to `maxEvents` | rejected | `UC_HOOK_MEM_READ`/`WRITE` | about 0.36 µs per access |
| `instructions` | VA list, optionally disassembled once per unique address | rejected | `UC_HOOK_CODE` | about 0.36 µs per instruction (2.7 M insns/s) |

- `maxEvents` defaults to 10,000; the maximum is 100,000. Every list carries `truncated`.
- The dynamic hooks are keyed by `(blocks or coverage or count, instructions, memory_mode)`. A change of key means
  `hook_del` plus `ctl_flush_tb` [V ext-backends §2.4 #4].
- Coverage wire format: `{granularity: "tb", blocks: [["0x…", size, hits], …] sorted by VA, distinct: n,
  truncated: bool}` (truncated beyond 1,000,000 distinct TBs). TypeScript converts it into `bea.coverage/1` (§11.4).
- Unicorn TBs are not static basic blocks (they split at page boundaries and at calls). Consumers map them to CFG
  blocks by range overlap, as with Stalker [ext-frida §3.8].

### 3.13 Stops, attribution and diagnostics

One stop record per vector; the first stop wins [ext-backends §2.2].

| Status | Attribution | `cause` values |
|---|---|---|
| `returned` | none | none |
| `fault` | **target**, except `capture: "not-captured-mapped-live"` or `"synthetic"` → **harness** | `read_unmapped`, `write_unmapped`, `fetch_unmapped`, `read_protected`, `write_protected`, `fetch_protected`, `import_arg`, `synthetic_unmapped` |
| `cpu_exception` | target | `div_error`, `ud`, `gp`, `breakpoint`, `debug_service`, `simd_fp`, `x87_fp`, `alignment`, `interrupt_<n>` |
| `invalid_instruction` | target: capstone cannot decode the bytes at the PC either | `undecodable` |
| `unsupported_instruction` | harness | `vex`, `evex`, `engine_rejected` (Unicorn raised `UC_ERR_INSN_INVALID` on bytes that capstone decodes, so the instruction is real but unsupported) |
| `unhandled_import` | harness | `no_model`, `override_stop`, `dynamic_stub_exhausted` |
| `syscall` | harness | `syscall`, `int2e` |
| `raised` | harness | `raise_exception`, `cxx_throw` |
| `terminated` | target | `abort`, `exit`, `exit_process`, `terminate_process`, `fastfail` (`int 0x29`; `code = ecx`), `assertion` (`int 0x2c`) |
| `budget_exhausted` | harness | `max_instructions` |
| `timeout` | harness | `watchdog`, `deadline` |
| `cancelled` | harness | `host_cancel` |
| `engine_error` | harness | `uc_err_<errno>` (an unexplained `UcError`, or `rip != sentinel` with no other cause while unbudgeted) |

Stop record (wire; TypeScript type `StopRecord` in §4.4):
- `pc`, `pcRegion` (`describe(pc)`), and `pcFunction = {module, beginRva, endRva, offsetHex}` from `.pdata`
  (null outside `.pdata`).
- `instruction[1]`: disassembly from **original** bytes.
- At most one of the cause-specific sub-objects `fault | exception | importCall | isa | syscall | engineError |
  terminate`.
- `registers` for target-attributed faults and exceptions, and for `unsupported_instruction` and
  `engine_error`: all GPRs, rip, rflags, mxcsr, fpcw, fpsw, xmm0–15 as 128-bit hex.
- `stackScan` [ext-backends §2.2]: the heuristic return-address scan, extended to every module image in dump
  sessions and labelled with the module.
- `lastBlocks` (≤ 16) when a block hook was active.

`describe(addr)` returns a `RegionDesc`:
- **A known region:** `{region, kind, module?, rva?, offset, import?}`.
- **In a dump session:** `capture: "captured"` for a captured region. For a non-captured address inside a
  readable memory-map range: `{region:"not captured", kind:"unmapped", capture:"not-captured-mapped-live",
  module, liveProtection, remediation:"re-run dump_memory including this range"}` [V lab:S5-E7].
- **Inside the synthetic window but unmapped** (for example a fake `HMODULE` from §3.6.3 being dereferenced):
  `{region:"synthetic (unmapped)", kind:"unmapped", capture:"synthetic"}`. This is a **harness** stop with
  `cause: "synthetic_unmapped"`, because BEA's own modeling put that address there.
- **Below 0x10000:** `{region:"null page", kind:"unmapped", capture:"unmapped-live", hint:"likely NULL pointer
  dereference (+0x18)"}` [V ext-backends §2.3].
- **Otherwise:** `{region:"unmapped", kind:"unmapped", capture:"unmapped-live", nearest, distance}`.

`fault` attribution, summarized:
- `not-captured-mapped-live` and `synthetic` → harness;
- `unmapped-live`, protection faults on mapped memory, and image sessions' unmapped addresses outside the synthetic
  window → target.

### 3.14 Batch engine

| Path | Selected when | Rate |
|---|---|---|
| **fast** | every slot comes from a scalar column or a constant; no buffers; no tracing except import counts; `timeoutMs = 0`; `faultPolicy = "stop"` | precomputed register plan [V ext-backends §2.6]: 16.3–18.2k vectors/s with snapshot isolation, 35.8–38.7k with chain (Node end to end) |
| **medium** | buffers present, otherwise as fast | template copy plus column patches plus one `mem_write` per buffer. Estimated ≥ 8k vectors/s [B]; the prototype's generic template path did 3.5–5.9k [V] |
| **full** | anything else (coverage, count, timeout, `map_zero`) | `run_vector` plus hooks |

Batch result (wire, `BatchResult` in §4.4):
- **summary:** `{offset, vectors, completed, returned, byStatus, byAttribution, elapsedMs, callsPerSecond,
  isolation, from, path, deterministic, deadlineReached, cancelled}`.
- **columns:**
  - `status[]` uses short codes: `ok fault cpu inv unsup imp sys raised term budget timeout cancel eng`;
  - `rax[]` and `xmm0lo[]` are hex strings, empty for non-returned vectors;
  - `out: {buffer: hex[]}`;
  - `instructions[]` when counting.
- **faults:** a sparse list, at most 1,000 entries. Each has a compact stop `{index, status, attribution, cause,
  pc, pcRva, faultAddress?, import?, mnemonic?}`. The first 8 also carry full diagnostics.
- **aggregates:** `{imports: {key: {calls, model}}, deviations: {kind: {vectors, detail}}, coverage?,
  cpuidLeaves?}`.

- `stopOnFault` ends the batch after the first non-`ok` vector.
- Progress events are emitted at most every 250 ms: `{phase: "batch", completed, total}`.

### 3.15 Sweep and known-function matching (behavioural identification) [P]

This serves the user's harness pattern: sweep every `.pdata` function in a range with probe inputs under a small
budget, and match the outputs against known math functions [ext-backends §3].

- **Targets.**
  - `functions: {module, rvaStart, rvaEnd, limit ≤ 20000}`: the bridge enumerates the module's `.pdata` begin
    addresses inside the range.
  - Or `targets: [va…]`.
- **Per target.** For each probe vector (≤ 16), restore B, then run the plan (target substituted) with
  `maxInstructions` (default 100,000).
- **Row:** `{rva, statuses[], rax[], xmm0lo[], matches[]}`.
- **Matcher** (`match: {returns: "f32"|"f64", argsFrom: ["arg0", "arg1"?], known: [...]|"unary"|"binary",
  toleranceUlp: 0..64 (default 1)}`):
  - The reference for each known function and vector is computed in Python double precision and rounded once to
    the return type.
  - A target matches when every vector returned and every `ulp(ret, ref) ≤ toleranceUlp`. A NaN reference requires
    a NaN result; infinities must be exactly equal.
  - Known unary: `sin cos tan asin acos atan sinh cosh tanh exp exp2 expm1 log log2 log10 log1p sqrt rsqrt recip
    cbrt floor ceil trunc round(C: half away from zero) fabs neg identity`.
  - Known binary: `atan2 pow fmod hypot fmin fmax copysign add sub mul div`.
- **Progress, deadline and continuation** are per function index (as in batches).

### 3.16 `--probe` and `--selftest`

`--probe` prints exactly one line (schema in §6.3) and exits.

`--selftest` runs micro-checks that pin the engine gotchas BEA's design depends on. It prints
`{"selftest":"bea-emu/0.1","engines":{…},"ms":…,"results":{name:{ok,observed,expected}}}`:

| Name | Check | Expected on unicorn 2.1.4 |
|---|---|---|
| `fp_reset` | FPCW and MXCSR of a fresh `Uc` | `0x0000`, `0x0000` [V ext-backends §2.4 #1] |
| `vex128_misexecutes` | `vaddss xmm0,xmm1,xmm2` with distinct inputs | result ≠ xmm1 + xmm2 [V] |
| `vex256_rejected` | `vaddps ymm0,ymm1,ymm2` | `UC_ERR_INSN_INVALID` [V] |
| `bmi_ok` | `andn eax,ebx,ecx` | correct [V] |
| `tb_hook_gotcha` | a code hook added after warm-up fires 0 times, then > 0 after flush | true [V ext-backends §2.4 #4] |
| `count_budget_gotcha` | a `count=0` warm run followed by `count=1000` on a loop is not enforced without a flush (watchdog bounded at 200 ms) | true [V #5] |
| `cow_lifo_ok` | S2 → S1 → B restores correct (**the crashing order is never executed**) | true [V lab:S5-E8] |
| `context_mode_toggle` | CPU-only save and restore inside a CPU+memory session | true [V lab:S5-E8b] |
| `int3_rip` | INTR hook: intno 3, RIP = site + 1 | true [V lab:S5-E4] |
| `mxcsr_flags_modeled` | an inexact `addss` sets MXCSR.PE | **false** [V lab:S5-E6] |
| `x87_reset` | after FPTAG = 0xFFFF, 8 × `fld1` then `fstp` loads cleanly | true [B] |
| `insn_hooks` | `hook_add(UC_HOOK_INSN, …)` accepted for CPUID, SYSCALL, RDTSC, RDTSCP | CPUID and SYSCALL true [V ext-backends §2.4 #2]; RDTSC [B] |
| `gs_base` | GS_BASE write, then `mov rax, gs:[0x30]` | matches [V] |
| `memory_limit` | the job is applied (server mode reports it; the self-test only reports whether the mechanism is available) | true on win32 [V lab:S5-E5] |

`src/emu/selftestExpectations.ts` holds the expected map per exact engine version. When the engines are not the
pinned set, BEA runs `--selftest` once per server process before the first `emu_open` and puts the result into
`bea_status`. A mismatched gotcha adds the limitation "engine behaviour differs from the validated set
(unicorn x.y.z); re-run the emulator probe suite" to every emulation result.

### 3.17 Error handling inside the bridge

Per request:

| Exception | Handling |
|---|---|
| `BridgeError(code, message, data)` | error frame |
| `MemoryError`, `UcError(UC_ERR_NOMEM)` | `resource_exhausted` |
| `OSError` whose message starts with `exception: access violation` (ctypes turns a native AV into this [V ext-backends §2.4 #11; lab:S5-E8]) | error `engine_crashed`; the session is marked **poisoned**, and later requests on it get `session_poisoned` |
| anything else | `internal_error` with `data.traceback` (≤ 4,000 characters) |

The bridge never exits because of a request [ext-backends §9.2].

---

## 4. Protocol `bea-emu/0.1` (final)

### 4.1 Transport

- **Channels.** stdin carries host → bridge frames; stdout carries bridge → host frames. stderr is free-form logs:
  bounded, captured, never parsed [ext-backends §9.1].
- **Framing.** One UTF-8 JSON object per line, terminated by `\n` (`\r\n` tolerated). At most **64 MiB per frame
  in each direction**. JSON is compact, with `allow_nan=False` on the Python side, so no NaN or Infinity token ever
  appears.
- **Ordering.**
  - Queued methods run one at a time and their **final frames arrive in request order**.
  - Zero or more `{id, event}` progress frames come before the final frame of that id.
  - **`bridge.cancel` and `bridge.ping` are answered out of band** by the reader thread, so their replies can
    interleave anywhere. The host matches every frame by `id`.
- **Request ids** are positive integers, unique per bridge process. `id: null` appears only on a `parse_error`
  reply to an unparseable line.
- **Lifetime.**
  - `bridge.shutdown` gives a final frame and then exit 0.
  - stdin EOF also exits 0 [V ext-backends §9.1].
  - The host never relies on signals: `child.kill()` is the hard stop, and it propagates through launchers
    [V lab:S5-E2].
- **Outcomes are results.** Every emulation outcome is a `result` with a `status`, including faults, exceptions,
  stops and unhandled imports. `error` means only that the request could not be attempted [ext-backends §9.2].

### 4.2 Handshake and versioning

1. The bridge writes `{"event":{"type":"ready",…}}` as its first line, or `{"event":{"type":"fatal",…}}` and exits
   with code 3.
2. The host checks `protocol === "bea-emu/0.1"` (an exact string match while the protocol is 0.x),
   `bridge.sha256 ===` the `dist/bridge-manifest.json` entry, and `bridge.version ===` the package version. Any
   mismatch → kill → `capability_unavailable` ("bridge file does not match this BEA build; reinstall").
3. The host sends `bridge.hello {protocol, client}`. The bridge answers `HelloResult`, or `protocol_mismatch`.
   After 1.0 the rule becomes: same major, and the bridge's minor version ≥ the host's required minor.

### 4.3 Methods

| Method | Queued? | Purpose |
|---|---|---|
| `bridge.hello` | yes | capabilities and limits |
| `bridge.ping` | **out of band** | liveness, plus the busy request id |
| `bridge.cancel` | **out of band** | cancel a running or queued request |
| `bridge.shutdown` | yes | final frame, then exit 0 |
| `session.open` / `session.info` / `session.close` | yes | open from an image or a `bea.dump/1` bundle; report; free |
| `state.save` / `state.restore` / `state.list` / `state.drop` | yes | named host-copy snapshots (§3.11). `restore("baseline")` is the COW baseline |
| `mem.read` / `mem.write` | yes | ≤ 16 MiB reads (overlay-transparent); writes (TB invalidation, overlay bookkeeping) |
| `mem.disassemble` | yes | ≤ 512 instructions, or a whole `.pdata` function (`function: true`) |
| `mem.regions` / `mem.functions` | yes | layout, and paged `.pdata` function ranges |
| `emu.call` | yes | **one** vector with full detail |
| `emu.batch` | yes | N vectors, columnar |
| `emu.sweep` | yes | many targets × few vectors, with an optional matcher |

Renames from the prototype (protocol 0.1 had not shipped): `session.snapshot` → `state.save`,
`session.restore` → `state.restore`, `emu.callBatch` → `emu.batch`. `args[]` specs, `signature`,
`argTemplates` and `target` objects are replaced by `plan` + `vectors` (raw bits; TypeScript classifies).

### 4.4 Canonical wire types (`src/emu/protocol.ts`)

```ts
// src/emu/protocol.ts: canonical bea-emu/0.1 types. bea_emu_bridge.py mirrors these exactly.
export const EMU_PROTOCOL = "bea-emu/0.1" as const;
export type Hex = `0x${string}`;            // lowercase, no leading zeros required; addresses and raw bits
export type HexBytes = string;               // lowercase hex byte string, no prefix, even length
export type RequestId = number;              // positive integer, unique per bridge process

// ---------------------------------------------------------------- frames
export type HostFrame = { id: RequestId; method: EmuMethod; params: object };
export type BridgeFrame =
  | { event: ReadyEvent | FatalEvent }                        // unsolicited; no id
  | { id: RequestId; event: ProgressEvent }                   // zero or more before the final frame
  | { id: RequestId; result: unknown }                        // final (shape = EmuMethods[M]["result"])
  | { id: RequestId | null; error: BridgeErrorBody };         // final; id null only for parse_error

export interface EngineVersions { python: string; unicorn: string; unicornCore: string; capstone: string; pefile: string }
export interface MemoryLimitInfo { applied: boolean; bytes: number | null; mechanism: "win32-job" | "linux-rlimit-data" | "none"; error?: string }
export interface ReadyEvent { type: "ready"; protocol: typeof EMU_PROTOCOL; bridge: { version: string; sha256: string }; pid: number;
  engines: EngineVersions; python: { version: string; executable: string; inVenv: boolean }; memoryLimit: MemoryLimitInfo }
export interface FatalEvent { type: "fatal"; code: "engine_unavailable" | "usage" | "internal_error"; message: string;
  data?: { missing?: string[]; errors?: Record<string, string> } }
export interface ProgressEvent { type: "progress"; phase: "load" | "isa-scan" | "batch" | "sweep" | "snapshot"; completed: number; total: number | null }

export type BridgeErrorCode =
  | "parse_error" | "frame_too_large" | "invalid_request" | "invalid_params" | "unknown_method" | "protocol_mismatch"
  | "unknown_session" | "session_poisoned" | "unknown_snapshot" | "unknown_symbol" | "image_unreadable" | "unsupported_image"
  | "relocation_unavailable" | "layout_conflict" | "dump_invalid" | "dump_incomplete" | "unmapped" | "resource_exhausted"
  | "unsupported_combination" | "cancelled" | "engine_crashed" | "internal_error";
export interface BridgeErrorBody { code: BridgeErrorCode; message: string; data?: Record<string, unknown> }

// ---------------------------------------------------------------- shared value shapes
export interface RegionDesc {
  region: string;
  kind: "image" | "module" | "runtime" | "stub" | "heap" | "scratch" | "stack" | "teb" | "captured" | "unmapped";
  module?: string; rva?: Hex; offset?: Hex; import?: string; hint?: string; nearest?: string; distance?: Hex;
  capture?: "captured" | "synthetic" | "not-captured-mapped-live" | "unmapped-live";
  liveProtection?: string; remediation?: string;
}
export interface Insn { va: Hex; rva: Hex | null; module: string | null; bytes: HexBytes; text: string }
export interface FunctionRange { module: string; beginRva: Hex; endRva: Hex; source: "pdata" }
export interface RegionInfo { start: Hex; end: Hex; name: string; kind: RegionDesc["kind"]; perms: string; module?: string; capture?: RegionDesc["capture"] }
export type DeviationKind =
  // loader-level
  | "tls_callbacks_not_run" | "entry_point_not_run" | "imports_hle_bound" | "no_seh_dispatch" | "delay_imports_present"
  | "managed_image" | "isa_guard_off" | "isa_guard_incomplete" | "x87_tagging_incomplete" | "fp_status_tagging_incomplete"
  | "iat_rebound" | "teb_stack_bounds_rewritten" | "memory_patched" | "synthetic_teb" | "synthetic_kuser_shared_data"
  | "malformed_directory" | "engine_unvalidated"
  // call-level
  | "x87_transcendental_inexact" | "inexact_import_model" | "unhandled_import_returned_zero" | "auto_mapped_zero_pages"
  | "fp_status_flags_unmodeled" | "cpuid_executed" | "virtualized_tsc" | "nondeterministic_tsc" | "nondeterministic_rng"
  | "dynamic_import_resolved" | "self_modifying_code" | "isa_overlay_overwritten"
  // host-added
  | "bridge_restarted_state_reset";
export interface Deviation { kind: DeviationKind; note: string; count?: number; detail?: Record<string, unknown> }

// ---------------------------------------------------------------- session.open
export interface OpenParams {
  source: { kind: "image"; path: string; base?: Hex } | { kind: "dump"; bundlePath: string; thread?: number; primaryModule?: string };
  memory?: { heapBytes?: number; scratchBytes?: number; stackBytes?: number };   // ≤ 256 MiB, ≤ 256 MiB, ≤ 16 MiB
  protections?: "sections" | "rwx";
  imports?: {
    builtin?: boolean;                                       // default true
    unhandled?: "stop" | "return_zero";                      // default "stop"
    dumpPolicy?: "auto" | "hle_known" | "lle" | "stop_all";  // default "auto"
    overrides?: Array<
      | { key: string; action: "return"; returns: { kind: "int" | "f32" | "f64" | "void"; bits: Hex } }
      | { key: string; action: "stop" }
      | { key: string; action: "model"; model: string }>;    // ≤ 256
  };
  patches?: Array<{ address: Hex | string; hex: HexBytes }>; // ≤ 256 entries, ≤ 1 MiB total; applied before the baseline.
                                                              // address: "0x…" | "module+0xRVA" | "module!export". The bridge resolves the
                                                              // symbolic forms (the only symbolic input in the protocol; TS cannot know a
                                                              // dump's or relocated image's modules before the open)
  cpu?: { mxcsr: number; fpcw: number };                      // session defaults; defaults 0x1F80 / 0x027F
  isaGuard?: "stop" | "off";
  snapshots?: "cow" | "manual";
  faultPolicy?: "stop" | "map_zero";                          // map_zero requires snapshots "manual"
  cacheDir?: string | null;
  deadlineMs?: number;
}
export interface ModuleInfo {
  name: string; path: string | null; sha256: string | null;  // file sha256 (image) or captured-bytes digest (dump module without file match)
  preferredBase: Hex | null; mappedBase: Hex; size: number; relocated: boolean;
  captured: "image" | "full" | "partial" | "none";
  sections: Array<{ name: string; rva: Hex; size: number; perms: string }>;
  exports: number; pdataFunctions: number; tlsCallbacks: Array<{ rva: Hex }>; tlsCallbacksExecuted: false; delayImports: number;
}
export interface IsaReport {
  scanSource: "pdata+gaps" | "sections"; cache: "hit" | "miss" | "off"; scanMs: number; instructionsScanned: number;
  sites: Record<"vex" | "evex" | "x87_inexact" | "fp_status" | "cpuid" | "syscall" | "tsc" | "rng", number>;
  guarded: { int3: number; hooks: number; unguarded: number }; functionsWithVex: Hex[] /* ≤ 100 RVAs of the primary */; guard: "stop" | "off";
}
export interface OpenResult {
  session: string;                                            // bridge-local id, e.g. "s1"
  primary: ModuleInfo; modules: ModuleInfo[];
  imports: { total: number; models: Record<"builtin" | "builtin-inexact" | "override" | "unhandled" | "lle" | "stop", number>; unhandled: string[] };
  isa: IsaReport;
  layout: { syntheticBase: Hex; regions: number; mappedBytes: number };
  cpu: { mxcsr: Hex; fpcw: Hex; model: string };
  snapshots: "cow" | "manual";
  thread: { tid: number; teb: Hex } | null;                   // dump sessions
  loaderDeviations: Deviation[];
  timings: { loadMs: number; isaMs: number; bindMs: number; snapshotMs: number; totalMs: number };
}
export interface SessionStateInfo { poisoned: boolean; named: Array<{ name: string; bytes: number }>; heapHigh: Hex; calls: number; vectors: number }

// ---------------------------------------------------------------- call plan (built by TS: callModel.planToWire)
export type GprName = "rcx" | "rdx" | "r8" | "r9";
export type ArgReg = GprName | "xmm0" | "xmm1" | "xmm2" | "xmm3" | "stack";
export interface SlotWire {
  reg: ArgReg; stackIndex?: number; dupGpr?: GprName;         // dupGpr: variadic float duplication
  source:
    | { kind: "column"; column: string }                      // vectors.columns[column][i]: 64-bit extended bits
    | { kind: "const"; bits: Hex }
    | { kind: "buffer"; buffer: string; offset: number }      // pointer = address(buffer) + offset
    | { kind: "byval"; buffer: string };                      // size 1/2/4/8: the buffer bytes as an integer
}
export interface BufferWire {
  name: string; size: number; align: number; placement: "scratch" | "heap";
  template: HexBytes;                                         // size bytes: init + field defaults (codecs applied by TS)
  columns: Array<{ column: string; offset: number; width: 1 | 2 | 4 | 8; count: number }>;   // count > 1: array cell
  ptrFields: Array<{ offset: number; buffer: string; plus: number }>;
  out: boolean;
}
export interface PlanWire {
  target: Hex;                                                // VA in the emulator address space
  slots: SlotWire[];                                          // a hidden-return pointer is already slot 0 when present
  returns: { kind: "void" } | { kind: "int"; width: 1 | 2 | 4 | 8 } | { kind: "f32" } | { kind: "f64" }
         | { kind: "struct"; size: number; via: "rax" | "hidden"; buffer?: string };
  buffers: BufferWire[];
}
export interface VectorsWire { offset: number; count: number; columns: Record<string, Hex[] | Hex[][]> }
export interface TraceOptions {
  imports: "off" | "counts" | "full"; blocks: boolean; coverage: boolean; countInstructions: boolean;
  memory: "off" | "reads" | "writes" | "all"; instructions: boolean; disassemble: boolean; maxEvents: number;
}
export interface RunOptions {
  maxInstructions: number; timeoutMs: number; mxcsr: number; fpcw: number; faultPolicy: "stop" | "map_zero"; trace: TraceOptions;
}
export interface StateWire { from: "baseline" | "current" | string; writes: Array<{ address: Hex; hex: HexBytes }>; saveAs: string | null }
export interface CallParams { session: string; plan: PlanWire; vectors: VectorsWire /* count 1 */; state: StateWire; options: RunOptions }
export interface BatchParams { session: string; plan: PlanWire; vectors: VectorsWire; state: StateWire;
  options: RunOptions & { isolation: "snapshot" | "chain"; stopOnFault: boolean; deadlineMs: number } }

// ---------------------------------------------------------------- outcomes
export type CallStatus = "returned" | "fault" | "cpu_exception" | "invalid_instruction" | "unsupported_instruction" | "unhandled_import"
  | "syscall" | "raised" | "terminated" | "budget_exhausted" | "timeout" | "cancelled" | "engine_error";
export type StatusCode = "ok" | "fault" | "cpu" | "inv" | "unsup" | "imp" | "sys" | "raised" | "term" | "budget" | "timeout" | "cancel" | "eng";
export type Attribution = "target" | "harness";
export interface StopRecord {
  status: Exclude<CallStatus, "returned">; attribution: Attribution; cause: string;
  pc: Hex; pcRegion: RegionDesc; pcFunction: (FunctionRange & { offset: Hex }) | null; instruction: Insn[];
  fault?: { access: "read" | "write" | "fetch"; kind: "unmapped" | "protected"; address: Hex; size: number; value: Hex | null; addressRegion: RegionDesc };
  exception?: { vector: number; name: string };
  importCall?: { import: string; caller: Hex; callerRva: Hex | null; args: [Hex, Hex, Hex, Hex]; xmm: [Hex, Hex, Hex, Hex] };
  isa?: { mnemonic: string; encoding: "vex" | "evex" | "engine"; rva: Hex | null; reason: string };
  syscall?: { number: Hex; args: [Hex, Hex, Hex, Hex] };
  terminate?: { via: string; code: Hex | null };
  engineError?: { errno: number; message: string };
  registers?: Record<string, Hex>;                            // rax…r15, rip, rflags, mxcsr, fpcw, fpsw, xmm0…xmm15 (128-bit)
  stackScan: Array<{ stackOffset: Hex; va: Hex; module: string | null; rva: Hex | null; note?: "harness return sentinel" }>;
  lastBlocks?: Hex[];
}
export interface ImportEvent { import: string; model: string; callerRva: Hex | null; args: [Hex, Hex, Hex, Hex]; ret: Hex | null }
export interface MemEvent { pc: Hex; access: "r" | "w"; address: Hex; size: number; value: Hex }
export interface CoverageWire { granularity: "tb"; blocks: Array<[Hex, number, number]>; distinct: number; truncated: boolean }
export interface Provenance {
  evidence: "emulation"; engine: "unicorn"; engines: EngineVersions; bridge: { version: string; sha256: string }; protocol: typeof EMU_PROTOCOL;
  source: "image" | "dump"; bundleId: string | null;
  primary: { name: string; sha256: string | null; mappedBase: Hex; preferredBase: Hex | null };
  target: { va: Hex; module: string | null; rva: Hex | null; export: string | null };
  abi: "win64"; mxcsr: Hex; fpcw: Hex; isaGuard: "stop" | "off";
}
export interface CallResult {
  status: CallStatus; attribution: Attribution | null;
  raw: { rax: Hex; xmm0: Hex; mxcsr: Hex; fpcw: Hex; fpsw: Hex };   // xmm0 128-bit
  buffers: Record<string, Hex>; out: Record<string, HexBytes>;
  stop: StopRecord | null;
  metrics: { wallUs: number; instructions?: number; blocks?: number; tbFlushes: number };
  trace?: { imports?: ImportEvent[]; blocks?: Hex[]; coverage?: CoverageWire; memory?: MemEvent[];
            instructions?: Array<{ va: Hex; text?: string }>; truncated: Record<string, boolean> };
  events: Array<{ type: "heap"; kind: string; ptr?: Hex; size?: number }>;
  deviations: Deviation[]; deterministic: boolean; provenance: Provenance;
}
export interface BatchResult {
  summary: { offset: number; vectors: number; completed: number; returned: number;
    byStatus: Partial<Record<StatusCode, number>>; byAttribution: { target: number; harness: number };
    elapsedMs: number; callsPerSecond: number | null; isolation: "snapshot" | "chain"; from: string;
    path: "fast" | "medium" | "full"; deterministic: boolean; deadlineReached: boolean; cancelled: boolean };
  columns: { status: StatusCode[]; rax: Hex[]; xmm0lo: Hex[]; out: Record<string, HexBytes[]>; instructions?: number[] };
  faults: Array<{ index: number; status: CallStatus; attribution: Attribution; cause: string; pc: Hex; pcRva: Hex | null;
                  faultAddress?: Hex; import?: string; mnemonic?: string; detail?: StopRecord /* first 8 only */ }>;
  aggregates: { imports: Record<string, { calls: number; model: string }>; deviations: Partial<Record<DeviationKind, { vectors: number; detail?: unknown }>>;
                coverage?: CoverageWire; cpuidLeaves?: Hex[] };
  provenance: Provenance;
}
export interface SweepParams {
  session: string; plan: PlanWire /* target ignored */; vectors: VectorsWire /* count ≤ 16 */;
  functions: { module: string; rvaStart: Hex; rvaEnd: Hex; offset: number; limit: number } | { targets: Hex[] };
  options: RunOptions & { deadlineMs: number };
  match: { returns: "f32" | "f64"; argsFrom: string[]; known: string[]; toleranceUlp: number } | null;
}
export interface SweepResult {
  summary: { functions: number; completed: number; byOutcomeProfile: Record<string, number>; matched: number; deadlineReached: boolean; cancelled: boolean; nextOffset: number | null };
  rows: Array<{ rva: Hex; module: string; statuses: StatusCode[]; rax: Hex[]; xmm0lo: Hex[]; matches: string[] }>;
  provenance: Provenance;
}
export interface HelloResult {
  protocol: typeof EMU_PROTOCOL; bridge: { version: string; sha256: string }; engines: EngineVersions;
  python: { version: string; executable: string; inVenv: boolean }; memoryLimit: MemoryLimitInfo;
  capabilities: { arch: ["x86_64"]; formats: ["pe64", "bea.dump/1"]; abi: ["win64"]; snapshots: ["cow", "manual"];
    trace: ["imports", "blocks", "coverage", "memory", "instructions"]; hle: string[];
    insnHooks: { cpuid: boolean; syscall: boolean; rdtsc: boolean }; sweepKnown: string[] };
  limits: { maxFrameBytes: 67108864; maxMemRead: 16777216; maxVectorsPerBatch: 1000000; maxSweepTargets: 20000;
    maxSweepVectors: 16; maxNamedSnapshots: 16; maxTraceEvents: 100000; maxPatches: 256; maxOverrides: 256 };
}
export interface MemReadResult { address: Hex; size: number; region: RegionDesc; data: string; encoding: "hex" | "base64"; overlayRestored: number }

export interface EmuMethods {
  "bridge.hello":    { params: { protocol: typeof EMU_PROTOCOL; client: { name: "bea"; version: string } }; result: HelloResult };
  "bridge.ping":     { params: Record<string, never>; result: { pong: true; busy: RequestId | null; sessions: number } };
  "bridge.cancel":   { params: { requestId: RequestId }; result: { cancelled: boolean; state: "running" | "queued" | "unknown" } };
  "bridge.shutdown": { params: Record<string, never>; result: { shutdown: true } };
  "session.open":    { params: OpenParams; result: OpenResult };
  "session.info":    { params: { session: string }; result: OpenResult & { state: SessionStateInfo } };
  "session.close":   { params: { session: string }; result: { closed: boolean } };
  "state.save":      { params: { session: string; name: string }; result: { name: string; bytes: number } };
  "state.restore":   { params: { session: string; name: string }; result: { restored: string } };
  "state.list":      { params: { session: string }; result: { snapshots: Array<{ name: string; bytes: number }>; totalBytes: number; limitBytes: number } };
  "state.drop":      { params: { session: string; name: string }; result: { dropped: boolean } };
  "mem.read":        { params: { session: string; address: Hex; size: number; encoding?: "hex" | "base64" }; result: MemReadResult };
  "mem.write":       { params: { session: string; address: Hex; hex?: HexBytes; base64?: string }; result: { written: number; region: RegionDesc; tbFlushed: boolean } };
  "mem.disassemble": { params: { session: string; address: Hex; count?: number; function?: boolean }; result: { instructions: Insn[]; function: FunctionRange | null } };
  "mem.regions":     { params: { session: string }; result: { regions: RegionInfo[]; syntheticBase: Hex } };
  "mem.functions":   { params: { session: string; module: string; rvaStart?: Hex; rvaEnd?: Hex; offset?: number; limit?: number }; result: { functions: FunctionRange[]; total: number; nextOffset: number | null } };
  "emu.call":        { params: CallParams; result: CallResult };
  "emu.batch":       { params: BatchParams; result: BatchResult };
  "emu.sweep":       { params: SweepParams; result: SweepResult };
}
export type EmuMethod = keyof EmuMethods;
```

**Ordering inside `session.open`:**
1. Load the image or dump.
2. Map the synthetic window.
3. Bind imports, including the dump IAT policy.
4. Apply `patches`, which may intentionally overwrite IAT slots or code.
5. ISA scan and install, on the post-patch bytes; patched code is scanned as patched.
6. Install the static hooks.
7. Set the FP defaults.
8. `ctl_flush_tb()`.
9. Take the baseline.

### 4.5 Example (illustrative; values from verified runs)

```jsonc
{"event":{"type":"ready","protocol":"bea-emu/0.1","bridge":{"version":"0.1.0","sha256":"…"},"pid":19184,"engines":{"python":"3.14.6","unicorn":"2.1.4","unicornCore":"2.1","capstone":"5.0.9","pefile":"2024.8.26"},"python":{"version":"3.14.6","executable":"C:\\…\\emu\\venv\\Scripts\\python.exe","inVenv":true},"memoryLimit":{"applied":true,"bytes":4294967296,"mechanism":"win32-job"}}}
// > {"id":1,"method":"bridge.hello","params":{"protocol":"bea-emu/0.1","client":{"name":"bea","version":"0.1.0"}}}
// > {"id":2,"method":"session.open","params":{"source":{"kind":"image","path":"C:\\lab\\fixture_gcc.exe"}}}
// > {"id":3,"method":"emu.call","params":{"session":"s1","plan":{"target":"0x140001730","slots":[{"reg":"xmm0","source":{"kind":"column","column":"arg0"}},{"reg":"xmm1","source":{"kind":"column","column":"arg1"}},{"reg":"xmm2","source":{"kind":"column","column":"arg2"}},{"reg":"xmm3","source":{"kind":"column","column":"arg3"}}],"returns":{"kind":"f32"},"buffers":[]},"vectors":{"offset":0,"count":1,"columns":{"arg0":["0x7fc12345"],"arg1":["0x40000000"],"arg2":["0x40400000"],"arg3":["0x40800000"]}},"state":{"from":"baseline","writes":[],"saveAs":null},"options":{"maxInstructions":200000,"timeoutMs":0,"mxcsr":8064,"fpcw":639,"faultPolicy":"stop","trace":{"imports":"full","blocks":false,"coverage":false,"countInstructions":false,"memory":"off","instructions":false,"disassemble":false,"maxEvents":10000}}}}
{"id":3,"result":{"status":"returned","attribution":null,"raw":{"rax":"0x…","xmm0":"0x7fc12345","mxcsr":"0x1f80","fpcw":"0x27f","fpsw":"0x0"},"buffers":{},"out":{},"stop":null,"metrics":{"wallUs":31.5,"tbFlushes":1},"events":[],"deviations":[],"deterministic":true,"provenance":{"evidence":"emulation","…":"…"}}}
```

`four_floats(qNaN(0x7fc12345), 2, 3, 4)` gives `0x7fc12345` in both legs [V lab:S5-E6].

---

## 5. TypeScript client (`src/emu/`)

### 5.1 `framing.ts`

```ts
export const MAX_FRAME_BYTES = 64 * 1024 * 1024;
export class FrameTooLarge extends Error {}
/** Splits a byte stream into LF-terminated frames; strips one trailing CR; never decodes partial UTF-8. */
export class NdjsonSplitter {
  #chunks: Buffer[] = []; #len = 0;
  push(chunk: Buffer): Buffer[] {               // returns complete frames (without the LF)
    const out: Buffer[] = [];
    let start = 0;
    for (let i = chunk.indexOf(0x0a); i !== -1; i = chunk.indexOf(0x0a, start)) {
      const piece = chunk.subarray(start, i);
      const line = this.#len === 0 ? piece : Buffer.concat([...this.#chunks, piece], this.#len + piece.length);
      this.#chunks = []; this.#len = 0; start = i + 1;
      const end = line.length > 0 && line[line.length - 1] === 0x0d ? line.length - 1 : line.length;
      if (end > 0) out.push(line.subarray(0, end));
    }
    const rest = chunk.subarray(start);
    if (rest.length) { this.#chunks.push(rest); this.#len += rest.length; }
    if (this.#len > MAX_FRAME_BYTES) throw new FrameTooLarge(`frame exceeds ${MAX_FRAME_BYTES} bytes`);
    return out;
  }
}
export const encodeFrame = (f: HostFrame): Buffer => Buffer.from(JSON.stringify(f) + "\n", "utf8");
```

Host frames never contain non-finite numbers, because every float travels as bits (§7). `JSON.stringify` of
`params` is therefore safe. A test asserts that no `number` leaf is non-finite.

### 5.2 `EmuBridge.ts`

```ts
export interface BridgeArtifact { path: string; sha256: string; version: string }      // from bridgeLocator
export interface EmuBridgeOptions {
  python: ResolvedPython; bridge: BridgeArtifact; memoryLimitBytes: number; cacheDir: string | null; cwd: string;
  startupTimeoutMs: number;   // 15_000
  shutdownGraceMs: number;    // 500   (bridge.shutdown reply)
  killGraceMs: number;        // 1_000 (exit after stdin EOF)
  cancelGraceMs: number;      // 2_000 (final frame after bridge.cancel)
  stderrHeadBytes: number;    // 16_384
  stderrTailBytes: number;    // 49_152
}
export interface EmuBridgeDeps { spawn: typeof import("node:child_process").spawn; now: () => number; logger: Logger }
export type BridgeExitReason = "shutdown" | "eof" | "killed" | "crashed" | "protocol_violation" | "startup_failed";
export interface BridgeExit { code: number | null; signal: NodeJS.Signals | null; reason: BridgeExitReason; stderrTail: string }
export type EmuStartError =
  | { kind: "spawn_failed"; message: string }                         // ENOENT/EACCES
  | { kind: "engine_unavailable"; data: FatalEvent["data"] }          // fatal ready
  | { kind: "exited"; exit: BridgeExit }                              // died before ready
  | { kind: "timeout"; afterMs: number }
  | { kind: "version_mismatch"; expected: { protocol: string; sha256: string; version: string }; actual: ReadyEvent | null };
export type EmuRequestFailure =
  | { kind: "bridge_error"; error: BridgeErrorBody }
  | { kind: "bridge_lost"; exit: BridgeExit }
  | { kind: "deadline"; partial: unknown | null }                     // final frame received after the auto-cancel, if any
  | { kind: "cancelled"; partial: unknown | null };
export interface RequestOptions { signal?: AbortSignal; deadlineAt?: number; onProgress?: (e: ProgressEvent) => void }

export class EmuBridge {
  static async start(o: EmuBridgeOptions, d: EmuBridgeDeps, signal: AbortSignal): Promise<Result<EmuBridge, EmuStartError>>;
  readonly pids: { child: number; bridge: number };                   // launcher vs interpreter [V lab:S5-E2]
  readonly hello: HelloResult;
  state(): "ready" | "closing" | "exited";
  request<M extends EmuMethod>(m: M, p: EmuMethods[M]["params"], o?: RequestOptions): Promise<Result<EmuMethods[M]["result"], EmuRequestFailure>>;
  ping(timeoutMs?: number): Promise<{ alive: boolean; busy: number | null }>;
  close(reason: "shutdown" | "session_closed" | "server_shutdown" | "restart"): Promise<BridgeExit>;
  onExit(listener: (e: BridgeExit) => void): () => void;
  stderrTail(maxBytes?: number): string;
}
```

**Spawn.**
- Command and arguments: `spawn(python.command, [...python.prefixArgs, "-I", "-X", "utf8", bridge.path,
  "--mem-limit", String(bytes), ...(cacheDir ? ["--cache-dir", cacheDir] : [])], {stdio:
  ["pipe","pipe","pipe"], windowsHide: true, detached: false, cwd: o.cwd /* <BEA_HOME>/emu */, env:
  bridgeEnv(process.env)})`.
- `bridgeEnv` copies the environment and drops every key matching `/^PYTHON/i`. This is defence in depth, since
  `-I` already ignores them.
- **Never `detached`.** libuv's job kills the direct child, and the launcher kills the interpreter
  [V lab:S5-E2b].
- `cwd` is a BEA-owned directory, never the user's. `EmuBridge.start` creates `<BEA_HOME>/emu` (recursive) before
  spawning.

**Startup.**
- Wait for the first frame. A `ready` event gets the version and sha256 checks; then `bridge.hello`. A `fatal`
  event, an exit, or no frame within `startupTimeoutMs` → kill, and the matching `EmuStartError`.
- `pids.bridge = ready.pid`.
- Measured `ready` latency is about 180 ms [V lab:S5-E3].

**Requests.**
- `id = ++nextId`. Encode the frame; one larger than 64 MiB fails locally as `bridge_error{frame_too_large}`.
- Register the pending entry, then write through a **serialized write queue**. If `stdin.write` returns false,
  await `drain`.
- Arm the cancellation paths:
  - **signal abort**: `cancel(id, "cancelled")`;
  - **deadline**: a timer at `deadlineAt + 1000 ms` calls `cancel(id, "deadline")`. Batch, sweep and open also
    carry `deadlineMs`, so the bridge normally stops itself first. The timer is the backstop.
- `cancel(id, why)`, at most once per id:
  - send `bridge.cancel {requestId: id}` as a fire-and-forget control frame;
  - start `cancelGraceMs`. If no final frame arrives by then: `kill()`, `reason: "killed"`, and **every**
    pending request resolves `bridge_lost`.
- **Final frame:** clear the timers.
  - `why` set → `{kind: why, partial: result ?? null}` (partial batch results are preserved).
  - Otherwise a result → `ok(result)`, and an error → `bridge_error`.

**Frame dispatch.**

| Frame | Action |
|---|---|
| `{id, event}` | the pending entry's `onProgress` |
| `{id, result \| error}` | finalize |
| a late frame for an unknown id | debug log only |
| `{id: null, error: parse_error}` | a host bug: error log, keep going |
| invalid JSON from the bridge, or `FrameTooLarge` | protocol violation: kill, `reason: "protocol_violation"` |

**Exit.**
- On the child's `exit` event: `state = exited`; every pending request resolves `bridge_lost`; the listeners fire.
- Reason: `shutdown` or `eof` when the host closed it, otherwise `crashed`.
- stderr goes into a head+tail bounded capture that is always drained [rea-process §8.2].

**Close** (idempotent):
1. `request("bridge.shutdown", {}, {deadlineAt: now + shutdownGraceMs})`, ignoring the result.
2. `stdin.end()`.
3. Wait for exit up to `killGraceMs`.
4. Otherwise `child.kill()`, then wait up to 1 s.

### 5.3 `EmuSessionRuntime.ts` (one per emulation session; S5-D3)

```ts
export type EmuSessionStatus = "opening" | "ready" | "lost" | "reopening" | "failed" | "closing" | "closed";
export interface NamedSnapshotRec { name: string; digest: StateDigest; savedAtSeq: number; generation: number; bytes: number }
export type StateDigest = `es_${string}`;                     // sha256 hex of a canonical state lineage record (§11.2)

export class EmuSessionRuntime {
  readonly kind = "emulation" as const;
  constructor(readonly id: string /* uuid */, readonly open: NormalizedOpen /* §8.1 normalized input, sans delivery args */,
              private readonly bridges: BridgeFactory, private readonly deps: RuntimeDeps) {}
  status: EmuSessionStatus = "opening";
  generation = 0; bridge: EmuBridge | null = null; bridgeSession: string | null = null;
  openResult: OpenResult | null = null;
  baselineDigest!: StateDigest; currentDigest!: StateDigest;
  named = new Map<string, NamedSnapshotRec>(); lostSnapshots: string[] = [];
  losses: number[] = [];                                        // monotonic ms of unexpected bridge exits
  async start(signal: AbortSignal): Promise<Result<OpenResult, BeaError>>;
  /** Runs one bridge request. A lost bridge is transparently re-opened first (§5.4). */
  async call<M extends EmuMethod>(m: M, p: Omit<EmuMethods[M]["params"], "session">, o: RequestOptions)
    : Promise<Result<EmuMethods[M]["result"], BeaError>>;
  async close(): Promise<Result<{ bridgeExit: BridgeExit }, BeaError>>;
}
```

- The **per-session lock** comes from the shared `SessionManager.run()` [rea-mcp §9.6]. One bridge serves one
  session, so bridge-level ordering never crosses sessions.
- **Capacity:** at most `BEA_EMU_MAX_SESSIONS` emulation sessions (default 4, config `emu.max_sessions`). The 5th
  `emu_open` gets `resource_constraint{resource: "capacity"}` with "Close an emulation session first. Configure
  `emu.max_sessions` to raise the limit."

### 5.4 Restart policy

1. **Loss detection.** The bridge's `exit` event while the session is `ready` or busy, a protocol violation, or
   the bridge error `engine_crashed` or `session_poisoned`. The host closes a poisoned bridge proactively. Then
   `status = "lost"` and `losses.push(now)`.
2. **In-flight request.** It fails as `bridge_lost`. The tool returns `capability_unavailable` (retryable), with
   `details: {bridge_exit: {code, reason}, stderr_tail (≤ 4 KiB), generation}` and remediation "Retry the call; the
   emulation session will be re-opened from its baseline." No partial result exists, so no Evidence is recorded.
3. **Lazy re-open on the next request.**
   - `status = "reopening"`, then start a new bridge and `session.open(open)` with the **same normalized
     parameters**.
   - **Identity check** against the original `openResult`: `primary.sha256`, `primary.mappedBase`, `isa.sites`,
     `imports.models`, and for dumps the bundle id. A mismatch → `failed` → `evidence_integrity_mismatch` ("the
     image or bundle changed on disk since emu_open").
   - On success: `generation += 1`; `currentDigest = baselineDigest`; every named snapshot moves into
     `lostSnapshots`, and `named` is cleared.
   - The next result carries the deviation `bridge_restarted_state_reset{generation, lostSnapshots}` and the
     limitation "The emulator was restarted; state was reset to the baseline."
4. **Crash loop.** Three losses within 10 minutes → `failed`. Every later call → `execution_failure`, not
   retryable: "The emulator crashed repeatedly for this session; close_session, then emu_open again (consider
   isa_guard, budgets, or a smaller dump)."
5. **Startup failures during a re-open** count as losses.

### 5.5 Deadlines, cancellation and progress (tool level)

- **Deadline.** Every emulation tool call computes `deadlineAt = start + min(input.timeout_ms ?? 60_000,
  110_000)` (S5-D15).
  - The bridge receives `deadlineMs = deadlineAt − now − 500` for batches, sweeps and opens.
  - On `deadline`, tools return **success** with partial coverage and a continuation (§8.2.3), not an error.
- **Cancellation.** `ctx.mcpReq.signal` → `bridge.cancel`.
  - The partial result (completed prefix) is recorded as Evidence before the `cancelled` error is projected
    (`details.partial_observation`) [rea-mcp §1.9].
  - The SDK suppresses the reply after a cancel, so the Evidence must be findable through `get_evidence` with an
    operation filter [rea-mcp §1.9].
- **Progress.** Bridge progress events become MCP progress, only when a progress token exists, at most every
  100 ms, with a strictly increasing `progress` and `message = "<phase>: <completed>/<total>"` [rea-mcp §1.8].

### 5.6 `EmuPort` (`src/ports/EmuPort.ts`; what the services use; fakeable)

```ts
export interface EmuPort {
  open(input: NormalizedOpen, signal: AbortSignal, onProgress?: Progress): Promise<Result<{ runtime: EmuSessionHandle; open: OpenResult }, BeaError>>;
  call(h: EmuSessionHandle, req: { plan: PlanWire; vectors: VectorsWire; state: StateWire; options: RunOptions }, o: RequestOptions): Promise<Result<CallResult, BeaError>>;
  batch(h: EmuSessionHandle, req: Omit<BatchParams, "session">, o: RequestOptions): Promise<Result<BatchResult, BeaError | PartialBatch>>;
  sweep(h: EmuSessionHandle, req: Omit<SweepParams, "session">, o: RequestOptions): Promise<Result<SweepResult, BeaError>>;
  state(h: EmuSessionHandle, op: { save: string } | { restore: string } | { drop: string } | { list: true }): Promise<Result<unknown, BeaError>>;
  readMemory(h: EmuSessionHandle, address: Hex, size: number): Promise<Result<MemReadResult, BeaError>>;
  disassemble(h: EmuSessionHandle, address: Hex, opts: { count?: number; function?: boolean }): Promise<Result<{ instructions: Insn[]; function: FunctionRange | null }, BeaError>>;
  regions(h: EmuSessionHandle): Promise<Result<{ regions: RegionInfo[]; syntheticBase: Hex }, BeaError>>;
  status(h: EmuSessionHandle): EmuSessionStatusView;           // no bridge round trip, except an optional ping
  close(h: EmuSessionHandle): Promise<Result<{ bridgeExit: BridgeExit }, BeaError>>;
}
export interface PartialBatch { kind: "partial"; reason: "deadline" | "cancelled"; result: BatchResult }
```

### 5.7 Shutdown participation

The server's `closeAll` (BRIEF §1.8 order) starts closing every bridge **concurrently with step 2** (killing owned
targets), because bridges are independent of targets:
- `bridge.shutdown`, then stdin EOF, then a kill at 1.5 s.
- The step must finish inside the global 2 s budget [rea-testing §0.5].
- A hard-killed server takes every bridge with it [V lab:S5-E2b].

---

## 6. Python provisioning: resolution, probe, setup, doctor

### 6.1 Resolution order (orchestrator decision, S5-D12)

```ts
// src/emu/pythonResolver.ts
export interface ResolvedPython {
  source: "BEA_PYTHON" | "bea-venv" | "path";
  command: string;            // what is spawned: an absolute path, or "python" / "py" / "python3" (looked up via PATH by Node)
  prefixArgs: string[];       // ["-3"] for py
  executable: string;         // sys.executable from the probe (a venv reports its Scripts\python.exe launcher)
  version: string;            // "3.14.6"
  inVenv: boolean;
  engines: EngineVersions;
  pin: "exact" | "compatible";                                   // "mismatch" candidates are rejected
  bridgeSha256: string;                                          // computed by the bridge itself during the probe
  probeMs: number;
}
export interface ResolutionReport { chosen: ResolvedPython | null; candidates: Array<{ source: string; command: string; outcome: string }> }
export class PythonResolver {
  constructor(deps: { spawn: typeof spawn; env: NodeJS.ProcessEnv; beaHome: string; bridge: BridgeArtifact; platform: NodeJS.Platform; fs: FsLike });
  resolve(signal: AbortSignal): Promise<Result<ResolvedPython, BeaError>>;   // memoized per server process
  invalidate(): void;                                                         // after setup, or when a cached command fails to spawn
  report(): ResolutionReport;                                                 // for doctor and bea_status
}
```

1. **`BEA_PYTHON`** (non-empty):
   - It must be an absolute path to an existing file; otherwise `configuration_invalid`.
   - Probe it. **No fall-through**: if the probe fails, the result is `capability_unavailable` with the probe
     outcome, because explicit configuration wins and must work.
2. **BEA venv** `<BEA_HOME>/emu/venv/Scripts/python.exe` (win32) or `…/bin/python3` (linux):
   - if present, probe it;
   - on failure, remember "BEA venv is broken (…): run `bea setup --emulator --repair`" and fall through.
3. **PATH.** win32: `python`, then `py -3`. linux: `python3`, then `python`.
   - Probe each in turn.
   - `ENOENT`, or exit code 9009 (a WindowsApps alias with no Python installed [B]), means skip.
   - Take the first with `ok && pin !== "mismatch"`.
4. **Nothing found** → `capability_unavailable`, remediation "Run `bea setup --emulator` (creates a BEA-owned
   Python venv with pinned unicorn 2.1.4, capstone 5.0.9, pefile 2024.8.26) or set BEA_PYTHON to a Python ≥ 3.10
   that has them."

**Pin classification:**

| Pin | Condition |
|---|---|
| `exact` | unicorn == 2.1.4, capstone == 5.0.9, pefile == 2024.8.26, Python ≥ 3.10 |
| `compatible` | unicorn 2.1.x, capstone 5.x, pefile present, Python ≥ 3.10. Every result gets the loader deviation `engine_unvalidated`, and `--selftest` runs at the first bridge start (§3.16) |
| `mismatch` | anything else (rejected; the reason is listed in the report) |

Versions come from distribution metadata, because the capstone 5.0.9 wheel reports `__version__ == "5.0.7"`
[V ext-backends §2.4 #8].

### 6.2 Spawning the resolved command

- BEA spawns `command` with `prefixArgs` exactly as resolved. It does **not** substitute `sys.executable`: for a
  venv that is the launcher anyway, and the base interpreter would lose the venv's site-packages.
- Launchers are safe for lifetime [V lab:S5-E2/E2b] and add 10–60 ms to startup [V lab:S5-E2].

### 6.3 `--probe` (one line, exit 0; exit 3 if the engines are missing)

```json
{"probe":"bea-emu/0.1","ok":true,"bridge":{"version":"0.1.0","sha256":"<hex>"},
 "python":{"version":"3.14.6","implementation":"CPython","executable":"C:\\Users\\…\\bea\\emu\\venv\\Scripts\\python.exe",
           "prefix":"…\\emu\\venv","basePrefix":"C:\\Users\\…\\pythoncore-3.14-64","inVenv":true,"bits":64,"platform":"win32"},
 "engines":{"unicorn":"2.1.4","unicornCore":"2.1","capstone":"5.0.9","pefile":"2024.8.26"},"missing":[],"errors":{}}
```

- Timeout 15 s; stdout capture ≤ 64 KiB; parse the **last** non-empty line.
- About 150–250 ms [B; `ready` measured at 180 ms, V lab:S5-E3].
- Probe results are memoized per server process.

### 6.4 `bea setup --emulator` (S5-D13)

```
bea setup --emulator [--repair | --remove] [--python PATH] [--prefer uv|pip] [--dry-run] [--yes] [--json]
```

**Plan** (read-only):
1. **Base interpreter.**
   - `--python PATH`, else `uv python find ">=3.10"` when uv exists, else `py -3` / `python` (win32) or
     `python3` (linux).
   - It must be CPython ≥ 3.10, 64-bit. (Probed with `-I -c` printing `sys.version_info`,
     `sys.implementation.name`, `struct.calcsize('P')` and `sys.executable`.)
   - If `BEA_PYTHON` is set, setup warns that it overrides the venv (§6.1).
2. **Tool.** `uv` if `uv --version` succeeds and `--prefer` is not `pip`; otherwise `venv` + `pip`, which needs the
   base's `ensurepip`.
3. **Paths.**
   - target `<BEA_HOME>/emu/venv`;
   - staging `<BEA_HOME>/emu/venv.staging-<8 hex>`;
   - lock `bridge/emu/requirements.lock`, whose sha256 is L.
4. **Plan object:**
   - `{target, tool, base: {executable, version}, packages: [{name, version, hashes}], download_estimate_mb: 17
     (unicorn 15.9 MB + capstone 1.3 MB + pefile 0.07 MB), disk_estimate_mb: 70, network: "PyPI (or your
     configured package index; integrity enforced by --require-hashes)"`,
   - `replaces: {path, marker} | null`,
   - `licensing: "unicorn's wheel metadata says BSD; Unicorn's QEMU-derived core is believed GPLv2. BEA installs it
     into a user-local venv on request and never redistributes it."` [ext-backends §10 Q1].
5. **Approval.** The REA rules [rea-cli §9.4]:
   - interactive prompt, or `--yes`;
   - non-interactive without `--yes` → `needs_confirmation`, exit 1;
   - `--dry-run` → `planned`, exit 0.

**Apply.**
- Runs under `<BEA_HOME>/emu/.setup.lock`, created `O_EXCL` and treated as stale after 10 minutes.
- Steps 6–7 build and verify in staging; steps 8–9 mark and commit.

| Step | uv route | pip route |
|---|---|---|
| 6a create | `uv venv "<staging>" --python "<base>"` with `UV_PYTHON_DOWNLOADS=never` (60 s) | `"<base>" -I -m venv "<staging>"` (60 s) |
| 6b install | `uv pip install --python "<staging-python>" --require-hashes --only-binary :all: --no-deps -r "<lock>"` (300 s) | `"<staging-python>" -I -m pip install --require-hashes --only-binary=:all: --no-deps --no-input --disable-pip-version-check -r "<lock>"` (300 s) |
| 7 verify | `"<staging-python>" -I -X utf8 "<bridge>" --probe` → `pin === "exact"`; then `--selftest` → every expected gotcha matches `selftestExpectations["2.1.4"]` | same |
| 8 marker | write `<staging>/bea-emu.json` = `{schema:"bea.emu-venv/1", created_by:{package:"bea-agents", version}, lock_sha256:L, bridge_sha256, tool, python:{version, base_executable}, engines, created_at}` | same |
| 9 commit | if the target exists, it must carry an **owned** marker, otherwise refuse ("foreign directory"); rename target → `venv.prev-<ts>`; rename staging → target; **re-probe at the final path** (relocating a venv is [B]: the launcher finds `pyvenv.cfg` next to itself); on failure, rename back (rollback); on success, delete `venv.prev-<ts>` | same |

- All child output is captured head+tail and quoted in failures.
- The user's pip and uv index configuration is **respected** (proxies, mirrors). Integrity comes from
  `--require-hashes`.
- After success: `PythonResolver.invalidate()`, and print the resolved path plus "Restart your MCP client" when a
  server is running.

**`--remove`** requires the owned marker; it deletes the target and any leftover `staging-*` or `prev-*`
directories. **`--repair`** is the same flow as install, against an existing owned venv.

Measured on this host: uv 154 ms + 5.35 s, pip 5.95 s, 68 MB [V lab:S5-E3].

### 6.5 `bridge/emu/requirements.lock` (exact content; hashes from PyPI JSON on 2026-10-28)

```
# BEA emulator bridge: exact pins, binary wheels only, hash-checked (win_amd64 + manylinux x86_64)
unicorn==2.1.4 \
    --hash=sha256:d7107500c64ce5c168fbff6bef9485b5db1350050036f4cea568650cf8bdbdf5 \
    --hash=sha256:9d6e6dea140560de4ebd8446661f7ef84a357d428c14a3ef09dacd306ec8c239
capstone==5.0.9 \
    --hash=sha256:732cedbbb56d42e723f14d7af6387f1454194a820b4b96b56d1e53f865ef85d0 \
    --hash=sha256:273fd8d747d2e35c88f91450be51a603ecfaafb00d96d9f315dcb8689c86193e
pefile==2024.8.26 \
    --hash=sha256:76f8b485dcd3b1bb8166f1128d395fa3d87af26360c2358fb75b80019b957c6f
```

| File | Notes |
|---|---|
| `unicorn-2.1.4-cp37-abi3-win_amd64.whl` (15.9 MB) | stable ABI, so one wheel serves every CPython ≥ 3.7 |
| `unicorn-2.1.4-cp37-abi3-manylinux_2_17_x86_64…` | Linux |
| `capstone-5.0.9-py3-none-win_amd64.whl` / `…manylinux_2_17_x86_64…` | |
| `pefile-2024.8.26-py3-none-any.whl` | |

- The source distributions are deliberately excluded (`--only-binary`).
- `--no-deps` is safe: none of the three needs a runtime dependency on Python ≥ 3.10 [B; it installed and imported
  cleanly, V lab:S5-E3].
- A build test re-derives the hashes from a vendored `pypi-pins.json` snapshot, so a lock edit cannot drift
  silently.

### 6.6 Doctor checks (`bea doctor --backend emulation [--probe]`)

| Check | How | Classification |
|---|---|---|
| `emulation:python` | `PythonResolver.report()` (probe only; no bridge server) | healthy when chosen; unhealthy when none |
| `emulation:pins` | `pin` | `exact` healthy; `compatible` warning ("unvalidated engine; selftest will run") |
| `emulation:bridge-file` | `bridge/emu/bea_emu_bridge.py` exists and its sha256 equals `dist/bridge-manifest.json`; the probe's self-reported sha256 is equal too | unhealthy on mismatch ("reinstall") |
| `emulation:venv` | marker present, owned, `lock_sha256 === sha256(requirements.lock)` | informational, or "stale: run `bea setup --emulator --repair`" |
| `emulation:selftest` (`--probe`) | `--selftest` with the chosen interpreter, compared with the expectations | warning per mismatched item |
| `emulation:start` (`--probe`) | start the bridge (server mode), `hello`, `session.open` on **the chosen `python.exe` itself** (a PE64 on disk, so no shipped fixture is needed), `session.close`, `shutdown`; report the `ready` latency and `memoryLimit` | healthy or unhealthy |

`bea_status` (no target) includes:

```ts
emulator: {
  available: boolean; reason?: string;
  python: { source: ResolvedPython["source"]; command: string; executable: string; version: string; pin: "exact" | "compatible" } | null;
  engines: EngineVersions | null;
  bridge: { path: string; sha256: string; version: string; protocol: "bea-emu/0.1" };
  sessions: { open: number; max: number; lost: number; failed: number };
  memory_limit_mb: number; selftest: "not-run" | "passed" | { mismatches: string[] };
}
```

---

## 7. Shared call model (`src/domain/callModel.ts`, S5-D7)

One model describes a Win64 call for `emu_call`, for `call_function` (the live batch, owned by the live designer)
and for both legs of `diff_function`. It has three parts:
- a **signature**: positional slots plus the return;
- **buffers**: named memory objects with typed fields, which can point at each other. This is a flat arena, so no
  recursive schema is needed;
- **vectors**: columns of values, one row per call.

TypeScript normalizes everything to **raw bits** and computes the **plan**. Executors (the bridge and the live
agent) never interpret types.

### 7.1 Schemas

```ts
import { z } from "zod";
export const SCALAR_TYPES = ["i8","u8","i16","u16","i32","u32","i64","u64","ptr","bool","f32","f64"] as const;
export const ARRAY_TYPES = ["i8[]","u8[]","i16[]","u16[]","i32[]","u32[]","i64[]","u64[]","f32[]","f64[]"] as const;
export type ScalarType = (typeof SCALAR_TYPES)[number];
const ident = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,63}$/u);
export const columnName = z.string().regex(/^(?:arg[0-9]{1,2}|[A-Za-z_][A-Za-z0-9_]{0,63}(?:\.[A-Za-z_][A-Za-z0-9_]{0,63})?|ret)$/u)
  .describe("argN (0-based, excluding a hidden return pointer), a slot name, <buffer>.<field>, or ret (expected values only)");
export const hexAddr = z.string().regex(/^0x[0-9a-fA-F]{1,16}$/u);
const hexBytes = z.string().max(2 * 1024 * 1024).regex(/^(?:[0-9a-fA-F]{2})*$/u);
/** A value as a caller writes it. Floats: number | "NaN" | "Infinity" | "-Infinity" | "-0" | decimal string | {bits}.
 *  Integers: safe-integer number | decimal or 0x string | {bits}. ptr also accepts "module+0xRVA" and "module!export". */
export const scalarInput = z.union([z.number(), z.string().max(300), z.boolean(), z.strictObject({ bits: hexAddr })]);
export const typedScalar = z.strictObject({ type: z.enum(SCALAR_TYPES), value: scalarInput });

export const argSlotSchema = z.union([
  z.strictObject({ type: z.enum(SCALAR_TYPES), name: ident.optional(), default: scalarInput.optional() }),
  z.strictObject({ type: z.literal("buffer_ptr"), buffer: ident, offset: z.number().int().min(0).max(16 * 1024 * 1024).default(0) }),
  z.strictObject({ type: z.literal("buffer_byval"), buffer: ident }),
]);
export const returnSchema = z.union([
  z.literal("void"), z.enum(SCALAR_TYPES),
  z.strictObject({ type: z.literal("struct"), size: z.number().int().min(1).max(4096), buffer: ident.optional() }),
]);
export const codecSchema = z.strictObject({ kind: z.enum(["xor", "add", "mul"]), key: hexAddr })
  .describe("Stored = encode(logical). xor: v^key; add: v+key mod 2^w; mul: v*key mod 2^w (key must be odd). Applies to the field's bit pattern.");
const offset = z.number().int().min(0).max(16 * 1024 * 1024 - 1);
export const fieldSchema = z.union([
  z.strictObject({ name: ident, offset, type: z.enum(SCALAR_TYPES), default: scalarInput.optional(), codec: codecSchema.optional() }),
  z.strictObject({ name: ident, offset, type: z.enum(ARRAY_TYPES), count: z.number().int().min(1).max(65536), default: z.array(scalarInput).max(65536).optional() }),
  z.strictObject({ name: ident, offset, type: z.literal("ptr_to"), buffer: ident, plus: z.number().int().min(-(2 ** 31)).max(2 ** 31 - 1).default(0) }),
]);
export const bufferSchema = z.strictObject({
  name: ident,
  size: z.number().int().min(1).max(16 * 1024 * 1024),
  align: z.union([z.literal(1), z.literal(2), z.literal(4), z.literal(8), z.literal(16), z.literal(32), z.literal(64), z.literal(4096)]).default(16),
  placement: z.enum(["scratch", "heap"]).default("scratch"),
  init: z.union([z.strictObject({ hex: hexBytes }), z.strictObject({ base64: z.string().max(1_500_000) }),
                 z.strictObject({ fill: z.number().int().min(0).max(255) })]).optional(),
  fields: z.array(fieldSchema).max(256).default([]),
  out: z.boolean().default(false),
});
export const signatureSchema = z.strictObject({
  args: z.array(argSlotSchema).max(32),
  returns: returnSchema,
  variadic: z.boolean().default(false),
});
const cell = z.union([scalarInput, z.array(scalarInput).max(65536)]);
export const vectorsSchema = z.strictObject({
  count: z.number().int().min(1).max(1_000_000).optional(),
  columns: z.record(columnName, z.array(cell).max(1_000_000)).optional(),
  rows: z.array(z.array(scalarInput.nullable()).max(32)).max(1_000_000).optional(),   // positional scalar args only
}).refine((v) => !(v.columns && v.rows), "Give columns or rows, not both.")
  .refine((v) => v.columns !== undefined || v.rows !== undefined || v.count !== undefined, "Give columns, rows, or count.");
export const distributionSchema = z.union([
  z.strictObject({ dist: z.literal("uniform"), min: z.number(), max: z.number() }),
  z.strictObject({ dist: z.literal("log_uniform"), min: z.number().positive(), max: z.number().positive(), signs: z.enum(["positive", "both"]).default("positive") }),
  z.strictObject({ dist: z.literal("grid"), values: z.array(scalarInput).min(1).max(4096) }),
  z.strictObject({ dist: z.literal("edge") }),
  z.strictObject({ dist: z.literal("bits_uniform") }),
  z.strictObject({ dist: z.literal("constant"), value: scalarInput }),
]);
export const generateSchema = z.strictObject({
  seed: z.number().int().min(0).max(0xffffffff),
  count: z.number().int().min(1).max(1_000_000).optional(),          // required unless every generated column is a grid under "cartesian"
  columns: z.record(columnName, distributionSchema),
  grid: z.enum(["cartesian", "zip"]).default("cartesian"),
});
export const fpSchema = z.strictObject({
  mxcsr: z.string().regex(/^0x[0-9a-fA-F]{1,4}$/u).optional(),   // default 0x1F80; status bits 0–5 are cleared before use
  fpcw: z.string().regex(/^0x[0-9a-fA-F]{1,4}$/u).optional(),    // default 0x027F
});
```

**Column resolution.**
- A scalar slot's column is its `name` if it has one, otherwise `argN`.
- A buffer field's column is `<buffer>.<field>`.
- Every column that the vectors do not supply takes the slot or field `default`, and otherwise zero. Such a column
  becomes a **constant**, not a per-vector column.
- An unknown column name, or a column with a different length from the others → `invalid_request`, listing the
  valid names.
- `rows[i][j]` is shorthand for column `arg<j>` (scalar slots only).

### 7.2 Value normalization (`normalizeScalar(type, input, resolveAddress) → bigint`)

| Type | Accepted input | Bits |
|---|---|---|
| f32 | a finite number (`Math.fround`; an error when \|x\| > FLT_MAX: "out of f32 range; pass {bits}"); `"NaN"` → `0x7fc00000`; `"Infinity"` / `"-Infinity"`; `"-0"`; a decimal string → `Number()` then fround (double rounding is possible, so pass `{bits}` when exactness matters); `{bits}` masked to 32 | zero-extended to 64 |
| f64 | the same with 64-bit IEEE; `"NaN"` → `0x7ff8000000000000` | 64 |
| i8 … i64 | a safe integer; a decimal or `0x` string (BigInt); `{bits}` (two's complement, masked) | range-checked, **sign-extended** to 64 |
| u8 … u64, bool | the same (bool also accepts `true`/`false`); negative values are rejected | zero-extended |
| ptr | as u64, plus the address forms `"module+0xRVA"` and `"module!export"`, **resolved per leg** by that leg's resolver (§9.3.1) | 64 |

- Array cells are arrays of the element type. Missing trailing elements take the default, else 0.
- Codecs (TypeScript only): `xor`, `add`, `mul` over the field width `w` (floats use their bit pattern). Decoding:
  `xor` → `s ^ key`; `add` → `(s − key) mod 2^w`; `mul` → `s · key⁻¹ mod 2^w`, where `key⁻¹` comes from Newton
  iteration `x ← x·(2 − key·x)`, six rounds in BigInt.
- An even `mul` key → `invalid_request` ("multiplicative codec keys must be odd to be invertible mod 2^w").
- The key is **the multiplier that maps a logical value to its stored value**. This is the user's
  "multiplicative encoding with modular-inverse keys" [ext-backends §3].

### 7.3 Normalized vectors

```ts
export interface NormalizedVectors {
  count: number;
  columns: Record<string, Hex[] | Hex[][]>;     // only the per-vector columns (constants live in the plan)
  digest: `sha256:${string}`;                    // sha256(JCS({count, columns})); enters Evidence identity
  source: { kind: "inline" } | { kind: "generated"; seed: number; spec_digest: string } | { kind: "recording"; stream_id: string; head_digest: string };
}
```

Vectors larger than 1 MiB of JSON are stored as a blob (`vectors.json`, media type `application/json`). Evidence
then cites the digest and the blob; the inputs are not inlined.

### 7.4 Win64 classification (`classifyWin64(sig, buffers) → CallPlan`)

```ts
export interface CallPlan {                       // leg-independent; each leg resolves `target` and address-form constants
  slots: Array<{ position: number; reg: ArgReg; stackIndex?: number; dupGpr?: GprName;
                 source: { kind: "column"; column: string; type: ScalarType } | { kind: "const"; bits: bigint; type: ScalarType }
                       | { kind: "buffer"; buffer: string; offset: number } | { kind: "byval"; buffer: string } }>;
  returns: { kind: "void" } | { kind: "int"; type: ScalarType; width: 1 | 2 | 4 | 8 } | { kind: "f32" } | { kind: "f64" }
         | { kind: "struct"; size: number; via: "rax" | "hidden"; buffer: string };
  buffers: NormalizedBuffer[];                    // includes synthetic "__ret" and "__byval_<i>" buffers
  columns: Array<{ name: string; type: ScalarType | `${string}[]`; count: number }>;
}
```

Algorithm (the Win64 ABI; **positional**: argument `i` uses `RCX/RDX/R8/R9` or `XMM0–3` by position, never by
class order):
1. If `returns` is a struct whose size is not 1, 2, 4 or 8, allocate an `out` buffer named `returns.buffer` or
   `__ret`. **Position 0** becomes a pointer to it, and declared arguments shift by one.
2. For each declared argument `a` at position `p`:
   - Class: `float` if `a.type ∈ {f32, f64}`, otherwise `int`. `buffer_ptr` is `int`.
   - `buffer_byval` with a buffer size of 1, 2, 4 or 8 is `int`, and its source is `byval`.
   - Any other `buffer_byval` size makes a hidden copy buffer `__byval_<p>`, initialized from the named buffer's
     template and overrides, and passes a pointer to that copy. The Win64 caller passes a pointer to a temporary
     copy.
   - Register: `p < 4` → `XMM[p]` (float) or `GPR[p]` (int). `p ≥ 4` → stack slot `p − 4`, 8 bytes at
     `[rsp + 0x28 + 8·(p−4)]` on entry.
   - `variadic` with a float at `p < 4` → `dupGpr = GPR[p]`.
3. Returns:
   - `void`;
   - `f32` from the low 32 bits of XMM0; `f64` from the low 64 bits;
   - integers, `ptr` and `bool` from RAX, truncated to the width and sign-extended per type (`bool` uses AL ≠ 0);
   - a struct of size 1, 2, 4 or 8 from the low bytes of RAX;
   - any other struct from the `__ret` buffer.
4. At most 32 slots. `__m128` and other vector arguments are **unsupported** in v0.1. Win64 passes them by
   reference, so model them as `buffer_ptr`.

`planToWire(plan, leg)` resolves the target and every `ptr` address-form constant in that leg's address space and
emits `PlanWire` (§4.4). `planToAgent(plan, leg)` emits the same structure for the live thunk executor (§9.4).

**Mapping the user's harness to the model** [ext-backends §3; read-only]:
- `call(rva, ints=[p, None], floats=[None, dt])`, with `ints[i]` in GPR *i* and `floats[i]` in XMM *i*, becomes
  `signature.args = [{type:"ptr"}, {type:"f32"}]`.
- `stack_args=[…]` becomes slots at position ≥ 4 with real types, which removes the need to pack float bits by
  hand.
- `alloc(bytes)` becomes a buffer (`placement: "scratch"`, or `"heap"` to persist with `save_as`).
- `rf`/`wf` become `out` buffers with `f32[]` fields, `read_memory` on the session, or `state.writes`.

### 7.5 Outcome decoding

```ts
export interface TypedValue { type: ScalarType; bits: Hex; value: number | string | boolean | null }
// value: f32/f64 → number, or "NaN" / "Infinity" / "-Infinity" / "-0"; i64/u64 → decimal string;
// i8–u32 → number; ptr → hex string; bool → boolean.
export interface CallOutcomeColumns {           // produced by the emulator leg (from BatchResult) and the live leg alike
  count: number; offset: number;
  status: CallStatus[]; attribution: Array<Attribution | null>;
  ret: Hex[] | null;                            // decoded return bits per vector ("" if not returned)
  fields: Record<string, Hex[] | Hex[][]>;      // "<buffer>.<field>": codec-decoded bits, out buffers only
  faults: Array<{ index: number; status: CallStatus; attribution: Attribution; cause: string; site: { module: string | null; rva: Hex | null } }>;
  fp_after?: { mxcsr_control: Hex[]; fpcw: Hex[] };   // control bits only (S5-D9)
}
export function decodeOutcome(plan: CallPlan, raw: { status: StatusCode[]; rax: Hex[]; xmm0lo: Hex[]; out: Record<string, HexBytes[]> }): CallOutcomeColumns;
```

### 7.6 Seeded generators (`src/application/diff/generators.ts`; determinism is part of the contract)

- **PRNG.** xoshiro128** (32-bit). A column's state is seeded through splitmix32 from
  `seed ⊕ fnv1a32(columnName)`, four words.
- **Floats.**
  - f32 columns draw `u = (next() >>> 8) / 2^24`.
  - f64 columns draw `u = ((a >>> 5) · 2^26 + (b >>> 6)) / 2^53`.
  - `uniform`: `x = min + u·(max − min)`, then `Math.fround` for f32.
  - `log_uniform`: `exp(ln(min) + u·(ln(max) − ln(min)))`, with an extra draw for the sign under `signs: "both"`.
- **Integers.** `uniform` over the inclusive range, by rejection sampling over 32-bit draws (BigInt for 64-bit
  ranges).
- **`edge`**, cycled to fill the column:
  - f32: `[+0, −0, 0x1, 0x7fffff, 0x800000, 1.0, −1.0, 0.5, 2.0, 0x7f7fffff, 0xff7fffff, +inf, −inf, 0x7fc00000,
    0xffc00000, 0x7fa00000]`;
  - f64: the analogous list;
  - integers: `[0, 1, −1, MIN, MAX, MIN+1, MAX−1]` per type (unsigned types skip the negatives).
- **`bits_uniform`.** Raw draws, two for 64-bit types.
- **`grid`.**
  - `cartesian`: the product of every grid column (`count` = product; a different `count` → `invalid_request`).
  - `zip`: every grid list must have the same length.
  - Non-grid columns are drawn per row.
- **Goldens.** `tests/golden/emu/generators.json` pins the first 16 rows for 6 specs. Changing the algorithm is a
  breaking change.

---

## 8. MCP tools: `emu_open`, `emu_call` (and how the shared tools treat emulation sessions)

The contracts live in `src/contracts/emulationTools.ts` and follow the BRIEF conventions:
- `z.strictObject` flat roots;
- refines for exclusivity;
- bounded numbers;
- examples parsed through the real schemas;
- output schemas without prose [rea-mcp §2, §3.1].

The **result** objects below sit inside the standard compact success envelope [BRIEF §1.5].

**Schema budget.** A contract test pins each input schema at **≤ 12 KiB of compact JSON Schema and depth ≤ 10**,
because clients reject single tool schemas around 13.7–15 KB [BRIEF §1.11; rea-mcp §3.1]. Estimates [B]:
`emu_open` about 3 KiB, `emu_call` about 9 KiB, `diff_function` about 11 KiB. If a schema goes over, trim in this
order:
1. drop the `rows` shorthand (`columns` stays);
2. drop the buffer `init.fill` and `init.base64` variants (`hex` stays);
3. move `distributionSchema` behind a single `{dist, params}` object with prose constraints.

The call-model fragments are shared, so `call_function` inherits the same budget.

### 8.1 `emu_open`

| | |
|---|---|
| Purpose | Open a Unicorn emulation session from an on-disk PE64 image or a `bea.dump/1` bundle. Runs the ISA scan (cached), binds imports, applies patches and takes the baseline. Returns `session_id` (kind `emulation`) |
| Effects | `mutatesSession` only. The bridge is a BEA helper and does not count as `launchesProcess` [BRIEF §1.4]. It touches no target |
| Hints | readOnly **true**, destructive false, idempotent false (each call creates a session), openWorld false |
| `returnsTargetContent` | true (image names, section names and imports are attacker-controlled strings) |
| CLI | `mcp-only`, with reason "session state cannot cross CLI processes; use `bea emulate request.json` or `bea run scenario.json`" |
| Phase | P2 [BRIEF §6.7] |

```ts
const hex16 = z.string().regex(/^0x[0-9a-fA-F]{1,4}$/u);
export const emuOpenInput = z.strictObject({
  image_path: z.string().min(1).max(4096).optional(),
  dump_path: z.string().min(1).max(4096).optional(),
  image_base: hexAddr.optional(),                                   // relocate (64 KiB aligned; needs .reloc)
  thread_id: z.number().int().min(1).max(0xffffffff).optional(),    // dump: which captured thread provides the TEB (default: the primary)
  primary_module: z.string().max(260).optional(),                   // dump: default is the process image
  static_base: hexAddr.optional(),                                  // base used for static_va inputs (default: preferred ImageBase from disk)
  imports: z.strictObject({
    builtin: z.boolean().default(true),
    unhandled: z.enum(["stop", "return_zero"]).default("stop"),
    dump_policy: z.enum(["auto", "hle_known", "lle", "stop_all"]).default("auto"),
    overrides: z.array(z.strictObject({
      import: z.string().max(300).regex(/^(?:[^!\s]{1,255}!)?[^!\s]{1,255}$/u),     // "kernel32.dll!CreateEventA" or "sqrtf"
      action: z.enum(["return", "stop", "model"]),
      returns: typedScalar.optional(),                              // action "return"
      model: z.string().max(64).optional(),                         // action "model": a builtin name
    })).max(256).default([]),
  }).optional(),
  patches: z.array(z.strictObject({
    address: z.string().max(300),                                   // "0x…", "module+0xRVA", "module!export"
    hex: hexBytes.optional(), value: typedScalar.optional(),
  }).refine((p) => (p.hex === undefined) !== (p.value === undefined), "Each patch needs exactly one of hex or value."))
    .max(256).optional(),
  memory: z.strictObject({
    heap_mb: z.number().int().min(1).max(256).default(64),
    scratch_mb: z.number().int().min(1).max(256).default(16),
    stack_kb: z.number().int().min(64).max(16384).default(1024),
  }).optional(),
  fp: fpSchema.optional(),
  isa_guard: z.enum(["stop", "off"]).default("stop"),
  protections: z.enum(["sections", "rwx"]).default("sections"),
  fault_policy: z.enum(["stop", "map_zero"]).default("stop"),
  snapshots: z.enum(["cow", "manual"]).default("cow"),
  timeout_ms: z.number().int().min(1000).max(110_000).default(60_000),
  label: z.string().max(64).optional(),                             // delivery-only; excluded from identity
})
  .refine((x) => (x.image_path === undefined) !== (x.dump_path === undefined), "Give exactly one of image_path or dump_path.")
  .refine((x) => x.fault_policy !== "map_zero" || x.snapshots === "manual", "fault_policy \"map_zero\" requires snapshots \"manual\" (Unicorn memory snapshots need a frozen layout).")
  .refine((x) => x.dump_path !== undefined || (x.thread_id === undefined && x.primary_module === undefined), "thread_id and primary_module apply to dump_path only.")
  .refine((x) => x.image_path !== undefined || x.image_base === undefined, "image_base applies to image_path only.");
```

**Workflow** (`EmulationService.open`):
1. Validate the input. Both paths must be absolute.
2. Check capacity (§5.3).
3. Resolve Python (§6.1).
4. For `dump_path`: `verifyDumpBundle()` (§10.4), recomputing the manifest digest and the file sizes. The bridge
   re-hashes the region files at load.
5. For `image_path`: sha256 the file on the host. It must equal the bridge's `primary.sha256`, otherwise
   `evidence_integrity_mismatch` (the file changed while opening).
6. Resolve the `patches` addresses using the open result's modules. This needs a **two-phase open**: the bridge
   resolves `module+0xRVA` itself because it knows the modules, so TypeScript sends patch addresses in **symbolic
   form**. The bridge accepts `address` as `Hex | "mod+0x…" | "mod!export"` inside `OpenParams.patches` (a
   documented exception to "TS resolves everything").
7. Start the `EmuSessionRuntime`, wait for `session.open` (with progress), and compute `baselineDigest` (§11.2).
8. Record the `bea.emu.session` Evidence. Return.

**Result** (`emuOpenResult`):

```ts
{
  session_id: string; kind: "emulation"; source: "image" | "dump"; bundle_id: string | null;
  primary: { name: string; path: string | null; sha256: string | null; preferred_base: Hex | null; mapped_base: Hex; static_base: Hex;
             static_base_source: "pe-header" | "caller"; relocated: boolean; size: number; sections: number; exports: number;
             pdata_functions: number; tls_callbacks: number; delay_imports: number };
  modules: Array<{ name: string; mapped_base: Hex; size: number; captured: "image" | "full" | "partial" | "none"; sha256: string | null }>;  // ≤ 64; dump sessions
  thread: { tid: number; teb: Hex } | null;
  imports: { total: number; models: Record<string, number>; unhandled_sample: string[] /* ≤ 50 */ };
  isa: { cache: "hit" | "miss" | "off"; scan_ms: number; sites: Record<string, number>; guarded: { int3: number; hooks: number; unguarded: number }; functions_with_vex_sample: Hex[] /* ≤ 20 RVAs */ };
  fp: { mxcsr: Hex; fpcw: Hex }; snapshots: "cow" | "manual";
  memory: { heap_mb: number; scratch_mb: number; stack_kb: number; mapped_mb: number; synthetic_base: Hex; limit_mb: number };
  loader_deviations: Array<{ kind: DeviationKind; note: string; count?: number }>;
  bridge: { pid: number; child_pid: number; version: string; protocol: "bea-emu/0.1"; generation: number;
            engines: EngineVersions; python: { source: string; version: string; pin: "exact" | "compatible" } };
  baseline_state: StateDigest;
  timings_ms: { bridge_start: number; load: number; isa: number; bind: number; snapshot: number; total: number };
}
```

### 8.2 `emu_call`

| | |
|---|---|
| Purpose | Emulate one call (full detail), a batch of vectors (columnar), or a sweep of functions (behavioural identification). Typed Win64 arguments through the shared call model; deterministic instruction budget; FP environment; isolation `snapshot` or `chain`; named state; opt-in bounded tracing and coverage. Faults and stops are **statuses**. Results are **derivations** carrying `deviations[]` |
| Effects | `mutatesSession` only (sandboxed) |
| Hints | readOnly **true**, destructive false, idempotent **false** (`chain` and `save_as` change emulator state), openWorld false |
| `returnsTargetContent` | true |
| CLI | `mcp-only` (reason as above); reachable through `bea emulate` and scenarios (§8.6) |

```ts
const snapName = z.string().regex(/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/u).refine((s) => s !== "baseline" && s !== "current");
export const stateSchema = z.strictObject({
  from: z.union([z.enum(["baseline", "current"]), snapName]).default("baseline"),
  writes: z.array(z.strictObject({ address: z.string().max(300), hex: hexBytes.optional(), value: typedScalar.optional() })
    .refine((w) => (w.hex === undefined) !== (w.value === undefined), "Each write needs exactly one of hex or value.")).max(256).default([]),
  save_as: snapName.optional(),
  drop: z.array(snapName).max(16).default([]),                     // drop named snapshots after the call
});
export const traceSchema = z.strictObject({
  imports: z.enum(["off", "counts", "full"]).optional(),           // default: full (single) / counts (batch)
  blocks: z.boolean().default(false),                              // single only
  coverage: z.boolean().default(false),                            // single and batch (aggregated)
  count_instructions: z.boolean().default(false),
  memory: z.enum(["off", "reads", "writes", "all"]).default("off"), // single only
  instructions: z.boolean().default(false),                        // single only
  disassemble: z.boolean().default(false),
  max_events: z.number().int().min(1).max(100_000).default(10_000),
});
export const sweepSchema = z.strictObject({
  module: z.string().max(260).optional(),                          // default: the primary module
  rva_start: hexAddr.optional(), rva_end: hexAddr.optional(),       // .pdata functions with begin in [start, end)
  targets: z.array(z.string().max(300)).max(20_000).optional(),
  match: z.strictObject({
    returns: z.enum(["f32", "f64"]),
    args: z.array(columnName).min(1).max(2),
    known: z.union([z.enum(["unary", "binary", "all"]), z.array(z.string().max(16)).max(64)]).default("all"),
    tolerance_ulp: z.number().int().min(0).max(64).default(1),
  }).optional(),
  offset: z.number().int().min(0).max(20_000).default(0),
  limit: z.number().int().min(1).max(20_000).default(5_000),
}).refine((s) => (s.targets !== undefined) !== (s.rva_start !== undefined && s.rva_end !== undefined), "Give targets, or rva_start and rva_end.");
export const emuCallInput = z.strictObject({
  session_id: z.string().uuid(),
  target: z.string().max(300).optional(),                          // "0x…" (emulator VA), "module+0xRVA", "module!export"
  static_va: hexAddr.optional(), module: z.string().max(260).optional(), static_base: hexAddr.optional(),
  signature: signatureSchema,
  buffers: z.array(bufferSchema).max(64).default([]),
  args: z.array(scalarInput.nullable()).max(32).optional(),        // single call: positional values (null = default)
  fields: z.record(columnName, cell).optional(),                   // single call: "<buffer>.<field>" overrides
  vectors: vectorsSchema.optional(),                               // batch
  generate: generateSchema.optional(),                             // batch
  sweep: sweepSchema.optional(),                                   // sweep (vectors = the probe inputs, count ≤ 16)
  state: stateSchema.optional(),
  isolation: z.enum(["snapshot", "chain"]).default("snapshot"),
  budget: z.strictObject({
    max_instructions: z.number().int().min(0).max(10_000_000_000).default(1_000_000),   // 0 = unbudgeted
    timeout_ms_per_call: z.number().int().min(0).max(110_000).default(0),               // wall-clock safety net
  }).optional(),
  fp: fpSchema.optional(),
  trace: traceSchema.optional(),
  fault_policy: z.enum(["stop", "map_zero"]).default("stop"),
  stop_on_fault: z.boolean().default(false),
  vector_offset: z.number().int().min(0).max(1_000_000).default(0),
  inline_limit: z.number().int().min(0).max(256).default(64),
  detail: z.enum(["summary", "complete"]).default("summary"),
  timeout_ms: z.number().int().min(1000).max(110_000).default(60_000),
})
  .refine((x) => [x.args !== undefined || x.fields !== undefined, x.vectors !== undefined, x.generate !== undefined, x.sweep !== undefined]
      .filter(Boolean).length <= 1, "Use exactly one mode: args/fields (single call), vectors or generate (batch), or sweep.")
  .refine((x) => x.sweep !== undefined || ((x.target !== undefined) !== (x.static_va !== undefined)), "Give exactly one of target or static_va (except in sweep mode).")
  .refine((x) => x.sweep === undefined || (x.vectors?.count ?? 1) <= 16, "Sweep probe vectors are limited to 16.");
```

**Mode.**
- **Single** when none of `vectors`, `generate` or `sweep` is given (`args` may be omitted for zero-argument
  functions).
- **Batch** when `vectors` or `generate` is given.
- **Sweep** when `sweep` is given (`vectors` holds the probe inputs).

**Workflow** (`EmulationService.call`):
1. Look up the session; it must be kind `emulation`, otherwise `invalid_request` ("use call_function for live
   sessions").
2. Resolve the target:
   - `static_va` → `mapped_base(module) + (static_va − (static_base ?? session.static_base))`;
   - otherwise the string form through the session's module table.
   - The result is an AddressInfo `{va, module, rva, static_va, static_base, static_base_source, image_sha256,
     address_space: "emulation"}` [BRIEF §6.0].
3. Classify the plan (§7.4). Normalize the vectors (§7.3), or generate them (§7.6).
4. **Continuation.** Slice the vectors from `vector_offset`.
5. Pick the bridge method (`emu.call`, `emu.batch` or `emu.sweep`). Build `StateWire` from `state`: resolve the
   write addresses, and turn `value` writes into bytes via `normalizeScalar`.
6. Run with the deadline (§5.5).
7. Decode the outcomes (§7.5).
8. Shape the result:
   - **Single:** full detail.
   - **Batch:** if `completed ≤ inline_limit`, inline columns; otherwise write the rows to a **stream** (§11.3) and
     return the summary, a preview, the stream id and the continuation.
9. Update the state lineage (§11.2). `save_as` → `state.save`; `drop` → `state.drop`.
10. Build the coverage blob if requested (§11.4).
11. Record the Evidence (`bea.emu.run`, `bea.emu.batch` or `bea.emu.sweep`).

#### 8.2.1 Single-call result

```ts
{
  mode: "single"; target: AddressInfo;
  call: {
    status: CallStatus; attribution: Attribution | null;
    ret: TypedValue | null;                                 // decoded per signature.returns
    outputs: Record<string, TypedValue | TypedValue[]>;      // "<buffer>.<field>" of out buffers (codec-decoded)
    out_buffers: Record<string, { address: Hex; bytes: number; hex: string /* ≤ 4 KiB */; truncated: boolean }>;
    raw: { rax: Hex; xmm0: Hex; mxcsr: Hex; fpcw: Hex };
    stop: StopView | null;                                  // StopRecord without registers unless detail = "complete"
    metrics: { wall_us: number; instructions?: number; blocks?: number };
    trace?: { imports?: ImportEvent[] /* ≤ 200 inline */; blocks?: { executed: number; unique: number; sample: Hex[] /* ≤ 64 */ };
              memory?: MemEvent[] /* ≤ 200 */; instructions?: Array<{ va: Hex; text?: string }> /* ≤ 200 */;
              truncated: Record<string, boolean>; full_trace_blob?: { sha256: string; bytes: number } };
    events: Array<{ type: "heap"; kind: string; ptr?: Hex; size?: number }>;
    deviations: Deviation[]; deterministic: boolean;
  };
  state: { from: string; from_digest: StateDigest; after_digest: StateDigest; saved_as: string | null };
  coverage: { blob: { sha256: string; bytes: number }; blocks: number } | null;
}
```

#### 8.2.2 Batch result

```ts
{
  mode: "batch"; target: AddressInfo;
  batch: {
    offset: number; vectors: number; completed: number; returned: number;
    by_status: Partial<Record<CallStatus, number>>; by_attribution: { target: number; harness: number };
    elapsed_ms: number; calls_per_second: number | null; isolation: "snapshot" | "chain"; path: "fast" | "medium" | "full";
    deterministic: boolean; deadline_reached: boolean; cancelled: boolean;
    continuation: { vector_offset: number } | null;         // present iff completed < vectors (deadline / stop_on_fault excluded)
    columns: Record<string, { bits: Hex[]; value: TypedValue["value"][] }> | null;   // "status", "ret", "<buf>.<field>" when inline
    status: CallStatus[] | null;                            // inline only
    preview: { first: Row[]; last: Row[] } | null;          // ≤ 8 each, when not inline
    ret_stats: { min: TypedValue | null; max: TypedValue | null; nan: number; inf: number; distinct_bits: number } | null;
    faults: Array<{ index: number; status: CallStatus; attribution: Attribution; cause: string; pc_rva: Hex | null; detail?: StopView }>;  // ≤ 32
    stream_id: string | null;                               // rows, when not inline
    vectors_blob: { sha256: string } | null;
    imports: Record<string, { calls: number; model: string }>;
    deviations: Array<{ kind: DeviationKind; vectors: number; note: string }>;
  };
  state: { from: string; from_digest: StateDigest; after_digest: StateDigest; saved_as: string | null };
  coverage: { blob: { sha256: string; bytes: number }; blocks: number } | null;
}
```

#### 8.2.3 Continuation

- When the deadline stops a batch, `continuation = {vector_offset: offset + completed}`. Re-calling with the same
  input plus that `vector_offset` resumes. Generated vectors are reproducible from the seed, so `generate` resumes
  exactly.
- Under `isolation: "chain"`, resuming starts from `state.from` again. The tool therefore refuses a continuation
  of a chain batch unless `state.from === "current"`; the error says to use `from: "current"` for chained
  resumption.

#### 8.2.4 Sweep result

```ts
{ mode: "sweep";
  sweep: { module: string; functions: number; completed: number; by_outcome_profile: Record<string, number>;
           matched: Array<{ rva: Hex; va: Hex; matches: string[] }> /* ≤ 200 */; next_offset: number | null;
           deadline_reached: boolean; stream_id: string | null } }
```

### 8.3 How the shared tools behave on emulation sessions

| Tool | Behaviour with an emulation `session_id` | Evidence |
|---|---|---|
| `session_status` | no bridge request unless `detail: "complete"` (then `bridge.ping` and `session.info`). Reports `kind: "emulation"`, the status (`ready`/`lost`/`failed`…), generation, bridge pids, the named snapshots with sizes and digests, `lost_snapshots`, `current_state` digest, call and vector counters, loader deviations, isa summary, memory limit | none, or `bea.emu.session.status` with `complete` |
| `close_session` | `session.close`, then bridge close (§5.2). Returns `{closed: true, bridge_exit}`. No target effects | `bea.emu.session.closed` |
| `read_memory` | `mem.read` (overlay-transparent: INT3 sites show original bytes, with `overlayRestored` count). Address forms resolve through the session's modules | `bea.emu.memory.read` (derived, authority emulation, subject emulation at `currentDigest`) |
| `disassemble` | `mem.disassemble` (original bytes, plus `function` from `.pdata`) | `bea.emu.disassembly` |
| `write_memory` | **not needed** for emulation. Use `emu_open.patches` (before the baseline) and `emu_call.state.writes`. This keeps emulation independent of the live write gate [P] | none |
| `export_coverage` | accepts `source: evidence_id` of a `bea.emu.run` or `bea.emu.batch` result that holds a `bea.coverage/1` blob (§11.4) | the export tool's own |
| `query_events` | pages `emu-batch`, `emu-sweep` and `diff` row streams (§11.3) | derived (the query tool's own) |
| `get_evidence` / `export_evidence` | generic | none |

### 8.4 Effects table (`src/contracts/effects.ts` rows)

| Tool | readsTargetMemory | injectsCode | instrumentsTarget | writesTargetMemory | executesTargetCode | launchesProcess | killsProcess | writesFilesystem | mayDiscardData | mutatesSession | idempotent | → readOnly / destructive / idempotent / openWorld |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `emu_open` | – | – | – | – | – | – | – | – | – | ✓ | – | **true** / false / false / false |
| `emu_call` | – | – | – | – | – | – | – | – | – | ✓ | – | **true** / false / false / false |
| `diff_function` | ✓ | – | – | ✓ | ✓ | – | – | – | – | ✓ | – | false / **true** / false / false |

`diff_function` stays destructive even when no live leg is requested, because annotations are static per tool. The
description says that "the live leg runs target code; omit live_session_id for a sandboxed comparison".

### 8.5 Examples (each parsed through the real schemas in the contract test)

```jsonc
// emu_open: on-disk image, CRT sqrtf aliased to an exact model, one .data tunable patched
{ "image_path": "C:/games/example/game.exe", "imports": { "overrides": [{ "import": "my_sqrtf", "action": "model", "model": "sqrtf" }] },
  "patches": [{ "address": "game.exe+0x1a2b3c0", "value": { "type": "f32", "value": 1.5 } }] }
// emu_call: single call f(Car*, float), struct via a buffer with an obfuscated field
{ "session_id": "…", "target": "game.exe+0x123460",
  "signature": { "args": [{ "type": "buffer_ptr", "buffer": "car" }, { "type": "f32", "name": "dt" }], "returns": "f32" },
  "buffers": [{ "name": "car", "size": 64, "out": true, "fields": [
      { "name": "speed", "offset": 0, "type": "f32", "default": 10 },
      { "name": "gear", "offset": 4, "type": "u32", "default": 3, "codec": { "kind": "mul", "key": "0x9e3779b1" } },
      { "name": "wheels", "offset": 8, "type": "ptr_to", "buffer": "wheels" } ] },
    { "name": "wheels", "size": 64, "fields": [{ "name": "slip", "offset": 0, "type": "f32[]", "count": 4, "default": [0, 0, 0, 0] }] }],
  "args": [null, 0.016] }
// emu_call: batch from Ghidra addresses, generated inputs, coverage
{ "session_id": "…", "static_va": "0x140123460", "signature": { "args": [{ "type": "f32" }, { "type": "f32" }], "returns": "f32" },
  "generate": { "seed": 7, "count": 20000, "columns": { "arg0": { "dist": "uniform", "min": -2, "max": 2 }, "arg1": { "dist": "edge" } } },
  "trace": { "coverage": true } }
// emu_call: behavioural sweep of a range against known math functions
{ "session_id": "…", "target": "game.exe+0x0", "signature": { "args": [{ "type": "f32" }], "returns": "f32" },
  "vectors": { "columns": { "arg0": [0, 0.1, 0.5, 1, 2, -0.7] } },
  "sweep": { "rva_start": "0x900000", "rva_end": "0x980000", "match": { "returns": "f32", "args": ["arg0"] } },
  "budget": { "max_instructions": 100000 } }
```

(The example addresses are illustrative placeholders, not values from the user's project.)

### 8.6 CLI: `bea emulate request.json`

- `bea emulate <file|->` is a **scenario with `target: {mode: "none"}`**, validated by the same zod schemas
  [rea-cli §9.3].
- Request shape: `{open: <emu_open input>, steps: [{tool: "emu_call", input: <emu_call input without
  session_id>} | {tool: "diff_function", input: <diff input without session ids; legs ⊆ {emulation, expected}>} |
  {tool: "read_memory" | "disassemble", input: …}], evidence_out?: "<dir>"}`.
- The runner injects the session id, runs the steps in order, closes the session, and prints the step results
  (TOON by default, `--json` compact).
- `--evidence-out DIR` exports one bundle.
- Exit codes follow REA: 0 completed (possibly partial), 1 failed, 130/143/141 [rea-cli §4.4].
- A diff with a live leg needs `bea run scenario.json` with a spawn target.

---

## 9. `diff_function` (S5-D8, S5-D9, S5-D10)

| | |
|---|---|
| Purpose | Run the same input vectors through two or three **legs**: `live` (in-process exact-bit oracle calls), `emulation` (Unicorn) and `expected` (caller values, a hook recording, or a captured call's real return). Compare them **bit-exactly**, with ulp statistics. Verdict: `equivalent-on-tested-inputs`, `differ` or `unknown`. Records a residual unknown whenever the verdict is not equivalence |
| Effects | readsTargetMemory, writesTargetMemory, executesTargetCode (the live leg), mutatesSession |
| Hints | readOnly false, **destructive true**, idempotent false, openWorld false |
| Gates | live leg on an **owned** target: allowed by default. On an **attached** target: requires `gates.call_attached` (the gate call_function uses), else `capability_unavailable` with remediation "Enable the attached-target call gate (config gates.call_attached or BEA_ALLOW_CALL_ATTACHED=1) and restart BEA" |
| CLI | `mcp-only`. Emulation-vs-expected diffs run inside `bea emulate`; live diffs run inside `bea run scenario.json` |

### 9.1 Input

```ts
const legEnum = z.enum(["live", "emulation", "expected"]);
export const diffFunctionInput = z.strictObject({
  emu_session_id: z.string().uuid().optional(),
  live_session_id: z.string().uuid().optional(),
  target: z.string().max(300).optional(),                         // "module+0xRVA" recommended: resolves in each leg's address space
  static_va: hexAddr.optional(), module: z.string().max(260).optional(), static_base: hexAddr.optional(),
  signature: signatureSchema,
  buffers: z.array(bufferSchema).max(64).default([]),
  vectors: vectorsSchema.optional(),
  generate: generateSchema.optional(),
  from_recording: z.strictObject({
    stream_id: z.string().max(80),
    args: z.array(z.string().max(64)).min(1).max(32),             // capture field names, in positional order
    ret: z.string().max(64).optional(),                           // capture field → expected "ret"
    max_events: z.number().int().min(1).max(100_000).default(10_000),
  }).optional(),
  from_dump_call: z.boolean().optional(),                         // replay the bundle's captured call (§10.6)
  expected: z.strictObject({ columns: z.record(columnName, z.array(cell.nullable()).max(1_000_000)) }).optional(),  // "ret", "<buf>.<field>"
  legs: z.array(legEnum).min(2).max(3).optional(),                // default: every leg whose inputs are present
  compare: z.strictObject({
    columns: z.array(columnName).max(64).optional(),              // default: "ret" (if not void) + every out-buffer field
    nan: z.enum(["bits", "any_nan"]).default("bits"),
    tolerance: z.strictObject({ ulp: z.number().int().min(0).max(1 << 30).optional(), abs: z.number().min(0).optional(), rel: z.number().min(0).optional() }).optional(),
    inconclusive: z.enum(["count", "exclude"]).default("count"),
    compare_fault_sites: z.boolean().default(true),
  }).optional(),
  live: z.strictObject({
    thread: z.union([z.literal("agent"), z.strictObject({ tid: z.number().int().min(1).max(0xffffffff) })]).default("agent"),
    chunk: z.number().int().min(1).max(10_000).default(1_000),
  }).optional(),
  emulation: z.strictObject({
    isolation: z.enum(["snapshot", "chain"]).default("snapshot"),
    state_from: z.union([z.enum(["baseline", "current"]), snapName]).default("baseline"),
    max_instructions: z.number().int().min(0).max(10_000_000_000).default(1_000_000),
  }).optional(),
  fp: fpSchema.optional(),                                        // identical for both executing legs
  allow_image_mismatch: z.boolean().default(false),
  record_unknown: z.boolean().default(true),
  vector_offset: z.number().int().min(0).max(1_000_000).default(0),
  inline_limit: z.number().int().min(0).max(256).default(64),
  timeout_ms: z.number().int().min(1000).max(110_000).default(60_000),
})
  .refine((x) => [x.vectors, x.generate, x.from_recording, x.from_dump_call ? true : undefined].filter((v) => v !== undefined).length === 1,
          "Give exactly one input source: vectors, generate, from_recording, or from_dump_call.")
  .refine((x) => x.from_dump_call !== undefined || ((x.target !== undefined) !== (x.static_va !== undefined)), "Give exactly one of target or static_va.")
  .refine((x) => countAvailableLegs(x) >= 2, "Need at least two legs: live_session_id (live), emu_session_id (emulation), expected/from_recording.ret/from_dump_call (expected).");
```

### 9.2 Workflow (`DiffService.run`)

1. **Resolve the legs.**
   - `live` needs `live_session_id`, a live session that is alive, and the gate check.
   - `emulation` needs `emu_session_id`.
   - `expected` needs `expected`, `from_recording.ret`, or a `from_dump_call` whose trigger has a `ret`.
   - When `legs` is given, every listed leg must be available.
2. **Align the target** (§9.3.1) and check image identity.
3. **Build the vectors** (§7.3, §7.6, §9.3.3, §10.6) and slice from `vector_offset`. Classify the **one** plan
   (§7.4) that both executing legs will run.
4. **Emulation leg first.** It is sandboxed and fast. `EmuPort.batch` with the leg's isolation, `state_from`,
   budget and `fp`, with the deadline at 45 % of the remaining budget. Its Evidence is `bea.emu.batch`, recorded
   as usual.
5. **Live leg.**
   - `OracleCallPort.callPlanBatch` over **exactly the vector range the emulation leg completed** (or every vector
     when there is no emulation leg), with the same `fp`, chunked, until the deadline.
   - Its Evidence is `bea.call.oracle`, plus one `function-called` Effect, recorded by the live service.
6. **Expected leg.** Normalize the columns per type (the `ret` type comes from `signature.returns`). A `null` cell
   means "not compared".
7. **Compare** (§9.7). Compute the statistics, the worst list and the hints (§9.8).
8. **Rows.** At most `inline_limit` inline; otherwise a `diff` stream (§11.3).
9. **Record** `bea.diff` (§11.1). When the verdict is not equivalence and `record_unknown` is true, create or
   update the unknown (§9.9).
10. **Deadline.** Vectors not run on any leg are `not_run`, which is inconclusive. The verdict becomes `unknown`
    (reason `deadline`) and a `continuation: {vector_offset}` is returned.

### 9.3 Leg semantics

#### 9.3.1 Target alignment and identity

- **Resolution per leg.**
  - `module+0xRVA`: `module_base(leg) + rva`.
  - `module!export`: the export in that leg.
  - `static_va`: `module_base(leg) + (static_va − (static_base ?? preferred_base_from_disk))` [ext-frida §3.14].
  - A raw `0x…` target is accepted only for a single-leg-space situation: emulation plus expected, or a dump
    session whose bundle `producer.instance_id` equals the live session's instance.
- **Identity.**
  - The live module's on-disk `file_sha256` must equal the emulation module's sha256: the image file sha256, or
    the bundle module's `file_sha256`.
  - On a mismatch: `invalid_request` ("the live module and the emulated image are different binaries"), unless
    `allow_image_mismatch`. That adds the limitation and the hint `image_mismatch`.
- **`ptr` values** given as address forms resolve per leg. Raw hex `ptr` values pass through verbatim. With an
  image-backed emulation session and a live leg, that gives the hint `raw_pointer_inputs` ("raw pointers refer to
  the live address space and are unmapped in an image-backed emulator; use buffers, address forms, or a
  dump-backed session").

#### 9.3.2 Outcome classes per leg and vector

| Leg | `returned` | `target_stop` | `harness_stop` | `not_run` |
|---|---|---|---|---|
| live | the thunk returned | stolen exception: `access-violation`, `guard-page`, `stack-overflow` → `fault`; `illegal-instruction` → `cpu_exception/ud`; `arithmetic` → `cpu_exception/div_error`; `breakpoint` → `cpu_exception/breakpoint` | an RPC error for the chunk, `abort`/`system` exceptions, an input that cannot be represented | after `lostTarget` (the process died, for example from `abort` or fastfail inside the function), cancelled, or past the deadline |
| emulation | `returned` | any status with attribution `target` | any status with attribution `harness` | past the deadline, or cancelled |
| expected | a non-null cell | none | none | every compared cell is null |

The live-leg mapping uses Frida's exception `type` strings [ext-frida §3.7, §3.11]. A live call that terminates
the process ends an owned session. That is reported as `lost_target` with the limitation "the function terminated
the live process during the live leg".

#### 9.3.3 Recording leg (`from_recording`, P2)

- Rows come from `query_events(stream_id)`. The hook capture must provide **bits** for each named field (an
  interface the hooks designer provides).
- Column `arg<i>` takes `args[i]`'s bits. `ret` becomes the expected leg.
- **v0.1 restriction:** scalar-only signatures. A `buffer_ptr`/`buffer_byval` slot → `invalid_request`
  ("recordings cannot reproduce pointed-to memory; capture a dump at the hook instead (§10.6)").
- `vectors.source = {kind: "recording", stream_id, head_digest}` enters the identity.

#### 9.3.4 FP environment and isolation

- **FP environment.** Both executing legs get the same `mxcsr` (control bits; status bits cleared) and `fpcw` per
  call, by default `0x1F80`/`0x027F`. The thunk sets them per call [V lab:S5-E6]. Status flags are never compared
  (S5-D9).
- **Isolation.** The live leg **is never isolated**: process globals persist from vector to vector, though buffers
  are fresh per vector in both legs. Emulation `isolation: "snapshot"` resets globals each vector. When there are
  differences, a live leg, and snapshot isolation, the result carries the hint `possible_state_carryover`.

### 9.4 `OracleCallPort` (required from the live designer)

```ts
// src/ports/OracleCallPort.ts
export interface LiveBatchRaw {                    // the same raw shape as the emulator's batch columns, so decodeOutcome() is shared
  completed: number;
  status: StatusCode[];                            // "ok" | "fault" | "cpu" | "term" | "eng" …
  rax: Hex[]; xmm0lo: Hex[];                       // hex strings, never JS numbers (JSON loses NaN and -0)
  out: Record<string, HexBytes[]>;                 // out-buffer bytes after each call
  mxcsrOut: Hex[]; fpcwOut: Hex[];
  faults: Array<{ index: number; type: string; address: Hex | null; memory: { operation: string; address: Hex } | null;
                  module: string | null; rva: Hex | null }>;
  lostTarget: boolean;
}
export interface OracleCallPort {
  callPlanBatch(session: LiveSessionHandle, req: {
    target: { va: Hex; module: string; rva: Hex };
    plan: PlanWire;                                // §4.4 shape, resolved in the live address space (planToAgent)
    vectors: VectorsWire;
    fp: { mxcsr: number; fpcw: number };
    thread: "agent" | { tid: number };
    chunk: number;
    deadlineAt: number;
  }, signal: AbortSignal): Promise<Result<{ raw: LiveBatchRaw; evidence_id: `ev_${string}`; effect_id: `fx_${string}` }, BeaError>>;
}
```

`call_function`'s own batch mode should be **the same RPC**. `call_function` then becomes `callPlanBatch` with
the call model inputs, so the semantics are identical by construction.

### 9.5 Exact-bit live call thunk (spec for the agent; mechanism verified [V lab:S5-E6])

**CallBlock layout** (little endian; the verified layout extended to 28 stack args; allocate 0x200 bytes):

| Offset | Field | Offset | Field |
|---|---|---|---|
| 0x00 | target u64 | 0x78 | rax_out u64 |
| 0x08 | gpr[4] (rcx, rdx, r8, r9) | 0x80 | xmm0_out 16 B |
| 0x28 | xmm[4], 16 B each (xmm0–3) | 0x90 | mxcsr_out u32 |
| 0x68 | nstack u64 | 0x94 | fpcw_out u16 |
| 0x70 | mxcsr_in u32 (status bits cleared) | 0x98 | saved_mxcsr u32 |
| 0x74 | fpcw_in u16 | 0x9C | saved_fpcw u16 |
| | | 0xA0 | stack_args[≤ 28] u64 |

**Thunk** (171 bytes, `rcx = &block`; verified by capstone disassembly and by execution; `bea-lab/design-S5-emu/thunk.mjs`):

```
53 55 4889e5 4889cb                     push rbx; push rbp; mov rbp,rsp; mov rbx,rcx
0fae9b98000000 d9bb9c000000             stmxcsr [rbx+0x98]; fnstcw [rbx+0x9c]      ; save the thread's FP env
0fae9370000000 d9ab74000000             ldmxcsr [rbx+0x70]; fldcw [rbx+0x74]       ; per-call FP env
488b4b68 4883ec08 4889c8 48c1e003 4883c00f 4883e0f0 4829c4 4883ec20 31d2
                                        rcx=nstack; align; reserve 16-aligned stack args + 0x20 shadow; edx=0
4839ca 7312 488b84d3a0000000 488944d420 48ffc2 ebe9
                                        copy nstack qwords [rbx+0xa0+8i] -> [rsp+0x20+8i]
f30f6f4328 f30f6f4b38 f30f6f5348 f30f6f5b58   movdqu xmm0..3, [rbx+0x28/0x38/0x48/0x58]
488b4b08 488b5310 4c8b4318 4c8b4b20     mov rcx/rdx/r8/r9, [rbx+0x08/0x10/0x18/0x20]
ff13                                    call [rbx]
48894378 f30f7f8380000000               mov [rbx+0x78],rax; movdqu [rbx+0x80],xmm0
0fae9b90000000 d9bb94000000             stmxcsr [rbx+0x90]; fnstcw [rbx+0x94]
0fae9398000000 d9ab9c000000             ldmxcsr [rbx+0x98]; fldcw [rbx+0x9c]       ; restore the thread's FP env
4889ec 5d 5b c3                         mov rsp,rbp; pop rbp; pop rbx; ret
```

- FP env read stub: `0fae19 d97904 c3`.
- FP env restore stub (used after a stolen fault): `0fae9198000000 d9a99c000000 c3`.

**Agent rules:**
1. **Keep allocations alive.** Allocate the code page with `Memory.alloc(Process.pageSize)`, `Memory.protect(…,
   'rwx')`, write the bytes, and keep the `NativePointer` in a module-level variable. QJS freed a page held only by
   a local and the next call faulted with an execute AV [V lab:S5-E6]. The same holds for the block and scratch
   allocations.
2. **Call through `new NativeFunction(code, 'void', ['pointer'])`** with the default `exceptions: 'steal'`. A
   fault becomes a JS `Error {type, address, memory}` and the target survives [V lab:S5-E6; ext-frida §3.7].
3. **Per vector:**
   - zero the block;
   - write the target and the slots per plan (GPR slot → `0x08 + 8i`; XMM slot → low 8 bytes at `0x28 + 16i`,
     upper 8 zero; stack slot k → `0xA0 + 8k`; `nstack`);
   - write `mxcsr_in & 0xFFC0` and `fpcw_in`;
   - materialize the buffers into agent scratch memory exactly as the bridge does (template, column patches, then
     `ptrFields`);
   - call;
   - read back `rax`, `xmm0`, `mxcsr_out`, `fpcw_out` and the out buffers **as hex strings** (`readU64().toString(16)`).
4. **After a stolen exception**, call the restore stub on the block (belt and braces: Frida's exceptor already
   restored MXCSR in the lab [V lab:S5-E6]), and record `{type, address, memory}`. Use
   `Process.findModuleByAddress` for `module` and `rva`.
5. **Variadic slots** load both the GPR and the XMM register (the plan lists both).
6. **Threads.** `thread: {tid}` runs each chunk via `Process.runOnThread(tid, fn)` (about 15 ms latency per chunk
   [ext-frida §3.7]). The FP env is still set per call by the thunk.
7. **Chunking.** At most `chunk` vectors per RPC, keeping the agent's single JS thread responsive [ext-frida §1.7].
8. **Effect.** One `function-called` Effect per batch: `{target, vectors_digest, count}`. Irreversible; side
   effects unknown; taints the instance [rea-evidence §10.5].
9. **Residual non-determinism.** The callee sees the agent thread's values in the callee-saved registers
   (rsi, rdi, r12–r15) and garbage in rax, r10 and r11. Correct functions do not read them. The emulator zeroes
   them (§3.9), so a function that reads an uninitialized register can show up as a genuine `differ`.

### 9.6 Verified parity (lab S5-E6, fixture `ext-frida/fixture_gcc.exe`, live base `0x7ff7a8a10000` vs emulator `0x140000000`)

| Function | Inputs | Live bits | Emulator bits | Equal |
|---|---|---|---|---|
| four_floats | 1, 2, 3, 4 | `0x449a4000` | `0x449a4000` | ✓ |
| four_floats | qNaN `0x7fc12345`, 2, 3, 4 | `0x7fc12345` | `0x7fc12345` | ✓ (payload propagated) |
| four_floats | sNaN `0x7fa00001`, 2, 3, 4 | `0x7fe00001` | `0x7fe00001` | ✓ (quieted identically) |
| four_floats | −0 × 4 | `0x80000000` | `0x80000000` | ✓ |
| four_floats | denormals, MXCSR `0x1F80` | `0x3480020` | `0x3480020` | ✓ |
| four_floats | denormals, MXCSR `0x9FC0` (FTZ+DAZ) | `0x0` | `0x0` | ✓ |
| four_floats | RN `0x1F80` vs RZ `0x7F80` | `0x447d4002` / `0x447d4001` | same per mode | ✓ |
| mix_args | 7, 1.5f, 2.25, 3.125f, 11 (stack), 0.5 (stack) | `0x4039600000000000` | same | ✓ |
| physics_step | struct (speed 10, counter 3, pos 1, 0, 4), 0.016 | `0x412282e8` + struct | same, struct bytes equal | ✓ (emulator deviation `x87_transcendental_inexact`: in-image x87 `sin`) |
| physics_step | struct (speed 60, …), 0.5 | `0x426c0000` + struct | same | ✓ |
| car_energy | struct, 1200.0 | `0x40f6e39000000000` | same | ✓ |
| physics_step | NULL, 0.1 | stolen `access-violation`, read 0x0 | `fault read_unmapped` (null page) | outcome class equal |

MXCSR after the call (live vs emulator): `0x1f81` vs `0x1f80` (sNaN), `0x1fa2` vs `0x1f80` (denormals), `0x1fa0`
vs `0x1f80` (inexact). These are status flags only (S5-D9).

### 9.7 Comparison algorithm (`src/application/diff/compare.ts`, pure)

```
Inputs: legs L (2..3) with CallOutcomeColumns over the same vector indices; compared columns C
        (default: "ret" if returns != void, plus every out-buffer field); options.
Pairs:  every unordered pair of L, in the order (live, emulation), (live, expected), (emulation, expected).
For each pair (a, b) and vector i:
  oa, ob ← outcome classes (§9.3.2)
  if oa ∈ {harness_stop, not_run} or ob ∈ {harness_stop, not_run}:
       r(i) = inconclusive(reason = the first harness cause, or "not_run:<why>")
  elif oa = target_stop and ob = target_stop:
       r(i) = equal, unless compare_fault_sites and both sites are known and
              (status family differs or site.rva differs or access kind differs) → differ("fault_site")
  elif oa ≠ ob:  r(i) = differ("outcome_class")             # returned vs target_stop
  else:          # both returned
       cols = [c ∈ C where both cells are present]
       if cols = ∅: r(i) = inconclusive("no_comparable_columns")
       else r(i) = differ("value") if ∃ c: !bitsEqual(type(c), a[c][i], b[c][i], options.nan) else equal
Pair verdict:
  differ_count > 0                                               → "differ"
  inconclusive_count > 0 and options.inconclusive = "count"      → "unknown"
  compared_count = 0                                             → "unknown"
  otherwise                                                      → "equivalent-on-tested-inputs"
Overall verdict: any pair "differ" → "differ"; else any pair "unknown" → "unknown"; else "equivalent-on-tested-inputs".
```

- `bitsEqual(f32 | f64)` compares raw bits. Under `nan: "any_nan"`, two NaNs are equal whatever their payload.
- Integer, `ptr` and `bool` columns compare after width masking. Array cells compare element-wise.
- `inconclusive: "exclude"` keeps a verdict over the compared vectors. It sets the coverage to `partial` and adds
  the limitation "N vectors excluded as inconclusive (harness stops)".
- Equivalence is **never** claimed in general: the word "on-tested-inputs" is part of the verdict
  [rea-evidence §10.9].

**ULP and statistics** (`src/domain/floatBits.ts`):

```ts
export const ordF32 = (b: number): number => (b & 0x80000000) ? -(b & 0x7fffffff) : b;               // ±0 → 0
export const ordF64 = (b: bigint): bigint => (b >> 63n) ? -(b & 0x7fffffffffffffffn) : b;
export function ulpF32(a: number, b: number): number | null { if (isNaN32(a) || isNaN32(b)) return null; return Math.abs(ordF32(a) - ordF32(b)); }
export function ulpF64(a: bigint, b: bigint): bigint | null { if (isNaN64(a) || isNaN64(b)) return null; const d = ordF64(a) - ordF64(b); return d < 0n ? -d : d; }
```

| Statistic | Definition |
|---|---|
| `exact_equal`, `differ` | counts of vectors whose cell bits are equal or not |
| `max_ulp`, `p50_ulp`, `p99_ulp` | over cells where neither side is NaN (exact; nearest-rank percentiles; BigInt→number with saturation) |
| `max_abs` | max \|a − b\| as doubles |
| `max_rel` | max \|a − b\| / max(\|a\|, \|b\|) (0 when both are 0) |
| `nan_payload` | both NaN, bits differ |
| `nan_vs_number` | exactly one NaN |
| `signed_zero` | ±0 mismatch (bits differ, ulp 0) |
| `inf_mismatch` | an ±inf vs a finite or opposite infinity |
| `int_max_delta` | integer columns: max \|a − b\| as a decimal string |
| `tolerance` | when given: `{within, outside}`, where within means `ulp ≤ t.ulp \|\| abs ≤ t.abs \|\| rel ≤ t.rel`. **It never changes the verdict** |

`worst[]` holds at most 10 entries: outcome-class differences first, then the largest ulp, then integer deltas.
Each entry has the input bits and the per-leg value bits.

### 9.8 Hints (closed list; each carries the probes recorded into the unknown)

| Code | Rule | Suggested probe |
|---|---|---|
| `x87_inexact` | there are differences and the emulation leg's deviations include `x87_transcendental_inexact` | trust the live leg; or override the function's math import or path |
| `hle_math_model` | there are differences and the emulation imports used a `builtin-inexact` model | `emu_open` with a dump-backed session (LLE of the real CRT), or override the import |
| `cpuid_dispatch` | there are differences and `cpuid_executed` | compare paths: `emu_call` with `trace.coverage` vs live per-call coverage (`call_function` with coverage); patch the dispatch flag via `emu_open.patches` to force the same path |
| `fp_status_read` | `fp_status_flags_unmodeled` | the code reads MXCSR/x87 status flags, which the emulator does not set; trust the live leg |
| `file_image_state` | the emulation is image-backed and a live leg is present | use a dump-backed session (`dump_memory` → `emu_open {dump_path}`) |
| `possible_state_carryover` | live leg, emulation `snapshot` isolation, differences | re-run with `emulation.isolation: "chain"` and `state_from: "current"` |
| `last_ulp_only` | every float difference is ≤ 2 ulp | typical of FMA vs mul+add or a libm variant |
| `nan_payload_only` / `signed_zero_only` | every difference is of that kind | consider `compare.nan: "any_nan"` if the payload is irrelevant |
| `outcome_class` | ≥ 1 outcome-class difference | inspect `worst[]`; `emu_call` single with `detail: "complete"` on that vector |
| `raw_pointer_inputs`, `image_mismatch`, `engine_unvalidated` | as defined in §9.3.1 and §6.1 | none |

### 9.9 Unknown recording (auto, when `verdict ≠ equivalent-on-tested-inputs` and `record_unknown`)

- **question:**
  - `differ`: "Why does `<module>+<rva>` differ between `<a>` and `<b>` on `<k>` of `<n>` tested inputs?"
  - `unknown`: "Is `<module>+<rva>` equivalent between `<a>` and `<b>`? `<m>` of `<n>` vectors were inconclusive
    (`<top reasons>`)."
- **domain:** `emulation-fidelity` when an emulation leg is involved; otherwise `function-semantics`.
- **scope:** `image_sha256`, so the question survives process restarts [rea-evidence §10.8].
- **severity:**
  - `high`: `differ` with outcome-class differences, any integer difference, or `max_ulp > 4`;
  - `medium`: other `differ` results, and every `unknown`.
- **supporting:** `[bea.diff evidence id]`. **recommended_probes:** the hints' probes, deduplicated, at most 5.
- **Deduplication:** key `(image_sha256, rva, sorted leg pair set, verdict)`. An open unknown with that key gets a
  CAS update with `expected_revision`, appending the new supporting Evidence and the counts.
- The result carries `unknown_id`.

### 9.10 Result

```ts
type Leg = "live" | "emulation" | "expected";
type Verdict = "equivalent-on-tested-inputs" | "differ" | "unknown";
{
  verdict: Verdict; verdict_basis: "bit-exact";
  target: Partial<Record<"live" | "emulation", AddressInfo>>;
  legs: Array<{ leg: Leg; completed: number; by_status: Partial<Record<CallStatus, number>>; evidence_id: string | null;
                effect_id?: string; lost_target?: boolean; fp: { mxcsr: Hex; fpcw: Hex } | null }>;
  vectors: { count: number; offset: number; digest: string; source: "inline" | "generated" | "recording" | "dump_call";
             continuation: { vector_offset: number } | null };
  pairs: Array<{ a: Leg; b: Leg; verdict: Verdict; compared: number; equal: number; differ: number; inconclusive: number;
                 inconclusive_reasons: Record<string, number>; outcome_mismatches: number;
                 columns: Record<string, ColumnStats>; tolerance?: { within: number; outside: number } }>;
  worst: Array<{ index: number; column: string; reason: "outcome_class" | "fault_site" | "value";
                 inputs: Record<string, Hex | Hex[]>; values: Partial<Record<Leg, { status: CallStatus; bits: Hex | null }>>; ulp: number | null }>;
  hints: Array<{ code: string; message: string }>;
  unknown_id: string | null;
  rows: Array<Record<string, unknown>> | null;        // ≤ inline_limit
  stream_id: string | null;
}
interface ColumnStats { type: string; compared: number; exact_equal: number; differ: number; max_ulp: number | null; p50_ulp: number | null;
  p99_ulp: number | null; max_abs: number | null; max_rel: number | null; nan_payload: number; nan_vs_number: number;
  signed_zero: number; inf_mismatch: number; int_max_delta?: string }
```

**Throughput budget** [B]:
- emulation leg: about 17k vectors/s with snapshot isolation, so 10k vectors take about 0.6 s [V ext-backends §2.6];
- live leg: about 10–30 µs per vector plus about 0.35 ms per chunk RPC, so 10k vectors take about 0.2–0.4 s.

Both fit the 110 s ceiling with a wide margin.

---

## 10. Dump-backed emulation sessions (S5-D11)

**Why.** The user's harnesses read `.data` tunables and objects from the **file** image, while the game uses
**runtime** values [ext-backends §3]. Emulating against captured runtime state removes that whole class of
divergence. The mechanism is verified end to end [V lab:S5-E7].

### 10.1 Bundle format `bea.dump/1` (directory)

```
<bundle>/manifest.json            JCS-canonical (RFC 8785) UTF-8
<bundle>/regions/<sha256>.bin     exact bytes of a captured region (content-addressed; identical regions deduplicate)
```

```ts
// src/emu/dumpBundle.ts (zod mirrors this; strict)
export interface DumpManifestV1 {
  schema: "bea.dump/1";
  bundle_id: `dump_${string}`;                         // "dump_" + sha256(JCS(manifest without bundle_id))
  created_at: string;                                  // ISO-8601 UTC (part of the identity: a capture is a moment)
  producer: { tool: "bea"; version: string; operation: "dump_memory"; evidence_id: `ev_${string}` | null; instance_id: `pi_${string}` | null };
  process: { pid: number; image_path: string; image_sha256: string | null; arch: "x64"; os: { platform: "windows"; version: string } };
  capture: {
    mode: "running" | "suspended" | "at_hook";
    time_anchor: { seq: number; effect_epoch: number; module_map_epoch: number } | null;
    duration_ms: number;
    trigger?: {                                        // mode "at_hook" only
      kind: "hook"; target: { va: Hex; module: string; rva: Hex }; thread_id: number;
      call: { gpr: { rcx: Hex; rdx: Hex; r8: Hex; r9: Hex }; xmm: [Hex, Hex, Hex, Hex] /* 128-bit */; rsp: Hex;
              stack: Hex[] /* qwords at [rsp+0x28+8k], ≤ 28 */ };
      ret?: { rax: Hex; xmm0: Hex };                   // filled by onLeave when requested
    };
  };
  modules: Array<{ name: string; path: string; base: Hex; size: number; file_sha256: string | null; preferred_base: Hex | null;
                   timestamp: number | null; captured: "full" | "partial" | "none" }>;
  regions: Array<{ base: Hex; size: number; protection: string; tag: "module" | "heap" | "stack" | "teb" | "peb" | "tls" | "kuser_shared_data" | "range";
                   module: string | null; sha256: string; complete: boolean; unreadable_pages: Hex[] }>;
  memory_map: Array<{ base: Hex; size: number; protection: string; module: string | null }>;   // readable ranges only
  threads: Array<{ tid: number; primary: boolean; teb: Hex;
                   context: Record<"rip"|"rsp"|"rbp"|"rax"|"rbx"|"rcx"|"rdx"|"rsi"|"rdi"|"r8"|"r9"|"r10"|"r11"|"r12"|"r13"|"r14"|"r15", Hex> & { xmm?: Hex[] };
                   stack: { base: Hex; limit: Hex } | null;
                   tls: { slots_array: Hex | null; static_blocks: Array<{ module: string; index: number; address: Hex; size: number }> } }>;
  peb: Hex | null;
  imports: Array<{ importer: string; slot: Hex; name: string | null; ordinal: number | null; dll: string; target: Hex }>;
  limitations: string[];
}
```

**Constraints** (checked by `verifyDumpBundle`, and again by the bridge):
- regions are 4 KiB-aligned, `size % 4096 === 0`, and do not overlap;
- each file's length equals `size`, and the region's sha256 equals the file name;
- `memory_map` contains no `---` ranges;
- the TEB of the chosen thread lies inside a captured region;
- total region bytes ≤ `emu.dump_max_mb` (default 2048) and < the memory limit minus 256 MiB of headroom;
- `unreadable_pages` are zero-filled in the file but **not mapped**. The bridge maps the region in runs of
  readable pages, skipping the listed ones, before the baseline, so the layout stays frozen. A fault there is
  classified `not-captured-mapped-live` with the note "unreadable at capture".

### 10.2 Producer requirements on `dump_memory` (S5's needs; capture recipe verified [V lab:S5-E7])

| # | Requirement | How (verified where marked) |
|---|---|---|
| R1 | Module images of the requested modules (default: the process image) | `module.enumerateRanges('---')` + `readByteArray` per range [V lab:S5-E7]; a whole image reads in milliseconds [V ext-frida §3.14]. `file_sha256` = sha256 of the file on disk; `preferred_base` read from disk [ext-frida §3.14] |
| R2 | The TEB range of each captured thread | `OpenThread(THREAD_QUERY_LIMITED_INFORMATION = 0x0800)` + `NtQueryInformationThread(h, ThreadBasicInformation = 0, buf, 48)` → `TebBaseAddress` at +8; then `Process.findRangeByAddress(teb)` [V lab:S5-E7] |
| R3 | KUSER_SHARED_DATA | the page at `0x7FFE0000` [V lab:S5-E7] |
| R4 | `memory_map` | `Process.enumerateRanges('r--')`, or a `---` filter, because `---` includes free address space [V lab:S5-E7], attributed with `findModuleByAddress` [ext-frida §3.2] |
| R5 | Thread context and stack bounds | `Process.enumerateThreads()` GPRs [V lab:S5-E7]; StackBase/StackLimit at TEB+0x08 and +0x10 |
| R6 | Static TLS (recommended; MSVC `thread_local`) | TEB+0x58 → slots array; for each module with a TLS directory: `index = [AddressOfIndex]`, `block = slots[index]`, `size = End − Start + SizeOfZeroFill`; capture both as `tls` regions [B: standard x64 TLS layout; the emulated `gs:[0x58]` path is verified, ext-backends §2.3] |
| R7 | Resolved IAT entries | `module.enumerateImports()` → `{name, module, address, slot}` [V ext-frida §3.1] |
| R8 | Optional heap | `Process.enumerateMallocRanges()` [V ext-frida §3.2], explicit ranges, or (P2) pointer-reachable closure from a root address to depth N |
| R9 | Consistency mode | `running`: torn state is possible, so add the limitation. `suspended`: suspend non-agent threads with `SuspendThread` through a `NativeFunction` with `{scheduling:'exclusive'}` [ext-frida §3.7; B]. `at_hook`: capture synchronously in `onEnter` on the target thread and record the call registers [B]. This is the best mode for diffing that exact call (§10.6) |
| R10 | Atomic publish | write to `<dir>.staging-*`, then rename; content-addressed region files |
| R11 | Evidence | `bea.dump.capture` (observed, live-process) with the region blobs. `producer.evidence_id` links back |

### 10.3 Consumer algorithm (`DumpSource` in the bridge, after TypeScript's `verifyDumpBundle`)

1. **Regions.**
   - Read each file and verify its sha256 (`dump_invalid` on a mismatch).
   - `mem_map(base, size, UC_PROT_ALL)` and write the bytes.
   - After everything is loaded, `mem_protect` per the protection string (`r`/`w`/`x`).
   - Unicorn commits memory up front [V lab:S5-E5], so the total is checked against the limit first →
     `resource_exhausted`.
2. **Modules.**
   - `MappedImage` over each captured module at its runtime `base`: `.pdata`, exports, imports, TLS (§3.5).
   - `preferred_base` comes from the manifest. Identity is `file_sha256`; null means a diff needs
     `allow_image_mismatch`.
   - The primary module is `primary_module`, else the module whose path equals `process.image_path`.
3. **Synthetic window.** `choose_window(regions ∪ memory_map)` [V lab:S5-E7].
4. **Thread.**
   - `thread_id`, else `primary`.
   - `GS_BASE = teb`.
   - **Rewrite the emulator copy of TEB StackBase (+0x08) and StackLimit (+0x10)** to the synthetic stack, so MSVC
     `__chkstk` probes stay mapped [V lab:S5-E7; ext-backends §2.5]. Deviation `teb_stack_bounds_rewritten`.
   - TEB+0x58 (TLS) is kept, so captured TLS works.
5. **KUSER_SHARED_DATA.** Captured → used as is. Otherwise a synthetic page plus the deviation
   `synthetic_kuser_shared_data`.
6. **Imports.** Bind per `dumpPolicy` (§3.6.4) using `manifest.imports`, with `MappedImage` imports as a fallback.
   Rebinding writes only the emulator copy.
7. **ISA scan.** Per captured executable module (cache key over the captured bytes) and per captured executable
   region outside modules (gap class) (§3.7).
8. **Synthetic regions.** Stubs, sentinel, heap, scratch and stack (§3.3).
9. **Finish.** `patches`, then TB flush, then the baseline (§4.4 ordering).

**Address space = runtime addresses.**
- `module+0xRVA` resolves to the runtime base plus the RVA. `static_va` resolves to the runtime base plus
  `(static_va − static_base)`.
- Raw pointers taken from live observations, for example a `g_car` address from `read_memory`, are valid as they
  are.

### 10.4 Uncaptured memory

- An access outside captured and synthetic regions is a `fault` (§3.13) with `addressRegion.capture`:
  - `not-captured-mapped-live` → attribution **harness**, `remediation: "re-run dump_memory including <module or
    range>"` [V lab:S5-E7];
  - `unmapped-live` → attribution **target** (a genuine wild or NULL pointer) [V lab:S5-E7].
- In a diff, `not-captured-mapped-live` is **inconclusive**, never `differ`.

### 10.5 Lazy live fetch (deferred to v0.2; forward-compatible design)

**Why it is deferred:**
- Unicorn COW snapshots need a frozen layout [V ext-backends §2.4 #7; lab:S5-E8].
- Unicorn commits mapped memory up front [V lab:S5-E5], so pre-mapping a game's whole memory map is unaffordable.
- Fetched pages come from **later** live state than the capture (temporal inconsistency).

**Design (not in protocol 0.1):**
- A session option `faultPolicy: "request_host"`, allowed only with `snapshots: "manual"`.
- A fault on a `not-captured-mapped-live` page stops the vector with `cause: "needs_memory"` and `pages[]`.
- The host fetches those pages through `read_memory` on a live session with the **same `instance_id`**, and records
  the limitation "page fetched at seq N after the capture at seq M".
- The host sends `mem.supply {session, pages: [{base, hex}]}` (maps them in manual mode) and **re-runs the vector
  from its start** (deterministic), up to `maxFetches` (64) rounds per vector.

### 10.6 Capture-at-hook replay (P2; the strongest workflow for the user's physics functions)

1. `hook_function` on the physics function, with dump_memory `at_hook` capture on the first hit (modules + TEB +
   the heap closure of the arguments) and the `onLeave` return recorded.
2. `emu_open {dump_path}`.
3. `diff_function {emu_session_id, from_dump_call: true, signature, legs: ["emulation", "expected"]}`:
   - **one vector**, built from `capture.trigger.call` by position: GPR or XMM low 64 bits, or the stack qwords;
   - pointer arguments are raw pointers, valid in the dump's address space;
   - the expected `ret` is `trigger.ret` (`rax`, or `xmm0` low bits per the return type).
4. Result: whether the emulator reproduces **the real call on the real state**. Then `emu_call` with
   `state.from: "baseline"` explores other inputs on the same state, bit-exact against the expectation wherever
   the deviations allow.

---

## 11. Evidence mapping

### 11.1 Predicates

| Predicate | Producer | Subject | Confidence | Authority | Coverage rule | Blobs / streams | Links |
|---|---|---|---|---|---|---|---|
| `bea.emu.session` | `emu_open` | `emulation{image_sha256: primary, function_rva: null, initial_state_digest: baseline}` | derived | emulation | complete | none | the `bea.dump.capture` Evidence (dump) |
| `bea.emu.run` | `emu_call` single | `emulation{image_sha256, function_rva, initial_state_digest: from (+writes)}` | derived | emulation | §11.5 | coverage, full trace, vectors | session |
| `bea.emu.batch` | `emu_call` batch | same | derived | emulation | §11.5 | row stream (`emu-batch`) manifest, coverage, vectors | session |
| `bea.emu.sweep` | `emu_call` sweep | `emulation{…, function_rva: null}` | derived | emulation | partial on deadline | row stream (`emu-sweep`) | session |
| `bea.emu.memory.read` / `bea.emu.disassembly` | `read_memory` / `disassemble` on emulation | `emulation{…, initial_state_digest: current}` | derived | emulation | complete | > 64 KiB → blob | session |
| `bea.diff` | `diff_function` | `artifact{sha256: image, format: "pe", architecture: "x86_64"}` + `locations: [{kind:"module-offset", module, module_sha256, rva}]` | derived | `emulation` if an emulation leg exists, else `live-process` | complete iff no pair has inconclusive vectors | row stream (`diff`), vectors | the leg Evidence; the unknown id |

- Emulation Evidence has `observed_at: null` (timeless) and `perturbation: {active_effect_ids: [], instrumentation:
  "none"}`, plus `provider: {id: "unicorn", name: "Unicorn via bea-emu bridge", version: "2.1.4"}` and `agent:
  null` [rea-evidence §10.4].
- Identity-relevant `parameters`:
  - the plan digest (sha256 of JCS(CallPlan with target as module+rva));
  - the vectors digest and slice;
  - run options (budget, fp, isolation, trace flags, fault policy);
  - `query_id` (§11.2).
  - Delivery arguments are excluded: `inline_limit`, `detail`, `timeout_ms`, `label`.
- **Confidence is `derived` for every emulation result** [ext-backends §9.7; BRIEF §3.3]. A deterministic rerun
  from the same state with the same inputs produces the same Evidence ID ("duplicate"). That is intended.
- Non-deterministic runs (`deterministic: false`) add `parameters.run_nonce` (a UUID) so they never merge.

### 11.2 State lineage and replay identity

```
es_<hex> = sha256(JCS(record))
baseline: {schema:"bea.emu-state/1", kind:"baseline",
           source: {kind:"image", sha256, mapped_base} | {kind:"dump", bundle_id},
           open: <normalized emu_open input minus image_path/dump_path/label/timeout_ms>,
           bridge: {protocol, sha256}, engines: {unicorn, capstone, pefile}}
after:    {schema:"bea.emu-state/1", kind:"after", prev: <es_ of the start state>,
           op: {method, plan_digest, vectors_digest, slice:{offset,count}, writes_digest, options_digest, isolation},
           run_nonce?: <uuid when non-deterministic>}
```

- **Updates.**
  - `current := after(op)` for every call or batch: chain mode, `from: current`, or any `save_as`.
  - Under snapshot isolation, `after` is the state after the **last** vector.
  - `state.writes` without a call never happens; writes always accompany a call.
- **Named snapshots** store their digest. `from: <name>` takes the subject's `initial_state_digest` from that
  digest plus a `writes` record.
- **A bridge restart** resets `current := baseline` (§5.4).
- **`query_id`** = `sha256(JCS({initial_state_digest, target: {image_sha256, rva}, plan_digest, vectors_digest,
  options_digest}))` [rea-evidence §10.7].
  - v0.1 records it.
  - v0.2 replay cache: a deterministic earlier result with the same `query_id` is returned from the ledger without
    running.

### 11.3 Row streams (inline cap exceeded)

Rows are canonical JSONL in the evidence store's stream chunks [rea-evidence §10.6]. The stream manifest Evidence
links to the producing Evidence.

| Kind | Row | Typical size |
|---|---|---|
| `emu-batch` | `{i, s: StatusCode, a?: "t"\|"h", c?: cause, r?: bits, f?: {"buf.field": bits \| bits[]}, n?: instructions}` | about 60–150 B |
| `emu-sweep` | `{rva, s: StatusCode[], r: bits[], m: string[]}` | about 200 B |
| `diff` | `{i, in: {col: bits}, l: {leg: {s, r?, f?}}, p: {"a~b": {r: "eq"\|"df"\|"ic", u?: ulp, why?}}}` | about 150–300 B |

- `query_events {stream_id, filter: {s?, a?, p?, column?: {name, op: "eq"|"lt"|"gt"|"between", bits|value}}, group_by:
  "s"|"c"|"pc"|"p", offset, limit}`. The query tool implements this over the stream's schema descriptor. S5 supplies
  the descriptor `{kind, columns: [{name, type}], pairs?: […]}`.
- 100k rows at about 150 B is about 15 MB, inside the 256 MiB per-stream quota (orchestrator quotas).

### 11.4 `bea.coverage/1` (blob, `application/json`; consumed by `export_coverage` → drcov)

```ts
export interface CoverageBlobV1 {
  schema: "bea.coverage/1";
  source: { kind: "emulation"; engine: "unicorn"; granularity: "translation-block"; session_id: string; evidence_id: string | null; vectors: number }
        | { kind: "stalker"; granularity: "stalker-block"; session_id: string; evidence_id: string | null; thread_ids: number[] };
  address_space: "emulation-image" | "emulation-dump" | "live";
  modules: Array<{ id: number; name: string; path: string | null; base: Hex; size: number; file_sha256: string | null;
                   preferred_base: Hex | null; entry_rva: Hex | null; timestamp: number | null }>;
  blocks: Array<[moduleId: number, rva: number, size: number, hits: number]>;   // sorted by (moduleId, rva); size ≤ 65535
  unattributed: Array<[va: Hex, size: number, hits: number]>;                  // outside modules (stub and synthetic regions excluded)
  totals: { distinct_blocks: number; executions: number; truncated: boolean };
}
```

- **Builder** (`src/emu/coverage.ts`): for each TB `(va, size, hits)`, binary-search the module ranges. Inside a
  module: `rva = va − base`. Otherwise: `unattributed`, dropping BEA stub and synthetic regions.
- **drcov mapping** is the export tool's job, and the layout is [B] [ext-landscape §9]: a module table of `id`,
  `base`, `end`, `entry`, `checksum = 0`, `timestamp`, `path`, plus 8-byte `bb_entry {u32 start = rva, u16 size,
  u16 mod_id}`.
- Coverage is module-relative, so it does not depend on ASLR. Live Stalker coverage of the same module can be
  merged with or compared to emulation coverage by `(file_sha256, rva)`.
- Unicorn TBs, like Stalker blocks, are not CFG blocks; map them by range overlap [ext-frida §3.8].

### 11.5 Coverage status and limitations for emulation results

`coverage.status = "complete"` iff all of these hold:
- no vector stopped for a **harness** reason;
- the run was not cut by a deadline or a cancel;
- no **substituted or inexact model** was used: `builtin-inexact` or `override` imports, `return_zero`, `map_zero`
  pages, dynamic imports bound to models.

Otherwise the status is `partial`, with the reasons as limitations [rea-evidence §10.9]. Exact builtin models
(memory/string, heap, TLS, deterministic time) keep the status `complete`, with the limitation `imports_hle_bound`.

Standard limitation sentences, keyed by deviation (`src/emu/limitations.ts`; each is curated text):

| Deviation | Sentence |
|---|---|
| `entry_point_not_run`, `tls_callbacks_not_run` | "DllMain, CRT initialization and TLS callbacks were not executed; globals keep their file-image values (image session)." |
| `imports_hle_bound` | "Imports were bound to BEA's high-level models, not to real system DLL code." |
| `no_seh_dispatch` | "SEH and C++ exception dispatch are not modeled; a raised exception stops emulation." |
| `inexact_import_model` | "Imports {names} were modeled with host double-precision math and can differ in the last bits from the target's CRT." |
| `x87_transcendental_inexact` | "x87 transcendental instructions executed; Unicorn approximates them (up to 19,737 ulp observed for sin of large arguments)." [ext-backends §2.3] |
| `fp_status_flags_unmodeled` | "The code read FP status flags; the emulator does not set MXCSR exception flags." |
| `cpuid_executed` | "CPUID executed; the emulated CPU reports no AVX/FMA, so feature-dispatched code can take a different path than on the host CPU." |
| `teb_stack_bounds_rewritten` | "The TEB stack bounds were rewritten to the emulator's synthetic stack." |
| `isa_guard_off` | "The VEX/EVEX guard was off; VEX.128 instructions may have executed with silently wrong results." |
| `bridge_restarted_state_reset` | "The emulator was restarted; the session state was reset to its baseline, and snapshots {names} were lost." |

### 11.6 Untrusted content

- All three tools have `returnsTargetContent: true`, so results carry `_meta.provenance.untrusted_content`
  [rea-mcp §4.6].
- Target-derived content includes module, export and import names, disassembly text, memory bytes, and the
  numeric outputs.
- The server instructions already tell agents to treat such content as data [BRIEF §1.5].

---

## 12. Error mapping (bridge and host conditions → BEA wire codes [BRIEF §1.6])

| Condition | Code | Category | Retryable | Remediation or recovery |
|---|---|---|---|---|
| no usable Python | `capability_unavailable` | unavailable | no | "Run `bea setup --emulator` or set BEA_PYTHON …" (§6.1) |
| `BEA_PYTHON` invalid | `configuration_invalid` | invalid_input | no | fix the variable |
| bridge sha256, version or protocol mismatch | `capability_unavailable` | unavailable | no | "reinstall bea-agents" |
| spawn failure; startup timeout | `capability_unavailable` | unavailable | yes | "run `bea doctor --backend emulation --probe`" |
| `fatal engine_unavailable` | `capability_unavailable` | unavailable | no | "`bea setup --emulator --repair`" |
| bridge lost during the request; `engine_crashed`; `session_poisoned` | `capability_unavailable` | unavailable | **yes** | "retry; the session re-opens from its baseline" + `details.bridge_exit` |
| crash loop (§5.4) | `execution_failure` | execution_failure | no | "close_session and emu_open again" |
| identity changed on re-open, or the file changed during open | `evidence_integrity_mismatch` | integrity_mismatch | no | "the image or bundle changed on disk" |
| bridge `invalid_params` caused by input semantics (unknown buffer, bad column, even codec key) | `invalid_request` | invalid_input | no | `recovery: inspect_input_contract` + the field list |
| bridge `invalid_params`, `invalid_request`, `unknown_method`, `parse_error`, `frame_too_large` from a host bug | `execution_failure` | execution_failure | no | (bug; logged) |
| `unknown_snapshot` | `invalid_request` | invalid_input | no | "see session_status.named_snapshots" (lost ones are listed) |
| `unknown_symbol` | `invalid_request` | invalid_input | no | `details.exports_sample` (≤ 50) |
| `image_unreadable` | `file_operation_failed` | execution_failure | no | none |
| `unsupported_image` (x86, ARM64) | `unsupported_target` | unsupported | no | "32-bit (WoW64) targets are unsupported in v0.1" |
| `relocation_unavailable` | `invalid_request` | invalid_input | no | "omit image_base; the image has no .reloc" |
| `layout_conflict` | `unsupported_target` | unsupported | no | none |
| `dump_invalid` (hash or digest mismatch) | `evidence_integrity_mismatch` | integrity_mismatch | no | "re-capture with dump_memory" |
| `dump_incomplete` (no TEB, no primary module) | `invalid_request` | invalid_input | no | "re-capture including …" |
| `unmapped` (`read_memory` on emulation) | `memory_access_failed` | target_state | no | none |
| `resource_exhausted` | `resource_constraint` `{resource: "memory"}` | resource_constraint | yes | "close emulation sessions, reduce memory/heap_mb or the dump size, or raise emu.memory_limit_mb" |
| fifth emulation session | `resource_constraint` `{resource: "capacity"}` | resource_constraint | yes | "close an emulation session" |
| `unsupported_combination` | `invalid_request` | invalid_input | no | the refine text |
| deadline with no partial result (open) | `provider_timeout` | timeout | yes | `recovery: inspect_timeout_state` |
| MCP cancellation | `cancelled` | cancelled | yes | `details.partial_observation` |
| emulation tool on a live session (or the reverse) | `invalid_request` | invalid_input | no | "use call_function" / "use emu_call" |
| diff: live gate off | `capability_unavailable` | unavailable | no | the gate text (§9) |
| diff: image mismatch | `invalid_request` | invalid_input | no | "allow_image_mismatch: true to compare anyway" |
| diff live leg failed after some calls | the live error code | | | **`details.effects_applied: [fx_…]`** is always projected [rea-evidence §10.1] |

---

## 13. Configuration and limits

| Setting | Env | `config.json` | Default | Range |
|---|---|---|---|---|
| interpreter override | `BEA_PYTHON` | `emu.python` | none | absolute path |
| bridge memory cap (per bridge) | `BEA_EMU_MEMORY_LIMIT_MB` | `emu.memory_limit_mb` | 4096 | 256–65536 |
| emulation sessions | `BEA_EMU_MAX_SESSIONS` | `emu.max_sessions` | 4 | 1–16 |
| named-snapshot bytes per session | none | `emu.snapshot_bytes_limit_mb` | 512 | 16–8192 |
| dump bundle size | none | `emu.dump_max_mb` | 2048 | 16–32768 |
| ISA scan cache | `BEA_EMU_ISA_CACHE` (`0`/`1`) | `emu.isa_cache` | on | |
| self-test policy | `BEA_EMU_SELFTEST` (`auto`/`always`/`never`) | `emu.selftest` | auto | |
| bridge startup timeout | none | `emu.startup_timeout_ms` | 15000 | 2000–60000 |
| vectors per call | none | `emu.max_vectors` | 100000 | ≤ 1,000,000 |
| default `max_instructions` | none | `emu.default_max_instructions` | 1,000,000 | 0–10^10 |

- **Fixed caps**, each refused with an exact sentence ending "This release has no runtime override"
  [rea-mcp §6.2]:
  - frame 64 MiB; `mem.read` 16 MiB;
  - trace events 100k; patches 256; overrides 256;
  - named snapshots 16;
  - sweep targets 20k, sweep vectors 16;
  - a tool call ≤ 110 s.
- **Disk:**
  - `<BEA_HOME>/emu/venv/` (owned marker `bea-emu.json`);
  - `<BEA_HOME>/emu/cache/isa/*.json` (bounded at 512 MiB, LRU-pruned by mtime at bridge start);
  - `<BEA_HOME>/emu/.setup.lock`.
  - Per-run outputs (blobs and streams) go through the evidence store under `<BEA_HOME>/runs/<run_id>/`
    (orchestrator decision).

---

## 14. Testing plan (REA layering [BRIEF §1.16]; `retry: 0`; named skips)

### 14.1 Lanes

| Lane | Needs | Contents |
|---|---|---|
| `test:fast` | Node only | **framing** (split frames, CRLF, oversize, invalid JSON → protocol violation). **EmuBridge** against `tests/emu/fakeBridge.mjs`, a Node implementation of `bea-emu/0.1` with scripted results, delays, crash-on-command, "ignore cancel" (tests `cancelGraceMs`), wrong sha256 (version check) and fatal `ready`. **Restart policy** (loss mid-request → `bridge_lost` → re-open → generation + 1 → lost snapshots listed; three losses → `failed`). **callModel**: classification goldens (mixed int/float positions, stack args, hidden-return shift, byval 4/12 bytes, variadic), normalization (NaN/−0/±inf/`{bits}`/ranges/address forms), codec round trips including Newton inverses, generator goldens. **compare**: the full verdict truth table over outcome-class combinations × pairs; ulp edge cases (±0, NaN payloads, inf, denormal boundary, f64 BigInt); tolerance never changes the verdict; `inconclusive: exclude` vs `count`. **Contracts**: examples parse; schema bytes and depth within budget; derived annotations match §8.4 |
| `test:emu` | Python with unicorn 2.1.x (named skip "python with unicorn 2.1.x not found") | **Real bridge** on `bea_emu_fixture.dll` (built in `globalSetup` with gcc, byte-reproducible):<br>• every status: INT3 stop on `bea_avx_dot` (the **first** VEX instruction, never a silent mis-execution); x87 tag on `bea_trig`; `unhandled_import kernel32.dll!CreateEventA` from `bea_tls_counter` with the caller RVA; `budget_exhausted` on `bea_spin`; watchdog `timeout`; cancel latency < 50 ms; `cpu_exception #DE` on `bea_div(7, 0)`; `syscall` on the inline-syscall stub; `terminated` on `abort`<br>• FP environment (FTZ/DAZ bits); struct buffers + `ptr_to` + codecs; hidden struct return; `heap` placement + `save_as` + `from: <name>`<br>• **the snapshot ordering suite**: the E8b sequence plus 200 random interleavings of save, restore, batch and chain, asserting correct values and **no native crash**<br>• `map_zero` in manual mode; memory limit (`--mem-limit 128 MiB` with a 256 MiB heap → `resource_exhausted`); `--probe` and `--selftest` schemas; the ISA cache hit on a second open<br>**Resolver**: `BEA_PYTHON` precedence, broken venv fall-through, alias 9009 skip (a fake command) |
| `test:acceptance` / `verify:emulation` (serial; JSON receipt) | real Frida + gcc fixtures + Python | the **E6 parity set** as golden bits through the live thunk (`callPlanBatch`) vs the emulator. `diff_function` verdicts: **equivalent** on `four_floats`, `mix_args` and `car_energy`; **differ** on `bea_dispatch` (CPUID-dispatched: `x*3.0001f` with AVX vs `x*3.0f` without) with the hint `cpuid_dispatch` and an unknown recorded; **unknown** on `bea_avx_dot` (emulation `unsupported_instruction` → inconclusive). **Dump-backed** (the E7 flow): `dump_memory` → `emu_open {dump_path}` → `physics_step(&g_car)` equal to the live scratch call; uncaptured-fault classification. **Capture-at-hook replay** (when dump_memory supports `at_hook`) |
| leak assertions | all lanes that spawn bridges | after close, neither the launcher nor the interpreter pid is alive (owned-pid ledger [rea-testing §11.3]); both pids are recorded [V lab:S5-E2] |

### 14.2 Fixtures (`tests/fixtures/emu/`)

- `bea_emu_fixture.c`: the ext-backends fixture's 14 exports [ext-backends §2.1], plus:

| Export | Purpose |
|---|---|
| `bea_dispatch(float)` | a `cpuid` leaf 1/7 check; returns `x*3.0001f` when AVX2 is present, else `x*3.0f` |
| `bea_struct_ret(float)` | returns a 24-byte struct, so the hidden pointer is used |
| `bea_byval12(S12 s)` | takes a 12-byte struct by value, so it receives a pointer to a copy |
| `bea_variadic_sum(int n, ...)` | variadic doubles |
| `bea_mxcsr_read()` | `stmxcsr`, an `fp_status` site |
| `bea_rdtsc()` | a `tsc` site |
| `bea_syscall_stub()` | inline `mov eax, 0x50; syscall`. Never run natively |
| `bea_codec_get(const Obj*)` | decodes a `mul`-obfuscated field |
| `bea_vec_sum(const Vec*)` | a begin/end/capacity container |

- Build: `gcc -O2 -shared -fno-builtin-sqrtf -fno-builtin-memcpy -Wl,--no-insert-timestamp` (byte-reproducible
  [rea-testing §11.2]).
- `live_fixture.c` is the ext-frida fixture (`physics_step`, `mix_args`, `four_floats`, `car_energy`, `g_car`)
  plus the `bea_dispatch` and `bea_vec_sum` exports. It is an executable, so it can be spawned.
- MSVC and PDB fixtures are a named-skip lane (no Windows SDK on this host [rea-testing §0.7]).

---

## 15. Coverage of the user's existing harness needs

Generic techniques only; the harness was read read-only [ext-backends §3]. Line references are to
the user's emulation harness.

| Observed need or pain point | BEA feature | Where |
|---|---|---|
| per-function boilerplate (alloc, pack, call, unpack) | typed positional slots, buffers with typed fields, typed returns | §7, §8.2 |
| `call(rva, ints=[…None…], floats=[None, …], stack_args)` positional with holes (`:59-73`) | the same positional semantics, typed; stack floats without hand packing | §7.4 |
| only f32 handled; returns only `xmm0[31:0]` and `rax` (`:79-80`) | f32, f64, int widths, ptr, bool, struct (RAX or hidden pointer), out buffers | §7.4, §7.5 |
| **budget exhaustion silently returns stale `xmm0`** (`emu_start(count=…)` returns without raising, `:75-80`) | `budget_exhausted` is a status (harness), never a value | S5-D17, §3.10 |
| emulator re-creation after faults | COW baseline restore per vector (18.6 µs); poisoned-session auto-reopen | §3.11, §5.4 |
| imports unsupported (pure leaf functions only) | HLE models, diagnostics with the caller RVA, overrides, dynamic imports, dump LLE | §3.6 |
| `.data` tunables taken from the **file** image | dump-backed sessions at runtime addresses (verified bit-exact); `patches`; `state.writes` | §10, §8.1, §8.2 |
| FPCW/MXCSR never set (Unicorn resets them to 0) | per-call CPU and FP environment, recorded in provenance | §3.9 |
| ad hoc differential statistics (worst relative error) | `diff_function`: ulp, abs and rel statistics, worst list, an expected leg for clean-room references, seeded generators | §9, §7.6 |
| behavioural identification sweeps over `.pdata` | `emu_call` sweep with the known-function matcher and budgets | §3.15 |
| obfuscated struct fields (multiplicative codes with modular inverses) | field codecs `xor`/`add`/`mul` (odd keys, Newton inverse) | §7.2 |
| C++ container layouts (begin/end/capacity) | `ptr_to` fields with `plus` offsets into named buffers | §7.1 |
| a local `dis.py` shadows the stdlib | `python -I -X utf8`, a single-file bridge, a BEA-owned cwd | §3.1, §5.2 |
| no tracing or coverage | imports, blocks, coverage, memory and instruction traces; `bea.coverage/1` → drcov | §3.12, §11.4 |
| Ghidra and REA static addresses | `static_va` + `static_base` (default: the preferred base from disk) | §8.2 |
| a function ledger TSV (address → class → role) | every emulation Evidence carries `(image_sha256, function_rva, state digest)`; the skill documents ledger columns `module, rva, static_va, role, status, evidence ids` | §11.1 |
| scripting MCP over HTTP from Python | the emulation tools are ordinary MCP tools, usable over `bea mcp --http` (a separate work package) | none |

---

## 16. Work packages (implementation order)

| WP | Deliverable | Depends on | Acceptance | Estimate |
|---|---|---|---|---|
| E1 | Bridge core: the §3.1 process model and memory limit; `FrameReader`; Server, cancel and ping; `MappedImage`; `ImageSource`; Layout; HLE v2; `CallEngine` (plan execution, CPU env reset, budget/TB discipline, watchdog); diagnostics v2 with attribution; **snapshots v2**; `--probe`; `--selftest` | none | `test:emu` status suite and snapshot ordering suite green | 4 d |
| E2 | ISA guard v2 (INT3 overlay, gap and tag hooks, INSN hooks, cache) | E1 | the `bea_avx_dot` INT3 stop, x87 and fp_status tags, a cache hit on reopen, overlay-transparent `mem.read` | 1 d |
| E3 | Batch engine (fast, medium, full; columns; deadline; aggregates); sweep and matcher | E1 | throughput ≥ 15k/s for snapshot scalars; ≥ 8k/s medium [B]; matcher finds `sinf`/`sqrtf` in the fixture | 1.5 d |
| E4 | TS client: `framing`, `EmuBridge`, `EmuSessionRuntime`, restart policy, `bridgeLocator`, `PythonResolver` | E1 protocol | the `test:fast` client suite against `fakeBridge.mjs`; real-bridge smoke | 2 d |
| E5 | `callModel` (+ generators, codecs); the `emu_open`/`emu_call` contracts and `EmulationService`; evidence (§11); streams and coverage blobs; integration with the shared tools (§8.3) | E3, E4; evidence store | contract tests; `bea emulate` request runs; `export_coverage` consumes `bea.coverage/1` | 3 d |
| E6 | `bea setup --emulator`, doctor checks, `bea_status` emulator section, `requirements.lock`, the build manifest | E1, E4 | a fresh-HOME setup → probe exact → selftest pass; rollback test; stale-lock detection | 1.5 d |
| E7 | `diff_function`: `compare.ts`, `DiffService`, hints, unknown recording; the recording leg (P2) | E5; the live designer's `callPlanBatch` (thunk) | `verify:emulation` verdict suite (equivalent, differ, unknown) | 2 d |
| E8 | Dump-backed sessions: `dumpBundle.ts`, the bridge `DumpSource`, IAT policies, TEB rewrite, uncaptured classification; capture-at-hook replay (P2) | E1, E5; dump_memory | the E7 flow in `verify:emulation` | 2.5 d |
| E9 | Fixtures, goldens, the verify script, docs (`docs/emulation.md`, skill reference `oracles-and-emulation.md`) | all | lanes green on 3 reruns, 0 leaks | 1.5 d |

Total: about 19 developer-days. MVP order: **E1 → E4 → E5 → E6** (emulation usable), then **E2, E3**, then
**E7** (once the live thunk exists), then **E8**.

---

## 17. Assumptions, conflicts and open questions

### 17.1 Believed facts, each with a lab check

| # | Assumption | Check |
|---|---|---|
| A1 | QEMU's FPTAG write treats a 2-bit value of 3 as empty (0xFFFF = all empty) | selftest `x87_reset` |
| A2 | `UC_HOOK_INSN` supports RDTSC/RDTSCP in unicorn 2.1.4 | selftest `insn_hooks`; the fallback is defined (§3.7) |
| A3 | `uc.ctl_remove_cache(start, end)` is available in the 2.1.4 Python binding | `hasattr` at runtime; the fallback is `ctl_flush_tb` |
| A4 | `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION` on a nested self-job suppresses WER for native crashes | `test:emu` crash-injection item (a ctypes write to address 0 in a debug-only method) |
| A5 | Linux: `RLIMIT_DATA` bounds Unicorn's commits without breaking TCG; `PR_SET_PDEATHSIG` via ctypes works | Linux lane (best effort; reported as a limitation) |
| A6 | ISA scan rate of about 1 M instructions/s holds for 40 MB `.text` (10–20 s once) | measure on a large real image; progress events cover it |
| A7 | INT3 patching is invisible except to code that reads its own bytes (deviation recorded) | covered by the overlay tests; real-game impact unknown |
| A8 | Venv relocation by rename (staging → final) keeps the launcher working | `setup` test re-probes after the rename and rolls back on failure |
| A9 | WindowsApps aliases with no Python installed exit 9009 or similar | resolver test with a fake command; real-host behaviour unverified |
| A10 | The medium batch path reaches ≥ 8k vectors/s | E3 benchmark |
| A11 | Frida `suspended` and `at_hook` capture modes behave as designed (dump_memory owns this) | dump_memory lab |
| A12 | The MSVC-specific behaviours (`/GS`, CFG, `__isa_available` dispatch, delay loads, SEH) [ext-backends §2.5] | a named-skip MSVC lane; real-game trials |
| A13 | The drcov layout [ext-landscape §9] | export_coverage owner (L6) |
| A14 | The thunk behaves the same under the V8 runtime (verified in QJS only) | `verify:emulation` runs both runtimes once |
| A15 | Unicorn's license (the wheel says BSD; the core is believed GPLv2) | legal review [ext-backends §10 Q1]; BEA never vendors it |

### 17.2 Conflicts with the BRIEF or the notes (resolved here; flagged for the orchestrator)

1. **The bridge under jobhost** [BRIEF §3.2, §6.7]. Replaced by a self-applied job memory limit plus a
   non-detached spawn. jobhost hands its target a NUL stdin, and the bridge's protocol *is* stdin
   [rea-process §8.1, §13 Q1]. Lifetime containment is verified without it [V lab:S5-E2/E2b/E5].
2. **Named snapshots** [ext-backends §9.9]. The prototype's arbitrary named COW snapshots crash unicorn.dll in some
   orders [V lab:S5-E8]. They are replaced by host-copy snapshots (S5-D5).
3. **ISA guard hooks** [ext-backends §2.2, "≤ 4096 ISA-guard hooks"]. Replaced by INT3 patching, because hook
   cost scales with hook count [V lab:S5-E4].
4. **Confidence of emulation Evidence.** rea-evidence §10.9 says `observed`; ext-backends §9.7 and BRIEF §3.3
   say derivation. **`derived`** is used (with authority `emulation`).
5. **Protocol method names and argument model** [ext-backends §9.4, §9.5]. Renamed (`state.*`, `emu.batch`). Specs
   and templates are replaced by plan + raw-bit vectors, with classification in TypeScript, so the live and
   emulated legs share one ABI implementation.
6. **`write_memory` on emulation sessions** [BRIEF §6.0 implies the shared tools accept either kind]. Not
   required. Emulation uses `emu_open.patches` and `emu_call.state.writes`, so it stays independent of the live
   write gate.
7. **Long batches** [BRIEF §6.5 `wait` covers "batch done"]. v0.1 uses deadline plus continuation; there are no
   async emulation handles.
8. **`call_function` batch.** S5 requires it to be the same `callPlanBatch` RPC using the exact-bit thunk (§9.4,
   §9.5). If the live designer chose NativeFunction float marshalling instead: NaN payloads, sNaN and −0 cannot
   round-trip through JS numbers or JSON. The diff live leg would then have to mark such vectors `harness_stop`,
   which weakens D14.

### 17.3 Open questions (product or user)

1. Should the emulator memory cap default be 4 GiB, or derive from physical RAM? (Games can need large dumps.)
2. Should the capture-at-hook replay (§10.6) be promoted to v0.1? It is the closest fit to "find what the physics
   function really computes", and it depends on dump_memory `at_hook`.
3. Should the sweep matcher ship a richer known-function table (game-math idioms such as `rsqrt` approximations
   or fast `atan`) with tolerance profiles?
4. Should speakeasy 2.0 (v0.2) be used to run DllMain and CRT initialization before snapshotting into the bridge,
   as an alternative to dumps for offline images [ext-backends §4]?

---

## Appendix A. Lab artifacts (this design phase)

All under `<scratch>/bea-lab/design-S5-emu/`.
Every spawned process was owned and killed. No global installs were made: the venvs are local to the lab.

| File | Verifies | Result |
|---|---|---|
| `e2_launchers.mjs` | spawn routes (alias `python`, alias `py -3`, real interpreter, stdlib venv, uv venv): pids, kill and EOF propagation | S5-E2 |
| `e2b_parent_death.mjs` | a hard kill of the server stand-in kills the launcher and the interpreter | S5-E2b |
| `venv-std/`, `venv-uv/`, `venv-bea/` | venv layout (venvlauncher sha256 `199ce15a…`); the hash-locked install via uv and pip | S5-E3 |
| `requirements.lock` | the exact lock content of §6.5; installed with `--require-hashes --only-binary --no-deps` | S5-E3 |
| `pypi_*.json` | PyPI metadata snapshots (hashes, licenses) | §6.5 |
| `e4_isa_guard.py` | per-address hook translation cost; INT3 RIP semantics | S5-E4 |
| `e5_memlimit.py` | a self-applied process memory job; Unicorn `UC_ERR_NOMEM`; Python `MemoryError` | S5-E5 |
| `thunk.mjs`, `thunk_hex.txt` | the register-file thunk, assembled and disassembled | §9.5 |
| `e6_live_vs_emu.mjs` | live thunk vs prototype bridge, 13 vectors (12 returning bit-exact + 1 fault); MXCSR flags; FP env after a stolen fault; the QJS allocation-lifetime failure | S5-E6, §9.6 |
| `e7_capture.mjs`, `bundle/` | Frida capture into a `bea.dump`-style bundle (module ranges, TEB via `NtQueryInformationThread`, KUSD, memory map, context) + the live leg | S5-E7 |
| `e7_emulate.py` | dump-backed emulation at runtime addresses; bit-exact against live; uncaptured-fault classification; synthetic-window choice after filtering `---` | S5-E7 |
| `e8_snapshots.py`, `e8_runner.py` | Unicorn COW snapshot ordering (the stack behaviour; the native AV) | S5-E8 |
| `e8b_hybrid.py` | the hybrid snapshot discipline, all orderings correct, 18.6 µs per restore+run | S5-E8b |

