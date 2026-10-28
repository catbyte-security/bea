# BEA DESIGN.md: technical critique (critic-technical)

Reviewer key: `critic-technical`. Subject: `bea-design/DESIGN.md` (11,493 lines, "authoritative v0.1"), cross-checked against
the VERIFIED facts in `bea-research/{ext-frida,ext-backends,rea-process,rea-mcp,rea-testing,rea-runtime}.md`, the
normative annexes S1–S6 where DESIGN delegates to them, and the integration lab (`bea-lab/design-integrate/`).

Lab for this review (every script, fixture and raw output):
`<scratch>/bea-lab/design-critic-tech/`
(`LAB/` below). Host: Windows 11 26200, Node 24.18.0, Frida 17.23.2 (imported read-only from REA's node_modules by
file URL), QJS runtime, gcc 16.1 (WinLibs). The fixture is ext-frida's `fixture_gcc.exe` (used read-only). Every
process the lab started was killed or exited; `tasklist` shows no `fixture_gcc.exe` left. Nothing outside `LAB/` and
this file was written.

Labels: **VERIFIED** = run here (experiment id `E<n>`, raw output in `LAB/out_e<n>.json` or
`LAB/out_console_results.json`). **READ** = read in the SDK/Frida source shipped in the labs. **BELIEVED** = inference,
not executed; each carries a lab check.

---

## 0. Summary

| Severity | Count | Items |
|---|---|---|
| Blocking | 3 | B1 oracle calls pre-empt the callee's own SEH/C++ EH; B2 oracle calls pre-empt BEA's own watch traps; B3 a schema-valid >10 MiB request shuts the whole stdio server down (and kills owned targets) |
| Important | 11 | I1 late `runOnThread` execution; I2 per-call `AbortSignal.any` leak; I3 shutdown hard-exit timer and admission-drain exit code; I4 `watch_memory auto` → page_guard on attached targets; I5 BEA guard pages break scans/reads/captures; I6 dumps embed live hook patches; I7 target environment inherits the server environment (secrets); I8 file-write-anywhere + spawn-anything under prompt injection; I9 fixed FP env for "bit-exact" live oracles; I10 HTTP session capacity + Windows launch/kill pitfalls; I11 machine-wide anti-cheat heuristic |
| Minor | 12 | M1–M12 |

Experiments that **confirmed** design claims (§4): E1, E4 (closes open item A-36), E6, E10 (closes L-S6-4 with a
caveat), E11, E13, E14, E16.

Most of the blocking/important items share one root cause that DESIGN does not model: **Frida try-scopes win over
`Process.setExceptionHandler` and over the target's own SEH.** Every agent memory access inside a Frida try-scope
(`NativePointer.read*`, `Memory.scanSync/copy`, `findPointers`, `NativeFunction {exceptions:'steal'}` — including the
oracle thunk, the scan kernels and `Process.runOnThread` callbacks) consumes exceptions *before* BEA's single dispatcher
and *before* the callee's own handlers (E6, E7, E8, E9, E16b). DESIGN §5.3 assumes the dispatcher "sees every exception
first" (S4 A5/A-33); that holds only for exceptions raised outside try-scopes.

---

## 1. Blocking

### B1. `call_function` / `diff_function` live leg: `exceptions:'steal'` pre-empts the callee's own SEH and C++ exception handling

**DESIGN.** D-INT-8 (l.127), §5.3 "Calls" (l.10048–10055): the exact-bits thunk is called through
`NativeFunction(code,'void',['pointer'])` "(exceptions `steal`)"; S5 §9.5 rule 2 ("default `exceptions:'steal'`");
D14/§6.2 #26/#33 present the live call as the bit-exact reference oracle.

**Evidence (VERIFIED).**
- E8 (`LAB/e8_steal_vs_callee_seh.agent.js`, `out_e8.json`): `kernel32!IsBadReadPtr(0x10, 4)`, which handles its own AV
  with SEH and returns 1 natively: `{exceptions:'steal'}` → **throws `access-violation`**; `{exceptions:'propagate'}` →
  returns 1.
- E9 (`LAB/cxx_catch.cpp` → `cxx_catch.dll`, `e9_steal_vs_cxx.agent.js`, `out_e9.json`): an exported function that
  `throw 42` and `catch`es it internally (g++ x64, SEH-based unwinding): `steal` → **throws `system`**; `propagate` →
  returns 43 (correct).
- E6 (`out_e6.json`): the try-scope also wins over `Process.setExceptionHandler` (the handler saw 0 of 4 stolen faults).

**Impact.** Any function whose body (or any callee) uses `__try/__except`, `IsBadReadPtr`-style probing, C++
`throw/catch` (MSVC game code: very common), `RaiseException` for control flow, or guard-page probing is aborted at the
first internal exception and reported as a fault. The abort is a longjmp out of the native frames: destructors,
`__finally` blocks and lock releases do not run, so the target can be left with held locks / half-updated state
(irreversible, on attached targets too). `diff_function` then reports `differ`/`unknown` against an emulator that
"stops at RaiseException" anyway, so the oracle that D14 calls ground truth is wrong exactly where MSVC code is
non-trivial. The S5-E6 parity set (12/12 bit-exact) contains no function with internal EH, so the lab did not catch it.

**Fix (WP11 + WP3; protocol unchanged).** Make the thunk a real SEH frame and stop using steal:
1. Emit the thunk with an unwind-describable prologue (it already is: `push rbx; push rbp; mov rbp,rsp`) plus a
   recovery label `rec:` that stores `status=fault` in the CallBlock, restores MXCSR/FPCW from `+0x98/+0x9c`,
   `mov rsp,rbp; pop rbp; pop rbx; ret`.
2. Register `RUNTIME_FUNCTION{thunk, thunk_end, UNWIND_INFO}` with `ntdll!RtlAddFunctionTable` (UNWIND_INFO v1,
   `UNW_FLAG_EHANDLER`, codes `UWOP_PUSH_NONVOL rbx`, `UWOP_PUSH_NONVOL rbp`, `UWOP_SET_FPREG` if used), whose
   language handler `bea_call_eh` lives in the same allocation (CModule or hand-assembled, ≤ 4 GiB from the base).
   `bea_call_eh(ExceptionRecord, EstablisherFrame, ContextRecord, DispatcherContext)`: if unwinding → `ContinueSearch`;
   else copy code/address/`ExceptionInformation[0..1]`/rip/rsp into the CallBlock and
   `RtlUnwindEx(EstablisherFrame, rec, ExceptionRecord, 0, ContextRecord, DispatcherContext->HistoryTable)`.
   This is exactly MSVC `__except(EXCEPTION_EXECUTE_HANDLER)` semantics: inner handlers run first, unwinding runs
   `__finally`/destructors, and only exceptions nobody below handles end the vector.
3. Call it with `new NativeFunction(thunk,'void',['pointer'],{exceptions:'propagate'})`; keep it module-scoped (S5-E6
   QJS free hazard).
4. The agent dispatcher (WP3 `exceptions.ts`) must check "thread has an active oracle call" **before** the
   `Cloak.hasCurrentThread()` early return: record an `exception/1` row tagged `in_call`, never send a blocking crash
   report for it, return `false`.
5. Lab checks (add to WP11 acceptance): IsBadReadPtr(0x10)=1, `cxx_catcher(1)`=43 (sources in `LAB/`),
   `touch_counter(NULL)` recovered with `FaultInfo`, MXCSR restored afterwards, 1,000 faulting vectors without leak.
   Status of the mechanism: BELIEVED (standard Win64 SEH; not run here).
6. If the lab check fails, the fallback is not silent: keep `steal`, and classify any stolen `system`/AV whose fault
   site is inside a function with an `UNW_FLAG_EHANDLER`/`UHANDLER` unwind entry as `raised` with a limitation
   "callee exception handlers were not honoured" and make `diff_function` treat it as inconclusive (`unknown`).

### B2. Oracle calls (and every other agent access inside a try-scope) pre-empt BEA's own watch traps

**DESIGN.** §5.3 Watchpoints (l.10035–10041) and Calls (l.10048–10055); S4 A5 ("BEA sees every exception first").
§6.2 #23 l.10594: `watch_memory auto` prefers `page_guard` on attached targets; investigation 1 combines a watch on the
car struct with `call_function` on `physics_step`.

**Evidence (VERIFIED, E7, `LAB/e7_steal_vs_bea_traps.agent.js`, `out_e7.json`).** A JS exception handler that claims
`guard-page` and `single-step` (as BEA's dispatcher does) was registered:
- call on the agent thread into a function writing a `PAGE_GUARD` page → `THREW guard-page`; the function never ran
  past the access (`counter` stayed 7); the handler saw nothing; the guard was consumed.
- DR write watchpoint armed on the main thread, call executed there via `Process.runOnThread` → `THREW single-step`
  **after** the write (`counter` 7→8) and before the rest of `physics_step` ran (`pos[0]` still 0): a half-executed
  function, a lost watch row, and the DR still armed.

**Impact.** In the motivating workflow (watch the struct → call the function as an oracle → emulate → diff), calls
fault spuriously, partially mutate state, consume the watch's guard (the watch silently stops until the 250 ms
verifier re-arms it and mislabels it `kernel_access_suspected`), and lose hits. `diff_function` reports `differ` on
correct code.

**Fix.** The B1 design (propagate + thunk SEH frame) fixes this automatically: BEA traps reach the dispatcher, are
handled (`return true`), and the call continues. Until B1 lands, `callFunction` must (a) suspend every BEA guard page
(`pageGuard.suspendAll()` → restore `origProtect`, re-arm after the chunk) and (b) refuse `thread_id` calls on threads
with armed BEA DR slots, or clear/restore those slots around the chunk (exclusive Get/SetThreadContext from the JS
thread before `runOnThread`), and record `watch_suspended_during_call` in the watch summary and the call evidence.
Same rule for scans and dumps (I5).

### B3. A schema-valid request larger than 10 MiB closes the stdio transport and shuts the server down

**DESIGN.** §4 `src/main/mcpStdio.ts` (l.8621–8627) calls `serveStdio(factory, {onerror})` with the SDK default
transport; `onServedInstanceClosed` → `requestShutdown("connection-closed")`. Input schemas allow far more than
10 MiB: `vectorsSchema.columns` `z.array(...).max(1_000_000)` per column (l.6404), `bufferSchema.init_hex` up to
2 MiB × 64 buffers (l.6344/6386), `fields[].default` 64 KiB × 256 × 64, `diff_function.expected.columns` (l.10719).

**Evidence.**
- READ: SDK 2.3.1 `StdioServerTransport._ondata` (`server/dist/stdio.mjs`): `ReadBuffer.append` throws
  "ReadBuffer exceeded maximum size of 10485760 bytes" → `onerror` → `this.close()` → `onclose`.
- VERIFIED E12 (`LAB/e12_oversize.mjs` against the integration-lab build `design-integrate/ts`): after two normal
  calls, one 12.1 MB `tools/call` line produced `mcp transport error … ReadBuffer exceeded maximum size of 10485760
  bytes`, then `shutdown complete … reason: connection-closed`, and the server exited 1.5 s after start; later requests
  got EOF.

**Impact.** One `call_function`/`emu_call`/`diff_function` request with ~1M vector cells (the advertised maximum) or a
few large `init_hex` buffers terminates BEA, kills every BEA-owned target (the game the user spawned), and leaves the
client without a reply. It is reachable without any client bug.

**Fix (WP0, frozen file → apply before WP0).**
1. Pass an explicit transport:
   ```ts
   import { serveStdio, StdioServerTransport } from "@modelcontextprotocol/server/stdio";
   export const MAX_STDIO_REQUEST_BYTES = 64 * 1024 * 1024;
   handle = deps.serve(factory, { onerror, transport: new StdioServerTransport(process.stdin, process.stdout,
     { maxBufferSize: MAX_STDIO_REQUEST_BYTES }) });
   ```
   (`serveStdio` accepts `transport` [rea-mcp §1.10, rea-testing §4.4]; the constructor reads `options.maxBufferSize`
   — READ above.)
2. Bound every input by bytes, not only by counts: total vector cells per request ≤ 200,000; Σ `init_hex` ≤ 8 MiB;
   Σ field defaults ≤ 1 MiB; add a contract invariant that computes the worst-case serialized input from the schema
   bounds (the same machinery as the "worst-case envelope ≤ 2 MiB" output check, §8.3) and asserts
   `< MAX_STDIO_REQUEST_BYTES − 64 KiB`. Larger batches go through `generate`, `from_recording`, or a CLI `--input` file.
3. HTTP: set an explicit body limit and answer 413 instead of reading unbounded bodies (S1 `requestBody` has none).

---

## 2. Important

### I1. `call_function {thread_id}` via `Process.runOnThread` can execute **after** BEA gave up

**DESIGN.** §6.2 #26 (`thread_id?` runOnThread), S5 §9.5 rule 6, `run_on_thread_timeout_ms: 2000` (l.1469).

**Evidence (VERIFIED E17, `LAB/e17_*`, `out_e17.json`).** `runOnThread` on a thread blocked in a non-alertable
`ReadFile(stdin)`: the caller's 1 s timeout passed with the promise unsettled; the closure ran only when the host
wrote a line to stdin, **1,968 ms after queueing** (~1 s after the caller gave up). The hijack cannot be cancelled.

**Impact.** A timed-out oracle call later runs at an arbitrary moment with whatever is then in the CallBlock and
scratch buffers (which BEA may have reused for another call): wrong arguments, writes into reused buffers, or a crash
of the game thread; the result is never recorded.

**Fix (WP11 agent `call.ts`).** (1) Each `runOnThread` closure captures a per-chunk token and first checks
`token === current && !expired`; on timeout set `expired = true`, so a late run is a no-op (count it in
`status().rpc`). (2) Never reuse the CallBlock/scratch of an expired thread call: allocate per chunk and free only
when the closure has run (it calls back) or the session ends. (3) Before hijacking, sample the thread context
(exclusive `GetThreadContext`) and refuse with `invalid_state{thread-in-syscall}` when RIP is inside an ntdll syscall
stub (24-byte `Nt*` stubs, S4 F7). (4) Prefer a precise safe point: offer `thread_at: AddrExpr` that runs the chunk
from inside an `onEnter` of a hook on that thread.

### I2. Per-call `AbortSignal.any` over long-lived signals leaks ~1.7 KB per tool call

**DESIGN.** `invokeTool.ts` l.7477 `AbortSignal.any([client, deadline, core.lifecycle.shutdownSignal])`;
`OperationContext.signal` "composed: caller ∪ shutdown ∪ session-closing ∪ deadline" (l.4761); providers attach
listeners (frida `Cancellable` wiring, `Deadline.signal()`, waits).

**Evidence (VERIFIED E3/E3b, Node 24.18.0, `LAB/e3b_abort_any.mjs`).** 200,000 compositions with the shutdown signal as
a source: no listener 49 B/call; **listener left attached 1,707 B/call (325 MB)**; listener removed 379 B/call; manual
forwarding with explicit `removeEventListener` 0 B/call.

**Impact.** Memory grows with every tool call for the server's lifetime (HTTP scripting loops of 100k calls ≈
170 MB+), and doubly so for per-op session-closing composition.

**Fix (WP0, frozen file).** Add `src/domain/abort.ts`:
```ts
export const composeSignal = (sources: readonly AbortSignal[]): { signal: AbortSignal; dispose(): void } => {
  const c = new AbortController(); const subs: [AbortSignal, () => void][] = [];
  for (const s of sources) { if (s.aborted) { c.abort(s.reason); break; }
    const f = () => c.abort(s.reason); s.addEventListener("abort", f, { once: true }); subs.push([s, f]); }
  return { signal: c.signal, dispose: () => { for (const [s, f] of subs) s.removeEventListener("abort", f); } };
};
```
Use it in `invokeTool` (dispose in the existing `finally`) and for `OperationContext`; add a unit test that runs
100k invocations under `--expose-gc` and asserts < 64 B/call growth.

### I3. Shutdown: the hard-exit timer is armed late, and a busy admission drain turns a clean shutdown into exit 1

**DESIGN.** D-INT-6 (l.125) and S3 §7.6 ("On the first trigger, arm `setTimeout(() => process.exit(code), 1900)`").
§4 `mcpStdio.ts` l.8604–8616 arms `forceExitAfterMs(code, 500)` only **after** `lifecycle.closeAll` (≤ 1,800 ms) and
`handle.close()`/`owned.closeAll()` have finished. `Lifecycle` gives `stop-admission` 50 ms (l.6965) and counts a timed
out closer as failed (l.7068, `ok = phases.every(failed.length === 0)` l.7078).

**Problems.**
1. Worst case is ≥ 2,300 ms, past the SDK client's 2 s stdin-EOF → SIGTERM window [rea-testing §0.5]; on Windows that
   is TerminateProcess, so the documented "exit 0 within 2 s" fails and late phases are cut.
2. `Admission.#drain` waits for in-flight handlers; an RPC cancel takes ~106 ms to reject (S3 lab), so any in-flight
   agent call at shutdown overruns 50 ms. The outer race resolves `timedOut=true` before the closer's microtask chain
   removes it from `pending`, so "phase budget elapsed" is recorded and the server exits **1** although nothing leaked
   (the release checklist requires exit 0 with instruments active).

**Fix (WP0, frozen files).** In `requestShutdown`, call `deps.forceExitAfterMs(signalStatus ?? 1, 1900)` at the first
trigger (before `closeAll`) and keep the post-cleanup 500 ms timer; make `Admission`'s drain informational (never a
failure: report `abandoned_ops` like S3's closeAll) or move it into `teardown-targets` after the kills.

### I4. `watch_memory auto` prefers `page_guard` on attached targets: wrong premise and a severe performance hazard

**DESIGN.** §6.2 #23 l.10593–10594, R6 (l.11360), C-42 (l.11447): page_guard is preferred on attached targets because
"DRs are a crash hazard if BEA dies".

**Evidence.**
- E4 (VERIFIED, `LAB/e4_*`, `out_e4.json`): fixture started outside Frida; a separate Node host attached, armed a DR
  write watch on `g_car.counter` and was then killed with `taskkill /F` (no JS cleanup). **`rpc.exports.dispose` ran in
  both variants** (marker file written). With dispose disarming (`unset*` from the JS thread) the target **survived**;
  without disarm it died with **0x80000004** (STATUS_SINGLE_STEP). This closes open item A-36 positively.
- E4c (VERIFIED, `LAB/guardpoke.c`, `out_e4c.json`): a `PAGE_GUARD` left armed with no handler kills a plain target
  with **0x80000001** (STATUS_GUARD_PAGE_VIOLATION) — the page_guard engine has the same post-detach hazard (plus a
  stray TF single-step if a thread is mid re-arm). E4b (Frida-attached variant) was inconclusive: the guard was
  consumed before unload in both runs.
- E18 (VERIFIED, `LAB/e18_*`): the S4 F19 engine (guard → TF → re-arm) costs **≈ 9 µs per access** to *any* byte of the
  4 KiB page (20,000 guard/step pairs in 181 ms); one core saturates at ~110k accesses/s. The S4 lab's 810 pairs/s
  came from a cold page. A game physics state page is touched far more often than that, and the cost is paid for
  every variable on the page, not only the watched bytes (filtered hits are uncapped).

**Fix (WP9 + WP17).** (1) `auto` = debug register on every target when size/alignment fit and a slot is free;
page_guard only on explicit request or when DR cannot express the watch. (2) A rate valve in `pageguard.ts`: if
`(hits + filtered)` exceeds e.g. 20,000/s for 100 ms, disarm in the handler (no re-arm in `onStep`), end the
instrument with `end_reason:"rate_limit"` and a limitation. (3) Keep `dispose` disarm (now verified) and add a native
safety net for both engines: on the first DR/guard arm in an attached session, register a leaked
`AddVectoredExceptionHandler(1, …)` routine in `VirtualAlloc`'d memory (not `Memory.alloc`/CModule, both freed on
unload) that, for STATUS_SINGLE_STEP with DR6 bits of BEA-owned slots or with TF set by BEA, clears those bits/TF and
continues, and for STATUS_GUARD_PAGE_VIOLATION on a page in a BEA table continues; it covers the trap-rate race of
`unset*` (ext-frida §3.9) after the script is gone. BELIEVED; lab check: hot DR watch + host `taskkill /F` → target
alive.

### I5. BEA guard pages break every other agent memory path (scans, captures, dumps, timers)

**DESIGN.** Only `readMemory`/`readTyped` use `pageGuard.suspendFor` (S4 §8.2); scans use `Memory.scanSync`,
`Memory.copy`, `findPointers` and steal-mode CModule kernels over `enumerateRanges` (S4 §9.2–9.3); dumps use
`readByteArray` (S4 §15.1); hook captures dereference target pointers.

**Evidence (VERIFIED E16b, `LAB/e16b_*`, `out_e16b.json`).** After BEA arms `PAGE_GUARD` on a page:
`Process.enumerateRanges('rw-')` **no longer contains it** and `findRangeByAddress` returns `null`;
`Memory.scanSync` over it **throws "guard page was hit"** and the guard is **consumed** (protection 0x104 → 0x4). (A
first E18 version hung because an agent timer read `g_frame`, which shares the watched page: the read was stolen and
the callback threw.) E16 confirmed the good half: the target's own guard pages (thread stacks) are not listed in
`rw-` ranges, so scans do not consume them.

**Impact.** `scan_memory` cannot find a value on a watched page; `scan_next` drops the true candidate as "faulted";
captures with `deref` into a watched page fail; dumps record holes; the watch silently disarms (and is later re-armed
under a wrong diagnosis); `list_memory_ranges`/`describeAddresses` report watched pages as unmapped.

**Fix (WP3 core + WP9/10/13/7).** One core primitive `withBeaGuardsSuspended(ranges, fn)` used by every agent access
path (scan slices and kernels, `Memory.copy` snapshots, `findPointers`, dump chunks, capture derefs, `poll` reads,
call vectors); region enumeration re-inserts BEA-guarded pages with their `origProtect`; any stolen `guard-page`
error on a BEA page immediately marks the page disarmed and re-arms it with a `suspend_window` count (never
`kernel_access_suspected`). Captures check `pageGuard.ownsPage` before dereferencing.

### I6. Dumps embed live Interceptor/Frida code patches

**DESIGN.** `dump_memory` (§6.2 #30), `emu_open {live_session_id}` (D-INT-29, l.10680), bundle rule R1 (S5:
`module.enumerateRanges('---') + readByteArray`), S4 §15.1 (raw `readByteArray`); the ISA cache key "covers the
captured bytes, so runtime-patched code is scanned as it really is" (S5 §3.7).

**Problem.** Images are read verbatim, so every BEA hook (the `jmp` that Interceptor writes over the function entry,
ext-frida §3.6 gotcha 7) and Frida's own patches (ntdll `LdrLoadDll`, `kernel32!FatalExit` — S2 E-verification) are
in the dump. Investigation 1 hooks `physics_step` and then emulates it from a live capture: the emulator executes the
`jmp` into Interceptor's trampoline slab, which is cloaked and never captured → `fetch` fault → `diff_function`
`unknown`. `dump_memory format:"pe"` hands Ghidra/REA functions that start with a jump to nowhere.

**Fix (WP13 + WP14).** Splice original bytes by default: the agent's `originals` overlay for BEA patches (already
kept for `disassemble`) plus a host comparison of executable sections against the on-disk image with relocations
applied (the S2 `FootprintScanner`/`imageBytes` machinery) for foreign patches; record each restored range in the
manifest (`restored_patches[]`) and add a loader deviation `live_patches_restored`; option `live_bytes:true` keeps
the raw bytes. Add an acceptance row: hook `physics_step` → `emu_open {live_session_id}` → `emu_call physics_step`
returns the live result.

### I7. Spawned targets inherit the whole BEA server environment

**DESIGN.** `SpawnInput.env` "merged into BEA's environment (S6), never a replacement" (l.4791); §6.2 #3 l.10407;
§5.1 l.9868 (`env merged`). Frida's `env` merges into the host process environment (ext-frida §1.4, VERIFIED).

**Problem.** BEA's environment is the MCP client's environment (API keys, cloud tokens, `GITHUB_TOKEN`, …) plus BEA's
own `BEA_HTTP_TOKEN` (accepted from env, config.ts l.2518) and `BEA_ALLOW_*` gates. Every spawned target, including
untrusted programs traced with `trace_api`, receives them and can exfiltrate them; a target holding
`BEA_HTTP_TOKEN` can drive the BEA server over HTTP.

**Fix (WP4).** Build the target environment explicitly and pass it as `envp` (replace): an allowlist of OS
variables (`SystemRoot windir SystemDrive ComSpec PATHEXT PATH TEMP TMP USERPROFILE USERNAME USERDOMAIN HOMEDRIVE
HOMEPATH APPDATA LOCALAPPDATA ProgramData ProgramFiles ProgramFiles(x86) ProgramW6432 CommonProgramFiles* PUBLIC
COMPUTERNAME NUMBER_OF_PROCESSORS PROCESSOR_* OS ALLUSERSPROFILE DriverData`) + the caller's `env`; always strip
`BEA_*`; record the allowlist version and the dropped-key count (never names) in the instance evidence;
`env_mode:"inherit"` only behind a config flag. Note in `docs/security.md` that in HTTP mode every same-user process,
analysed targets included, can read `BEA_HOME/http/connection.json`; recommend not running `--http` while tracing
untrusted programs.

### I8. File writes anywhere with target-controlled content, and spawn-anything, under prompt injection

**DESIGN.** `out_path?: string (abs; must not exist)` on `dump_memory` (l.10666), `export_coverage` (l.10607),
`export_evidence` (l.10743); `spawn_process` accepts any drive-absolute program (`.bat/.cmd` refused, but
`cmd.exe /c …`, `powershell.exe -c …`, `mshta`, `rundll32` are fine) and is ungated; target strings reach the model.

**Problem.** `dump_memory {format:"raw"}` writes bytes chosen by the (possibly malicious) target to any new path,
e.g. `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\x.cmd`; together with an interpreter spawn this turns a
prompt injection in target output into persistence or code execution. The untrusted marker and instructions are
advisory only (R15).

**Fix (WP13/WP9/WP1/WP4).** Restrict `out_path` to `BEA_HOME/runs/<run>/exports/` or a user-configured
`exports.allowed_roots` list (config only, never a tool input); refuse executable/script extensions
(`.exe .dll .sys .scr .com .bat .cmd .ps1 .psm1 .vbs .vbe .js .jse .wsf .wsh .hta .lnk .url .msi .reg`); refuse paths
under Startup folders and `%WINDIR%`. For `spawn_process`, refuse known interpreters/LOLBins unless
`spawn.allow_interpreters` is set in config (user-only), and say so in the description.

### I9. Live oracle calls use a fixed FP environment instead of the target thread's

**DESIGN.** `fpSchema` defaults 0x1F80/0x027F (l.6429–6432; §6.2 #26 l.10621); diff uses "the same FP env" on both legs.
S4 F14: a real gcc/msvcrt thread runs FPCW 0x37F, MXCSR 0x1FA0; S4 §15.1 already tells the emulator to take
FPCW/MXCSR from the captured `ThreadState` for dumps.

**Problem.** Game physics threads commonly run with FTZ/DAZ (MXCSR 0x9FC0); the oracle then computes with denormals
enabled, which S5-E6 shows changes results (`0x3480020` vs `0x0`). "Bit-exact oracle" is bit-exact only to the
chosen FP env, which by default is not the game's, so `diff_function` can call the emulator "equivalent" to a live
result that the game never produces.

**Fix (WP11/WP14).** Add `fp: "thread"` as the default for live calls when a thread can be named (the `thread_id`,
the hooked thread of `from_recording`, or the dump's primary thread): read MXCSR/FPCW via `captureThreadState`, clear
the MXCSR status bits, use them for **both** legs, and record `fp_source` in the evidence; keep `"windows-default"`
(0x1F80/0x027F) as an explicit choice; the skill tells agents to pass the physics thread.

### I10. HTTP mode: session capacity and the Windows launch/kill pitfalls of scripted use

**DESIGN.** D-INT-12 / §5.9 (≤ 4 MCP sessions, 30 min idle eviction, l.10285–10287); the Python recipe is the WP16
acceptance test.

**Problems.** (1) Small Python clients that crash, are interrupted, or never send `DELETE /mcp` each leave a session;
the fifth script within 30 minutes gets `503 capacity reached`. (2) On Windows, a script that starts `bea` (the npm
`bea.cmd` shim) and later calls `Popen.terminate()` kills `cmd.exe`, not node: the server and its owned targets keep
running and the port stays bound.

**Fix (WP16/WP17).** At capacity, evict the least recently used session with `inFlight === 0` instead of refusing;
idle eviction 5 min; the recipe sends `DELETE` in `finally`, launches `node <abs>/scripts/bea.mjs mcp --http` directly
(no shim) and stops with authenticated `POST /shutdown` (falling back to killing the `pid` from `connection.json`).

### I11. Anti-cheat refusal fires on machine-wide processes

**DESIGN.** D-INT-1 (l.120) and §5.1 (l.9865–9867): refuse spawn/attach when "running EAC/BattlEye/vgc/FACEIT/
EAAntiCheat/mhyprot/nProtect processes" exist (S6-catalog l.638–641, signal (a): "a known anti-cheat service or
client process is running").

**Problem.** `vgc.exe` (Vanguard) runs permanently as a service wherever Valorant/LoL is installed; FACEIT and EAC/EOS
services are similar. BEA then refuses every target (fixtures included), and the only escape,
`BEA_ALLOW_ANTI_CHEAT=1`, also disables the protection for genuinely protected targets.

**Fix (WP4).** Make signals target-scoped: AC components in the target's directory or its parent (signal (b)), AC
modules loaded in or imported by the target (`EasyAntiCheat_x64.dll`, `BEClient_x64.dll`, …, checked after attach and
before any instrument), or an AC client in the target's ancestry. Machine-wide AC processes become a limitation and a
`bea_status` warning, not a refusal. Allow a per-image override by sha256 (`attach.allow_anti_cheat_images`).

---

## 3. Minor

- **M1. `trace_execution on_call` misses the entry block** (VERIFIED E10, `out_e10.json`): following from `onEnter`
  works for N=3 invocations with the target healthy (closes L-S6-4), but the first recorded block is `+0x1765`, not
  `+0x1760`: the relocated prologue runs in Interceptor's trampoline. Synthesize `[entry, first_block)` for each
  invocation or follow from the caller; say so in the drcov export.
- **M2. `call_function hooks:"observe"|"suppress"`**: E14 (VERIFIED) shows `hook_function` listeners **do** fire on the
  agent JS thread for `NativeFunction` calls (5/5), so suppression must be explicit in every JS and CModule listener
  (`agentCallTids`), while profile listeners drop the cloaked agent thread anyway, so `observe` never yields
  `trace_api` rows for agent-thread calls. Require `thread_id` for `observe`, or document the difference.
- **M3. ISA guard v2 INT3 overlay** (§5.6 l.10192; S5 §3.7): inside `.pdata` ranges a decode that hit a `skipdata`
  event can be desynchronized, and an INT3 written mid-instruction silently changes an immediate/displacement (no
  fault, wrong result). Patch INT3 only at sites reached by a skipdata-free decode from the function start; elsewhere
  use the non-destructive per-address hooks.
- **M4. `BEA_MCP_MAX_RESPONSE_BYTES` up to 256 MiB** (config l.2253): SDK-based clients read with the same 10 MiB
  `ReadBuffer`; an over-10 MiB response closes the *client* transport (then the client usually closes BEA). Cap the
  stdio default at 10 MiB and document that raising it needs a matching client setting.
- **M5. Canonicalization and validation cost** (VERIFIED E11): the §4 emitter digests 76–134 MB/s (1 MiB ≈ 8–13 ms,
  10 MiB ≈ 75–130 ms) synchronously on the event loop, and outputs are zod-validated twice (`invokeTool` self-check and
  SDK). Acceptable, but keep big arrays in blobs/streams, and give the advertised output schema a pass-through
  `validate` since `invokeTool` already checked. A non-finite number anywhere in a result throws
  `CanonicalizationError` at record time (stats/ulp code): normalize to `"NaN"`/`"Infinity"` strings in builders.
- **M6. Timed-out shutdown phases keep running** into later phases (Lifecycle only stops waiting): a late
  `sink.sessionEnded` can append after `{t:"end"}`. Fence `EvidenceRuntime` (reject appends once finalize starts and
  report them).
- **M7. Paths** (`paths.ts` l.2156): `win32.isAbsolute` accepts `\bea` (drive-relative) and UNC roots for `BEA_HOME`;
  require drive-absolute. If `BEA_HOME` is outside the user profile, `http/connection.json` inherits a possibly shared
  DACL: set an owner-only DACL on Windows or refuse.
- **M8. Untrusted text on "content-free" tools**: `agentErrorMap` copies `agent_message` (agent-authored, target
  address space) into `details.diagnostics` (l.3562–3565); `stop_instrumentation` is `returnsTargetContent:false`, so
  such errors go out without the untrusted marker. Drop `agent_message` for those tools or force the marker.
- **M9. Emulator bridge stop escalation 1.5 s** (l.10205) exceeds the 1,300 ms `teardown-targets` budget; use ≤ 900 ms
  like jobhost.
- **M10. `@types/frida-gum` 19.12.0**: E13 (VERIFIED) shows frida.Compiler ignores an ancestor
  `node_modules/@types/frida-gum` (a probe `.d.ts` had no effect; type errors still fail), so the build is safe, but the
  repo `src/agent/tsconfig.json` `types:["frida-gum"]` makes editors check against a newer API than 17.23.2
  (ext-frida §2). Pin the typings to the Frida version or document that only `build:agent` is authoritative.
- **M11. Python under `-I`** ignores user site-packages, so a `pip install --user unicorn` Python fails the probe;
  the resolver message should name that cause, not only "run `bea setup --emulator`".
- **M12. CLI numbers** (`argv.ts` l.8374): `Number("")` is 0 and negative values need `--opt=-1` with `parseArgs`;
  parse numbers with the same decimal/hex grammar as the schemas and document the `=` form.

---

## 4. Checked and confirmed (no change needed)

| Id | Claim checked | Result |
|---|---|---|
| E1 | `build-agent.mjs` with a connected `compiler.diagnostics` handler terminates without `process.exit` | VERIFIED: exit 0 in 304 ms |
| E4 | A-36 `rpc.exports.dispose` runs when the host dies | VERIFIED on `taskkill /F` of the host; DR disarm there prevents the 0x80000004 crash (see I4 for the residual race) |
| E6 | BEA's own faulting reads (JS thread, hook callbacks, NativeFunction, runOnThread) never produce false crash reports | VERIFIED: the dispatcher saw 0 of 4 (the flip side is B1/B2/I5) |
| E10 | L-S6-4 Stalker follow from `onEnter` / unfollow in `onLeave`, N invocations | VERIFIED working; entry-block caveat M1 |
| E11 | RFC 8785 emitter cost | 76–134 MB/s (M5) |
| E13 | Ancestor `@types/frida-gum` does not change frida.Compiler's checking | VERIFIED |
| E14 | Interceptor listeners vs agent-thread `NativeFunction` calls | fire (5/5) → explicit suppression needed (M2) |
| E16 | Scans over `enumerateRanges('rw-')` cannot consume target stack guard pages | VERIFIED: 0 guarded sub-regions in 61 `rw-` ranges |
| read | S5 §9.5 thunk ABI | callee entry RSP ≡ 8 (mod 16), 0x20 shadow space, stack args at `[rsp+0x28+8k]`, rbx/rbp saved; no unwind info (needed for B1) |
| read | SDK 2.3.1 stdio transport | oversize → `close()` (B3); `serveStdio({transport})` and `maxBufferSize` exist |
| read | HTTP auth (S1 A.6) | Host → Origin → bearer (SHA-256 + `timingSafeEqual`) before any body read; browser CSRF needs a preflight that the Origin check refuses; token never logged |

Experiment index: E1 `e1_compiler_exit.mjs`; E3/E3b `e3*_abort_any.mjs`; E4/E4b/E4c `e4*_driver.mjs`, `guardpoke.c`;
E6 `e6_*`; E7 `e7_*`; E8 `e8_*`; E9 `e9_*` + `cxx_catch.cpp`; E10 `e10_*`; E11 `e11_canonical_cost.mjs`; E12
`e12_oversize.mjs`; E13 `e13_compile*.mjs`; E14 `e14_*`; E16/E16b `e16*`; E17 `e17_*`; E18 `e18_*`. Console-only results
are in `LAB/out_console_results.json`.
