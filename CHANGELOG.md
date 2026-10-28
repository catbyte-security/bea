# Changelog

## Unreleased

### Fixed (dogfooding on Chrome's GPU process, BEA-FEEDBACK 2026-10-28)

- **PE reader:** functions that share a linker-folded `UNWIND_INFO` blob are no longer reported as fragments of
  the first function that used it. Before the fix, 98% of `chrome.dll`'s functions were affected. `hook_function`,
  `override_function` and `trace_execution {on_call}` refused real function starts as "not a function start", and
  `func` / `function_start` in `map_address`, crash frames, `list_threads` and coverage summaries named the wrong
  function. Only chained and indirect unwind links are cached now.
- **No deadlock on ASan targets:**
  - Crash backtraces come from ntdll's unwinder (`RtlLookupFunctionEntry` + `RtlVirtualUnwind`) on a private copy
    of the exception context instead of dbghelp, so nothing allocates through the target's CRT.
  - Blocking first-chance reports are opt-in (`crash.first_chance_blocking`, `BEA_CRASH_FIRST_CHANCE_BLOCKING`).
  - First-chance exceptions in ASan's runtime, in ASan's shadow memory or in `crash.passthrough_modules` pass through
    without reporting work.
  - Last-chance reports list only the faulting frames.
- **Code Integrity Guard and Arbitrary Code Guard:**
  - `attach_process` refuses processes that enforce either one before injecting (`access_denied`, reason
    `code-integrity-guard` / `arbitrary-code-guard`).
  - `bea-jobhost inspect` reports the target's mitigation policies, and attach evidence records them. A process
    that enforces user-mode shadow stacks gets the `USER_SHADOW_STACKS` limitation.
- **Failure details:**
  - A failed spawn, attach or resume carries Frida's own message in `details.diagnostics.frida_message`, sanitized
    and at most 300 characters.
  - An injection that ended the target is reported as `target_exited` with its exit status.
- **Attach deadline:** it is configurable (`limits.attach_timeout_ms`, `BEA_ATTACH_TIMEOUT_MS`, 1–110 s), and a
  timeout names the setting. `spawn_process` and `attach_process` deadlines are 120 s, and `bea_status` reports the
  attach deadline and the crash policy.
- **Thread names:** `list_threads` reports them (`SetThreadDescription`).
- **`trace_execution` thread mode on busy processes:** a traced thread that is blocked in a system call is followed
  from its next entry into that stub, through a hook on the stub. Before, every wait of every thread passed through a
  JavaScript callback and the agent's lock for the whole trace, which wedged Chrome's GPU process. The hook is now
  native, so other threads never enter JavaScript, and it is removed as soon as the thread is followed. A thread
  sampled inside `NtAllocateVirtualMemory` is refused (`invalid_state`; retry). The `modules` description now says
  that indirect calls into other modules are still followed.
- **New test fixtures:** `vehcommit.exe` (an ASan-like commit-on-demand allocator), `waiters.exe` (a busy wait stub
  plus a parked thread) and `mitigated.exe` (self-enabled CIG/ACG and named threads).

## 0.1.0 (unreleased; release candidate 2026-10-28)

First integrated version, built in waves by work packages WP0–WP17 and integrated by WP18
([docs/STATUS.md](docs/STATUS.md) has the verified state; [docs/decisions.md](docs/decisions.md) the change log of
the frozen core).

### Added

- MCP server (`bea mcp`, stdio; `bea mcp --http` for local HTTP) with 37 tools in 12 areas: sessions, inspection,
  address mapping, scans, instruments and recordings, API behavior profiles, watchpoints and Stalker tracing, oracle
  calls, gated modification, dumps, emulation and differential testing, evidence and unknowns
  ([docs/tools.md](docs/tools.md)).
- CLI (`bea`): one-shot commands generated from the tool contracts, `bea run` scenarios (`bea-scenario/1`),
  `bea setup` / `bea doctor` / `bea uninstall` for six MCP clients and the agent skill, `bea mcp doctor`.
- Frida 17.23.2 agent compiled at build time (`dist/agent/bea-agent.js`), the gcc-built containment helper
  `bea-jobhost.exe` (kill-on-close job objects), and the Python/Unicorn emulator bridge.
- Evidence ledger: content-addressed records with coverage and limitations, streams, blobs, export/import bundles.
- The `bea-dynamic-analysis` agent skill with nine references; recipes R1–R7 are the seven investigation scenarios of
  the release lane.

### Release stage (WP18)

- Lanes: lifecycle must-haves (S6 §10.9), the seven S6 §1 investigations as `bea run` scenarios, the cross-wave
  integration rows, the `verify:frida:windows` receipt (CLI one-shots vs MCP, pointer-free projections).
- Fixes found by those lanes: forward-slash spawn paths, `resume_process`/`wait` returning before the recordings they
  waited for had finished, raw-VA callers in hook summaries, `query_events` on emulation and diff row streams, a Frida
  17.23.2 deadlock in `trace_execution` thread mode (worked around), QJS float handling in the agent core, Python
  auto-install during interpreter probes, `end_reason: "rate-limit"`, client cancellations on the server log.
- knip back to strict; the catalog budget golden regenerated (drift check active).

### Post-release review fixes

- Emulator: legacy-SSE `rcpss`/`rcpps`/`rsqrtss`/`rsqrtps` and `dpps`/`dppd`, which Unicorn computes differently from
  hardware, are tagged (`sse_approx_inexact`; ISA cache key `bea-isa/2`) instead of returning their values as exact.
- Emulator: out buffers come back whole in single calls and batches (they were cut at 1 MiB and 4 KiB, and the cut
  bytes decoded as zeros); a request whose out-buffer hex would exceed 56 MiB is refused before it runs.
- Emulator: the HLE heap reuses freed memory (best-fit, coalescing free list; `realloc` in place), reports a full
  heap as `hle_heap_exhausted`, and a `chain` batch whose next vector's `heap` buffers do not fit returns the
  completed prefix instead of an error that discarded it.
- Docs and skill: Node 24.x only (`npm ci` refuses 25 and 26); the verified impact of a never-returning
  `call_function` on an attached target (L-S6-11); `from_recording` takes scalar-only signatures; the emulator row
  is `not-loaded` until the first `emu_open`, which is no reason for `bea setup --emulator`.
- Agent: closing a session no longer frees the call thunk under a still-running call (attached targets crashed);
  page_guard watches respect the target's own `VirtualProtect`; dispose leaves memory the target changed after a
  write as found; stopped native hooks and counting traces free their buffers (6 MiB and 23 MiB each before);
  `trace_api` records threads Stalker follows; the "second thread-mode trace records nothing" bug is fixed (cause:
  `Stalker.unfollow` of a remote thread); C++ throws and `OutputDebugString` are no longer crash reports; the x87
  stack is reset after a callee fault (`fninit`).
- Helper: `bea-jobhost` accepts the same file reached through a junction, symlink, `subst` drive or 8.3 name.
- Host security: spawn refusal by name, location and version resource (`spawn.allowed_programs` lifts it for one
  program); network paths refused for programs, `cwd` and input files; redaction covers `read_memory` views and
  `scan_results`; zip imports are capped before any write; anti-cheat directory signals look 3 levels up.
- Host lifecycle: Frida's ~45 MB agent extraction goes to `BEA_HOME\tmp\frida\<run>` and is reclaimed (it leaked
  one `%TEMP%\frida-*` directory per server process); cancelled attaches and installs leave no stray agent or
  instrument; the shutdown hard-exit timer can fire; jobhost adoption runs before the metadata step.
- Host results: mid-function hook addresses are refused unless `probe:true`; `query_events` pages no longer repeat
  the recording summary; `resume_process {until:"exit"}` settles built-in recordings; diff and emulation fixes
  (EMU-3/4/8/9/11/12/13, `signature.convention:"msvc_method"`); PE reader caps; dump region protections; the
  `mapped` dump is labelled a raw memory image (Ghidra receipt: the realigned dump loads like the original).
- Integration: lost live targets give `diff_function` a verdict; chain batches that stop at a full emulated heap
  say so; a call still running after a thread timeout is reported as such; `close_session` on an unresponsive agent
  says a retry cannot help; zod 4.6.7 (GHSA-mrhx-c7xc-m3w5).
