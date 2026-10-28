# Crashes

## Getting a crash report

Spawned target:

```
spawn_process {program:"C:\\lab\\crashy.exe", args:["av-write"]}
resume_process {session_id, wait_ms:60000, until:"exit"}
```

Attached target: `wait {session_id, until:"exit", timeout_ms:60000}` (repeat while `reason` is `timeout`). Afterwards
`session_status {detail:"complete"}` returns the same report with XMM registers.

`exit` (`ExitInfo`): `code`, `code_hex`, `name` (`STATUS_ACCESS_VIOLATION`, …) and `kind` (`normal`, `ntstatus`,
`bea-kill` when BEA's job killed it, `unknown`).

`crash` (`CrashReport`):

| Field                | Meaning                                                                                                          |
| -------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `type`               | `access-violation`, `illegal-instruction`, `arithmetic`, `stack-overflow`, `fast-fail`, `abort`, `breakpoint`, … |
| `ntstatus`           | the exception code                                                                                               |
| `thread_id`          | the faulting thread                                                                                              |
| `pc`                 | `{va, at, static, func, sym}` of the faulting instruction; **null** when no exception reached user mode          |
| `insn`               | Intel text of the faulting instruction                                                                           |
| `memory`             | `{op: read                                                                                                       | write | execute, address}` for access violations |
| `registers`          | all 17 general-purpose registers                                                                                 |
| `backtrace`          | faulting pc first, then return addresses as `Loc` (module + RVA, static VA)                                      |
| `first_chance_count` | exceptions recorded before the fatal one                                                                         |
| `evidence_id`        | the derived `bea.crash` record                                                                                   |

BEA builds the report from the last crash-class exception before the process died and cross-checks it against the
exit code; a mismatch becomes a limitation.

## NTSTATUS codes you will see

| Code                      | Name                   | Usual meaning                                                                                                  |
| ------------------------- | ---------------------- | -------------------------------------------------------------------------------------------------------------- |
| `0xC0000005`              | ACCESS_VIOLATION       | read/write/execute of an invalid or protected address; `memory.address` near 0 = null pointer (+ field offset) |
| `0xC000001D`              | ILLEGAL_INSTRUCTION    | `ud2`, an unsupported instruction (AVX-512 on an older CPU), jumping into data                                 |
| `0xC0000096`              | PRIVILEGED_INSTRUCTION | a kernel-only instruction in user mode                                                                         |
| `0xC0000094`              | INTEGER_DIVIDE_BY_ZERO | `div`/`idiv` by zero                                                                                           |
| `0xC0000095`              | INTEGER_OVERFLOW       | `idiv` overflow (`INT_MIN / -1`)                                                                               |
| `0xC000008D`–`0xC0000093` | FLOAT_*                | an FP exception that the program unmasked                                                                      |
| `0xC00000FD`              | STACK_OVERFLOW         | runaway recursion or a huge stack allocation                                                                   |
| `0xC0000409`              | STACK_BUFFER_OVERRUN   | **fast fail** (`__fastfail`): stack cookie failure, CFG violation, invalid parameter, `abort()` in some CRTs   |
| `0xC0000374`              | HEAP_CORRUPTION        | the heap manager detected corruption (often long after the bug)                                                |
| `0x80000003`              | BREAKPOINT             | `int3` / `__debugbreak` with no debugger                                                                       |
| `0xE06D7363`              | (C++ exception)        | an uncaught C++ `throw` (`msc` magic)                                                                          |
| `0x40010004`              | DBG_TERMINATE_PROCESS  | terminated through a debug API                                                                                 |
| `3`                       | (exit code 3)          | the MinGW/MSVC `abort()` exit code                                                                             |

## When `pc` is null

Fast fail (`0xC0000409`) and stack overflow (`0xC00000FD`) may terminate the process without delivering an exception
to user-mode handlers. Then `crash.pc` is null, a limitation says so, and **only the exit code is known**. Say that;
do not invent a faulting instruction. Next steps: hook the suspected function and `__report_gsfailure` /
`RtlFailFast` callers, or check the `exceptions` recording for the last first-chance exceptions before the exit.

## First-chance noise

Every live session has a built-in `exceptions` recording (its `recording_id` is in the spawn/attach result's
`recordings`). It holds **first-chance** exceptions: many are normal (C++ exceptions caught by the program, guard-page
probes, `IsBadReadPtr`-style probing, `OutputDebugString`, thread-naming exceptions `0x406D1388`). They are not
crashes. Use them to see what led up to a crash:

```
query_events {recording_id:"rec_…", view:"group", group_by:["type"]}
query_events {recording_id:"rec_…", view:"rows", order:"desc", limit:10}
```

Fields: `type`, `address`, `memory_op`, `memory_address`, `insn`.

## Reporting a crash

1. The exception type and NTSTATUS, and which thread.
2. The faulting instruction (`insn`) at `pc.at` and its static VA `pc.static` (map it into Ghidra with that VA; run
   `map_address` on `pc.at` if you need verification bytes).
3. The memory access (`memory.op`, `memory.address`) and the registers that explain it (the base register of the
   operand; a register near 0 for a null dereference).
4. The backtrace with static VAs, innermost first. Frames without a module (`at` null) are JIT, heap-executed or
   corrupted stack.
5. Reproducibility: run again with the same arguments and say whether the same `pc.static` faulted.
6. What is not known: `pc` null, a corrupted stack (`backtrace` short or nonsensical), or a mismatch limitation.

## Pitfalls

- Heap corruption crashes far from the bug. The faulting instruction is the victim; say so instead of blaming it.
- A crash inside a system DLL (`ntdll`, `ucrtbase`) usually has its cause in the first frame of the program's own
  module in the backtrace.
- The job object kills child processes at `close_session`; a crash in a child is not reported by the parent session.
- On attached targets BEA learns the exit through a watcher; if BEA itself was detached before the crash, there is no
  report.
- A program that crashes only under BEA: suspect timing (hooks), the FP environment, or anti-debug checks; try again
  with fewer instruments and report the difference.
