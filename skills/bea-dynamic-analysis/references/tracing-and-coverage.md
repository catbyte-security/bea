# Tracing and coverage

`trace_execution` follows threads with Frida's Stalker (dynamic recompilation) and records which basic blocks run.
`export_coverage` writes the result as a drcov file for Lighthouse (IDA, Binary Ninja) or Cartographer (Ghidra).

## Choosing what to follow

Give exactly one of:

- `on_call:"game.exe+0x123460"` with `invocations:N` (default 1, up to 1000): follow the thread from the entry of
  the next N calls of that function until each returns. The cleanest way to get "the code of one call".
- `thread_ids:[…]` (up to 16): follow those threads for the whole window. Find thread ids with `list_threads`, from
  hook rows (`tid`) or from watch hits.

`modules` (default `["$main"]`, up to 16) are instrumented; code in other modules runs natively and is not recorded.
Add a DLL to `modules` when the logic you want lives there. At most one trace per thread.

## Modes and cost

| `mode`               | Records                             | Cost                                                                |
| -------------------- | ----------------------------------- | ------------------------------------------------------------------- |
| `coverage` (default) | each block once                     | low after warm-up; the first execution of every block is recompiled |
| `block_counts`       | each block with its execution count | moderate                                                            |
| `calls`              | caller → callee edges with counts   | high: call-heavy code can run about 90× slower                      |

Stalker slows the followed thread. On a game, follow one call (`on_call`) or a short window, never the render thread
for minutes. `max_events` (default 1,000,000) bounds the recording; `dropped > 0` makes coverage `partial`.

```
trace_execution {session_id, on_call:"game.exe+0x123460", invocations:1, mode:"coverage", wait_ms:5000}
```

The summary (`TraceSummary`): `invocations`, `threads`, `blocks`, per-module block counts, up to 50 functions with
their block counts and first sequence number, and the top call edges in `calls` mode. Rows (`query_events`): `block`
(at), `size`, `hits` (block_counts), `from`/`to` (calls).

`on_call` coverage includes the function's entry block even though Stalker starts following just after it (limitation
`TRACE_ENTRY_SYNTHESIZED`).

## Other sources of coverage

| Source                      | Call                                                                                | Then                                             |
| --------------------------- | ----------------------------------------------------------------------------------- | ------------------------------------------------ |
| one call with chosen inputs | `call_function {…, coverage:true}`                                                  | `export_coverage {evidence_id}` of the call      |
| an emulated call            | `emu_call {…, trace:{coverage:true}}` (or `trace:{blocks:true}` for the block list) | `export_coverage {evidence_id}` of the emulation |

Emulated coverage is authority `emulation`: it shows what the emulator executed for that input, which is the same
code path only when `diff_function` says the function is equivalent on that input.

## Exporting

```
export_coverage {recording_id:"rec_…", format:"drcov"}
export_coverage {evidence_id:"ev_…"}
```

- `format:"drcov"` (default) writes drcov version 2 (module table + basic-block table); `format:"modoff"` writes
  plain `module+offset` lines for tools that do not read drcov.
- The file goes to the run's `exports\` directory unless `out_path` names a new absolute path that the output
  policy allows (never one taken from target text). It never overwrites.
- The result lists `blocks`, per-module counts and up to 50 functions with block counts.

Loading:

- **Lighthouse** (IDA/Binary Ninja): File → Load File → Code coverage file. **Cartographer** (Ghidra): use its load-coverage action
  on the open program.
- Load it against the **same binary** (same sha256) the trace ran on. Modules are matched by name; a different build
  produces nonsense coverage without an error.
- Offsets are relative to each module's base, so ASLR does not matter.

## Interpreting coverage

- Stalker splits blocks after every call, so a block boundary in BEA's output may sit inside one Ghidra basic block.
  Compare by **address range**, not by block count.
- One call covers one path. "Not covered" means not executed **for those inputs**, never "dead code".
- Code in modules outside `modules` shows up as calls out, not as blocks.
- JIT or self-modifying code is recorded at its runtime address; it has no static form.
- Exception paths taken through the OS dispatcher (SEH handlers) may appear without the edge that led to them.

## Pitfalls

- `on_call` on a function that never runs in the window ends with `invocations:0`; ask the user to trigger it (open
  the menu, drive the car) during `wait_ms`, or use `wait {ids:["rec_…"]}` afterwards.
- A thread already followed by another trace gives `instrumentation_failed`; stop the other trace first.
- Hooks added or removed while a thread is followed are handled (Stalker is invalidated at that address); expect a
  small hiccup.
- Following a thread that is blocked in a system call records nothing until it returns.
