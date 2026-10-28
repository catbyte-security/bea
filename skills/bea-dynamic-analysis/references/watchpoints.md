# Watchpoints

`watch_memory` answers "which instruction writes (or reads, or executes) this address?" and "which fields of this
struct change?".

```
watch_memory {session_id, address, size:4, access:"write", method:"auto", duration_ms:2000, wait_ms:3000}
```

## Methods

| Method           | How                                                                                    | Cost                                                | Use for                                                |
| ---------------- | -------------------------------------------------------------------------------------- | --------------------------------------------------- | ------------------------------------------------------ |
| `debug_register` | a hardware breakpoint (DR0–DR3) armed on every thread, including threads created later | none until hit                                      | **the default**: 1, 2, 4 or 8 bytes, naturally aligned |
| `page_guard`     | PAGE_GUARD on the whole page + single-step to identify the access                      | a trap on **every** access to the page, by any code | only when a debug register cannot express the watch    |
| `poll`           | timer sampling of the range                                                            | none in the target's threads                        | struct exploration; never finds the instruction        |

`method:"auto"` (default) picks a debug register whenever size and alignment fit and one of the 4 slots is free,
on attached and spawned targets alike; otherwise page_guard. It never picks poll.

- `access`: `write`, `read_write` or `execute`. Hardware has no read-only watch: `read_write` reports reads and
  writes and the hit row says which (`access`).
- Debug registers: size 1/2/4/8 at an address aligned to that size; a misaligned watch fails with the nearest
  valid size and address in the message. 4 slots per session, shared by all watches.
- page_guard: up to 16 pages. Keep the window short (a few seconds) and the page quiet: a hot page slows the target
  heavily. Above `rate_limit_per_sec` (default 20,000 traps/s over 100 ms) the watch disarms itself (end reason
  `rate-limit`, limitation `WATCH_RATE_LIMIT`). Guarded pages that BEA itself must read are suspended briefly
  (`bea_guard_suspended`, `WATCH_SUSPEND_WINDOWS`); hits in those windows are lost.
- poll: `interval_ms` (default 16), `view` (`f32`, `i32`, …) decides how the range is split into fields.

## Reading hits

The summary (`WatchSummary`) groups hits by instruction: `writers[{insn{va, at, static, func, text}, access, count,
threads, struct_bases[{base, disp, count}], values{first, last, distinct}}]`, most frequent first.

Hit rows (`query_events`): `seq, t_ms, tid, access, insn, insn_text, insn_confidence, operand{base, index, scale,
disp}, struct_base, value, value_when, regs`.

- `insn_confidence`:
  - `exact` — a debug register traps **after** the access; BEA decodes forward from the enclosing `.pdata`
    function start to the instruction that ends at the trap address (page_guard reports the instruction itself);
  - `recovered` — no `.pdata` function: one candidate instruction before the trap address fits; usually right, not
    guaranteed;
  - `ambiguous` — several candidates fit; treat the writer as unknown.
- `struct_base` = the base register's value at the access, `disp` = the displacement: `movss [rbx+0x1c4], xmm6` with
  `rbx = 0x1f3a5c40` gives base `0x1f3a5c40`, disp `0x1c4`. It is a **heuristic**:
  - null when the access overwrote its own base register (`mov rax, [rax+8]`) or used an index register in a way
    that hides the object start;
  - an index (`[rbx+rcx*4+0x10]`) means an array element: the object start is not `rbx` alone;
  - compilers sometimes point a register into the middle of an object; confirm with a hook on the writer function
    (`capture:[{name:"this", arg:0, type:"ptr"}]`) before naming a struct base.
- `value` / `value_when`: the value at the hit, `after` the access for debug registers, `before` it for page_guard.
- `registers:["rbx","rcx"]` adds registers to every hit (operand registers are always captured).

## Recipes

**Writer of a variable.** `access:"write"`, `size:4`, `duration_ms:2000`. Ask the user to make the value change
during the window. Several candidates: watch up to 4 at once on debug registers. The variable you want is written by
game logic (the same writer every frame); UI and telemetry copies are written by other code, often less often.

**Readers.** `access:"read_write"`; expect many hits from many functions. Use `query_events {view:"group",
group_by:["insn"]}`.

**Who executes this code.** `access:"execute"` on a code address (a debug register), or `trace_execution`.

**Struct layout.** `watch_memory {address:<struct_base>, size:512, method:"poll", view:"f32", interval_ms:16,
duration_ms:3000, wait_ms:4000}` while the user drives/plays. `PollSummary.fields[{offset, changes, min, max, first,
last}]` lists the offsets that change; confirm a field's meaning by correlating with what the user did.

## Safety

- A watch is an armed hardware or page trap in someone else's process. `stop_instrumentation` it when done; it is
  also disarmed at `close_session` and when BEA unloads its agent.
- On **attached** targets, close sessions before stopping BEA. If BEA dies abruptly, BEA leaves a small exception
  handler behind to absorb stray traps, but an armed trap in a target without it would crash the target.
- Calls made with `call_function` while a watch is armed work: BEA handles its own traps during the call.
- A page_guard watch on a page the program also guards (its own guard pages, stack probes) can interfere with the
  program; prefer debug registers on such ranges.
