# Oracles and emulation

Three tools share one **call model**: `call_function` runs a function inside the live process (an oracle),
`emu_call` runs it in Unicorn, and `diff_function` runs the same vectors on two or three legs and compares the bits.

## The call model

```
signature: {args:[slot…], returns, variadic:false}
buffers:   [{name, size, init_hex | init_fill | init_from, fields:[…], out:false, placement:"scratch"}]
inputs:    args (one call) | fields (one call, buffer fields) | vectors {columns} | generate {seed, columns}
```

**Slots** (`signature.args`, in Win64 position order): a scalar `{type:"f32", name:"dt"}` (types `i8`…`u64`, `ptr`,
`bool`, `f32`, `f64`), or a buffer `{type:"buffer_ptr", buffer:"car"}` (pointer to a buffer, optionally `offset`) or
`{type:"buffer_byval", buffer:"v"}`. `bool` is one byte (C/C++ `bool`); a Win32 `BOOL` is `i32`. A slot's column is
its `name`, otherwise `argN`.

**Returns**: `"void"`, a scalar type, or `{type:"struct", size, buffer?}` for a struct returned by value (the hidden
result pointer is handled for you). **Convention**: `signature.convention:"c"` (default: free functions, GCC/MinGW
methods) or `"msvc_method"` for an MSVC/clang-cl C++ instance method: `args[0]` is `this` (rcx) and every struct
result comes back through a hidden pointer in rdx, whatever its size.

**Buffers** are scratch memory BEA allocates per call:

- `init_hex:"…"` literal bytes, `init_fill:0` a fill byte, or `init_from:"0x1f3a5c40"` — **copy that many bytes from
  the live (or emulated) object once per call** and use the copy as the template for every vector. The game's own
  object is never passed, so the oracle cannot corrupt game state through it. In `diff_function` the copy is read
  once for all legs.
- `fields:[{name:"speed", offset:452, type:"f32"}]` names values inside a buffer; a field is a column
  `car.speed` you can vary per vector or read back. Arrays: `type:"f32[]", count:4` (cells are comma-separated
  strings). `ptr_to` fields point at another buffer (`buffer`, `plus`). `codec_kind`/`codec_key` (`xor`, `add`,
  `mul`) handle obfuscated stored values.
- `out:true` returns the buffer's bytes after the call (`out_buffers`) and its fields in `outputs`.

**Values**: a number, a decimal string, `true`/`false`, `"NaN"`, `"Infinity"`, `"-Infinity"`, `"-0"`, or `"0x…"`,
which is **always the raw bit pattern** of the declared type (`"0x7fc00000"` = f32 quiet NaN, `"0x3f800000"` = 1.0).
Use bits for exact replays of hook rows (`query_events {fields:["dt:bits"]}`).

**Batches**: `vectors:{columns:{dt:[0.016667, 0.008333, "0x7fc00000"], "car.speed":[0, 10, 100]}}` (equal-length
columns; at most 200,000 cells per request; `call_function` runs up to 1,000 vectors, emulation 10,000).
`generate:{seed, count, columns:{dt:{dist:"log_uniform", min:1e-4, max:0.1}}}` builds seeded vectors (`uniform`,
`log_uniform`, `grid`, `edge`, `bits_uniform`, `constant`). Large runs continue with `vector_offset` from the
result's `continuation`; long result tables become a row stream (`stream_id`) paged with `query_events {stream_id}`.

## `call_function` (live oracle)

```
call_function {session_id, address:"game.exe+0x123460",
  signature:{args:[{type:"buffer_ptr", buffer:"car"}, {type:"f32", name:"dt"}], returns:"f32"},
  buffers:[{name:"car", size:512, init_from:"0x1f3a5c40"}],
  vectors:{columns:{dt:[0.016667, 0.008333]}}}
```

- **Permission.** Allowed on BEA-spawned targets. Attached targets need the user's `call_attached` gate
  (`capability_unavailable` otherwise). Either way the call **executes target code** and taints the instance.
- **Which thread.** By default BEA's agent thread runs the call. A function that touches thread-local state, a
  render context or locks a game thread holds needs that thread:
  - `thread_at:"game.exe+0x…"` (recommended for game threads): BEA briefly hooks a function the thread runs every
    frame and runs each chunk on the first thread that arrives there, a safe point between frames;
  - `thread_id`: run on that thread directly. Refused while the target is paused, and `invalid_state` when the thread
    is inside a system call (a blocked thread would run the call only when it wakes).
- **FP environment.** `fp.source:"auto"` (default) uses the MXCSR/FPCW of a known thread (`fp.thread_id`, else the
  call's `thread_id`/`thread_at` thread); with no known thread it falls back to the Windows default
  (0x1F80/0x027F, limitation `CALL_FP_DEFAULT`). Games often run with FTZ/DAZ set: give `fp:{thread_id:<game
  thread>}` so denormal handling and rounding match the game. Results report `fp{mxcsr, fpcw, source}`.
- **Exceptions.** `callee_exceptions` counts exceptions the callee raised **and handled itself** (SEH, C++
  `try/catch`, probing APIs such as `IsBadReadPtr`): normal execution. `fault` is an exception **no** callee frame
  handled; BEA's frame catches it after unwinding and reports `{type, code, address, memory, insn}` per vector. A
  fault is a result, not an error, and the session continues. `exception_model:"steal"` (rare fallback) means callee
  handlers were not honored and faulting vectors are inconclusive.
- **Hooks on the path.** `hooks:"suppress"` (default) hides the call from your own hooks and profiles;
  `"observe"` records it (needs `thread_id` or `thread_at`). `overrides:"bypass"` (default) ignores active overrides.
- **Coverage.** `coverage:true` records the blocks each vector executed (`export_coverage {evidence_id}`).
- **Timeouts.** `timeout_ms` up to 110 s. A native call cannot be interrupted: after `provider_timeout` the session is
  marked unresponsive; close it (owned targets are killed). On an attached target BEA's agent and the still-running
  call then stay in the user's process until it exits: no `close_session`, not even `force:true`, removes them. Call
  only functions that terminate on their inputs.
- Results: `call{status, ret, outputs, out_buffers, fault, raw{rax, xmm0, mxcsr, fpcw}}` for one call;
  `batch{completed, by_status, columns{bits[], value[]}, faults, preview, stream_id, continuation}` for vectors. Every
  float has `bits`.

## Emulation

**Open a session** (exactly one source):

| Source         | Call                                                                                       | State of `.data`/heap                                         |
| -------------- | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------- |
| on-disk image  | `emu_open {image_path:"C:\\lab\\mathlib.dll"}`                                             | **file** values: no runtime initialization ran                |
| live process   | `emu_open {live_session_id, capture_modules:["$main"], capture_regions:[{address, size}]}` | a snapshot of the live process (original code bytes restored) |
| a saved bundle | `emu_open {dump_path}` (from `dump_memory {format:"bundle"}`)                              | the captured state                                            |

Include in `capture_regions` every object the function reads (the struct, globals it dereferences, lookup tables
outside the image). Reads outside captured memory fault (`fault_policy:"stop"`) or read zeros (`"map_zero"`, with a
deviation).

Options: `imports{unhandled:"stop"|"return_zero", overrides:[{import:"kernel32.dll!QueryPerformanceCounter",
action:"return", returns_type:"i64", returns_value:0}]}` for imports the emulator does not model; `patches` to change
code or data before calls; `memory{heap_mb, scratch_mb, stack_kb}`; `isa_guard:"stop"` (default) stops at the first
AVX/AVX-512 instruction instead of mis-executing it; `fp` (dump sessions default to the captured thread's MXCSR/FPCW).

**Call**: `emu_call {session_id, address, signature, buffers, vectors|args|generate, isolation:"snapshot"}`.
Each vector starts from the baseline snapshot unless `isolation:"chain"` (with `state.from:"current"`) carries state
forward; `state.save_as` names a snapshot. `budget.max_instructions` (default 1,000,000) bounds runaway loops;
`trace{blocks, coverage, imports, memory}` records what ran. Statuses are results, not errors: `returned`, `fault`,
`cpu_exception`, `invalid_instruction`, `unsupported_instruction` (AVX/FMA under the ISA guard),
`unhandled_import`, `syscall`, `raised`, `terminated`, `budget_exhausted`, `timeout`.

Emulated values have authority `emulation`. Say "the emulator returns X for these inputs", never "the game does X".
Emulator deviations (x87 transcendental precision, approximate SSE `rcpss`/`rsqrtss`/`dpps`/`dppd` results, inexact
math models, `cpuid`, zero-mapped pages, a full emulated heap) are listed in the result and must be carried into
conclusions. `heap`-placement buffers stay allocated in the session state, so a `chain` batch holds one per vector.

## `diff_function`

```
diff_function {live_session_id, emu_session_id, address:"game.exe+0x123460", signature, buffers, vectors}
```

- Legs: `live` (needs `live_session_id`; gate rules as `call_function`), `emulation` (`emu_session_id`), `expected`
  (`expected:{columns:{ret:[…]}}` or `from_recording.ret`). At least two. The FP environment is resolved **once** and
  used by every executing leg.
- Inputs: exactly one of `vectors`, `generate`, or `from_recording:{recording_id, args:[capture names in slot
  order], ret:"ret"}` (replays what a `hook_function` recording saw; its `ret` becomes the expected leg).
  `from_recording` needs a **scalar-only** signature: a recording cannot reproduce pointed-to memory, so any
  `buffer_ptr` / `buffer_byval` slot is `invalid_request`. A `ptr` slot replays the recorded address itself, which
  only means something on a dump-backed session, and then against the struct as captured at `emu_open` (each
  recorded return saw the struct of its own call). For pointer functions give `vectors` with `buffers` instead.
- Use `module+0xRVA` or `module:0xVA` for `address`: it resolves per leg. The live module and the emulated image must
  be the same binary (sha256) unless you pass `allow_image_mismatch` and say so.
- Comparison is **bit-exact** by default (`nan:"bits"`); `compare{tolerance_ulp, tolerance_abs, tolerance_rel,
  nan:"any_nan"}` relaxes it — report any tolerance you used.

**Verdicts** (report exactly):

- `equivalent-on-tested-inputs` — every compared output matched on every tested vector. Only for those vectors.
- `differ` — at least one vector differs: show `worst[]` (vector, column, both values, ulp distance) and `hints`.
- `unknown` — inconclusive: an emulator status (unsupported instruction, unhandled import), a deadline
  (`continuation`), or a fault the live leg could not attribute. Not a pass.

Hints point at the usual causes: `x87_inexact`, `hle_math_model`, `cpuid_dispatch`, `fp_status_read`,
`file_image_state` (use a live or dump-backed session), `possible_state_carryover`, `last_ulp_only` (FMA vs
mul+add), `nan_payload_only`, `signed_zero_only`. A non-equivalent verdict records an unknown automatically
(`unknown_id`).

## Pitfalls

- Image-backed sessions see initial `.data` values, not the runtime ones: a function reading globals differs from
  the live leg for that reason alone (`file_image_state`). Use `live_session_id`.
- Raw `0x…` pointers in vectors point into one address space only; pass objects as buffers instead.
- A function that depends on time, randomness, threads or I/O is not a pure function: the oracle and the emulator
  will differ for reasons unrelated to the math.
- `call_function` on a function that never returns wedges BEA's agent. An owned target is killed when you close the
  session; on an attached target `frida-agent.dll` and the spinning call stay in the user's process until it exits,
  and you must tell the user so. Prefer functions whose termination you established statically, and an owned target
  for anything uncertain.
