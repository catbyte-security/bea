# Hooks and API profiles

## Win64 argument slots

BEA reads arguments by **position** under the Microsoft x64 calling convention:

| Position | Integer / pointer | float / double | At function entry          |
| -------- | ----------------- | -------------- | -------------------------- |
| 0        | `rcx`             | `xmm0`         |                            |
| 1        | `rdx`             | `xmm1`         |                            |
| 2        | `r8`              | `xmm2`         |                            |
| 3        | `r9`              | `xmm3`         |                            |
| 4+       | stack             | stack          | `[rsp + 0x28 + 8·(n − 4)]` |

- Position counts every parameter, integer or float: in `f(Car* car, float dt)` `dt` is position 1 and lives in
  `xmm1`, not `xmm0`.
- C++ member functions pass `this` at position 0. A function returning a large struct by value takes a hidden
  result pointer at position 0 and shifts everything right.
- Structs larger than 8 bytes are passed by pointer. Returns: integers/pointers in `rax`, floats in `xmm0`.
- Varargs functions duplicate floats into integer registers; read them as `f64` by position.

## `hook_function`

```
hook_function {session_id, address, capture:[…], returns, caller:true, backtrace:0, duration_ms, max_events, wait_ms}
```

A capture is `{name, arg | reg, type, deref?, count?, when}`:

| Want                   | Capture                                                                             |
| ---------------------- | ----------------------------------------------------------------------------------- |
| a pointer argument     | `{name:"car", arg:0, type:"ptr"}`                                                   |
| a float argument       | `{name:"dt", arg:1, type:"f32"}` (the XMM slot of position 1)                       |
| a struct field         | `{name:"speed", arg:0, type:"f32", deref:[452]}` (reads `[rcx]+452`)                |
| an in/out field        | `{…, when:"both"}` (fields `speed` and `speed@leave`)                               |
| a field after the call | `{…, when:"leave"}`                                                                 |
| a register             | `{name:"rbx", reg:"rbx", type:"ptr"}`, `{name:"x", reg:"xmm6", type:"f32"}`         |
| a string or buffer     | `{name:"path", arg:0, type:"utf16"}`, `{name:"buf", arg:1, type:"bytes", count:64}` |

`deref` on an `arg` reads the **integer** register or stack slot as a pointer first. An `f32`/`f64` `arg` without
`deref` reads the XMM register. `returns` (`f32`, `i32`, `ptr`, …) adds the `ret` field.

Other options:

- `caller:true` records the return address (`caller` as `module+0xRVA`); `backtrace:N` up to 32 frames (costly).
- `thread_id` restricts to one thread; `sample_every:N` records every Nth call of a hot function.
- `engine:"native"` uses a C-level recorder for very hot functions (register and XMM captures only, no deref or
  strings).
- `probe:true` observes one instruction, not a function: no args, no `when:"leave"`, no `returns`. Capture registers.

Read the result:

- `summary` (when finished): `calls`, `recorded`, `read_failures`, `threads`, top `callers`, `duration_us`
  percentiles, per-field stats (`min`, `max`, `distinct`, `top` values), `returns` stats.
- `bytes_match_file:false` means the hooked bytes differ from the file: say so.
- `relocation:"forced"`: a tiny function was relocated more aggressively; watch for instability.

Then `query_events {recording_id, view:"group", group_by:["dt","ret"]}` for distinct pairs, `view:"stats"` for
numeric summaries, `view:"rows", fields:["dt:bits","ret:bits"]` for exact float bits to replay as vectors. Event
fields: `seq, t_ms, tid, depth, caller, dur_us, bt, <name>, <name>@leave, ret`.

`instrumentation_failed` carries `details.alternatives`: watch the address with `watch_memory {access:"execute"}`,
`trace_execution {on_call}`, or hook the caller. Some system functions BEA itself depends on are on a hook-deny
list.

### Pitfalls

- A Ghidra address inside a function (`map_address` `is_start:false`): hooking it as a function reads garbage
  arguments. Hook `func.start`, or `probe:true`.
- Hot functions (per-frame physics, allocators): set `max_events` and `sample_every`; `dropped > 0` makes coverage
  `partial`.
- Hooks change timing slightly. A race that disappears under a hook is evidence of a race, not of its absence.
- Several instruments may share an address (an API profile and your hook); BEA dispatches one listener to all.

## `trace_api`: behavior profiles

```
trace_api {session_id, profiles:["file","registry","network","process","module_load","memory_protection"],
           include_failed:true, caller:true, duration_ms:30000}
```

Install profiles on a **paused** spawned target, then `resume_process`: the duration clock starts at resume and
startup activity is captured. `hooks_pending` counts APIs in modules not loaded yet (hooked when they load);
`hooks_failed` lists what could not be hooked.

| Profile             | Layer                                                                               | Ops                                                                                |
| ------------------- | ----------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `file`              | `ntdll!Nt*File` (all Win32/CRT file APIs funnel here)                               | create, open, overwrite, read, write, rename, delete, truncate, stat, list         |
| `registry`          | `ntdll!Nt*Key`                                                                      | create, open, query_value, set_value, delete_key, delete_value, enum               |
| `network`           | `ws2_32`, `dnsapi`, `winhttp`, `wininet` exports                                    | socket, connect, bind, listen, accept, send, recv, dns, http_connect, http_request |
| `process`           | `kernelbase!CreateProcessInternalW`, `ntdll` process/thread APIs, `ShellExecuteExW` | spawn, shell_execute, open_process, terminate, create_thread, write_process_memory |
| `module_load`       | module observer, `LdrLoadDll`, `GetProcAddress`                                     | loaded, unloaded, load_request, resolve                                            |
| `memory_protection` | `NtProtectVirtualMemory`, `NtAllocateVirtualMemory`, `NtMapViewOfSection`           | protect, alloc, map_view (flags `wx`, `x_added`, `remote`)                         |

Normalization: NT paths become drive paths (`\Device\HarddiskVolume3\…` → `C:\…`), pipes/console/devices get a
`kind`, registry roots become `HKLM\`, `HKCU\`, `HKU\`. Registry value data is `{type, size}` plus a short preview;
URL query strings are stripped; credentials are never read.

The summary lists up to 50 rows per category with totals: files (ops, ok/failed, bytes), registry keys (values),
endpoints (sent/received, host from DNS), DNS names, HTTP requests, process operations (image, command line, pid),
loaded and failed modules, resolved imports, and executable or RWX memory transitions.

Details: `query_events {recording_id, view:"rows", where:[{field:"profile", op:"eq", value:"file"},
{field:"ok", op:"eq", value:false}]}`. Event fields: `profile, op, api, target, kind, status, ok, bytes, handle,
caller, detail`.

### What profiles do not see (always in `limitations`)

- **Direct system calls** that bypass ntdll.
- **Brokered actions**: COM, RPC, WMI, services and the shell do the work in other processes.
- **Child processes** are recorded when created (and killed with the job) but not instrumented.
- **Handles opened before tracing** appear as `<handle 0x…>` without names (common on attached targets).
- **Payloads**: byte counts only, never file, registry or network contents.
- **Late modules**: APIs in modules loaded during the trace are hooked on load; calls during that load can be missed.

Also not covered: `ConnectEx`/`AcceptEx` through `WSAIoctl` pointers, raw AFD ioctls, QUIC and custom network
stacks. Failed probes (`stat` of a missing file, `load_request` with `STATUS_DLL_NOT_FOUND`) are normal search
behavior, not errors; they are also how DLL-search-order candidates show up.

Report per category, quote the limitations, and never conclude "it does not use the network" from an empty network
list: say "no Winsock/WinHTTP/WinINet activity was observed in this window".
