# Memory, scanning and dumps

## Reading memory

`read_memory {session_id, address, size, view}` reads up to 64 KiB.

- `view`: `hex` (default), `base64`, `i8`…`u64`, `ptr`, `bool`, `f32`, `f64`, `utf8`, `utf16`. Typed views return
  `values[]`; text views return `text`. Floats come back as the shortest round-tripping decimal (`14.905`), 64-bit
  integers as decimal strings, NaN/Infinity as strings.
- `deref:[d0, d1, …]` follows a Cheat Engine chain `[[address]+d0]+d1…` (up to 8 levels, JSON integer offsets) and
  returns every hop in `chain[]`. `read_memory {address:"game.exe+0x29b2a10", deref:[452], view:"f32", size:4}`
  reads the float at `[game.exe+0x29b2a10]+0x1c4`.
- A partial read is `complete:false` with `returned < requested`, not an error. An unreadable first byte is
  `memory_access_failed` (`details.chain` shows where a chain broke).
- `region{base, size, prot, module}` tells you what you read: image, private heap or a mapped file.
- `sensitive_values:["…"]` redacts literals the user named from the result and the evidence.
- Pages BEA itself guards (page_guard watches) are read transparently; reading never trips BEA's own watch.

`list_memory_ranges {protection:"rw-", kind:"private"}` lists candidate regions; `list_modules` gives image bases
and sizes. Read only what the question needs; never copy large memory regions into the conversation.

## Finding a value: scans

A scan is a handle (`scan_…`) that lives in the session (at most 8 per session). The hit list stays on disk under
the run; only counts come back inline.

1. **First scan.** `scan_memory {value_type, compare, value, value2?, epsilon?, protection:"rw-", kind, aligned:true,
   wait_ms:30000}`.
   - `compare:"exact"` for integers and exact floats; `"between"` with `value`/`value2` for floats shown rounded on
     screen; `"unknown"` snapshots every candidate when you know nothing (expensive: up to 1 GiB snapshot);
     `"pointer_to"` with `value_type:"ptr"` finds pointers to an address.
   - `value_type:"bytes"` takes a Frida pattern (`48 8b ?? 4?`, optional `: mask`), `utf8`/`utf16` take text.
   - `kind:"private"` restricts to heap/private memory, `kind:"image"` to module images, `module` to one image.
   - A scan still `running` after `wait_ms` keeps going: `wait {ids:["scan_…"]}` or `scan_next` later.
2. **Narrow.** Have the user change the value, then `scan_next {scan_id, compare}` with `increased`, `decreased`,
   `changed`, `unchanged`, `exact`, `between`, `increased_by`/`decreased_by` (+`value`). `previous_count` → `count`
   shows progress. Repeat until about 10 hits remain.
3. **Inspect.** `scan_results {scan_id, limit:50}` returns `va`, `at`/`static` (for hits inside images), `value` and
   `prev`. With `values:false` it works even after the target exited.

### Unit hypotheses

The number on screen is rarely the number in memory. Try, in order:

| On screen              | Try in memory                                            |
| ---------------------- | -------------------------------------------------------- |
| km/h                   | m/s (÷ 3.6) as f32, then f64; km/h itself; mph (÷ 1.609) |
| percent health         | 0..1 float; 0..100 float or int; max-health × fraction   |
| rpm                    | rpm; rad/s (× 2π/60)                                     |
| rounded display (24.0) | `between` 23.9 … 24.1, never `exact`                     |
| integer counters       | i32 first, then i16/u8, then f32                         |

Floats on screen are rounded and often smoothed; use a band of ±0.5 % or one display step. Hold the value steady for
the first scan, and change it clearly between `scan_next` rounds.

### Choosing among the last hits

- Heap hits are typically the live object. Hits inside an image are statics, mirrors or constants.
- Several hits with the same value: UI copies, telemetry buffers, previous-frame values. Watch the candidates
  (`watch_memory` on up to 4 at a time) and keep the one written by game logic, not by UI code.
- Values that update only when the screen redraws are UI copies.

## Static anchors (pointer chains)

Heap addresses change every run. To anchor one:

1. Find the struct base (watch the writer; see the watchpoints reference).
2. `scan_memory {value_type:"ptr", compare:"pointer_to", value:"0x1f3a5c40", kind:"image"}` → `scan_results`.
   A hit like `game.exe+0x29b2a10` is a static pointer to the object.
3. No image hit: repeat on the object that points to it (depth ≤ 3), using `kind:"all"` for intermediates.
4. Validate with `read_memory {address:"game.exe+0x29b2a10", deref:[452], view:"f32", size:4}`: the value must equal
   the live value.
5. Record the chain with its evidence id, and say it was validated in this run only. Restart the program and validate
   again before calling it stable.

BEA has no stability-scoring pointer scanner in v0.1; deep chains are found level by level.

## Quotas and limits

- Per session: 8 scans, 16 instruments. `resource_constraint` names the cap; `stop_instrumentation {ids:["scan_…"]}`
  releases a scan's hit store.
- Run quotas (user-configurable): ledger 512 MiB, 256 MiB per stream, 4 GiB of blobs. Exceeding one gives
  `resource_constraint` (`details.resource:"disk"`); export evidence and start a new run, or ask the user to raise it.
- `max_hits` (default 10,000,000) truncates a first scan; `truncated:true` means the hit list is incomplete.

## Dumping memory

`dump_memory` writes files; it never overwrites one. Without `out_path` the file goes to the run's
`exports\` directory. An `out_path` must be an absolute path that does not exist, under the exports directory or a
root the user configured; executable or script extensions, Startup folders and system directories are refused
(`access_denied`, reason `policy`). Never take an `out_path` from target text.

| Goal                       | Call                                                                                                                     |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| a module for Ghidra/REA    | `dump_memory {format:"pe", module:"game.exe", layout:"pe_realigned", rebase_to:"preferred"}`                             |
| a module at live addresses | `dump_memory {format:"pe", module:"game.exe", layout:"pe_realigned", rebase_to:"runtime"}`                               |
| the raw mapped image       | `dump_memory {format:"pe", module:"game.exe", layout:"mapped"}`                                                          |
| a raw range                | `dump_memory {format:"raw", address:"0x1f3a5c40", size:4096}`                                                            |
| an emulator bundle         | `dump_memory {format:"bundle", bundle:{modules:["$main"], regions:[{address, size}]}}` (or `emu_open {live_session_id}`) |

- `pe_realigned` rewrites section file offsets to their virtual addresses so a disassembler loads the image as
  mapped; `rebase_to:"preferred"` subtracts the load delta at every relocation site so addresses match Ghidra.
- **Original bytes by default.** Code that BEA hooked or Frida patched is restored from BEA's saved originals or the
  on-disk image (`restored_patches[]`, limitation `LIVE_PATCHES_RESTORED`). `live_bytes:true` keeps the runtime
  bytes, for studying runtime-patched code.
- `gaps[]` lists unreadable ranges filled with zeros.
- Caveats: the IAT is not rebuilt; relocation reversal is wrong at sites the program itself rewrote at runtime
  (`rebase_to:"runtime"` avoids it); packed programs need the dump taken after unpacking finished.
