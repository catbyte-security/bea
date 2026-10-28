# Address model

Every BEA address input is one string, an **AddrExpr**. It is accepted in every address field, including nested
ones (`map_address.addresses[]`, `trace_execution.on_call`, `call_function.thread_at`, `buffers[].init_from`,
`emu_open.capture_regions[].address`, patch and state-write addresses).

## Grammar

| Form              | Example                                         | Meaning                                                                            |
| ----------------- | ----------------------------------------------- | ---------------------------------------------------------------------------------- |
| Runtime VA        | `0x7ff6a1231760`                                | an address in the live process (or the emulator's address space)                   |
| Module + RVA      | `game.exe+0x1234ab`                             | `base(module) + rva` in the session's current module map                           |
| Main module + RVA | `+0x1760`                                       | the same, for the session's main image                                             |
| Export            | `kernel32.dll!Sleep`, `kernel32.dll!Sleep+0x10` | the export's address (forwarders followed), plus an optional displacement          |
| Ordinal           | `ws2_32.dll!#115`                               | export by ordinal                                                                  |
| **Static**        | `game.exe:0x1401234ab`                          | a Ghidra/REA VA: `base(module) + (va − preferred base read from the file on disk)` |
| Static with base  | `game.exe:0x1401234ab/0x140000000`              | the same with an explicit static image base (a rebased Ghidra program)             |
| Static on main    | `$main:0x140001760`                             | static VA in the session's main image                                              |

Rules:

- Hexadecimal always needs `0x`. A bare decimal number is rejected ("addresses are hexadecimal with a 0x prefix").
  Integer **offsets inside JSON arrays** (`deref`, `offset`, `size`) are plain JSON numbers: 452, not 0x1c4.
- Quote module names that contain `+`, `!`, `:` or spaces, and full paths: `"notepad++.exe"+0x1000`,
  `"My Game.exe":0x140001760`, `"C:\\Games\\x\\msvcp140.dll"+0x10`.
- Two loaded modules with the same basename: qualify with the runtime base, `msvcp140.dll@0x7ffa10000000+0x1234`, or
  quote the full path. `@` always means "this loaded copy"; `:` always means "static VA".
- A token without a dot also tries `.dll` and then `.exe` when exactly one module matches.
- User-mode only: VAs above `0x7fffffffffff` are rejected.

## Outputs

Single addresses come back as an `AddressRef` (VA, module, RVA, static VA, function bounds). Rows, frames and hits
use the compact form:

| Field    | Example                | Meaning                                                                                          |
| -------- | ---------------------- | ------------------------------------------------------------------------------------------------ |
| `va`     | `0x7ff6a1354b20`       | runtime VA                                                                                       |
| `at`     | `game.exe+0x1234ab`    | module + RVA; null for heap, stack and private memory                                            |
| `static` | `game.exe:0x1401234ab` | preferred base (from the file) + RVA; paste it back as input or into Ghidra                      |
| `func`   | `game.exe+0x123460`    | start of the enclosing `.pdata` function; null for leaf or hand-written code without unwind data |
| `sym`    | `physics_step+0x36`    | only when `func` is exactly an export; never a nearest-export guess                              |

Module identity (path, sha256, preferred and runtime base) appears once per result, in `modules[]`.

## Static vs runtime

ASLR loads the image at a different base each run. Ghidra and REA show the **preferred** base from the PE header
(usually `0x140000000` for an x64 EXE, `0x180000000` for a DLL) unless the program was rebased in Ghidra.

- Prefer the static form for anything that came from Ghidra/REA: `game.exe:0x1401234ab`. BEA does the arithmetic
  and records which base it used (`static_base_source: pe-header | caller`).
- If the Ghidra program was rebased (Memory Map → Set Image Base), pass that base: `game.exe:0x2401234ab/0x240000000`.
  A static VA outside `[base, base + SizeOfImage)` fails with `static_out_of_image`: check the base.
- Heap addresses have no static form (`at` and `static` are null). Use a pointer chain for anything that must survive
  a restart (see the memory reference).
- A module that loads later (a plugin DLL) gives `address_unmapped` with `reason:"module_not_loaded"`; retry once it
  appears in `list_modules`.

## Verifying a static address: `map_address`

```
map_address {addresses:["game.exe:0x1401234ab"], verify_bytes:16, expected_image_sha256:"<sha256 from REA>"}
```

Read each row:

- `status`: `mapped`, `non-image` (heap or private memory) or `error` (with `issue{code, message}`; one bad row
  does not fail the call).
- `image_check`: `match` when the running image's sha256 equals `expected_image_sha256`; `mismatch` means a
  different build — **stop** and tell the user.
- `verify.status`: live bytes vs the on-disk image at that address. `match` is the go signal. `mismatch` or
  `partial` lists `differences[{rva, size, class}]`: `foreign-or-agent-patch` (Frida's own patches in system DLLs,
  BEA hooks) is explained; `unexplained` means the code differs (packed, self-modifying, or another build).
  `not-applicable` for data sections; `own_effects_restored` counts BEA hooks it masked.
- `func{start, size, is_start}`: whether the address is the start of a `.pdata` function. Hook `func.start` for the
  function's arguments; use `hook_function {probe:true}` to observe one instruction mid-function.
- `modules[].runtime_matches_file`: false means the image in memory was modified after load.

A mismatch makes the result `confidence:"inferred"` and records an unknown automatically. Never hook or call on an
unverified address.

### Offline mapping

Without a session, `map_address {pe_path:"C:\\games\\game.exe", addresses:[…], runtime_base:"0x7ff6a1220000"}`
converts between static and runtime forms from the file alone, and `list_module_symbols {pe_path, kind:"exports"}`
reads exports, imports or `.pdata` functions. CLI: `bea map <addresses…> --pe-path PATH`.

### Registering names from Ghidra/REA

`map_address` accepts a caller symbol table: `symbols:[{static_va:"0x140123460", name:"VehiclePhysics::Step",
size:642}]`, `symbols_module:"game.exe"`, `symbols_source:"ghidra"`. Later results name those functions in `func`
rows. These names are caller-supplied: cite them as such, not as BEA observations. `external_ref:{system:"rea", id}`
links the mapping to a REA evidence id.

## Pitfalls

- Ghidra's default base for a DLL can differ from the PE header when it was imported with options; compare the image
  base in Ghidra's Memory Map with `modules[].preferred_base`.
- An address in the middle of an instruction disassembles to garbage and hooks crash the target: `disassemble
  {address, function:true}` shows the real instruction boundaries.
- `is_start:false` with a large function usually means the Ghidra address is inside a function body; Ghidra
  function starts and `.pdata` starts agree for normal compiler output.
- Packed or protected binaries: `verify` reports `unexplained` differences across `.text`. Dump the module after
  unpacking (`dump_memory`) and analyze the dump statically.
- Emulation sessions resolve against the emulated image: `$main` is the opened image, and `0x…` VAs are emulator
  addresses, not live ones.
