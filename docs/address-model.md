# Address model

Written by WP5-ADDR. DESIGN §5.5 (with annex S2 §16–§19 and S6 §2.1–§2.2) is the authoritative design; this page
describes what the code in `src/domain/address/`, `src/application/address/` and `src/providers/pe/` does.

Every BEA tool that takes an address takes **one string**, an `AddrExpr`. Every tool that returns one address returns an
`AddressRef`; rows, frames and summaries return the compact `Addr`/`Loc` forms. Two tools belong to this area:
`map_address` and `list_module_symbols`.

## AddrExpr: the input grammar

```
expr      := va | modrva | mainrva | export | ordinal | static
va        := "0x" HEX{1,16}                          ; ≤ 0x7fffffffffff (user mode), else out_of_range
modrva    := module "+0x" HEX{1,8}
mainrva   := "+0x" HEX{1,8}                          ; the main module
export    := module "!" name ["+0x" HEX{1,8}]
ordinal   := module "!#" DEC{1,5} ["+0x" HEX{1,8}]   ; ordinal ≤ 65535
static    := module ":0x" HEX{1,16} ["/0x" HEX{1,16}] ; Ghidra/REA static VA [/ explicit static image base]
module    := '"' JSON-string '"' ["@0x" HEX] | bare ["@0x" HEX] | "$main"
bare      := 1*(any char except whitespace, '"', '+', '!', ':')
```

| Example                                  | Meaning                                                                       |
| ---------------------------------------- | ----------------------------------------------------------------------------- |
| `0x7ff7a8a11760`                         | a runtime VA                                                                  |
| `game.exe+0x1760`, `+0x1760`             | module-relative; `+0x…` is the main module                                    |
| `kernel32.dll!Sleep+0x10`, `ws2_32!#115` | an export (forwarders followed) or an ordinal, with a displacement            |
| `game.exe:0x140001760`                   | a static VA; the static base is the PE preferred base read **from disk**      |
| `game.exe:0x150001760/0x150000000`       | a static VA in an image rebased to an explicit base (Ghidra "Set Image Base") |
| `$main:0x140001760`                      | the static form on the main module                                            |
| `"notepad++.exe"+0x10`                   | quoting: a name with `+`, `!`, `:`, spaces or quotes; a full path             |
| `msvcp140.dll@0x7ffa10000000+0x1234`     | `@0x<runtime base>` picks one of several modules with the same basename       |

- A name without a dot also matches `<name>.dll`, then `<name>.exe` (`kernel32+0x10`). Names match case-insensitively on
  Windows; a quoted token containing `\` or `/` is a path and matches by path key.
- Decimal input (`1234`) is rejected with the hint that addresses are hexadecimal.
- `@` belongs to the name unless `@0x<hex>` ends a bare token, so `a@b.dll` is a name.
- The parser is `parseAddrExpr` (`src/domain/address/grammar.ts`); `formatAddrExpr` writes the canonical text, and
  `parse(format(p)) == p` is a property test. The compact `at`/`static` texts are themselves AddrExprs, so an agent can
  paste any output address back as input.

## Resolution

`AddressService.resolve(space, expr, op)` resolves against one **address space**:

| Space       | Module table                                                                                        | `$main`                   |
| ----------- | --------------------------------------------------------------------------------------------------- | ------------------------- |
| `live`      | the host module map (`EvidenceRuntime.modules`), else an agent `listModules` snapshot               | the identity's image path |
| `emulation` | the emulated images, through the late-bound `EmuPort` (`lookup` + `modules`; never at construction) | the opened image          |
| `file`      | one PE file (`pe_path`); its base is `runtime_base`, else the PE preferred base                     | the file                  |

Steps (S2 §16.3): select the module; find the rva (given; export through the on-disk PE with up to 4 forwarder hops;
API-set forwarders through the agent's `resolveTargets`; static `rva = static_va − static_base`); check
`0 ≤ rva < SizeOfImage`; `va = base + rva`; hash the module file (`FileHashCache`); symbolize.

When a module token matches nothing in a live space, BEA refreshes the map once with `listModules` before failing (the
module may have loaded since the last module event).

### Errors (S2 §16.2)

| Situation                                                                                         | Error                                                                                                                                                               |
| ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| syntax, VA above user mode, rva > 32 bits                                                         | `invalid_request` (`invalid_format` / `out_of_range`) at the input path                                                                                             |
| module not loaded                                                                                 | `address_unmapped`, `details.diagnostics{reason:"module_not_loaded", token, suggestions}`, recovery `refresh_module_map`                                            |
| basename matches several modules                                                                  | `invalid_request`, `diagnostics{reason:"module_ambiguous", candidates[{name, path, base}]}`                                                                         |
| export missing                                                                                    | `invalid_request`, `diagnostics{reason:"export_not_found", module, export, similar[≤5]}`                                                                            |
| forwarder target not loaded / API set unresolved                                                  | `address_unmapped`, `diagnostics{reason:"forwarder_unresolved", forwarder}`                                                                                         |
| rva ≥ SizeOfImage                                                                                 | `invalid_request` (`out_of_range`), `diagnostics{reason:"rva_out_of_image", size_of_image}`                                                                         |
| static VA outside the image for its base                                                          | `invalid_request` (`out_of_range`), `diagnostics{reason:"static_out_of_image", static_base, size_of_image}`                                                         |
| module form with `pe_path` naming another module; runtime VA with `pe_path` but no `runtime_base` | `invalid_request`, `diagnostics{reason:"no_module_map"}`                                                                                                            |
| the module's file cannot be read                                                                  | `file_operation_failed` / `unsupported_target` (PE32 is always `unsupported_target{wow64}`)                                                                         |
| `expectedImageSha256` given and the digest differs                                                | `invalid_request`, `diagnostics{reason:"image_mismatch", expected, actual}` (single-address `resolve` only; `map_address` reports `image_check:"mismatch"` instead) |

A VA outside every module is **not** an error for resolution: the AddressRef has `module:null` and the caller decides.

## Outputs

- **AddressRef** (single-address results): `va, module, rva, static_va, static_base, static_base_source
  (pe-header | caller | rea-evidence | emulation), module_map_id, image_sha256, symbol?, section?`.
- **Addr** `{va, at, static}` and **Loc** `{va, at, static, func, sym}` for rows: `at` = `name+0xrva` (with
  `@0xbase` when the basename is ambiguous), `static` = `name:0x<preferred base + rva>`, `func` = the start of the
  enclosing `.pdata` function, `sym` = a name **only** when it is an export (or a caller-table name) at the address or at
  its function start — never the nearest preceding export.
- `describe()` is synchronous. It knows the preferred base of a module only after `prepare(space, vas, op)` read it from
  disk; an unprepared module yields `static:null` (CI-I10). `describeCode()` and `fromFrameRef()` are asynchronous and
  prepare what they need.

## Byte verification (S2 §18.3)

`verify(space, va, len, op)` (and every `map_address` row with `verify_bytes > 0` in a live session):

1. Writable sections (`.data`, `.bss`, …) are `not-applicable`: they change at run time.
2. Live bytes are read through the agent (`readMemory`; an unreadable tail is excluded and makes the result `partial`).
3. BEA's own patches are undone first: `EffectRegistry.originalBytes` is overlaid (`own_effects_restored`).
4. The expected bytes are the file bytes with DIR64 base relocations applied for the runtime base (`imageBytes`).
5. Loader-written bytes are masked: IAT and delay-IAT slots, `fothk` forwarder thunks, the CFG pointer slots, and the
   header ImageBase field; zero-fill (no file backing) is masked too (`excluded_loader`).
6. Differences closer than 4 bytes coalesce into ranges (at most 8 are reported). A range inside the module's
   **footprint** — the code sections compared with the file once per module and instance (FootprintScanner) — is
   `foreign-or-agent-patch` (the injected Frida agent patches `ntdll!LdrLoadDll` and a few others; a scan cannot tell
   that from other in-process hooks); anything else is `unexplained`, which makes the record `inferred`, adds
   `BYTES_MISMATCH` and an auto-unknown.

Status: `match`, `mismatch`, `partial` (unreadable bytes), `not-applicable`, or `skipped` (nothing compared, e.g. every
byte of the window was loader-written, or the space is not live).

## Symbolization (S2 §19)

First hit wins: the **caller table** (names registered through `map_address.symbols`, per image sha256, cited by their
`bea.symbols.caller` evidence id) > an exact or function-start **export** (data exports only exactly) > an **import
slot** (`DLL!name`) > the bare **`.pdata`** function (`name:null`, start/end, `fragment` for chained parts). BEA never
invents `sub_XXXX` names and never uses DebugSymbol by default.

## The PE reader (`src/providers/pe/`)

- Positioned reads on short-lived handles; headers, sections (gcc long names through the COFF string table), CodeView and
  TLS callbacks at open; exports (forwarders, NONAME ordinals, aliases), imports and delay imports with IAT slot rvas,
  `.pdata` with unwind chains and indirect entries (≤ 32 hops), DIR64 relocations, load-config CFG slots lazily.
- Malformed tables never fail the image: the table is empty and `issues` gets an entry (coverage `partial`,
  `malformed_pe_directory` / `pe_table_cap`). Only an invalid header is an error. A fuzz test truncates and corrupts
  images and requires no throw and no hang.
- Equal to pefile on every fixture and on six system DLLs (`tests/unit/pe/peReader.test.ts`; a named skip
  `PEFILE_SKIP` when `python -I -c "import pefile"` fails).
- `PeImageCache` is an LRU (64) keyed by FileKey `(path_key, size, mtime_ns, ctime_ns, ino, dev)`: a rewritten file is
  re-parsed, and a read through a stale image fails with "changed on disk".
- `FileHashCache` persists sha256 digests in `BEA_HOME/cache/file-sha256.jsonl` (append-only, last line wins, corrupt
  lines ignored, compacted at twice the unique keys). Nothing is read or written until the first hash is requested.

## map_address

Input: `session_id` **or** `pe_path` (+ `runtime_base`), `addresses[1..64]`, `verify_bytes 0..64 = 16`,
`expected_image_sha256?`, caller `symbols[≤4096]` (`rva` or `static_va`, `name`, `size?`) with `symbols_module`
(default `$main`) and `symbols_source`, `external_ref?` (its `image_sha256` counts as the expected digest, its
`image_base` is the static base of static forms without `/0x…`), `sensitive_values?`.

- A grammar error in any element fails the call, listing every bad index. A row that does not resolve is a row with
  `status:"error"` and `issue{code, message}`; coverage becomes `partial` (`entry_errors`).
- Rows report `address` (AddressRef), `func{start, size, name, is_start}`, `region` (`module:.section`, `private` or
  `unmapped` for non-image live addresses), `image_check`, `verify`. `modules[]` gives each module once, with
  `runtime_matches_file` from the verified rows.
- Recorded as `bea.address.map`: confidence `derived` (`inferred` on a digest mismatch or unexplained bytes), anchored
  only when bytes were read. A derived record links what it was computed from (S2 invariant 6), and its authority is
  the weakest of those parents (S2 §7.4): in a live session the module map (`live-process`); for `pe_path` and in an
  emulation session the `bea.image.pe` summary of each image the rows resolved into (else the space's main image), so
  `static-artifact`; plus any caller table used (`imported` or `analyst-inference`). The record keeps each difference's
  `live_hex`/`expected_hex`; the inline result does not.
- `bea.image.pe` is BEA's own reading of an on-disk image (observed, `static-artifact`, unanchored, so one record per
  image digest): name, format, machine, preferred base, sizes, entry point, timestamp, subsystem, DLL characteristics,
  up to 96 sections and the CodeView GUID/age; never a file path.

Without `runtime_base`, offline mode maps to the PE preferred base and says so (`PREFERRED_BASE_ASSUMED`).

## list_module_symbols

`kind: exports | imports | functions`, `filter` (case-insensitive substring; imports match `DLL!name`), paged
(`offset`, `limit ≤ 1000`, `page{total, next_offset}`). Live and emulation rows carry runtime VAs; live imports also
read their IAT slots and report what each resolves to as a `Loc`. Row strings are capped so a 1000-row page stays within
the 2 MiB envelope bound (export names 768, import names 400, `resolved` texts 180/256; a `resolved` text that would not
fit is `null`, never cut). Recorded as `bea.symbols.module` (`observed` for a file; `derived` for a session module,
linked to the live module map or to the emulated image's `bea.image.pe` summary).

## Design notes and conservative choices

- `list_module_symbols` export rows add `ordinal` (needed to address NONAME exports as `module!#ord`).
- An emulation `map_address` records an `image` subject (the opened image's digest), never verifies bytes, and adds
  `EMULATED_IMAGE_SPACE`; its authority is `static-artifact` (the image summary it derives from). When no module image
  of the space can be read from disk, the call fails with `capability_unavailable` (`module-file-unknown`): there is
  nothing observed to derive the map from.
- `fromFrameRef()` of a module that is no longer loaded returns `va:"0x0"` with the original text in `at`.
- The FootprintScanner reads code sections in 512 KiB agent reads; a failed scan is not cached and its differences stay
  `unexplained` (`FOOTPRINT_UNAVAILABLE`).
