# BEA research: backends beyond Frida (`ext-backends`)

Date: 2026-10-28. Host: Windows 11 Pro 10.0.26200 x64, Ryzen 7 7800X3D, 32 GB.
Lab (all experiments, scripts, fixtures, outputs):
`<scratch>/bea-lab/ext-backends/`
(abbreviated `LAB/` below).

Legend: **[V]** = VERIFIED on this host (ran it, or read the code). **[V-doc]** = read today from an
official page or package metadata, not executed. **[B]** = BELIEVED (memory, secondary sources, or inference).

---

## 0. TL;DR

**Recommended backend set for BEA v0.1**
1. **Frida** (other research tracks): live instrumentation in the target process.
2. **Unicorn 2.1.4 behind a Python stdio JSON-lines bridge** (`bea-emu/0.1`): the emulation backend for
   function oracles, differential testing, and batch evaluation of many input vectors. A working prototype
   is at `LAB/bea_emu_bridge.py`: about 1,900 lines, PE64/Win64, with HLE imports, snapshots, batching, tracing,
   cancellation, and an ISA guard. It passes my probe suite and a Node.js end-to-end client.
3. Design it in from day one, even if the code ships in v0.1.x: **dump-backed emulation sessions**. Frida captures
   module and heap memory plus a thread context, and Unicorn emulates a function against that *real runtime state*.
   For the user's game-RE workflow this is the high-value combination.

**Defer** to v0.2+ as optional providers: speakeasy 2.0 (whole-module and API-heavy emulation), a GDB/MI or
DAP provider (Windows fallback for hardware watchpoints; Linux), cdb/DbgEng (minidump triage), TTD
(record via standalone `TTD.exe`, replay via cdb `dx` or the Replay API), x64dbg-automate interop, and LLDB for macOS.
**Avoid**: Qiling (GPLv2, needs a rootfs of real Windows DLLs, no PyPI release since 2023), in-box `tttracer.exe`
(its license text forbids automation), speakeasy 1.5.x (pins unicorn 1.0.2, broken on Python ≥3.12).

**Unicorn gotchas that must shape BEA's design (all [V] on unicorn 2.1.4 / Python 3.14.6):**
1. **Reset FP environment is wrong for Windows.** Unicorn starts with `FPCW=0x0000` (24-bit x87 precision,
   exceptions unmasked) and `MXCSR=0x0000`. Windows x64 threads start with `FPCW=0x027F` and `MXCSR=0x1F80`
   (native read: `0x27f`/`0x1fa0`). Uncorrected, x87 `sqrt`/`exp`/`pow` were wrong in 1500/1500 cases.
2. **VEX instructions are silently mis-executed.** `vaddss xmm0,xmm1,xmm2` runs as legacy `addss xmm0,xmm2`
   (gives 102 instead of 3). VEX.128 doesn't zero the upper YMM lanes, and `vzeroupper` is a no-op. VEX.256 and
   FMA are rejected with `UC_ERR_INSN_INVALID`. CPUID reports AVX=0/FMA=0/AVX2=0 for every CPU model. BMI1/BMI2
   (VEX-encoded GPR ops) execute correctly. → BEA needs a pre-scan **ISA guard** (implemented).
3. **x87 transcendentals are approximate**, even with the correct FPCW: `sin` of large arguments is off by up to
   19,737 ulp and `pow` by up to 88 ulp. SSE arithmetic, `fsqrt`, `fprem`, and f32-rounded results were exact in
   my tests. → results that execute those instructions get tagged as an inexact deviation (implemented).
4. **Code and block hooks don't reach already-translated blocks.** A `UC_HOOK_CODE` or `UC_HOOK_BLOCK` added after
   a block was translated fired **0 times**. It needs `ctl_flush_tb()`, after which it fired 99,360 of 99,360 times.
   A deleted hook keeps costing time until re-translation.
5. **The `emu_start(count=N)` budget isn't enforced on cached blocks** that were translated during a `count=0`
   run (an infinite loop ran until my 2 s safety stop). Fix: flush the TB cache whenever the budget mode changes
   (0.54 ms).
6. **`emu_start(timeout=…)` costs ~15 ms per call on Windows** (66 calls/s). Use a host-side polling watchdog
   plus `emu_stop()` instead (33 µs stop latency).
7. **CPU+memory snapshots (`UC_CTL_CONTEXT_MEMORY`) require a frozen memory layout.** Calling `mem_map` or
   `mem_unmap` after `context_save()` and then restoring corrupts the region list, and the next `mem_write`
   causes a native access violation in `unicorn.dll`. CPU-only contexts are fine.
8. Smaller items: `pefile.get_memory_mapped_image()` silently drops sections past 256 MiB RVA by default, and
   after `relocate_image()` it returns `bytearray`, which `uc.mem_write` rejects. The capstone 5.0.9 wheel reports
   `__version__ == "5.0.7"`. `importlib.metadata` lookups cost about 1 ms, so cache them: uncached, they cut bridge
   throughput to 719 calls/s.

**Headline performance** ([V], ±30% run-to-run on this machine):
- JIT speed: about 186–203 M guest instructions/s with no hooks; about 65 M/s with a consistent `count` budget.
- A 10-instruction function called from Python: 5–17 µs per call. Through the library API: 26–30 k calls/s.
- Batches through the stdio bridge (Node client, end to end): **35.8–38.7 k calls/s** with chained state,
  **16.3–18.2 k calls/s** when every vector starts from a restored snapshot. Single requests: 4.6–5.4 k calls/s
  sequential, 13–15 k calls/s pipelined.
- Python hook callbacks cost about 0.36 µs each: a code hook gives ~2.7 M insn/s, a block hook ~15 M insn/s.
- speakeasy 2.0 `call()`: about 14 calls/s.

---

## 1. Environment and lab inventory

| Component | Version / location | Status |
|---|---|---|
| Python (global, used read-only with `python -I`) | 3.14.6 (`%LOCALAPPDATA%\Python\pythoncore-3.14-64`) | [V] |
| unicorn (global) | dist 2.1.4, core 2.1 (`unicorn.uc_version()` → `(2, 1, 33621247)`); bundled `unicorn/lib/unicorn.dll` 9.6 MB | [V] |
| capstone (global) | dist **5.0.9**, but `capstone.__version__ == "5.0.7"`, `cs_version()==(5,0,1280)` | [V] |
| pefile (global) | 2024.8.26 | [V] |
| uv | 0.13.1. Managed CPython 3.13.15 at `%APPDATA%\uv\python\cpython-3.13.15-windows-x86_64-none` | [V] |
| gcc | WinLibs **GCC 16.1.0** `x86_64-msvcrt-posix-seh` (MinGW-w64, msvcrt.dll CRT, winpthreads) | [V] |
| gdb | WinLibs **GDB 17.2** (embedded Python 3.9.7) + `gdbserver.exe` on PATH | [V] |
| MSVC | VS 18 Community, toolset 14.51.36231: `cl/link/lib/dumpbin.exe` present, **no `lib\`/`include\` dirs and no Windows SDK** (`C:\Program Files (x86)\Windows Kits\10` absent) → cannot build CRT-linked MSVC binaries | [V] |
| Node | 24.18.0 | [V] |
| Debuggers | no cdb/WinDbg/x64dbg/LLDB installed. In-box: `System32\dbgeng.dll` 10.0.26100.1, `dbghelp.dll` 10.0.26100.9549, `dbgcore.dll`; **no `symsrv.dll`**; in-box TTD recorder `tttracer.exe` 1.11.580.0 + `ttdrecord.dll`, `TTDRecordCPU.dll`, `ttdloader.dll`, `ttdinject.exe` | [V] |

Lab files (`LAB/`):

| File | Purpose |
|---|---|
| `fixture.c` → `bea_fixture.dll` | 14 generic exported test functions (see §2.1). Built `gcc -O2 -shared -static -fno-builtin-sqrtf -fno-builtin-memcpy`. sha256 `1d9ebd73…79dc`, ImageBase `0x2ac880000` |
| `libm_fixture.c` → `bea_libm.dll` | wrappers over MinGW's statically linked libm (x87-heavy) plus `get_fpcw`/`get_mxcsr` |
| `tls_native.c` → `bea_tls_native.dll` | hand-written MSVC-style static TLS access (`gs:[0x58]` → `[_tls_index]`), `-fstack-protector-all`, 20 KB frame (`___chkstk_ms`) |
| **`bea_emu_bridge.py`** | **prototype bridge** (library `EmuSession` + stdio server `Server`), sha256 `aada9704847a743837ebb1136f2d48575824c611f2b30be6e71c857a7ae7c719` (final version used for all reported runs) |
| `probe.py` / `probe_out.txt` | per-function emulation vs native (ctypes) comparison, plus gotcha probes |
| `x87diff.py` | differential test of x87 libm: native vs emulated, ulp distances |
| `bench.py` / `bench_out.txt` | in-process throughput measurements |
| `bridge_client.mjs` / `client_out.txt` | Node 24 end-to-end protocol client: errors, call, fault, sequential and pipelined, batches, coverage, cancel, progress, shutdown |
| `transcript.jsonl` | real protocol frames (used in §9.12) |
| `snapmap_case.py` | minimal repro of the snapshot plus `mem_map`/`mem_unmap` corruption |
| `speakeasy-run/se_eval.py` | speakeasy 2.0.0b9 evaluation script (run in an isolated uv env with cache in `LAB/uv-cache`) |
| `gdbtest/watch_target.c`, `gdbtest/watch.py` | GDB 17.2 hardware-watchpoint automation via the GDB Python API |

---

## 2. Unicorn hands-on evaluation

### 2.1 Fixture (`LAB/fixture.c`)

| Export | What it exercises |
|---|---|
| `bea_spring_damper(f32 x4) -> f32` | pure scalar SSE float math (10 instructions), clamp branches |
| `bea_poly_d(f64 x4) -> f64` | pure scalar SSE double math |
| `bea_stack_args(f32 x5, f64, i32) -> f64` | Win64 stack args 5..7, mixed float/int |
| `bea_norm_copy(const f32*, i32, f32* out) -> f32` | **imports** `malloc`/`memcpy`/`free` (msvcrt via IAT thunks `jmp [rip+__imp_x]`) plus in-image `sqrtf` |
| `bea_body_step(Body*, const f32*, f32)` | struct in/out through a pointer |
| `bea_global_gain(f32)`, `g_gain`, `g_calls` | reads a `.data` tunable, writes a counter (state persistence across calls) |
| `bea_big_frame(i32)` | 16 KB frame → `___chkstk_ms` probe; ~99,360 instructions per call |
| `bea_tls_counter(i32)` | `__thread` → MinGW **emutls** (`__emutls_get_address` → winpthreads → `TlsAlloc`/`CreateEventA`…) |
| `bea_avx_dot` | `__attribute__((target("avx2,fma")))` → `vxorps`, `vmovss`, `vfmadd231ss` |
| `bea_div(i32,i32)` | `idiv` → #DE when b=0 |
| `bea_apply(fnptr, f32)` | indirect call through a caller-supplied function pointer |
| `bea_trig(f32,f32)` | `sinf`/`atan2f`/`pow`, statically linked from libmingwex. **The x87 instructions used are `fsin`, `fpatan`, `fyl2x`, `f2xm1`, `fscale`.** |
| `bea_spin(i32)` | infinite loop (budgets, timeouts, cancellation) |
| `bea_read_teb_self()` | `mov rax, gs:[0x30]` (TEB self pointer) |

Toolchain facts [V]: with `-static`, the DLL imports only `KERNEL32.dll` (47 functions, mostly from winpthreads)
and `msvcrt.dll` (33). Math functions are **in-image** (libmingwex), not imports. Without `-static`, `__thread`
pulls `libgcc_s_seh-1.dll!__emutls_get_address`. GCC 16 here has no `-fno-emulated-tls`.

### 2.2 Harness architecture (as implemented in `LAB/bea_emu_bridge.py`)

**Memory layout.** All synthetic regions sit under `0x7E00_0000_0000`, so addresses identify themselves in
diagnostics. The image goes at its preferred base, or is relocated on request.

| Region | VA | Notes |
|---|---|---|
| TEB | `0x7E0000000000` | `+0x08` StackBase, `+0x10` StackLimit (read by MSVC `__chkstk`), `+0x30` Self, `+0x40/48` ClientId, `+0x58` ThreadLocalStoragePointer, `+0x60` PEB, `+0x68` LastErrorValue. `GS_BASE` = TEB via `UC_X86_REG_GS_BASE` [V works] |
| PEB | `+0x1000` | `+0x10` ImageBaseAddress, `+0x30` ProcessHeap (opaque) |
| misc | `+0x2000` | TLS slot array (`[0]` → static TLS block), errno cell at `+0x800` |
| static TLS block | `+0x4000` | copy of the TLS template + zero fill. `_tls_index` (AddressOfIndex) := 0. **TLS callbacks are not run; they are reported** |
| import stubs | `+0x100000` | 16 bytes per import: `C3` (ret) + `CC` padding. The IAT slot gets the stub VA |
| return sentinel | `+0x200000` | `F4` (hlt) page; `emu_start(entry, until=SENTINEL)` |
| guest heap | `+0x10000000` | 64 MiB default, HLE `malloc` (bump allocator plus live map; double and invalid frees reported) |
| arg scratch | `+0x20000000` | 16 MiB default. Host-built argument buffers, reset per call |
| stack | `+0x30000000` | 1 MiB default |
| KUSER_SHARED_DATA | `0x7FFE0000` | read-only synthetic page (`NtMajorVersion=10` @0x26C, `NtBuildNumber` @0x260). Fixed by the Windows ABI; code reads it inline |

**PE loading** (pefile, parsed once with `fast_load=True` plus `parse_data_directories` for IMPORT, EXPORT,
BASERELOC, TLS, and DELAY_IMPORT):
- Capture imports, exports, and TLS as **RVAs before relocating**: pefile computes `imp.address` from the parse-time
  ImageBase. Then `pe.relocate_image(base)` if a different base is requested. [V] works at `0x180000000`.
- Map `SizeOfImage` (page-rounded) and write headers and each section (`min(len(raw), VirtualSize)`). **Don't use
  `get_memory_mapped_image()`**: it drops sections at RVA ≥ 256 MiB unless `max_virtual_address` is raised, and
  doesn't pad a trailing `.bss`. Section raw data is a `bytearray` after relocation, so wrap it in `bytes()` [V bug hit].
- Then apply per-section protections (`r/w/x` from Characteristics). The headers page is `r--`.
  [V: jumping to RVA 0x1 → `fetch_protected` with a clean diagnostic.] Host `mem_write` ignores protections, so
  IAT patching works regardless of order.

**Win64 call frame** (`EmuSession.call`):
```python
a_aligned = (frame_top - 0x20 - 8*len(stack_args)) & ~0xF      # rsp before `call`, 16-aligned
entry_rsp = a_aligned - 8                                       # [rsp] = return address (sentinel)
frame = pack("<Q", SENTINEL_VA) + b"\0"*0x20 + b"".join(pack("<Q", v) for v in stack_args)  # arg5 at [rsp+0x28]
# args 0..3: int-class -> RCX,RDX,R8,R9 ; f32/f64 -> XMM0..3 low lane (positional);
# variadic=true duplicates floats into the GPR; struct returns not of size 1/2/4/8 -> hidden RCX pointer.
```
Returns: `f32` = `xmm0[31:0]`, `f64` = `xmm0[63:0]`, ints from `rax`. Raw `rax` and the 128-bit `xmm0` are
always included. **MXCSR and FPCW are set at every call start** (defaults `0x1F80`/`0x027F`, overridable per
call), so a previous call can't leak FP state.

**Imports → HLE stubs.** A single `UC_HOOK_CODE` covers `[STUB_VA, STUB_VA + n*16)`. Range-limited hooks only
instrument that range. The handler reads args (`rcx..r9`, `xmm0..3`, stack `[rsp+0x28+8k]`; the return address is
`[rsp]` because the IAT `jmp`/`call [iat]` already pushed it), sets `rax`/`xmm0`, and the stub's `ret` returns
naturally. If no handler exists, the call stops with `unhandled_import`, the args, and the caller's RVA.
Built-in handlers: malloc/calloc/realloc/free/_aligned_*, memcpy/memmove/memset/memcmp/strlen/strcmp, _errno,
Get/SetLastError, Tls*, CriticalSection no-ops, QPC/QPF/GetTickCount (deterministic), Sleep (no-op),
IsProcessorFeaturePresent (0), abort/_assert/RaiseException/ExitProcess (stop), and CRT math
(`sin/cos/…/pow` and their `f` variants via Python `math`, tagged `builtin-inexact`). Per-session overrides by
`"dll!name"` or bare name: `{"returns": {...}}` or `{"action": "stop"}`.

**Faults and diagnostics** (one stop record; the first stop wins):
- `UC_HOOK_MEM_{READ,WRITE,FETCH}_UNMAPPED` and `…_PROT` produce `fault.kind` (`read_unmapped`, `write_protected`, …)
  with the address, size, written value, and `addressRegion`: the image section with its RVA, stack, heap, stub
  (with the import name), the "null page: likely NULL pointer dereference (+0x18)" case, or the nearest region.
- `UC_HOOK_INTR` produces `cpu_exception` with the vector name (#DE, #UD, #GP, int3, `int 0x29` __fastfail, …).
- `UC_HOOK_INSN_INVALID` produces `invalid_instruction`.
- Every non-returning stop includes: the PC and its region, capstone disassembly of the faulting instruction
  (including AVX mnemonics capstone *can* decode), all GPRs + MXCSR + xmm0–15 for faults and exceptions, and a
  **heuristic stack scan** for return addresses (a qword into the image preceded by `E8`/`FF 15`/`FF /2`).
- An optional `faultPolicy: "map_zero"` satisfies unmapped reads and writes with zero pages and tags the result
  `auto_mapped_zero_pages`. It is only allowed in `snapshots: "manual"` sessions (gotcha #7).

**Snapshots.** By default the session enables Unicorn CPU+memory contexts
(`uc.ctl(UC_CTL_CONTEXT_MODE, UC_CTL_IO_WRITE, c_int(UC_CTL_CONTEXT_CPU|UC_CTL_CONTEXT_MEMORY))`, then
`context_save/restore`). A **baseline snapshot** is taken at `session.open`. Python-side HLE state (heap top,
live allocations, TLS slots, QPC counter) is snapshotted alongside, which is mandatory because HLE state lives
outside the engine. The alternative mode `snapshots: "manual"` copies only the *used extents* (writable image
sections, the TEB pages, heap and scratch up to their high-water marks, and the stack) and unmaps pages
auto-mapped after the snapshot. [V: same speed for small working sets: 18.5 k vs 18.7 k calls/s.]

**Budgets, timeouts, cancellation:**
- `maxInstructions` (default 1 M) maps to `emu_start(count=N)`. `0` means unbudgeted fast mode, and switching
  modes triggers `ctl_flush_tb()` (gotcha #5).
- `timeoutMs` uses a **single polling watchdog thread** (5 ms period). Arming is a lock-protected tuple swap, and
  the deadline is checked against a sequence number so a late fire can't stop the next call. A Condition-based
  version cost about 40 µs per call [V].
- `bridge.cancel {requestId}` is handled on the reader thread. It sets the request's event and calls
  `uc.emu_stop()`. The watchdog thread **re-issues** `emu_stop()` every period while the active request is
  flagged, because a stop issued before `emu_start` actually begins is lost [V design]. Measured cancel latency:
  0.4–0.6 ms.

**ISA guard** (session.open, [V]):
- Capstone (with `skipdata`) sweeps the function ranges from raw `.pdata` (`struct.iter_unpack("<III")`, not
  pefile's slow exception parsing) **plus the gaps** between them inside executable sections. Leaf and asm
  functions have no `.pdata` entry: the first pdata-only version found 1 of 6 x87 transcendentals [V].
- It flags VEX/EVEX lead bytes (`C4/C5/62` after optional segment and `67` prefixes), except the BMI1/BMI2
  mnemonics, and the x87 transcendental mnemonics (`fsin fcos fsincos fptan fpatan f2xm1 fyl2x fyl2xp1`).
- VEX addresses get per-address `UC_HOOK_CODE` hooks (only those instructions are instrumented) that stop with
  `unsupported_instruction`. x87 addresses get per-address hooks that add the `x87_transcendental_inexact`
  deviation.
- Cost: 12.8 k instructions in about 12 ms (~1 M insn/s), so a 30 MB `.text` would take seconds. **Cache the scan
  by image sha256.**

### 2.3 Results: emulated vs native ([V], `LAB/probe_out.txt`)

| Function | Emulated | Native (ctypes) | Notes |
|---|---|---|---|
| `bea_spring_damper(0.25,-1.5,40,2)` | -7.0 (`0xc0e00000`), 10 insns / 2 blocks | -7.0 | first call 2.9 ms (cold translation) |
| `bea_stack_args(1,2,3,4,0.5,1.25,-7)` | -0.75 | -0.75 | stack args OK |
| `bea_norm_copy([3,4,12])` | 13.0, out `[0.2307…,0.3076…,0.9230…]` bit-identical | same | HLE malloc/memcpy/free traced with caller RVAs |
| `bea_body_step` struct | fields decoded; `steps` 41→42 | — | struct `fields` readback |
| `bea_global_gain` ×3 | `g_calls`=3, then 0 after baseline restore | — | memory snapshot restore works |
| `bea_big_frame(3)` | 21927, 99,360 insns, 16,561 blocks | 21927 | `___chkstk_ms` fine |
| `bea_tls_counter` (emutls) | `unhandled_import kernel32!CreateEventA` (caller RVA 0x6480) after HLE calloc/malloc/TlsAlloc/free | — | MinGW emutls/winpthreads needs many kernel32 HLEs |
| `tls_bump` (MSVC-style static TLS) ×2 | 42, 44 | 42, 44 | `gs:[0x58]` + `_tls_index=0` setup verified |
| `chk_big` (stack protector + chkstk) | 46 (120,060 insns) | 46 | `__stack_chk_guard` uninitialized but consistent |
| `bea_avx_dot` | `unsupported_instruction` at `vxorps` (guard). Without the guard: `invalid_instruction` at `vfmadd231ss` (2nd insn; the 1st, `vxorps`, ran silently) | — | |
| `bea_div(7,0)` | `cpu_exception` vector 0 `#DE`, insn `idiv ecx` | — | |
| `bea_apply(&bea_global_gain, 3)` | 9.0 | — | `{"type":"symbol","export":…}` arg |
| `bea_trig` (7 inputs, f32) | 0 ulp difference | same | x87 inside, but f32 rounding hides it; tagged `x87_transcendental_inexact` (fpatan, fsin) |
| `bea_spin` | `budget_exhausted` @200 k insns (6.2 ms); `timeout` at 50 ms | — | |
| `bea_read_teb_self` | `0x7e0000000000` | — | GS base OK |
| `bea_body_step(NULL,…)` | `fault read_unmapped @0x18`, "likely NULL pointer dereference (+0x18)", insn `movss xmm0, dword ptr [rcx + 0x18]` | — | |
| denormal input, MXCSR `0x1F80` vs `0x9FC0` | `0x80000100` vs `0x80000000` | — | FTZ/DAZ honored |
| relocated session (base `0x180000000`) | `bea_global_gain(2)`=3.0, `bea_trig` OK | — | |

**x87 differential test** (`LAB/x87diff.py`, 1500 random inputs each, FPCW `0x027F`; mismatch count, max ulp):
`sin(±10)` 49/1 · `sin(±1e6)` **1318/19737** · `cos` 52/1 · `tan` 32/1 · `atan` 0 · `atan2` 3/1 · `exp(±50)` 1/1 ·
`log` 376/1 · `pow` **581/88** · `sqrt` 0 · `fmod` 0 · f32 `sinf/expf/powf/atan2f` 0.
With Unicorn's reset FPCW `0x0000`: `sqrt` 1500/1500 (results rounded to float precision, e.g. 280.5699462890625
vs 280.5699615323975), `exp` 1500/1500, `pow` 1500/1500 (up to 2.2e10 ulp), and `expf`/`powf` mismatches too.

### 2.4 Verified gotchas (each with evidence and mitigation)

1. **FP control words reset to 0.** `Uc(UC_ARCH_X86, UC_MODE_64)` gives `FPCW=0x0 MXCSR=0x0 FPTAG=0x5555 CR0=0x11
   CR4=0x50200`. Native Windows gives `FPCW=0x27f MXCSR=0x1fa0` (0x1F80 plus a sticky PE flag).
   *Mitigation:* write `0x027F`/`0x1F80` at session start **and at every call**, and record both in provenance. The
   user's existing harnesses never set them. Their SSE code is unaffected by PC, but any x87 path, or code
   relying on masked SSE exceptions, would diverge.
2. **VEX silent mis-execution** (see TL;DR). Test vectors with distinct register contents (`ymm0`=100+i,
   `ymm1`=1+i, `ymm2`=2+i):
   - `vaddss xmm0,xmm1,xmm2` → `[102,101,102,103,104…]`, expected `[3,2,3,4,0…]`.
   - `vaddps xmm` is wrong; `vmovaps xmm0,xmm1` doesn't zero the upper lanes; `vzeroupper` is a no-op.
   - `vaddps ymm` and `vfmadd231ss` raise `UC_ERR_INSN_INVALID`.
   - CPUID reports `GenuineIntel` (or `AuthenticAMD` for `EPYC_ROME`) with SSE4.2=1, AVX=0, FMA=0, F16C=0,
     AVX2=0, BMI2=1, AVX512F=0 for the default, `HASWELL`, and `EPYC_ROME` models.
   - CPUID can be spoofed with `hook_add(UC_HOOK_INSN, cb, None, 1, 0, UC_X86_INS_CPUID)`, where returning 1
     skips the real instruction.

   *Mitigation:* the ISA guard. Also: native code dispatching on CPUID takes AVX/FMA paths on the Ryzen while the
   emulator takes SSE paths, so differential comparisons must expect last-bit differences in CRT math. MSVC's
   ucrtbase picks FMA3 paths at runtime [B].
3. **x87 transcendentals are inexact** (table above). *Mitigation:* tag them as deviations. For true bit-exactness
   use native oracles (Frida `NativeFunction` calls in the real process) and treat emulation as the tracer, not
   the ground truth.
4. **Hooks vs the TB cache.** Repro in `bench.py` and inline tests:
   - `UC_HOOK_BLOCK`/`UC_HOOK_CODE` added after warm-up fired 0 times. After `ctl_flush_tb()` they fired
     16,561 and 99,360 times.
   - After `hook_del` without a flush: 0 fires, but 0.76 ms per call vs 0.49 ms, because the instrumentation
     remains.

   *Mitigation:* keep dynamic hooks installed per session "hook signature" and flush when it changes (implemented
   in `_ensure_dynamic_hooks`). Memory hooks (`UC_HOOK_MEM_WRITE`) took effect without a flush in my test, but
   flush anyway.
5. **Budget vs TB cache.** Both orders fail ("count>0, then count=0, then count=1000" → not enforced). A flush
   before the budgeted run fixes it (0.069 ms to stop). *Mitigation:* track the budget mode and flush on change
   (implemented). Cost of budgeting: big_frame 500 µs → 1497 µs; nothing measurable for 10-instruction functions.
6. **`emu_start(timeout=)` costs ~15 ms per call** (66 calls/s even when the function returns in microseconds).
   *Mitigation:* polling watchdog plus `emu_stop()`.
7. **Memory snapshots plus layout changes** (`LAB/snapmap_case.py`):
   - map after save, then restore: write → `OSError: access violation reading 0x38`;
   - unmap after save, then restore: region list shows the pre-existing region at base `0x0`;
   - mapping page 0 after save: `UC_ERR_MAP`;
   - CPU-only mode: fine.

   *Mitigation:* freeze the layout before any memory snapshot. Pre-reserve big regions and sub-allocate, and use
   `snapshots: "manual"` for sessions that map dynamically (implemented and enforced).
8. **Daemon reader thread vs interpreter shutdown.** A thread blocked in `sys.stdin.buffer.readline()` made the
   bridge die at exit with `Fatal Python error: _enter_buffered_busy … possibly due to daemon threads`, exit code
   `0xC0000005`. *Mitigation:* read fd 0 with `os.read` and frame lines manually, then flush and `os._exit(code)`
   (implemented; exit code 0 confirmed).
9. **Metadata lookups are slow.** `importlib.metadata.version()` per response cut throughput to 719 calls/s.
   Cache it.
10. **pefile pitfalls**: the `max_virtual_address=0x10000000` default in `get_memory_mapped_image`, `bytearray`
    after relocation, and import VAs computed from the parse-time ImageBase.
11. **ctypes converts native access violations into `OSError`** on Windows. The process *may* survive, but treat
    the session as poisoned: close it and recreate it from a fresh `Uc`.
12. **Python 3.14 compatibility**: unicorn 2.1.4 (ctypes binding), capstone 5.0.9, and pefile all import and work
    under `python -I` on 3.14.6. No issues found.
13. **The emutls path** in MinGW binaries needs `TlsAlloc`/`TlsGetValue`/`TlsSetValue` plus winpthreads
    (`CreateEventA`, …). Expect long HLE tails for CRT-internal machinery. Prefer dump-backed sessions, where TLS
    and CRT state are already initialized by the real process.

### 2.5 Believed gotchas for MSVC-built game binaries (couldn't build MSVC here, no SDK)

- **/GS cookies.** The prologue does `mov rax,[__security_cookie]; xor rax,rsp` and the epilogue calls
  `__security_check_cookie`. Since `__security_init_cookie` never ran, the cookie keeps its static default
  (`0x00002B992DDFA232`) and checks pass. A mismatch reaches `__report_gsfailure`, which does `int 0x29` (fastfail,
  `ecx=2`); the bridge reports that as a `cpu_exception`, `int 0x29 (__fastfail)`. [B]
- **`__chkstk` reads `gs:[0x10]` (StackLimit)** and probes downward. A zeroed TEB makes it skip probing. The
  bridge sets StackLimit to the real stack bottom, so probes stay in mapped memory. [B for MSVC; [V] the MinGW
  `___chkstk_ms` equivalent works]
- **Static TLS:** MSVC `__declspec(thread)`/`thread_local` compiles to exactly the sequence verified in
  `bea_tls_native.dll`. [V sequence, B codegen]
- **CFG:** `__guard_dispatch_icall_fptr` in the file image points at `_guard_dispatch_icall_nop` (`jmp rax`) until
  the loader patches it, so indirect calls work unpatched. [B]
- **SEH and C++ EH:** x64 SEH is table-based (`.pdata`/`.xdata`). Unicorn has no dispatcher, so faults stop the
  run and `throw` reaches `RaiseException`/`_CxxThrowException`, which stops as a terminating import. Functions
  that *rely* on try/except for control flow can't be emulated faithfully (speakeasy 2.0 implements SEH/VEH
  dispatch). [B]
- **Delay-load imports** go through in-image `__delayLoadHelper2` → `LoadLibrary`/`GetProcAddress`. These need HLE
  versions that return stub addresses dynamically (not implemented; reported as `delayImports` count). [B]
- **Statically linked CRT math in MSVC images** (common for games) uses SSE2/FMA3 implementations chosen through
  `__isa_available`, which CRT init sets. In an emulator it stays at its file value, so the SSE2 path runs, while
  natively the FMA3 path may run. Last-ulp differences are possible. [B]
- **Inline syscalls, `rdtsc`, `cpuid`, `KUSER_SHARED_DATA` reads** (`0x7FFE0000`, mapped synthetic) appear in
  anti-tamper and timing code. Hook `UC_HOOK_INSN` for `SYSCALL`/`CPUID` and report them. [B]
- **32-bit (WoW64) games** need `UC_MODE_32`, an FS-based TEB, and stdcall/cdecl/thiscall conventions. Not
  implemented in the prototype. [B]
- **Huge images.** Mapping 100+ MB is fine. With `snapshots:"manual"`, large writable sections make each restore
  expensive (copying 20 MB ≈ ms), so prefer Unicorn's COW snapshots there (restore cost ∝ dirtied pages [B]).

### 2.6 Performance (`LAB/bench_out.txt`, `LAB/client_out.txt`; ±30% run-to-run)

In-process (Python 3.14.6, unicorn 2.1.4):

| Scenario | Rate | Per call |
|---|---|---|
| raw 10-insn call, minimal prep (1 `mem_write` + 2 `reg_write`) | ~190 k calls/s | 5.2 µs |
| raw 10-insn call, 6 `reg_write` + float packing | 59–62 k calls/s | 16–17 µs |
| same with `reg_write_batch` | 60 k calls/s | 16.6 µs (no gain) |
| same + `emu_start(timeout=1s)` | **66 calls/s** | 15.2 ms |
| same + `context_restore` (CPU+memory snapshot) | 27.6–28.7 k calls/s | 35–36 µs |
| big_frame, no hooks | **186–203 M insn/s** | 0.49–0.53 ms / 99,360 insns |
| big_frame, consistent `count` budget | 64.6 M insn/s | 1.5 ms |
| + `UC_HOOK_BLOCK` (Python no-op, after flush) | 15.2 M insn/s | 6.5 ms (≈0.36 µs per block) |
| + `UC_HOOK_CODE` (Python no-op, after flush) | 2.74 M insn/s | 36 ms (≈0.36 µs per insn) |
| + `UC_HOOK_MEM_WRITE` (Python no-op) | 12.4 M insn/s | 8 ms |
| `ctl_flush_tb()` + cold re-translation of big_frame | — | 0.54 ms |
| external `emu_stop()` latency (other thread) | — | 33 µs |
| `EmuSession.call(spring)` generic path (spec parsing, result dicts) | 26–30 k calls/s | 33–38 µs |
| `EmuSession.call(norm_copy)` (3 HLE imports, 2 buffers, readback) | 10.9–11.6 k calls/s | 86–92 µs |
| `call_batch` fast path, chained state | 38.7–40.2 k calls/s | 25 µs |
| `call_batch` fast path, snapshot per vector | 16.6–18.7 k calls/s | 54–60 µs |
| native ctypes call of the same function | 2.1 M calls/s | 0.48 µs |
| `session.open` (132 KB DLL: map, stubs, hooks, baseline snapshot) | — | 4.7–6.3 ms + ISA scan ≈12 ms |

End to end, Node 24 ↔ stdio bridge (`bridge_client.mjs`):

| Scenario | Rate |
|---|---|
| process start → `ready` frame | 225–380 ms |
| sequential `emu.call` (1 in flight) | 4.6–5.4 k calls/s (187–218 µs) |
| pipelined `emu.call` (3000 in flight) | 13.0–15.3 k calls/s |
| `emu.callBatch` 20k vectors, chain, columns | 35.8–38.7 k calls/s (response 0.85 MB) |
| … snapshot, columns | 16.3–18.2 k calls/s |
| … snapshot, objects | 10.6–17.4 k calls/s (2.12 MB) |
| … snapshot, generic path (`fastPath:false`) | 7.9–13.2 k calls/s |
| `argTemplates` batch, norm_copy (buffers + HLE) | 3.5–5.9 k calls/s |
| cancel of a runaway call | ack + `cancelled` status in 0.4–0.6 ms |

Takeaways: per-call overhead dominates for small functions, so **batching is mandatory**: 7–8x versus
sequential requests. Snapshot isolation roughly halves throughput, so it should be an explicit option, with
`chain` as the cheap default for pure functions. Tracing hooks cost about 0.36 µs per event, so tracing has to be
opt-in and bounded.

---

## 3. The user's existing harnesses (private, read-only, generic techniques only)

The user's private emulation harnesses are a few Python scripts built around one shared `Emu` class, with
per-function wrappers on top. A pefile helper supplies `.pdata` function boundaries and MSVC RTTI vtable recovery.
They were read for techniques only, and no target-specific values are reproduced here.

**Generic techniques they use:**
- Map the whole `pe.get_memory_mapped_image()` at the preferred ImageBase as one RWX region (no relocations needed).
- Stack, scratch heap with a bump allocator (`alloc(bytes|size, align=16)`, reset per call), return-sentinel page
  with `hlt`, `emu_start(base+rva, SENTINEL, count=max_ins)`.
- `UC_X86_REG_GS_BASE` pointed at a *zeroed* fake TEB page.
- `UC_HOOK_MEM_UNMAPPED` collecting `(access, addr, size)`. Errors report the RVA of RIP plus the last 3 unmapped
  accesses.
- Float args written as f32 bits into `xmm0..3`. Results from the low 32 bits of `xmm0` and from `rax`. Stack
  args at `[rsp+0x28…]` with float bits packed into 8-byte slots.
- Synthetic structs built in Python as `bytearray` at known field offsets, with helpers for any field encodings
  the target uses.
- **Differential testing**: a clean-room Python reference vs emulation of the original on seeded random synthetic
  inputs, reporting the worst relative error per output. Emulator faults are counted and the emulator is
  re-created.
- **Behavioral identification**: sweep every `.pdata` function in an address range, call each with probe inputs
  under a small instruction budget, and match outputs against known math functions (atan, exp, log, pow, …).
- Build C++ container layouts (begin/end/capacity triples) in emulated memory.
- `import capstone` *before* adding the tools dir to `sys.path`, because a local `dis.py` shadows the stdlib `dis`.

**Needs and pain points these imply, and how BEA covers them:**

| Observed need | BEA feature |
|---|---|
| boilerplate per function (alloc, pack, call, unpack) | declarative typed args: `f32[]`, `struct` with named fields and offsets, `ptr` with nested `to`, `symbol`; typed returns; `out` readback |
| emulator re-creation after faults | baseline and named snapshots; `restore` is cheap (tens of µs) |
| only f32 handled; doubles and stack floats done by hand | full Win64 ABI typing (f32/f64/ints/ptr, stack args, struct returns via hidden pointer, variadic) |
| no import handling (pure leaf functions only) | HLE stubs plus `unhandled_import` stops with caller RVA and args; per-session overrides |
| `.data` tunables read from the *file* image, not the runtime value | dump-backed sessions (Frida memory capture) and `mem.write` patches |
| FP environment never set (FPCW/MXCSR = 0 in Unicorn) | explicit FP environment per call, recorded in provenance |
| differential stats computed ad hoc | batch columns with exact `bits`; the host computes ulp/relative error; seeded vector generators can live in BEA (TS) |
| behavioral sweeps over many unknown functions | batches with budgets, fault isolation, ISA guard, `stopOnFault:false` |
| `dis.py` module shadowing | the bridge runs as `python -I` with a single self-contained file |
| no tracing or coverage | opt-in block coverage (RVA→hits), instruction and memory traces, import call log |

---

## 4. speakeasy (Mandiant)

**Status (2026)** [V-doc]:
- PyPI `speakeasy-emulator`: last stable **1.5.11 (2022-06-08)**, which pins `unicorn==1.0.2`. A **2.0.0 beta series**
  followed: b1 2026-03-09, b3 04-08, b4 07-24, b6 08-13, b8 09-15, **b9 2026-10-11**.
- 2.0.0b9: `requires_python >=3.10`, deps `pefile, capstone, lznt1, unicorn>=2.1.4, pycryptodome, pydantic>=2.0,
  rich`, `License-Expression: MIT`, classifier Python 3.13, pure `py3-none-any` wheel.
- GitHub `mandiant/speakeasy` is active: commits on **2026-10-24** (SEH/VEH work: "Share the exception APIs of
  kernel32 and ntdll, and honor VEH First").

**Install and run on CPython 3.13 in an isolated uv env** [V]. Cache in `LAB/uv-cache`, `UV_PYTHON_DOWNLOADS=never`:
```
uv run --no-project --python 3.13 --with speakeasy-emulator ...        # resolves 1.5.11
  -> import unicorn (1.0.2) -> `import distutils.sysconfig` -> ModuleNotFoundError: No module named 'distutils'
uv run ... --with speakeasy-emulator==1.5.11 --with setuptools ...     # shim
  -> ModuleNotFoundError: No module named 'pkg_resources'
uv run --no-project --python 3.13 --with "speakeasy-emulator==2.0.0b9" python -I se_eval.py bea_fixture.dll
  -> OK: speakeasy 2.0.0b9, unicorn 2.1.4, capstone 5.0.9, pefile 2024.8.26, pydantic 2.14.1 (15 pkgs, ~8 s)
```

**API (2.0.0b9, read from the installed package)** [V]:
- `Speakeasy(config=None, argv=None, debug=False, gdb_port=None, gdb_host="127.0.0.1")`
- `load_module(path|data, filename)`
- `run_module(module, all_entrypoints=False, emulate_children=False, entry_point=None)`
- `call(addr, params=[])`: integer params via `set_func_args(..., CALL_CONV_STDCALL)`. **It resets the stack and
  the CPU context on every call** (`reset_stack`, `reset_cpu_context`, and zeroes the whole stack map).
- `add_api_hook(cb, module, api_name, argc, call_conv)`, `add_code_hook(cb(emu, addr, size), begin, end)`,
  `add_mem_read/write_hook`, `add_mem_invalid_hook`, `add_interrupt_hook`, `add_invalid_instruction_hook`
- `mem_alloc/mem_read/mem_write`, `reg_read/reg_write` by name. `xmm*` names are not in `REG_LOOKUP`; pass the
  `speakeasy.winenv.arch.X86_REG_XMM0` (=1063) constants instead.
- `get_report()` (pydantic) / `get_json_report()`, `get_memory_dumps()`, `create_file_archive()`
- `speakeasy/gdb.py`: a **GDB Remote Serial Protocol server** (all-stop subset for GDB/IDA).
- About 1,044 `@apihook` handlers across user-mode and kernel API modules (advapi32, kernel32, msvcrt, ntdll,
  ws2_32, wininet, …).

**Evaluation on `bea_fixture.dll`** [V] (`LAB/speakeasy-run/se_eval.py`):
- `load_module` 431–466 ms; `run_module` (DllMain through the MinGW CRT, **plus 3 TLS callbacks executed**) about 390 ms.
- `bea_global_gain(2.0)`=3.0 and `bea_spring_damper(...)`=-7.0, via a code hook at the entry that writes
  `xmm0..3`. `call()` wipes registers, so floats can't be preset.
- `bea_norm_copy` = 13.0 with correct outputs, using speakeasy's own msvcrt models.
- `bea_div(7,0)` gives the error record `unhandled_interrupt intnum=0x0`, with registers, stack, and disassembly.
- `bea_avx_dot` gives `UC_ERR_INSN_INVALID` (same engine limits; the VEX mis-execution applies too).
- `gs:[0x30]` = `0x3000`.
- **Throughput: 14 calls/s (70 ms per call)**. The JSON report grew to **81 MB** after about 310 recorded runs
  (every `call` is an "entry point" with full context).

**Verdict:** not suitable as BEA's oracle/differential engine (too slow per call, report bloat, int-only call API).
Valuable as an *optional* v0.2 provider for:
- running DllMain/TLS/CRT init so an image is initialized before snapshotting it into the Unicorn bridge;
- API-heavy or malware-style code where speakeasy's 1k Windows API models and SEH/VEH dispatch matter;
- its GDB stub (step-debugging emulated code).

Its MIT license and pure-Python wheel make it easy to add as an optional extra.

---

## 5. Qiling

[V-doc]:
- PyPI `qiling` latest **1.4.6 (2023-08-04)**; earlier 1.4.5 (2022-12-31). Deps include `unicorn>=2.0.1`,
  `capstone>=4.0.1`, `pefile>=2022.5.30`, `python-registry`, `keystone-engine`, `pyelftools`, `gevent`,
  `multiprocess`, `pyyaml`, `questionary`, `termcolor`, `windows-curses` (Windows). License **GPLv2**.
- GitHub `qilingframework/qiling` is not archived (7,475 commits; dev-branch commits on 2026-09-24, "updated
  ARCHITECTURE files"), but there has been no PyPI release since 2023.
- Windows PE emulation needs a **rootfs with real Windows DLLs and registry hives**; the README says rootfs files
  "must be downloaded separately". I believe it uses a `dllscollector.bat` script to copy them from a Windows
  install [B]. That means copying and redistributing Microsoft DLLs plus heavy dependencies.

**Verdict:** avoid for BEA, for three reasons:
- the GPLv2 license is a poor fit for an MIT tool;
- its rootfs/LLE model drags system DLLs into the evidence chain;
- its releases are stale.

Unicorn directly, plus targeted HLE, gives more control. Use speakeasy if broad API modeling is needed.

---

## 6. Windows debugging engines

### 6.1 WinDbg / DbgEng / cdb
- **winget** [V]: `Microsoft.WinDbg` **1.2610.1001.0**, installer type msix
  (`https://windbg.download.prss.microsoft.com/dbazure/prod/1-2610-1001-0/windbg.msixbundle`), offline
  distribution supported. Not installed here.
- **cdb.exe:** absent on this host [V]. The Store/winget WinDbg ships `cdb.exe`/`kd.exe`, according to
  mcp-windbg's README ("WinDbg from the Microsoft Store … ship cdb.exe and kd.exe … auto-detected") [V-doc
  third-party, B]. Classic `cdb.exe` comes from the Windows SDK "Debugging Tools for Windows" feature (winget
  `Microsoft.WindowsSDK.10.0.*`) [B]. The path within the MSIX should be confirmed after install with
  `(Get-AppxPackage Microsoft.WinDbg).InstallLocation`.
- **In-box engine:** `System32\dbgeng.dll` 10.0.26100.1 exists, but **`symsrv.dll` is absent** [V]. That means no
  symbol-server downloads with the in-box engine; that's acceptable for stripped game binaries, but not for OS
  symbols.
- **Python bindings:** `Pybag` **2.2.16 (2025-06-26)**, MIT, wraps DbgEng via `comtypes` (+ `pywin32`,
  `win32more`, `capstone`) [V-doc]. `pykd` is legacy [B].
- **mcp-windbg** (svnscha) [V-doc]: MIT, Python ≥3.10, "a Python wrapper around cdb.exe / kd.exe" run headless.
  - Tools: `list_dumps, open_cdb_dump, open_cdb_remote, open_kd_session, open_kd_dump, run_cdb_command,
    run_kd_command, close_cdb_session, close_kd_session, send_ctrl_break, wait_for_break`.
  - Live user-mode attaches via cdb `-remote` (tcp/npipe/com), kernel via `-k`. Per-call timeouts interrupt with
    CTRL+BREAK and resync the session. `--filter-script` redacts output. stdio or streamable-HTTP transport.
  - The general technique for driving cdb over pipes: send a command, then `.echo <unique marker>`, and read until
    the marker (output parsing) [B].
- **BEA use (v0.2+):** minidump triage of crashes BEA captures (`cdb -z dump.dmp -c "!analyze -v; .ecxr; kb; q"`),
  and `dx` data-model queries (`dx -r2 …`; JavaScript extensions can emit JSON). Don't make it a v0.1 dependency:
  it requires an install and duplicates Frida's live capabilities.

### 6.2 Time Travel Debugging
- **In-box recorder** [V]: `System32\tttracer.exe` 1.11.580.0 with TTDRecord/TTDRecordCPU/TTDLoader/TTDInject.
  Its `-?` output states: *"Time Travel Debugging (TTD) command line utility is not meant for use in custom
  software or automation … not intended for direct use as a stand-alone solution"*. The license section also bars
  reverse engineering and commercial use. → **BEA must not automate `tttracer.exe`.**
- **Standalone recorder** [V winget, V-doc]: `Microsoft.TimeTravelDebugging` **1.11.611.0** (msix, from
  `https://aka.ms/ttd/download`), which puts `TTD.exe` on PATH. The docs (MS Learn, updated 2026-06-11) explicitly
  support automation.
  - **Requires admin.**
  - Recording slowdown is **5x–20x**.
  - Modes: `-launch <exe> [args]` (default), `-attach <pid>`, `-monitor <exe>` (uses a driver).
  - Options: `-out <file|dir>`, `-noUI` ("Use this option for automation scenarios"), `-accepteula`, `-children`,
    `-ring`, `-maxFile <MB>`, `-module <name>` (record only that module and its callees; full speed elsewhere),
    `-recordmode Manual` (pairs with the in-process recording API), `-replayCpuSupport
    Default|MostConservative|MostAggressive|IntelAvxRequired|IntelAvx2Required`, `-passThroughExit`,
    `-onInitCompleteEvent <name>`, `-stop <name|pid|all>`, `-wait <s>`, `-tracingOff`, `-timestampFilename`,
    `-numVCpu`.
  - Outputs: `.run` (trace), `.idx` (index built by the debugger), `.out` (recorder log).
  - Once attached, TTD can't detach.
- **Replay automation options:**
  1. cdb/WinDbg on the `.run` file with the TTD data model [B]: `dx @$cursession.TTD.Calls("mod!func")`,
     `dx @$cursession.TTD.Memory(lo, hi, "w")`, `!tt <pos>`, and reverse execution (`g-`, `p-`, `t-`). Simplest,
     but it requires cdb.
  2. **TTD Replay API** [V-doc]: NuGet `Microsoft.TimeTravelDebugging.Apis`; runtime `TTDReplay.dll` and
     `TTDReplayCPU.dll` via the `GetTtd` scripts; samples `TraceInformation`, `TraceAnalysis` (coverage mining),
     `TraceDebugger`, `TtdExtension` in `microsoft/WinDbg-Samples/TTD/ReplayApi`; C++20; **experimental (major
     version 0)**; MIT samples. A small C++ helper exe could emit JSON lines for BEA (coverage, memory-write
     history, call/return lists).
  3. **ttd-bindings** (commial) [V-doc]: PoC "for educational purposes only", C++ wrapper plus Python
     `pyTTD.pyd`. It needs `TTDReplay.dll`/`TTDReplayCPU.dll` from WinDbg ≥1.2111, and supports positions,
     cursors, registers, memory, replay forward and back, call/ret callbacks, and memory watchpoints. No license
     stated, so it's unsuitable as a dependency.
- **BEA use (v0.2+):** a `record` tool (admin and elevation must be explicit and user-consented), then
  replay-derived *observations*: "every write to X over the whole run", call histories. This is the gold standard
  for "what writes this address", because it covers every write in the run with no breakpoint budget. The cost is
  admin plus a 5–20x slowdown, which can matter for anti-cheat-protected games.

### 6.3 x64dbg automation
- winget `x64dbg.x64dbg` **2026.05.27** [V].
- **x64dbg-automate** (dariushoule) [V-doc]: MIT.
  - An RPC-server plugin inside x64dbg (built with CMake and VS) plus a Python client, pip `x64dbg_automate`.
  - Transport: ZeroMQ + msgpack, request/reply commands (e.g. `XAUTO_REQ_DBG_EVAL`) plus pub/sub events.
  - Docs list: session, debug, memory, and breakpoint control; registers and expressions; assemble and
    disassemble; labels, comments, and bookmarks; settings; GUI.
  - **An MCP server is included**: `pip install x64dbg_automate[mcp]` → `x64dbg-automate-mcp`, with
    `X64DBG_PATH` set.
- **BEA use:** interop only. Tell users they can run it side by side, possibly with deep links like "open this
  address in x64dbg". A GUI debugger as a backend conflicts with BEA's headless, evidence-first design.

### 6.4 GDB on Windows (a verified extra option)
- WinLibs ships **GDB 17.2 with embedded Python 3.9.7** plus `gdbserver` [V]. It debugs native Windows PE
  processes (`windows-nat`).
- **Hardware watchpoints verified** on a self-built test exe (`LAB/gdbtest`), driven headless through the GDB
  Python API (`gdb.events.stop`, `gdb.Breakpoint`, JSON printed to stdout):
  - `watch -l g_value` → `Hardware watchpoint 2` but **reports only value changes**: 4 of 6 writes, so the 0→0
    writes are suppressed.
  - `awatch -l g_value` → `Hardware access (read/write) watchpoint` **reports every access**: 6 writes plus 1 read.
    This matches Cheat Engine's "find out what writes/accesses this address" semantics; filter reads using the
    disassembly.
  - The stop PC is *after* the accessing instruction (debug trap semantics). BEA must disassemble backwards from a
    known instruction boundary (function start from `.pdata`) to name the writer instruction.
  - Run to `main` takes about 0.09 s; **about 0.9–1.4 ms per stop** round trip in the Python API.
- REA already drives GDB through **MI3**: `src/gdb/GdbSessionManager.ts:744` spawns `gdb --nx --quiet
  --interpreter=mi3` and runs console commands via `-interpreter-exec console` (`:1170`). That protocol code is
  reusable.
- **BEA use (v0.2):** a "debugger provider" fallback for hardware watchpoints when Frida isn't usable, and the
  basis of the Linux provider. On Windows, prefer Frida's own hardware breakpoint/watchpoint APIs first (other
  tracks).

---

## 7. LLDB and GDB scripting for future Linux/macOS providers

- **GDB** (Linux): use MI3 (REA has a session manager) or **DAP** (`gdb -i=dap`; supports `launch` with
  `stopOnEntry`, `attach` with `pid|target|coreFile`, `disassemble` with hex instruction bytes, `evaluate` repl,
  `cancel`) [V-doc for DAP extensions; B for the version: GDB ≥14]. The Python API gives structured events
  (`gdb.events.stop`, `gdb.Breakpoint` subclasses with `stop()` callbacks, `Inferior.read_memory`,
  `Frame.read_register`, `gdb.lookup_type`). That makes in-GDB JSON emitters easy [V on Windows GDB 17.2].
  Hardware watchpoints (`watch -l`, `rwatch`, `awatch`) are limited to 4 x86 debug registers.
- **LLDB** (macOS and Linux): the Python SB API (`SBDebugger`, `SBTarget.LaunchSimple`/`Launch(SBLaunchInfo)`,
  `SBProcess`, `SBThread`, `SBFrame`, `SBBreakpoint.SetScriptCallbackFunction`, `SBTarget.WatchAddress`,
  `SBProcess.ReadMemory`) [B].
  - REA's pattern: `src/native/LldbCallTracer.ts:493-499` runs `lldb --batch -o "command script import
    bridge/native/rea_lldb_tracer.py" -o "rea_trace <config.json>"`. The bridge stops at functions, records entry
    registers and memory with *no expression evaluation*, enforces byte, frame, and duration budgets, and flushes
    a **bounded JSONL observation journal** so partial results survive tracer failure
    (`bridge/native/rea_lldb_tracer.py:73-90`). It also hashes file identity for provenance. [V read]
  - **LLDB has built-in MCP** [V-doc]:
    - start it with `protocol-server start MCP listen://localhost:59999` (or `accept:///path`); also
      `protocol-server stop|get MCP`;
    - the `lldb-mcp` stdio shim exposes tools `session_create`, `command`, `sessions_list`, `session_close`, and
      resources `lldb://instance/<pid>/debugger/<id>[/target/<idx>]`;
    - discovery happens through `~/.lldb`, and **any `lldb-mcp` can run commands in any discovered session (no
      auth)**;
    - it speaks MCP protocol `2024-11-05`, so there is no structured content;
    - an `SBProtocolServer` API was added in July 2026.

  - BEA should *not* proxy raw LLDB commands. Like REA, wrap structured primitives with budgets, and treat
    lldb-mcp as an interop target, not a dependency.
- **Recommendation for the provider interface:** define BEA's runtime primitives (spawn/attach,
  modules/exports/maps, read/write, breakpoint/hook with structured capture, hardware watchpoint,
  call-function-as-oracle, dump) once, then implement Frida first, with GDB/MI or DAP and LLDB-SB adapters later.
  Each adapter is a child process speaking a JSON-lines protocol shaped like `bea-emu/0.1` (same
  framing/error/provenance envelope, different methods).

---

## 8. Recommendation: BEA v0.1 backend set

| Backend | v0.1? | Why |
|---|---|---|
| Frida (Node binding 17.23.2, verified working in REA) | **Yes (primary)** | live observation, hooks, Stalker, memory, native oracle calls (other tracks) |
| **Unicorn bridge (`bea-emu/0.1`)** | **Yes** | deterministic, scriptable, high-throughput function emulation (≈17–39 k calls/s batched); differential testing vs native/Frida oracles; per-run coverage and traces; no admin; pure user-mode; Python already present |
| Dump-backed Unicorn sessions (Frida → bridge) | **Yes (design now; ship early)** | emulate against real runtime state (initialized globals, heap objects, TLS); fixes the "file-image `.data` ≠ runtime" problem |
| speakeasy 2.0 | v0.2 optional extra | init-path emulation (DllMain/TLS/CRT), API-heavy code, SEH/VEH, GDB stub; beta, slow per call |
| GDB (MI3/DAP) | v0.2 | Linux provider; Windows hardware-watchpoint fallback (verified) |
| cdb/DbgEng (+ Pybag) | v0.2 | minidump triage; requires the WinDbg or SDK install |
| TTD.exe + replay (cdb `dx` or Replay API helper) | v0.3 | exhaustive write/call history; admin + 5–20x slowdown; experimental API |
| x64dbg-automate | interop only | GUI-centric; has its own MCP server |
| LLDB (SB API) | v0.3 (macOS) | REA's tracer pattern; lldb-mcp for interop |
| Qiling | **No** | GPLv2, rootfs of real DLLs, last release 2023 |
| in-box `tttracer.exe` | **No** | license forbids automation |
| speakeasy 1.5.x | **No** | unicorn 1.0.2 breaks on Python ≥3.12 |

**Packaging the bridge** [design]:
- Ship `bea_emu_bridge.py` as one self-contained file in the npm package (like REA's `bridge/*.py`).
- At `bea doctor`/first use, create a **BEA-owned venv** with uv or `python -m venv` under BEA's data dir, and
  install pinned, hash-locked `unicorn==2.1.4 capstone==5.0.9 pefile==2024.8.26`. Never touch global
  site-packages.
- Spawn with `python -I -X utf8 bea_emu_bridge.py` and a sanitized env. Use REA's `spawnOwnedProviderProcess`
  pattern (`src/process/ProviderProcess.ts:30-55`: `stdin: "pipe"`, a Windows Job Object with
  `memoryLimitBytes`, owned process-group cleanup), so emulation of huge images can't exhaust RAM and orphans
  can't survive.
- Gate engine-version changes behind re-running the probe suite: the gotchas above are version-specific.

---

## 9. Protocol: `bea-emu/0.1` (JSON lines over stdio)

### 9.1 Transport and lifecycle
- Child process: `python -I -X utf8 bea_emu_bridge.py`. stdin carries requests, stdout carries frames, stderr is
  free-form logs (bounded and captured by the host, never parsed).
- **Framing:** one UTF-8 JSON object per line, `\n` terminated (the bridge tolerates `\r\n`). Max frame 64 MiB.
  Larger blobs go by file path (planned `{"file": "..."}` blob form).
- The bridge writes frames through a private binary handle. `sys.stdout` is redirected to stderr, so stray
  `print`s can't corrupt the stream. Output is compact JSON with `allow_nan=False`, so non-finite floats never
  leak as invalid tokens.
- **Startup:** the bridge first emits an unsolicited `{"event":{"type":"ready","protocol":"bea-emu/0.1",
  "bridge":"0.1.0","pid":…,"engines":{…}}}`. On import failure it emits `{"event":{"type":"fatal",
  "code":"engine_unavailable",…}}` and exits with code 3.
- **Shutdown:** `bridge.shutdown` produces a final frame, then exit 0. **stdin EOF** (the parent died or closed
  the pipe) also exits 0. The bridge never outlives its host.
- **Concurrency:** requests run sequentially in one emulation thread and may be **pipelined** (responses come back
  in order, matched by `id`). A reader thread handles `bridge.cancel` out of band.

### 9.2 Frames (aligned with REA's Hopper bridge NDJSON shape, minus the socket capability token: stdio pipes are private)
```jsonc
// request
{"id": 7, "method": "emu.call", "params": {...}}                  // id: non-negative int or string
// success
{"id": 7, "result": {...}}
// request-level failure (the operation could not be attempted)
{"id": 7, "error": {"code": "unknown_session", "message": "no session 's9'", "data": {...}}}
// zero or more events before the final frame of that id
{"id": 7, "event": {"type": "progress", "completed": 470, "total": 600}}
// unparseable frame
{"id": null, "error": {"code": "parse_error", "message": "Expecting value: line 1 column 1 (char 0)"}}
```
**Emulation outcomes are results, not errors.** A fault, exception, budget stop, or unhandled import is
`{"result": {"status": "fault", "stop": {...}}}`. `error` is reserved for "couldn't run": bad params, unknown
session or symbol, unreadable image, an unsupported combination, an internal bug.

### 9.3 Value encoding
- Integers ≥ 2^53 and all addresses are hex strings (`"0x2ac881540"`). Inputs accept a number, `"0x…"`, or a
  decimal string.
- Floats: input `1.5` | `"NaN"` | `"Infinity"` | `"-Infinity"` | `{"value": 1.5}` | `{"bits": "0x3fc00000"}` (exact,
  including NaN payloads and denormals). Output is always `{"type":"f32","value":1.5,"bits":"0x3fc00000"}`, with
  `value` as a JSON number or one of the strings `NaN`/`Infinity`/`-Infinity`. **Differential comparisons use
  `bits`.**
- Ints out: `{"type":"i32","value":-3,"hex":"0xfffffffd"}`; 64-bit types use a decimal-string `value`. `ptr` is
  hex. `bool` is a JSON boolean.
- Blobs: `{"hex": "..."}` or `{"base64": "..."}`.

### 9.4 Methods

| Method | Params | Result |
|---|---|---|
| `bridge.hello` | `{}` (planned: `{"protocol":"bea-emu/0.1"}` major-version check) | `protocol, bridge, engines, capabilities{arch,formats,abi,snapshots,batch,cancel,trace[],hleImports[]}, limits` |
| `session.open` | `image{path, base?}`, `memory{heapSize,scratchSize,stackSize}?`, `protections:"sections"\|"rwx"`, `imports{builtin:bool, overrides{"dll!name"\|"name": {returns:{type,value\|bits}}\|{action:"stop"}}}?`, `cpu{mxcsr,fpcw}?`, `snapshots:"unicorn"\|"manual"`, `isaGuard:"stop"\|"off"` | `session, image{path,name,sha256,preferredBase,mappedBase,relocated,sizeOfImage,sections[],exports,tlsCallbacks[],tlsCallbacksExecuted:false,delayImports}, imports{total,models{builtin,builtin-inexact,override,unhandled},unhandled[]}, layout[], cpu, snapshots, isa{…}, loaderDeviations[]` |
| `session.info` / `session.close` | `session` | info / `{closed}` |
| `session.snapshot` | `session, name?` | `{snapshot, mode}` |
| `session.restore` | `session, snapshot:"baseline"\|name` | `{restored}` |
| `mem.read` | `session, address, size(≤16 MiB), as?:"f32[]"\|…` | `{address,size,region,hex\|values}` |
| `mem.write` | `session, address, hex\|base64` | `{written}` |
| `mem.disassemble` | `session, target, count≤512` | `{instructions:[{va,rva,bytes,text}]}` |
| `emu.call` | `session, target, args[], returns, options` | call result (§9.5) + `provenance` |
| `emu.callBatch` | `session, target, signature{args[],returns}` **or** `argTemplates[] + returns`, `vectors[][]`, `options` | `summary, columns\|results, faults[], provenance` (+ `progress` events) |
| `bridge.cancel` | `requestId` | `{cancelled: bool}` (answered immediately by the reader thread) |
| `bridge.shutdown` | `{}` | `{shutdown: true}` then exit |

### 9.5 Calls in detail
**`target`**: one of `{"export": "name"}` | `{"rva": "0x15e0"}` | `{"va": "0x…"}` |
`{"staticVa": "0x140123460", "staticBase": "0x140000000"}`. The last form handles static↔runtime rebasing of
Ghidra/REA addresses against `mappedBase`. Planned: `{"module": "name", "rva": …}` for multi-module sessions.

**`args[]`** (Win64 positional classification):
- scalars: `{"type": "i8|u8|i16|u16|i32|u32|i64|u64|ptr|bool", "value": …}`, `{"type": "f32|f64", "value"|"bits": …}`;
- arrays: `{"type": "f32[]|f64[]|i8[]…u64[]", "values": [...]?, "count"?, "align"?, "out"?: true}` → buffer in
  scratch; the pointer is passed;
- `{"type": "buffer", "hex"|"base64"?, "size"?, "out"?}`, `{"type": "cstring", "text": "…"}`;
- `{"type": "struct", "size": 32, "align"?, "hex"?, "fields": [{"name","offset","type","value"|"bits"} |
  {"offset","type":"ptr","to":{…nested arg spec…}} | {"offset","type":"f32[]","values":[…]}], "out"?: true}`;
- `{"type": "symbol", "export": "name"}` (or rva/va), for function pointers and callbacks.

**`returns`**: `"void"`, a scalar type, or `{"type":"struct","size":N}`. Sizes 1/2/4/8 come back in `rax`;
anything else uses a hidden RCX pointer, which the bridge allocates and prepends automatically.

**`options`**:

| Option | Default | Meaning |
|---|---|---|
| `maxInstructions` | 1,000,000 | deterministic budget (`emu_start(count)`); `0` = unbudgeted fast mode |
| `timeoutMs` | 0 | wall-clock safety net via the watchdog (non-deterministic: the evidence notes it) |
| `mxcsr` / `fpcw` | session defaults `0x1F80`/`0x027F` | FP environment at call entry |
| `variadic` | false | duplicate float args into GPRs |
| `countInstructions` | false | block-granular count (block hook; ~0.36 µs per block) |
| `faultPolicy` | `"stop"` | `"map_zero"` (manual-snapshot sessions only; result tagged) |
| `trace` | `{imports:true}` | `{imports, blocks, instructions, memory:"reads"\|"writes"\|"all", disassemble, maxEvents:10000}` |
| batch: `isolation` | `"snapshot"` | `"snapshot"` restores the baseline (or the `from` snapshot) before each vector; `"chain"` lets state flow |
| batch: `resultFormat` | `"objects"` | `"columns"`: `{status[],value[],bits[]}` plus a sparse `faults[]` (≈2.5x smaller) |
| batch: `stopOnFault` | false | stop the batch at the first non-returned vector |
| batch: `fastPath` | true | scalar signatures skip spec parsing (same semantics) |

**Call result**:
```jsonc
{
  "status": "returned" | "fault" | "cpu_exception" | "invalid_instruction" | "unsupported_instruction"
          | "unhandled_import" | "budget_exhausted" | "timeout" | "cancelled" | "stopped" | "engine_error",
  "return": {"type":"f32","value":13.0,"bits":"0x41500000"},          // only when status == "returned"
  "raw": {"rax":"0x8","xmm0":"0x41500000","mxcsr":"0x1f80","fpcw":"0x27f"},
  "outputs": [{"arg":"args[2]","type":"f32[]","address":"0x7e0020000010","values":[...],"bits":[...]}],
  "stop": {                                                               // when status != "returned"
    "fault": {"kind":"read_unmapped","address":"0x18","size":4,"addressRegion":{...}},
    "exception": {"vector":0,"name":"#DE divide error"},
    "importCall": {"import":"kernel32.dll!CreateEventA","callerRva":"0x6480","args":[...],"xmm":[...]},
    "isa": {"instruction":"vxorps","rva":"0x18da","reason":"..."},
    "engineError": {"errno":6,"message":"Invalid memory read (UC_ERR_READ_UNMAPPED)"},
    "pc":"0x…","pcRegion":{...},"instruction":[{"va","rva","bytes","text"}],
    "registers":{...},                                                    // faults and exceptions
    "stackScan":[{"stackOffset":"0x0","va":"0x…","rva":"0x…"} | {"note":"harness return sentinel"}]
  },
  "metrics": {"wallUs":1067.4,"instructions":159,"blocks":36},
  "trace": {"imports":[...],"blocks":[rva…],"coverage":{"0x15e0":1,…},"truncated":false,"instructions":[...],"memory":[...]},
  "events": [{"type":"heap","kind":"invalid_or_double_free","ptr":"0x…"}],
  "deviations": [{"kind":"x87_transcendental_inexact","instructions":[...]},
                 {"kind":"inexact_import_model","imports":["msvcrt.dll!sinf"]},
                 {"kind":"auto_mapped_zero_pages","pages":["0x0"]}],
  "provenance": {...}                                                     // §9.7
}
```

### 9.6 Error codes (request level)
`parse_error`, `frame_too_large`, `invalid_request`, `invalid_params`, `unknown_method`, `unknown_session`,
`unknown_snapshot`, `unknown_symbol` (with `data.exports` sample), `image_unreadable`, `unsupported_image`
(non-x64), `relocation_unavailable`, `layout_conflict`, `unmapped` (mem.read/write), `resource_exhausted` (scratch),
`unsupported_combination` (e.g. `map_zero` with Unicorn snapshots), `engine_unavailable` (fatal ready), and
`internal_error` (with a bounded traceback). Codes are stable snake_case strings. The host maps them to its own
error classes; nothing depends on message text.

### 9.7 Provenance and evidence mapping
Every `emu.call`/`emu.callBatch` result carries:
```json
{"evidence":"emulation","engine":"unicorn","engines":{"python":"3.14.6","unicorn":"2.1.4","unicornCore":"2.1","capstone":"5.0.9","pefile":"2024.8.26"},
 "bridge":"0.1.0","protocol":"bea-emu/0.1",
 "image":{"sha256":"1d9e…79dc","name":"bea_fixture.dll","mappedBase":"0x2ac880000","preferredBase":"0x2ac880000"},
 "target":{"va":"0x2ac8815e0","rva":"0x15e0","export":"bea_norm_copy"},"abi":"win64","mxcsr":"0x1f80","fpcw":"0x27f"}
```
Mapping onto REA's evidence model: an emulated result is a **derivation** (a computation over the image with a
modeled environment). It is *not* a runtime observation of the real process. `deviations[]` and `session.open`'s
`loaderDeviations[]` list everything modeled: DllMain/TLS callbacks not run, HLE imports, inexact math, an
auto-mapped memory "assumption", and so on. Those belong in BEA's "limitations/unknowns" section of a report.
Differential runs that compare emulation to Frida native-oracle calls should cite both provenances. Planned:
`inputDigest` (sha256 of the canonical args) for deduplication and reproducibility.

### 9.8 Tracing (opt-in, bounded)
- `imports` (default on): bounded list of `{import, model, callerRva, args[4], ret}`.
- `blocks`: an ordered list of block RVAs plus a `coverage` map (RVA→hits) with a `truncated` flag. The host can
  export drcov or Lighthouse-style coverage from it and pair it with REA/Ghidra function names.
- `instructions`: an RVA list, optionally disassembled (unique addresses disassembled once).
- `memory`: `{pcRva, access:"r"|"w", address, size, value}`, with read values sampled at hook time.
- `maxEvents` caps every list. Hooks persist per session "hook signature", and the TB cache is flushed on change
  (§2.4 #4).

### 9.9 Snapshot and isolation semantics
- `session.open` takes a **baseline** snapshot after mapping, before any call.
- `restore` resets CPU state, memory, and Python HLE state (heap allocator, TLS slots, counters).
- `isolation:"snapshot"` makes each batch vector independent and order-insensitive: deterministic evidence.
  `"chain"` is faster but order-dependent; use it for pure functions or deliberate stateful sequences.
- The memory layout is frozen under `snapshots:"unicorn"` (no `mem.map`, no `map_zero`). `snapshots:"manual"`
  allows dynamic mapping, and restore unmaps the pages added since the snapshot.

### 9.10 Cancellation, timeouts, limits
- `bridge.cancel {requestId}` stops the in-flight `emu.call`/`emu.callBatch` (re-issued `emu_stop` until it takes
  effect). A batch returns the completed prefix with `summary.cancelled=true`.
- The `timeoutMs` watchdog has 5 ms resolution. A deterministic `maxInstructions` budget is preferred for
  evidence; the timeout is a safety net.
- Progress events fire at most every 250 ms during batches. Limits: 64 MiB per frame, 16 MiB per `mem.read`,
  `trace.maxEvents` per call, ≤4096 ISA-guard hooks per session.

### 9.11 Planned extensions (designed, not implemented)
- **Dump-backed sessions**:
  ```jsonc
  "source": {"kind":"dump",
             "modules":[{"name","path","sha256","base","size"}],
             "regions":[{"base","size","perms","file"|"hex","tag":"module|heap|stack|teb"}],
             "thread":{"teb":"0x…","regs":{…}}}
  ```
  Frida provides the modules (`Process.enumerateModules`), the regions (`Process.enumerateRanges` plus
  `readByteArray`), and the TEB address (`gs:[0x30]` read in-process). The emulator then uses the real TEB/PEB/TLS
  and heap pointers. HLE stubs are installed only for imports whose target module is not in the dump.
- **Multi-module LLE**: load real system DLLs (e.g. ucrtbase math) into the session for bit-exact CRT behavior,
  with an ISA guard on them too.
- `trace.export: "drcov"`, `emu.findCallers` (bounded backtrace by shadow stack), and `hle` scripting via the host
  (an import stops with `needs_host` and the host supplies the return; this enables Frida-oracle-backed imports).
- Per-session x86-32 (`UC_MODE_32`, FS TEB, stdcall/cdecl/thiscall).
- `bridge.hello` version negotiation, and a `capabilities.engineGotchas` list so the host can explain
  limitations to users.

### 9.12 Real transcript (`LAB/transcript.jsonl`, trimmed with `"..."`)
```jsonc
{"event":{"type":"ready","protocol":"bea-emu/0.1","bridge":"0.1.0","pid":28436,"engines":{"python":"3.14.6","unicorn":"2.1.4","unicornCore":"2.1","capstone":"5.0.9","pefile":"2024.8.26"}}}
// > {"id":1,"method":"session.open","params":{"image":{"path":"bea_fixture.dll"}}}
{"id":1,"result":{"session":"s1","imports":{"total":80,"models":{"builtin":32,"builtin-inexact":0,"override":0,"unhandled":48},"unhandled":["kernel32.dll!CloseHandle","kernel32.dll!CreateEventA","kernel32.dll!CreateSemaphoreA","..."]},"isa":{"scanSource":"pdata+gaps","rangesScanned":314,"instructionsScanned":12822,"vexInstructions":8,"bmiAllowed":0,"vexFunctionsRva":["0x18d0"],"x87TranscendentalInstructions":6,"guard":"stop","scanMs":11.9},"snapshots":"unicorn-cpu+memory","cpu":{"mxcsr":"0x1f80","fpcw":"0x27f"},"image":{"name":"bea_fixture.dll","sha256":"1d9e…79dc","preferredBase":"0x2ac880000","mappedBase":"0x2ac880000","relocated":false,"tlsCallbacks":[{"va":"0x2ac881b20","rva":"0x1b20"},"..."],"tlsCallbacksExecuted":false}}}
// > {"id":2,"method":"emu.call","params":{"session":"s1","target":{"export":"bea_norm_copy"},"args":[{"type":"f32[]","values":[3,4,12]},{"type":"i32","value":3},{"type":"f32[]","count":3,"out":true}],"returns":{"type":"f32"},"options":{"maxInstructions":100000,"countInstructions":true,"trace":{"imports":true}}}}
{"id":2,"result":{"status":"returned","return":{"type":"f32","value":13.0,"bits":"0x41500000"},"raw":{"rax":"0x8","xmm0":"0x41500000","mxcsr":"0x1f80","fpcw":"0x27f"},"outputs":[{"arg":"args[2]","type":"f32[]","address":"0x7e0020000010","values":[0.23076923191547394,0.3076923191547394,0.9230769276618958],"bits":["0x3e6c4ec5","0x3e9d89d9","0x3f6c4ec5"]}],"metrics":{"wallUs":1067.4,"instructions":159,"blocks":36},"trace":{"imports":[{"import":"msvcrt.dll!malloc","model":"builtin","callerRva":"0x1602","args":["0xc","0x3","0x7e0020000010","0x0"],"ret":"0x7e0010000010"},{"import":"msvcrt.dll!memcpy","callerRva":"0x161c","...":"..."},{"import":"msvcrt.dll!free","callerRva":"0x173e","...":"..."}]},"provenance":{"evidence":"emulation","...":"..."}}}
// > {"id":3,"method":"emu.call","params":{"session":"s1","target":{"export":"bea_div"},"args":[{"type":"i32","value":7},{"type":"i32","value":0}],"returns":"i32"}}
{"id":3,"result":{"status":"cpu_exception","stop":{"exception":{"vector":0,"name":"#DE divide error"},"pc":"0x2ac881935","pcRegion":{"region":"bea_fixture.dll:.text","kind":"image","offset":"0x935","rva":"0x1935"},"instruction":[{"va":"0x2ac881935","rva":"0x1935","bytes":"f7f9","text":"idiv ecx"}],"registers":{"rip":"0x2ac881935","rsp":"0x7e00300fefd8","rcx":"0x0","...":"all GPRs + xmm0-15"},"stackScan":[{"stackOffset":"0x0","va":"0x7e0000200000","note":"harness return sentinel"}]},"metrics":{"wallUs":25.4},"...":"..."}}
// > batch with a NaN-bits input and an overflow input
{"id":4,"result":{"summary":{"vectors":3,"completed":3,"returned":3,"elapsedMs":0.318,"callsPerSecond":9434.0,"isolation":"snapshot","fastPath":true,"deviations":[],"cancelled":false},"columns":{"status":["returned","returned","returned"],"value":[-7.0,"NaN",-1000.0],"bits":["0xc0e00000","0x7fc00000","0xc47a0000"]},"faults":[],"...":"..."}}
// > {"id":5,...,"target":{"rva":"0x1"}}   (jump into the PE header)
{"id":5,"result":{"status":"fault","stop":{"fault":{"kind":"fetch_protected","address":"0x2ac880001","size":1,"addressRegion":{"region":"bea_fixture.dll:headers","kind":"image","rva":"0x1"}},"engineError":{"errno":14,"message":"Fetch from non-executable memory (UC_ERR_FETCH_PROT)"},"...":"..."}}}
// > {"id":6,...,"options":{"faultPolicy":"map_zero"}}  (on a unicorn-snapshot session)
{"id":6,"error":{"code":"unsupported_combination","message":"faultPolicy 'map_zero' needs a session opened with snapshots: 'manual' (Unicorn memory snapshots require a frozen memory layout)"}}
// > not json
{"id":null,"error":{"code":"parse_error","message":"Expecting value: line 1 column 1 (char 0)"}}
// > {"id":7,"method":"bridge.shutdown"}
{"id":7,"result":{"shutdown":true}}
```

### 9.13 Host-side sketch (TypeScript; zod 4 schemas would mirror these)
```ts
type Hex = `0x${string}`;
type F = { type: "f32" | "f64"; value: number | "NaN" | "Infinity" | "-Infinity"; bits: Hex };
type Frame =
  | { event: { type: "ready" | "fatal"; protocol?: string; engines?: Record<string, string>; code?: string } }
  | { id: number | string; event: { type: "progress"; completed: number; total: number } }
  | { id: number | string | null; result: unknown }
  | { id: number | string | null; error: { code: string; message: string; data?: unknown } };

class EmuBridge {               // one per BEA server process; sessions multiplexed by id
  #pending = new Map<number, (f: Frame) => void>();
  request<T>(method: string, params: object, onEvent?: (e: unknown) => void): Promise<T>;
  cancel(id: number): Promise<{ cancelled: boolean }>;  // bridge.cancel {requestId}
}
// MCP tools map 1:1 onto bridge methods: bea_emu_open / bea_emu_call / bea_emu_batch / bea_emu_snapshot / ...
// with BEA adding: default budgets, result-size caps, evidence wrapping (derivation + deviations), and
// static<->runtime address mapping (target.staticVa/staticBase) from REA/Ghidra function addresses.
```

---

## 10. Open questions
1. **Unicorn licensing.** The unicorn 2.1.4 wheel metadata says "BSD License" [V], but Unicorn's core is, I
   believe, GPLv2 (QEMU-derived) [B]. Before shipping, BEA needs a decision (legal review) on whether to install
   it into a user-local venv at first use, with notices, rather than vendoring `unicorn.dll`. Capstone is BSD and
   pefile MIT [V].
2. **Python provisioning.** Use the user's Python 3.10+, or a uv-managed BEA Python? (The ~250–380 ms bridge
   start is fine either way.) Is pinning `unicorn==2.1.4` acceptable, or should newer Unicorn releases be tracked?
   The gotchas listed here (VEX handling, hook/TB-cache, snapshot+map) must be re-verified per engine version; the
   probe suite in `LAB/` is the start of that.
3. **Dump-backed sessions.** Which capture granularity does the Frida track provide (full module images vs
   touched pages, heap ranges, TEB/TLS)? How should BEA handle pointers into memory that wasn't captured: fault
   with diagnostics (default) or lazy fetch from the live process through Frida (a hybrid "remote memory"
   emulator)?
4. **Native-oracle parity.** For bit-exact differential testing, should BEA call the real function in-process via
   Frida (`NativeFunction`) as the reference, and use Unicorn mainly for tracing and coverage of the same inputs?
   This matters because of CPU-dispatched AVX/FMA paths and x87 inexactness.
5. **Batch result size.** At 20k vectors the response was 0.85–2.1 MB. Should results larger than N MB go to a
   file artifact, with MCP returning a summary plus a path, as in REA's artifact patterns?
6. **Elevation for TTD** (admin) and anti-cheat interactions with debuggers and TTD in games: product policy needed.
7. **cdb in the WinDbg MSIX.** Its exact path and presence should be confirmed after a user-approved install
   (mcp-windbg claims auto-detection).
8. **Unicorn alternatives.** Is a native Node binding for Unicorn 2 worth it (no maintained one known [B]), versus
   the Python bridge? The current per-call IPC overhead is small compared with Python's own overhead (~25 µs per
   vector in batches).

---

## 11. Sources
- Local [V]: `LAB/*` outputs; REA files read: `bridge/hopper_bridge.py:1057-1151` (NDJSON request loop, events,
  errors), `bridge/native/rea_lldb_tracer.py:1-140` (bounded JSONL journal, budgets),
  `src/process/ProviderProcess.ts:30-60` (owned process spawn, Job Object memory limit),
  `src/gdb/GdbSessionManager.ts:744,1170` (MI3), `src/native/LldbCallTracer.ts:191,493-499` (lldb --batch).
- speakeasy: https://pypi.org/pypi/speakeasy-emulator/json , https://pypi.org/pypi/speakeasy-emulator/2.0.0b9/json ,
  https://github.com/mandiant/speakeasy , https://api.github.com/repos/mandiant/speakeasy/commits
- Qiling: https://pypi.org/pypi/qiling/json , https://github.com/qilingframework/qiling ,
  https://api.github.com/repos/qilingframework/qiling/commits?sha=dev
- WinDbg/mcp-windbg/Pybag: `winget show --id Microsoft.WinDbg` (local), https://github.com/svnscha/mcp-windbg ,
  https://pypi.org/pypi/Pybag/json
- TTD: `winget show --id Microsoft.TimeTravelDebugging` (local), `tttracer.exe -?` (local),
  https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/time-travel-debugging-ttd-exe-command-line-util ,
  https://github.com/microsoft/WinDbg-Samples/tree/master/TTD , https://github.com/microsoft/WinDbg-Samples/tree/master/TTD/ReplayApi ,
  https://github.com/commial/ttd-bindings
- x64dbg: `winget search x64dbg` (local), https://github.com/dariushoule/x64dbg-automate ,
  https://github.com/dariushoule/x64dbg-automate-pyclient , https://dariushoule.github.io/x64dbg-automate-pyclient/
- LLDB MCP: https://lldb.llvm.org/use/mcp.html (and the search results pointing to llvm-project PR #143628 and #162752)
- GDB DAP: https://sourceware.org/gdb/current/onlinedocs/gdb.html/Debugger-Adapter-Protocol.html
