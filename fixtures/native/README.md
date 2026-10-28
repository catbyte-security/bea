# Native test fixtures

Sources of the Windows x64 programs BEA's process, acceptance and emulation lanes run against (DESIGN §8.1, S6 §10.1).
Binaries are build outputs, never committed: `npm run build:fixtures` (also run by the acceptance lane's
`tests/globalSetup.ts`) compiles them with WinLibs gcc into `.cache/fixtures/<key>/` and writes `manifest.json`
next to them. The emulator fixtures live in `../emu/`.

| Fixture        | Source       | What it gives                                                                                                                                                                                                                                            |
| -------------- | ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `game_sim.exe` | `game_sim.c` | ~60 Hz "racing game" loop: `Car` (0x80 B; `speed` +0x08 with a single writer `physics_step`, `rpm` +0x14 written by `physics_step` and `engine_update` on two threads), static root `[[g_world]+8]+8`, float-argument exports, markers, `--ballast-mb N` |
| `crashy.exe`   | `crashy.c`   | deterministic crashes with real NTSTATUS exit codes; every faulting instruction is in an exported function                                                                                                                                               |
| `behavior.exe` | `behavior.c` | known, confined, self-cleaning file / registry / network / process / module / memory activity (the `trace_api` oracle)                                                                                                                                   |
| `mathlib.dll`  | `mathlib.c`  | pure functions and edge cases (VEX, x87, #DE, infinite loop) at the fixed image base 0x180000000                                                                                                                                                         |
| `pidcheck.exe` | `pidcheck.c` | test-only leak oracle: `{pid, alive, creation100ns, matches, exit_code}`                                                                                                                                                                                 |

Rules:

- **Read addresses from the manifest, never from documents.** `manifest.artifacts.<id>.pe.exportRvas`, `.pe.pdata`
  and `.expectations` (speed writer, rpm writers, crash sites, VEX functions, …) come from the PE headers and
  `objdump -d -M intel` of the build at hand.
- The builder fails with a "fixture invariant" error unless: exactly one `speed` store (in `physics_step`); the `rpm`
  writers are exactly `{physics_step, engine_update}`; `tiny_add` ≤ 5 bytes; the crashy return sites exist;
  `mathlib.dll`'s ImageBase is 0x180000000; the emulator fixtures export every S5 §14.2 symbol; no artifact imports
  a MinGW runtime DLL (`libgcc_s*`, `libstdc++*`, `libwinpthread*`), so fixtures run without the toolchain on PATH.
- Without gcc/objdump the builder returns `{unavailable: reason}` and tests skip with that reason (named skip).
- `behavior.exe`'s registry step writes and deletes `HKCU\Software\BEA-Fixture\<key>`; network traffic stays on
  127.0.0.1; files stay inside `--out-dir`.
- `fixtures/golden/pe32-minimal.bin` is the only committed binary: a 1 KiB PE32 (i386) image header for the
  `unsupported_target` refusal and PE-parser tests.

Build lines (all with `-Wl,--no-insert-timestamp`; DLLs are linked from the staging directory with relative output
names, because MinGW ld derives an automatic image base from the output path):

| Artifact              | Flags                                                            |
| --------------------- | ---------------------------------------------------------------- |
| `game_sim.exe`        | `gcc -O2 -fno-math-errno -Wall`                                  |
| `crashy.exe`          | `gcc -O2 -fno-optimize-sibling-calls -Wno-infinite-recursion`    |
| `behavior.exe`        | `gcc -O2 … -lws2_32`                                             |
| `mathlib.dll`         | `gcc -O2 -fno-math-errno -shared -Wl,--image-base,0x180000000`   |
| `pidcheck.exe`        | `gcc -O2`                                                        |
| `bea_emu_fixture.dll` | `gcc -O2 -shared -static -fno-builtin-sqrtf -fno-builtin-memcpy` |
| `live_fixture.exe`    | `gcc -O2`                                                        |
| `cxx_catch.dll`       | `g++ -O2 -shared -static`                                        |
