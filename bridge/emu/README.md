# BEA emulator bridge (`bea-emu/0.1`)

`bea_emu_bridge.py` is the process that runs BEA's emulation sessions (`emu_open`, `emu_call`, the emulation leg of
`diff_function`). It is one self-contained Python file. It needs Python 3.10 or later, the standard library, and
three engines pinned in `requirements.lock`: unicorn 2.1.4, capstone 5.0.9 and pefile 2024.8.26. BEA starts one bridge
per emulation session and talks to it over stdin/stdout. You do not run it by hand.

- **Setup.** `bea setup --emulator` creates a BEA-owned virtual environment from `requirements.lock`. The install uses
  hash-checked binary wheels only (`--require-hashes --only-binary :all: --no-deps`). Alternatively, set `BEA_PYTHON`
  to an interpreter that already has the three packages.
- **Check.** `bea doctor --backend emulation --probe` runs the bridge's `--probe` and `--selftest` modes and checks
  the interpreter.

## Protocol

The canonical wire types are in `src/domain/emuProtocol.ts`, and the call-plan types are in `src/shared/callPlan.ts`.
This file mirrors them exactly.

### Command line

```
"<python>" -I -X utf8 bea_emu_bridge.py --mem-limit <bytes> [--cache-dir <dir>] [--probe | --selftest]
```

- `-I` keeps the user's environment, user site-packages and the working directory out of the import path.
- `--mem-limit` puts the bridge in its own Windows Job Object (`JOB_OBJECT_LIMIT_PROCESS_MEMORY`) before unicorn is
  imported. On Linux it uses `RLIMIT_DATA` instead, on a best-effort basis.
  - `0` disables the limit.
  - When the flag is absent, the limit is `BEA_EMU_MEMORY_LIMIT_MB` (default 4096) MiB.
- `--cache-dir` keeps the ISA-scan cache in `<dir>/isa/*.json`. The cache is capped at 512 MiB and the oldest files
  are pruned first, at bridge start.
- `--probe` prints one JSON line with the versions and the bridge's own sha256. It exits 0, or 3 when the engines are
  missing.
- `--selftest` checks the engine behaviours BEA's design depends on and prints one JSON line.

### Framing and requests

- **Frames.** One compact JSON object per line, at most 64 MiB in each direction. `\r\n` is accepted.
  - The first stdout line is `{"event":{"type":"ready",…}}`, or `{"event":{"type":"fatal",…}}` followed by exit 3.
  - stderr carries free-form logs.
- **Requests.** `{id, method, params}`, where `id` is a positive integer.
  - Queued methods run one at a time, and their final frames arrive in request order.
  - Progress frames `{id, event:{type:"progress",…}}` may come before a final frame.
  - `bridge.cancel` and `bridge.ping` are answered at once by the reader thread, so their replies can arrive in
    between other frames.
- **Outcomes are results.** Faults, CPU exceptions, unhandled imports, budgets, timeouts and cancellations are all
  `result`s with a `status` and an `attribution` (`target` or `harness`). An `error` frame means the request could not
  be attempted.

### Methods

| Group       | Methods                                                                                                                  |
| ----------- | ------------------------------------------------------------------------------------------------------------------------ |
| bridge      | `bridge.hello`, `bridge.ping` (out of band), `bridge.cancel` (out of band), `bridge.shutdown`                            |
| sessions    | `session.open` (a PE64 image or a `bea.dump/1` bundle), `session.info`, `session.close`                                  |
| named state | `state.save`, `state.restore`, `state.list`, `state.drop`                                                                |
| memory      | `mem.read`, `mem.write`, `mem.disassemble`, `mem.regions`, `mem.functions`                                               |
| emulation   | `emu.call` (one vector, full detail), `emu.batch` (columnar), `emu.sweep` (many targets with the known-function matcher) |

The bridge does no ABI reasoning. TypeScript classifies every Win64 call and sends a plan that already holds raw bits.

### Exit codes

| Code | Meaning                          |
| ---- | -------------------------------- |
| 0    | `bridge.shutdown` or stdin EOF   |
| 2    | usage error                      |
| 3    | engines unavailable              |
| 70   | a bug (stderr has the traceback) |

## Behaviour worth knowing

- **Snapshots.**
  - The baseline and one temporary context per batch are Unicorn copy-on-write (COW) contexts.
  - Named snapshots are host copies of the writable memory plus a CPU-only context.
  - The bridge never restores a COW context newer than the last one it restored. Doing so is a native crash in
    unicorn 2.1.4.
- **Writes to read-only memory.** In a session with COW snapshots and section protections, the host cannot write
  read-only memory after the baseline, so `mem.write` and `state.writes` into code or read-only data return
  `unsupported_combination`.
  - Verified on this host: once a CPU+memory context exists, unicorn 2.1.4 fails such writes with
    `UC_ERR_WRITE_UNMAPPED` and refuses `mem_protect` with `UC_ERR_ARG`.
  - To change those bytes, use `patches` at open (they are applied before the baseline), or open the session with
    `protections: "rwx"` or `snapshots: "manual"`.
- **ISA guard.**
  - A VEX/EVEX site that a skipdata-free decode from a `.pdata` function start reaches has its first byte replaced by
    `INT3` in emulator memory. The emulator stops there with `unsupported_instruction`, so such code never silently
    mis-executes.
  - Other VEX/EVEX sites get per-address hooks, up to 256.
  - Reads, disassembly and stack scans show the original bytes.
  - x87 transcendental, approximate legacy-SSE (`rcpss`, `rcpps`, `rsqrtss`, `rsqrtps`, `dpps`, `dppd`: Unicorn's
    results differ from the hardware's), FP-status, `rdtsc` and `rdrand` sites are tagged as deviations (at most 512
    tag hooks). The scan cache key is `bea-isa/2`; scans cached under `/1` predate the SSE class and are not reused.
- **Out buffers** come back whole in `emu.call` and `emu.batch`. A request whose out-buffer hex would exceed 56 MiB
  (`Σ(2 × size + 3)` per vector) is refused with `invalid_params` (`data.maxVectors`) before anything runs;
  `bridge.hello` reports the budget as `limits.maxOutHex`.
- **HLE heap.** `malloc`/`calloc`/`realloc`/`free` use a best-fit, coalescing free list over `memory.heapBytes`
  (snapshotted with the rest of the HLE state); `realloc` resizes in place when it can. A guest allocation that does
  not fit returns NULL and counts as the `hle_heap_exhausted` deviation. `heap`-placement buffers persist in the
  session state; a `chain` batch whose next vector's buffers do not fit returns the completed prefix with
  `summary.stopped` (nothing of that vector ran, its allocations were rolled back).
- **Determinism.** Every call starts from a fixed CPU environment:
  - MXCSR from the plan with its status flags cleared;
  - FPCW from the plan;
  - empty x87 tags;
  - RFLAGS `0x202`;
  - every non-argument register zeroed.

  A budget stop is a status, never a value.

## Tests

```
python -I bridge/emu/tests/run_tests.py [-k PATTERN] [-q]
```

- The tests start the real bridge on the gcc-built fixtures from `npm run build:fixtures`. Set `BEA_EMU_FIXTURE_DIR`
  to use another fixture directory.
- They skip with a named reason when unicorn, capstone, pefile or gcc is missing.
- The dump lane captures the test's own process (Windows only).

## Licensing

- The unicorn wheel's metadata says "BSD License", but Unicorn's QEMU-derived core is believed to be GPLv2.
- BEA never vendors or redistributes the engines. `bea setup --emulator` installs them from your package index into a
  user-local venv, on request.
- capstone uses the BSD license and pefile uses MIT.
