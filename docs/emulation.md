# Emulation and differential testing

Written by WP14-EMU: WP14b wrote the TypeScript side, WP14a wrote the Python bridge. DESIGN §5 and annex S5 are the
authoritative design. This page describes what the code in `src/providers/emulator/`, `src/application/emu/`,
`src/application/diff/`, `src/contracts/areas/emulation.ts` and `bridge/emu/` does. For every input and output field
of the three tools, see the generated reference in [tools/emulation.md](tools/emulation.md).

The emulation area has three tools:

| Tool            | What it does                                                                                                                                                                     |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `emu_open`      | Opens a Unicorn session from a PE64 file, a `bea.dump/1` bundle, or a fresh capture of a live session. Records `bea.emu.session`.                                                |
| `emu_call`      | Runs one call, a batch of vectors, or a sweep over many functions, with typed arguments, buffers and named snapshots. Records `bea.emu.run`, `bea.emu.batch` or `bea.emu.sweep`. |
| `diff_function` | Feeds the same vectors to two or three legs (live, emulation, expected) and compares them bit-exactly. Records `bea.diff`; a non-equivalence also records an unknown.            |

Emulation never touches a target. The only target effects in this area come from the live leg of `diff_function`,
which executes target code through `call_function`'s oracle. That is gated exactly like `call_function`:
`call_attached` applies to attached targets.

## Pieces

| Path                                                                               | Role                                                                                                                |
| ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `src/providers/emulator/framing.ts`                                                | NDJSON framing for `bea-emu/0.1`: frames up to 64 MiB, CRLF tolerated, non-finite numbers refused before sending    |
| `src/providers/emulator/EmuBridge.ts`                                              | One bridge process: start checks, requests, progress, out-of-band ping and cancel, deadlines, close escalation      |
| `src/providers/emulator/EmuSessionRuntime.ts`                                      | One emulation session: FIFO request queue, lazy reopen after a lost bridge, identity check, crash-loop limit        |
| `src/providers/emulator/EmuAdapter.ts`                                             | `EmuPort` (frozen `src/ports/emu.ts`): session admission, registration with the session manager, restart deviations |
| `src/providers/emulator/pythonResolver.ts`                                         | Finds the interpreter and probes it with the bridge's `--probe`                                                     |
| `src/providers/emulator/bridgeLocator.ts`                                          | Locates `bea_emu_bridge.py` and checks it against `dist/bridge-manifest.json` (sha256, protocol, requirements lock) |
| `src/providers/emulator/venvProvisioner.ts`                                        | `bea setup --emulator`: plans and applies the BEA-owned venv                                                        |
| `src/providers/emulator/selftestExpectations.ts`                                   | Expected `--selftest` results per Unicorn version                                                                   |
| `src/providers/emulator/createEmulatorService.ts`                                  | Composition: lifecycle closer, `bea_status` row, doctor checks, the once-per-process selftest                       |
| `src/application/emu/EmulationService.ts`                                          | `emu_open` and `emu_call`: address resolution, the shared call model, state lineage, evidence, row streams          |
| `src/application/diff/`                                                            | `diff_function`: legs, the bit-exact comparison, hints, the auto-unknown                                            |
| `src/application/emu/{views,envelope,deviations,coverageBlob,lineage,callPrep}.ts` | Output views, the envelope, coverage and limitations, `bea.coverage/1` blobs, state digests, call preparation       |
| `src/domain/evidence/limitations/emulation.ts`                                     | The BEA-authored limitation sentences of this area                                                                  |

The call model (signatures, buffers, fields, codecs, generators, the Win64 classification and the result codecs) is
the shared one in `src/domain/callModel/`. `emu_call` and `call_function` accept the same `signature`, `buffers`,
`args`, `vectors` and `generate`, and their outputs carry the same bit strings.

## The bridge process

Each emulation session owns one bridge process. The command line is:

```
<python> [prefix args] -I -X utf8 <package>/bridge/emu/bea_emu_bridge.py --mem-limit <bytes> [--cache-dir <BEA_HOME>\emu\cache]
```

- `-I` isolates the interpreter: no user site-packages, no `PYTHON*` environment variables, and no script or current
  directory on `sys.path`. BEA also drops `PYTHON*` variables from the child environment. The working directory is
  `<BEA_HOME>\emu`.
- The bridge must write `ready` (or `fatal`) as its first line within `emu.startup_timeout_ms`, then answer
  `bridge.hello`. BEA checks the protocol (`bea-emu/0.1`), the bridge sha256 and the engine versions. A mismatch is
  `capability_unavailable` with `bea setup --emulator` or `bea doctor --backend emulation` as the remediation.
- stdout carries only protocol frames. stderr is logged at debug level and is never copied into tool output.
- Requests to one session are serialized in FIFO order. Progress frames become MCP progress notifications. A deadline
  or a client cancel sends `bridge.cancel` out of band. A bridge that does not answer within 2 s is killed. The bridge
  gets the tool deadline minus a margin, and BEA keeps a 1 s backstop of its own.
- Outcomes (`returned`, faults, ISA stops, budget exhaustion and so on) are results with a status. A bridge `error`
  means the request was not attempted. `src/providers/emulator/errors.ts` maps each bridge error code to a BEA error
  (S5 §12).
- Closing a session (`close_session`, idle reaping or server shutdown) sends `bridge.shutdown`, closes stdin and kills
  the process at 900 ms (CT-M9). This fits inside the 1,300 ms teardown-targets budget. Both the launcher pid and the
  interpreter pid are reported in `emu_open.bridge`, and the test lanes check that neither outlives the session.

### When a bridge dies

A crash, a kill or a protocol violation ends the request in flight. That request fails with
`capability_unavailable` (`bridge-lost`, retryable), with the exit code and generation in its diagnostics. The
session is not closed. The next request starts a new bridge (generation + 1), reopens the same image or bundle, and
checks that the identity is unchanged: primary sha256, mapped base, ISA site counts and import models. A changed
identity is `evidence_integrity_mismatch`.

The first result after a restart carries a one-time `bridge_restarted_state_reset` deviation. Named snapshots do not
survive a restart. `session_status` lists them under `lost_snapshots`, and `state.from: "<name>"` then fails with
`invalid_request`. Three losses within 10 minutes mark the session failed, and further requests answer
`execution_failure`. At that point, close it and open a new one.

## Finding Python

Resolution runs once per server process. A failed start and a completed `bea setup --emulator` both clear it.

1. `BEA_PYTHON`, which must be an absolute path.
2. `python` in `config.json`.
3. The BEA venv at `<BEA_HOME>\emu\venv`, created by `bea setup --emulator` and marked by `bea-emu.json`.
4. `PATH`: `python`, then `py -3` on Windows; `python3`, then `python` elsewhere.

BEA checks each candidate by running the bridge itself with `--probe` under `-I`. It reads package versions from
distribution metadata. A Windows Store alias that exits with 9009 counts as "not found". The pins are:

- `exact`: Python 3.10 or later, `unicorn 2.1.4`, `capstone 5.0.9` and `pefile 2024.8.26`.
- `compatible`: `unicorn 2.1.x`, `capstone 5.x` and `pefile` present.
- `mismatch`: anything else. The candidate is rejected.

An explicit setting never falls through. If `BEA_PYTHON` or the config `python` is broken, that is the error, and
BEA does not silently try the next candidate. A `BEA_PYTHON` path that does not exist is `configuration_invalid`. An
existing file that is not a usable Python is `capability_unavailable`. When the packages are installed only in the
user site, which `-I` hides, the remediation says so (CT-M11).

The selftest (`--selftest`) runs once per process at the first open. By default (`emu.selftest: "auto"`) it runs only
when the pin is `compatible`. With `"always"` it runs on every pin, and with `"never"` it is skipped. Its result is
compared with `selftestExpectations.ts` and shown in `bea_status`.

| Setting                                           | Default | Meaning                                                                            |
| ------------------------------------------------- | ------- | ---------------------------------------------------------------------------------- |
| `BEA_PYTHON` / `config.json` `python`             | unset   | The interpreter (absolute path)                                                    |
| `emu.max_sessions` / `BEA_EMU_MAX_SESSIONS`       | 4       | Concurrent emulation sessions (1–16); one more is `resource_constraint`            |
| `emu.memory_limit_mb` / `BEA_EMU_MEMORY_LIMIT_MB` | 4096    | The bridge's own memory cap (`--mem-limit`); exceeding it is `resource_constraint` |
| `emu.startup_timeout_ms`                          | 15000   | Time allowed for the `ready` line                                                  |
| `emu.isa_cache` / `BEA_EMU_ISA_CACHE`             | true    | Caches ISA scans under `<BEA_HOME>\emu\cache` (`isa.cache: hit` on reopen)         |
| `emu.selftest` / `BEA_EMU_SELFTEST`               | auto    | `auto`, `always` or `never`                                                        |

### `bea setup --emulator`

`createEmulatorProvisioner` plans a BEA-owned venv at `<BEA_HOME>\emu\venv`. The plan shows:

- the tool: `uv`, or `venv` plus `pip`
- the base CPython: 3.10 or later, 64-bit
- the packages, pinned with hashes from `bridge/emu/requirements.lock`
- the network origins
- the exact commands: `--require-hashes`, `--only-binary :all:` and `--no-deps`

Apply takes `<BEA_HOME>\emu\.setup.lock` and builds the venv in `venv.staging-<id>`. It probes the result for the
`exact` pin, runs the selftest and writes the `bea-emu.json` marker. Then it swaps the staging directory into place
and probes again. Any failure rolls back. A directory without BEA's marker is never replaced. Global site-packages
are never touched.

### Status and doctor

`bea_status` has an `emulator` backend row. It shows `not-loaded` until the first resolution, then `available` or
`unavailable` with the Python source and pin, the memory cap, the open sessions and the selftest result.

| Doctor check            | Scope               | Checks                                                           |
| ----------------------- | ------------------- | ---------------------------------------------------------------- |
| `emulation:bridge-file` | `backend:emulation` | The bridge script exists and matches `dist/bridge-manifest.json` |
| `emulation:python`      | `backend:emulation` | Resolution: every candidate and its outcome                      |
| `emulation:pins`        | `backend:emulation` | Exact, compatible (warning) or mismatch                          |
| `emulation:venv`        | `backend:emulation` | The BEA venv marker and its ownership (optional)                 |
| `emulation:selftest`    | `probe`             | Runs `--selftest` and compares it with the expectations          |
| `emulation:start`       | `probe`             | Starts the bridge and completes `bridge.hello`                   |

## `emu_open`

Give exactly one source.

- **`image_path`**: a PE64 file on disk. The emulator maps the file image, so globals hold their on-disk values.
  `image_base` rebases it. Entry points and TLS callbacks are not run, and each such case is reported as a
  `loader_deviations` entry.
- **`dump_path`**: a `bea.dump/1` bundle from `dump_memory {format: "bundle"}`. BEA verifies the bundle before
  opening it. Module images carry their runtime `.data`, and the extra regions and thread contexts are mapped at their
  runtime addresses. `thread_id` picks the thread whose TEB and FP state are used.
- **`live_session_id`**: captures a bundle of a live session now, through `dump_memory`'s capture, and opens it.
  `capture_modules`, `capture_regions` and `capture_thread_id` choose what to capture. Code under BEA's hooks is
  captured with its original bytes restored (CT-I6). The capture is recorded as evidence and its id is returned in
  `capture`.

The bridge then runs the ISA guard. With `isa_guard: "stop"` (the default), an INT3 guard is placed on the first
VEX/EVEX instruction of each function, so AVX code stops with `unsupported_instruction` instead of executing wrongly.
x87 transcendental instructions, legacy-SSE instructions Unicorn computes differently from hardware (`rcpss`,
`rcpps`, `rsqrtss`, `rsqrtps`, `dpps`, `dppd`; site class `sse_inexact`), MXCSR/x87 status reads, CPUID, RDTSC and
syscalls are counted by site; x87, SSE, status-read, RDTSC and RDRAND sites get per-address tag hooks (at most 512),
so a vector that executes one carries the matching deviation (`x87_transcendental_inexact`, `sse_approx_inexact`,
`fp_status_flags_unmodeled`, …). Scans are cached per code digest under the key `bea-isa/2`. Imports are
bound to the built-in HLE models; `imports.overrides` can replace a model, return a constant, or stop. Unhandled
imports stop the call with `unhandled_import` and the caller's RVA. `patches` write bytes before the baseline is
taken. The FP environment comes from, in order: an explicit `fp`, the dump thread's FP state, or the Windows defaults
(MXCSR `0x1f80`, FPCW `0x27f`).

The output reports the image identity, the modules, the import counts by model, the ISA report, the memory layout,
the bridge (both pids, version, engines, Python source and pin) and `baseline_state`, which is the session's `es_`
state digest. The session appears in `session_status` with kind `emulation`. `close_session` closes it.

## `emu_call`

- **Single call**: `args`, plus `fields` for buffer fields. The output has `call` with `status`, `attribution`
  (`target` or `harness`), `ret` (value and bits), `outputs` for `out` buffers, the stop or fault site, deviations and
  optional trace data. A call that is still running when the tool deadline (`timeout_ms`) comes ends as `timeout`
  (harness, `stop.cause: "deadline"`, not deterministic), inside `timeout_ms`; `budget.timeout_ms_per_call` sets a
  tighter per-call watchdog (`stop.cause: "watchdog"`).
- **Batch**: `vectors` (columns) or `generate` (seeded distributions; S5 §7.6). The output has `batch` with per-status
  counts, up to 16 preview rows, inline columns up to `inline_limit` (default 64), and up to 4 fault details. Larger
  batches stream as an `emu-batch` row stream (`stream_id`). A batch stopped by its deadline or a cancel returns the
  completed prefix and a `vector_offset` continuation. So does a `chain` batch whose next vector's `heap`-placement
  buffers no longer fit the emulated heap: the bridge reports `summary.stopped {code, message, index}`, nothing of
  that vector ran, and the session holds the state after the prefix.
- **Out buffers** come back whole, in single calls and batches (the bridge used to cut them at 1 MiB and 4 KiB, and
  the cut bytes decoded as zeros). One result carries at most 56 MiB of out-buffer hex, `Σ(2 × size + 3)` per
  vector; a request over that is refused before anything runs (bridge `invalid_params` with `maxVectors`).
- **The emulated heap** (`memory.heap_mb`) serves the HLE `malloc`/`calloc`/`realloc`/`free` models best fit from a
  coalescing free list, with a 16-byte gap before every block; `realloc` resizes in place when it can. An allocation
  that does not fit returns NULL and adds `hle_heap_exhausted`. `heap`-placement buffers are allocated like guest
  blocks and stay allocated in the session state, one per vector in a `chain`.
- **Sweep**: `sweep.targets` or `sweep.module` with an RVA range. Each function runs on the probe vectors, and the
  optional `sweep.match` names known unary or binary math functions within `tolerance_ulp`. Rows stream as `emu-sweep`.

Every vector starts from the chosen state:

- `state.from` names the starting state: `baseline`, `current` or a saved name. Snapshots are copy-on-write.
- `state.writes` writes values or bytes first.
- `state.save_as` keeps the end state under a name, and `state.drop` forgets names.
- `isolation: "chain"` runs the vectors one after another on the same state.

Each result reports the input and output state digests (`es_…`), so evidence shows exactly which state a value came
from. `budget.max_instructions` (default 1,000,000) ends a runaway call with `budget_exhausted`, a harness status
that is never mistaken for a value. `trace.coverage` adds a `bea.coverage/1` blob (role `coverage`) of
module-relative translation blocks, which `export_coverage` turns into drcov.

## `diff_function`

`diff_function` needs at least two legs:

- **live** (`live_session_id`): the oracle thunk of `call_function`, which keeps the exact bits.
- **emulation** (`emu_session_id`).
- **expected**: `expected.columns`, or the return values of a hook recording given as `from_recording`.

The target address is resolved once per leg, as module+RVA or an export. If the live module and the emulated image are
different binaries, or a digest is unknown, the call is refused with `invalid_request` unless you pass
`allow_image_mismatch: true`. A raw `0x` address is refused when there is a live leg, because the same VA can mean
different code in the two legs. The one exception is an emulation session captured from that same process instance.

Buffer `init_from` contents are read once and fed to every leg. They come from the live process when there is a live
leg, and from the emulation session otherwise. The FP environment is resolved once and applied to every leg
(D-INT-43).

The emulation leg runs first, with about 45% of the time budget. The live leg then runs over the range the emulation
leg completed. A live leg that loses its target counts as inconclusive.

The comparison is bit-exact per column. ulp, abs and rel statistics, the worst vectors and the tolerance counts are
reported, but tolerances never change the verdict. A vector is inconclusive when one side is a harness stop or did not
run. With `inconclusive: "count"` (the default), an inconclusive vector makes the pair unknown unless another vector
differs. With `"exclude"`, inconclusive vectors are left out.

There are three verdicts:

- `equivalent-on-tested-inputs`: every compared vector is bit-equal.
- `differ`: at least one vector differs, by outcome class, fault site or value.
- `unknown`: there is no difference, but something was inconclusive or nothing was compared.

Hints come from a closed list in `src/application/diff/hints.ts`, for example `cpuid_dispatch`, `x87_inexact`,
`file_image_state`, `hle_math_model` and `nan_payload_only`. When the verdict is not equivalent and `record_unknown`
is on (the default), an unknown is recorded with a deterministic question and the hints' probes. Up to 64 compact rows
are returned inline; more rows go to a `diff` row stream that includes the inputs.

## Evidence

| Predicate         | Recorded by                | Confidence                   | Notes                                                      |
| ----------------- | -------------------------- | ---------------------------- | ---------------------------------------------------------- |
| `bea.emu.session` | `emu_open`                 | observed                     | authority `emulation`; the dump-capture evidence is linked |
| `bea.emu.run`     | single `emu_call`          | observed                     | coverage blob when traced                                  |
| `bea.emu.batch`   | batch `emu_call`, diff leg | observed                     | `emu-batch` stream for large batches                       |
| `bea.emu.sweep`   | sweep `emu_call`           | observed                     | `emu-sweep` stream                                         |
| `bea.diff`        | `diff_function`            | derived (the weakest parent) | links the legs' evidence; `diff` stream; the auto-unknown  |

The subject of emulation evidence is the emulated image, not a process. It carries `image_sha256`, `config_digest`
(the session's open parameters) and `state`. The `basis` in `state` is `baseline`, `snapshot`, `chained` or `dump`,
and `digest` is the `es_` state digest. Coverage and limitations use the sentences in
`src/domain/evidence/limitations/emulation.ts`, for example HLE imports used, emulation deviations, ISA-guard stops,
deadline or cancel, and row caps.

## Testing

| Lane         | Command                                                                                                          | Needs                                                                           |
| ------------ | ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| unit         | `npx vitest run --project unit tests/unit/emu/`                                                                  | Node                                                                            |
| MCP boundary | `npx vitest run --project mcp-boundary tests/boundary/mcp/emulation/`                                            | Node (the fake bridge)                                                          |
| real bridge  | `npm run test:emu` or, from a snapshot, `BEA_DIST_DIR=<snapshot> npx vitest run --project emu-boundary`          | Python with unicorn 2.1.x, gcc                                                  |
| bridge suite | `python -I bridge/emu/tests/run_tests.py [-q] [-k NAME]` (also run by `test:emu`)                                | Python with unicorn 2.1.x, gcc                                                  |
| acceptance   | `BEA_DIST_DIR=<snapshot> npx vitest run --project acceptance tests/acceptance/emulation/`                        | the built server, Python, gcc; the parity file also needs Frida and bea-jobhost |
| receipt      | `npm run verify:emulation`, or `BEA_DIST_DIR=<snapshot> node scripts/verify-emulation.mjs [--out f] [--no-live]` | as acceptance                                                                   |

- The fake bridge (`tests/support/emu/fakeBridge.mjs`) is a Node implementation of `bea-emu/0.1`. It is launched
  exactly like the real one, and scenario files script its results, delays, crashes, ignored cancels, sha mismatches
  and fatal `ready` lines. The unit and MCP-boundary lanes use it, so they need no Python.
- `tests/golden/emu/mathlib.json` holds bits-only goldens for `mathlib.dll`. The real-bridge lane and the receipt
  replay them.
- `scripts/verify-emulation.mjs` prints one JSON receipt (`bea.verify-emulation/1`). It covers the emulator checks,
  the S5 §9.6 parity set through `diff_function` live vs emulation (`four_floats` under RN, FTZ+DAZ and RZ,
  `mix_args`, `car_energy`, and `bea_dispatch`, which differs with `cpuid_dispatch` on an AVX2 host), the dump-backed
  `physics_step` on the runtime `g_car`, the capture under a hook, and a check that no process is left running. Exit
  codes: 0 when every check passed, 1 when a check failed, and 2 when nothing failed but some checks were skipped for
  a named reason.
- Named skips are only for a missing toolchain: `EMU_SKIP` (no Python with unicorn 2.1.x), `GCC_SKIP`, `FRIDA_SKIP`
  and `JOBHOST_SKIP`.

## Known limitations

- `session_status` does not show an emulation session's current state digest. The digest lineage lives in the
  application layer, so each `emu_call` result reports its own digests instead.
- Inline `diff_function` rows are compact: each has the leg statuses and bits and the per-pair results, but not the
  inputs or output fields. The `diff` row stream has the full rows.
- Unicorn's x87 transcendental instructions are approximate, and the emulator does not set MXCSR/x87 status flags.
  Results that depend on them carry deviations and hints. Trust the live leg for them.
- Unicorn computes `rcpss`/`rcpps`/`rsqrtss`/`rsqrtps` exactly (hardware uses a vendor-specific approximation
  table, so no emulator matches it bit for bit), sums `dpps` products sequentially instead of `(p0+p1)+(p2+p3)`, and
  loses the sign of a zero `dpps`/`dppd` sum. Measured by running the same instruction bytes natively and in Unicorn
  2.1.4 on random and special inputs; `haddps`, `hsubps`, `addsubps`, `sqrtss`, `roundss`, `minps`, `cvt*` and the
  basic arithmetic matched except for NaN payloads. Vectors that execute one of the six carry `sse_approx_inexact`.
  Computing `dpps` exactly in a hook (summation order under the MXCSR rounding mode) is possible but not done.
- When both operands of an SSE operation are NaN, Unicorn's NaN-propagation rule differs from the CPU's, so the
  result's NaN payload can differ (`nan_payload_only` in a diff).
- The emulated CPUID reports no AVX or AVX2, so feature-dispatched code takes its non-AVX path, as `bea_dispatch`
  shows in the receipt.
- `bea setup --emulator` is tested with a scripted command runner, and the test lanes never download packages. It
  was run end to end once at acceptance: about 42 s with uv and the downloads, an `exact` venv, and the server then
  resolved it as `bea-venv`.
- `query_events {stream_id}` does not work yet on the emulation row streams (`emu-batch`, `emu-sweep`, `diff`):
  streams without a process get no `bea.stream.manifest`, so the query has no parent evidence to cite and fails with
  an internal error. The inline columns, the preview rows and the records themselves are unaffected.
- The sweep matcher compares return registers only, so a function that leaves `xmm0` untouched (it returns in `rax`,
  or ignores its float argument) matches `identity`. Read `identity` matches as "did not change xmm0".
