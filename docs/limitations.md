# Known limitations (v0.1)

What BEA v0.1 does not do, does only partly, or has not verified, with the workaround where one exists. Results
state the limitations that apply to them in their `limitations` field; this page is the product-level list. The
integrator (WP18) reconciles it with the release (see also [decisions.md](decisions.md) and the design's risk
register).

## Platform and targets

| Limitation                       | Detail                                                                                                                                                                                                                                                     | Workaround                                                                         |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| Windows x64 user mode only       | 32-bit (WoW64) programs are `unsupported_target`; no kernel, drivers or remote Frida devices; macOS is not supported                                                                                                                                       | analyze 32-bit programs with other tools                                           |
| Linux x64 is best effort         | same catalog where cheap; containment is a process group (not crash-safe); `trace_api` is unavailable                                                                                                                                                      | use Windows for anything that matters                                              |
| Tested on Windows 11 x64 only    | Node.js 24.x only (`engines` `^24.11.0` with `engine-strict`: `npm ci` refuses Node 25 and 26 with `EBADENGINE`), Frida 17.23.2                                                                                                                            | use Node 24 (24.11 or newer)                                                       |
| Protected and critical processes | PPL, critical, session-0, system, other-user and higher-integrity processes are refused                                                                                                                                                                    | —                                                                                  |
| Anti-cheat                       | targets with anti-cheat signals are refused unless the user overrides; the signal lists are heuristics and cannot see kernel-only anti-cheat; on attach, anti-cheat modules the process already loaded are seen only after injection (SEC-6, partly fixed) | do not analyze protected online games                                              |
| Brokered launches                | programs relaunched by Steam or another launcher, and work done through COM, services or the shell, run outside BEA's job object (`BROKERED_LAUNCH`)                                                                                                       | attach to the relaunched process                                                   |
| Spawn-to-adoption window         | a spawned program exists (suspended) for a few tens of milliseconds before its job adopts it; if the server dies in that window it stays suspended and outside any job (LIFE-4)                                                                            | end it with Task Manager                                                           |
| Environment allowlist            | spawned programs get an OS allowlist plus the caller's `env`; a program that needs another server variable fails                                                                                                                                           | pass it in `env`, or the user sets `spawn.env_mode: "inherit"`                     |
| Script interpreters and LOLBins  | refused as spawn targets by name, by location (Windows directory, execution aliases, interpreter installs) and by version resource; the lists are heuristics                                                                                               | the user sets `spawn.allowed_programs` (one program) or `spawn.allow_interpreters` |
| No stdin forwarding              | spawned programs get an empty stdin pipe (`STDIN_EMPTY_PIPE`)                                                                                                                                                                                              | —                                                                                  |
| Local paths only                 | programs, `cwd` and input paths (`pe_path`, `image_path`, `dump_path`, import paths) on UNC, device or network-resolving paths are refused (SEC-2)                                                                                                         | copy the file to a local drive                                                     |
| No re-adoption                   | owned targets do not survive a server restart; there is no keep-alive                                                                                                                                                                                      | —                                                                                  |
| Captured output                  | at most 3 sessions with captured stdout/stderr; more need `capture_output:false`                                                                                                                                                                           | —                                                                                  |

## Injection footprint

Attaching or spawning loads `frida-agent.dll` and about 24 system DLLs, starts 3 thread-pool threads and patches a
few system-DLL functions; 11 DLLs stay loaded after detach (`AGENT_FOOTPRINT`). The agent module is cloaked from
BEA's own module lists (`AGENT_CLOAKED`). Programs with anti-debugging or integrity checks may notice, change behavior
or exit. BEA has no stealth features.

Frida extracts its agent (about 45 MB) once per server process. BEA points that extraction at
`BEA_HOME\tmp\frida\<run_id>` (only while it attaches) and removes it at a graceful exit; a server that was killed
leaves its directory until the next server's first attach reclaims it. A directory that an attached process still maps
(an agent that could not be unloaded) stays until that process exits (LIFE-3). Frida writes its extraction with
MAX_PATH-limited calls, so when `BEA_HOME` is longer than about 149 characters BEA leaves the extraction in `%TEMP%`
as before (removed at a graceful exit, left behind by a killed server).

## Symbols and addresses

- Names come from exports, `.pdata` function bounds, and symbol tables the caller registers from Ghidra/REA. PDB
  symbolization is not verified (no MSVC/PDB fixtures on the test host). `sym` is never a nearest-export guess.
- Static addresses use the preferred base from the file on disk; a Ghidra program rebased elsewhere needs the
  explicit `/0xBASE` form.
- JIT code and code without `.pdata` have no function bounds; their frames have no `func`.

## Behavior profiles (`trace_api`)

Rows travel on the profile's own stream (no core flow control); on a very fast exit the last ~50 ms of rows can be
lost. Every result states: direct system calls are not seen; work brokered to other processes (COM, RPC, WMI, services,
the shell) is not seen; child processes are recorded but not instrumented; handles opened before tracing are partly
unnamed; payloads (file, registry, network contents) are not captured; modules loaded during the trace are hooked on
load, so their first calls can be missed. Not covered: `ConnectEx`/`AcceptEx` via `WSAIoctl`, raw AFD ioctls,
QUIC and custom network stacks, overlapped I/O byte counts. Some API argument layouts are documented as believed and
verified only on the test fixture.

## Watchpoints and tracing

- 4 hardware debug-register slots per session; no read-only hardware watch (`read_write` reports both). A
  `read_write` hit costs one extra system call (BEA reads the watched bytes with a kernel-side copy, because a
  user-mode read would trip the slot again).
- page_guard watches trap every access to the page (about 55 µs per access on the test host, a heavy slowdown on hot
  pages), disarm when traps exceed 20,000/s or BEA's handlers take more than half of a 100 ms window (`end_reason`
  `rate-limit`, `WATCH_RATE_LIMIT` / `WATCH_RATE_LIMIT_BUSY`), and lose hits while BEA itself reads the page or when
  several threads touch it at once.
- While a page_guard watch is armed, the target's own system calls that read or write the watched page (`ReadFile`,
  `recv`, `NtQuery*` into a watched buffer) **fail** with `STATUS_GUARD_PAGE_VIOLATION`: that is how PAGE_GUARD works
  for kernel accesses. BEA re-arms the page but does not report these accesses as hits; their count is `kernel_rearms`
  in the summary (`WATCH_KERNEL_ACCESS_SEEN`). Watch I/O buffers with `debug_register` (aligned 1, 2, 4 or 8-byte
  parts). `method:"auto"` does not yet split a larger range across debug-register slots; when it falls back to
  page_guard the result says so (`WATCH_AUTO_PAGE_GUARD`).
- A page_guard watch keeps a protection the target sets on the watched page while it is armed (it re-arms over it),
  and stop leaves the target's protection in place (AGENT-2). A microsecond race between BEA's protection query and
  its write remains.
- `struct_base` is a heuristic; `insn_confidence` other than `exact` is a reconstruction.
- Stalker (`trace_execution`) slows followed threads; `calls` mode can be about 90× slower on call-heavy code;
  behavior on large games is unmeasured. Only modules in `modules` are recorded.
- Thread mode works around a Frida 17.23.2 deadlock (following a thread that is blocked in a system call could freeze
  it and then BEA's agent): such a thread is followed from its next entry into the same system-call stub, so its
  first wake-up until then is not traced (a game loop loses at most one frame), and a thread that never makes that
  call again is never followed. `on_call` mode is not affected.
- Fixed (AGENT-8): a second thread-mode trace of the same thread used to record nothing about every other time,
  because `Stalker.unfollow` of a remote thread takes effect only at the thread's next pass through Stalker's gate,
  and a steady loop in back-patched blocks never passes it. BEA now invalidates up to 4,096 of the stopped trace's
  blocks (hottest first, about 40 µs each). Remaining: a thread blocked in a system call when a trace stops leaves
  Stalker only after it returns, and the internal `call_events` mode has no block list.
- Each stopped `block_counts`, `call_summary` or `on_call` coverage trace leaves about 55–108 KiB in the target for
  the rest of the session (its compiled counting module stays pinned; before AGENT-6 it was 23 MiB per trace).
- The drcov layout is believed compatible with Lighthouse and Cartographer; `modoff` output is the fallback.
- If BEA dies abruptly while hardware watches are armed in an attached process, a small handler BEA leaves behind
  absorbs stray traps. Verified on the test fixture only (a hot debug-register watch survives a hard kill of the
  server); close sessions before stopping BEA anyway.

## Memory, scans and dumps

- `read_memory` reads at most 64 KiB per call; `unknown`-value first scans snapshot at most 1 GiB.
- No pointer scanner with depth and stability scores: chains are found level by level and validated in one run.
- Dumps do not rebuild the IAT; relocation reversal (`rebase_to:"preferred"`) is wrong at sites the program rewrote,
  and pointers the program wrote at runtime at non-relocation sites (for example a `.data` function pointer) keep
  their runtime values (`DUMP_REBASE_RUNTIME_WRITES`).
- The default realigned dump (`pe_realigned`, `rebase_to:"preferred"`) loads in Ghidra 12.1.4 and REA 6.7.0 like the
  file on disk (verified 2026-10-28 on game_sim: same image base, 248 functions, 10,173 instructions, identical
  pseudocode for `physics_step`). A `mapped` dump is a raw memory image, not a loadable PE file
  (`DUMP_MAPPED_NOT_A_PE_FILE`): Ghidra's PE loader misreads it or fails, so load it as raw bytes at its base and
  use the realigned layout for analysis (GHIDRA-1).
- A realigned dump of a gcc/MinGW image carries the file's COFF symbol table after `SizeOfImage`, so it is larger
  than the image.
- No minidump writing.

## Oracle calls (`call_function`)

- A call that never returns cannot be interrupted; the session is marked unresponsive. On an owned target
  `close_session` kills the target. On an attached target (the user's `call_attached` gate) nothing removes BEA's agent
  afterwards: `frida-agent.dll`, its threads and the call still running on the agent's thread stay in the user's
  process until that process exits (verified on game_sim with mathlib's `mf_spin`: about 1.5 cores busy after BEA had
  exited). `close_session` cannot complete the cleanup and a retry does not help; `force:true` detaches BEA but the
  agent stays loaded, so do not read a forced close's `reverted` list as proof that the agent left; server shutdown
  then exits non-zero (the Frida release step does not finish), and the agent's extracted copy under `%TEMP%` stays
  in use until the process exits. On attached targets call only functions known to terminate; reproduce anything
  uncertain on an owned (spawned) target.
- Callee exceptions are honored through a registered SEH frame; a frame without unwind information (JIT code,
  stripped `.pdata`) between BEA's frame and a fault can stop the unwind, and the target then crashes (owned targets
  are killed with their job).
- `thread_id` calls are refused while the thread sits in a system call; `thread_at` needs a function the thread
  actually runs.
- A function that changes the FP environment itself, or depends on thread-local state BEA cannot reproduce, can
  differ from in-game behavior even with `fp.source:"auto"`.
- At most 1,000 vectors per call (continue with `vector_offset`).

## Emulation

- Requires a user-provided Python with Unicorn 2.1.x, Capstone 5.x and pefile, or a venv created with the user's
  approval. Unicorn is never bundled.
- AVX/AVX-512/FMA code stops at the first such instruction (`unsupported_instruction`) instead of mis-executing.
- x87 transcendental instructions are inexact in Unicorn; MXCSR/x87 status flags are not modeled.
- Legacy-SSE `rcpss`/`rcpps`/`rsqrtss`/`rsqrtps` are exact in Unicorn but a vendor-specific ~12-bit approximation on
  hardware (rsqrtss(2): Unicorn 0x3f3504f3, this host 0x3f350000), and `dpps` adds its products one after another
  instead of `(p0+p1)+(p2+p3)` (`[1e8,1,-1e8,1]·1`: 1.0 vs 0.0); `dpps`/`dppd` also lose the sign of a zero sum.
  Vectors that execute one carry `sse_approx_inexact` (coverage partial; `sse_tagging_incomplete` when more sites
  exist than the 512 tag hooks). No emulator can match the approximation tables bit for bit: trust the live leg.
- When both operands of an SSE operation are NaN, Unicorn and the CPU can propagate different operands' NaN payloads
  (seen for `mulss`, `addps`, `haddps`, `dppd` and others on the test host). Values agree; a bit-exact diff then
  differs in NaN payloads only (`nan_payload_only`; `compare.nan:"any_nan"` if payloads do not matter).
- The emulated heap (`memory.heap_mb`, default 64 MiB, at most 256) reuses freed blocks, but it is smaller than a real
  process's: an allocation that does not fit returns NULL, and the vector carries `hle_heap_exhausted`. Buffers with
  `placement:"heap"` stay allocated in the session state (that is what lets `save_as` keep them), so a `chain` batch
  holds one per vector; when the next one does not fit, the batch ends with the completed prefix (nothing of the
  failed vector ran). Use `placement:"scratch"` when the function does not keep or free the buffer.
- One result carries at most 56 MiB of out-buffer hex (out buffers are never cut short): a batch fits
  `floor(58,720,256 / Σ(2 × size + 3))` vectors over its out buffers; a larger request is refused before it runs.
- Imports are modeled for a limited set of functions; others stop (`unhandled_import`) unless overridden.
- Image-backed sessions see file values in `.data`, not runtime state; use a live or dump-backed session.
- No lazy fetching of live memory for dump-backed sessions; capture everything the function reads.
- Replaying a captured call from a dump (`from_dump_call`) is deferred.
- Tested with GCC-built fixtures only; MSVC-built game code is untested in emulation.

## Inspection and hooks

- Emulation sessions: `list_modules` is not recorded as evidence (`EMU_MODULES_UNRECORDED`), and read_memory /
  disassemble records use a provisional emulation configuration digest.
- `list_memory_ranges` reports mapped (`MEM_MAPPED`) ranges as private (`RANGE_KIND_MAPPED_UNDISTINGUISHED`).
- With `sample_every > 1` a hook summary's `calls` counts the recorded events, not every call.

## Crashes

Fast-fail (`0xC0000409`) and stack-overflow (`0xC00000FD`) exits may give only the exit code (`crash.pc` null); a
fast fail never borrows an earlier first-chance report. On attached targets the crash report depends on BEA still
being attached when the process dies. Software exceptions (C++ throws, `OutputDebugString`, thread naming; Frida's
type `system`) are first-chance rows, not crash reports; an unhandled one is still reported at last chance with its
NTSTATUS (AGENT-11).

## Evidence and limits

- Quotas: ledger 512 MiB per run, 256 MiB per stream, 4 GiB of blobs (configurable); long sessions may need more.
- The ledger is content-addressed but not signed.
- `import_evidence` refuses archives over its entry-count, per-entry and archive-wide compression-ratio and size
  caps before writing anything, and extracts only files the manifests reference. A default (manifests-only) import
  keeps stream manifests without their records (marked absent) and charges nothing to the stream quota.
- Redaction (`sensitive_values`, `redact_literals`) covers `read_memory` (every typed view is withheld when the raw
  bytes hold a literal) and `scan_results` cells, but not yet byte or array captures in `hook_function` /
  `query_events` rows (SEC-3, partly fixed).
- MCP responses above 10 MiB need a client that accepts them (`BEA_MCP_MAX_RESPONSE_BYTES`); bulk data goes to files.
- No call blocks longer than 120 s; waits are at most 60 s.

## Interfaces

- MCP tools only: no MCP prompts, resources or completions; results are JSON (TOON only on the CLI).
- HTTP mode supports the 2025-era sessionful streamable-HTTP traffic; routing for newer protocol envelopes is open.
- On Windows, HTTP mode refuses to start when `BEA_HOME` or `--connection-file` is outside the user profile (no
  owner-only ACL is set yet).
- `bea schema --help` does not print usage yet (`bea help <command>` and `bea <tool command> --help` do).
- Client tool-timeout keys are written only for Codex; other clients need the user to set ≥ 180 s.
- `bea-jobhost.exe` is an unsigned local build; endpoint protection may block it (`bea doctor --probe` shows this).

## Not verified on the test host

- Linux paths (no Linux host); machine-wide anti-cheat services (none present; the harness records their notes);
  MSVC/PDB-built targets; JIT or packed code on the oracle call path; Lighthouse/Cartographer loading of drcov files
  (an independent reader is used instead); Ctrl+C on a real Windows console for the HTTP server.

## Open lab items of DESIGN §11.2 at release

| Item                                                     | Status at release                                                                                                                                                                                                                |
| -------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Safety-net VEH after an abrupt unload                    | verified on game_sim (WP9 acceptance: hot DR watch, server hard-killed, target alive)                                                                                                                                            |
| SEH unwinding through non-`.pdata` frames                | not verified (no JIT/packer fixture); limitation above                                                                                                                                                                           |
| `thread_at` safe point under load                        | verified on game_sim (WP11 acceptance; a `thread_at` call under an armed DR watch in the WP18 integration lane)                                                                                                                  |
| knip rule names and `ignore` semantics                   | closed: the strict config (`error`, no `ignore`) passes `npm run knip`                                                                                                                                                           |
| Anti-cheat signal lists                                  | heuristics; kernel-only anti-cheat is invisible; limitation above                                                                                                                                                                |
| A5 send()/RPC ordering for checkpoints                   | not separately verified; the checkpoint path (`query_events` on active recordings) passes in acceptance                                                                                                                          |
| A-6 native ring, xmm fields from a CModule               | exercised by the native hook tier in WP7 acceptance                                                                                                                                                                              |
| A-21 / L-S6-2 API argument layouts                       | verified on behavior.exe only; limitation above                                                                                                                                                                                  |
| L6 / L-S6-5 drcov round trip                             | verified with an independent reader, not with Lighthouse or Cartographer                                                                                                                                                         |
| L-S6-6 realigned PE in Ghidra/REA                        | verified 2026-10-28 (Ghidra 12.1.4, REA 6.7.0): the default realigned, preferred-base dump matches the original; `mapped` is not a loadable PE (above)                                                                           |
| L-S6-7 `crash.pc` null for fast-fail / stack overflow    | limitation above                                                                                                                                                                                                                 |
| L-S6-8 DR watch on a merged 8-byte store                 | not separately verified (the acceptance row uses the 4-byte engine writer)                                                                                                                                                       |
| L-S6-11 detach after a wedged call on an attached target | verified (post-release review, game_sim + mathlib `mf_spin`): no clean detach; the agent and its threads stay until the process exits; limitation above                                                                          |
| A2 GetProcessTimes cross-check                           | closed by design: the jobhost creation time is authoritative                                                                                                                                                                     |
| S5 [B] items                                             | settled by WP14 (errata in decisions.md)                                                                                                                                                                                         |
| OI-1 motivating game's anti-cheat status                 | user decision; the refusal stands unless the user opts in                                                                                                                                                                        |
| OI-2 Node 22, Node 25/26                                 | not supported: `engines` stays `^24.11.0`. Widening it (e.g. `^24.11.0 \|\| ^26.0.0`) needs a lab run of Frida 17.23.2's prebuilt binding and the acceptance lane on that Node, plus the same range in `bea doctor`'s Node check |
| OI-3 MSVC/PDB fixtures                                   | not available on the host; PDB symbolization unverified                                                                                                                                                                          |
| OI-4 Unicorn license                                     | user-local install only, never bundled                                                                                                                                                                                           |
| OI-5 per-client timeout keys                             | written for Codex; the docs tell other clients' users to set ≥ 180 s                                                                                                                                                             |
| OI-6 HTTP modern-era routing                             | open; 2025-era sessionful traffic only                                                                                                                                                                                           |
