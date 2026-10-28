# BEA v0.1 — status

State of 2026-10-28: the first release candidate, updated after a post-release review the same day. [Review
(2026-10-28)](#review-2026-10-28) has the findings, their fixes and the lane counts of the final tree; the
release-stage test table below is kept as it was. Everything below was run on one Windows 11 x64 machine (Node
24.18.0, Frida 17.23.2, WinLibs gcc, Python 3.14.6 with unicorn 2.1.4) unless it says otherwise.

## How BEA was built

BEA was researched, designed, built and reviewed in one AI-assisted run on 2026-10-28, with Claude Code orchestrating
many agents:

1. **Research.** Nine notes on REA's patterns, other dynamic-analysis MCP servers, Frida 17.23.2 on Windows and
   emulation backends, plus a consolidated brief: [research/](research/).
2. **Design.** Six subsystem specialists produced designs, which were integrated, critiqued adversarially twice and
   revised: [design/DESIGN.md](design/DESIGN.md), with the decisions in [decisions.md](decisions.md).
3. **Build.** 19 work packages produced about 96k lines of TypeScript under `src/` and 59k lines of tests, verified
   against real Frida targets.
4. **Review.** Seven reviewers, independent verification of every finding, fixes, and a full re-run: 73 findings, 68
   fixed, 5 partly fixed ([Review](#review-2026-10-28)).

**Current state:** every lane is green on the final tree:

- `npm run check` and `npm run build`;
- 1,394 unit and boundary tests;
- 224/224 real-Frida acceptance tests, including the seven investigations and the lifecycle must-haves;
- both receipts;
- a Ghidra 12.1.4 and REA load of a BEA module dump, with the same functions and pseudocode as the original.

**Open items** (details in [limitations.md](limitations.md)):

- **LIFE-4:** if the server dies in the short window between Frida's spawn and job adoption, the suspended target is
  left outside the job.
- **SEC-6:** anti-cheat modules loaded at runtime are detected only after injection. Directory, import and launcher
  signals are checked before injection.
- **SEC-3:** byte and array captures from `hook_function` and `query_events` are not yet redacted against sensitive
  literals.
- **Unicorn:** it is installed by the user (`bea setup --emulator`, or `BEA_PYTHON`) and never vendored. Check its
  license for your use.
- **Bridge tests:** the bridge's Python test suite leaves `%TEMP%\bea-emu-test*` directories behind.

**Frida temp directories.** Frida extracts about 40 MB per injection into a `frida-*` directory. BEA extracts under
`BEA_HOME` and reclaims these directories (LIFE-3). Other Frida tools on the same machine still leave theirs in
`%TEMP%`.

## What BEA is

BEA (Binary Execution Analysis) is an MCP server and a command-line tool, `bea`, that lets an AI agent observe and
test **running Windows x64 user-mode programs**. It is the runtime companion of REA/Ghidra: they say what the code is,
BEA says what it does when it runs. It spawns a program paused (inside a kill-on-close job held by the gcc-built
helper `bea-jobhost.exe`) or attaches to one you name, injects a Frida 17.23.2 agent compiled at build time, and
returns every result with an evidence id, a coverage statement and fixed limitation sentences. A Python/Unicorn
bridge emulates functions for batch runs and bit-exact comparison with the live program.

### The 37 tools

| Area                       | Tools                                                                                                                  |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Sessions                   | `bea_status`, `list_processes`, `spawn_process`, `attach_process`, `resume_process`, `session_status`, `close_session` |
| Inspection                 | `list_modules`, `list_memory_ranges`, `list_threads`, `read_memory`, `disassemble`                                     |
| Address mapping            | `list_module_symbols`, `map_address`                                                                                   |
| Scans (Cheat-Engine style) | `scan_memory`, `scan_next`, `scan_results`                                                                             |
| Hooks and recordings       | `hook_function`, `wait`, `stop_instrumentation`, `query_events`                                                        |
| Behavior profiles          | `trace_api`                                                                                                            |
| Watchpoints and coverage   | `watch_memory`, `trace_execution`, `export_coverage`                                                                   |
| Oracle calls               | `call_function`                                                                                                        |
| Modification (gated)       | `write_memory`, `override_function`, `run_script`                                                                      |
| Dumps                      | `dump_memory`                                                                                                          |
| Emulation and diffs        | `emu_open`, `emu_call`, `diff_function`                                                                                |
| Evidence and unknowns      | `get_evidence`, `export_evidence`, `import_evidence`, `record_unknown`                                                 |

Every tool's inputs, effects and CLI command are in [tools.md](tools.md) (generated from the contracts). The agent
skill `bea-dynamic-analysis` (`skills/`) teaches an agent when and how to use them; its recipes R1–R7 are the seven
investigations tested below.

## Build, install and register with Claude Code

From a clone (Windows x64, Node 24.11+, gcc on PATH for the native helper and fixtures):

```powershell
git clone https://github.com/catbyte-security/bea
cd bea
npm ci                                         # also downloads Frida's prebuilt binding
npm run build                                  # dist/: server, agent bundle, bea-jobhost.exe, bridge manifest, skill
node scripts/bea.mjs doctor                    # read-only health report
node scripts/bea.mjs setup --client claude_code --dry-run   # shows the files it would change and the skill install
node scripts/bea.mjs setup --client claude_code --yes       # writes BEA's entry and installs the skill
node scripts/bea.mjs doctor --client claude_code            # exit 0 = registered and healthy
```

Then restart Claude Code. The registered command is `node <clone>\scripts\bea.mjs mcp`.
Set Claude Code's MCP tool timeout to at least 180 seconds (a BEA call can block up to 120 s). `npm link` would put
`bea` on PATH (not tested). For emulation, `node scripts/bea.mjs setup --emulator` creates a pinned, hash-checked venv under
`BEA_HOME\emu\venv` with your approval, or set `BEA_PYTHON` to a Python that has unicorn 2.1.x, capstone and pefile.

What was verified of this: `npm run build`; `bea doctor` with `--backend frida --probe` and
`--backend emulation --probe` (all checks healthy, nothing written to `BEA_HOME`); `bea mcp doctor` (ok);
`bea setup --skill --yes` followed by `bea doctor --skill` (healthy, installed files identical to `dist/skills`);
`bea setup --dry-run` for all six clients (claude_code, codex, cursor, vscode, claude_desktop, gemini_cli) in a
throwaway home. Applying `setup --client claude_code --yes` and `doctor --client claude_code` was verified by WP17 in a
throwaway home; it was not run against a real Claude Code configuration.

Opt-in capabilities stay off unless you start BEA with them: `BEA_ALLOW_WRITE_MEMORY=1`, `BEA_ALLOW_OVERRIDE=1`,
`BEA_ALLOW_RUN_SCRIPT=1`, `BEA_ALLOW_CALL_ATTACHED=1` (or `"gates"` in `BEA_HOME\config.json`). Targets with
anti-cheat signals are refused unless you set `BEA_ALLOW_ANTI_CHEAT=1`.

## How to use it

Ask Claude Code in plain language; the skill routes the question to the tools. Three prompts that match tested
investigations:

1. "Spawn `C:\lab\tool.exe` paused, trace its file, registry, network, process, module and memory-protection activity
   until it exits, and tell me what it touched." (investigation 4: `spawn_process` → `trace_api` → `resume_process`)
2. "In the running `game.exe`, Ghidra shows `0x1401234AB` inside the physics function. Verify the address against the
   running build, hook that function's float arguments and return value for 2 seconds and summarize them."
   (investigation 2: `map_address` → `hook_function` → `query_events`)
3. "`crashy.exe av-write` crashes. Run it and tell me the faulting instruction, module+RVA, registers and backtrace."
   (investigation 5: `spawn_process` → `resume_process {until:"exit"}`)

The same work from a terminal: `bea trace-api --profiles file --profiles network --spawn C:\lab\tool.exe`,
`bea map game.exe:0x1401234ab --pe-path C:\games\game.exe`, or a planned multi-step `bea run scenario.json`
([cli.md](cli.md)).

## Test results (this machine, final runs)

All runs below use one build (`npm run build`), with the lanes that start the built server pointed at a snapshot of it
(`BEA_DIST_DIR`, docs/testing.md). Vitest runs with `retry: 0`.

| Lane                    | Command                                                                                | Result                                                                                                                                                                                                                                                   |
| ----------------------- | -------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| check                   | `npm run check`                                                                        | exit 0: generated files up to date (29), `tsc` host and shared 0 errors, oxlint 0 errors (370 warnings: complexity, file and function length), module boundaries ok (466 files), oxfmt clean, knip strict 0 findings, 173 test files each in one project |
| build                   | `npm run build`                                                                        | exit 0: agent bundle 598,117 B with 0 diagnostics, `bea-jobhost.exe` 66,560 B (probe ok), bridge 221,796 B, skill (37 tools)                                                                                                                             |
| smoke                   | `npm run smoke`                                                                        | exit 0: 37 tools, `bea_status` poll envelope, invalid input → `invalid_request`, client close → server exit in 16 ms                                                                                                                                     |
| fast                    | `npm test`                                                                             | 130 files: **1,279 passed, 0 failed, 5 named skips** (symlink privilege; 4 HTTP tests of the built server that need `BEA_DIST_DIR`)                                                                                                                      |
| fast with the build     | `npm test` projects with `BEA_DIST_DIR`                                                | **1,283 passed, 0 failed, 1 named skip** (symlink privilege); the http-boundary lane alone 57/57, including the Python `urllib` recipe                                                                                                                   |
| process                 | `vitest --project process-boundary`                                                    | **14/14**                                                                                                                                                                                                                                                |
| emulation               | `vitest --project emu-boundary`                                                        | **8/8** (one of them runs the bridge's Python suite)                                                                                                                                                                                                     |
| acceptance (real Frida) | `vitest --project acceptance`                                                          | **40 files, 212/212 passed, 0 skipped** in 330 s (per area below)                                                                                                                                                                                        |
| receipt                 | `node scripts/verify-frida-windows.mjs`                                                | **11/11 checks pass**: CLI one-shots and MCP give the same pointer-free results for symbols and map (offline), modules, read, disasm, call, dump, hook, trace-api, emulate; nothing left running                                                         |
| receipt                 | `node scripts/verify-emulation.mjs`                                                    | **15/15 checks pass** (live vs emulator bit-exact parity set, dump-backed and hooked `physics_step`)                                                                                                                                                     |
| catalog budget          | `npm run catalog:golden` + `tests/contracts`                                           | 37 tools; model-visible 81,321 B (≤ 96 KiB); wire 290,992 B (over the design's 192 KiB, under the raised 320 KiB); inputs ≤ 4 KiB except `call_function` 6,410 B, `emu_call` 8,595 B, `diff_function` 7,717 B (≤ 12 KiB)                                 |
| doctors                 | `bea mcp doctor`; `bea doctor --backend frida --probe` / `--backend emulation --probe` | all healthy (the frida probe spawns, injects and kills a BEA-owned child); `BEA_HOME` stays empty                                                                                                                                                        |
| skill and setup         | `bea setup --skill --yes`, `bea doctor --skill`, `bea setup --dry-run` ×6              | skill healthy (37 tools, files identical to `dist/skills`); dry-run plans for claude_code, codex, cursor, vscode, claude_desktop and gemini_cli                                                                                                          |
| leak audit              | after the full acceptance run                                                          | no BEA, fixture or bridge process left; `tasklist /M frida-agent.dll` finds none; the `%TEMP%\frida-*` and `bea-*` directory counts did not change (786 and 215, all from earlier stages)                                                                |

Acceptance per area: sessions 24, agent core 19, address 9, inspect 10, scans 10, hooks and recordings 11, behavior
5, watch 20, calls 27, modify 15, dumps 11, emulation 26, evidence 5, and the release lanes: lifecycle 7 (S6 §10.9:
graceful close with 3 owned + 1 attached + 1 emulation session in < 2 s, hard kill, self-dying targets, cancellation,
stragglers, pid reuse, shutdown with every instrument kind), investigations 7 (the seven S6 §1 investigations as
`bea run` scenarios with 11 / 3 / 3 / 4 / 3 / 2 / 1 analysis calls), integration 6 (cross-wave rows and a 24-trace
regression for the Frida deadlock workaround). The run recorded no machine-wide anti-cheat service on this machine.

One earlier full acceptance run had one failure: a timing race in a WP12 test (it compared two reads of a value the
game keeps changing); the test now uses a fixed scratch object and passed 3 of 3 runs, and the final run above is
clean. The receipts, the doctors and the setup checks were re-run on the final build (agent build `93a3de1ff66705bf`);
the catalog drift check passes on it.

## Known limitations

The full list is [limitations.md](limitations.md). The ones most likely to matter:

- Windows x64 user mode only; 32-bit programs, protected processes and anti-cheat-protected games are refused. Linux
  is best effort and was not tested (no Linux host).
- BEA is not a sandbox: containment kills processes, it does not isolate them. Run unknown programs in a VM.
- Injection is visible (frida-agent.dll and ~24 system DLLs; 11 stay after detach); anti-debug code may react.
- `trace_execution` thread mode: a Frida 17.23.2 deadlock is worked around by following a sleeping thread from its
  next system call (its first wake-up is not traced). The empty second thread-mode trace was fixed in the review
  (AGENT-8: `Stalker.unfollow` of a remote thread waits for the thread's next gate pass).
- A `page_guard` watch makes the target's own system calls on the watched page fail while it is armed (inherent
  to PAGE_GUARD); use `debug_register` for I/O buffers.
- A server that dies in the few tens of milliseconds between spawning a program and adopting it into its job
  leaves that program suspended and uncontained (LIFE-4, partly fixed).
- `trace_api` covers documented Win32/NT APIs only: no direct syscalls, no brokered work (COM, services), children are
  not instrumented, payloads are not captured.
- Emulation stops at AVX/FMA instructions and unmodeled imports instead of guessing; x87 transcendentals are inexact.
- Two size budgets are over the design's numbers (both raised by integrator decision, see
  [decisions.md](decisions.md)): after the review the agent bundle is 612,373 B (design 512 KiB; enforced ceiling
  640 KiB) and the catalog's wire size is 292,527 B (design 192 KiB; ceiling 320 KiB). The model-visible part
  (82,916 B) is within its 96 KiB budget.
- Not verified here: Lighthouse loading of drcov files, MSVC/PDB-built targets, machine-wide anti-cheat services
  (none present). Ghidra 12.1.4 and REA 6.7.0 loading of realigned dumps was verified in the review.

## Review (2026-10-28)

A post-release review confirmed 73 findings (security, lifecycle, agent, results and UX, data, emulation, onboarding,
and the Ghidra receipt). They were fixed in three partitions — A: agent and `bea-jobhost`; B: host; C: emulator bridge,
documentation and skill — and a final verification pass applied the requests the partitions left for each other, re-ran
every lane and audited leaks. Each code fix carries a test that fails without it (documentation-only fixes are checked
by the skill and generator tests). [decisions.md](decisions.md) "Review fixes" lists the change per finding;
[limitations.md](limitations.md) has what remains. Result: **68 fixed, 5 partly fixed, 0 open without a fix**.

### Findings

| ID         | Sev.     | Status | Fix, or what remains                                                                                                                                                             |
| ---------- | -------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SEC-1      | high     | fixed  | Spawn refusal by name, location (given and real path) and version resource; `spawn.allowed_programs` admits one program.                                                         |
| SEC-2      | medium   | fixed  | UNC, device and network-resolving `cwd`, input paths and (at integration) spawn programs are refused before BEA opens them.                                                      |
| SEC-3      | high     | partly | `read_memory` views and `scan_results` cells are redacted; hook/query byte and array captures are not yet.                                                                       |
| SEC-4      | medium   | fixed  | A literal match gives a valid `read_memory` result with withheld views, not an internal error.                                                                                   |
| SEC-5      | medium   | fixed  | Zip import extracts manifest entries only and enforces count, ratio and total caps before any write.                                                                             |
| SEC-6      | medium   | partly | Directory signals walk 3 levels up (and around the real path); attach still checks loaded modules only after injection.                                                          |
| LIFE-1     | high     | fixed  | Cancel/shutdown during create-script settles, unloads and detaches; a stranded agent is reported.                                                                                |
| LIFE-2     | medium   | fixed  | The hard-exit timer is ref'd, so a blocked native teardown cannot hang shutdown.                                                                                                 |
| LIFE-3     | high     | fixed  | Frida's extraction goes to `BEA_HOME\tmp\frida\<run>` and is reclaimed; `%TEMP%\frida-*` delta over the full acceptance run: 0.                                                  |
| LIFE-4     | high     | partly | Adoption before metadata and a creation-time cross-check; the spawn-to-adopt window (suspended orphan if the server dies) remains.                                               |
| LIFE-5     | medium   | fixed  | `bea-jobhost` compares file identity; the host resolves the real path and gives `image-path` its own message.                                                                    |
| LIFE-6     | medium   | fixed  | A cancelled install completes on a detached op and is rolled back.                                                                                                               |
| LIFE-8     | medium   | fixed  | Impact documented; `close_session` on an unresponsive agent says a retry cannot help, and a forced close reports the agent left loaded.                                          |
| AGENT-1    | critical | fixed  | The thunk page stays while a call may run; the host reports a still-running call and records no effect for one that never started.                                               |
| AGENT-2    | critical | fixed  | Guard writes are relative to the current protection; the target's `VirtualProtect` is kept.                                                                                      |
| AGENT-3    | high     | partly | Documented and disclosed (limitations, `kernel_rearms` count, auto fallback notice); PAGE_GUARD itself makes such calls fail; auto does not split ranges across debug registers. |
| AGENT-4    | high     | fixed  | Reverts write `before` only over the bytes BEA wrote.                                                                                                                            |
| AGENT-5    | high     | fixed  | Stopped native hooks free their ring and staging buffers.                                                                                                                        |
| AGENT-6    | high     | fixed  | The counting slab is committed on demand and freed; 55–108 KiB stays per stopped trace (was 23 MiB).                                                                             |
| AGENT-7    | high     | fixed  | Every BEA attach/detach flushes and invalidates followed threads.                                                                                                                |
| AGENT-8    | high     | fixed  | Cause found (`Stalker.unfollow` of a remote thread); the stopped trace's blocks are invalidated.                                                                                 |
| AGENT-9    | medium   | fixed  | The modify seam passes `save(site, n, owner)`.                                                                                                                                   |
| AGENT-10   | medium   | fixed  | Hook captures read through the guard-aware reader.                                                                                                                               |
| AGENT-11   | medium   | fixed  | `system` is not a crash class in the agent or the host hello; crash derivation joins only matching reports.                                                                      |
| AGENT-12   | low      | fixed  | `StalkerBusy` names the releasing instrument and its state.                                                                                                                      |
| UX-1       | critical | fixed  | Mid-function hook, `on_call` and override addresses are refused unless `probe:true`.                                                                                             |
| UX-2       | low      | fixed  | `query_events` pages no longer repeat the recording summary.                                                                                                                     |
| UX-3       | medium   | fixed  | `wait_ms` on a paused target returns at once with `TARGET_PAUSED`.                                                                                                               |
| UX-4       | medium   | fixed  | `BROKERED_LAUNCH` only on evidence; it tells the agent to ask the user.                                                                                                          |
| UX-5       | medium   | fixed  | `resume_process {until:"exit"}` settles built-in recordings.                                                                                                                     |
| UX-6       | medium   | fixed  | `get_evidence {id}` requires `detail:"complete"`.                                                                                                                                |
| UX-7       | medium   | fixed  | `record_unknown` says unknowns are run-scoped.                                                                                                                                   |
| UX-8       | medium   | fixed  | `--evidence-out` relative names go to the run's exports; absolute ones are checked before the scenario runs.                                                                     |
| UX-9       | low      | fixed  | No-free-slot errors name the holders' `rec_` ids and a valid method.                                                                                                             |
| UX-10      | low      | fixed  | `static` filled for the main image and prepared modules; watch summaries carry `insn_confidence`.                                                                                |
| UX-11      | low      | fixed  | `end_reason:"invocations"`, which expires the trace effect like `max_hits`.                                                                                                      |
| UX-12      | low      | fixed  | Skill R3 and the `from_recording` description state the scalar-only rule.                                                                                                        |
| UX-13      | low      | fixed  | Unknown ids are `reference_not_found`; the skill names `details.diagnostics.candidates`.                                                                                         |
| DATA-1     | high     | fixed  | Aggregate PE table budgets; `.pdata` limited to file-backed bytes.                                                                                                               |
| DATA-2     | high     | fixed  | Agent footprint limited to ntdll/kernel32/kernelbase.                                                                                                                            |
| DATA-4     | medium   | fixed  | Manifests-only imports keep exports of the importing run working.                                                                                                                |
| DATA-5     | medium   | fixed  | Manifests-only imports charge no stream quota.                                                                                                                                   |
| DATA-6     | medium   | fixed  | Dump captures split at protection boundaries.                                                                                                                                    |
| DATA-7     | medium   | fixed  | `Loc.sym` holds exact PE exports only.                                                                                                                                           |
| DATA-8     | low      | fixed  | Empty sections past EOF give raw offset 0.                                                                                                                                       |
| EMU-1      | high     | fixed  | Approximate legacy-SSE instructions are tagged `sse_approx_inexact` (an exact `dpps` model is deferred).                                                                         |
| EMU-2      | high     | fixed  | Out buffers come back whole; over-budget requests are refused up front as `invalid_request`.                                                                                     |
| EMU-3      | high     | fixed  | Live CPU exceptions use the emulator's `cpu_exception` family.                                                                                                                   |
| EMU-4      | high     | fixed  | Per-session FIFO for emulation calls.                                                                                                                                            |
| EMU-5      | medium   | fixed  | The SEH page resets the x87 stack (`fninit`); new `SEH_PAGE_SHA256`.                                                                                                             |
| EMU-6      | high     | fixed  | Free-list HLE heap; a chain that runs out stops with the completed prefix, partial coverage and `EMU_BATCH_STOPPED`.                                                             |
| EMU-7      | medium   | partly | The diff hint names the emulator's NaN rule; the bridge does not tag NaN outputs (documented).                                                                                   |
| EMU-8      | medium   | fixed  | Lineage after a bridge loss is recorded after `ensureReady`.                                                                                                                     |
| EMU-9      | medium   | fixed  | Undetailed stops are harness stops; the bridge now sends per-vector `attr`/`pcRva` past 1,000 faults.                                                                            |
| EMU-10     | medium   | fixed  | A live target lost mid-run gives `diff_function` a verdict with `lost_target` (host-derived).                                                                                    |
| EMU-11     | medium   | fixed  | Inline out arrays capped at 256 with `value_cap`.                                                                                                                                |
| EMU-12     | medium   | fixed  | `compare.columns` validated.                                                                                                                                                     |
| EMU-13     | high     | fixed  | `signature.convention:"msvc_method"`.                                                                                                                                            |
| EMU-14     | low      | fixed  | A `thread_at` hook failure is not executed and names the requested address.                                                                                                      |
| ONBOARD-1  | medium   | fixed  | `CreateProcess`' own child writes fold into `setup_writes`.                                                                                                                      |
| ONBOARD-2  | medium   | fixed  | Failed Python resolutions are not cached.                                                                                                                                        |
| ONBOARD-3  | medium   | fixed  | Same fix as UX-8.                                                                                                                                                                |
| ONBOARD-4  | medium   | fixed  | No `--repair` remediations.                                                                                                                                                      |
| ONBOARD-5  | medium   | fixed  | Same fix as UX-4.                                                                                                                                                                |
| ONBOARD-6  | low      | fixed  | Docs say Node 24.x only.                                                                                                                                                         |
| ONBOARD-7  | low      | fixed  | Same fix as UX-2 (the CLI prints the digest once).                                                                                                                               |
| ONBOARD-9  | low      | fixed  | The skill treats `not-loaded` as normal before the first `emu_open`.                                                                                                             |
| ONBOARD-10 | low      | fixed  | `bea doctor` treats the skill as advisory without Claude Code; the README adds the frida probe.                                                                                  |
| ONBOARD-11 | low      | fixed  | Python probe failures show stderr and a hex exit code.                                                                                                                           |
| ONBOARD-12 | low      | fixed  | `bea help <built-in>` works; the hook help lists `--capture`.                                                                                                                    |
| ONBOARD-13 | low      | fixed  | zod 4.6.7 (`npm audit`: 0 vulnerabilities).                                                                                                                                      |
| GHIDRA-1   | medium   | fixed  | A `mapped` dump is labelled a raw memory image (`DUMP_MAPPED_NOT_A_PE_FILE`); docs no longer call it the Ghidra fallback.                                                        |
| GHIDRA-2   | low      | fixed  | `DUMP_REBASE_RUNTIME_WRITES` names runtime-written pointers at non-relocation sites.                                                                                             |

### Ghidra receipt (L-S6-6)

**Pass.** Ghidra 12.1.4 (headless, JDK 21) loads the default `dump_memory {format:"pe"}` dump (`pe_realigned`,
`rebase_to:"preferred"`) of game_sim with no loader error and analyzes it exactly like the file on disk: image base
`0x140000000`, 248 functions, 10,173 instructions, 22 entry points, `physics_step` at `0x1400017a0` (276 bytes) and
`engine_update` at `0x1400019b0`; the DWARF section names come back because BEA appends the COFF symbol table. REA
6.7.0 (Ghidra provider) gives identical pseudocode, signature and body ranges for `physics_step`. Byte comparison:
every section equals the file except one runtime-written `.data` pointer and the resolved IAT. The `mapped` layout
does not load as a PE (25 functions at the preferred base, an import failure at the runtime base), which became
GHIDRA-1; the `.data` pointer became GHIDRA-2. Evidence (logs, dumps, REA output) is in the review lab directory.

### Lanes after the review (final tree, one build, acceptance from a fresh snapshot)

| Lane       | Command                                                        | Result                                                                                                                                                                                                    |
| ---------- | -------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| check      | `npm run check`                                                | exit 0: 29 generated files up to date, `tsc` host and shared 0 errors, oxlint 0 errors (379 warnings), module boundaries ok (470 files), oxfmt clean, knip 0 findings, 183 test files each in one project |
| build      | `npm run build`                                                | exit 0: agent bundle 612,373 B (ceiling 640 KiB), `bea-jobhost.exe` 66,560 B, bridge 234,059 B, skill (37 tools)                                                                                          |
| smoke      | `npm run smoke`                                                | exit 0: 37 tools, invalid input → `invalid_request`, client close → server exit in 12 ms                                                                                                                  |
| fast       | `npm test`                                                     | 139 files: **1,394 passed, 0 failed, 5 named skips**; with `BEA_DIST_DIR` **1,398 passed, 0 failed, 1 named skip**                                                                                        |
| process    | `npm run test:process`                                         | **15/15**                                                                                                                                                                                                 |
| emulation  | `npm run test:emu`                                             | **8/8**; the bridge's own Python suite inside it: 127 tests OK (fast path ≈ 45,000 vectors/s)                                                                                                             |
| acceptance | `vitest --project acceptance`, `BEA_DIST_DIR` = fresh snapshot | **41 files, 224/224 passed, 0 skipped** in 323 s (lifecycle, investigations and integration included)                                                                                                     |
| receipt    | `npm run verify:frida:windows`                                 | **11/11 checks pass**                                                                                                                                                                                     |
| receipt    | `npm run verify:emulation`                                     | **15/15 checks pass**                                                                                                                                                                                     |
| catalog    | `npm run catalog:golden`                                       | 37 tools; model-visible 82,916 B (≤ 96 KiB); wire 292,527 B (≤ 320 KiB)                                                                                                                                   |
| audit      | `npm audit`                                                    | 0 vulnerabilities (zod 4.6.7)                                                                                                                                                                             |

These runs found three regressions of the review fixes, fixed before the final runs above: the EMU-14 agent change
broke the raw call harness's staging list (`tests/acceptance/call/sehThunk.test.ts` did not compile); LIFE-3's
extraction directory overflowed MAX_PATH under a 150-character `BEA_HOME`, so every spawn failed (Frida's "Error
opening file"; BEA now leaves the extraction in `%TEMP%` when the path would not fit); and the
`verify:frida:windows` receipt still read the old `query_events` summary shape (UX-2 / ONBOARD-7).

### Leak audit

- `%TEMP%\frida-*`: 790 before and after each of the three full acceptance runs and the two receipts (delta 0; all
  790 predate this pass, 786 of them the release stages). The harness gives every test server its own TEMP, so this
  delta alone does not prove LIFE-3; lifecycle must-have 9 and a direct check do.
- Direct LIFE-3 check with the user's real TEMP and a throwaway `BEA_HOME`: a CLI `trace-api --spawn game_sim.exe`
  killed with `taskkill /F` while injected left `%TEMP%` unchanged; its `BEA_HOME\tmp\frida\run_…` stayed until the
  next CLI run's first attach reclaimed it, and that graceful run removed its own; game_sim died with its job each
  time.
- `tasklist /M frida-agent.dll` finds no process. No fixture, `bea-jobhost`, bridge or BEA node process is left (the
  only node/python processes running belong to unrelated sessions). `%TEMP%\bea-*` directories: 220 → 220. The
  snapshot `build/dist-snapshots/final` was removed.

## Dogfooding fixes (2026-10-29)

An agent that used BEA on Chrome's GPU process reported seven issues (FB-1 to FB-7). Their decisions are in
[decisions.md](decisions.md), and the user-facing changes are in `CHANGELOG.md` under "Unreleased".

| Item                        | Fix                                                                                                                                                |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| FB-2 folded unwind info     | real function starts were refused as "not a function start" (98% of `chrome.dll`): only chained/indirect unwind links are cached now               |
| FB-4 ASan deadlock          | crash backtraces use ntdll's unwinder, never dbghelp; blocking first-chance reports are opt-in; ASan runtime and shadow faults pass through        |
| FB-6 thread-mode stall      | the deferred-follow stub listener is native: other threads never enter JavaScript                                                                  |
| FB-1 CIG / ACG              | refused before injection (`code-integrity-guard`, `arbitrary-code-guard`); Frida's own failure text is kept in `details.diagnostics.frida_message` |
| FB-3 attach deadline        | `limits.attach_timeout_ms` / `BEA_ATTACH_TIMEOUT_MS`                                                                                               |
| FB-5 thread names           | `list_threads` returns `name`                                                                                                                      |
| FB-7 `on_call` context loss | documented, not root-caused                                                                                                                        |

All lanes were run on one build; the lanes that use the built server ran against a snapshot of it:

- `npm run check` exits 0.
- `npm test`: **1,471 passed, 0 failed**, 5 named skips.
- smoke: exit 0.
- process + emulation + HTTP lanes: **82/82**.
- Full acceptance, run three times: the first run had **2 failures**; the second and third passed **236/236**.
  - In the first run, the AGENT-7 test (a thread-mode trace that never started within 10 s) and the `trace_api`
    behavior table (`behavior.exe` did not print `DONE` within 30 s) failed.
  - Two isolated runs of those two files each failed one different test: AGENT-6 (`Invalid PID`) and the behavior
    table.
  - A standalone repro of the behavior-table scenario passed 4 of 4.
  - The suite was clean in three runs before these fixes, so treat these as intermittent failures to investigate.

## Next steps

1. Investigate the intermittent acceptance failures seen after the dogfooding fixes (AGENT-7, AGENT-6, the
   `trace_api` behavior table), which appear when acceptance files run in parallel.
2. Use the new ntdll unwinder for hook and watch backtraces and for `symbol_hints`, which still use dbghelp and can
   deadlock on ASan targets.
3. Add each detached hook's trampoline blocks to `invalidateAll` for every detach while threads are followed. The
   FB-6 slice-reuse exposure applies to hooks, profiles, overrides and the `on_call` listener.
4. From the feedback: a many-probe coverage tool (thousands of one-shot probes, native engine) and per-function
   coverage from a PDB function list.
5. Revisit the integrator decisions: the two raised budgets and the knip `@public` tags ([decisions.md](decisions.md),
   release stage).
6. Report the Frida 17.23.2 exceptor deadlock upstream (WP9's stack analysis is summarized in decisions.md).
7. The review's remainders: a `bea-jobhost` adopt mode started before the spawn (closes the LIFE-4 window) and an
   `inspect` mode (spawn-intent recovery, SEC-6 pre-injection module check on attach); redaction of hook/query
   captures (SEC-3); `method:"auto"` splitting a range across debug registers (AGENT-3); NaN tagging in the
   bridge (EMU-7).
8. Remaining feature work from the deferred list: trace_api rows on the core stream registry (flow control, acked exit
   flush), agent counters in hook summaries under sampling, emulation `list_modules` evidence, the HTTP owner-only
   ACL, CLI help for built-in commands, `bea evidence show --run`.
9. Try BEA on real targets you own or are authorized to analyze. Check a game's anti-cheat status before attaching:
   BEA refuses targets with anti-cheat signals unless the user overrides.
