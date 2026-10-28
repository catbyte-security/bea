# BEA

BEA — Binary Execution Analysis: dynamic binary analysis for agents.

BEA is an MCP server and a command-line tool (`bea`) that lets an AI agent observe and test running **Windows x64
user-mode programs**. It is the runtime companion of [REA](https://github.com/morluto/rea) (static analysis): REA and
Ghidra say what the code is, BEA says what it does when it runs.

- **Live sessions** through [Frida](https://frida.re) 17.23.2: BEA spawns a program paused or attaches to one the user
  named, and injects a small agent compiled at build time.
- **Containment** for the programs BEA starts: a kernel job object held by a helper (`bea-jobhost.exe`, built with gcc)
  kills the whole process tree when the session closes, even if BEA itself is killed.
- **Emulation** with [Unicorn](https://www.unicorn-engine.org) through a Python bridge, for batch execution and
  bit-exact differential tests against the live process.
- **Evidence**: every result carries an evidence id, a coverage statement (`complete` / `partial` and why) and fixed
  limitation sentences, stored in a content-addressed ledger you can export as a bundle.

## What it is for

| Question                                                                           | Tools                                                                       |
| ---------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| Is my Ghidra/REA address right in the running build?                               | `map_address` (rebase + byte verification against the file)                 |
| Where is the live value (speed, health) and which instruction writes it?           | `scan_memory`, `scan_next`, `watch_memory`                                  |
| What does this function receive and return in practice, floats included?           | `hook_function`, `query_events`                                             |
| What does `f(x)` return for chosen inputs, and does my emulator agree bit for bit? | `call_function`, `emu_open`, `emu_call`, `diff_function`                    |
| Which files, registry keys, endpoints and child processes does a program touch?    | `trace_api` (six typed profiles)                                            |
| Where and why does it crash?                                                       | `resume_process {until:"exit"}` → crash report with registers and backtrace |
| Which code runs for one call?                                                      | `trace_execution {on_call}` → `export_coverage` (drcov)                     |
| Give me the runtime image for Ghidra                                               | `dump_memory {format:"pe"}`                                                 |

The full catalog (37 tools) is in [docs/tools.md](docs/tools.md); the error contract in [docs/errors.md](docs/errors.md).
Agents get an operating manual as a skill: [skills/bea-dynamic-analysis](skills/bea-dynamic-analysis/SKILL.md).

## Requirements

- Windows 11 x64, the tested platform (Linux x64 is best effort; macOS is not supported).
- Node.js 24.x (24.11 or newer within the 24 line) with npm 11. `engines` is `^24.11.0` and `.npmrc` sets
  `engine-strict`, so `npm ci` refuses Node 25 and later (`EBADENGINE`) until Frida 17.23.2's Node binding is
  verified there.
- To build: WinLibs MinGW-w64 `gcc` on PATH (for `bea-jobhost.exe` and the test fixtures). No MSVC is needed.
- For emulation only: Python 3 with `unicorn` 2.1.x, `capstone` 5.x and `pefile`, or let `bea setup --emulator`
  create a private environment for BEA.

## Install

BEA v0.1 is installed from a checkout (the npm package is private).

```sh
git clone https://github.com/catbyte-security/bea
cd bea
npm ci                 # also downloads Frida's prebuilt Node binding
npm run build          # dist/: server, agent bundle, bea-jobhost.exe, skill
npm link               # optional: puts `bea` on PATH (otherwise use `node <checkout>/scripts/bea.mjs`)
bea doctor             # read-only health report
bea doctor --backend frida --probe   # spawns, injects and kills one BEA-owned child: Frida and bea-jobhost work
```

## Connect a client

```sh
bea setup --client claude_code --dry-run   # shows the exact files, backups and the skill it would install
bea setup --client claude_code --yes       # applies it; then restart the client
bea doctor --client claude_code            # exit 0 = healthy
```

Clients: `claude_code`, `codex`, `cursor`, `vscode`, `claude_desktop`, `gemini_cli`. Setup edits only BEA's own entry
(comments and formatting of everything else are preserved), backs up each file once, verifies what it wrote and rolls
back on a mismatch. It installs the `bea-dynamic-analysis` skill for Claude Code. The registered command is
`node <checkout>/scripts/bea.mjs mcp`. Details: [docs/setup.md](docs/setup.md).

**Set your client's tool timeout to at least 180 seconds.** A BEA call can block for up to 120 s (waits are at most
60 s). Codex gets `tool_timeout_sec = 240` automatically; set it yourself for Claude Code and Gemini CLI.

Emulation needs one more step, with your approval: `bea setup --emulator` creates a pinned, hash-checked virtual
environment under `BEA_HOME\emu\venv`. BEA never installs anything into your global Python and never ships Unicorn.

## Quick start (CLI)

```sh
bea status
bea trace-api --profiles file --profiles registry --profiles network --duration-ms 20000 --spawn C:\lab\tool.exe
bea map game.exe:0x1401234ab --pe-path C:\games\game.exe
bea hook game.exe+0x123460 --pid 1234 --capture dt=arg1:f32 --returns f32 --duration-ms 5000
bea run scenario.json            # a planned multi-step investigation (bea-scenario/1)
bea tools                        # every tool, its CLI command or why it has none
```

Output is one TOON document on stdout (`--json` for JSON). A command that spawns a target kills it at the end; one
that attaches detaches. See [docs/cli.md](docs/cli.md).

## Safety model

BEA injects code into other processes. It is built to fail closed:

- **Targets.** BEA acts only on processes it spawned or that the caller names by pid or image name, and refuses
  protected and critical processes, session-0 services, other users' processes, higher-integrity processes, its own
  process tree and 32-bit (WoW64) programs.
- **Anti-cheat.** Before injecting, BEA checks the **target** for anti-cheat signals: anti-cheat components next to
  the executable or in its parent directory, anti-cheat modules it imports (spawn) or has loaded (attach), and an
  anti-cheat client or launcher among its ancestors. Any signal refuses the call with `access_denied`
  (`anti-cheat-detected`). A machine-wide anti-cheat service running elsewhere (Vanguard, FACEIT, EasyAntiCheat
  services) does not block other programs; `bea_status` shows a note instead. Only you can override a refusal:
  `BEA_ALLOW_ANTI_CHEAT=1` or `attach.allow_anti_cheat: true` (global), or `attach.allow_anti_cheat_images:
  ["<sha256>"]` (one image, config file only). Results of an allowed run carry the `ANTI_CHEAT_ALLOWED` limitation.
  Injecting into a game protected by anti-cheat can get your account banned; BEA does not support such targets, and
  its signal lists cannot see kernel-only anti-cheat.
- **Gates.** Four capabilities are off until you enable them at server start:

  | Gate                | Environment                 | Enables                                                                   |
  | ------------------- | --------------------------- | ------------------------------------------------------------------------- |
  | `write_memory`      | `BEA_ALLOW_WRITE_MEMORY=1`  | writing or patching target memory                                         |
  | `override_function` | `BEA_ALLOW_OVERRIDE=1`      | rewriting arguments or return values                                      |
  | `run_script`        | `BEA_ALLOW_RUN_SCRIPT=1`    | running your own Frida JavaScript in the target                           |
  | `call_attached`     | `BEA_ALLOW_CALL_ATTACHED=1` | `call_function` and `diff_function` on attached (not BEA-spawned) targets |

  Or `"gates": {"write_memory": true}` in the config file. An agent cannot enable a gate through a tool call.

- **Untrusted content.** Everything read from a target is data, marked `_meta.provenance.untrusted_content`. Files
  are written only under the run's `exports` directory (or roots you configure), never with executable extensions;
  spawned programs get an allowlisted environment without `BEA_*` variables; script interpreters are refused as spawn
  targets unless you allow them.
- **BEA is not a sandbox.** Containment kills processes; it does not isolate them. Run unknown programs in a
  disposable VM.

Details: [SECURITY.md](SECURITY.md) and [docs/security.md](docs/security.md).

## Configuration

BEA stores runs, evidence and the emulator environment under `BEA_HOME` (default `%LOCALAPPDATA%\bea`,
`~/.local/share/bea` on Linux). Settings come from the environment first, then `BEA_HOME\config.json`:

```json
{
  "schema": "bea.config/1",
  "gates": { "call_attached": false },
  "quotas": { "ledger_mb": 512, "stream_mb": 256, "blob_mb": 4096 },
  "attach": { "allow_anti_cheat": false, "allow_anti_cheat_images": [] },
  "spawn": { "env_mode": "allowlist", "allow_interpreters": false },
  "exports": { "allowed_roots": [] }
}
```

Unknown keys are errors, so a typo never silently does nothing; `bea doctor` also reports unknown `BEA_*` environment
variables. Common variables: `BEA_HOME`, `BEA_LOG_LEVEL`, the `BEA_ALLOW_*` gates, `BEA_*_QUOTA_MB`,
`BEA_MAX_LIVE_SESSIONS`, `BEA_PYTHON` (an absolute path to the Python for emulation), `BEA_HTTP_TOKEN`.

## HTTP mode

`bea mcp --http [--port N]` serves MCP over streamable HTTP on `127.0.0.1` only, with a random bearer token written to
`BEA_HOME\http\connection.json` (never printed). It is meant for your own scripts (for example Python). Any process
running as your user can read that file, so do not run HTTP mode while analyzing untrusted programs. See
[docs/http.md](docs/http.md).

## Limitations (v0.1)

- Windows x64 user mode only: no 32-bit (WoW64) targets, no kernel or drivers, no remote devices; Linux x64 best
  effort (no API profiles, weaker containment).
- Behavior profiles see Win32/NT API calls in the traced process: not direct system calls, not work brokered to other
  processes (COM, services, the shell), not child processes, not payload contents.
- Programs relaunched through a broker (Steam and similar launchers) escape the job object; attach to them instead.
- Attaching leaves 11 of Frida's DLLs loaded in the target after detach.
- Symbols come from exports, `.pdata` and tables you register from Ghidra/REA; PDB symbolization is not verified.
- The emulator stops at AVX/FMA code instead of guessing, and models a limited set of imports.
- Crash reports for fast-fail and stack-overflow exits may carry only the exit code.

The full list with reasons: [docs/limitations.md](docs/limitations.md).

## Documentation

| Document                                                                                                                     | Contents                                                    |
| ---------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| [docs/architecture.md](docs/architecture.md)                                                                                 | components, layers, processes, data flow                    |
| [docs/security.md](docs/security.md)                                                                                         | threat model, gates, untrusted content, injection footprint |
| [docs/tools.md](docs/tools.md), [docs/errors.md](docs/errors.md)                                                             | generated tool reference and error contract                 |
| [docs/cli.md](docs/cli.md), [docs/setup.md](docs/setup.md), [docs/http.md](docs/http.md)                                     | command line, client setup, HTTP                            |
| [docs/evidence.md](docs/evidence.md), [docs/address-model.md](docs/address-model.md), [docs/emulation.md](docs/emulation.md) | evidence ledger, addresses, emulator                        |
| [docs/decisions.md](docs/decisions.md), [docs/limitations.md](docs/limitations.md)                                           | design decisions and known limits                           |
| [docs/testing.md](docs/testing.md)                                                                                           | test lanes and the shared-tree rules for contributors       |

## Development

```sh
npm ci
npm run check   # generated files, typecheck (host + shared), lint + module boundaries, format, knip, test discovery
npm test        # unit, MCP/CLI/HTTP boundary (no build needed)
npm run build   # dist/: server, agent bundle (frida.Compiler), bea-jobhost.exe, skill
npm run smoke   # the built server over stdio
npm run test:acceptance   # real Frida against gcc-built fixtures (Windows x64)
```

Several agents may build and test in one checkout at a time: build scripts serialize on a cross-process lock, and
tests of built binaries run from a snapshot (`node scripts/snapshot-dist.mjs <name>`). See
[docs/testing.md](docs/testing.md).

## License

MIT. See [LICENSE](LICENSE). BEA depends on Frida (wxWindows Library Licence) and other packages listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md); Unicorn is installed by the user and never distributed with BEA.
