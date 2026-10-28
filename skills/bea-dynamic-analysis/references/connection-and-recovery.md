# Connection and recovery

Installing this skill supplies instructions only. It does not register the BEA MCP server, build BEA, install the
emulator, or add tools to an agent that is already running.

## Is BEA connected?

- `bea_*` tools are listed (at least `bea_status`): BEA is connected. Go straight to the target. Do not run doctor or
  setup before every investigation.
- `bea_status` answers without loading Frida or starting anything. Read it when you need to know what is enabled:
  - `backends[]` rows `frida`, `agent`, `jobhost`, `emulator` with `state` `available | not-loaded | unavailable |
    failed`. `not-loaded` is normal before first use: Frida loads at the first session, and the emulator resolves
    Python and its bridge at the first `emu_open` (until then its row is `not-loaded` even when everything is
    installed).
  - `gates` — which of `write_memory`, `override_function`, `run_script`, `call_attached` the user enabled.
  - `limits` — wait and call ceilings, session caps, debug-register slots, quotas, `anti_cheat_allowed`.
  - `notes` — BEA-authored notes such as a machine-wide anti-cheat service or open gates.
- The live `tools/list` is authoritative. An older server may lack tools this skill describes; use what it offers.

## The recovery ladder

`bea` below is the BEA command-line interface. When it is not on PATH, use `node <BEA checkout>/scripts/bea.mjs`,
which is also exactly what the client registration launches (`[node, <realpath>/scripts/bea.mjs, "mcp"]`).

1. **Diagnose (read-only).** `bea doctor --client <id> --json`. Client ids: `claude_code`, `codex`, `cursor`,
   `vscode`, `claude_desktop`, `gemini_cli`. Without `--client`, doctor audits every detected client.
   Doctor never writes configuration and never loads Frida unless asked (`--backend frida|emulation`, `--probe`).
2. **Tell the reasons apart.**
   - Registration `missing`, `stale` or `invalid`: needs a scoped configuration repair (step 3).
   - Registration `aligned` but no tools in this session: the client must be restarted or reconnected. Doctor cannot
     prove that the running agent has loaded the server.
   - `foreign` / `unknown` / `manual` / `symlink`: a human must look at the file; setup will not touch it.
   - A backend check failing (`frida:*`, `jobhost:*`, `emulator:*`) affects only the work that needs that backend.
3. **Plan the repair.** `bea setup --client <id> --dry-run --json`. Show the user the exact files, the backups setup
   would make, and the skill replacement. Get explicit **approval**.
4. **Apply.** `bea setup --client <id> --yes`. Setup writes one transaction per file (backup, temp file, rename,
   read-back, rollback on mismatch). Claude Code may rewrite `~/.claude.json` while it runs, so the user should close
   it first.
5. **Restart** every client listed in the result's `restart`. Check that `bea_*` tools now appear, then resume the
   original task.
6. Tools still missing: read the client's MCP launch error. `bea mcp doctor` starts the real server and checks
   initialize, the tool inventory, annotations, `bea_status`, an invalid request and a clean shutdown. Do not repeat
   setup for a problem setup cannot fix.

Setup never installs or upgrades Node.js, npm, gcc, Python or Frida, and never copies your environment into a client
entry. The skill is installed with Claude Code (or `--skill`); `bea doctor --skill` compares the installed skill's
name, version and tool count with the bundled copy.

## Timeouts

| Symptom                                              | Meaning                                          | What to do                                                                                                |
| ---------------------------------------------------- | ------------------------------------------------ | --------------------------------------------------------------------------------------------------------- |
| The client reports "timed out awaiting tools/call"   | the **client** gave up; BEA may still be working | do not repeat the call; read state with `session_status`, `wait`, or `get_evidence {filters:{operation}}` |
| `provider_timeout` error                             | BEA hit its own 120 s deadline                   | partial observations are in `details.partial_observation`; shorten the window or split the work           |
| `wait` returns `satisfied:false`, `reason:"timeout"` | a poll ran out                                   | call `wait` again; nothing was consumed                                                                   |

Recommend a client tool timeout of at least **180 s** (BEA's ceiling is 120 s per call; `wait_ms` and `timeout_ms`
are at most 60 s). Codex registrations get `tool_timeout_sec = 240` automatically; Claude Code and Gemini CLI need
the user to set it.

After a cancellation the client never sees the reply. Instruments installed by the cancelled call keep running;
find what it recorded with `get_evidence {filters:{operation:"<tool name>"}}` and stop it with
`stop_instrumentation`.

## The emulator

`emu_open` needs Python with unicorn 2.1.x, capstone 5.x and pefile. A `not-loaded` `emulator` row only means no
`emu_open` has run yet: call `emu_open`, or check without opening a session with
`bea doctor --backend emulation --json`. When `emu_open` fails with `capability_unavailable` ("run
`bea setup --emulator`"), or the row is `unavailable`:

1. Explain that setup will create a BEA-owned venv under `BEA_HOME\emu\venv` with pinned, hash-checked packages, and
   that it downloads them from the package index.
2. With the user's approval: `bea setup --emulator --dry-run --json`, show the plan, then `bea setup --emulator --yes`.
3. `bea doctor --backend emulation --json` verifies the bridge.

After `bea setup --emulator` a running server picks the new venv up at the next `emu_open` (no restart). A lost
bridge (`capability_unavailable`, reason `bridge-lost`) needs no restart either: retry, and the session reopens
from its baseline (named snapshots made before the loss are gone).

Never `pip install` anything yourself, and never point BEA at a Python you chose; `BEA_PYTHON` is the user's setting.
When `BEA_PYTHON` or `python` in `config.json` is set, that interpreter takes precedence over the venv, so setup
cannot fix it: tell the user which setting the doctor output names.

## CLI fallbacks

The CLI runs the same tools through the same validation. It prints one TOON document (`--json` for JSON) and closes
every session it created before exiting. Flags are the tool's field names in kebab case (`duration_ms` →
`--duration-ms`); list fields repeat the flag; objects go through `--input FILE`.

| Need              | Command                                                                                                |
| ----------------- | ------------------------------------------------------------------------------------------------------ |
| status, processes | `bea status`, `bea ps <filter>`                                                                        |
| behavior triage   | `bea trace-api --profiles file --profiles network --duration-ms 30000 --spawn C:\lab\tool.exe -- args` |
| one hook          | `bea hook game.exe+0x123460 --pid 1234 --capture dt=arg1:f32 --returns f32 --duration-ms 5000`         |
| rebase offline    | `bea map game.exe:0x1401234ab --pe-path C:\games\game.exe`                                             |
| module dump       | `bea dump game.exe --pid 1234`                                                                         |
| multi-step plan   | `bea run scenario.json` (`bea-scenario/1`; steps run in order, sessions torn down at the end)          |
| one emulated call | `bea emulate --image C:\lab\lib.dll --address lib.dll!f --input request.json`                          |
| list every tool   | `bea tools`, `bea schema <tool>`                                                                       |

A one-shot that spawns kills its target at the end; one that attaches detaches. Session tools that need state across
calls (`scan_*`, `wait`, `query_events`, `diff_function`) are scenario steps, not one-shots.

## HTTP mode

`bea mcp --http` serves MCP on `127.0.0.1` with a random bearer token in `BEA_HOME\http\connection.json`. It is for
the user's own scripts. Any process running as the same user can read that file, including a traced program, so do
not suggest HTTP mode while untrusted programs are being analyzed.
