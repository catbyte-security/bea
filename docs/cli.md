# BEA command line

`bea` is one binary with two faces: `bea mcp` runs the MCP server, and every other command is a short-lived CLI
process that builds its own application, runs one tool (or a scenario) and tears everything down before it exits.
Generated commands go through the same `invokeTool` pipeline as MCP, so validation, errors and results are identical.

Owner: WP15-CLI. Design: DESIGN §5.8, annex S1 §7, S6 §8.1–8.2.

## Output and exit codes

- stdout carries exactly **one document**: the result, or `{"error": <projection>}` (the closed error contract in
  [errors.md](errors.md)). The default is **TOON**; `--json` prints JSON (indented on a terminal, compact when piped).
  There is no global `--format` (it would collide with `read_memory.format`).
- Progress (`--progress`, always on for `bea run`) and logs go to **stderr** as JSON lines
  (`{"bea_progress":{tool, seq, phase, message}}`).
- Large data never goes inline: dumps, coverage and bundles are files reported as `{path, bytes, sha256}`.

| Exit      | Meaning                                                                                                                         |
| --------- | ------------------------------------------------------------------------------------------------------------------------------- |
| 0         | completed (results may carry partial coverage, limitations, unknowns); setup `planned`/`cancelled`/`ready`; doctor healthy      |
| 1         | could not complete (structured error on stdout); cleanup incomplete; setup `needs_confirmation`/`needs_human`; doctor unhealthy |
| 130 / 143 | SIGINT / SIGTERM, reported after the running call and the cleanup settled                                                       |
| 141       | the reader of stdout went away early (EPIPE)                                                                                    |

## Commands

| Command                                                                        | Purpose                                                                     |
| ------------------------------------------------------------------------------ | --------------------------------------------------------------------------- |
| `bea mcp` · `bea mcp --http …` · `bea mcp doctor [--json] [--timeout-ms N]`    | MCP server (stdio / HTTP, see [http.md](http.md)) and its self-check        |
| `bea status`, `bea ps [filter]`, `bea evidence show\|export\|verify`           | tools that need no session                                                  |
| `bea modules\|symbols\|maps\|threads\|map\|read\|disasm\|dump\|call\|script …` | one tool on a live target                                                   |
| `bea hook\|watch\|trace\|trace-api …`                                          | one instrument: install, run, summarize                                     |
| `bea emulate --image PE [--address A] --input request.json`                    | one emulator call (`emu_call`)                                              |
| `bea run <scenario.json\|-> [--evidence-out DIR] [--keep-run] [--json]`        | a planned multi-step investigation                                          |
| `bea doctor …`, `bea setup …`, `bea uninstall …`                               | health report and client registration ([setup.md](setup.md))                |
| `bea tools [--json]`                                                           | every tool: area, phase, hints, gate, CLI command or the reason it has none |
| `bea schema <tool\|command> [--output]`                                        | the advertised input (or output) JSON Schema                                |
| `bea help [command]`, `bea <command> --help`, `bea version`                    | help is generated from the contracts                                        |

The router matches built-ins first, then the longest generated command (`evidence show` before `evidence`).
`bea help` lists the commands of the running build; `bea tools` lists every tool, including the scenario-only and
MCP-only ones.

## Generated commands

Each tool contract's `cli` field picks a tier (S6 §8.1); flags come from the tool's advertised JSON Schema.

| Schema shape                | Flag                                                                               |
| --------------------------- | ---------------------------------------------------------------------------------- |
| string, enum                | `--name value`                                                                     |
| integer, number             | `--name N`: decimal or `0x` hex, optionally signed; negative values as `--name=-1` |
| boolean                     | `--name` / `--no-name`                                                             |
| array of strings or numbers | repeatable `--name v --name w`                                                     |
| objects, arrays of objects  | only through `--input FILE\|-`                                                     |

- Field names become kebab-case flags (`follow_pointers` → `--follow-pointers`).
- `cli.positional` fields may be given positionally. A field given as a flag leaves the positional sequence; a
  list-typed last positional is variadic (`bea map 0x140001000 +0x2000 …`).
- `--keep-run` keeps the command's evidence run (below); it is taken out before the flags are parsed, and after `--`
  it belongs to the spawned program.
- `--input FILE|-` supplies a JSON object with any fields. Capture shorthands (`--capture name=arg0:f32+0x8@both`,
  `src/cli/shorthands.ts`) merge over it, and explicit flags win over both.
- **File fields** (CI-I11): only fields a contract lists in `cli.fileFields` read files — `bea script hook.js --pid N`
  reads `hook.js` into `run_script.source`; `-` reads stdin. No other string is ever treated as a file reference.
- Only one argument may read stdin per command.
- Global flags: `--input`, `--json`, `--progress`, `--help`/`-h`.

### Targets (session and instrument tiers)

Exactly one of:

- `--pid N` (or the pid as the first positional) or `--name EXE`: attach. The target is detached, never killed, at
  the end.
- `--spawn PROG [-- args…]`: spawn suspended under BEA's job object. PROG is resolved against the current directory,
  everything after `--` is its argv, and the target is killed when the command ends.

Attaching or spawning loads BEA's Frida agent (frida-agent.dll + 24 system DLLs; 11 stay loaded after detach). Use
these commands only on processes you own.

Before any target is touched, the command checks the tool's `always` gate and validates the tool input (with a
placeholder session id). A typo or a closed gate therefore never costs an injection or a spawned process.

**Offline mode:** a contract's `cli.offlineField` waives the target. `bea symbols --pe-path X` and
`bea map a b --pe-path X` read the PE file and create no session.

### Runners

| Tier               | Sequence                                                                                                                                                                                                                                                                                                                        |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| oneshot            | the tool                                                                                                                                                                                                                                                                                                                        |
| session-oneshot    | attach, or spawn → `resume_process` → the tool → `close_session`                                                                                                                                                                                                                                                                |
| instrument-oneshot | attach/spawn → install (on a spawned target: before its first instruction) → `resume_process` if spawned → `wait {until:"done"}` in ≤ 60 s slices until the recording finished, the target exited, or `duration_ms` (counted from resume) plus 5 s → `query_events {view:"summary"}` → `stop_instrumentation` → `close_session` |
| emu-oneshot        | `emu_open {image_path}` → the tool → `close_session`                                                                                                                                                                                                                                                                            |

The instrument document is `{instrument, stop_reason: finished|target_exited|duration|wait_failed, wait, summary,
stopped}`. A failing follow-up (`summary` or `stopped` holds `{error}`) still prints the document but exits 1.

Every session the command created is closed in a `finally` block, followed by `lifecycle.closeAll("cli-exit")`. Both
happen after SIGINT/SIGTERM too: cleanup calls use their own signal, never the cancelled one. A cleanup failure turns
exit 0 into 1 and prints a note on stderr.

## Scenarios: `bea run scenario.json`

```json
{
  "schema": "bea-scenario/1",
  "target": { "spawn": { "program": "C:/lab/behavior.exe", "args": ["--out-dir", "C:/lab/out"] } },
  "steps": [
    { "tool": "trace_api", "input": { "profiles": ["file", "registry"], "duration_ms": 20000 }, "save_as": "api" },
    { "tool": "resume_process", "input": { "wait_ms": 25000 } },
    { "tool": "query_events", "input": { "recording_id": "${api.instrument.recording_id}", "view": "summary" } }
  ],
  "teardown": "close",
  "on_error": "stop",
  "limits": { "total_ms": 600000 }
}
```

- `target` is optional: `{spawn: <spawn_process input>}`, `{attach: {pid}|{name}}` or `{emulate: <emu_open input>}`.
  Its output is available as `${target.…}`. A spawned target stays paused until a `resume_process` step, so hooks can
  be installed first.
- Each step is `{tool, input = {}, save_as?, expect: ok|error|any = ok}`. A step whose expectation fails stops the run
  (`on_error: "stop"`) or is recorded and skipped (`"continue"`).
- **Session-creating steps** (D-INT-47): `spawn_process`, `attach_process` and `emu_open` may be steps with `save_as`.
  Every session the runner creates (target and steps) is closed at the end, newest first. This is how one scenario
  holds a live and an emulation session for `diff_function`.
- **`session_id` injection:** when a target exists, its `session_id` is added to every step whose contract has a
  `session_id` field and that did not set one. Nothing is ever injected into `live_session_id` or `emu_session_id`;
  those always come from references.
- **References:** a string that is exactly `${name.path}` is replaced by the value at `path` in the result saved
  under `name` (`rows[0].address` indexes arrays). This is whole-string substitution only, never interpolation. An
  unresolved reference fails its step with `invalid_request`. A step that failed saves `{error: projection}`.
- **Validation before any effect** (exit 1, nothing runs):
  - the scenario schema;
  - unknown tools; MCP-only tools; `close_session` (the teardown owns it);
  - a closed `always` gate;
  - references to names not saved by an earlier step;
  - duplicate or reserved `save_as` names (`target`);
  - the input of every step without references (with a placeholder session id where one would be injected);
  - the target input.
- **Teardown** always runs, also after SIGINT/SIGTERM or `limits.total_ms`: `close_session` for every created
  session, then `export_evidence {out_path: DIR}` when `--evidence-out DIR` is given. A relative `DIR` (a plain name,
  no `..`) is written under this run's exports directory (`BEA_HOME/runs/<run id>/exports/DIR`); an absolute `DIR`
  must lie under a configured `exports.allowed_roots` entry and is checked during validation, before any step runs
  (output-path policy, D-INT-42: it must not exist either). Last comes `lifecycle.closeAll`.
- **Result** (`bea-scenario-result/1`): `{ok, session_id, stopped?: signal|time_limit, target, steps: [{index, tool,
  save_as?, expect, passed, ok, ms, result|error}], sessions: [{session_id, tool, created_by}], teardown: {closed,
  cleanup_ok}, evidence_bundle?: {path, bytes, sha256}|{error}}`. Exit 0 iff every expectation held and teardown
  succeeded; 130/143 after a signal.

## Evidence runs

Every one-shot and `bea run` records into its own run directory, `BEA_HOME/runs/<run id>` (`kind: "cli"`). The run is
finalized by `lifecycle.closeAll("cli-exit")` and then **deleted** (S2 §9.2), unless:

- `--keep-run` was given;
- `bea run --evidence-out DIR` asked for a bundle (the bundle lives under the run's `exports/`);
- the cleanup failed (the run stays for `bea status` and diagnosis).

A kept run is named on stderr (`bea: evidence run kept: <dir>`). Only the command's own run directory is ever deleted.
`bea doctor --probe` removes the run its probe recorded, and `runs/` and `BEA_HOME` too when the doctor created them.

There is no separate `bea emulate request.json` built-in. Emulation runs through the generated `emulate` command, or
through a scenario with an `emulate` target or an `emu_open` step.

## `bea mcp doctor`

This command spawns the real stdio server of the same build (`node <package>/scripts/bea.mjs mcp`) through the SDK
client. The child gets a minimal environment: PATH, SystemRoot, TEMP/TMP, profile directories and `BEA_*`. The
overall deadline is 30 s (`--timeout-ms`, at most 60 s). It checks, in order:

1. `spawn-initialize`: serverInfo `{name: "bea", version}` and non-empty instructions.
2. `inventory`: the advertised tools equal the build's catalog. Missing, unexpected and duplicate names are listed.
3. `annotations`: each tool's hints and `_meta["bea/effects"]` match its contract.
4. `schema-dialect`: every schema is JSON Schema 2020-12.
5. `bea_status`: the call succeeds, the output schema holds, the text equals the JSON, and the untrusted marker is
   present.
6. `invalid-request`: `bea_status {"bogus":1}` returns a strict `{error}` with code `invalid_request`.
7. `shutdown`: after stdin EOF the server exits with code 0 within 2 s.

The report is `bea.mcp-doctor/1`. The command exits 0 iff every check passed.

## `bea doctor`

See [setup.md](setup.md#bea-doctor).
