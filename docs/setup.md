# Setting BEA up for MCP clients

Owner: WP15-CLI. Design: DESIGN §5.8, annex S1 §7.8–§7.9 (REA's setup and doctor model), S5 §6.4 for the emulator.

## Quick start

```sh
bea doctor                                  # read-only: what is registered, what is missing
bea setup --client claude_code --dry-run    # show the exact plan (paths, backups, skill)
bea setup --client claude_code --yes        # apply it; then restart Claude Code
bea doctor --client claude_code             # verify (exit 0 = healthy)
```

Set your client's tool timeout to at least **180 s**: a single BEA call may block for up to 120 s. Codex gets
`tool_timeout_sec = 240` automatically. For Claude Code and Gemini CLI, BEA does not write a timeout key (OI-5), so
set it yourself.

## `bea setup`

```
bea setup [--client ID]… [--all-detected] [--skill|--no-skill] [--emulator] [--dry-run] [--yes] [--json]
```

| `--client`       | File                                                                                                                                                            | Key                 | Entry                                                                                        |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- | -------------------------------------------------------------------------------------------- |
| `claude_code`    | `%CLAUDE_CONFIG_DIR%\.claude.json`, else `%USERPROFILE%\.claude.json` (strict JSON)                                                                             | `mcpServers.bea`    | `{command, args}`                                                                            |
| `codex`          | `%CODEX_HOME%\config.toml`, else `~\.codex\config.toml`                                                                                                         | `[mcp_servers.bea]` | `command`, `args`, `startup_timeout_sec = 30`, `tool_timeout_sec = 240` (larger values kept) |
| `cursor`         | `~\.cursor\mcp.json` (JSONC)                                                                                                                                    | `mcpServers.bea`    | `{command, args}`                                                                            |
| `vscode`         | `%APPDATA%\Code\User\mcp.json` (JSONC)                                                                                                                          | `servers.bea`       | `{type: "stdio", command, args}`                                                             |
| `claude_desktop` | MSIX `…\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude_desktop_config.json` if installed so, else `%APPDATA%\Claude\claude_desktop_config.json` | `mcpServers.bea`    | `{command, args}` (quit Claude Desktop first)                                                |
| `gemini_cli`     | `%GEMINI_CLI_HOME%\.gemini\settings.json`, else `~\.gemini\settings.json` (JSONC)                                                                               | `mcpServers.bea`    | `{command, args}`                                                                            |

**The registered command** is `[<node>, <realpath of this package's scripts/bea.mjs>, "mcp"]`. Setup refuses a package
running from npm's `_npx` cache. Setup never copies your environment into an entry; `BEA_*` keys already present in
an entry BEA owns are kept on update.

**Which clients:**

- `--client ID` (repeatable) selects those clients.
- `--all-detected` selects every client whose config file or directory exists.
- With neither, only clients that already have a BEA-owned entry are refreshed. Detection is never permission.

The skill is installed when `--skill` is given or `claude_code` is selected. `--no-skill` turns it off.

**Ownership and states.** An existing `bea` entry is classified first:

| State     | Meaning                                                               | Setup       |
| --------- | --------------------------------------------------------------------- | ----------- |
| `missing` | no `bea` entry                                                        | create      |
| `aligned` | BEA-owned and equal to the plan                                       | unchanged   |
| `stale`   | BEA-owned, different                                                  | update      |
| `foreign` | a `bea` entry BEA did not write                                       | needs_human |
| `unknown` | points at a `bea.mjs` that is gone or belongs to another checkout     | needs_human |
| `invalid` | the file does not parse, or the edit would change more than the entry | needs_human |
| `manual`  | Codex defines `mcp_servers.bea` with dotted keys or inline            | needs_human |
| `symlink` | the config file is a symbolic link                                    | needs_human |

An entry is BEA-owned when one of its `command`/`args` resolves to this package's `scripts/bea.mjs` or names
`bea-agents[@version]`. If **any** selected client needs a human, setup writes nothing at all.

**Approval:**

- `--dry-run` → `planned`, exit 0, read-only.
- `--yes` applies the plan.
- In a terminal (stdin, stdout and stderr all TTYs, no `--json`), the plan is shown on stderr followed by
  `Apply these N changes? [y/N]`.
- Otherwise the command stops at `needs_confirmation`, exit 1.

**Edits and transaction:**

- Comments, key order and formatting of everything else are preserved: JSONC edits use `jsonc-parser`, and Codex
  replaces only the key lines of `[mcp_servers.bea]`, keeping its sub-tables such as `[mcp_servers.bea.env]` and
  per-tool approvals.
- Each file is published in one transaction:
  1. Re-check that the file still matches the plan; a change means `target_changed`.
  2. Write a one-time `<file>.bea.backup`. A different existing backup is kept, and the current bytes go to
     `<file>.bea.backup.<sha12>.recovery`.
  3. Write an O_EXCL temp file in the same directory and fsync it.
  4. Publish by rename (update) or hard link (create).
  5. Read the file back and verify it. On a mismatch, roll back.
- Running the same setup twice is a no-op: nothing is written and no backup is made.

**Result** (`bea.setup/1`):

```
{status: planned|cancelled|needs_confirmation|ready|needs_human,
 planned_actions, applied_actions,
 clients: {id: {state_before, outcome, reason?}},
 restart, doctor, failures?, remediation?}
```

Restart every client listed in `restart`. An aligned file does not mean a running client has loaded the tools.
Claude Code may rewrite `~/.claude.json` while it runs, so close it before applying.

### The skill

The skill goes to `<CLAUDE_CONFIG_DIR or ~/.claude>/skills/bea-dynamic-analysis/`, copied from the build's
`dist/skills/` (`npm run build:skill` injects `metadata.tool_count`, `metadata.bea_version` and pins
`bea-agents@latest`).

A directory counts as BEA's only if its `SKILL.md` starts with `---\nname: bea-dynamic-analysis\n`. Anything else,
or a symlinked directory, is left alone (`needs_human`).

Install copies into a staging directory and renames it into place. An old owned copy is renamed aside first, then
removed.

### The emulator: `bea setup --emulator`

Setup asks the `EmulatorProvisioner` (WP14-EMU) for a plan. The plan creates a BEA-owned venv under
`BEA_HOME\emu\venv` with the pinned, hash-checked `unicorn 2.1.4`, `capstone 5.0.9` and `pefile 2024.8.26`. The plan
shows the venv, the tool (uv or venv+pip), the base Python, the packages, the network origins and the exact
commands. It is applied only after approval.

Global site-packages are never touched, and Unicorn is never redistributed. A failed plan (no suitable Python, or a
build without the provisioner) is `needs_human`.

## `bea uninstall`

```
bea uninstall [--client ID]… [--skill] [--dry-run] [--yes] [--json]
```

This removes BEA-owned entries; for Codex that includes the `[mcp_servers.bea.*]` sub-tables. It uses the same
backup, verify and rollback transaction as setup.

- Without `--client`, it removes every owned registration and the owned skill.
- With `--client`, it removes the skill only when `--skill` is also given.
- Foreign and unknown entries are skipped and reported.
- `BEA_HOME` (runs, evidence, the emulator venv) is kept.

## `bea doctor`

```
bea doctor [--client ID]… [--backend frida|emulation]… [--skill] [--probe] [--json]
```

The doctor is **read-only**: it never writes configuration and never leaves `BEA_HOME` behind. The only processes it
starts are probes it owns, and only with `--backend` or `--probe`. Plain `bea doctor` never loads Frida. A probe that
records evidence (`frida:inject-probe` opens a real session) writes a CLI run; doctor deletes that run after closing,
and removes `runs/` and `BEA_HOME` again when it created them.

| Check                                                                                                                                                                                                                                                                                                                                                                               | When                                                                                                                                                                         |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `node` (^24.11), `platform` (win32-x64; linux-x64 best effort), `config`, `home` (exists, or nearest ancestor writable)                                                                                                                                                                                                                                                             | always                                                                                                                                                                       |
| `config:unknown-env`                                                                                                                                                                                                                                                                                                                                                                | always, informational (likely-misspelled `BEA_*` variables)                                                                                                                  |
| `registration:<client>`                                                                                                                                                                                                                                                                                                                                                             | detected clients (audit-wide) or `--client`                                                                                                                                  |
| `skill` (name, `metadata.version`, `tool_count` vs the bundled copy)                                                                                                                                                                                                                                                                                                                | audit-wide when Claude Code is detected, or `--skill`                                                                                                                        |
| checks registered by the providers: `build:agent`, `frida:binding`, `frida:local-device` and `frida:inject-probe` (scope `probe`) (SESS); `jobhost:binary`, `jobhost:probe`, `host:elevation` (PROC); `emulation:bridge-file`, `emulation:python`, `emulation:pins`, `emulation:venv` (scope `backend:emulation`) and `emulation:selftest`, `emulation:start` (scope `probe`) (EMU) | by their scope: `always`/`informational` every time, `backend:*` with `--backend`, `probe` with `--probe`; an `emulation:*` probe also needs `--backend emulation` (S1 §7.8) |

Scope works as in REA:

- With no option, doctor runs an audit-wide check.
- Any option makes the scope explicit. Only scope checks decide `healthy` and the exit code. The rest of the run goes
  to `informational_checks` and into `environment_healthy`.

The report is `bea.doctor/1`:

```
{healthy, environment_healthy,
 scope: {mode, clients, backends, skill, probe},
 scope_checks, informational_checks,
 identity: {cli_package_version, expected_skill_version, node, platform, frida_version, registrations, skill}}
```

Each check is `{name, ok, classification: healthy|missing_dependency|runtime_failure|unsupported_host|
configuration_invalid|config_drift|unknown, detail?, remediation?}`.

## Recovery ladder (for agents)

1. Run `bea doctor --client <id> --json` when BEA's tools are missing or failing.
2. Run `bea setup --client <id> --dry-run --json` and show the user the plan: paths, backups, skill replacement.
3. With the user's approval, run `bea setup --client <id> --yes`, then restart the client.
4. If the tools still do not appear, read the client's MCP launch error rather than repeating setup. Run
   `bea mcp doctor` to prove the server itself starts.
