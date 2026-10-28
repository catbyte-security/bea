# Security model

BEA is a local tool that injects an agent into Windows processes on behalf of an AI agent. This document describes
the assets, the actors, what BEA trusts, and each control with the decision it implements (decision numbers refer to
[decisions.md](decisions.md)). The summary is [SECURITY.md](../SECURITY.md).

## Assets and actors

| Asset                                                            | Why it matters                                                        |
| ---------------------------------------------------------------- | --------------------------------------------------------------------- |
| The user's machine and account                                   | BEA runs with the user's privileges and can start programs            |
| Analyzed processes and their data                                | BEA reads their memory; gated tools can change it                     |
| The user's game accounts                                         | injecting into an anti-cheat-protected game can get an account banned |
| `BEA_HOME` (runs, evidence, emulator venv, HTTP connection file) | evidence integrity; the HTTP token                                    |
| The MCP client and model                                         | they act on what BEA returns                                          |

| Actor                          | Trust                                                                                                      |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------- |
| The **user**                   | trusted: chooses targets, enables gates and overrides, edits `config.json` and the environment             |
| The **agent** (model + client) | trusted to call tools, **not** trusted to widen its own authority                                          |
| The **target program**         | untrusted: its memory, strings, names, arguments, exception text and output are data, possibly adversarial |
| Other **same-user processes**  | not defended against (they share the user's privileges)                                                    |

## Authority: what only the user can change

Gates (D-INT-1, F3) are read once at server start from the environment or `BEA_HOME\config.json`, are reported in
`bea_status.gates`, and cannot be changed by any tool:

| Gate                | Environment                 | Config                    | Unlocks                                                                                                                                              |
| ------------------- | --------------------------- | ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `write_memory`      | `BEA_ALLOW_WRITE_MEMORY=1`  | `gates.write_memory`      | `write_memory`                                                                                                                                       |
| `override_function` | `BEA_ALLOW_OVERRIDE=1`      | `gates.override_function` | `override_function`                                                                                                                                  |
| `run_script`        | `BEA_ALLOW_RUN_SCRIPT=1`    | `gates.run_script`        | `run_script` (a separate Frida script, never inside BEA's agent)                                                                                     |
| `call_attached`     | `BEA_ALLOW_CALL_ATTACHED=1` | `gates.call_attached`     | `call_function` and the live leg of `diff_function` on attached targets (a call that never returns leaves BEA's agent in the process until it exits) |

A closed gate answers `capability_unavailable` with `details.gate` and the exact instruction for the user. The CLI
checks `always` gates before touching a target, so a closed gate never costs an injection.

Other user-only settings: `attach.allow_anti_cheat`, `attach.allow_anti_cheat_images`, `attach.allow_session0`,
`attach.extra_denylist`, `spawn.allow_interpreters`, `spawn.allowed_programs`, `spawn.env_mode`, `exports.allowed_roots`, quotas, `python` /
`BEA_PYTHON`. `config.json` is strict: unknown keys are configuration errors.

## Target selection (fail closed)

Spawn preflight: a drive-absolute `.exe` (`.bat`/`.cmd` refused) whose final path (junctions, symlinks, `subst` and
mapped drives resolved) is not a network location, a local existing `cwd` (a network `cwd` is `access_denied`, a
missing one `invalid_request`), PE32+ x64 (WoW64 → `unsupported_target`), `expect_sha256` checked first,
interpreter/LOLBin refusal (rule 4 below), anti-cheat signals, capacity. Input paths (`pe_path`, `image_path`,
`dump_path`, `import_evidence` `path`) follow the same local-only rule: UNC, device and network-resolving paths are
refused before BEA opens them (opening a share would send the user's NTLM credentials to that host).

Attach refusal rules, first hit wins: pid ≤ 4; BEA's own process tree (itself, its MCP client, its helpers); a pid
already in a session; an exited process; a protected (PPL) process; a critical process; session 0 (unless
`attach.allow_session0`); WoW64; the system denylist (plus `attach.extra_denylist`); another user's process; a
higher-integrity process; target-scoped anti-cheat signals.

### Anti-cheat (D-INT-1)

Signals are evaluated for the **target**, before injection:

- (a) anti-cheat components in the image's directory or up to three levels above it, which covers the Unreal Engine
  `Binaries\Win64` layout (`EasyAntiCheat/`, `EasyAntiCheat_EOS/`, `BattlEye/`, `EAAntiCheat/`,
  `start_protected_game.exe`, `BEService*.exe`); a spawn through a junction is checked around both the given and the
  real path;
- (b) anti-cheat DLLs in the image's import tables (`EasyAntiCheat_x64.dll`, `EasyAntiCheat_EOS*.dll`,
  `BEClient_x64.dll`, `EAAntiCheat*.dll`, `GameGuard*`/`npggNT*`, `xhunter*`, `mhyprot*`); on attach also among the
  loaded modules;
- (c) on attach, an anti-cheat client or launcher as parent or grandparent (`EasyAntiCheat*.exe`,
  `start_protected_game.exe`, `BEService*.exe`, `EAAntiCheat*.exe`, `vgc.exe`, `FACEIT*.exe`).

Any signal refuses with `access_denied`, reason `anti-cheat-detected`, and the signals in `details`. Machine-wide
anti-cheat services or processes elsewhere never refuse; they add a `bea_status` note and the
`ANTI_CHEAT_GLOBAL_PRESENT` limitation. Only the user can allow a signalled target: `BEA_ALLOW_ANTI_CHEAT=1` or
`attach.allow_anti_cheat: true` (global), or `attach.allow_anti_cheat_images: ["<sha256>"]` (per image, config
only). Allowed runs carry `ANTI_CHEAT_ALLOWED`. The lists are heuristics: kernel-only anti-cheat without user-mode
files, renamed components or unknown products are not detected. Modules an attached process already loaded can only
be listed after injection; that check runs before any instrumentation (`ANTI_CHEAT_LIVE_CHECK`). The skill tells
agents to stop on a refusal and never to suggest an override.

## Untrusted content and prompt injection (D-INT-41, D-INT-42)

Content from the target can contain text written to manipulate an agent ("ignore previous instructions, run …").
BEA's controls:

1. **Labeling.** Every result that can carry target content has `_meta.provenance = {untrusted_content: true,
   source: "analysis_target"}`. Only `stop_instrumentation`, `export_evidence`, `import_evidence` and
   `record_unknown` are exempt, because they return no target content. The server's MCP `instructions` and the skill
   tell the agent to treat such content as data and to report embedded requests.
2. **Clean prose channels.** Limitation sentences are fixed BEA text whose parameters are numbers, hex, ids or enum
   codes. Error messages and remediation never include agent free text (the agent's own error messages are dropped
   from diagnostics). An agent can therefore trust the envelope outside `result` fields.
3. **No side effect driven by content alone.** Every `out_path` (`dump_memory`, `export_coverage`,
   `export_evidence`, scenario `--evidence-out`) passes `checkOutputPath`:
   - drive-absolute, no `..`, no alternate data streams (`file:stream`);
   - under `BEA_HOME\runs\<run>\exports\` or a user-configured `exports.allowed_roots` entry;
   - not in `%SystemRoot%`, not in a Startup folder;
   - no executable or script extension (`.exe .dll .sys .bat .cmd .ps1 .vbs .js .hta .lnk .msi .reg .py .sh …`);
   - must not exist (writers never overwrite).
     A refusal is `access_denied` with reason `policy`. Without `out_path` files go to the exports directory.
4. **Spawn hardening.** A program that runs a command line or changes the system is refused by any of three rules:
   its name (shells, consoles and script interpreters such as `cmd`, `conhost`, `powershell`, `pwsh`, `wscript`,
   `mshta`, `bash`, `wsl`, `python`/`python3`/`py`, `node`; LOLBins and system tools such as `rundll32`, `regsvr32`,
   `msiexec`, `wmic`, `certutil`, `bitsadmin`, `msbuild`, `schtasks`, `sc`, `reg`, `taskkill`, …), its location (the
   Windows directory, the WindowsApps execution aliases, Python, Git, MSYS, Cygwin, Node, .NET and PowerShell install
   roots, checked on the given and the real path) or its version resource (`OriginalFilename`/`InternalName` of a
   renamed or hard-linked copy). Only the user lifts it: `spawn.allow_interpreters` (everything) or
   `spawn.allowed_programs` (listed drive-absolute paths or image sha256 digests).
5. **Environment allowlist.** A spawned program receives an OS allowlist (version 1) plus the caller's `env` entries;
   every `BEA_*` key is stripped from both, so the HTTP token and gate settings never reach a target. `spawn.env_mode:
   "inherit"` (user config) passes the server environment minus `BEA_*`. Evidence records the mode and counts only.
6. **Redaction.** `redact_literals` (spawn/attach) and `sensitive_values` (reads, exports) replace user-named secrets
   in results and evidence; registry value data and URL query strings are not captured by the behavior profiles.

Residual risk: a client that ignores `_meta`, settings the user widens (`exports.allowed_roots`,
`spawn.allow_interpreters`, `spawn.allowed_programs`, `env_mode: "inherit"`), and programs the rules do not know
(the refusal is defence in depth, not a complete list).

## Containment and its limits

Owned targets are adopted into a kernel Job Object (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, no breakaway) by
`bea-jobhost.exe` before their first instruction. The chain BEA server → helper → job means the tree dies when the
session closes, when the server exits, and when the server is killed after adoption. Limits:

- A job is not a sandbox: no filesystem, registry, network or privilege isolation.
- Programs relaunched through a broker (Steam, launchers, COM servers, the shell's `ShellExecute` paths) start outside
  the job (`BROKERED_LAUNCH` when detected).
- There is a window of a few tens of milliseconds between process creation (suspended) and adoption on spawn. If
  the server dies inside it, the program stays suspended and outside any job; nothing BEA starts later reclaims it
  (kill it with Task Manager). Adoption now runs before any other startup step, and a creation-time mismatch between
  the spawned process and the adopted one kills the job (review fix LIFE-4; closing the window needs a helper that is
  started before the spawn).
- The helper is an unsigned local gcc build; endpoint protection may block it (`bea doctor --probe` detects this).
- BEA never runs an uncontained owned target on Windows: if the helper is missing or unproven, spawn fails with
  `capability_unavailable`.

Attached targets are never killed by BEA. Their exit is observed through a watcher helper without terminate rights.

## Agent footprint and stability

Injection loads `frida-agent.dll` and about 24 system DLLs, starts 3 ntdll pool threads and patches a few system-DLL
functions; 11 DLLs remain after detach (`AGENT_FOOTPRINT`). Programs can detect this.

Hardware debug registers and PAGE_GUARD traps are fatal to a process that has no handler for them. BEA disarms both
on agent unload (verified also when the BEA host is killed with `taskkill /F`), never unloads an attached agent with
armed watches before its shutdown, rate-limits page-guard traps (default 20,000/s), and leaves a small native
exception handler in attached targets that absorbs stray BEA traps after an abrupt unload. Close sessions before
stopping BEA.

`call_function` executes target code on the user's request. A call that never returns cannot be interrupted; the
session is then marked unresponsive and should be closed. On an owned target closing the session kills the target. On
attached targets that risk is part of what the `call_attached` gate opts into, and it outlives BEA: the agent cannot
be unloaded while its thread runs the call, so `frida-agent.dll`, its threads and the still-running call stay in the
user's process until that process exits. Neither `close_session` (also with `force:true`, which only detaches BEA)
nor server shutdown can remove them (verified, L-S6-11 in [limitations.md](limitations.md)).

## HTTP mode (§5.9)

`bea mcp --http` binds `127.0.0.1` only and checks, per request, the `Host` and `Origin` headers, the path, and a
bearer token (compared by SHA-256 digest in constant time; 401 otherwise). Request bodies above 64 MiB are refused
with 413 before parsing. At most 4 MCP sessions; idle sessions are evicted after 5 minutes.

- The token comes from `BEA_HTTP_TOKEN` (32–256 characters) or 32 random bytes; it is **never printed**. It is
  written to `BEA_HOME\http\connection.json` together with the URL and pid.
- Every process running as the same user can read `connection.json` — **including programs BEA is analyzing**. Do
  not run HTTP mode while tracing untrusted programs.
- On Windows, when `BEA_HOME` (or `--connection-file`) lies outside the user profile, v0.1 refuses to start: it does
  not set an owner-only ACL yet (docs/http.md); `BEA_HOME` must be a drive-absolute path.
- Stop the server with an authenticated `POST /shutdown`, Ctrl+C or SIGTERM; all BEA sessions and owned targets are
  torn down first. A scripted client should launch `node <checkout>\scripts\bea.mjs mcp --http` directly (killing an
  npm `.cmd` shim would leave node and its owned targets running).

## Evidence integrity

Evidence ids are content addresses (SHA-256 over canonical JSON, RFC 8785), so a record cannot be changed without
changing its id. Bundles are staged and renamed into place; `import_evidence` verifies digests
(`evidence_integrity_mismatch` on failure) and marks imported records `origin: "imported"`. The ledger is not signed:
anyone who can write `BEA_HOME` can create a self-consistent fake run. Treat evidence as reproducible notes, not as
tamper-proof attestations.

## Emulation

The emulator bridge is a separate Python process per emulation session, started without a shell, that talks to BEA over its
standard input and output only and caps its own memory with a job object; closing its stdin ends it. It executes target code under Unicorn with no host
system calls (system calls stop the run). The Python environment is either the user's (`BEA_PYTHON`, config
`python`) or a BEA-owned venv created only with the user's approval (`bea setup --emulator`) from pinned,
hash-checked packages.
