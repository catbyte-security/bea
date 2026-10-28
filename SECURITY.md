# Security

BEA injects code into other processes, reads and (behind gates) writes their memory, and starts programs. It is
meant to be driven by an AI agent that reads text produced by the programs it analyzes. This file summarizes how BEA
limits the harm that can follow; [docs/security.md](docs/security.md) has the full threat model.

## What BEA protects against

| Threat                                                     | Mitigation                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| An agent acts on the wrong process                         | Only processes BEA spawned, or that the caller names by pid or image name; `expect_sha256` pins the image; protected, critical, session-0, system, other-user and higher-integrity processes and BEA's own process tree are refused before injection.                                                                                                                                                                                                                                                               |
| An agent triggers an anti-cheat ban                        | Target-scoped anti-cheat signals (components next to the image, anti-cheat imports or loaded modules, an anti-cheat launcher among the ancestors) refuse spawn and attach. Only the user can override, globally or per image sha256. Machine-wide anti-cheat services elsewhere only produce a note.                                                                                                                                                                                                                |
| An agent escalates its own power                           | Memory writes, function overrides, caller scripts and calls into attached processes are **gates** read once at server start from the user's environment or `BEA_HOME\config.json`. No tool can change them.                                                                                                                                                                                                                                                                                                         |
| Prompt injection through target content                    | Every result that can carry target bytes, strings, names or output is marked `_meta.provenance.untrusted_content`; BEA's own prose (limitations, error messages and remediation) never contains target text.                                                                                                                                                                                                                                                                                                        |
| Prompt injection turned into persistence or code execution | Files are written only under the run's `exports` directory or user-configured roots, never over an existing file, never with executable or script extensions, never into Startup folders or system directories. Script interpreters, shells, system tools and living-off-the-land binaries are refused as spawn targets (by name, by location such as the Windows directory, and by version resource for renamed copies) unless the user allows them. Input paths and spawn programs on network shares are refused. |
| Secrets leaking into spawned programs                      | Spawned programs get an allowlisted OS environment plus the caller's explicit entries; `BEA_*` variables (including the HTTP token) are always stripped. Evidence records counts, never variable names or values.                                                                                                                                                                                                                                                                                                   |
| Orphaned processes                                         | Every spawned program is placed in a kill-on-close kernel job object before its first instruction; the tree dies at `close_session`, at server exit, and if BEA is killed after adoption. A server that dies in the few tens of milliseconds between creating the program and adopting it leaves that program suspended and outside the job (see docs/security.md).                                                                                                                                                 |
| A crashed BEA leaves a trap armed in an attached process   | Hardware and page-guard watches are disarmed on agent unload; attached targets keep a small handler that absorbs stray BEA traps.                                                                                                                                                                                                                                                                                                                                                                                   |

## What BEA does not protect against

- **BEA is not a sandbox.** The job object kills processes; it does not stop them from reading files, using the
  network or changing the system. Analyze unknown or untrusted programs in a disposable virtual machine.
- **Same-user processes.** BEA runs with your privileges. Programs running as you, including analyzed targets, can
  read `BEA_HOME` (evidence, HTTP connection file) and talk to a local HTTP server if they obtain its token.
- **Settings you widen.** `exports.allowed_roots`, `spawn.allow_interpreters`, `spawn.allowed_programs`, `spawn.env_mode: "inherit"`, the
  anti-cheat overrides and the gates each enlarge the attack surface on purpose.
- **Clients that ignore the untrusted marker.** BEA labels target content; it cannot make a client or model honor
  the label.
- **Kernel-level anti-cheat** without user-mode files is invisible to BEA's signals; a missing refusal is not a
  clearance.

## Injection footprint

Attaching or spawning loads `frida-agent.dll` and about 24 system DLLs into the target, starts 3 thread-pool threads
and patches a few system-DLL functions. After detach, 11 DLLs stay loaded. Every spawn and attach result carries this
statement as a limitation. The target can detect it.

## Reporting a vulnerability

Please report security issues privately to the maintainers (for example through the repository host's private
vulnerability reporting) rather than in a public issue. Include the BEA version (`bea version`), the client, the exact
tool calls or CLI commands, and what you expected to happen. Do not include analyzed programs you are not allowed to
share.
