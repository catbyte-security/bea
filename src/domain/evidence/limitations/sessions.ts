/** Limitation sentences of area sessions (CI-I5). Day-0 content by WP0 (seeded with the sentences DESIGN requires); ONLY WP-SESS edits this file.
 *  Fixed BEA-authored text; template parameters are BEA-controlled only (numbers, hex, ids, enum codes). */
export const SESSIONS_LIMITATIONS = {
  ARGV_ENV_COUNTS:
    "Program arguments and caller environment entries are recorded as counts and key digests, not values.",
  STDIN_EMPTY_PIPE: "The target's stdin is an open, empty pipe; a program that waits for console input blocks.",
  POSIX_BEST_EFFORT:
    "Linux containment is best effort (process group, killed on close); a hard-killed server can leave the target running.",
  CRASH_PC_UNKNOWN:
    "The process ended with an error status but no crash report arrived (a fast fail or stack overflow is likely); the faulting instruction is unknown.",
  ENV_ALLOWLIST: (withheld: number) =>
    `The target received BEA's allowlisted OS environment plus the caller's entries; ${String(withheld)} server variable(s) were withheld and BEA_* variables are never passed.`,
  ENV_INHERITED:
    "The target inherited the server environment (config spawn.env_mode = inherit) minus BEA_* variables; secrets in that environment are visible to the target.",
  ANTI_CHEAT_GLOBAL_PRESENT:
    "A machine-wide anti-cheat service was running; this target showed no anti-cheat signal of its own and was not refused.",
  // WP-SESS additions (S3 §8–§15)
  OUTPUT_NOT_CAPTURED:
    "Output capture was off (capture_output:false): the target inherited the server's standard handles and its output is not recorded.",
  CRASH_ACK_TIMEOUT:
    "A crash or exit report was acknowledged before its evidence write completed (5 s bound); the record may be missing.",
  CREATION_TIME_UNCHECKED:
    "Frida reported no usable start time, so containment adopted the process by image path and parent only (creation time not cross-checked).",
  MAIN_PATH_DIFFERS:
    "The agent reported a main-module path that differs from the requested program path (for example an 8.3 short name).",
  PROTECTION_UNKNOWN: "The process's protection or critical status could not be read before attaching.",
  HELPER_LOST: "The containment helper exited unexpectedly; the kernel terminated the job and the target with it.",
  KILLED_BEFORE_ADOPTION:
    "The target was killed before containment adopted it; it was still suspended and had run no code, so it had no descendants.",
  CRASH_EXIT_MISMATCH:
    "The last exception report does not match the process exit status; the reported crash site may not be the cause of the exit.",
  ANTI_CHEAT_LIVE_CHECK:
    "Anti-cheat modules already loaded in an attached process can only be detected after injection; the live module list was checked before any instrumentation.",
  EXIT_REPORT_LATE:
    "The agent connection reported the process ended, but the containment or watcher exit report did not arrive within 2 s; the exit code may be missing.",
  WATCHER_UNAVAILABLE:
    "No exit watcher could be started for this attached process; its exit code is unknown and exit is detected only when the agent connection ends.",
  // ---- review fix LIFE-8 (append-only)
  AGENT_LEFT_LOADED:
    "BEA's agent did not respond and could not be unloaded (a call that never returned holds its thread): frida-agent.dll, its threads and the running call stay in the process until it exits, although BEA detached.",
  // ---- BEA-FEEDBACK 2026-10-28 (append-only)
  USER_SHADOW_STACKS:
    "The process enforces user-mode hardware shadow stacks (Intel CET); trace_execution and hooks with leave captures are not verified on such processes.",
} as const satisfies Readonly<Record<string, string | ((...args: never[]) => string)>>;
