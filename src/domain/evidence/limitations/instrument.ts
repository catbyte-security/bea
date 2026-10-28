/** Limitation sentences of area instrument (CI-I5). Owned by WP-HOOK (hook_function, wait, stop_instrumentation,
 *  query_events). Fixed BEA-authored text; template parameters are BEA-controlled only (numbers, hex, ids, enum codes). */
export const INSTRUMENT_LIMITATIONS = {
  HOOK_FORCED_RELOCATION:
    "The function was too short for a default inline hook; it was hooked with forced relocation, which can misbehave if another thread is inside the first instructions at install time.",
  HOOK_SAMPLED: (n: number) =>
    `Only every ${String(n)}th call was recorded (sample_every); event counts and value statistics cover the recorded calls only.`,
  HOOK_BACKTRACE_RATE: (perSec: number) =>
    `Backtraces were captured for at most ${String(perSec)} calls per second; the other events carry no backtrace.`,
  HOOK_READ_FAILURES: (n: number) =>
    `${String(n)} capture read(s) failed (null pointer or unreadable memory); those fields are null in their events.`,
  HOOK_NATIVE_TIER:
    "The native hook tier records raw argument registers and stack slots only; values are decoded on the host from the capture specification.",
  HOOK_NO_DURATION:
    "Calls were recorded at entry only (no return value or leave capture), so call durations are unknown.",
  HOOK_TARGET_THUNK: (to: string) =>
    `The address is a jump thunk; Interceptor patched its target ${to}, so every caller of that target is observed.`,
  TARGET_PAUSED:
    'The target is paused (spawned and not resumed yet): its instruments record nothing and their duration clock starts at resume_process. Block with resume_process {wait_ms, until:"instruments_done"} instead.',
  QUERY_VALUE_CAP: (chars: number) =>
    `Some values were longer than ${String(chars)} characters and were shortened in this page; read the recording with fields to see them whole.`,
  QUERY_GROUP_CAP: (n: number) =>
    `More than ${String(n)} distinct groups were seen; later new groups were counted under the totals only.`,
} as const satisfies Readonly<Record<string, string | ((...args: never[]) => string)>>;
