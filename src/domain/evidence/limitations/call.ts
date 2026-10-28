/** Limitation sentences of area call (CI-I5). Day-0 content by WP0 (seeded with the sentences DESIGN requires); ONLY WP-CALL edits this file.
 *  Fixed BEA-authored text; template parameters are BEA-controlled only (numbers, hex, ids, enum codes). */
export const CALL_LIMITATIONS = {
  CALL_FP_DEFAULT:
    "The call ran with the Windows default FP environment (MXCSR 0x1F80, FPCW 0x027F), not a target thread's; flush-to-zero or rounding settings of target threads were not applied.",
  CALL_CALLEE_EXCEPTIONS: (n: number) =>
    `The callee raised ${String(n)} exception(s) that its own handlers resolved; the handlers' side effects are included in the results.`,
  CALL_SEH_UNAVAILABLE:
    "The call thunk could not register its exception frame; faults were caught before the callee's own handlers, so code that relies on SEH or C++ exceptions is reported as faulting.",
  CALL_HOOKS_ON_PATH: (n: number) =>
    `${String(n)} BEA instrument(s) were on the call path; their listeners were suppressed for the calling thread and their recordings do not contain these calls.`,
} as const satisfies Readonly<Record<string, string | ((...args: never[]) => string)>>;
