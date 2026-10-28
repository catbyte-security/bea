/** Limitation sentences of area behavior (CI-I5). Day-0 content by WP0 (seeded with the sentences DESIGN requires); ONLY WP-BEHAVIOR edits this file.
 *  Fixed BEA-authored text; template parameters are BEA-controlled only (numbers, hex, ids, enum codes).
 *  The first six are the trace_api "always" set (S6 §6.8); the API_* ones are conditional (WP-BEHAVIOR). */
export const BEHAVIOR_LIMITATIONS = {
  DIRECT_SYSCALLS: "Direct system calls bypass the hooked API layer and are not observed.",
  BROKERED_ACTIONS:
    "Work brokered to other processes (services, COM servers, the shell) happens outside this process and is not observed.",
  CHILDREN_UNINSTRUMENTED: "Child processes are recorded when created but are not instrumented.",
  PREEXISTING_HANDLES: "Handles opened before tracing started may appear without their object names.",
  NO_PAYLOADS: "Payload bytes (file contents, registry data, network data) are not captured; only sizes and names are.",
  LATE_MODULES:
    "APIs in modules loaded later are hooked when the module loads; calls made during that load can be missed.",
  API_HOOKS_FAILED: (n: number) =>
    `${String(n)} profile API(s) could not be hooked; calls to them are not observed (see hooks_failed).`,
  API_BACKTRACE_UNAVAILABLE:
    "API profile events carry the first caller outside system modules but no backtrace; use hook_function with backtrace on one API for call stacks.",
  API_FAILED_EXCLUDED: "Failed calls are excluded (include_failed:false); probes such as missing files do not appear.",
  API_EXEC_REGIONS_SAMPLED:
    "Executable memory allocated through VirtualAlloc/NtAllocateVirtualMemory cannot be hooked; such regions are found by sampling and when they are freed, so short-lived regions can be missed.",
} as const satisfies Readonly<Record<string, string | ((...args: never[]) => string)>>;

/** The six sentences every trace_api result carries (DESIGN §6.2 #22). */
export const TRACE_API_ALWAYS = [
  BEHAVIOR_LIMITATIONS.DIRECT_SYSCALLS,
  BEHAVIOR_LIMITATIONS.BROKERED_ACTIONS,
  BEHAVIOR_LIMITATIONS.CHILDREN_UNINSTRUMENTED,
  BEHAVIOR_LIMITATIONS.PREEXISTING_HANDLES,
  BEHAVIOR_LIMITATIONS.NO_PAYLOADS,
  BEHAVIOR_LIMITATIONS.LATE_MODULES,
] as const;
