/** Limitation sentences of area watch (CI-I5). Day-0 content by WP0 (seeded with the sentences DESIGN requires); ONLY WP-WATCH edits this file.
 *  Fixed BEA-authored text; template parameters are BEA-controlled only (numbers, hex, ids, enum codes). */
export const WATCH_LIMITATIONS = {
  WATCH_RATE_LIMIT: (perSecond: number) =>
    `The page-guard watch exceeded ${String(perSecond)} accesses per second on its pages and was disarmed to protect the target; later accesses were not observed.`,
  WATCH_SUSPEND_WINDOWS: (n: number) =>
    `BEA suspended its own guard ${String(n)} time(s) for its memory accesses; target accesses inside those windows were not observed.`,
  WATCH_PAGE_GUARD_COST:
    "A page-guard watch traps every access to its pages, not only the watched bytes; the target ran slower while it was armed.",
  TRACE_ENTRY_SYNTHESIZED:
    "The first instructions of each followed invocation ran in the hook trampoline; the entry block was added from the function start, not observed by Stalker.",
  // ---- WP9 additions (append-only)
  WATCH_DR_TRAP_AFTER:
    "Debug registers trap after the access; the accessing instruction was recovered by decoding up to the next instruction (insn_confidence says how reliably).",
  WATCH_DR_READ_WRITE:
    "Hardware has no read-only watch: read_write traps reads and writes alike and each hit's access comes from its instruction's memory operand; where the instruction could not be decoded, a write that stores the value already present is reported as a read.",
  WATCH_PAGE_GUARD_CONCURRENT:
    "While one access to a watched page is single-stepped the page is unguarded; accesses other threads make in that window were not observed, so on pages several threads touch hits can be missed.",
  WATCH_KERNEL_ACCESS:
    "While the guard is set, system calls the target makes on the watched pages (ReadFile, recv or NtQuery* into a watched buffer) fail with STATUS_GUARD_PAGE_VIOLATION; BEA re-arms the guard, and these accesses are not reported as hits. Prefer debug_register for I/O buffers.",
  WATCH_POLL_SAMPLED: (intervalMs: number) =>
    `The range was sampled every ${String(intervalMs)} ms; changes that reverted between two samples, and the instructions that made them, were not observed.`,
  WATCH_STALKER_THREADS:
    "Hits on threads followed by trace_execution execute inside Stalker's code cache; their accessing instruction is reported as unknown.",
  WATCH_ARM_ERRORS: (n: number) =>
    `The debug register could not be set on ${String(n)} thread(s) (most exit while being armed); accesses from those threads were not observed.`,
  WATCH_UNVERIFIED:
    "Reading the debug registers back did not confirm the watch on every sampled thread; some accesses may not have been observed.",
  TRACE_DYNAMIC_BLOCKS:
    "Stalker blocks are dynamic blocks: they end after calls and do not split at join points; map them to static basic blocks by range overlap.",
  TRACE_EXCLUDED_MODULES: (n: number) =>
    `${String(n)} module(s) outside the traced set were excluded from Stalker; calls into them ran natively, callbacks from them were not followed, and the exclusion lasts for the session.`,
  TRACE_FUNCTIONS_UNRESOLVED: (n: number) =>
    `${String(n)} block(s) could not be attributed to a .pdata function (no image on disk, no unwind data, or code outside modules).`,
  COVERAGE_DRCOV_LAYOUT:
    "The drcov file uses the DynamoRIO drcov version 2 layout as read by Lighthouse and Cartographer; it was not checked against every drcov consumer.",
  COVERAGE_UNATTRIBUTED: (n: number) =>
    `${String(n)} block(s) outside every module were left out of the export, which is module-relative.`,
  // ---- review fix AGENT-3 (append-only)
  WATCH_KERNEL_ACCESS_SEEN: (n: number) =>
    `The guard was consumed outside a trap ${String(n)} time(s) (a system call on a watched page, or another process); each such system call failed in the target with STATUS_GUARD_PAGE_VIOLATION, and the access is not among the hits.`,
  WATCH_AUTO_PAGE_GUARD:
    "method auto chose page_guard: the range is not one aligned 1, 2, 4 or 8-byte debug-register watch, or no debug-register slot was free. Watch an I/O buffer with debug_register (aligned parts of it) to keep the target's system calls working.",
  WATCH_RATE_LIMIT_BUSY: (percent: number) =>
    `Handling the page-guard traps held the target for ${String(percent)}% of a 100 ms window (the limit is half), so the watch was disarmed to protect the target; later accesses were not observed.`,
} as const satisfies Readonly<Record<string, string | ((...args: never[]) => string)>>;
