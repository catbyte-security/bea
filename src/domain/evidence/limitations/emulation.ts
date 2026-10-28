/** Limitation sentences of area emulation (CI-I5; S5 §11.5, §9). ONLY WP-EMU edits this file.
 *  Fixed BEA-authored text; template parameters are BEA-controlled only (numbers, hex, ids, enum codes): import and
 *  snapshot names never appear here (they are counted; the result's `deviations` carry the details). */
export const EMULATION_LIMITATIONS = {
  // ---------------------------------------------------------------- loader deviations (image and dump sessions)
  EMU_ENTRY_NOT_RUN:
    "DllMain, CRT initialization and TLS callbacks were not executed; globals keep their file-image values (image session).",
  EMU_NO_SEH_DISPATCH: "SEH and C++ exception dispatch are not modeled; a raised exception stops emulation.",
  EMU_TEB_STACK_REWRITTEN: "The TEB stack bounds were rewritten to the emulator's synthetic stack.",
  EMU_ISA_GUARD_OFF: "The VEX/EVEX guard was off; VEX.128 instructions may have executed with silently wrong results.",
  EMU_ISA_GUARD_INCOMPLETE:
    "The ISA guard could not cover every VEX/EVEX site it found; an unsupported instruction may have run unguarded.",
  EMU_FP_TAGGING_INCOMPLETE:
    "x87 or FP-status reader tagging hit its site cap; inexact-x87 and FP-status deviations may be under-reported.",
  EMU_SYNTHETIC_TEB: "The TEB, PEB and TLS of the emulated thread are synthetic; no process initialization ran.",
  EMU_SYNTHETIC_KUSER:
    "KUSER_SHARED_DATA is synthetic; time and OS-version fields read from it do not reflect the host.",
  EMU_IAT_REBOUND: "Import address table slots were rebound in emulator memory to BEA's import models.",
  EMU_DELAY_IMPORTS: "The image has delay-load imports; they resolve to BEA stubs only when called.",
  EMU_MANAGED_IMAGE: "The image is a managed (.NET) image; its IL code is not emulated.",
  EMU_PATCHED:
    "The emulated memory was patched before the baseline (emu_open patches); results describe the patched code.",
  EMU_MALFORMED_DIRECTORY: "A PE directory of the emulated image was malformed; entries from it may be missing.",
  EMU_ENGINE_UNVALIDATED:
    "The emulator engines are not the validated set (unicorn 2.1.4, capstone 5.0.9, pefile 2024.8.26); engine behaviour may differ from the tested one.",
  EMU_SELFTEST_MISMATCH:
    "The emulator engine self-test differs from the validated set; re-run `bea doctor --backend emulation --probe` before trusting bit-exact results.",
  EMU_MEMORY_UNCAPPED: "The emulator bridge could not cap its own memory; a large run can exhaust host memory.",
  // ---------------------------------------------------------------- call-level deviations
  EMU_INEXACT_IMPORTS: (n: number) =>
    `${String(n)} import(s) ran as host double-precision math models and can differ in the last bits from the target's CRT (see deviations).`,
  EMU_X87_INEXACT:
    "x87 transcendental instructions executed; Unicorn approximates them (up to 19,737 ulp observed for sin of large arguments).",
  EMU_SSE_APPROX:
    "RCPSS/RCPPS/RSQRTSS/RSQRTPS or DPPS/DPPD executed; Unicorn computes them differently from hardware (exact reciprocals instead of the CPU's approximation table, sequential dot-product sums), so results are not bit-exact.",
  EMU_SSE_TAGGING_INCOMPLETE:
    "Approximate-SSE instruction tagging hit its site cap; approximate-SSE deviations may be under-reported.",
  EMU_HEAP_EXHAUSTED:
    "A guest allocation failed because the emulated heap (memory.heap_mb) was full; the allocator returned NULL where the real process may have succeeded.",
  EMU_BATCH_STOPPED: (index: number, resource: "heap" | "scratch" | null) =>
    resource === "heap"
      ? `The chain batch stopped at vector ${String(index)}: the emulated heap (memory.heap_mb) could not hold that vector's placement:"heap" buffers, which stay allocated in the session state; nothing of that vector ran, and the result covers the vectors before it.`
      : `The chain batch stopped at vector ${String(index)}: that vector's buffers could not be placed${resource === "scratch" ? " in the argument scratch region (memory.scratch_mb)" : ""}; nothing of that vector ran, and the result covers the vectors before it.`,
  EMU_FP_STATUS_UNMODELED: "The code read FP status flags; the emulator does not set MXCSR exception flags.",
  EMU_CPUID:
    "CPUID executed; the emulated CPU reports no AVX/FMA, so feature-dispatched code can take a different path than on the host CPU.",
  EMU_TSC_VIRTUAL: "RDTSC returned a virtual time-stamp counter, not the host's.",
  EMU_NONDETERMINISTIC:
    "The run was not deterministic (watchdog timeout, cancel, a host-timed counter or a random source); repeating it may give different results.",
  EMU_RETURN_ZERO:
    'Unhandled imports returned zero (imports.unhandled "return_zero"); code after them ran on substituted values.',
  EMU_ZERO_PAGES:
    'Faulting pages were mapped as zero-filled memory (fault_policy "map_zero"); reads there returned zeros instead of faulting.',
  EMU_DYNAMIC_IMPORT: "An import resolved at run time (GetProcAddress) was bound to a BEA model or stub.",
  EMU_SELF_MODIFYING:
    "The code wrote to executable memory; translated blocks were flushed and the run may differ from native execution.",
  EMU_OVERLAY_OVERWRITTEN: "The code overwrote an ISA-guard INT3 overlay site.",
  EMU_RESTARTED: (lost: number) =>
    `The emulator bridge was restarted; the session state was reset to its baseline and ${String(lost)} named snapshot(s) were lost (session_status lists them).`,
  EMU_HARNESS_STOPS: (n: number) =>
    `${String(n)} vector(s) stopped for an emulator (harness) reason, such as an unsupported instruction, an unhandled import or the instruction budget; their outcome says nothing about the target.`,
  EMU_TRACE_TRUNCATED: (cap: number) => `A trace hit its event cap (${String(cap)}); later events were not kept.`,
  // ---------------------------------------------------------------- dump-backed sessions
  EMU_DUMP_STATE:
    "The session emulates a memory capture: memory outside the captured regions is unavailable, and an access there stops the vector (inconclusive, not a target fault).",
  EMU_DUMP_RUNNING: "The capture was taken while the process ran; memory and thread state may be torn across threads.",
  // ---------------------------------------------------------------- diff_function
  DIFF_TESTED_INPUTS_ONLY:
    "Equivalence holds on the tested inputs only; inputs that were not tested may behave differently.",
  DIFF_EXCLUDED: (n: number) =>
    `${String(n)} vector(s) were excluded from the verdict as inconclusive (compare.inconclusive "exclude").`,
  DIFF_NOT_RUN: (n: number) =>
    `${String(n)} vector(s) did not run on every leg (deadline or cancellation); continue with vector_offset.`,
  DIFF_IMAGE_MISMATCH:
    "The live module and the emulated image are different binaries (allow_image_mismatch); differences may come from the build rather than the emulator.",
  DIFF_LIVE_LOST: "The function terminated the live process during the live leg; later vectors did not run live.",
  DIFF_STEAL_MODEL:
    "The live leg caught faults before the callee's own handlers (steal fallback); every faulting live vector is inconclusive.",
  DIFF_LIVE_NOT_ISOLATED:
    "The live leg is not isolated: process globals persist from vector to vector, while snapshot-isolated emulation resets them for every vector.",
  DIFF_RECORDING_VECTORS:
    "Vectors and expected values came from a hook recording; only the recorded scalar arguments and return were replayed.",
} as const satisfies Readonly<Record<string, string | ((...args: never[]) => string)>>;
