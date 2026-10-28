import type { Deviation, DeviationKind } from "../../domain/emuProtocol.js";
import { COMPLETE, mergeCoverage, type Coverage, type ReasonCode } from "../../domain/evidence/coverage.js";
import { CORE_LIMITATIONS } from "../../domain/evidence/limitations.js";
import { EMULATION_LIMITATIONS as L } from "../../domain/evidence/limitations/emulation.js";

/**
 * Emulation coverage and limitations (S5 §11.5). Coverage is `complete` iff no vector stopped for a HARNESS reason,
 * the run was not cut by a deadline or a cancel, and no substituted or inexact model was used (builtin-inexact or
 * override imports, return_zero, map_zero pages, dynamic imports bound to models, inexact x87). Exact builtin models
 * keep `complete` with the HLE limitation. Every emulation result also says it is not an observation of the real
 * process. Sentences are fixed text; counts are the only parameters (import and snapshot names stay in `deviations`).
 */
type Sentence = string;

/** Deviation kind -> its limitation sentence (null: reported in deviations only). */
export const deviationSentence = (deviation: Pick<Deviation, "kind" | "count" | "detail">): Sentence | null => {
  switch (deviation.kind) {
    case "tls_callbacks_not_run":
    case "entry_point_not_run":
      return L.EMU_ENTRY_NOT_RUN;
    case "imports_hle_bound":
      return CORE_LIMITATIONS.EMU_HLE_IMPORTS;
    case "no_seh_dispatch":
      return L.EMU_NO_SEH_DISPATCH;
    case "delay_imports_present":
      return L.EMU_DELAY_IMPORTS;
    case "managed_image":
      return L.EMU_MANAGED_IMAGE;
    case "isa_guard_off":
      return L.EMU_ISA_GUARD_OFF;
    case "isa_guard_incomplete":
      return L.EMU_ISA_GUARD_INCOMPLETE;
    case "x87_tagging_incomplete":
    case "fp_status_tagging_incomplete":
      return L.EMU_FP_TAGGING_INCOMPLETE;
    case "sse_tagging_incomplete":
      return L.EMU_SSE_TAGGING_INCOMPLETE;
    case "sse_approx_inexact":
      return L.EMU_SSE_APPROX;
    case "hle_heap_exhausted":
      return L.EMU_HEAP_EXHAUSTED;
    case "iat_rebound":
      return L.EMU_IAT_REBOUND;
    case "teb_stack_bounds_rewritten":
      return L.EMU_TEB_STACK_REWRITTEN;
    case "memory_patched":
      return L.EMU_PATCHED;
    case "synthetic_teb":
      return L.EMU_SYNTHETIC_TEB;
    case "synthetic_kuser_shared_data":
      return L.EMU_SYNTHETIC_KUSER;
    case "malformed_directory":
      return L.EMU_MALFORMED_DIRECTORY;
    case "engine_unvalidated":
      return L.EMU_ENGINE_UNVALIDATED;
    case "x87_transcendental_inexact":
      return L.EMU_X87_INEXACT;
    case "inexact_import_model":
      return L.EMU_INEXACT_IMPORTS(Math.max(1, deviation.count ?? 1));
    case "unhandled_import_returned_zero":
      return L.EMU_RETURN_ZERO;
    case "auto_mapped_zero_pages":
      return L.EMU_ZERO_PAGES;
    case "fp_status_flags_unmodeled":
      return L.EMU_FP_STATUS_UNMODELED;
    case "cpuid_executed":
      return L.EMU_CPUID;
    case "virtualized_tsc":
      return L.EMU_TSC_VIRTUAL;
    case "nondeterministic_tsc":
    case "nondeterministic_rng":
      return L.EMU_NONDETERMINISTIC;
    case "dynamic_import_resolved":
      return L.EMU_DYNAMIC_IMPORT;
    case "self_modifying_code":
      return L.EMU_SELF_MODIFYING;
    case "isa_overlay_overwritten":
      return L.EMU_OVERLAY_OVERWRITTEN;
    case "bridge_restarted_state_reset": {
      const lost = deviation.detail?.["lost_snapshots"];
      return L.EMU_RESTARTED(Array.isArray(lost) ? lost.length : 0);
    }
  }
};

/** Deviations that substitute or approximate target behaviour: the result is `partial` (S5 §11.5). */
const INEXACT: ReadonlySet<DeviationKind> = new Set<DeviationKind>([
  "inexact_import_model",
  "unhandled_import_returned_zero",
  "auto_mapped_zero_pages",
  "dynamic_import_resolved",
  "x87_transcendental_inexact",
  "sse_approx_inexact",
  "hle_heap_exhausted",
  "fp_status_flags_unmodeled",
  "isa_overlay_overwritten",
]);
const HLE_SUBSTITUTION: ReadonlySet<DeviationKind> = new Set<DeviationKind>([
  "inexact_import_model",
  "unhandled_import_returned_zero",
  "dynamic_import_resolved",
]);

export interface EmulationAssessment {
  readonly coverage: Coverage;
  readonly limitations: readonly string[];
}

export interface AssessInput {
  readonly deviations: readonly Pick<Deviation, "kind" | "count" | "detail">[];
  /** import models used by the run: builtin-inexact and override models substitute target code */
  readonly importModels?: readonly string[];
  /** vectors that stopped for a harness reason; how many of them were ISA-guard stops */
  readonly harnessStops?: number;
  readonly isaStops?: number;
  readonly endedEarly?: "deadline" | "cancelled" | null;
  readonly deterministic?: boolean;
  readonly traceTruncated?: number | null;
  readonly extraLimitations?: readonly string[];
}

const partial = (reason: ReasonCode): Coverage => ({ status: "partial", truncated: false, reasons: [reason] });

export const assessEmulation = (input: AssessInput): EmulationAssessment => {
  const parts: Coverage[] = [COMPLETE];
  const limitations: string[] = [CORE_LIMITATIONS.NOT_REAL_PROCESS];
  for (const deviation of input.deviations) {
    const sentence = deviationSentence(deviation);
    if (sentence !== null) limitations.push(sentence);
    if (HLE_SUBSTITUTION.has(deviation.kind)) parts.push(partial("hle_imports_used"));
    else if (INEXACT.has(deviation.kind)) parts.push(partial("emulation_deviation"));
  }
  if ((input.importModels ?? []).some((model) => model === "builtin-inexact" || model === "override"))
    parts.push(partial("hle_imports_used"));
  const harness = input.harnessStops ?? 0;
  const isa = input.isaStops ?? 0;
  if (isa > 0) parts.push(partial("isa_guard_stop"));
  if (harness > isa) parts.push(partial("emulation_deviation"));
  if (harness > 0) limitations.push(L.EMU_HARNESS_STOPS(harness));
  if (input.endedEarly === "deadline" || input.endedEarly === "cancelled") {
    parts.push(partial(input.endedEarly));
    limitations.push(CORE_LIMITATIONS.ENDED_EARLY(input.endedEarly));
  }
  if (input.deterministic === false) limitations.push(L.EMU_NONDETERMINISTIC);
  if (input.traceTruncated !== null && input.traceTruncated !== undefined) {
    parts.push({ status: "partial", truncated: true, reasons: ["row_cap"] });
    limitations.push(L.EMU_TRACE_TRUNCATED(input.traceTruncated));
  }
  limitations.push(...(input.extraLimitations ?? []));
  return { coverage: mergeCoverage(...parts), limitations: [...new Set(limitations)] };
};

/** Harness-attributed statuses (S5 §3.13) when the bridge gave no per-vector attribution. */
export const HARNESS_STATUSES: ReadonlySet<string> = new Set([
  "unsupported_instruction",
  "unhandled_import",
  "syscall",
  "raised",
  "budget_exhausted",
  "timeout",
  "cancelled",
  "engine_error",
]);
