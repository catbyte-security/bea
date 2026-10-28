import type { DeviationKind } from "../../domain/emuProtocol.js";
import type { DifferenceProfile, Verdict } from "./compare.js";

/**
 * diff_function hints (S5 §9.8, a CLOSED list): each names a likely cause of a non-equivalence and the probe that
 * tests it. The probes are recorded into the auto-unknown (`recommended_probes`, ≤ 5). Messages are BEA-authored.
 */
export const HINT_CODES = [
  "x87_inexact",
  "hle_math_model",
  "cpuid_dispatch",
  "fp_status_read",
  "file_image_state",
  "possible_state_carryover",
  "last_ulp_only",
  "nan_payload_only",
  "emulator_nan_rule",
  "signed_zero_only",
  "outcome_class",
  "raw_pointer_inputs",
  "image_mismatch",
  "engine_unvalidated",
] as const;
export type HintCode = (typeof HINT_CODES)[number];

export interface Hint {
  readonly code: HintCode;
  readonly message: string;
  /** recorded into the unknown's recommended_probes (null: informational) */
  readonly probe: string | null;
}

const HINTS: { readonly [C in HintCode]: { readonly message: string; readonly probe: string | null } } = {
  x87_inexact: {
    message:
      "The emulated run executed x87 transcendental instructions, which Unicorn approximates; trust the live leg for those results.",
    probe:
      "Trust the live leg for x87 transcendental code, or override the function's math import or path (emu_open imports.overrides).",
  },
  hle_math_model: {
    message: "An import ran as BEA's inexact host-math model in the emulator, not the target's CRT.",
    probe:
      "Re-run the emulation leg on a dump-backed session (emu_open {live_session_id}) so the real CRT runs, or override the import.",
  },
  cpuid_dispatch: {
    message:
      "CPUID executed in the emulator, which reports no AVX/FMA; feature-dispatched code can take a different path than on the host CPU.",
    probe:
      "Compare paths: emu_call with trace.coverage vs call_function with coverage; patch the dispatch flag via emu_open.patches to force the same path.",
  },
  fp_status_read: {
    message: "The code reads MXCSR/x87 status flags, which the emulator does not set.",
    probe: "Trust the live leg for code that reads FP status flags.",
  },
  file_image_state: {
    message:
      "The emulator runs the file image (globals keep their on-disk values) while the live process has runtime state.",
    probe:
      'Use a dump-backed session: emu_open {live_session_id} (or dump_memory {format:"bundle"} -> emu_open {dump_path}).',
  },
  possible_state_carryover: {
    message:
      "The live leg keeps process globals from vector to vector while the emulation leg resets them (snapshot isolation).",
    probe: 'Re-run with emulation.isolation "chain" and emulation.state_from "current".',
  },
  last_ulp_only: {
    message: "Every float difference is within 2 ulp: typical of FMA vs mul+add or a different libm variant.",
    probe: "Inspect worst[]; set compare.tolerance_ulp to quantify the difference (it never changes the verdict).",
  },
  nan_payload_only: {
    message: "Every difference is a NaN with a different payload.",
    probe: 'Re-run with compare.nan "any_nan" if the NaN payload is irrelevant.',
  },
  emulator_nan_rule: {
    message:
      "Every difference is a NaN payload or sign in the emulated leg: when two NaNs meet in an SSE instruction Unicorn propagates the larger-significand NaN, x86 hardware the first source operand. An engine artifact, not the function.",
    probe: 'Trust the live leg for NaN payloads, or compare with compare.nan "any_nan".',
  },
  signed_zero_only: {
    message: "Every difference is +0 vs -0.",
    probe: "Check whether the sign of zero matters to callers of this function.",
  },
  outcome_class: {
    message: "At least one vector returned in one leg and stopped in another (or stopped at a different site).",
    probe: 'Inspect worst[]; run emu_call single with detail "complete" on that vector.',
  },
  raw_pointer_inputs: {
    message: "Raw pointer inputs refer to the live address space and are unmapped in an image-backed emulator.",
    probe: "Pass pointers as buffers or address expressions, or use a dump-backed emulation session.",
  },
  image_mismatch: {
    message: "The live module and the emulated image are different binaries (allow_image_mismatch).",
    probe: null,
  },
  engine_unvalidated: {
    message: "The emulator engines are not the validated set; engine behaviour may differ from the tested one.",
    probe: null,
  },
};

export interface HintFacts {
  readonly verdict: Verdict;
  readonly differences: number;
  readonly outcomeDifferences: number;
  readonly profile: DifferenceProfile;
  readonly emulationDeviations: ReadonlySet<DeviationKind>;
  readonly emulationImportModels: ReadonlySet<string>;
  readonly imageBackedWithLive: boolean;
  readonly liveWithSnapshotIsolation: boolean;
  readonly rawPointerInputs: boolean;
  readonly imageMismatch: boolean;
  readonly engineUnvalidated: boolean;
  /** review fix EMU-7: the emulation leg is part of the comparison */
  readonly emulationCompared?: boolean;
}

export const diffHints = (facts: HintFacts): Hint[] => {
  const codes: HintCode[] = [];
  const differs = facts.differences > 0;
  const valueOnly = differs && facts.outcomeDifferences === 0 && facts.profile.integerDiffs === 0;
  if (differs && facts.emulationDeviations.has("x87_transcendental_inexact")) codes.push("x87_inexact");
  if (
    differs &&
    (facts.emulationImportModels.has("builtin-inexact") || facts.emulationDeviations.has("inexact_import_model"))
  )
    codes.push("hle_math_model");
  if (differs && facts.emulationDeviations.has("cpuid_executed")) codes.push("cpuid_dispatch");
  if (facts.emulationDeviations.has("fp_status_flags_unmodeled")) codes.push("fp_status_read");
  // EMU-7: NaN-payload-only differences against the emulator are its two-NaN propagation rule; the state hints would
  // only send the agent to dump-backed sessions and chained isolation, which never change them
  const engineNan = valueOnly && facts.profile.nanPayloadOnly && facts.emulationCompared === true;
  if (!engineNan && facts.imageBackedWithLive && facts.verdict !== "equivalent-on-tested-inputs")
    codes.push("file_image_state");
  if (!engineNan && differs && facts.liveWithSnapshotIsolation) codes.push("possible_state_carryover");
  if (valueOnly && facts.profile.allWithin2Ulp) codes.push("last_ulp_only");
  if (engineNan) codes.push("emulator_nan_rule");
  else if (valueOnly && facts.profile.nanPayloadOnly) codes.push("nan_payload_only");
  if (valueOnly && facts.profile.signedZeroOnly) codes.push("signed_zero_only");
  if (facts.outcomeDifferences > 0) codes.push("outcome_class");
  if (facts.rawPointerInputs) codes.push("raw_pointer_inputs");
  if (facts.imageMismatch) codes.push("image_mismatch");
  if (facts.engineUnvalidated) codes.push("engine_unvalidated");
  return codes.slice(0, 16).map((code) => ({ code, message: HINTS[code].message, probe: HINTS[code].probe }));
};

/** Deduplicated probes of the hints (≤ 5) for the auto-unknown. */
export const hintProbes = (hints: readonly Hint[]): string[] =>
  [...new Set(hints.map((h) => h.probe).filter((p): p is string => p !== null))].slice(0, 5);
