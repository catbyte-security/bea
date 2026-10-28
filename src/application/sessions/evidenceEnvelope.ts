import type { z } from "zod";

import type { recordedEnvelopeShape } from "../../contracts/schemas/envelope.js";
import type { BeaEvidence } from "../../domain/evidence/record.js";
import type { FxId } from "../../domain/ids.js";
import type { JsonValue } from "../../domain/json.js";
import { compactOf } from "../../domain/time.js";

/**
 * The spread result envelope of a recorded tool (S2 §8, D-INT-17) built from the Evidence record the tool just wrote
 * (record-before-deliver). Only envelope keys; the tool adds its result fields.
 */
type RecordedEnvelope = {
  -readonly [K in keyof typeof recordedEnvelopeShape]?: z.output<(typeof recordedEnvelopeShape)[K]>;
};

export const envelopeOf = (
  record: BeaEvidence<JsonValue>,
  extras: { readonly effectsApplied?: readonly FxId[] } = {},
): Required<
  Pick<RecordedEnvelope, "evidence_id" | "predicate_type" | "confidence" | "authority" | "coverage" | "limitations">
> &
  RecordedEnvelope => {
  const subject = record.subject;
  const instanceId = subject?.kind === "process-instance" ? subject.instance_id : undefined;
  const moduleMapId =
    subject?.kind === "process-instance" || subject?.kind === "emulation"
      ? (subject.module_map_id ?? undefined)
      : undefined;
  const effects = extras.effectsApplied ?? record.effects;
  return {
    evidence_id: record.evidence_id,
    predicate_type: record.predicate_type,
    confidence: record.confidence,
    authority: record.authority,
    coverage: record.coverage,
    limitations: [...record.limitations],
    ...(instanceId === undefined ? {} : { instance_id: instanceId }),
    ...(moduleMapId === undefined ? {} : { module_map_id: moduleMapId }),
    ...(record.observed_at === null ? {} : { observed_at: compactOf(record.observed_at) }),
    perturbation: {
      level: record.perturbation.level,
      active_effect_ids: [...record.perturbation.active_effect_ids],
      tainted: record.perturbation.tainted_by.length > 0,
    },
    ...(effects.length === 0 ? {} : { effects_applied: [...effects] }),
    ...(record.redactions.length === 0 ? {} : { redactions: record.redactions.length }),
  };
};
