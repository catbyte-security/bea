import type { recordedEnvelopeShape } from "../../contracts/schemas/envelope.js";
import type { z } from "zod";

import type { JsonValue } from "../../domain/json.js";
import { compactOf } from "../../domain/time.js";
import type { RecordedEvidence } from "../../ports/evidence.js";

/** The recorded-envelope fields (D-INT-17) as the output schemas type them. */
export type RecordedEnvelope = z.output<z.ZodObject<typeof recordedEnvelopeShape>>;

/**
 * Envelope of one recorded `bea.evidence/1` record (DESIGN §5.4 "Envelope"): the reserved keys spread beside the
 * result fields. Optional keys are present only when they carry information (effects_applied non-empty,
 * redactions > 0), as the envelope schema requires.
 */
export const recordedEnvelope = <R extends JsonValue>(recorded: RecordedEvidence<R>): RecordedEnvelope => {
  const record = recorded.record;
  const subject = record.subject;
  const instance = subject?.kind === "process-instance" ? subject : null;
  return {
    evidence_id: record.evidence_id,
    predicate_type: record.predicate_type,
    confidence: record.confidence,
    authority: record.authority,
    coverage: record.coverage,
    limitations: [...record.limitations],
    ...(instance === null ? {} : { instance_id: instance.instance_id }),
    ...(instance?.module_map_id == null ? {} : { module_map_id: instance.module_map_id }),
    ...(record.observed_at === null ? {} : { observed_at: compactOf(record.observed_at) }),
    perturbation: {
      level: record.perturbation.level,
      active_effect_ids: [...record.perturbation.active_effect_ids],
      tainted: record.perturbation.tainted_by.length > 0,
    },
    ...(record.effects.length > 0 ? { effects_applied: [...record.effects] } : {}),
    ...(record.redactions.length > 0 ? { redactions: record.redactions.length } : {}),
  };
};
