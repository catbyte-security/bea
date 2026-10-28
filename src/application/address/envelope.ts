import type { BeaEvidence } from "../../domain/evidence/record.js";
import type { JsonValue } from "../../domain/json.js";
import { compactOf } from "../../domain/time.js";
import type { RecordedEvidence } from "../../ports/evidence.js";

/**
 * The spread result envelope (S2 §8.1) of one recorded tool call: the projection of the (redacted) record result
 * plus the reserved keys taken from the record itself, so the envelope never claims more than the ledger holds.
 */
export interface RecordedEnvelopeFields {
  readonly evidence_id: BeaEvidence["evidence_id"];
  readonly predicate_type: string;
  readonly confidence: BeaEvidence["confidence"];
  readonly authority: BeaEvidence["authority"];
  readonly coverage: BeaEvidence["coverage"];
  readonly limitations: string[];
  readonly instance_id?: `pi_${string}`;
  readonly module_map_id?: `mm_${string}`;
  readonly observed_at?: { seq: number; effect_epoch: number | null; module_map_epoch: number | null };
  readonly perturbation?: {
    level: BeaEvidence["perturbation"]["level"];
    active_effect_ids: `fx_${string}`[];
    tainted: boolean;
  };
  readonly effects_applied?: `fx_${string}`[];
  readonly redactions?: number;
}

export const envelopeOf = <R extends JsonValue, P extends object>(
  recorded: RecordedEvidence<R>,
  project: (result: R) => P,
): P & RecordedEnvelopeFields => {
  const record = recorded.record;
  const subject = record.subject;
  const instanceId = subject?.kind === "process-instance" ? subject.instance_id : undefined;
  const moduleMapId = subject !== null && subject.kind !== "image" ? (subject.module_map_id ?? undefined) : undefined;
  const perturbation = record.perturbation;
  return {
    ...project(record.result),
    evidence_id: record.evidence_id,
    predicate_type: record.predicate_type,
    confidence: record.confidence,
    authority: record.authority,
    coverage: record.coverage,
    limitations: [...record.limitations].slice(0, 64),
    ...(instanceId === undefined ? {} : { instance_id: instanceId }),
    ...(moduleMapId === undefined ? {} : { module_map_id: moduleMapId }),
    ...(record.observed_at === null ? {} : { observed_at: compactOf(record.observed_at) }),
    ...(perturbation.level === "none" && perturbation.active_effect_ids.length === 0
      ? {}
      : {
          perturbation: {
            level: perturbation.level,
            active_effect_ids: [...perturbation.active_effect_ids].slice(0, 256),
            tainted: perturbation.tainted_by.length > 0,
          },
        }),
    ...(record.effects.length === 0 ? {} : { effects_applied: [...record.effects].slice(0, 64) }),
    ...(record.redactions.length === 0 ? {} : { redactions: record.redactions.length }),
  };
};
