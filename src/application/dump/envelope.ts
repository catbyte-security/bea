import type { Coverage } from "../../domain/evidence/coverage.js";
import type { BeaEvidence } from "../../domain/evidence/record.js";
import type { EvId, FxId, MmId, PiId } from "../../domain/ids.js";
import type { JsonValue } from "../../domain/json.js";
import type { CompactAnchor } from "../../domain/time.js";

/** The recorded envelope keys (src/contracts/schemas/envelope.ts recordedEnvelopeShape) of one evidence record. */
export interface RecordedEnvelope {
  readonly evidence_id: EvId;
  readonly predicate_type: string;
  readonly confidence: BeaEvidence["confidence"];
  readonly authority: BeaEvidence["authority"];
  readonly coverage: Coverage;
  readonly limitations: string[];
  readonly instance_id?: PiId;
  readonly module_map_id?: MmId;
  readonly observed_at?: CompactAnchor;
  readonly perturbation?: {
    readonly level: BeaEvidence["perturbation"]["level"];
    readonly active_effect_ids: FxId[];
    readonly tainted: boolean;
  };
  readonly effects_applied?: FxId[];
  readonly redactions?: number;
}

const MAX_LIMITATIONS = 64;

export const envelopeOf = (record: BeaEvidence<JsonValue>): RecordedEnvelope => {
  const subject = record.subject?.kind === "process-instance" ? record.subject : null;
  const anchor = record.observed_at;
  return {
    evidence_id: record.evidence_id as EvId,
    predicate_type: record.predicate_type,
    confidence: record.confidence,
    authority: record.authority,
    coverage: record.coverage,
    limitations: record.limitations.slice(0, MAX_LIMITATIONS),
    ...(subject !== null ? { instance_id: subject.instance_id as PiId } : {}),
    ...(subject?.module_map_id != null ? { module_map_id: subject.module_map_id as MmId } : {}),
    ...(anchor !== null
      ? {
          observed_at: {
            seq: anchor.seq,
            effect_epoch: anchor.effect_epoch,
            module_map_epoch: anchor.module_map_epoch,
          },
        }
      : {}),
    perturbation: {
      level: record.perturbation.level,
      active_effect_ids: record.perturbation.active_effect_ids as FxId[],
      tainted: record.perturbation.tainted_by.length > 0,
    },
    ...(record.effects.length > 0 ? { effects_applied: record.effects as FxId[] } : {}),
    ...(record.redactions.length > 0 ? { redactions: record.redactions.length } : {}),
  };
};
