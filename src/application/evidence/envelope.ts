import type { NextStep } from "../../contracts/schemas/envelope.js";
import { COMPLETE, type Coverage } from "../../domain/evidence/coverage.js";
import type { BeaEvidence } from "../../domain/evidence/record.js";
import type { FxId, MmId, PiId } from "../../domain/ids.js";
import type { JsonValue } from "../../domain/json.js";
import { compactOf, type CompactAnchor } from "../../domain/time.js";
import type { RecordedEvidence } from "../../ports/evidence.js";

/**
 * Envelope builders (S2 §8.1, D-INT-17) for every area's handlers: spread these next to the tool's own result fields
 * (`{...result, ...recordedEnvelope(recorded)}`) so recorded tools carry exactly the reserved keys their
 * `recordedOutput` schema expects, and polls carry `evidence_id: null`.
 */
export interface RecordedEnvelope {
  readonly evidence_id: BeaEvidence["evidence_id"];
  readonly predicate_type: string;
  readonly confidence: BeaEvidence["confidence"];
  readonly authority: BeaEvidence["authority"];
  readonly coverage: Coverage;
  readonly limitations: readonly string[];
  readonly instance_id?: PiId;
  readonly module_map_id?: MmId;
  readonly observed_at?: CompactAnchor;
  readonly perturbation?: {
    readonly level: BeaEvidence["perturbation"]["level"];
    readonly active_effect_ids: readonly FxId[];
    readonly tainted: boolean;
  };
  readonly effects_applied?: readonly FxId[];
  readonly redactions?: number;
  readonly next?: readonly NextStep[];
}

export const recordedEnvelope = (
  recorded: RecordedEvidence<JsonValue> | { readonly record: BeaEvidence },
  next?: readonly NextStep[],
): RecordedEnvelope => {
  const r = recorded.record;
  const subject = r.subject;
  const instance = subject?.kind === "process-instance" ? subject.instance_id : undefined;
  const moduleMap = subject !== null && subject.kind !== "image" ? subject.module_map_id : null;
  return {
    evidence_id: r.evidence_id,
    predicate_type: r.predicate_type,
    confidence: r.confidence,
    authority: r.authority,
    coverage: r.coverage,
    limitations: r.limitations,
    ...(instance === undefined ? {} : { instance_id: instance }),
    ...(moduleMap === null ? {} : { module_map_id: moduleMap }),
    ...(r.observed_at === null ? {} : { observed_at: compactOf(r.observed_at) }),
    ...(r.perturbation.level === "none"
      ? {}
      : {
          perturbation: {
            level: r.perturbation.level,
            active_effect_ids: r.perturbation.active_effect_ids,
            tainted: r.perturbation.tainted_by.length > 0,
          },
        }),
    ...(r.effects.length > 0 ? { effects_applied: r.effects } : {}),
    ...(r.redactions.length > 0 ? { redactions: r.redactions.length } : {}),
    ...(next === undefined || next.length === 0 ? {} : { next: next.slice(0, 3) }),
  };
};

export interface PollEnvelope {
  readonly evidence_id: null;
  readonly coverage: Coverage;
  readonly limitations: readonly string[];
  readonly next?: readonly NextStep[];
}

export const pollEnvelope = (
  coverage: Coverage = COMPLETE,
  limitations: readonly string[] = [],
  next?: readonly NextStep[],
): PollEnvelope => ({
  evidence_id: null,
  coverage,
  limitations,
  ...(next === undefined || next.length === 0 ? {} : { next: next.slice(0, 3) }),
});
