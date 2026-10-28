// =================================================================================================
// src/application/watch/envelope.ts — the compact recorded envelope of a BEA evidence record (S2 §8.1), for the
// three watch-area tools (WP9-WATCH). Delivery-time additions (an instrument that finished while the call waited)
// may widen coverage and add limitation sentences; they never change the recorded evidence.
// =================================================================================================
import { mergeCoverage, type Coverage } from "../../domain/evidence/coverage.js";
import type { JsonValue } from "../../domain/json.js";
import type { RecordedEvidence } from "../../ports/evidence.js";

export interface RecordedEnvelope {
  readonly evidence_id: RecordedEvidence<JsonValue>["record"]["evidence_id"];
  readonly predicate_type: string;
  readonly confidence: RecordedEvidence<JsonValue>["record"]["confidence"];
  readonly authority: RecordedEvidence<JsonValue>["record"]["authority"];
  readonly coverage: Coverage;
  readonly limitations: string[];
  readonly instance_id?: `pi_${string}`;
  readonly module_map_id?: `mm_${string}`;
  readonly observed_at?: { seq: number; effect_epoch: number | null; module_map_epoch: number | null };
  readonly perturbation?: {
    level: "none" | "agent-only" | "passive" | "intrusive";
    active_effect_ids: `fx_${string}`[];
    tainted: boolean;
  };
  readonly effects_applied?: `fx_${string}`[];
  readonly redactions?: number;
}

export const envelopeOf = (
  recorded: RecordedEvidence<JsonValue>,
  extra: { readonly coverage?: readonly Coverage[]; readonly limitations?: readonly string[] } = {},
): RecordedEnvelope => {
  const r = recorded.record;
  const limitations = [...new Set([...r.limitations, ...(extra.limitations ?? [])])].slice(0, 64);
  const subject = r.subject;
  const anchor = r.observed_at;
  return {
    evidence_id: r.evidence_id,
    predicate_type: r.predicate_type,
    confidence: r.confidence,
    authority: r.authority,
    coverage:
      extra.coverage === undefined || extra.coverage.length === 0
        ? r.coverage
        : mergeCoverage(r.coverage, ...extra.coverage),
    limitations,
    ...(subject?.kind === "process-instance" ? { instance_id: subject.instance_id } : {}),
    ...(subject !== null && "module_map_id" in subject && subject.module_map_id !== null
      ? { module_map_id: subject.module_map_id }
      : {}),
    ...(anchor === null
      ? {}
      : {
          observed_at: {
            seq: anchor.seq,
            effect_epoch: anchor.effect_epoch,
            module_map_epoch: anchor.module_map_epoch,
          },
        }),
    perturbation: {
      level: r.perturbation.level,
      active_effect_ids: [...r.perturbation.active_effect_ids],
      tainted: r.perturbation.tainted_by.length > 0,
    },
    ...(r.effects.length > 0 ? { effects_applied: [...r.effects] } : {}),
    ...(r.redactions.length > 0 ? { redactions: r.redactions.length } : {}),
  };
};
