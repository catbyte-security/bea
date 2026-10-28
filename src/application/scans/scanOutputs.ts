import type { Coverage } from "../../domain/evidence/coverage.js";
import { CORE_LIMITATIONS } from "../../domain/evidence/limitations.js";
import { SCAN_LIMITATIONS } from "../../domain/evidence/limitations/scan.js";
import type { BeaEvidence } from "../../domain/evidence/record.js";
import type { JsonObject, JsonValue } from "../../domain/json.js";
import { compactOf } from "../../domain/time.js";
import type { ScanRecord } from "./ScanService.js";

/**
 * WP10-SCAN: coverage, limitations, the recorded result and the envelope projection (S2 §8.1) of scan outcomes.
 * Paging is never coverage; a scan's coverage describes the scan (hit cap, unreadable ranges, dropped candidates).
 */

/** Coverage of a finished (or still running) scan iteration. Reason codes are registered in REASONS (coverage.ts). */
export const scanCoverage = (rec: ScanRecord): Coverage => {
  if (rec.state === "running") return { status: "partial", truncated: false, reasons: ["unknown_completeness"] };
  const reasons: string[] = [];
  if (rec.truncated) reasons.push("value_cap");
  if (rec.rangesFailed > 0) reasons.push("unreadable_ranges");
  if (rec.faultedDropped > 0) reasons.push("unreadable_memory");
  if (rec.cancelled) reasons.push("cancelled");
  reasons.sort();
  return reasons.length === 0
    ? { status: "complete", truncated: false, reasons: [] }
    : { status: "partial", truncated: rec.truncated, reasons };
};

/** Fixed BEA sentences for a scan iteration (parameters are numbers and BEA ids only). */
export const scanLimitations = (rec: ScanRecord): string[] => {
  const out: string[] = [SCAN_LIMITATIONS.SCAN_SCOPE];
  if (rec.state === "running") out.push(SCAN_LIMITATIONS.SCAN_RUNNING(rec.id));
  if (rec.truncated) out.push(SCAN_LIMITATIONS.SCAN_TRUNCATED(rec.cap ?? rec.maxHits));
  if (rec.rangesFailed > 0) out.push(CORE_LIMITATIONS.UNREADABLE_RANGES);
  if (rec.faultedDropped > 0) out.push(SCAN_LIMITATIONS.SCAN_FAULTED(rec.faultedDropped));
  if (rec.cancelled) out.push(SCAN_LIMITATIONS.SCAN_CANCELLED);
  if ((rec.valueType === "f32" || rec.valueType === "f64") && rec.firstCompare === "exact")
    out.push(SCAN_LIMITATIONS.SCAN_FLOAT_EQUALITY);
  return out;
};

/** The `bea.scan.result` record body (retained; the tool output is a projection of it). */
export const scanResultBody = (rec: ScanRecord): JsonObject => ({
  scan_id: rec.id,
  value_type: rec.valueType,
  compare: rec.firstCompare,
  iteration: rec.iteration,
  state: rec.state,
  mode: rec.mode,
  count: rec.count,
  previous_count: rec.previousCount,
  scanned_bytes: rec.scannedBytes,
  ranges_failed: rec.rangesFailed,
  faulted_dropped: rec.faultedDropped,
  truncated: rec.truncated,
  cancelled: rec.cancelled,
  elapsed_ms: rec.elapsedMs,
});

/** Recorded envelope keys from a stored record (S2 §8.1). */
export const recordedEnvelope = (record: BeaEvidence<JsonValue>) => ({
  evidence_id: record.evidence_id,
  predicate_type: record.predicate_type,
  confidence: record.confidence,
  authority: record.authority,
  coverage: record.coverage,
  limitations: record.limitations.slice(0, 64),
  ...(record.subject?.kind === "process-instance"
    ? {
        instance_id: record.subject.instance_id,
        ...(record.subject.module_map_id === null ? {} : { module_map_id: record.subject.module_map_id }),
      }
    : {}),
  ...(record.observed_at === null ? {} : { observed_at: compactOf(record.observed_at) }),
  perturbation: {
    level: record.perturbation.level,
    active_effect_ids: record.perturbation.active_effect_ids,
    tainted: record.perturbation.tainted_by.length > 0,
  },
  ...(record.effects.length > 0 ? { effects_applied: record.effects } : {}),
  ...(record.redactions.length > 0 ? { redactions: record.redactions.length } : {}),
});

/** The not-recorded branch of a maybeRecorded output (scan still running). */
export const unrecordedEnvelope = (rec: ScanRecord) => ({
  evidence_id: null,
  predicate_type: null,
  confidence: null,
  authority: null,
  coverage: scanCoverage(rec),
  limitations: scanLimitations(rec),
});
