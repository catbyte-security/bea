import type { BeaError } from "../../domain/errors/beaError.js";
import { COMPLETE, mergeCoverage, type Coverage } from "../../domain/evidence/coverage.js";
import type { EvId, FxId, StId } from "../../domain/ids.js";
import type { JsonObject } from "../../domain/json.js";
import { ok, type Result } from "../../domain/result.js";
import type { CallOutcomeColumns } from "../../domain/callModel/types.js";
import type { AppendOutcome, EvidenceRuntime, SensitiveLiterals } from "../../ports/evidence.js";
import type { LiveSession } from "../../ports/sessions.js";
import type { Hex } from "../../shared/hex.js";

/**
 * `call-batch` host row streams (CI-I6; S5 §11.3 layout): a batch with more completed vectors than the inline limit
 * writes one NDJSON row per vector, pageable with `query_events {stream_id}`. Row:
 * `{i, s, r, f, e}` = absolute vector index, CallStatus, return bits (null: void/hidden struct/not returned),
 * decoded out-buffer fields (bits or bits[]), fault cause (null unless the vector faulted).
 */
export type CallBatchRow = {
  readonly i: number;
  readonly s: CallOutcomeColumns["status"][number];
  readonly r: Hex | null;
  readonly f: { readonly [field: string]: Hex | readonly Hex[] };
  readonly e: string | null;
};

const ROWS_PER_FRAME = 1000;
const QUEUE_RETRIES = 50;

export const batchRows = (outcome: CallOutcomeColumns): CallBatchRow[] => {
  const causes = new Map(outcome.faults.map((f) => [f.index, f.cause]));
  return Array.from({ length: outcome.count }, (_, k) => {
    const f: Record<string, Hex | readonly Hex[]> = {};
    for (const [name, cells] of Object.entries(outcome.fields)) {
      const cell = cells[k];
      if (cell !== undefined) f[name] = cell;
    }
    const status = outcome.status[k] ?? "fault";
    return {
      i: outcome.offset + k,
      s: status,
      r: status === "returned" ? (outcome.ret?.[k] ?? null) : null,
      f,
      e: status === "returned" ? null : (causes.get(outcome.offset + k) ?? status),
    };
  });
};

/** The stream descriptor's decoders (query_events reads host row streams through it). */
const CALL_BATCH_DECODERS: JsonObject = {
  schema: "bea.call-batch/1",
  row: { i: "vector index", s: "status", r: "return bits", f: "out-buffer fields (bits)", e: "fault cause" },
};

const COVERAGE_OF: { readonly [K in Exclude<AppendOutcome, "accepted">]: Coverage } = {
  "queue-full": { status: "partial", truncated: true, reasons: ["host_queue_full"] },
  "quota-exceeded": { status: "partial", truncated: true, reasons: ["stream_quota"] },
  redacted: { status: "partial", truncated: true, reasons: ["explicit_sensitive_value"] },
  closed: { status: "partial", truncated: true, reasons: ["host_queue_full"] },
};

const yieldTurn = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** Writes the rows (frames of ≤ 1000) and ends the stream; returns its id and manifest evidence. */
export const writeCallBatchStream = async (
  evidence: EvidenceRuntime,
  session: LiveSession,
  effectId: FxId,
  rows: readonly CallBatchRow[],
  literals: SensitiveLiterals,
): Promise<
  Result<{ readonly stream_id: StId; readonly manifest: EvId | null; readonly coverage: Coverage }, BeaError>
> => {
  const opened = await evidence.streams.open({
    source: { kind: "call-batch", instance_id: session.instanceId, effect_id: effectId, channel: "call_function" },
    encoding: { kind: "ndjson" },
    decoders: CALL_BATCH_DECODERS,
    literals,
  });
  if (!opened.ok) return opened;
  const writer = opened.value;
  const problems: Coverage[] = [];
  const encoder = new TextEncoder();
  for (let start = 0; start < rows.length; start += ROWS_PER_FRAME) {
    const frame = rows.slice(start, start + ROWS_PER_FRAME);
    const payload = encoder.encode(frame.map((row) => `${JSON.stringify(row)}\n`).join(""));
    const header = { first_seq: start + 1, count: frame.length, dropped_before: 0, module_map_epoch: null };
    let outcome = writer.append(header, payload);
    for (let retry = 0; outcome === "queue-full" && retry < QUEUE_RETRIES; retry++) {
      await yieldTurn(10);
      outcome = writer.append(header, payload);
    }
    if (outcome !== "accepted") {
      problems.push(COVERAGE_OF[outcome]);
      if (outcome !== "redacted") {
        writer.noteDropped(rows.length - start - frame.length, outcome);
        break;
      }
    }
    await yieldTurn(0);
  }
  const ended = await writer.end("stopped");
  return ok({
    stream_id: writer.stream_id,
    manifest: ended.ok ? (ended.value.record.evidence_id as EvId) : null,
    coverage: problems.length === 0 ? COMPLETE : mergeCoverage(...problems),
  });
};
