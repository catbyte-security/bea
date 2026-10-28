import type { BeaError } from "../../domain/errors/beaError.js";
import { COMPLETE, mergeCoverage, type Coverage } from "../../domain/evidence/coverage.js";
import type { BeaEvidence } from "../../domain/evidence/record.js";
import type { EvId, FxId, MmId, PiId, StId } from "../../domain/ids.js";
import type { JsonObject, JsonValue } from "../../domain/json.js";
import { ok, type Result } from "../../domain/result.js";
import type {
  AppendOutcome,
  EvidenceRuntime,
  RecordedEvidence,
  SensitiveLiterals,
  StreamSourceKind,
} from "../../ports/evidence.js";

/**
 * The recorded envelope of emulation tools (S2 §8 spread envelope, D-INT-17) and the host row streams they write
 * (S5 §11.3: emu-batch, emu-sweep, diff; NDJSON rows pageable with query_events {stream_id}). The delivered result is
 * the RECORDED one (redactions applied), so the caller sees exactly what the ledger holds.
 */
export interface RecordedEnvelope {
  readonly evidence_id: EvId;
  readonly predicate_type: string;
  readonly confidence: BeaEvidence["confidence"];
  readonly authority: BeaEvidence["authority"];
  readonly coverage: BeaEvidence["coverage"];
  readonly limitations: string[];
  readonly instance_id?: PiId;
  readonly module_map_id?: MmId;
  readonly perturbation?: {
    readonly level: BeaEvidence["perturbation"]["level"];
    readonly active_effect_ids: FxId[];
    readonly tainted: boolean;
  };
  readonly effects_applied?: FxId[];
  readonly redactions?: number;
}

const envelopeOf = (record: BeaEvidence<JsonValue>): RecordedEnvelope => {
  const subject = record.subject?.kind === "process-instance" ? record.subject : null;
  return {
    evidence_id: record.evidence_id as EvId,
    predicate_type: record.predicate_type,
    confidence: record.confidence,
    authority: record.authority,
    coverage: record.coverage,
    limitations: record.limitations.slice(0, 64),
    ...(subject === null ? {} : { instance_id: subject.instance_id as PiId }),
    ...(subject !== null && subject.module_map_id !== null ? { module_map_id: subject.module_map_id as MmId } : {}),
    ...(subject === null
      ? {}
      : {
          perturbation: {
            level: record.perturbation.level,
            active_effect_ids: [...record.perturbation.active_effect_ids] as FxId[],
            tainted: record.perturbation.tainted_by.length > 0,
          },
        }),
    ...(record.effects.length > 0 ? { effects_applied: [...record.effects] as FxId[] } : {}),
    ...(record.redactions.length > 0 ? { redactions: record.redactions.length } : {}),
  };
};

export const deliver = <R extends JsonValue>(recorded: RecordedEvidence<R>): JsonObject & RecordedEnvelope =>
  ({ ...(recorded.record.result as JsonObject), ...envelopeOf(recorded.record) }) as JsonObject & RecordedEnvelope;

const ROWS_PER_FRAME = 1000;
const QUEUE_RETRIES = 50;
const COVERAGE_OF: { readonly [K in Exclude<AppendOutcome, "accepted">]: Coverage } = {
  "queue-full": { status: "partial", truncated: true, reasons: ["host_queue_full"] },
  "quota-exceeded": { status: "partial", truncated: true, reasons: ["stream_quota"] },
  redacted: { status: "partial", truncated: true, reasons: ["explicit_sensitive_value"] },
  closed: { status: "partial", truncated: true, reasons: ["host_queue_full"] },
};
const yieldTurn = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

export interface WrittenStream {
  readonly stream_id: StId;
  /** the bea.stream.manifest evidence (null when ending the stream failed) */
  readonly manifest: EvId | null;
  readonly coverage: Coverage;
}

/** Writes NDJSON rows in frames of ≤ 1000 and ends the stream with its manifest evidence. */
export const writeRowStream = async (
  evidence: EvidenceRuntime,
  spec: { readonly kind: StreamSourceKind; readonly channel: string; readonly decoders: JsonObject },
  rows: readonly JsonObject[],
  literals: SensitiveLiterals,
): Promise<Result<WrittenStream, BeaError>> => {
  const opened = await evidence.streams.open({
    source: { kind: spec.kind, instance_id: null, effect_id: null, channel: spec.channel },
    encoding: { kind: "ndjson" },
    decoders: spec.decoders,
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

export const EMU_BATCH_DECODERS: JsonObject = {
  schema: "bea.emu-batch/1",
  row: {
    i: "vector index",
    s: "status code",
    a: "attribution (t target, h harness)",
    c: "stop cause",
    r: "return bits",
    f: "out-buffer fields (bits)",
    n: "instructions",
  },
};
export const EMU_SWEEP_DECODERS: JsonObject = {
  schema: "bea.emu-sweep/1",
  row: {
    rva: "function rva",
    module: "module",
    s: "status codes",
    r: "rax bits",
    x: "xmm0 low bits",
    m: "matched functions",
  },
};
export const DIFF_DECODERS: JsonObject = {
  schema: "bea.diff/1",
  row: {
    i: "vector index",
    in: "input bits",
    l: "per-leg {s status, r return bits, f fields}",
    p: "per-pair {r eq|df|ic, u ulp, why}",
  },
};
