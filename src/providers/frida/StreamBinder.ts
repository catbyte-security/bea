import type { BeaError } from "../../domain/errors/beaError.js";
import { DROP_REASON_CODES } from "../../domain/evidence/coverage.js";
import type { StId } from "../../domain/ids.js";
import type { JsonObject } from "../../domain/json.js";
import type { Logger } from "../../domain/logger.js";
import { err, ok, type Result } from "../../domain/result.js";
import type {
  FrameBatchHeader,
  RecordedEvidence,
  StreamEndReason,
  StreamSpec,
  StreamStore,
  StreamWriter,
} from "../../ports/evidence.js";
import type { StreamBinder, StreamCounters } from "../../ports/sessions.js";
import type { DropReason, RowKind } from "../../shared/agentProtocol.js";
import { estimateRowBytes, type FlowTracker } from "./flowTracker.js";

/**
 * Agent batches → evidence frames (D-INT-7, D-INT-23; S3 §12 as amended). Streams are agent-allocated: the RPC that
 * creates one replies before its first batch (announcement rule), and `bind` runs right after that reply. Batches for
 * an unknown id are parked (≤ 256 KiB, ≤ 2 s) and replayed at bind, else counted `unbound`. Per batch: `bseq` must be
 * previous + 1 (a gap is noted as dropped `seq_gap` and makes coverage unknown for the window); `dropped_before` = Σ of
 * the batch's drop deltas; `first_seq` = records + drops so far + dropped_before + 1. Payloads are the binary data as
 * delivered or the JSON rows as NDJSON. `onBatch` is the hot path: O(1) work per batch, never awaits, never throws.
 */
export interface BinderDeps {
  readonly streams: StreamStore;
  /** agent flush({streams:[id]}) barrier for StreamWriter.checkpoint */
  readonly flushAgent: (agentStream: string, signal: AbortSignal) => Promise<void>;
  readonly flow: FlowTracker;
  readonly moduleEpoch: () => number | null;
  /** row taps for the system streams (module map mirror, exception counters) */
  readonly onRows: (agentStream: string, kind: RowKind, rows: readonly unknown[]) => void;
  readonly onQuota: (agentStream: string) => void;
  readonly notify: () => void;
  readonly logger: Logger;
  readonly now: () => number;
  readonly parking: { readonly maxBytes: number; readonly maxAgeMs: number };
}

interface Binding {
  readonly agentStream: string;
  readonly writer: StreamWriter;
  readonly kind: RowKind | "bytes";
  readonly recordBytes: number | null;
  lastBseq: number | null;
  /** records + drops already assigned to frames (the next frame starts at nextSeq + dropped_before) */
  nextSeq: number;
  received: number;
  batches: number;
  agentDropped: number;
  readonly hostDropped: { bseqGap: number; hostQueueFull: number; quota: number; malformed: number; unbound: number };
  ended: boolean;
  manifest: Promise<Result<RecordedEvidence<JsonObject>, BeaError>> | null;
}

interface ParkedBatch {
  readonly header: Record<string, unknown>;
  readonly data: Buffer | null;
  readonly bytes: number;
  readonly at: number;
}

const isU32 = (value: unknown): value is number =>
  typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 0xffff_ffff;
const isSafeCount = (value: unknown): value is number =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

const DROP_REASONS: ReadonlySet<string> = new Set(Object.keys(DROP_REASON_CODES));

/** Σ of a DropCounters delta; null when malformed. */
const dropSum = (dropped: unknown): number | null => {
  if (typeof dropped !== "object" || dropped === null || Array.isArray(dropped)) return null;
  let sum = 0;
  for (const [reason, count] of Object.entries(dropped)) {
    if (!DROP_REASONS.has(reason) || !isSafeCount(count)) return null;
    sum += count;
  }
  return sum;
};

export class SessionStreamBinder implements StreamBinder {
  readonly #deps: BinderDeps;
  readonly #bindings = new Map<string, Binding>();
  readonly #parked = new Map<string, ParkedBatch[]>();
  #parkedBytes = 0;
  #unboundBatches = 0;
  #malformedBatches = 0;
  /** per agent stream, the reason drops were attributed (for coverage reasons) */
  readonly #dropReasons = new Map<string, Map<DropReason, number>>();

  constructor(deps: BinderDeps) {
    this.#deps = deps;
  }

  get unboundBatches(): number {
    return this.#unboundBatches;
  }

  get malformedBatches(): number {
    return this.#malformedBatches;
  }

  /** Agent stream ids currently bound (live or ended). */
  boundStreams(): readonly string[] {
    return [...this.#bindings.keys()];
  }

  async bind(agentStream: string, spec: StreamSpec): Promise<Result<StreamWriter, BeaError>> {
    const existing = this.#bindings.get(agentStream);
    if (existing !== undefined) return ok(existing.writer);
    const opened = await this.#deps.streams.open({
      ...spec,
      flush: spec.flush ?? ((signal) => this.#deps.flushAgent(agentStream, signal)),
    });
    if (!opened.ok) return opened;
    const writer = opened.value;
    const encoding = spec.encoding;
    const binding: Binding = {
      agentStream,
      writer,
      kind: encoding.kind === "json-rows" || encoding.kind === "fixed-records" ? encoding.row_kind : "bytes",
      recordBytes: encoding.kind === "fixed-records" ? encoding.record_bytes : null,
      lastBseq: null,
      nextSeq: 1,
      received: 0,
      batches: 0,
      agentDropped: 0,
      hostDropped: { bseqGap: 0, hostQueueFull: 0, quota: 0, malformed: 0, unbound: 0 },
      ended: false,
      manifest: null,
    };
    this.#bindings.set(agentStream, binding);
    writer.onQuota(() => {
      try {
        this.#deps.onQuota(agentStream);
      } catch (cause) {
        this.#deps.logger.warn("quota handler failed", { cause: cause instanceof Error ? cause : String(cause) });
      }
    });
    const parked = this.#parked.get(agentStream) ?? [];
    this.#parked.delete(agentStream);
    for (const batch of parked) {
      this.#parkedBytes -= batch.bytes;
      this.#ingest(binding, batch.header, batch.data);
    }
    return ok(writer);
  }

  writer(agentStream: string): StreamWriter | undefined {
    return this.#bindings.get(agentStream)?.writer;
  }

  counters(agentStream: string): StreamCounters | null {
    const b = this.#bindings.get(agentStream);
    if (b === undefined) return null;
    return {
      agentStream,
      streamId: b.writer.stream_id,
      kind: b.kind,
      received: b.received,
      batches: b.batches,
      agentDropped: b.agentDropped,
      hostDropped: { ...b.hostDropped },
      ended: b.ended,
    };
  }

  streamIdOf(agentStream: string): StId | null {
    return this.#bindings.get(agentStream)?.writer.stream_id ?? null;
  }

  /** Coverage reason codes the drops of a stream map to (agent drop reasons + host-side causes). */
  dropReasons(agentStream: string): readonly string[] {
    const reasons = new Set<string>();
    for (const [reason, count] of this.#dropReasons.get(agentStream) ?? new Map<DropReason, number>())
      if (count > 0) reasons.add(DROP_REASON_CODES[reason]);
    const b = this.#bindings.get(agentStream);
    if (b !== undefined) {
      if (b.hostDropped.bseqGap > 0) reasons.add("seq_gap");
      if (b.hostDropped.hostQueueFull > 0) reasons.add("host_queue_full");
      if (b.hostDropped.quota > 0) reasons.add("stream_quota");
    }
    return [...reasons].sort();
  }

  /** Mark a stream ended without a final batch (instrument ended message, process exit). */
  markEnded(agentStream: string): void {
    const b = this.#bindings.get(agentStream);
    if (b !== undefined && !b.ended) {
      b.ended = true;
      this.#deps.notify();
    }
  }

  async end(
    agentStream: string,
    reason: "stopped" | "expired" | "install-failed" | "agent-error",
  ): Promise<Result<RecordedEvidence<JsonObject>, BeaError>> {
    return this.endWith(agentStream, reason);
  }

  /** Ends the writer once; later calls (any reason) return the manifest recorded by the first end. */
  endWith(
    agentStream: string,
    reason: StreamEndReason,
    deadlineMs?: number,
  ): Promise<Result<RecordedEvidence<JsonObject>, BeaError>> {
    const b = this.#bindings.get(agentStream);
    if (b === undefined)
      return Promise.resolve(
        err({
          _tag: "ReferenceNotFound",
          operation: "stream.end",
          reference: { kind: "stream", id: agentStream },
        }),
      );
    b.ended = true;
    this.#deps.notify();
    b.manifest ??= b.writer.end(reason, deadlineMs).then((result) => {
      if (!result.ok) b.manifest = null; // a failed end may be retried
      return result;
    });
    return b.manifest;
  }

  /** Ends every bound stream (close, exit, detach); settles even when some ends fail. */
  async endAll(
    reason: StreamEndReason,
    deadlineMs?: number,
  ): Promise<{ readonly manifests: readonly RecordedEvidence<JsonObject>[]; readonly failures: readonly BeaError[] }> {
    const results = await Promise.all([...this.#bindings.keys()].map((id) => this.endWith(id, reason, deadlineMs)));
    this.#parked.clear();
    this.#parkedBytes = 0;
    return {
      manifests: results.filter((r) => r.ok).map((r) => (r as { readonly value: RecordedEvidence<JsonObject> }).value),
      failures: results.filter((r) => !r.ok).map((r) => (r as { readonly error: BeaError }).error),
    };
  }

  /** Host-produced rows (output recording): appended as one NDJSON frame. */
  appendHostRows(agentStream: string, rows: readonly unknown[]): void {
    const b = this.#bindings.get(agentStream);
    if (b === undefined || b.manifest !== null || rows.length === 0) return;
    const payload = Buffer.from(`${rows.map((row) => JSON.stringify(row)).join("\n")}\n`, "utf8");
    const header: FrameBatchHeader = {
      first_seq: b.nextSeq,
      count: rows.length,
      dropped_before: 0,
      module_map_epoch: this.#deps.moduleEpoch(),
    };
    this.#account(b, header, payload, rows.length);
  }

  /** Hot path (AgentChannel `batch` route). */
  onBatch(header: Record<string, unknown>, data: Buffer | null): void {
    const stream = header["stream"];
    if (typeof stream !== "string" || stream.length === 0 || stream.length > 64) {
      this.#malformedBatches += 1;
      return;
    }
    const binding = this.#bindings.get(stream);
    if (binding === undefined) {
      this.#park(stream, header, data);
      return;
    }
    this.#ingest(binding, header, data);
  }

  #park(stream: string, header: Record<string, unknown>, data: Buffer | null): void {
    const now = this.#deps.now();
    this.#expireParked(now);
    const rows = header["rows"];
    const bytes = (data?.length ?? 0) + (Array.isArray(rows) ? rows.length * 64 : 0) + 256;
    if (this.#parkedBytes + bytes > this.#deps.parking.maxBytes) {
      this.#unboundBatches += 1;
      return;
    }
    const list = this.#parked.get(stream) ?? [];
    list.push({ header, data: data === null ? null : Buffer.from(data), bytes, at: now });
    this.#parked.set(stream, list);
    this.#parkedBytes += bytes;
  }

  #expireParked(now: number): void {
    for (const [stream, list] of this.#parked) {
      const fresh = list.filter((batch) => now - batch.at <= this.#deps.parking.maxAgeMs);
      for (const stale of list) if (!fresh.includes(stale)) this.#parkedBytes -= stale.bytes;
      this.#unboundBatches += list.length - fresh.length;
      if (fresh.length === 0) this.#parked.delete(stream);
      else this.#parked.set(stream, fresh);
    }
  }

  #ingest(b: Binding, h: Record<string, unknown>, data: Buffer | null): void {
    const n = h["n"];
    const bseq = h["bseq"];
    const kind = h["kind"];
    const dropped = dropSum(h["dropped"]);
    const enc = h["enc"];
    const rows = h["rows"];
    const lostEstimate = isU32(n) && n > 0 ? n : 1;
    const writerEnded = b.manifest !== null;
    // continuity first: a batch that arrived (even a malformed one) is not a gap
    if (isSafeCount(bseq) && !writerEnded) {
      if (b.lastBseq !== null && bseq <= b.lastBseq) {
        b.hostDropped.malformed += lostEstimate;
        this.#malformedBatches += 1;
        return;
      }
      const missing = b.lastBseq === null ? 0 : bseq - b.lastBseq - 1;
      if (missing > 0) {
        b.hostDropped.bseqGap += missing;
        b.writer.noteDropped(missing, "seq_gap");
      }
      b.lastBseq = bseq;
    }
    const valid =
      isU32(n) &&
      isSafeCount(bseq) &&
      typeof kind === "string" &&
      dropped !== null &&
      (enc === "json"
        ? Array.isArray(rows) && rows.length === n
        : enc === "bin" && data !== null && b.recordBytes !== null && data.length === n * b.recordBytes);
    if (!valid || writerEnded) {
      b.hostDropped.malformed += lostEstimate;
      if (!writerEnded) b.writer.noteDropped(lostEstimate, "decode_error");
      this.#malformedBatches += 1;
      return;
    }
    this.#recordAgentDrops(b.agentStream, h["dropped"] as Readonly<Record<string, number>>);
    let payload: Buffer;
    let flowBytes: number;
    if (enc === "json") {
      const list = rows as readonly unknown[];
      try {
        this.#deps.onRows(b.agentStream, kind as RowKind, list);
      } catch (cause) {
        this.#deps.logger.debug("row tap failed", { cause: cause instanceof Error ? cause : String(cause) });
      }
      payload = Buffer.from(list.length === 0 ? "" : `${list.map((row) => JSON.stringify(row)).join("\n")}\n`, "utf8");
      flowBytes = list.reduce<number>((sum, row) => sum + estimateRowBytes(row), 0);
    } else {
      payload = data ?? Buffer.alloc(0);
      flowBytes = payload.length;
    }
    const header: FrameBatchHeader = {
      first_seq: b.nextSeq + dropped,
      count: n,
      dropped_before: dropped,
      module_map_epoch: this.#deps.moduleEpoch(),
      ...(h["final"] === true ? { final: true } : {}),
      bseq,
      ...(isSafeCount(h["g0"]) ? { g0: h["g0"] } : {}),
      ...(isSafeCount(h["g1"]) ? { g1: h["g1"] } : {}),
    };
    b.agentDropped += dropped;
    this.#account(b, header, payload, n);
    this.#deps.flow.add(flowBytes);
    if (h["final"] === true) b.ended = true;
    this.#deps.notify();
  }

  #account(b: Binding, header: FrameBatchHeader, payload: Buffer, n: number): void {
    const outcome = b.writer.append(header, payload);
    b.nextSeq = header.first_seq + n;
    b.batches += 1;
    if (outcome === "accepted" || outcome === "redacted") b.received += n;
    else if (outcome === "queue-full") b.hostDropped.hostQueueFull += n;
    else if (outcome === "quota-exceeded") b.hostDropped.quota += n;
  }

  #recordAgentDrops(agentStream: string, dropped: Readonly<Record<string, number>>): void {
    let map = this.#dropReasons.get(agentStream);
    for (const [reason, count] of Object.entries(dropped)) {
      if (count <= 0) continue;
      map ??= new Map();
      map.set(reason as DropReason, (map.get(reason as DropReason) ?? 0) + count);
    }
    if (map !== undefined) this.#dropReasons.set(agentStream, map);
  }
}
