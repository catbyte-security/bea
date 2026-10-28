// =================================================================================================
// src/agent/pure/coreEvents.ts — WP3-AGENT stream registry (S4 §6, D-INT-7, D-INT-23). Events never use a per-call
// send: every instrument has a stream with a JSON row buffer or a binary record buffer (native rings are drained into
// it at flush time). Streams flush every flush_ms, at batch_max_rows / 256 KiB from the producer, and finally at
// stop/exit/crash/shutdown. Per-reason drop counters travel as per-batch deltas; flow control sheds non-system rows
// when the host falls behind. The ANNOUNCEMENT RULE: a stream created inside an RPC sends nothing before that RPC's
// reply was produced, and nothing at all is sent before hello (phase "ready").
// Pure: events.ts injects send(), the clock, the limits and the phase.
// =================================================================================================
import type {
  AgentError,
  AgentLimits,
  BatchMessage,
  DropReason,
  InstrumentId,
  LayoutId,
  NoticeMessage,
  RowKind,
  StreamId,
  StreamInfo,
} from "../../shared/agentProtocol.js";
import { admitRow, DropLedger, estimateBytes, FlowControl, needsImmediateFlush } from "./coreStreams.js";

export interface StreamSpec {
  /** fixed id for system streams ("s:exceptions" …); allocated "s<n>" otherwise */
  readonly id?: StreamId;
  readonly instrument: InstrumentId | null;
  readonly kind: RowKind;
  readonly enc: "json" | "bin";
  /** binary streams: layout id and record size */
  readonly layout?: LayoutId;
  readonly recBytes?: number;
  readonly system?: boolean;
}

/** A binary chunk appended by a producer (whole records). */
export interface BinChunk {
  readonly bytes: Uint8Array;
  readonly n: number;
  readonly g0: number;
  readonly g1: number;
  readonly t0: number;
  readonly t1: number;
}

export class Stream {
  readonly id: StreamId;
  readonly instrument: InstrumentId | null;
  readonly kind: RowKind;
  readonly enc: "json" | "bin";
  readonly layout: LayoutId | null;
  readonly recBytes: number;
  readonly system: boolean;
  state: "open" | "closing" | "closed" = "open";
  announced: boolean;
  rows: unknown[] = [];
  /** admission estimates of the pending rows (parallel to `rows`) and their sum */
  rowEst: number[] = [];
  rowBytes = 0;
  bin: BinChunk[] = [];
  binBytes = 0;
  bseq = 0;
  recorded = 0;
  sentRows = 0;
  readonly drops = new DropLedger();
  lastBatchMs = 0;
  /** native producers: pull committed records into the stream (called at every flush) */
  drain: (() => void) | null = null;
  /** sent the final batch */
  finalSent = false;

  constructor(id: StreamId, spec: StreamSpec, announced: boolean) {
    this.id = id;
    this.instrument = spec.instrument;
    this.kind = spec.kind;
    this.enc = spec.enc;
    this.layout = spec.layout ?? null;
    this.recBytes = spec.recBytes ?? 0;
    this.system = spec.system === true;
    this.announced = announced;
  }

  get pendingRows(): number {
    return this.enc === "json" ? this.rows.length : this.bin.reduce((n, c) => n + c.n, 0);
  }

  get batches(): number {
    return this.bseq;
  }
}

export interface EventDeps {
  readonly send: (message: BatchMessage | NoticeMessage, data?: ArrayBuffer) => void;
  readonly nowMs: () => number;
  readonly limits: () => AgentLimits;
  /** batches may be sent (phase ready, i.e. after hello) */
  readonly canSend: () => boolean;
}

export interface FlushOutcome {
  batches: number;
  rows: number;
  streams: number;
}

const CLOSED_KEEP = 64;
const DROP_ONLY_BATCH_MS = 1000;

export class StreamRegistry {
  readonly #deps: EventDeps;
  readonly #streams = new Map<StreamId, Stream>();
  #next = 1;
  /** RPC scope depth and the streams created inside it (announcement rule) */
  #scopeDepth = 0;
  readonly #scopeStreams: Stream[] = [];
  readonly flow: FlowControl;

  constructor(deps: EventDeps) {
    this.#deps = deps;
    const l = deps.limits();
    this.flow = new FlowControl(l.flow_high_water_bytes, l.flow_low_water_bytes);
  }

  /** Open a stream; ResourceLimit{streams} at max_streams open streams. */
  open(spec: StreamSpec): Stream | AgentError {
    const live = [...this.#streams.values()].filter((s) => s.state !== "closed").length;
    const max = this.#deps.limits().max_streams;
    if (live >= max)
      return {
        _tag: "ResourceLimit",
        message: "too many agent streams",
        resource: "streams",
        limit: max,
        observed: live,
      };
    const id = spec.id ?? `s${this.#next++}`;
    const stream = new Stream(id, spec, this.#scopeDepth === 0);
    if (this.#scopeDepth > 0) this.#scopeStreams.push(stream);
    this.#streams.set(id, stream);
    this.#pruneClosed();
    return stream;
  }

  get(id: StreamId): Stream | null {
    return this.#streams.get(id) ?? null;
  }

  list(): Stream[] {
    return [...this.#streams.values()];
  }

  /** RPC wrapper: streams opened between begin and end are announced when the RPC's reply has been produced. */
  beginScope(): void {
    this.#scopeDepth++;
  }

  endScope(): void {
    this.#scopeDepth = Math.max(0, this.#scopeDepth - 1);
    if (this.#scopeDepth > 0) return;
    this.announcePending();
  }

  /** Announce every stream still waiting for its RPC scope (scope end, or a stale scope released by the agent). */
  announcePending(): void {
    for (const s of this.#scopeStreams.splice(0)) s.announced = true;
  }

  /** Admit one JSON row (S4 §6.2); returns false when it was dropped (and counted). */
  emit(s: Stream, row: unknown[], estBytes?: number): boolean {
    const limits = this.#deps.limits();
    const est = estBytes ?? estimateBytes(row);
    const drop = admitRow(
      { open: s.state === "open", system: s.system, pendingRows: s.rows.length, pendingBytes: s.rowBytes },
      this.flow.shedding,
      limits,
    );
    if (drop !== null) {
      s.drops.add(drop);
      if (drop === "flow_control") this.flow.shedRows++;
      return false;
    }
    s.rows.push(row);
    s.rowEst.push(est);
    s.rowBytes += est;
    s.recorded++;
    if (needsImmediateFlush(s.rows.length, s.rowBytes, limits)) this.flushStream(s, false);
    return true;
  }

  /** Append whole binary records (JS-assembled or drained from a native ring). */
  emitBin(s: Stream, chunk: BinChunk): boolean {
    if (s.state !== "open") {
      s.drops.add("stopped", chunk.n);
      return false;
    }
    if (this.flow.shedding && !s.system) {
      s.drops.add("flow_control", chunk.n);
      this.flow.shedRows += chunk.n;
      return false;
    }
    const limits = this.#deps.limits();
    if (s.binBytes + chunk.bytes.length > limits.stream_max_pending_bytes) {
      s.drops.add("buffer_full", chunk.n);
      return false;
    }
    s.bin.push(chunk);
    s.binBytes += chunk.bytes.length;
    s.recorded += chunk.n;
    if (s.binBytes >= limits.batch_max_bin_bytes) this.flushStream(s, false);
    return true;
  }

  /** Count drops that happened outside the registry (rate limits, caps, ring overruns). */
  drop(s: Stream, reason: DropReason, n = 1): void {
    if (n > 0) s.drops.add(reason, n);
  }

  /** Send the pending rows of one stream (no-op before hello or before the stream was announced). */
  flushStream(s: Stream, final: boolean): FlushOutcome {
    const out: FlushOutcome = { batches: 0, rows: 0, streams: 0 };
    if (s.finalSent || !s.announced || !this.#deps.canSend()) return out;
    try {
      s.drain?.();
    } catch {
      s.drops.add("decode_error");
    }
    if (s.enc === "json") this.#flushJson(s, final, out);
    else this.#flushBin(s, final, out);
    if (final) s.finalSent = true;
    if (out.batches > 0) out.streams = 1;
    return out;
  }

  /** Flush every stream (or the named ones); `final` ends them (exit hook, shutdown). */
  flushAll(opts: { readonly final?: boolean; readonly streams?: readonly StreamId[] } = {}): FlushOutcome {
    const total: FlushOutcome = { batches: 0, rows: 0, streams: 0 };
    const targets =
      opts.streams === undefined
        ? [...this.#streams.values()]
        : opts.streams.map((id) => this.#streams.get(id)).filter((s): s is Stream => s !== undefined);
    for (const s of targets) {
      if (s.state === "closed" && s.finalSent) continue;
      const final = opts.final === true;
      const r = this.flushStream(s, final);
      if (final && s.finalSent) s.state = "closed";
      total.batches += r.batches;
      total.rows += r.rows;
      total.streams += r.streams;
    }
    return total;
  }

  /** Stop accepting rows, send the final batch, mark closed (instrument stop). */
  close(s: Stream): FlushOutcome {
    if (s.state === "closed") return { batches: 0, rows: 0, streams: 0 };
    s.state = "closing";
    const r = this.flushStream(s, true);
    s.state = "closed";
    return r;
  }

  info(s: Stream): StreamInfo {
    return {
      id: s.id,
      instrument: s.instrument,
      kind: s.kind,
      enc: s.enc,
      state: s.state,
      recorded: s.recorded,
      sent_rows: s.sentRows,
      batches: s.bseq,
      pending_rows: s.pendingRows,
      dropped: s.drops.snapshot(),
    };
  }

  /** Host flow post {type:"flow", received_bytes} (cumulative). */
  onFlowPost(receivedBytes: number): void {
    this.#notice(this.flow.onReceived(receivedBytes));
  }

  /** Re-apply limits after hello. */
  configureFlow(high: number, low: number): void {
    this.#notice(this.flow.configure(high, low));
  }

  /** Non-batch payload bytes (blobs) count toward inflight but are never shed. */
  accountSent(bytes: number): void {
    this.#notice(this.flow.onSent(bytes));
  }

  #flushJson(s: Stream, final: boolean, out: FlushOutcome): void {
    const max = Math.max(1, this.#deps.limits().batch_max_rows);
    do {
      const rows = s.rows.splice(0, max);
      for (const est of s.rowEst.splice(0, rows.length)) s.rowBytes -= est;
      if (s.rows.length === 0) s.rowBytes = 0;
      // flow accounting in the shared unit the host mirrors (estimateBytes of each sent row; WP4 flowTracker.ts)
      let bytes = 0;
      for (const row of rows) bytes += estimateBytes(row);
      const last = s.rows.length === 0;
      const isFinal = final && last;
      if (rows.length === 0 && !isFinal && !this.#dropOnlyDue(s)) return;
      const first = rows[0] as unknown[] | undefined;
      const lastRow = rows[rows.length - 1] as unknown[] | undefined;
      const message: BatchMessage = {
        bea: "batch",
        stream: s.id,
        instrument: s.instrument,
        bseq: ++s.bseq,
        kind: s.kind,
        n: rows.length,
        g0: numAt(first, 0),
        g1: numAt(lastRow, 0),
        t0: numAt(first, 1),
        t1: numAt(lastRow, 1),
        dropped: s.drops.takeDelta(),
        final: isFinal,
        enc: "json",
        rows,
      };
      this.#deps.send(message);
      s.sentRows += rows.length;
      s.lastBatchMs = this.#deps.nowMs();
      out.batches++;
      out.rows += rows.length;
      this.#notice(this.flow.onSent(bytes));
    } while (s.rows.length > 0);
  }

  #flushBin(s: Stream, final: boolean, out: FlushOutcome): void {
    const maxBytes = Math.max(s.recBytes, this.#deps.limits().batch_max_bin_bytes);
    do {
      const take: BinChunk[] = [];
      let bytes = 0;
      while (s.bin.length > 0 && (take.length === 0 || bytes + s.bin[0]!.bytes.length <= maxBytes)) {
        const c = s.bin.shift()!;
        take.push(c);
        bytes += c.bytes.length;
      }
      s.binBytes -= bytes;
      const isFinal = final && s.bin.length === 0;
      if (take.length === 0 && !isFinal && !this.#dropOnlyDue(s)) return;
      const data = new Uint8Array(bytes);
      let off = 0;
      let n = 0;
      for (const c of take) {
        data.set(c.bytes, off);
        off += c.bytes.length;
        n += c.n;
      }
      const message: BatchMessage = {
        bea: "batch",
        stream: s.id,
        instrument: s.instrument,
        bseq: ++s.bseq,
        kind: s.kind,
        n,
        g0: take[0]?.g0 ?? 0,
        g1: take[take.length - 1]?.g1 ?? 0,
        t0: take[0]?.t0 ?? 0,
        t1: take[take.length - 1]?.t1 ?? 0,
        dropped: s.drops.takeDelta(),
        final: isFinal,
        enc: "bin",
        layout: s.layout ?? "block-span/1",
        rec_bytes: s.recBytes,
      };
      this.#deps.send(message, data.buffer);
      s.sentRows += n;
      s.lastBatchMs = this.#deps.nowMs();
      out.batches++;
      out.rows += n;
      this.#notice(this.flow.onSent(bytes));
    } while (s.bin.length > 0);
  }

  /** A batch carrying only drop deltas, at most once per second per stream. */
  #dropOnlyDue(s: Stream): boolean {
    return s.drops.hasPendingDelta() && this.#deps.nowMs() - s.lastBatchMs >= DROP_ONLY_BATCH_MS;
  }

  #notice(t: "shedding-on" | "shedding-off" | null): void {
    if (t === null) return;
    this.#deps.send({
      bea: "notice",
      code: t === "shedding-on" ? "flow-shedding-on" : "flow-shedding-off",
      detail: {
        inflight: this.flow.inflight,
        sent_bytes: this.flow.sentBytes,
        received_bytes: this.flow.receivedBytes,
      },
    });
  }

  #pruneClosed(): void {
    const closed = [...this.#streams.values()].filter((s) => s.state === "closed" && !s.system);
    for (const s of closed.slice(0, Math.max(0, closed.length - CLOSED_KEEP))) this.#streams.delete(s.id);
  }
}

const numAt = (row: unknown[] | undefined, i: number): number => {
  const v = row?.[i];
  return typeof v === "number" ? v : 0;
};
