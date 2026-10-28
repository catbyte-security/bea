// =================================================================================================
// src/agent/events.ts — WP3-AGENT event pipeline wiring (S4 §6, D-INT-7). The stream registry itself is pure
// (pure/coreEvents.ts, unit-tested): this file binds it to send(), the clock, the limits and the phase, runs the
// flush timer (flush_ms, default 50 ms), creates the system streams at boot (s:exceptions and s:modules — so early
// module loads and exceptions are kept and flushed after hello; s:threads at hello when enabled) and offers the
// helpers features use for native rings and blob messages.
// =================================================================================================
import type {
  AgentError,
  BinaryLayout,
  BlobId,
  BlobMessage,
  InstrumentId,
  JobId,
  RowKind,
  StreamId,
} from "../shared/agentProtocol.js";
import { BINARY_LAYOUTS } from "../shared/binaryLayouts.js";
import { env } from "./env.js";
import type { NativeRing } from "./native/core.js";
import { Stream, StreamRegistry, type FlushOutcome, type StreamSpec } from "./pure/coreEvents.js";
import type { AgentCore } from "./state.js";

export { Stream };
export type { StreamSpec };

export const SYSTEM_STREAM_IDS = {
  exceptions: "s:exceptions",
  modules: "s:modules",
  threads: "s:threads",
  memmap: "s:memmap",
} as const satisfies Record<string, StreamId>;

/**
 * The registry bound to the agent core. Besides the S4 API (open(spec) → Stream, emit, emitBin, close(stream)), the
 * WP12 seam form works on stream ids: `open(kind, instrument)` → id, `push(id, tail)` prepends [g, t], `close(id)`.
 */
export class AgentStreams extends StreamRegistry {
  readonly #core: AgentCore;

  constructor(core: AgentCore) {
    super({
      send: (message, data) => env.send(message, data),
      nowMs: () => Date.now(),
      limits: () => core.limits,
      canSend: () => core.phase !== "loaded",
    });
    this.#core = core;
  }

  override open(spec: StreamSpec): Stream | AgentError;
  override open(kind: RowKind, instrument: InstrumentId | null): StreamId;
  override open(a: StreamSpec | RowKind, instrument?: InstrumentId | null): Stream | AgentError | StreamId {
    if (typeof a !== "string") return super.open(a);
    const s = super.open({ instrument: instrument ?? null, kind: a, enc: "json" });
    if (!(s instanceof Stream)) throw new Error(`cannot open a ${a} stream: ${s.message}`);
    return s.id;
  }

  override close(s: Stream | StreamId): FlushOutcome {
    const stream = typeof s === "string" ? this.get(s) : s;
    return stream === null ? { batches: 0, rows: 0, streams: 0 } : super.close(stream);
  }

  /** One JSON row given without its leading [g, t] (stamped here). */
  push(s: Stream | StreamId, tail: readonly unknown[]): boolean {
    const stream = typeof s === "string" ? this.get(s) : s;
    if (stream === null) return false;
    const c = this.#core;
    return this.emit(stream, [c.native.nextG(), c.native.nowUs(), ...tail]);
  }
}

export const createStreamRegistry = (core: AgentCore): AgentStreams => new AgentStreams(core);

export class EventLoop {
  readonly #core: AgentCore;
  #timer: number | null = null;
  #intervalMs = 0;
  #nextBlob = 1;

  constructor(core: AgentCore) {
    this.#core = core;
  }

  /** Boot step 4: system streams, persistent receivers, the flush timer. */
  init(): void {
    const c = this.#core;
    c.systemStreams.exceptions = this.#openSystem("exceptions", "exception/1");
    c.systemStreams.modules = this.#openSystem("modules", "module/1");
    c.acks.start();
    this.setFlushInterval(c.limits.flush_ms);
  }

  /** (Re)start the flush timer. */
  setFlushInterval(ms: number): void {
    const interval = Math.max(1, Math.min(ms, 1000));
    if (this.#timer !== null && interval === this.#intervalMs) return;
    if (this.#timer !== null) env.cancelEvery(this.#timer);
    this.#intervalMs = interval;
    this.#timer = env.every(interval, () => this.#tick());
  }

  /** dispose: stop the timer (the transport may already be gone). */
  stop(): void {
    if (this.#timer !== null) env.cancelEvery(this.#timer);
    this.#timer = null;
  }

  /** Open the s:threads system stream (hello with streams.threads). */
  enableThreads(): Stream | null {
    const c = this.#core;
    c.systemStreams.threads ??= this.#openSystem("threads", "thread/1");
    return c.systemStreams.threads;
  }

  /** Drop the s:exceptions stream (hello with streams.exceptions false or crash.first_chance_rows false). */
  disableExceptions(): void {
    const c = this.#core;
    const s = c.systemStreams.exceptions;
    if (s === null) return;
    s.state = "closed";
    s.rows = [];
    s.rowEst = [];
    s.rowBytes = 0;
    c.systemStreams.exceptions = null;
  }

  /** The s:memmap system stream (opened on demand by WP8's memmap watcher). */
  memmapStream(): Stream | null {
    const c = this.#core;
    c.systemStreams.memmap ??= this.#openSystem("memmap", "memmap/1");
    return c.systemStreams.memmap;
  }

  /**
   * A binary stream drained from a native ring at every flush (WP7 native hooks): copies committed records through a
   * staging buffer, counts ring_overrun / torn_record drops, and appends one binary chunk.
   */
  attachRing(
    stream: Stream,
    ring: NativeRing,
    firstG: (bytes: Uint8Array, n: number) => [number, number] = gFromHead,
  ): void {
    const c = this.#core;
    const staging = Memory.alloc(ring.capacity * ring.recBytes);
    let last = { overrun: 0, torn: 0 };
    c.keep.pin(staging);
    stream.drain = () => {
      const n = c.native.ringCollect(ring, staging, ring.capacity);
      const counters = c.native.ringCounters(ring);
      c.streams.drop(stream, "ring_overrun", counters.overrun - last.overrun);
      c.streams.drop(stream, "torn_record", counters.torn - last.torn);
      last = counters;
      if (n === 0) return;
      const ab = staging.readByteArray(n * ring.recBytes);
      if (ab === null) return;
      const bytes = new Uint8Array(ab);
      const [g0, g1] = firstG(bytes, n);
      const t = c.native.nowUs();
      c.streams.emitBin(stream, { bytes, n, g0, g1, t0: t, t1: t });
    };
  }

  /** The layout descriptor of a binary row kind. */
  layout(id: keyof typeof BINARY_LAYOUTS): BinaryLayout {
    return BINARY_LAYOUTS[id];
  }

  /** Allocate a blob id ("b<n>") for a job's binary payload (WP13 dumps). */
  nextBlobId(): BlobId {
    return `b${this.#nextBlob++}`;
  }

  /** Send one blob part; counted toward flow control (never shed: blobs are job output). */
  sendBlob(part: Omit<BlobMessage, "bea">, data: ArrayBuffer, job: JobId | null = part.job): void {
    const message: BlobMessage = { bea: "blob", ...part, job };
    env.send(message, data);
    this.#core.streams.accountSent(data.byteLength);
  }

  #openSystem(name: keyof typeof SYSTEM_STREAM_IDS, kind: StreamSpec["kind"]): Stream {
    const s = this.#core.streams.open({
      id: SYSTEM_STREAM_IDS[name],
      instrument: null,
      kind,
      enc: "json",
      system: true,
    });
    if (!(s instanceof Stream)) throw new Error(`cannot open system stream ${name}: ${s.message}`);
    return s;
  }

  #tick(): void {
    const c = this.#core;
    try {
      if (c.scope.isStale(Date.now())) {
        c.scope.releasePending();
        c.streams.announcePending();
      }
      c.streams.flushAll();
    } catch (e) {
      c.fault("flush", e);
    }
  }
}

/** g0/g1 of hook-native/1 records (u64 at offset 0 of the first and last record). */
const gFromHead = (bytes: Uint8Array, n: number): [number, number] => {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const rec = bytes.length / n;
  return [Number(dv.getBigUint64(0, true)), Number(dv.getBigUint64((n - 1) * rec, true))];
};
