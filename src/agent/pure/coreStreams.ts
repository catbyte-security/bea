// =================================================================================================
// src/agent/pure/coreStreams.ts — WP3-AGENT pure helpers for the event pipeline (S4 §6.2–§6.5): row byte estimates,
// admission decisions, flush thresholds, per-reason drop counters and their per-batch deltas, and the flow-control
// hysteresis that bounds target memory when the host is slow (21 GB without bounds [ext-frida §1.9]).
// =================================================================================================
import type { AgentLimits, DropCounters, DropReason } from "../../shared/agentProtocol.js";

export const DROP_REASONS: readonly DropReason[] = [
  "buffer_full",
  "flow_control",
  "rate_limit",
  "instrument_cap",
  "agent_memory",
  "ring_overrun",
  "torn_record",
  "decode_error",
  "stopped",
  "per_api_cap",
];

/** JSON batch byte threshold that triggers an immediate flush from the producer (S4 §6.2). */
export const IMMEDIATE_FLUSH_BYTES = 256 * 1024;

/**
 * Cheap byte estimate of one JSON row (feeds flow control only): 12 per number, 2 + length per string ("0x…" text
 * counts as 20), recursive for arrays/objects, 4 for null/boolean.
 */
export const estimateBytes = (v: unknown, depth = 0): number => {
  if (typeof v === "number") return 12;
  if (typeof v === "string") return v.startsWith("0x") ? 20 : 2 + v.length;
  if (v === null || typeof v === "boolean" || v === undefined) return 4;
  if (depth > 6) return 16;
  if (Array.isArray(v)) {
    let n = 2;
    for (const item of v) n += estimateBytes(item, depth + 1) + 1;
    return n;
  }
  if (typeof v === "object") {
    let n = 2;
    for (const [k, item] of Object.entries(v as Record<string, unknown>))
      n += k.length + 3 + estimateBytes(item, depth + 1);
    return n;
  }
  return 8;
};

export interface StreamFill {
  readonly open: boolean;
  readonly system: boolean;
  readonly pendingRows: number;
  readonly pendingBytes: number;
}

/** Admission of one JS row (S4 §6.2): null = admit, else the drop reason. */
export const admitRow = (
  fill: StreamFill,
  shedding: boolean,
  limits: Pick<AgentLimits, "stream_max_pending_rows" | "stream_max_pending_bytes">,
): DropReason | null => {
  if (!fill.open) return "stopped";
  if (shedding && !fill.system) return "flow_control";
  if (fill.pendingRows >= limits.stream_max_pending_rows || fill.pendingBytes >= limits.stream_max_pending_bytes)
    return "buffer_full";
  return null;
};

/** Flush from the producer right away (≥ batch_max_rows or ≈ 256 KiB pending). */
export const needsImmediateFlush = (
  pendingRows: number,
  pendingBytes: number,
  limits: Pick<AgentLimits, "batch_max_rows">,
): boolean => pendingRows >= limits.batch_max_rows || pendingBytes >= IMMEDIATE_FLUSH_BYTES;

/** Mutable per-reason counters with a delta since the last batch. */
export class DropLedger {
  readonly total: Record<DropReason, number>;
  readonly #atLastBatch: Record<DropReason, number>;

  constructor() {
    this.total = Object.fromEntries(DROP_REASONS.map((r) => [r, 0])) as Record<DropReason, number>;
    this.#atLastBatch = { ...this.total };
  }

  add(reason: DropReason, n = 1): void {
    this.total[reason] += n;
  }

  /** Non-zero cumulative counters (InstrumentCounters.dropped / StreamInfo.dropped). */
  snapshot(): DropCounters {
    const out: DropCounters = {};
    for (const r of DROP_REASONS) if (this.total[r] > 0) out[r] = this.total[r];
    return out;
  }

  /** Delta since the previous call (a batch's `dropped`), then remembers the current totals. */
  takeDelta(): DropCounters {
    const out: DropCounters = {};
    for (const r of DROP_REASONS) {
      const d = this.total[r] - this.#atLastBatch[r];
      if (d > 0) out[r] = d;
      this.#atLastBatch[r] = this.total[r];
    }
    return out;
  }

  hasPendingDelta(): boolean {
    return DROP_REASONS.some((r) => this.total[r] !== this.#atLastBatch[r]);
  }

  sum(): number {
    let n = 0;
    for (const r of DROP_REASONS) n += this.total[r];
    return n;
  }
}

export type FlowTransition = "shedding-on" | "shedding-off" | null;

/**
 * Flow control (S4 §6.5): inflight = sent − received; above high water → shed non-system rows; below low water →
 * resume. `received` is cumulative from the host and never decreases.
 */
export class FlowControl {
  sentBytes = 0;
  receivedBytes = 0;
  shedding = false;
  shedRows = 0;
  #high: number;
  #low: number;

  constructor(highWater: number, lowWater: number) {
    this.#high = highWater;
    this.#low = Math.min(lowWater, highWater);
  }

  configure(highWater: number, lowWater: number): FlowTransition {
    this.#high = highWater;
    this.#low = Math.min(lowWater, highWater);
    return this.#evaluate();
  }

  get inflight(): number {
    return Math.max(0, this.sentBytes - this.receivedBytes);
  }

  onSent(bytes: number): FlowTransition {
    this.sentBytes += Math.max(0, bytes);
    return this.#evaluate();
  }

  onReceived(cumulative: number): FlowTransition {
    if (Number.isFinite(cumulative) && cumulative > this.receivedBytes) this.receivedBytes = cumulative;
    return this.#evaluate();
  }

  #evaluate(): FlowTransition {
    const inflight = this.inflight;
    if (!this.shedding && inflight > this.#high) {
      this.shedding = true;
      return "shedding-on";
    }
    if (this.shedding && inflight < this.#low) {
      this.shedding = false;
      return "shedding-off";
    }
    return null;
  }
}
