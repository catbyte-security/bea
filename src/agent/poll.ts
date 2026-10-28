// =================================================================================================
// src/agent/poll.ts — the poll watcher (DESIGN D-INT-20 / §5.3, S6 §4.22 R5; WP9-WATCH). A timer on the agent JS
// thread reads `size` bytes every interval_ms and reports the 8-byte cells that changed since the previous sample
// (poll/1 rows; the host splits cells by view). Never auto-picked: it sees values, not instructions.
// Reads go through the page-guard engine's suspension windows when BEA guards the range (CT-I5).
// =================================================================================================
import type { InstrumentId } from "../shared/agentProtocol.js";
import { bigOf } from "./hwbp.js";
import { changedCells, type ChangedCell } from "./pure/watchPlan.js";

interface PollSink {
  /** one sample's changed cells; "stop" when the instrument reached max_hits */
  changes(cells: readonly ChangedCell[]): "continue" | "stop";
  /** the range became unreadable (unmapped or protection changed) */
  unreadable(): void;
}
export interface PollSpec {
  readonly owner: InstrumentId;
  readonly address: NativePointer;
  readonly size: number;
  readonly intervalMs: number;
  readonly sink: PollSink;
}
export interface PollReader {
  /** read through BEA guard suspension when needed; null when unreadable */
  read(address: NativePointer, lo: bigint, size: number): ArrayBuffer | null;
}

interface Poller {
  readonly spec: PollSpec;
  readonly lo: bigint;
  timer: ReturnType<typeof setInterval> | null;
  prev: Uint8Array | null;
  samples: number;
  unreadable: number;
}

export class PollEngine {
  readonly #pollers = new Map<InstrumentId, Poller>();
  constructor(private readonly reader: PollReader) {}

  /** Starts sampling; the first read is the baseline (no rows). Null when the range is unreadable now. */
  start(spec: PollSpec): ArrayBuffer | null {
    const lo = bigOf(spec.address);
    const first = this.reader.read(spec.address, lo, spec.size);
    if (first === null) return null;
    const poller: Poller = { spec, lo, timer: null, prev: new Uint8Array(first), samples: 1, unreadable: 0 };
    poller.timer = setInterval(() => this.#sample(poller), Math.max(1, spec.intervalMs));
    this.#pollers.set(spec.owner, poller);
    return first;
  }

  #sample(p: Poller): void {
    if (p.timer === null) return;
    const now = this.reader.read(p.spec.address, p.lo, p.spec.size);
    p.samples += 1;
    if (now === null) {
      p.unreadable += 1;
      p.spec.sink.unreadable();
      return;
    }
    const next = new Uint8Array(now);
    const cells = p.prev === null ? [] : changedCells(p.prev, next);
    p.prev = next;
    if (cells.length > 0 && p.spec.sink.changes(cells) === "stop") this.#clear(p);
  }

  #clear(p: Poller): void {
    if (p.timer !== null) clearInterval(p.timer);
    p.timer = null;
  }

  stop(owner: InstrumentId): { samples: number; unreadable: number } | null {
    const p = this.#pollers.get(owner);
    if (p === undefined) return null;
    this.#clear(p);
    this.#pollers.delete(owner);
    return { samples: p.samples, unreadable: p.unreadable };
  }

  stopAll(): void {
    for (const p of this.#pollers.values()) this.#clear(p);
    this.#pollers.clear();
  }
}
