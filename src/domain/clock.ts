/** Injectable time. Evidence identity uses `seq`, never wall time (rea-evidence §10.3). */
export interface Clock {
  /** Monotonic nanoseconds (process.hrtime.bigint()). */
  readonly monoNs: () => bigint;
  /** Milliseconds for durations and deadlines (performance.now() based). */
  readonly monoMs: () => number;
  /** ISO-8601 UTC wall time, display only. */
  readonly wallIso: () => string;
}

export const systemClock: Clock = {
  monoNs: () => process.hrtime.bigint(),
  monoMs: () => performance.now(),
  wallIso: () => new Date().toISOString(),
};

/** Manually advanced clock for tests. */
export const manualClock = (
  startWall = "2026-01-01T00:00:00.000Z",
): Clock & { readonly advanceMs: (ms: number) => void } => {
  let ms = 0;
  const base = Date.parse(startWall);
  return {
    monoNs: () => BigInt(Math.round(ms * 1e6)),
    monoMs: () => ms,
    wallIso: () => new Date(base + ms).toISOString(),
    advanceMs: (delta) => {
      ms += delta;
    },
  };
};

/**
 * Run-global, strictly increasing sequence (one per server run). Assigned by the
 * host to every BEA operation that records Evidence or an Effect.
 */
export class SequenceAllocator {
  #next: number;

  constructor(start = 1) {
    if (!Number.isSafeInteger(start) || start < 1) throw new RangeError("start must be a positive safe integer");
    this.#next = start;
  }

  next(): number {
    if (this.#next >= Number.MAX_SAFE_INTEGER) throw new RangeError("sequence exhausted");
    const value = this.#next;
    this.#next += 1;
    return value;
  }

  /** The value the next call will return. */
  peek(): number {
    return this.#next;
  }
}
