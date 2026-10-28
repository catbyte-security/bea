// =================================================================================================
// src/agent/pure/coreRate.ts — WP3-AGENT pure helpers: rate limiters with an injected clock (S4 §7.3, §7.4, §5.1).
//  - SlidingCount: at most N events per window (blocking crash reports: max_blocking_per_10s).
//  - ExceptionRowLimiter: rows_per_sec first-chance rows; above the cap, a (type, address) key that still has a row in
//    the pending buffer folds into that row's repeat count, other keys drop with rate_limit (LRU of 256 keys).
//  - FaultCoalescer: ≤ N fault messages per second, coalescing the rest into the next message's count.
//  - TokenBucket: backtraces per second and similar budgets.
// =================================================================================================

/** At most `max` events in any trailing `windowMs`. */
export class SlidingCount {
  readonly #times: number[] = [];
  #max: number;
  readonly #windowMs: number;

  constructor(max: number, windowMs: number) {
    this.#max = max;
    this.#windowMs = windowMs;
  }

  setMax(max: number): void {
    this.#max = max;
  }

  allow(nowMs: number): boolean {
    while (this.#times.length > 0 && nowMs - this.#times[0]! >= this.#windowMs) this.#times.shift();
    if (this.#times.length >= this.#max) return false;
    this.#times.push(nowMs);
    return true;
  }
}

/** Decision for one first-chance exception row. */
export type RowDecision<R> =
  | { readonly kind: "new" }
  | { readonly kind: "repeat"; readonly row: R }
  | { readonly kind: "drop" };

/**
 * rows_per_sec limiter over 1-second windows. `isPending(row)` tells whether a remembered row is still in the stream's
 * pending buffer (a sent row can no longer change).
 */
export class ExceptionRowLimiter<R> {
  #perSec: number;
  readonly #lruSize: number;
  /** null until the first row: never -Infinity, which Frida's QJS runtime evaluates to NaN (WP10 probe). */
  #windowStart: number | null = null;
  #inWindow = 0;
  readonly #recent = new Map<string, R>();

  constructor(rowsPerSec: number, lruSize = 256) {
    this.#perSec = rowsPerSec;
    this.#lruSize = lruSize;
  }

  setRate(rowsPerSec: number): void {
    this.#perSec = rowsPerSec;
  }

  decide(key: string, nowMs: number, isPending: (row: R) => boolean): RowDecision<R> {
    if (this.#windowStart === null || nowMs - this.#windowStart >= 1000) {
      this.#windowStart = nowMs;
      this.#inWindow = 0;
    }
    if (this.#inWindow < this.#perSec) {
      this.#inWindow++;
      return { kind: "new" };
    }
    const row = this.#recent.get(key);
    return row !== undefined && isPending(row) ? { kind: "repeat", row } : { kind: "drop" };
  }

  /** Remember the row emitted for `key` (most recent first out of the LRU). */
  remember(key: string, row: R): void {
    this.#recent.delete(key);
    this.#recent.set(key, row);
    if (this.#recent.size > this.#lruSize) {
      const oldest = this.#recent.keys().next();
      if (oldest.done !== true) this.#recent.delete(oldest.value);
    }
  }
}

/** ≤ maxPerSec messages per second; suppressed occurrences are added to the next allowed message's count. */
export class FaultCoalescer {
  readonly #maxPerSec: number;
  /** null until the first message (see ExceptionRowLimiter: no -Infinity in agent code). */
  #windowStart: number | null = null;
  #sent = 0;
  #suppressed = 0;

  constructor(maxPerSec = 10) {
    this.#maxPerSec = maxPerSec;
  }

  /** The count to report now (≥ 1), or null when this occurrence is coalesced into a later message. */
  note(nowMs: number): number | null {
    if (this.#windowStart === null || nowMs - this.#windowStart >= 1000) {
      this.#windowStart = nowMs;
      this.#sent = 0;
    }
    if (this.#sent >= this.#maxPerSec) {
      this.#suppressed++;
      return null;
    }
    this.#sent++;
    const count = this.#suppressed + 1;
    this.#suppressed = 0;
    return count;
  }

  get suppressed(): number {
    return this.#suppressed;
  }
}

/** Token bucket: `ratePerSec` tokens per second, capacity `burst`. */
export class TokenBucket {
  #tokens: number;
  #last: number | null = null;
  readonly #rate: number;
  readonly #burst: number;

  constructor(ratePerSec: number, burst = ratePerSec) {
    this.#rate = ratePerSec;
    this.#burst = Math.max(1, burst);
    this.#tokens = this.#burst;
  }

  take(nowMs: number): boolean {
    if (this.#last !== null)
      this.#tokens = Math.min(this.#burst, this.#tokens + ((nowMs - this.#last) * this.#rate) / 1000);
    this.#last = nowMs;
    if (this.#tokens < 1) return false;
    this.#tokens -= 1;
    return true;
  }
}

/** Small LRU map (findAccessInsn cache, crash backtrace cache per thread). */
export class LruMap<K, V> {
  readonly #map = new Map<K, V>();
  readonly #max: number;

  constructor(max: number) {
    this.#max = Math.max(1, max);
  }

  get(key: K): V | undefined {
    const v = this.#map.get(key);
    if (v !== undefined) {
      this.#map.delete(key);
      this.#map.set(key, v);
    }
    return v;
  }

  set(key: K, value: V): void {
    this.#map.delete(key);
    this.#map.set(key, value);
    if (this.#map.size > this.#max) {
      const oldest = this.#map.keys().next();
      if (oldest.done !== true) this.#map.delete(oldest.value);
    }
  }

  delete(key: K): void {
    this.#map.delete(key);
  }

  get size(): number {
    return this.#map.size;
  }

  clear(): void {
    this.#map.clear();
  }
}
