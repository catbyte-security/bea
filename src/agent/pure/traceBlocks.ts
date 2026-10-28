// =================================================================================================
// src/agent/pure/traceBlocks.ts — Stalker block bookkeeping for trace_execution (S4 §12, CT-M1; WP9-WATCH):
// module filters, the coverage dedupe set with its cap, on_call entry-block synthesis and the fixed-record encoders
// of block-span/1, block-count/1 and call-site-count/1 (src/shared/binaryLayouts.ts). Pure: no GumJS.
// =================================================================================================

export interface CodeRange {
  readonly base: bigint;
  readonly end: bigint;
}

/** Linear scan; ≤ 16 traced modules. */
export const inRanges = (address: bigint, ranges: readonly CodeRange[]): boolean => {
  for (const r of ranges) if (address >= r.base && address < r.end) return true;
  return false;
};

/** Unique blocks keyed by start, capped (stalker_max_blocks); overflow is counted, never silent. */
export class BlockSet {
  readonly #blocks = new Map<bigint, bigint>();
  #overflow = 0;
  constructor(readonly cap: number) {}

  /** "added" | "duplicate" | "cap" (the block was not kept). A later, longer span for a known start widens it. */
  add(start: bigint, end: bigint): "added" | "duplicate" | "cap" {
    const known = this.#blocks.get(start);
    if (known !== undefined) {
      if (end > known) this.#blocks.set(start, end);
      return "duplicate";
    }
    if (this.#blocks.size >= this.cap) {
      this.#overflow += 1;
      return "cap";
    }
    this.#blocks.set(start, end);
    return "added";
  }
  get size(): number {
    return this.#blocks.size;
  }
  get overflow(): number {
    return this.#overflow;
  }
  /** Sorted by start. */
  entries(): [bigint, bigint][] {
    return [...this.#blocks.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  }
}

/**
 * CT-M1: Interceptor runs the hooked function's first instructions in its relocated prologue, so the first block
 * Stalker sees for an on_call invocation starts after them (E10: +0x1765 for a function at +0x1760). The missing
 * entry block is [entry, firstBlock) when the gap is a plausible relocated prologue (1..maxGap bytes).
 */
export const synthesizeEntryBlock = (entry: bigint, firstBlock: bigint | null, maxGap = 64): CodeRange | null => {
  if (firstBlock === null || firstBlock <= entry) return null;
  const gap = firstBlock - entry;
  return gap <= BigInt(maxGap) ? { base: entry, end: firstBlock } : null;
};

const putU64 = (view: DataView, offset: number, value: bigint): void => {
  view.setBigUint64(offset, BigInt.asUintN(64, value), true);
};

/** block-span/1: {start u64, end u64} per record. */
export const encodeBlockSpans = (blocks: readonly (readonly [bigint, bigint])[]): ArrayBuffer => {
  const buf = new ArrayBuffer(blocks.length * 16);
  const view = new DataView(buf);
  blocks.forEach(([start, end], i) => {
    putU64(view, i * 16, start);
    putU64(view, i * 16 + 8, end);
  });
  return buf;
};

/** block-count/1 and call-site-count/1 share the shape {a u64, b u64, count u64}. */
export const encodeTriples = (rows: readonly (readonly [bigint, bigint, bigint])[]): ArrayBuffer => {
  const buf = new ArrayBuffer(rows.length * 24);
  const view = new DataView(buf);
  rows.forEach(([a, b, count], i) => {
    putU64(view, i * 24, a);
    putU64(view, i * 24 + 8, b);
    putU64(view, i * 24 + 16, count);
  });
  return buf;
};

/** Sum counts of recompiled slab entries by start (block-count) or (site, target) (call-site-count). */
export const sumTriples = (
  rows: readonly (readonly [bigint, bigint, bigint])[],
  key: "a" | "ab",
): [bigint, bigint, bigint][] => {
  const merged = new Map<string, [bigint, bigint, bigint]>();
  for (const [a, b, count] of rows) {
    const k = key === "a" ? a.toString(16) : `${a.toString(16)}:${b.toString(16)}`;
    const known = merged.get(k);
    if (known === undefined) merged.set(k, [a, b, count]);
    else {
      known[2] += count;
      if (key === "a" && b > known[1]) known[1] = b;
    }
  }
  return [...merged.values()].sort((x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : x[1] < y[1] ? -1 : 1));
};
