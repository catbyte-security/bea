// =================================================================================================
// src/agent/pure/coreRanges.ts — WP3-AGENT pure helpers: page and range arithmetic, BEA guard-page re-insertion into
// range listings (CT-I5: Frida omits PAGE_GUARD pages from enumerateRanges [CT-lab E16b]), protection filters,
// binary searches (nearest preceding export, .pdata entries), name globs and paging (S4 §8.1, §8.5).
// =================================================================================================
import type { Paged } from "../../shared/agentProtocol.js";

export interface RangeRec {
  readonly base: bigint;
  readonly size: number;
  readonly protection: string;
}

export const pageBaseOf = (addr: bigint, pageSize: number): bigint => addr - (addr % BigInt(pageSize));

/** Page bases covering [base, base+size) (size ≥ 1). */
export const pagesCovering = (base: bigint, size: number, pageSize: number): bigint[] => {
  const out: bigint[] = [];
  if (size <= 0) return out;
  const ps = BigInt(pageSize);
  const end = base + BigInt(size);
  for (let p = pageBaseOf(base, pageSize); p < end; p += ps) out.push(p);
  return out;
};

/** [a, a+an) ∩ [b, b+bn) is non-empty. */
export const overlaps = (a: bigint, an: number, b: bigint, bn: number): boolean =>
  a < b + BigInt(bn) && b < a + BigInt(an);

/**
 * Frida protection filters are minimums: every non-'-' character of the filter must be present ("rw-" matches "rw-"
 * and "rwx"; "---" matches everything).
 */
export const protectionMatches = (prot: string, filter: string): boolean => {
  for (let i = 0; i < 3; i++) {
    const want = filter[i];
    if (want !== undefined && want !== "-" && prot[i] !== want) return false;
  }
  return true;
};

const byBase = (a: RangeRec, b: RangeRec): number => (a.base < b.base ? -1 : a.base > b.base ? 1 : 0);

/** Merge adjacent ranges with the same protection (input sorted by base). */
export const coalesceRanges = (sorted: readonly RangeRec[]): RangeRec[] => {
  const out: RangeRec[] = [];
  for (const r of sorted) {
    const last = out[out.length - 1];
    if (last !== undefined && last.protection === r.protection && last.base + BigInt(last.size) === r.base)
      out[out.length - 1] = { base: last.base, size: last.size + r.size, protection: last.protection };
    else out.push(r);
  }
  return out;
};

/**
 * Re-insert BEA-guarded pages (with their original protection) into a range listing that omitted them. Pages whose
 * original protection does not pass `filter`, or that some listed range already covers, are skipped.
 */
export const reinsertGuardPages = (
  ranges: readonly RangeRec[],
  pages: readonly RangeRec[],
  filter: string,
  coalesce: boolean,
): RangeRec[] => {
  const merged = [...ranges];
  for (const page of pages) {
    if (!protectionMatches(page.protection, filter)) continue;
    if (ranges.some((r) => overlaps(r.base, r.size, page.base, page.size))) continue;
    merged.push(page);
  }
  merged.sort(byBase);
  return coalesce ? coalesceRanges(merged) : merged;
};

/** Index of the last element ≤ key in an ascending array, or -1. */
export const lastIndexAtOrBelow = (sorted: readonly bigint[], key: bigint): number => {
  let lo = 0;
  let hi = sorted.length - 1;
  let found = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (sorted[mid]! <= key) {
      found = mid;
      lo = mid + 1;
    } else hi = mid - 1;
  }
  return found;
};

/** .pdata lookup: index of the RUNTIME_FUNCTION whose [begin, end) contains `rva` (begins ascending), or -1. */
export const findPdataIndex = (begins: ArrayLike<number>, ends: ArrayLike<number>, rva: number): number => {
  let lo = 0;
  let hi = begins.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const b = begins[mid]!;
    if (rva < b) hi = mid - 1;
    else if (rva >= ends[mid]!) lo = mid + 1;
    else return mid;
  }
  return -1;
};

/** Case-insensitive glob (`*`, `?`) → RegExp anchored on the whole name. */
export const globToRegExp = (glob: string): RegExp => {
  let src = "";
  for (const ch of glob) {
    if (ch === "*") src += ".*";
    else if (ch === "?") src += ".";
    else src += ch.replace(/[.+^${}()|[\]\\]/gu, "\\$&");
  }
  return new RegExp(`^${src}$`, "iu");
};

/** One page of `items` (limit clamped to [1, max]). */
export const paginate = <T>(items: readonly T[], offset: number, limit: number, max: number): Paged<T> => {
  const off = Math.max(0, Math.floor(offset));
  const lim = Math.max(1, Math.min(Math.floor(limit), max));
  const page = items.slice(off, off + lim);
  const next = off + page.length;
  return { total: items.length, offset: off, items: page, next_offset: next < items.length ? next : null };
};

/** TTL + LRU store for listRanges snapshots (S4 §8.5: ss<n>, snapshot_ttl_ms, max_snapshots). */
export class TtlLru<V> {
  readonly #entries = new Map<string, { value: V; at: number }>();
  readonly #ttlMs: number;
  readonly #max: number;

  constructor(ttlMs: number, max: number) {
    this.#ttlMs = ttlMs;
    this.#max = Math.max(1, max);
  }

  put(id: string, value: V, nowMs: number): void {
    this.#sweep(nowMs);
    this.#entries.delete(id);
    this.#entries.set(id, { value, at: nowMs });
    while (this.#entries.size > this.#max) {
      const oldest = this.#entries.keys().next();
      if (oldest.done === true) break;
      this.#entries.delete(oldest.value);
    }
  }

  /** The value, refreshed as most recently used; null when unknown or expired. */
  get(id: string, nowMs: number): V | null {
    this.#sweep(nowMs);
    const e = this.#entries.get(id);
    if (e === undefined) return null;
    this.#entries.delete(id);
    this.#entries.set(id, { value: e.value, at: nowMs });
    return e.value;
  }

  get size(): number {
    return this.#entries.size;
  }

  #sweep(nowMs: number): void {
    for (const [id, e] of this.#entries) if (nowMs - e.at > this.#ttlMs) this.#entries.delete(id);
  }
}
