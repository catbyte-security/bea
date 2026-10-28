import type { JsonObject, JsonValue } from "../../domain/json.js";

/**
 * Bounded digests shared by recording summaries and query_events stats (S6 §5.3 FieldStats; WP7-HOOK owns, other
 * recording kinds may import). Every list is capped and carries totals; distinct values are capped at 10,000.
 */
export type Scalar = number | string | boolean | null;

export const DISTINCT_CAP = 10_000;
export const TOP_VALUES = 5;

// ---------------------------------------------------------------------------------------------- floats (S6 §2.3)
const F32 = new Float32Array(1);
const U32 = new Uint32Array(F32.buffer);
const F64 = new Float64Array(1);
const U64 = new BigUint64Array(F64.buffer);

/** Shortest decimal that round-trips to the same f32 (S6 §2.3 "shortest round-trip numbers"). */
export const shortestF32 = (x: number): number => {
  if (!Number.isFinite(x) || x === 0) return x;
  for (let p = 1; p <= 9; p++) {
    const y = Number(x.toPrecision(p));
    if (Math.fround(y) === x) return y;
  }
  return x;
};

/** Float output form: a number, or "NaN" / "Infinity" / "-Infinity". */
export const floatOut = (x: number): number | string =>
  Number.isNaN(x) ? "NaN" : x === Infinity ? "Infinity" : x === -Infinity ? "-Infinity" : x;

/** f32 / f64 value of raw bits ("0x…", up to 8 / 16 digits). */
export const floatOfBits = (type: "f32" | "f64", bits: string): number | string => {
  const v = BigInt(bits.startsWith("0x") || bits.startsWith("0X") ? bits : `0x${bits}`);
  if (type === "f32") {
    U32[0] = Number(v & 0xffff_ffffn);
    return floatOut(shortestF32(F32[0] ?? 0));
  }
  U64[0] = v & 0xffff_ffff_ffff_ffffn;
  return floatOut(F64[0] ?? 0);
};

/** Raw bits of a float output value (f32 via Math.fround); NaN payloads are not recoverable from a number. */
export const bitsOfFloat = (type: "f32" | "f64", value: number | string): string => {
  const x =
    typeof value === "number" ? value : value === "Infinity" ? Infinity : value === "-Infinity" ? -Infinity : NaN;
  if (type === "f32") {
    F32[0] = x;
    return `0x${(U32[0] ?? 0).toString(16).padStart(8, "0")}`;
  }
  F64[0] = x;
  return `0x${(U64[0] ?? 0n).toString(16).padStart(16, "0")}`;
};

// ---------------------------------------------------------------------------------------------- ordering
const DECIMAL_INT = /^-?\d{1,20}$/u;
const HEX_INT = /^0x[0-9a-f]{1,16}$/iu;

/** Numeric view of a value: numbers, 64-bit decimal strings and "0x" hex strings; null otherwise. */
export const numericOf = (v: JsonValue | undefined): number | bigint | null => {
  if (typeof v === "number") return Number.isFinite(v) ? v : null;
  if (typeof v === "boolean") return v ? 1 : 0;
  if (typeof v === "string") {
    if (DECIMAL_INT.test(v) || HEX_INT.test(v)) return BigInt(v);
    if (v === "Infinity") return Infinity;
    if (v === "-Infinity") return -Infinity;
  }
  return null;
};

/** -1 / 0 / 1 for two numeric views (bigint and number mixed exactly). */
export const compareNumeric = (a: number | bigint, b: number | bigint): number => {
  if (typeof a === "bigint" && typeof b === "bigint") return a < b ? -1 : a > b ? 1 : 0;
  if (typeof a === "number" && typeof b === "number") return a < b ? -1 : a > b ? 1 : 0;
  const an = typeof a === "bigint" ? a : null;
  const bn = typeof b === "bigint" ? b : null;
  if (an !== null && typeof b === "number") {
    if (!Number.isFinite(b)) return b > 0 ? -1 : 1;
    const bi = BigInt(Math.trunc(b));
    return an < bi ? -1 : an > bi ? 1 : b > Math.trunc(b) ? -1 : b < Math.trunc(b) ? 1 : 0;
  }
  if (bn !== null && typeof a === "number") return -compareNumeric(bn, a);
  return 0;
};

const TYPE_RANK = { boolean: 0, number: 1, string: 2, object: 3 } as const;
/** Total order over scalars for min/max: numeric when both are numeric, else by type then text. */
export const compareValues = (a: JsonValue, b: JsonValue): number => {
  const na = numericOf(a);
  const nb = numericOf(b);
  if (na !== null && nb !== null) return compareNumeric(na, nb);
  const ra = TYPE_RANK[typeof a as keyof typeof TYPE_RANK] ?? 3;
  const rb = TYPE_RANK[typeof b as keyof typeof TYPE_RANK] ?? 3;
  if (ra !== rb) return ra - rb;
  const sa = typeof a === "string" ? a : JSON.stringify(a);
  const sb = typeof b === "string" ? b : JSON.stringify(b);
  return sa < sb ? -1 : sa > sb ? 1 : 0;
};

/** Scalar form of any value for digests (arrays/objects become compact JSON text, capped). */
export const scalarOf = (v: JsonValue | undefined, maxChars = 256): Scalar => {
  if (v === undefined) return null;
  if (v === null || typeof v === "number" || typeof v === "boolean") return v;
  const s = typeof v === "string" ? v : JSON.stringify(v);
  return s.length > maxChars ? `${s.slice(0, maxChars - 1)}…` : s;
};

// ---------------------------------------------------------------------------------------------- accumulators
/** Incremental FieldStats (S6 §5.3): count, min, max, mean of numbers, distinct (capped), top 5 values. */
export class FieldStatsAccumulator {
  #count = 0;
  #min: JsonValue | undefined;
  #max: JsonValue | undefined;
  #sum = 0;
  #numbers = 0;
  #capped = false;
  readonly #distinct = new Map<string, { value: Scalar; count: number }>();

  constructor(readonly type: string) {}

  add(v: JsonValue | undefined): void {
    if (v === undefined || v === null) return;
    this.#count++;
    if (this.#min === undefined || compareValues(v, this.#min) < 0) this.#min = v;
    if (this.#max === undefined || compareValues(v, this.#max) > 0) this.#max = v;
    if (typeof v === "number" && Number.isFinite(v)) {
      this.#sum += v;
      this.#numbers++;
    }
    const key = typeof v === "string" ? `s${v}` : JSON.stringify(v);
    const seen = this.#distinct.get(key);
    if (seen !== undefined) seen.count++;
    else if (this.#distinct.size < DISTINCT_CAP) this.#distinct.set(key, { value: scalarOf(v), count: 1 });
    else this.#capped = true;
  }

  get count(): number {
    return this.#count;
  }

  /** count/min/max/distinct/top as plain values (min/max as scalars). */
  result(maxChars = 256): {
    readonly type: string;
    readonly count: number;
    readonly min: Scalar;
    readonly max: Scalar;
    readonly mean: number | null;
    readonly distinct: number;
    readonly distinct_capped: boolean;
    readonly top: readonly { readonly value: Scalar; readonly count: number }[];
  } {
    const top = [...this.#distinct.values()]
      .sort((a, b) => b.count - a.count || compareValues(a.value, b.value))
      .slice(0, TOP_VALUES)
      .map((t) => ({ value: typeof t.value === "string" ? scalarOf(t.value, maxChars) : t.value, count: t.count }));
    return {
      type: this.type,
      count: this.#count,
      min: scalarOf(this.#min, maxChars),
      max: scalarOf(this.#max, maxChars),
      mean: this.#numbers > 0 && this.#numbers === this.#count ? this.#sum / this.#numbers : null,
      distinct: this.#distinct.size,
      distinct_capped: this.#capped,
      top,
    };
  }

  /** The S6 FieldStats digest (optional keys omitted when empty). */
  digest(): JsonObject {
    const r = this.result();
    return {
      type: r.type,
      count: r.count,
      ...(r.count > 0 ? { min: r.min, max: r.max } : {}),
      distinct: r.distinct,
      ...(r.distinct_capped ? { distinct_capped: true } : {}),
      ...(r.top.length > 0 ? { top: r.top.map((t) => ({ value: t.value, count: t.count })) } : {}),
    };
  }
}

/** Counts per key, reported as the top N by count (ties by key) plus the total distinct count. */
export class TopCounter<K extends string | number> {
  readonly #counts = new Map<K, number>();
  #capped = false;

  add(key: K, n = 1): void {
    const c = this.#counts.get(key);
    if (c !== undefined) this.#counts.set(key, c + n);
    else if (this.#counts.size < DISTINCT_CAP) this.#counts.set(key, n);
    else this.#capped = true;
  }

  get distinct(): number {
    return this.#counts.size;
  }

  get capped(): boolean {
    return this.#capped;
  }

  top(n: number): readonly (readonly [K, number])[] {
    return [...this.#counts.entries()]
      .sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
      .slice(0, n);
  }
}

/**
 * Deterministic bounded sample for percentiles: keeps every k-th value, doubling k (and halving the sample)
 * whenever the sample is full. max is exact; p50/p90 are approximate above the capacity.
 */
export class QuantileSample {
  #values: number[] = [];
  #stride = 1;
  #seen = 0;
  #max = -Infinity;

  constructor(private readonly capacity = 8192) {}

  add(v: number): void {
    if (!Number.isFinite(v)) return;
    if (v > this.#max) this.#max = v;
    if (this.#seen++ % this.#stride !== 0) return;
    this.#values.push(v);
    if (this.#values.length >= this.capacity) {
      this.#values = this.#values.filter((_, i) => i % 2 === 0);
      this.#stride *= 2;
    }
  }

  get count(): number {
    return this.#seen;
  }

  /** {p50, p90, max} or null when empty. */
  summary(): { readonly p50: number; readonly p90: number; readonly max: number } | null {
    if (this.#seen === 0) return null;
    const sorted = [...this.#values].sort((a, b) => a - b);
    const at = (q: number): number => sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))] ?? 0;
    return { p50: at(0.5), p90: at(0.9), max: this.#max };
  }
}
