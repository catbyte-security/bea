import { canonicalDigest } from "../canonical.js";
import type { InputIssue } from "../errors/beaError.js";
import type { JsonObject } from "../json.js";
import { err, ok, type Result } from "../result.js";
import { extendTo64, f32ToBits, f64ToBits, isFloatType, isSignedType, SCALAR_WIDTH } from "./floatBits.js";
import { normalizeScalar, splitElements, type AddressBits, type ColumnBits, type ScalarInput } from "./normalize.js";
import type { CallPlan, CallScalarType } from "./types.js";

/**
 * Seeded vector generators (S5 §7.6). DETERMINISM IS PART OF THE CONTRACT: the goldens in
 * tests/golden/callModel/generators.json pin the first 16 rows of 6 specs, and changing anything below is a breaking
 * change (a continuation with vector_offset must regenerate exactly the rows the first call saw).
 *
 * - PRNG: xoshiro128** (32-bit). Each column has its own stream, seeded with four splitmix32 words drawn from the
 *   Weyl state `seed ⊕ fnv1a32(utf8(columnName))` (splitmix32 = state += 0x9e3779b9; MurmurHash3 fmix32 of it).
 * - f32 draws u = (next() >>> 8) / 2^24; f64 draws u = ((a >>> 5)·2^26 + (b >>> 6)) / 2^53 (a then b).
 * - uniform: floats min + u·(max − min) (then Math.fround for f32); integers: inclusive range by rejection sampling
 *   over 32-bit draws (64-bit ranges: hi then lo draw).
 * - log_uniform (floats, 0 < min ≤ max): exp(ln min + u·(ln max − ln min)); signs "both" draws one more word after
 *   the magnitude and negates when its low bit is 1.
 * - edge: a fixed per-type list, cycled; bits_uniform: one raw draw (two for 64-bit types: hi then lo), masked.
 * - grid: comma-separated values; cartesian = product over the grid columns in sorted name order, the LAST name
 *   varying fastest; zip = all grid lists the same length. Non-grid columns draw once per row.
 */
export interface DistributionInput {
  readonly dist: "uniform" | "log_uniform" | "grid" | "edge" | "bits_uniform" | "constant";
  readonly min?: number | undefined;
  readonly max?: number | undefined;
  readonly signs?: "positive" | "both" | undefined;
  readonly values?: string | undefined;
  readonly value?: ScalarInput | undefined;
}
export interface GenerateInput {
  readonly seed: number;
  readonly count?: number | undefined;
  readonly columns: Readonly<Record<string, DistributionInput>>;
  readonly grid: "cartesian" | "zip";
}

export const fnv1a32 = (text: string): number => {
  let hash = 0x811c_9dc5;
  for (const byte of new TextEncoder().encode(text)) {
    hash ^= byte;
    hash = Math.imul(hash, 0x0100_0193) >>> 0;
  }
  return hash >>> 0;
};

/** splitmix32 words from a Weyl state (MurmurHash3 fmix32 of state += golden gamma). */
export const splitmix32 = (state: number, words: number): number[] => {
  let s = state >>> 0;
  const out: number[] = [];
  for (let k = 0; k < words; k++) {
    s = (s + 0x9e37_79b9) >>> 0;
    let z = s;
    z = Math.imul(z ^ (z >>> 16), 0x85eb_ca6b) >>> 0;
    z = Math.imul(z ^ (z >>> 13), 0xc2b2_ae35) >>> 0;
    out.push((z ^ (z >>> 16)) >>> 0);
  }
  return out;
};

const rotl = (x: number, k: number): number => ((x << k) | (x >>> (32 - k))) >>> 0;

/** xoshiro128** (Blackman & Vigna); state of four non-zero-in-total 32-bit words. */
export class Xoshiro128 {
  readonly #s: [number, number, number, number];

  constructor(words: readonly number[]) {
    const [a = 0, b = 0, c = 0, d = 0] = words;
    this.#s = [a >>> 0, b >>> 0, c >>> 0, d >>> 0];
    if ((a | b | c | d) === 0) this.#s[0] = 1; // the all-zero state is a fixed point
  }

  static forColumn(seed: number, column: string): Xoshiro128 {
    return new Xoshiro128(splitmix32((seed ^ fnv1a32(column)) >>> 0, 4));
  }

  next(): number {
    const s = this.#s;
    const result = Math.imul(rotl(Math.imul(s[1], 5) >>> 0, 7), 9) >>> 0;
    const t = (s[1] << 9) >>> 0;
    s[2] = (s[2] ^ s[0]) >>> 0;
    s[3] = (s[3] ^ s[1]) >>> 0;
    s[1] = (s[1] ^ s[2]) >>> 0;
    s[0] = (s[0] ^ s[3]) >>> 0;
    s[2] = (s[2] ^ t) >>> 0;
    s[3] = rotl(s[3], 11);
    return result;
  }
}

const unitF32 = (rng: Xoshiro128): number => (rng.next() >>> 8) / 2 ** 24;
const unitF64 = (rng: Xoshiro128): number => {
  const a = rng.next();
  const b = rng.next();
  return ((a >>> 5) * 2 ** 26 + (b >>> 6)) / 2 ** 53;
};

const draw64 = (rng: Xoshiro128): bigint => {
  const hi = BigInt(rng.next());
  const lo = BigInt(rng.next());
  return (hi << 32n) | lo;
};

/** Uniform integer in [0, range) by rejection (range ≤ 2^64). */
const belowRange = (rng: Xoshiro128, range: bigint): bigint => {
  if (range <= 1n) return 0n;
  if (range <= 1n << 32n) {
    const limit = ((1n << 32n) / range) * range;
    for (;;) {
      const r = BigInt(rng.next());
      if (r < limit) return r % range;
    }
  }
  if (range === 1n << 64n) return draw64(rng);
  const limit = ((1n << 64n) / range) * range;
  for (;;) {
    const r = draw64(rng);
    if (r < limit) return r % range;
  }
};

const F32_EDGES = [
  0x0, 0x8000_0000, 0x1, 0x7f_ffff, 0x80_0000, 0x3f80_0000, 0xbf80_0000, 0x3f00_0000, 0x4000_0000, 0x7f7f_ffff,
  0xff7f_ffff, 0x7f80_0000, 0xff80_0000, 0x7fc0_0000, 0xffc0_0000, 0x7fa0_0000,
].map(BigInt);
const F64_EDGES = [
  0x0n,
  0x8000_0000_0000_0000n,
  0x1n,
  0x000f_ffff_ffff_ffffn,
  0x0010_0000_0000_0000n,
  0x3ff0_0000_0000_0000n,
  0xbff0_0000_0000_0000n,
  0x3fe0_0000_0000_0000n,
  0x4000_0000_0000_0000n,
  0x7fef_ffff_ffff_ffffn,
  0xffef_ffff_ffff_ffffn,
  0x7ff0_0000_0000_0000n,
  0xfff0_0000_0000_0000n,
  0x7ff8_0000_0000_0000n,
  0xfff8_0000_0000_0000n,
  0x7ff4_0000_0000_0000n,
];

/** Edge list of a type as 64-bit lanes: floats as above; integers [0, 1, −1, MIN, MAX, MIN+1, MAX−1] (signed). */
export const edgeValues = (type: CallScalarType): readonly bigint[] => {
  if (type === "f32") return F32_EDGES;
  if (type === "f64") return F64_EDGES;
  if (type === "bool") return [0n, 1n];
  const bits = BigInt(SCALAR_WIDTH[type] * 8);
  if (isSignedType(type)) {
    const min = -(1n << (bits - 1n));
    const max = (1n << (bits - 1n)) - 1n;
    return [0n, 1n, -1n, min, max, min + 1n, max - 1n].map((v) => extendTo64(type, BigInt.asUintN(64, v)));
  }
  const max = (1n << bits) - 1n;
  return [0n, 1n, max, max - 1n];
};

type Sampler = (rng: Xoshiro128) => bigint;

const floatSampler = (type: "f32" | "f64", d: DistributionInput, path: string): Result<Sampler, InputIssue> => {
  const min = d.min ?? 0;
  const max = d.max ?? 0;
  if (min > max) return err({ path: `${path}.min`, reason: "invalid_value", message: "min must be ≤ max." });
  const unit = type === "f32" ? unitF32 : unitF64;
  const bitsOf = (x: number): bigint => (type === "f32" ? f32ToBits(Math.fround(x)) : f64ToBits(x));
  if (d.dist === "uniform") return ok((rng) => bitsOf(min + unit(rng) * (max - min)));
  if (!(min > 0))
    return err({ path: `${path}.min`, reason: "invalid_value", message: "log_uniform needs 0 < min ≤ max." });
  const lo = Math.log(min);
  const span = Math.log(max) - lo;
  const both = d.signs === "both";
  return ok((rng) => {
    const magnitude = Math.exp(lo + unit(rng) * span);
    const negative = both && (rng.next() & 1) === 1;
    return bitsOf(negative ? -magnitude : magnitude);
  });
};

const integerSampler = (type: CallScalarType, d: DistributionInput, path: string): Result<Sampler, InputIssue> => {
  if (d.dist === "log_uniform")
    return err({ path: `${path}.dist`, reason: "invalid_value", message: "log_uniform applies to f32/f64 columns." });
  const min = d.min ?? 0;
  const max = d.max ?? 0;
  if (!Number.isSafeInteger(min) || !Number.isSafeInteger(max) || min > max)
    return err({
      path: `${path}.min`,
      reason: "invalid_value",
      message: "Integer uniform needs safe-integer min ≤ max.",
    });
  const lowNorm = normalizeScalar(type, min);
  const highNorm = normalizeScalar(type, max);
  if (!lowNorm.ok || !highNorm.ok)
    return err({ path: `${path}.max`, reason: "out_of_range", message: `min and max must fit ${type}.` });
  const range = BigInt(max) - BigInt(min) + 1n;
  return ok((rng) => extendTo64(type, BigInt.asUintN(64, BigInt(min) + belowRange(rng, range))));
};

const listValues = (
  type: CallScalarType,
  text: string,
  path: string,
  resolve: AddressBits,
): Result<bigint[], InputIssue> => {
  const out: bigint[] = [];
  for (const [i, element] of splitElements(text).entries()) {
    const normalized = normalizeScalar(type, element);
    if (!normalized.ok)
      return err({ path, reason: "invalid_value", message: `Value ${String(i)}: ${normalized.error}` });
    const bits = normalized.value.kind === "bits" ? normalized.value.bits : resolve(normalized.value.expr);
    if (bits === undefined)
      return err({
        path,
        reason: "invalid_value",
        message: "The address expression could not be resolved in this session.",
      });
    out.push(bits);
  }
  if (out.length === 0) return err({ path, reason: "invalid_value", message: "grid needs at least one value." });
  if (out.length > 4096)
    return err({ path, reason: "out_of_range", message: "grid takes at most 4096 values.", maximum: 4096 });
  return ok(out);
};

type ColumnPlan =
  | { readonly kind: "grid"; readonly name: string; readonly values: readonly bigint[] }
  | { readonly kind: "edge"; readonly name: string; readonly values: readonly bigint[] }
  | { readonly kind: "draw"; readonly name: string; readonly sample: Sampler }
  | { readonly kind: "constant"; readonly name: string; readonly bits: bigint };

const columnPlan = (
  name: string,
  type: CallScalarType,
  d: DistributionInput,
  resolve: AddressBits,
): Result<ColumnPlan, InputIssue> => {
  const path = `generate.columns.${name}`;
  switch (d.dist) {
    case "grid": {
      const values = listValues(type, d.values ?? "", `${path}.values`, resolve);
      return values.ok ? ok({ kind: "grid", name, values: values.value }) : values;
    }
    case "edge":
      return ok({ kind: "edge", name, values: edgeValues(type) });
    case "constant": {
      const values = listValues(type, String(d.value ?? ""), `${path}.value`, resolve);
      if (!values.ok) return values;
      return ok({ kind: "constant", name, bits: values.value[0] ?? 0n });
    }
    case "bits_uniform": {
      const width = SCALAR_WIDTH[type];
      const mask = (1n << BigInt(width * 8)) - 1n;
      return ok({
        kind: "draw",
        name,
        sample: (rng) => extendTo64(type, (width === 8 ? draw64(rng) : BigInt(rng.next())) & mask),
      });
    }
    case "uniform":
    case "log_uniform": {
      const sampler = isFloatType(type) ? floatSampler(type, d, path) : integerSampler(type, d, path);
      return sampler.ok ? ok({ kind: "draw", name, sample: sampler.value }) : sampler;
    }
  }
};

/** Rows to produce: count and the grid index of each row. */
const gridShape = (
  input: GenerateInput,
  grids: readonly Extract<ColumnPlan, { kind: "grid" }>[],
): Result<{ count: number; indexOf: (row: number, column: number) => number }, InputIssue> => {
  if (grids.length === 0) {
    if (input.count === undefined)
      return err({
        path: "generate.count",
        reason: "missing_argument",
        message: "count is required unless a grid column fixes it.",
      });
    return ok({ count: input.count, indexOf: () => 0 });
  }
  if (input.grid === "zip") {
    const lengths = new Set(grids.map((g) => g.values.length));
    const length = grids[0]?.values.length ?? 0;
    if (lengths.size > 1)
      return err({
        path: "generate.columns",
        reason: "invalid_value",
        message: "zip needs every grid list to have the same length.",
      });
    if (input.count !== undefined && input.count !== length)
      return err({
        path: "generate.count",
        reason: "conflicting_arguments",
        message: `zip grids fix count at ${String(length)}.`,
      });
    return ok({ count: length, indexOf: (row) => row });
  }
  const sizes = grids.map((g) => g.values.length);
  const product = sizes.reduce((a, b) => a * b, 1);
  if (product > 1_000_000)
    return err({
      path: "generate.columns",
      reason: "out_of_range",
      message: "The cartesian grid exceeds 1,000,000 rows.",
      maximum: 1_000_000,
    });
  if (input.count !== undefined && input.count !== product)
    return err({
      path: "generate.count",
      reason: "conflicting_arguments",
      message: `The cartesian grid fixes count at ${String(product)}.`,
    });
  const strides = sizes.map((_, i) => sizes.slice(i + 1).reduce((a, b) => a * b, 1));
  return ok({
    count: product,
    indexOf: (row, column) => Math.floor(row / (strides[column] ?? 1)) % (sizes[column] ?? 1),
  });
};

export interface GeneratedWindow {
  /** total vectors the spec defines */
  readonly total: number;
  /** rows [from, to) of every generated column (logical 64-bit-lane bits) */
  readonly bits: ColumnBits;
  readonly specDigest: string;
}

/**
 * Generate rows [from, min(to, total)) of every column of a plan whose supplied columns are exactly
 * `input.columns` (scalar columns only). Draw streams advance through the skipped rows, so a continuation
 * regenerates the same values.
 */
export const generateWindow = (
  plan: CallPlan,
  input: GenerateInput,
  window: { readonly from: number; readonly to: number },
  resolve: AddressBits,
): Result<GeneratedWindow, InputIssue[]> => {
  const issues: InputIssue[] = [];
  const plans: ColumnPlan[] = [];
  for (const name of Object.keys(input.columns).sort()) {
    const declared = plan.columns.find((c) => c.name === name);
    const dist = input.columns[name];
    if (declared === undefined || dist === undefined) continue; // classification already reported unknown columns
    if (declared.type.endsWith("[]")) {
      issues.push({
        path: `generate.columns.${name}`,
        reason: "invalid_value",
        message: "generate supports scalar columns only.",
      });
      continue;
    }
    const p = columnPlan(name, declared.type as CallScalarType, dist, resolve);
    if (p.ok) plans.push(p.value);
    else issues.push(p.error);
  }
  if (issues.length > 0) return err(issues);
  const grids = plans.filter((p): p is Extract<ColumnPlan, { kind: "grid" }> => p.kind === "grid");
  const shape = gridShape(input, grids);
  if (!shape.ok) return err([shape.error]);
  const total = shape.value.count;
  const from = Math.min(window.from, total);
  const to = Math.min(window.to, total);
  const columns = new Map<string, bigint[]>();
  for (const p of plans) {
    const cells: bigint[] = [];
    if (p.kind === "draw") {
      const rng = Xoshiro128.forColumn(input.seed, p.name);
      for (let row = 0; row < to; row++) {
        const bits = p.sample(rng);
        if (row >= from) cells.push(bits);
      }
    } else
      for (let row = from; row < to; row++) {
        if (p.kind === "grid") cells.push(p.values[shape.value.indexOf(row, grids.indexOf(p))] ?? 0n);
        else if (p.kind === "edge") cells.push(p.values[row % p.values.length] ?? 0n);
        else cells.push(p.bits);
      }
    columns.set(p.name, cells);
  }
  return ok({
    total,
    bits: { count: to - from, columns },
    specDigest: canonicalDigest(JSON.parse(JSON.stringify(input)) as JsonObject),
  });
};
