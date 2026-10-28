import {
  floatFromBits,
  isNaNBits,
  maskTo,
  SCALAR_WIDTH,
  signedOf,
  ulpDistance,
} from "../../domain/callModel/floatBits.js";
import type { CallScalarType } from "../../domain/callModel/types.js";
import type { CallStatus } from "../../shared/callPlan.js";
import type { Hex } from "../../shared/hex.js";

/**
 * diff_function's comparator (S5 §9.7, pure). Legs carry per-vector outcome CLASSES (S5 §9.3.2: returned, target
 * stop, harness stop, not run) and decoded column bits. For every pair of legs — (live, emulation), (live, expected),
 * (emulation, expected) — each vector is equal, differ (outcome class, fault site or value) or inconclusive (a
 * harness stop or a vector that did not run on one side). Comparison is BIT-EXACT per declared type (MXCSR status bits
 * never take part); ulp/abs/rel statistics are reported beside it and a tolerance never changes the verdict. Pair
 * verdict: any difference -> differ; else any inconclusive vector (inconclusive "count") or nothing compared ->
 * unknown; else equivalent-on-tested-inputs. Overall: any differ -> differ; any unknown -> unknown.
 */
export type Leg = "live" | "emulation" | "expected";
export type OutcomeClass = "returned" | "target_stop" | "harness_stop" | "not_run";
export type Verdict = "equivalent-on-tested-inputs" | "differ" | "unknown";
export type Cell = Hex | readonly Hex[] | null;

export interface FaultSite {
  /** status family ("fault", "cpu_exception", …) */
  readonly family: string;
  readonly module: string | null;
  readonly rva: string | null;
  readonly access: "read" | "write" | "execute" | null;
}

export interface LegData {
  readonly leg: Leg;
  /** per vector k (absolute index offset + k) */
  readonly classes: readonly OutcomeClass[];
  readonly status: readonly (CallStatus | null)[];
  /** harness cause / "not_run:<why>" per vector (null when returned or a target stop) */
  readonly reasons: readonly (string | null)[];
  readonly sites: readonly (FaultSite | null)[];
  /** compared columns ("ret", "<buffer>.<field>") -> per-vector bits; null = no value (not compared) */
  readonly cells: Readonly<Record<string, readonly Cell[]>>;
}

export interface ColumnSpec {
  readonly name: string;
  /** element type for arrays */
  readonly type: CallScalarType;
}

export interface CompareOptions {
  readonly nan: "bits" | "any_nan";
  readonly tolerance?:
    | { readonly ulp?: number | undefined; readonly abs?: number | undefined; readonly rel?: number | undefined }
    | undefined;
  readonly inconclusive: "count" | "exclude";
  readonly compareFaultSites: boolean;
}

export type PairCode = "eq" | "df" | "ic";
export type DiffReason = "outcome_class" | "fault_site" | "value";
export interface VectorPair {
  readonly r: PairCode;
  readonly why?: string;
  /** largest ulp over the vector's float cells (null: no float cell or a NaN) */
  readonly ulp?: number | null;
}

export interface ColumnStats {
  type: string;
  compared: number;
  exact_equal: number;
  differ: number;
  max_ulp: number | null;
  p50_ulp: number | null;
  p99_ulp: number | null;
  max_abs: number | null;
  max_rel: number | null;
  nan_payload: number;
  nan_vs_number: number;
  signed_zero: number;
  inf_mismatch: number;
  int_max_delta: string | null;
}

export interface PairSummary {
  readonly a: Leg;
  readonly b: Leg;
  readonly verdict: Verdict;
  readonly compared: number;
  readonly equal: number;
  readonly differ: number;
  readonly inconclusive: number;
  readonly inconclusive_reasons: Record<string, number>;
  readonly outcome_mismatches: number;
  readonly columns: Record<string, ColumnStats>;
  readonly tolerance?: { within: number; outside: number };
  /** per-vector outcome (diff rows) */
  readonly vectors: readonly VectorPair[];
}

export interface WorstEntry {
  readonly index: number;
  readonly column: string;
  readonly reason: DiffReason;
  readonly inputs: Record<string, Hex | Hex[]>;
  readonly values: Partial<Record<Leg, { status: CallStatus | null; bits: Hex | Hex[] | null }>>;
  readonly ulp: number | null;
}

export interface DifferenceProfile {
  /** float cells that differ */
  readonly floatDiffs: number;
  /** every differing float cell is within 2 ulp */
  readonly allWithin2Ulp: boolean;
  readonly nanPayloadOnly: boolean;
  readonly signedZeroOnly: boolean;
  readonly integerDiffs: number;
  readonly maxUlp: number | null;
}

export interface CompareResult {
  readonly verdict: Verdict;
  readonly pairs: readonly PairSummary[];
  readonly worst: readonly WorstEntry[];
  /** vectors excluded as inconclusive (inconclusive "exclude") over every pair */
  readonly excluded: number;
  readonly profile: DifferenceProfile;
}

const PAIR_ORDER: readonly (readonly [Leg, Leg])[] = [
  ["live", "emulation"],
  ["live", "expected"],
  ["emulation", "expected"],
];
const WORST_MAX = 10;
const SATURATE = BigInt(Number.MAX_SAFE_INTEGER);

const isFloat = (type: CallScalarType): type is "f32" | "f64" => type === "f32" || type === "f64";
const lane = (type: CallScalarType, hex: Hex): bigint => maskTo(BigInt(hex), SCALAR_WIDTH[type]);
const toNumber = (value: bigint): number => Number(value > SATURATE ? SATURATE : value);

/** Bit equality of one element under the declared type (any_nan: two NaNs are equal whatever their payload). */
export const bitsEqual = (type: CallScalarType, a: Hex, b: Hex, nan: CompareOptions["nan"]): boolean => {
  const x = lane(type, a);
  const y = lane(type, b);
  if (x === y) return true;
  return isFloat(type) && nan === "any_nan" && isNaNBits(type, x) && isNaNBits(type, y);
};

class StatsBuilder {
  readonly stats: ColumnStats;
  readonly #ulps: bigint[] = [];
  #intDelta: bigint | null = null;
  within = 0;
  outside = 0;
  constructor(
    readonly type: CallScalarType,
    private readonly options: CompareOptions,
  ) {
    this.stats = {
      type,
      compared: 0,
      exact_equal: 0,
      differ: 0,
      max_ulp: null,
      p50_ulp: null,
      p99_ulp: null,
      max_abs: null,
      max_rel: null,
      nan_payload: 0,
      nan_vs_number: 0,
      signed_zero: 0,
      inf_mismatch: 0,
      int_max_delta: null,
    };
  }

  /** one element pair; returns its ulp distance (floats, null for NaN / ints) */
  element(
    a: Hex,
    b: Hex,
  ): {
    equal: boolean;
    ulp: bigint | null;
    kind: "nan_payload" | "nan_vs_number" | "signed_zero" | "inf" | "value" | null;
  } {
    const type = this.type;
    const equal = bitsEqual(type, a, b, this.options.nan);
    if (!isFloat(type)) {
      if (!equal) {
        const width = SCALAR_WIDTH[type];
        const x = type.startsWith("i") ? signedOf(lane(type, a), width) : lane(type, a);
        const y = type.startsWith("i") ? signedOf(lane(type, b), width) : lane(type, b);
        const delta = x > y ? x - y : y - x;
        if (this.#intDelta === null || delta > this.#intDelta) this.#intDelta = delta;
      }
      return { equal, ulp: null, kind: equal ? null : "value" };
    }
    const x = lane(type, a);
    const y = lane(type, b);
    const nanX = isNaNBits(type, x);
    const nanY = isNaNBits(type, y);
    let kind: "nan_payload" | "nan_vs_number" | "signed_zero" | "inf" | "value" | null = null;
    const tolerance = this.options.tolerance;
    if (nanX || nanY) {
      if (!equal) kind = nanX && nanY ? "nan_payload" : "nan_vs_number";
      if (kind === "nan_payload") this.stats.nan_payload += 1;
      if (kind === "nan_vs_number") this.stats.nan_vs_number += 1;
      if (tolerance !== undefined) this.#tally(equal);
      return { equal, ulp: null, kind };
    }
    const ulp = ulpDistance(type, x, y) ?? 0n;
    this.#ulps.push(ulp);
    const fa = floatFromBits(type, x);
    const fb = floatFromBits(type, y);
    if (!equal) {
      const zero = fa === 0 && fb === 0;
      const infinite = !Number.isFinite(fa) || !Number.isFinite(fb);
      kind = zero ? "signed_zero" : infinite ? "inf" : "value";
      if (kind === "signed_zero") this.stats.signed_zero += 1;
      if (kind === "inf") this.stats.inf_mismatch += 1;
    }
    if (Number.isFinite(fa) && Number.isFinite(fb)) {
      const abs = Math.abs(fa - fb);
      const scale = Math.max(Math.abs(fa), Math.abs(fb));
      const rel = scale === 0 ? 0 : abs / scale;
      if (Number.isFinite(abs)) this.stats.max_abs = Math.max(this.stats.max_abs ?? 0, abs);
      if (Number.isFinite(rel)) this.stats.max_rel = Math.max(this.stats.max_rel ?? 0, rel);
      if (tolerance !== undefined) {
        const inside =
          equal ||
          (tolerance.ulp !== undefined && ulp <= BigInt(tolerance.ulp)) ||
          (tolerance.abs !== undefined && abs <= tolerance.abs) ||
          (tolerance.rel !== undefined && rel <= tolerance.rel);
        this.#tally(inside);
      }
    } else if (tolerance !== undefined) this.#tally(equal);
    return { equal, ulp, kind };
  }

  /** tolerance bookkeeping (it never changes a verdict) */
  #tally(inside: boolean): void {
    if (inside) this.within += 1;
    else this.outside += 1;
  }

  finish(): ColumnStats {
    if (this.#ulps.length > 0) {
      const sorted = [...this.#ulps].sort((p, q) => (p < q ? -1 : p > q ? 1 : 0));
      const rank = (q: number): bigint => sorted[Math.max(0, Math.ceil(q * sorted.length) - 1)] ?? 0n;
      this.stats.max_ulp = toNumber(sorted.at(-1) ?? 0n);
      this.stats.p50_ulp = toNumber(rank(0.5));
      this.stats.p99_ulp = toNumber(rank(0.99));
    }
    if (this.#intDelta !== null) this.stats.int_max_delta = this.#intDelta.toString();
    return this.stats;
  }
}

const siteDiffers = (a: FaultSite | null, b: FaultSite | null): boolean => {
  if (a === null || b === null) return false;
  // EMU-9: the family (and access) still compare when a site has no rva (an undetailed stop)
  if (a.family !== b.family) return true;
  if (a.access !== null && b.access !== null && a.access !== b.access) return true;
  if (a.rva === null || b.rva === null) return false;
  if (BigInt(a.rva) !== BigInt(b.rva)) return true;
  return a.module !== null && b.module !== null && a.module.toLowerCase() !== b.module.toLowerCase();
};

interface PendingWorst {
  readonly entry: WorstEntry;
  readonly rank: number;
  readonly magnitude: bigint;
}

export interface CompareInput {
  /** absolute index of vector k = 0 */
  readonly offset: number;
  readonly count: number;
  readonly legs: readonly LegData[];
  readonly columns: readonly ColumnSpec[];
  readonly options: CompareOptions;
  /** request inputs per vector (worst[] reports them) */
  readonly inputs: Readonly<Record<string, readonly (Hex | readonly Hex[])[]>>;
}

export const compareLegs = (input: CompareInput): CompareResult => {
  const legs = new Map(input.legs.map((l) => [l.leg, l]));
  const pairs: PairSummary[] = [];
  const worst: PendingWorst[] = [];
  let excluded = 0;
  let floatDiffs = 0;
  let integerDiffs = 0;
  let maxUlp: bigint | null = null;
  let allWithin2 = true;
  let nanPayloadOnly = true;
  let signedZeroOnly = true;
  const inputsAt = (k: number): Record<string, Hex | Hex[]> => {
    const out: Record<string, Hex | Hex[]> = {};
    for (const [name, cells] of Object.entries(input.inputs)) {
      const cell = cells[k];
      if (cell !== undefined) out[name] = typeof cell === "string" ? cell : [...cell];
    }
    return out;
  };
  const valueOf = (
    leg: LegData,
    column: string,
    k: number,
  ): { status: CallStatus | null; bits: Hex | Hex[] | null } => {
    const cell = leg.cells[column]?.[k] ?? null;
    return { status: leg.status[k] ?? null, bits: cell === null ? null : typeof cell === "string" ? cell : [...cell] };
  };

  for (const [aName, bName] of PAIR_ORDER) {
    const a = legs.get(aName);
    const b = legs.get(bName);
    if (a === undefined || b === undefined) continue;
    const builders = new Map(input.columns.map((c) => [c.name, new StatsBuilder(c.type, input.options)]));
    const vectors: VectorPair[] = [];
    let equal = 0;
    let differ = 0;
    let inconclusive = 0;
    let outcomeMismatches = 0;
    const reasons: Record<string, number> = {};
    for (let k = 0; k < input.count; k++) {
      const oa = a.classes[k] ?? "not_run";
      const ob = b.classes[k] ?? "not_run";
      const index = input.offset + k;
      const pushWorst = (
        column: string,
        reason: DiffReason,
        ulp: bigint | null,
        rank: number,
        magnitude: bigint,
      ): void => {
        worst.push({
          entry: {
            index,
            column,
            reason,
            inputs: inputsAt(k),
            values: { [aName]: valueOf(a, column, k), [bName]: valueOf(b, column, k) },
            ulp: ulp === null ? null : toNumber(ulp),
          },
          rank,
          magnitude,
        });
      };
      if (oa === "harness_stop" || oa === "not_run" || ob === "harness_stop" || ob === "not_run") {
        const why =
          (oa === "harness_stop" || oa === "not_run" ? a.reasons[k] : null) ??
          (ob === "harness_stop" || ob === "not_run" ? b.reasons[k] : null) ??
          (oa === "not_run" || ob === "not_run" ? "not_run" : "harness_stop");
        reasons[why] = (reasons[why] ?? 0) + 1;
        inconclusive += 1;
        vectors.push({ r: "ic", why });
        continue;
      }
      if (oa === "target_stop" && ob === "target_stop") {
        if (input.options.compareFaultSites && siteDiffers(a.sites[k] ?? null, b.sites[k] ?? null)) {
          differ += 1;
          vectors.push({ r: "df", why: "fault_site" });
          pushWorst(input.columns[0]?.name ?? "ret", "fault_site", null, 0, 0n);
        } else {
          equal += 1;
          vectors.push({ r: "eq" });
        }
        continue;
      }
      if (oa !== ob) {
        differ += 1;
        outcomeMismatches += 1;
        vectors.push({ r: "df", why: "outcome_class" });
        pushWorst(input.columns[0]?.name ?? "ret", "outcome_class", null, 0, 0n);
        continue;
      }
      // both returned: compare every column both legs have a value for
      let comparedAny = false;
      let vectorDiffers = false;
      let vectorUlp: bigint | null = null;
      let firstDiff: { column: string; ulp: bigint | null; integer: boolean } | null = null;
      for (const column of input.columns) {
        const ca = a.cells[column.name]?.[k] ?? null;
        const cb = b.cells[column.name]?.[k] ?? null;
        if (ca === null || cb === null) continue;
        comparedAny = true;
        const builder = builders.get(column.name);
        if (builder === undefined) continue;
        builder.stats.compared += 1;
        const elementsA = typeof ca === "string" ? [ca] : ca;
        const elementsB = typeof cb === "string" ? [cb] : cb;
        let cellEqualAll = elementsA.length === elementsB.length;
        let cellUlp: bigint | null = null;
        for (let e = 0; e < Math.max(elementsA.length, elementsB.length); e++) {
          const x = elementsA[e];
          const y = elementsB[e];
          if (x === undefined || y === undefined) {
            cellEqualAll = false;
            continue;
          }
          const result = builder.element(x, y);
          if (result.ulp !== null && (cellUlp === null || result.ulp > cellUlp)) cellUlp = result.ulp;
          if (!result.equal) {
            cellEqualAll = false;
            if (isFloat(column.type)) {
              floatDiffs += 1;
              if (result.kind !== "nan_payload") nanPayloadOnly = false;
              if (result.kind !== "signed_zero") signedZeroOnly = false;
              if (result.ulp === null || result.ulp > 2n) allWithin2 = false;
            } else {
              integerDiffs += 1;
              nanPayloadOnly = false;
              signedZeroOnly = false;
            }
          }
        }
        if (cellUlp !== null) {
          if (vectorUlp === null || cellUlp > vectorUlp) vectorUlp = cellUlp;
          if (!cellEqualAll && (maxUlp === null || cellUlp > maxUlp)) maxUlp = cellUlp;
        }
        if (cellEqualAll) builder.stats.exact_equal += 1;
        else {
          builder.stats.differ += 1;
          vectorDiffers = true;
          firstDiff ??= { column: column.name, ulp: cellUlp, integer: !isFloat(column.type) };
        }
      }
      if (!comparedAny) {
        inconclusive += 1;
        reasons["no_comparable_columns"] = (reasons["no_comparable_columns"] ?? 0) + 1;
        vectors.push({ r: "ic", why: "no_comparable_columns" });
        continue;
      }
      if (vectorDiffers) {
        differ += 1;
        vectors.push({ r: "df", why: "value", ulp: vectorUlp === null ? null : toNumber(vectorUlp) });
        if (firstDiff !== null)
          pushWorst(firstDiff.column, "value", firstDiff.ulp, firstDiff.integer ? 2 : 1, firstDiff.ulp ?? 0n);
      } else {
        equal += 1;
        vectors.push({ r: "eq", ...(vectorUlp === null ? {} : { ulp: toNumber(vectorUlp) }) });
      }
    }
    const compared = equal + differ;
    if (input.options.inconclusive === "exclude") excluded += inconclusive;
    const verdict: Verdict =
      differ > 0
        ? "differ"
        : (inconclusive > 0 && input.options.inconclusive === "count") || compared === 0
          ? "unknown"
          : "equivalent-on-tested-inputs";
    let within = 0;
    let outside = 0;
    const columns: Record<string, ColumnStats> = {};
    for (const [name, builder] of builders) {
      columns[name] = builder.finish();
      within += builder.within;
      outside += builder.outside;
    }
    pairs.push({
      a: aName,
      b: bName,
      verdict,
      compared,
      equal,
      differ,
      inconclusive,
      inconclusive_reasons: reasons,
      outcome_mismatches: outcomeMismatches,
      columns,
      ...(input.options.tolerance === undefined ? {} : { tolerance: { within, outside } }),
      vectors,
    });
  }
  const verdict: Verdict = pairs.some((p) => p.verdict === "differ")
    ? "differ"
    : pairs.length === 0 || pairs.some((p) => p.verdict === "unknown")
      ? "unknown"
      : "equivalent-on-tested-inputs";
  // outcome-class (and fault-site) differences first, then the largest ulp, then integer deltas
  worst.sort(
    (p, q) =>
      p.rank - q.rank ||
      (p.magnitude > q.magnitude ? -1 : p.magnitude < q.magnitude ? 1 : p.entry.index - q.entry.index),
  );
  const anyDiff = floatDiffs + integerDiffs > 0;
  return {
    verdict,
    pairs,
    worst: worst.slice(0, WORST_MAX).map((w) => w.entry),
    excluded,
    profile: {
      floatDiffs,
      allWithin2Ulp: floatDiffs > 0 && allWithin2,
      nanPayloadOnly: anyDiff && nanPayloadOnly,
      signedZeroOnly: anyDiff && signedZeroOnly,
      integerDiffs,
      maxUlp: maxUlp === null ? null : toNumber(maxUlp),
    },
  };
};
