import type { z } from "zod";

import {
  SCAN_CAPS,
  type scanMemoryInputSchema,
  type ScanNextCompare,
  type scanNextInputSchema,
  type ScanToolValueType,
} from "../../contracts/areas/scan.js";
import type { InputIssue } from "../../domain/errors/beaError.js";
import type {
  RegionFilter,
  ScalarInput,
  ScanNextOp,
  ScanNextParams,
  ScanStartParams,
  ScanValueType,
  TypedOut,
} from "../../shared/agentProtocol.js";

/**
 * WP10-SCAN: tool inputs → agent scan parameters (S6 §2.3 value encoding, S4 §9.2) and agent values → tool cells.
 * Validates here, before any agent RPC, so mistakes come back as invalid_request with the input path; the agent
 * re-checks structurally (S4 §5.2).
 */
export type ScanMemoryInput = z.output<typeof scanMemoryInputSchema>;
export type ScanNextInput = z.output<typeof scanNextInputSchema>;

/** The longest element a scan stores (agent MAX_ELEM_BYTES). */
const MAX_ELEM_BYTES = 256;

const INT_BITS: Readonly<Partial<Record<ScanToolValueType, readonly [bigint, bigint, number]>>> = {
  i8: [-128n, 127n, 8],
  u8: [0n, 255n, 8],
  i16: [-32_768n, 32_767n, 16],
  u16: [0n, 65_535n, 16],
  i32: [-2_147_483_648n, 2_147_483_647n, 32],
  u32: [0n, 4_294_967_295n, 32],
  i64: [-(1n << 63n), (1n << 63n) - 1n, 64],
  u64: [0n, (1n << 64n) - 1n, 64],
  ptr: [0n, (1n << 64n) - 1n, 64],
};
const HEX_RE = /^0[xX][0-9a-fA-F]{1,16}$/u;
const DEC_RE = /^-?\d{1,20}$/u;
const FLOAT_WORDS = new Set(["NaN", "Infinity", "-Infinity"]);

const agentValueType = (t: ScanToolValueType): ScanValueType => (t === "bool" ? "u8" : t);
const isFloat = (t: ScanToolValueType): boolean => t === "f32" || t === "f64";
const isByteString = (t: ScanToolValueType): boolean => t === "bytes" || t === "utf8" || t === "utf16";

/** Natural alignment of the tool type (aligned:true). */
const naturalAlign = (t: ScanToolValueType): 1 | 2 | 4 | 8 => {
  switch (t) {
    case "i16":
    case "u16":
    case "utf16":
      return 2;
    case "i32":
    case "u32":
    case "f32":
      return 4;
    case "i64":
    case "u64":
    case "f64":
    case "ptr":
      return 8;
    default:
      return 1;
  }
};

const issue = (path: string, message: string, expected?: string): InputIssue => ({
  path,
  reason: "invalid_value",
  message,
  ...(expected === undefined ? {} : { expected }),
});

export type Checked<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly issue: InputIssue };
const good = <T>(value: T): Checked<T> => ({ ok: true, value });
const bad = (path: string, message: string, expected?: string): Checked<never> => ({
  ok: false,
  issue: issue(path, message, expected),
});

/** A ptr value that is neither a number nor plain hex/decimal text is an AddrExpr the host resolves. */
const isAddrExpr = (v: string | number | boolean): v is string =>
  typeof v === "string" && !HEX_RE.test(v) && !DEC_RE.test(v);

/** Numeric value as the agent's ScalarInput, with the S6 §2.3 range and form checks. */
export const normalizeNumeric = (
  t: ScanToolValueType,
  v: string | number | boolean,
  path: string,
): Checked<ScalarInput> => {
  if (t === "bool") {
    if (v === true || v === 1) return good(1);
    if (v === false || v === 0) return good(0);
    return bad(path, "bool values are true or false (one byte: 1 or 0).", "true | false");
  }
  if (isFloat(t)) {
    const digits = t === "f32" ? 8 : 16;
    if (typeof v === "number") return good(v);
    if (typeof v === "boolean") return bad(path, `${t} values are numbers.`, "number");
    if (/^0[xX]/u.test(v))
      return HEX_RE.test(v) && v.length - 2 <= digits
        ? good({ bits: `0x${BigInt(v.toLowerCase()).toString(16)}` as const })
        : bad(path, `${t} bits are 0x followed by at most ${String(digits)} hex digits.`, `0x${"0".repeat(digits)}`);
    if (FLOAT_WORDS.has(v)) return good(v);
    return v.trim() !== "" && Number.isFinite(Number(v))
      ? good(v)
      : bad(path, `${t} values are numbers, "NaN", "Infinity", "-Infinity" or 0x… bits.`, "number");
  }
  const range = INT_BITS[t];
  if (range === undefined) return bad(path, `${t} has no numeric value.`);
  const [lo, hi, width] = range;
  let n: bigint;
  if (typeof v === "boolean") return bad(path, `${t} values are integers.`, "integer");
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) return bad(path, `${t} values are integers within ±(2^53-1); use a decimal string.`);
    n = BigInt(v);
  } else if (HEX_RE.test(v)) {
    n = BigInt(v.toLowerCase());
    if (n >= 1n << BigInt(width)) return bad(path, `${v} does not fit ${t}.`);
    // "0x…" = raw bits of the declared type (two's complement for signed types)
    if (lo < 0n && n >= 1n << BigInt(width - 1)) n -= 1n << BigInt(width);
  } else if (DEC_RE.test(v)) n = BigInt(v);
  else return bad(path, `${t} values are numbers, decimal strings or 0x… hex.`, "integer");
  if (n < lo || n > hi) return bad(path, `${t} values are ${lo.toString()}..${hi.toString()}.`);
  return good(v);
};

const numericOrder = (t: ScanToolValueType, a: ScalarInput, b: ScalarInput): boolean => {
  const asNumber = (x: ScalarInput): number | bigint => {
    if (typeof x === "object") {
      const bits = BigInt(x.bits);
      const view = new DataView(new ArrayBuffer(8));
      view.setBigUint64(0, bits, true);
      return t === "f32" ? view.getFloat32(0, true) : view.getFloat64(0, true);
    }
    if (isFloat(t)) return Number(x);
    if (typeof x === "string" && HEX_RE.test(x)) {
      const width = BigInt(INT_BITS[t]?.[2] ?? 64);
      const n = BigInt(x.toLowerCase());
      return t.startsWith("i") && n >= 1n << (width - 1n) ? n - (1n << width) : n;
    }
    return typeof x === "boolean" ? BigInt(x ? 1 : 0) : BigInt(x);
  };
  const x = asNumber(a);
  const y = asNumber(b);
  return Number.isNaN(x) || Number.isNaN(y) ? false : x <= y;
};

const encodedLength = (t: "utf8" | "utf16", text: string): number =>
  t === "utf16" ? text.length * 2 : Buffer.byteLength(text, "utf8");

const PATTERN_TOKEN = /^[0-9a-fA-F?]{2}$/u;
/** The match-pattern grammar the agent accepts (ext-frida §3.4); "/regex/" is refused (S4 §9.2). */
export const checkPattern = (text: string, path: string): Checked<string> => {
  const example = 'Example: "48 8b ?? 4?" or "40 45 41 : f0 ff ff".';
  if (text.trim().startsWith("/")) return bad(path, `Regex patterns are not supported by scans. ${example}`);
  const [value = "", mask, extra] = text.split(":");
  const tokens = value
    .trim()
    .split(/\s+/u)
    .filter((x) => x !== "");
  if (extra !== undefined || tokens.length === 0 || !tokens.every((x) => PATTERN_TOKEN.test(x)))
    return bad(path, `invalid match pattern. ${example}`, "Frida match pattern");
  if (tokens.every((x) => x === "??")) return bad(path, `invalid match pattern: no fixed byte. ${example}`);
  if (tokens.length > MAX_ELEM_BYTES) return bad(path, `The pattern is longer than ${String(MAX_ELEM_BYTES)} bytes.`);
  if (mask !== undefined) {
    const m = mask
      .trim()
      .split(/\s+/u)
      .filter((x) => x !== "");
    if (m.length !== tokens.length || !m.every((x) => /^[0-9a-fA-F]{2}$/u.test(x)))
      return bad(path, `invalid match pattern: the mask needs one hex byte per pattern byte. ${example}`);
  }
  return good(text.trim());
};

/** A scan_memory plan: agent params, plus an AddrExpr the handler resolves (ptr/pointer_to). */
export interface FirstScanPlan {
  readonly params: ScanStartParams;
  readonly resolve: { readonly path: string; readonly expr: string } | null;
}

const regionsOf = (input: ScanMemoryInput): RegionFilter => ({
  protection: input.protection,
  ...(input.module !== undefined ? { modules: [input.module] } : input.kind === "image" ? { modules: ["*"] } : {}),
  ...(input.kind === "private" ? { private_only: true } : {}),
});

export const planScanMemory = (input: ScanMemoryInput): Checked<FirstScanPlan> => {
  const t = input.value_type;
  const common = {
    regions: regionsOf(input),
    align: input.aligned ? naturalAlign(t) : 1,
    max_candidates: input.max_hits,
  } as const;
  const value = input.value;
  if (input.compare === "unknown")
    return good({ params: { kind: "unknown", value_type: agentValueType(t), ...common }, resolve: null });
  if (value === undefined) return bad("value", "value is required.");
  if (input.compare === "pointer_to") {
    if (isAddrExpr(value))
      return good({
        params: { kind: "pointers-to", value_type: "ptr", targets: ["0x0"], ...common },
        resolve: { path: "value", expr: value },
      });
    const target = normalizeNumeric("ptr", value, "value");
    if (!target.ok) return target;
    const va = BigInt(target.value as string | number);
    return good({
      params: { kind: "pointers-to", value_type: "ptr", targets: [`0x${va.toString(16)}`], ...common },
      resolve: null,
    });
  }
  if (t === "bytes") {
    if (typeof value !== "string") return bad("value", "bytes scans take a Frida match pattern string.");
    const pattern = checkPattern(value, "value");
    return pattern.ok
      ? good({ params: { kind: "pattern", pattern: pattern.value, ...common }, resolve: null })
      : pattern;
  }
  if (t === "utf8" || t === "utf16") {
    if (typeof value !== "string") return bad("value", `${t} scans take text.`);
    if (encodedLength(t, value) > MAX_ELEM_BYTES)
      return bad("value", `The text is longer than ${String(MAX_ELEM_BYTES)} bytes in ${t}.`);
    return good({
      params: { kind: "value", value_type: t, compare: { op: "eq", text: value }, ...common },
      resolve: null,
    });
  }
  if (t === "ptr" && isAddrExpr(value))
    return good({
      params: { kind: "value", value_type: "ptr", compare: { op: "eq", value: "0x0" }, ...common },
      resolve: { path: "value", expr: value },
    });
  const a = normalizeNumeric(t, value, "value");
  if (!a.ok) return a;
  if (input.compare === "between") {
    const b = normalizeNumeric(t, input.value2 ?? 0, "value2");
    if (!b.ok) return b;
    if (!numericOrder(t, a.value, b.value)) return bad("value2", "value2 must not be smaller than value.");
    return good({
      params: {
        kind: "value",
        value_type: agentValueType(t),
        compare: { op: "range", min: a.value, max: b.value },
        ...common,
      },
      resolve: null,
    });
  }
  const compare =
    input.epsilon !== undefined && isFloat(t)
      ? { op: "approx" as const, value: a.value, eps: input.epsilon }
      : { op: "eq" as const, value: a.value };
  return good({ params: { kind: "value", value_type: agentValueType(t), compare, ...common }, resolve: null });
};

/** Puts the resolved VA of an AddrExpr into the plan. */
export const withResolvedAddress = (plan: FirstScanPlan, va: bigint): ScanStartParams => {
  const hex = `0x${va.toString(16)}` as const;
  return plan.params.kind === "pointers-to"
    ? { ...plan.params, targets: [hex] }
    : { ...plan.params, compare: { op: "eq", value: hex } };
};

const NEXT_OPS: Readonly<Record<ScanNextCompare, ScanNextOp>> = {
  exact: "eq",
  between: "range",
  changed: "changed",
  unchanged: "unchanged",
  increased: "increased",
  decreased: "decreased",
  increased_by: "increased_by",
  decreased_by: "decreased_by",
};

export type ScanNextPlan = Omit<ScanNextParams, "scan_id">;

/** scan_next → agent op and operands for a scan of tool type `t`. */
export const planScanNext = (t: ScanToolValueType, input: ScanNextInput): Checked<ScanNextPlan> => {
  const eps = input.epsilon;
  if (eps !== undefined && !isFloat(t)) return bad("epsilon", "epsilon applies to f32/f64 scans.");
  if (isByteString(t)) {
    if (!["exact", "changed", "unchanged"].includes(input.compare))
      return bad("compare", `${t} scans support exact, changed and unchanged.`, "exact | changed | unchanged");
    if (input.compare !== "exact") return good({ op: NEXT_OPS[input.compare] });
    const v = input.value;
    if (typeof v !== "string") return bad("value", `${t} scans compare with a string value.`);
    if (t === "bytes" && !/^(?:[0-9a-fA-F]{2})+$/u.test(v))
      return bad("value", "A bytes scan compares with an even-length hex string of the element's length.");
    return good({ op: "eq", value: t === "bytes" ? v.toLowerCase() : v });
  }
  const op = NEXT_OPS[input.compare];
  const withEps = eps === undefined ? {} : { eps };
  if (input.value === undefined) return good({ op, ...withEps });
  const a = normalizeNumeric(t, input.value, "value");
  if (!a.ok) return a;
  if (input.compare === "between") {
    const b = normalizeNumeric(t, input.value2 ?? 0, "value2");
    if (!b.ok) return b;
    if (!numericOrder(t, a.value, b.value)) return bad("value2", "value2 must not be smaller than value.");
    return good({ op, min: a.value, max: b.value, ...withEps });
  }
  if (input.compare === "exact" && eps !== undefined) return good({ op: "approx", value: a.value, eps });
  return good({ op, value: a.value, ...withEps });
};

/** Agent typed value → tool cell (S6 §2.3: 64-bit ints as decimal strings, pointers as hex, bool as boolean). */
export type ScanCell = number | string | boolean | null;
export const cellOf = (t: ScanToolValueType, v: TypedOut | { readonly error: unknown } | undefined): ScanCell => {
  if (v === undefined || "error" in v) return null;
  const clip = (s: string): string => (s.length > SCAN_CAPS.cellChars ? s.slice(0, SCAN_CAPS.cellChars) : s);
  if (t === "bool") return typeof v.value === "number" ? v.value !== 0 : null;
  if (t === "bytes") return v.hex === undefined ? null : clip(v.hex);
  if (typeof v.value === "string") return clip(v.value);
  return v.value;
};
