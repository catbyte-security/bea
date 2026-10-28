// =================================================================================================
// src/agent/pure/coreScalar.ts — WP3-AGENT pure helpers: ValueType sizes, ScalarInput → exact bits, raw bits →
// TypedOut / ValueCell (S4 §4.1, §5.3). Pure (no GumJS): unit-tested in tests/unit/agent/core/.
// Rules: integers are exact (|v| ≤ 2^53-1 as JS numbers, decimal or "0x…" strings otherwise); a "0x…" string is
// always the raw bit pattern of the declared type (D-INT-9); floats given as numbers round like Math.fround; float
// outputs always carry their exact bits.
// =================================================================================================
import type { ScalarInput, TypedOut, ValueCell, ValueType } from "../../shared/agentProtocol.js";
import { f32Bits, f64Bits, FLOAT_SPECIAL_BITS, floatViewOfBits, hexOfBigint, parseHexText } from "./coreHex.js";

/** Fixed byte width of a scalar type; null for strings and bytes. */
export const VALUE_TYPE_BYTES: Readonly<Record<ValueType, number | null>> = {
  i8: 1,
  u8: 1,
  i16: 2,
  u16: 2,
  i32: 4,
  u32: 4,
  i64: 8,
  u64: 8,
  ptr: 8,
  bool8: 1,
  bool32: 4,
  f32: 4,
  f64: 8,
  utf8: null,
  utf16: null,
  ansi: null,
  bytes: null,
};

const SIGNED: ReadonlySet<ValueType> = new Set(["i8", "i16", "i32", "i64"]);
const STRING_TYPES: ReadonlySet<ValueType> = new Set(["utf8", "utf16", "ansi"]);

export const isStringType = (t: ValueType): boolean => STRING_TYPES.has(t);
export const isFloatType = (t: ValueType): t is "f32" | "f64" => t === "f32" || t === "f64";

export type ScalarParse =
  | { readonly ok: true; readonly bits: bigint }
  | { readonly ok: false; readonly problem: string };

const widthMask = (bytes: number): bigint => (1n << BigInt(bytes * 8)) - 1n;

/** Integer range check of an exact integer value for the type; returns the two's-complement bits or a problem. */
const intBits = (value: bigint, t: ValueType, bytes: number): ScalarParse => {
  const bitsN = BigInt(bytes * 8);
  const min = SIGNED.has(t) ? -(1n << (bitsN - 1n)) : 0n;
  const max = SIGNED.has(t) ? (1n << (bitsN - 1n)) - 1n : (1n << bitsN) - 1n;
  if (value < min || value > max) return { ok: false, problem: `${value} is out of range for ${t}` };
  return { ok: true, bits: value & widthMask(bytes) };
};

/** The words for float specials map to canonical bits (never through a JS number: see floatViewOfBits). */
const floatWordBits = (text: string, t: "f32" | "f64"): bigint | null => {
  if (/^[+-]?nan$/iu.test(text)) return FLOAT_SPECIAL_BITS[t].NaN;
  if (/^\+?inf(inity)?$/iu.test(text)) return FLOAT_SPECIAL_BITS[t].Infinity;
  if (/^-inf(inity)?$/iu.test(text)) return FLOAT_SPECIAL_BITS[t]["-Infinity"];
  return null;
};

const parseFloatInput = (v: number | string, t: "f32" | "f64"): ScalarParse => {
  if (typeof v === "string") {
    const special = floatWordBits(v.trim(), t);
    if (special !== null) return { ok: true, bits: special };
  }
  const n = typeof v === "number" ? v : Number(v.trim());
  if (typeof v === "string" && (v.trim() === "" || Number.isNaN(n)))
    return { ok: false, problem: `"${v}" is not a ${t} value` };
  return { ok: true, bits: t === "f32" ? BigInt(f32Bits(n)) : f64Bits(n) };
};

/**
 * Convert a ScalarInput to the exact raw bits of type `t` (scalar types only). `{bits}` and "0x…" strings are raw
 * bits and must fit the width; booleans are 1/0; numbers must be safe integers for integer types.
 */
export const scalarBits = (v: ScalarInput, t: ValueType): ScalarParse => {
  const bytes = VALUE_TYPE_BYTES[t];
  if (bytes === null) return { ok: false, problem: `${t} is not a scalar type` };
  if (typeof v === "object") {
    const raw = parseHexText(v.bits);
    if (raw === null) return { ok: false, problem: "bits must be a 0x-prefixed hex value of 1..16 digits" };
    return raw > widthMask(bytes) ? { ok: false, problem: `bits ${v.bits} exceed ${t}` } : { ok: true, bits: raw };
  }
  if (typeof v === "boolean") return { ok: true, bits: v ? 1n : 0n };
  if (typeof v === "string") {
    const raw = parseHexText(v.trim());
    if (raw !== null)
      return raw > widthMask(bytes) ? { ok: false, problem: `${v} exceeds ${t}` } : { ok: true, bits: raw };
  }
  if (isFloatType(t)) return parseFloatInput(v, t);
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) return { ok: false, problem: `${v} is not an exact integer` };
    return intBits(BigInt(v), t, bytes);
  }
  if (!/^[+-]?\d+$/u.test(v.trim())) return { ok: false, problem: `"${v}" is not an integer` };
  return intBits(BigInt(v.trim()), t, bytes);
};

/** Sign-extend `bits` of `bytes` width to a signed bigint. */
export const signExtend = (bits: bigint, bytes: number): bigint => {
  const n = BigInt(bytes * 8);
  const v = bits & widthMask(bytes);
  return v >= 1n << (n - 1n) ? v - (1n << n) : v;
};

/** Raw bits → TypedOut for a scalar type (floats keep exact bits; 64-bit integers are decimal strings + bits). */
export const typedOutOfBits = (t: ValueType, bits: bigint): TypedOut => {
  const bytes = VALUE_TYPE_BYTES[t] ?? 8;
  const raw = bits & widthMask(bytes);
  switch (t) {
    case "f32":
    case "f64":
      return { type: t, value: floatViewOfBits(t, raw), bits: hexOfBigint(raw) };
    case "i64":
      return { type: t, value: signExtend(raw, 8).toString(), bits: hexOfBigint(raw) };
    case "u64":
      return { type: t, value: raw.toString(), bits: hexOfBigint(raw) };
    case "ptr":
      return { type: t, value: hexOfBigint(raw), bits: hexOfBigint(raw) };
    case "bool8":
    case "bool32":
      return { type: t, value: raw !== 0n };
    case "i8":
    case "i16":
    case "i32":
      return { type: t, value: Number(signExtend(raw, bytes)) };
    default:
      return { type: t, value: Number(raw) };
  }
};

/** Raw bits → ValueCell (row form): ≤ 32-bit ints and booleans as numbers, 64-bit/ptr/float bits as Hex. */
export const cellOfBits = (t: ValueType, bits: bigint): ValueCell => {
  const bytes = VALUE_TYPE_BYTES[t] ?? 8;
  const raw = bits & widthMask(bytes);
  switch (t) {
    case "i8":
    case "i16":
    case "i32":
      return Number(signExtend(raw, bytes));
    case "u8":
    case "u16":
    case "u32":
      return Number(raw);
    case "bool8":
    case "bool32":
      return raw !== 0n ? 1 : 0;
    default:
      return hexOfBigint(raw);
  }
};

/** Read a scalar of type `t` from little-endian bytes at `off` (caller checks the length). */
export const bitsFromBytes = (bytes: Uint8Array, off: number, t: ValueType): bigint => {
  const width = VALUE_TYPE_BYTES[t] ?? 8;
  let v = 0n;
  for (let i = width - 1; i >= 0; i--) v = (v << 8n) | BigInt(bytes[off + i] ?? 0);
  return v;
};

/** Little-endian bytes of `bits` for a scalar type (writes, test fixtures). */
export const bytesFromBits = (t: ValueType, bits: bigint): Uint8Array => {
  const width = VALUE_TYPE_BYTES[t] ?? 8;
  const out = new Uint8Array(width);
  let v = bits;
  for (let i = 0; i < width; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
};
