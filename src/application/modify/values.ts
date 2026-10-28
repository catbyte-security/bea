import type { ModifyValueType } from "../../contracts/areas/modify.js";
import { formatHex, HEX_INPUT_RE, type Hex } from "../../shared/hex.js";
import type { ScalarInput, ValueType } from "../../shared/agentProtocol.js";

/**
 * Tool-level scalar encoding for write_memory and override_function (S6 §2.3, DESIGN §6.0 "Values"): a number, a
 * decimal string, a "0x…" string that is ALWAYS the raw bit pattern of the declared type (two's complement for signed
 * integers, IEEE-754 bits for floats), the float specials "NaN" / "Infinity" / "-Infinity" / "-0", a boolean for
 * `bool` (one byte, CI-M13), and for `ptr` any AddrExpr (resolved by the caller through AddressService).
 * Everything is reduced to exact raw bits here, so the agent never re-interprets a value.
 */

export const TYPE_WIDTH: { readonly [T in ModifyValueType]: 1 | 2 | 4 | 8 } = {
  i8: 1,
  u8: 1,
  i16: 2,
  u16: 2,
  i32: 4,
  u32: 4,
  i64: 8,
  u64: 8,
  ptr: 8,
  bool: 1,
  f32: 4,
  f64: 8,
};

/** Agent ValueType of a tool type (the tool `bool` is the agent's one-byte `bool8`). */
export const agentValueType = (type: ModifyValueType): ValueType => (type === "bool" ? "bool8" : type);

export const isFloatType = (type: ModifyValueType): boolean => type === "f32" || type === "f64";

export type ScalarParse =
  | { readonly kind: "bits"; readonly bits: bigint }
  /** ptr given as an AddrExpr: the caller resolves it and passes the VA to {@link bitsOfAddress} */
  | { readonly kind: "address"; readonly expr: string }
  | { readonly kind: "error"; readonly reason: "invalid_value" | "out_of_range"; readonly message: string };

const DECIMAL_INT_RE = /^[+-]?\d{1,20}$/u;
const DECIMAL_FLOAT_RE = /^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$/u;
const FLOAT_SPECIALS: Readonly<Record<string, number>> = {
  NaN: Number.NaN,
  Infinity: Number.POSITIVE_INFINITY,
  "-Infinity": Number.NEGATIVE_INFINITY,
  "-0": -0,
};

const fail = (reason: "invalid_value" | "out_of_range", message: string): ScalarParse => ({
  kind: "error",
  reason,
  message,
});

const signed = (type: ModifyValueType): boolean => type === "i8" || type === "i16" || type === "i32" || type === "i64";

/** Exact IEEE bits of a JS number at the given width (NaN is the canonical quiet NaN). */
export const floatBits = (value: number, width: 4 | 8): bigint => {
  const view = new DataView(new ArrayBuffer(8));
  if (width === 4) {
    view.setFloat32(0, value, true);
    return BigInt(view.getUint32(0, true));
  }
  view.setFloat64(0, value, true);
  return view.getBigUint64(0, true);
};

const intBits = (type: ModifyValueType, value: bigint): ScalarParse => {
  const bitsWidth = BigInt(TYPE_WIDTH[type] * 8);
  const min = signed(type) ? -(1n << (bitsWidth - 1n)) : 0n;
  const max = signed(type) ? (1n << (bitsWidth - 1n)) - 1n : (1n << bitsWidth) - 1n;
  if (value < min || value > max)
    return fail("out_of_range", `${type} takes ${String(min)}..${String(max)}; use "0x…" for raw bits.`);
  return { kind: "bits", bits: value & ((1n << bitsWidth) - 1n) };
};

/** Parse one tool scalar of the declared type into raw bits (little-endian width = TYPE_WIDTH[type]). */
export const parseScalar = (type: ModifyValueType, value: number | string | boolean): ScalarParse => {
  const width = TYPE_WIDTH[type];
  if (typeof value === "boolean") {
    if (type !== "bool") return fail("invalid_value", `A boolean is only valid for type bool; ${type} takes a number.`);
    return { kind: "bits", bits: value ? 1n : 0n };
  }
  if (typeof value === "string" && HEX_INPUT_RE.test(value)) {
    const bits = BigInt(`0x${value.slice(2)}`);
    if (bits >> BigInt(width * 8) !== 0n)
      return fail("out_of_range", `"${value}" has more bits than ${type} (${String(width * 8)}).`);
    return { kind: "bits", bits };
  }
  if (isFloatType(type)) {
    const number =
      typeof value === "number"
        ? value
        : Object.hasOwn(FLOAT_SPECIALS, value)
          ? FLOAT_SPECIALS[value]
          : DECIMAL_FLOAT_RE.test(value)
            ? Number(value)
            : undefined;
    if (number === undefined)
      return fail(
        "invalid_value",
        `${type} takes a number, a decimal string, NaN, Infinity, -Infinity, -0 or "0x…" bits.`,
      );
    return { kind: "bits", bits: floatBits(number, width === 4 ? 4 : 8) };
  }
  if (typeof value === "number") {
    if (!Number.isInteger(value)) return fail("invalid_value", `${type} takes an integer.`);
    if (!Number.isSafeInteger(value))
      return fail("out_of_range", `Integers beyond 2^53 must be given as decimal strings or "0x…" bits.`);
    if (type === "bool" && value !== 0 && value !== 1) return fail("out_of_range", "bool takes true, false, 0 or 1.");
    return intBits(type, BigInt(value));
  }
  if (type === "ptr" && !DECIMAL_INT_RE.test(value)) return { kind: "address", expr: value };
  if (!DECIMAL_INT_RE.test(value)) return fail("invalid_value", `${type} takes an integer, a decimal string or "0x…".`);
  if (type === "bool") {
    const parsed = BigInt(value);
    return parsed === 0n || parsed === 1n ? { kind: "bits", bits: parsed } : fail("out_of_range", "bool takes 0 or 1.");
  }
  return intBits(type, BigInt(value));
};

/** Bits of a resolved ptr AddrExpr. */
export const bitsOfAddress = (va: bigint): Extract<ScalarParse, { kind: "bits" }> => ({ kind: "bits", bits: va });

/** Little-endian bytes of raw bits at the type's width. */
export const bytesOfBits = (type: ModifyValueType, bits: bigint): Uint8Array => {
  const width = TYPE_WIDTH[type];
  const out = new Uint8Array(width);
  let rest = bits;
  for (let i = 0; i < width; i++) {
    out[i] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  return out;
};

/**
 * Agent ScalarInput of raw bits (S4 §4.1): floats as `{bits}` (exact, NaN payloads kept), every other type as a raw
 * two's-complement Hex string, which the agent's override engine reads as bits of the declared type.
 */
export const agentScalarOfBits = (type: ModifyValueType, bits: bigint): ScalarInput =>
  isFloatType(type) ? { bits: formatHex(bits) } : (formatHex(bits) as Hex);
