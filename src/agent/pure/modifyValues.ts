// Agent pure helpers of WP12-MODIFY (DESIGN §9.1 rule 3: no GumJS globals or types; importable by vitest).
// Exact value encoding for gated writes and overrides: ScalarInput -> raw bits -> little-endian bytes, original
// values -> ValueCells, and the XMM low-lane replacement that keeps the upper lanes (S4 §14).
import type { Hex, ScalarInput, ValueCell, ValueType } from "../../shared/agentProtocol.js";

export type ScalarValueType = Exclude<ValueType, "utf8" | "utf16" | "ansi" | "bytes">;

export const SCALAR_WIDTH: { readonly [T in ScalarValueType]: 1 | 2 | 4 | 8 } = {
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
};

export const isScalarType = (type: ValueType): type is ScalarValueType => Object.hasOwn(SCALAR_WIDTH, type);
export const isFloat = (type: ValueType): boolean => type === "f32" || type === "f64";
const isSigned = (type: ScalarValueType): boolean =>
  type === "i8" || type === "i16" || type === "i32" || type === "i64";

export type BitsResult =
  | { readonly ok: true; readonly bits: bigint }
  | { readonly ok: false; readonly problem: string };

const RAW_HEX_RE = /^0[xX][0-9a-fA-F]{1,16}$/u;
const DEC_INT_RE = /^[+-]?\d{1,20}$/u;
const DEC_FLOAT_RE = /^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$/u;

/** IEEE bits of a JS number (f32 rounds to nearest even; NaN becomes the canonical quiet NaN). */
export const floatToBits = (value: number, width: 4 | 8): bigint => {
  const view = new DataView(new ArrayBuffer(8));
  if (width === 4) {
    view.setFloat32(0, value, true);
    return BigInt(view.getUint32(0, true));
  }
  view.setFloat64(0, value, true);
  return view.getBigUint64(0, true);
};

/** JS number of IEEE bits (QJS keeps NaN payloads in doubles; f32 payloads widen exactly). */
export const bitsToFloat = (bits: bigint, width: 4 | 8): number => {
  const view = new DataView(new ArrayBuffer(8));
  if (width === 4) {
    view.setUint32(0, Number(bits & 0xffff_ffffn), true);
    return view.getFloat32(0, true);
  }
  view.setBigUint64(0, bits & 0xffff_ffff_ffff_ffffn, true);
  return view.getFloat64(0, true);
};

const fitInt = (type: ScalarValueType, value: bigint): BitsResult => {
  const width = BigInt(SCALAR_WIDTH[type] * 8);
  const min = isSigned(type) ? -(1n << (width - 1n)) : 0n;
  const max = isSigned(type) ? (1n << (width - 1n)) - 1n : (1n << width) - 1n;
  if (value < min || value > max) return { ok: false, problem: `${type} value out of range` };
  return { ok: true, bits: value & ((1n << width) - 1n) };
};

/** Canonical bits of the float words (quiet NaN with an empty payload; -0 keeps its sign bit). */
const FLOAT_SPECIALS: Readonly<Record<string, { readonly f32: bigint; readonly f64: bigint }>> = {
  NaN: { f32: 0x7fc0_0000n, f64: 0x7ff8_0000_0000_0000n },
  Infinity: { f32: 0x7f80_0000n, f64: 0x7ff0_0000_0000_0000n },
  "-Infinity": { f32: 0xff80_0000n, f64: 0xfff0_0000_0000_0000n },
  "-0": { f32: 0x8000_0000n, f64: 0x8000_0000_0000_0000n },
};

/**
 * ScalarInput (S4 §4.1) -> raw bits of `type`. A `{bits}` object or a "0x…" string is the raw bit pattern; a number
 * or decimal string is the value; floats also take NaN / Infinity / -Infinity / -0; booleans are 0/1.
 */
export const scalarBits = (type: ScalarValueType, input: ScalarInput): BitsResult => {
  const width = SCALAR_WIDTH[type];
  const raw = (text: string): BitsResult => {
    const bits = BigInt(`0x${text.slice(2)}`);
    return bits >> BigInt(width * 8) === 0n ? { ok: true, bits } : { ok: false, problem: `${type} raw bits too wide` };
  };
  if (typeof input === "object") {
    return typeof input.bits === "string" && RAW_HEX_RE.test(input.bits)
      ? raw(input.bits)
      : { ok: false, problem: "bits must be 0x-prefixed hex" };
  }
  if (typeof input === "boolean") return { ok: true, bits: input ? 1n : 0n };
  if (typeof input === "string" && RAW_HEX_RE.test(input)) return raw(input);
  if (isFloat(type)) {
    // The specials are canonical BITS, never JS numbers: Frida 17.23.2's QJS has no infinities
    // (Number.POSITIVE_INFINITY is 1e300 there, so an f64 "Infinity" written through a number stored 1e300; WP10).
    const special =
      typeof input === "string" && Object.hasOwn(FLOAT_SPECIALS, input) ? FLOAT_SPECIALS[input] : undefined;
    if (special !== undefined) return { ok: true, bits: width === 4 ? special.f32 : special.f64 };
    const value = typeof input === "number" ? input : DEC_FLOAT_RE.test(input) ? Number(input) : undefined;
    return value === undefined
      ? { ok: false, problem: `${type} takes a number` }
      : { ok: true, bits: floatToBits(value, width === 4 ? 4 : 8) };
  }
  if (typeof input === "number") {
    if (!Number.isSafeInteger(input)) return { ok: false, problem: `${type} takes a safe integer` };
    return fitInt(type, BigInt(input));
  }
  if (!DEC_INT_RE.test(input)) return { ok: false, problem: `${type} takes an integer` };
  return fitInt(type, BigInt(input));
};

export const bitsToBytes = (bits: bigint, width: number): Uint8Array => {
  const out = new Uint8Array(width);
  let rest = bits;
  for (let i = 0; i < width; i++) {
    out[i] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  return out;
};

export const bytesToBits = (bytes: Uint8Array): bigint => {
  let bits = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) bits = (bits << 8n) | BigInt(bytes[i] ?? 0);
  return bits;
};

export const toHexBytes = (bytes: Uint8Array): string => {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
};

export const fromHexBytes = (hex: string): Uint8Array | null => {
  if (!/^(?:[0-9a-fA-F]{2})*$/u.test(hex)) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
};

export const hexOf = (bits: bigint): Hex => `0x${(bits & 0xffff_ffff_ffff_ffffn).toString(16)}`;

/** Bytes of a typed write ({type, values}); strings and raw bytes go through `bytes`, not `typed`. */
export const typedBytes = (
  type: ValueType,
  values: readonly ScalarInput[],
): { readonly ok: true; readonly bytes: Uint8Array } | { readonly ok: false; readonly problem: string } => {
  if (!isScalarType(type)) return { ok: false, problem: `typed writes take scalar types; send ${type} as bytes` };
  if (values.length === 0) return { ok: false, problem: "typed.values is empty" };
  const width = SCALAR_WIDTH[type];
  const out = new Uint8Array(width * values.length);
  for (const [i, value] of values.entries()) {
    const bits = scalarBits(type, value);
    if (!bits.ok) return { ok: false, problem: `values[${String(i)}]: ${bits.problem}` };
    out.set(bitsToBytes(bits.bits, width), i * width);
  }
  return { ok: true, bytes: out };
};

/** Value cell of an original value (S4 §4.6): ≤ 32-bit ints and bools as numbers, 64-bit and float bits as Hex. */
export const cellOf = (type: ScalarValueType, bits: bigint): ValueCell => {
  const width = SCALAR_WIDTH[type];
  const masked = bits & ((1n << BigInt(width * 8)) - 1n);
  if (isFloat(type) || width === 8) return hexOf(masked);
  if (isSigned(type)) {
    const sign = 1n << BigInt(width * 8 - 1);
    return Number(masked & sign ? masked - (sign << 1n) : masked);
  }
  return Number(masked);
};

/** A 16-byte XMM image with only the low `width` bytes replaced by `bits` (upper lanes preserved, S4 §14). */
export const replaceLowLane = (current: Uint8Array, bits: bigint, width: 4 | 8): Uint8Array => {
  const out = new Uint8Array(16);
  out.set(current.subarray(0, 16));
  out.set(bitsToBytes(bits, width), 0);
  return out;
};

/** NativeCallback return type of a replace override (bool8 is one byte). */
export const nativeTypeOf = (type: ScalarValueType | "void"): string =>
  ({
    void: "void",
    i8: "int8",
    u8: "uint8",
    i16: "int16",
    u16: "uint16",
    i32: "int32",
    u32: "uint32",
    i64: "int64",
    u64: "uint64",
    ptr: "pointer",
    bool8: "uint8",
    bool32: "int32",
    f32: "float",
    f64: "double",
  })[type];
