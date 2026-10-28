import type { Hex } from "../../shared/hex.js";
import type { CallScalarType } from "./types.js";

/**
 * Bit-level helpers of the call model (S5 §7.2, §9.7): IEEE-754 bits <-> JS numbers, scalar widths, sign/zero
 * extension to the 64-bit lane every executor uses, and ulp distances for diff statistics. Values always travel as
 * raw bits; JS numbers are only a display form (a NaN payload never survives a JS number, A-9).
 */
export const MASK32 = 0xffff_ffffn;
export const MASK64 = 0xffff_ffff_ffff_ffffn;

/** Default quiet NaNs written for the "NaN" literal. */
export const F32_QNAN = 0x7fc0_0000n;
export const F64_QNAN = 0x7ff8_0000_0000_0000n;
export const F32_INF = 0x7f80_0000n;
export const F64_INF = 0x7ff0_0000_0000_0000n;
export const F32_SIGN = 0x8000_0000n;
export const F64_SIGN = 0x8000_0000_0000_0000n;

/** Byte width of a scalar type in memory (bool is one byte, CI-M13). */
export const SCALAR_WIDTH: { readonly [T in CallScalarType]: 1 | 2 | 4 | 8 } = {
  i8: 1,
  u8: 1,
  bool: 1,
  i16: 2,
  u16: 2,
  i32: 4,
  u32: 4,
  f32: 4,
  i64: 8,
  u64: 8,
  f64: 8,
  ptr: 8,
};

export const isSignedType = (type: CallScalarType): boolean =>
  type === "i8" || type === "i16" || type === "i32" || type === "i64";
export const isFloatType = (type: CallScalarType): type is "f32" | "f64" => type === "f32" || type === "f64";

export const maskTo = (bits: bigint, width: 1 | 2 | 4 | 8): bigint => bits & ((1n << BigInt(width * 8)) - 1n);

/** Two's-complement value of the low `width` bytes (signed interpretation). */
export const signedOf = (bits: bigint, width: 1 | 2 | 4 | 8): bigint => BigInt.asIntN(width * 8, bits);

/**
 * The 64-bit lane of a scalar: signed integers sign-extend, everything else zero-extends (S5 §7.2 table). Every
 * per-vector cell and every constant slot carries this form; executors write the low `width` bytes of it.
 */
export const extendTo64 = (type: CallScalarType, bits: bigint): bigint => {
  const width = SCALAR_WIDTH[type];
  const low = maskTo(bits, width);
  return isSignedType(type) ? BigInt.asUintN(64, BigInt.asIntN(width * 8, low)) : low;
};

const scratch = new DataView(new ArrayBuffer(8));

export const f32ToBits = (value: number): bigint => {
  scratch.setFloat32(0, value, true);
  return BigInt(scratch.getUint32(0, true));
};
export const f64ToBits = (value: number): bigint => {
  scratch.setFloat64(0, value, true);
  return scratch.getBigUint64(0, true);
};
export const f32FromBits = (bits: bigint): number => {
  scratch.setUint32(0, Number(bits & MASK32), true);
  return scratch.getFloat32(0, true);
};
export const f64FromBits = (bits: bigint): number => {
  scratch.setBigUint64(0, bits & MASK64, true);
  return scratch.getFloat64(0, true);
};

/** @public */
export const floatBitsOf = (type: "f32" | "f64", value: number): bigint =>
  type === "f32" ? f32ToBits(value) : f64ToBits(value);
export const floatFromBits = (type: "f32" | "f64", bits: bigint): number =>
  type === "f32" ? f32FromBits(bits) : f64FromBits(bits);

export const isNaNBits = (type: "f32" | "f64", bits: bigint): boolean =>
  type === "f32"
    ? (bits & 0x7f80_0000n) === F32_INF && (bits & 0x007f_ffffn) !== 0n
    : (bits & F64_INF) === F64_INF && (bits & 0x000f_ffff_ffff_ffffn) !== 0n;

/** Shortest decimal that round-trips through Math.fround (S6 §2.3 "shortest round-trip numbers"). */
const shortestF32 = (value: number): number => {
  for (let precision = 1; precision <= 9; precision++) {
    const candidate = Number(value.toPrecision(precision));
    if (Math.fround(candidate) === value) return candidate;
  }
  return value;
};

export type FloatDisplay = number | "NaN" | "Infinity" | "-Infinity" | "-0";

/**
 * Display value of float bits: the shortest round-trip number, or a literal for the values JSON cannot carry
 * (`-0` serializes as `0`, so it is spelled "-0"). The bits stay the authority.
 */
export const floatDisplay = (type: "f32" | "f64", bits: bigint): FloatDisplay => {
  const value = floatFromBits(type, bits);
  if (Number.isNaN(value)) return "NaN";
  if (value === Number.POSITIVE_INFINITY) return "Infinity";
  if (value === Number.NEGATIVE_INFINITY) return "-Infinity";
  if (Object.is(value, -0)) return "-0";
  return type === "f32" ? shortestF32(value) : value;
};

/**
 * Ordered integer image of float bits (monotonic in the float order, -0 == +0), the basis of ulp distances.
 * NaNs have no place in the order: callers check isNaNBits first.
 */
const orderedOf = (type: "f32" | "f64", bits: bigint): bigint => {
  const sign = type === "f32" ? F32_SIGN : F64_SIGN;
  const magnitude = bits & (sign - 1n);
  return (bits & sign) !== 0n ? -magnitude : magnitude;
};

/** |a − b| in units in the last place; null when either side is a NaN (S5 §9.7 keeps NaNs out of ulp stats). */
export const ulpDistance = (type: "f32" | "f64", a: bigint, b: bigint): bigint | null => {
  if (isNaNBits(type, a) || isNaNBits(type, b)) return null;
  const d = orderedOf(type, a) - orderedOf(type, b);
  return d < 0n ? -d : d;
};

export const hexOf = (bits: bigint): Hex => `0x${BigInt.asUintN(64, bits).toString(16)}`;
/** @public */
export const bitsOfHex = (hex: string): bigint => BigInt(hex);
