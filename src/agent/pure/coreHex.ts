// =================================================================================================
// src/agent/pure/coreHex.ts — WP3-AGENT pure helpers: hex text, byte strings and exact float bits.
// No GumJS globals or types (DESIGN §9.1 rule 3): importable by vitest (tests/unit/agent/core/) and staged into the
// agent build. Floats always cross the wire as exact bits (S4 §5.3); a JS number is only a convenience view.
// =================================================================================================
import type { Hex, HexBytes } from "../../shared/hex.js";

const MASK64 = (1n << 64n) - 1n;
const HEX_DIGITS = "0123456789abcdef";

/** Canonical "0x…" (lowercase, no leading zeros) of a non-negative safe integer (sizes, RVAs, counters). */
export const hexOfNumber = (n: number): Hex => {
  if (!Number.isSafeInteger(n) || n < 0) throw new RangeError(`hexOfNumber: ${n} is not a non-negative safe integer`);
  return `0x${n.toString(16)}`;
};

/** Canonical "0x…" of a bigint as 64-bit two's complement (negative values wrap). */
export const hexOfBigint = (v: bigint): Hex => `0x${(v & MASK64).toString(16)}`;

/** Canonical "0x…" of a u32 (two's complement for negative int32 inputs). */
export const hexOfU32 = (n: number): Hex => `0x${(n >>> 0).toString(16)}`;

/** Lowercase even-length byte string of `bytes[off, off+len)`. */
export const bytesHex = (bytes: Uint8Array, off = 0, len = bytes.length - off): HexBytes => {
  let out = "";
  const end = Math.min(bytes.length, off + len);
  for (let i = off; i < end; i++) {
    const b = bytes[i] ?? 0;
    out += HEX_DIGITS[b >> 4]! + HEX_DIGITS[b & 15]!;
  }
  return out;
};

/** Inverse of bytesHex; throws RangeError on odd length or non-hex characters. */
export const hexBytesToArray = (hex: string): Uint8Array => {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/u.test(hex)) throw new RangeError("not an even-length hex byte string");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
};

/** Little-endian unsigned integer of `len` (≤ 8) bytes at `off` as a bigint. */
export const readLeBigint = (bytes: Uint8Array, off: number, len: number): bigint => {
  let v = 0n;
  for (let i = len - 1; i >= 0; i--) v = (v << 8n) | BigInt(bytes[off + i] ?? 0);
  return v;
};

/** Little-endian u32 at `off` (0 past the end). */
export const readLeU32 = (bytes: Uint8Array, off: number): number =>
  ((bytes[off] ?? 0) | ((bytes[off + 1] ?? 0) << 8) | ((bytes[off + 2] ?? 0) << 16) | ((bytes[off + 3] ?? 0) << 24)) >>>
  0;

/** Little-endian u16 at `off`. */
export const readLeU16 = (bytes: Uint8Array, off: number): number => (bytes[off] ?? 0) | ((bytes[off + 1] ?? 0) << 8);

/** A 64-bit value given as two u32 lanes (lo, hi). */
export const u64FromLanes = (lo: number, hi: number): bigint => (BigInt(hi >>> 0) << 32n) | BigInt(lo >>> 0);

/**
 * A 128-bit xmm register (16 little-endian bytes) as a fixed 32-digit "0x…" (high qword first), the CrashReport.xmm
 * form. Never canonicalized: the width is part of the meaning.
 */
export const xmmHex = (bytes16: Uint8Array): Hex => {
  let out = "";
  for (let i = 15; i >= 0; i--) {
    const b = bytes16[i] ?? 0;
    out += HEX_DIGITS[b >> 4]! + HEX_DIGITS[b & 15]!;
  }
  return `0x${out}`;
};

const scratch = new DataView(new ArrayBuffer(8));

/** f32 value of raw bits (exact; NaN payloads are not preserved by the JS view, the bits are). */
export const f32FromBits = (bits: number): number => {
  scratch.setUint32(0, bits >>> 0, true);
  return scratch.getFloat32(0, true);
};

/** f64 value of raw bits. */
export const f64FromBits = (bits: bigint): number => {
  scratch.setBigUint64(0, bits & MASK64, true);
  return scratch.getFloat64(0, true);
};

/** Raw f32 bits of a JS number (round to nearest-even, like Math.fround). */
export const f32Bits = (v: number): number => {
  scratch.setFloat32(0, v, true);
  return scratch.getUint32(0, true);
};

/** Raw f64 bits of a JS number. */
export const f64Bits = (v: number): bigint => {
  scratch.setFloat64(0, v, true);
  return scratch.getBigUint64(0, true);
};

/** The JSON-safe view of a float (TypedOut.value): a finite number, or the strings NaN / Infinity / -Infinity. */
export type FloatView = number | "NaN" | "Infinity" | "-Infinity";

/** Canonical bits of the float specials (quiet NaN with an empty payload). */
export const FLOAT_SPECIAL_BITS = {
  f32: { Infinity: 0x7f800000n, "-Infinity": 0xff800000n, NaN: 0x7fc00000n },
  f64: { Infinity: 0x7ff0000000000000n, "-Infinity": 0xfff0000000000000n, NaN: 0x7ff8000000000000n },
} as const;

/**
 * The view of raw float bits, classified FROM THE BITS: in Frida 17.23.2's QJS runtime on Windows there are no
 * infinities (±Infinity, 1/0 and float reads of infinity bits are the canonical NaN; Number.POSITIVE_INFINITY is
 * 1e300) and `NaN === x` holds for every x (WP10 probes), so a JS-number comparison cannot tell the specials apart.
 */
export const floatViewOfBits = (t: "f32" | "f64", bits: bigint): FloatView => {
  const [expBits, mantBits] = t === "f32" ? [8n, 23n] : [11n, 52n];
  const width = expBits + mantBits + 1n;
  const raw = bits & ((1n << width) - 1n);
  const expMax = (1n << expBits) - 1n;
  if (((raw >> mantBits) & expMax) === expMax) {
    if ((raw & ((1n << mantBits) - 1n)) !== 0n) return "NaN";
    return raw >> (width - 1n) === 1n ? "-Infinity" : "Infinity";
  }
  return t === "f32" ? f32FromBits(Number(raw)) : f64FromBits(raw);
};

/** Parse "0x…" (any case, 1..16 digits) to a bigint, or null. */
export const parseHexText = (text: string): bigint | null =>
  /^0[xX][0-9a-fA-F]{1,16}$/u.test(text) ? BigInt(`0x${text.slice(2)}`) : null;
