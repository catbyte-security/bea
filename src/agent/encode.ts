// =================================================================================================
// src/agent/encode.ts — WP3-AGENT hex/pointer/bits helpers over GumJS values (S4 §5.3). The pure parts live in
// pure/coreHex.ts and pure/coreScalar.ts (unit-tested); this file adapts NativePointer / UInt64 / Int64 / ArrayBuffer.
// Floats read from xmm registers are captured as bits straight from the 16-byte ArrayBuffer and never round-trip
// through a JS number (exact, NaN payloads included).
// =================================================================================================
import type { Hex, HexBytes, ScalarInput, TypedOut, ValueCell, ValueType } from "../shared/agentProtocol.js";
import { badParam, raise } from "./errors.js";
import { bytesHex, hexOfBigint, hexOfNumber, parseHexText, u64FromLanes } from "./pure/coreHex.js";
import { cellOfBits, scalarBits, typedOutOfBits } from "./pure/coreScalar.js";

/** Canonical lowercase "0x…" of a pointer-like value (two's complement for negative numbers). */
export const hex = (p: NativePointer | UInt64 | Int64 | number | bigint): Hex => {
  if (typeof p === "bigint") return hexOfBigint(p);
  if (typeof p === "number")
    return p >= 0 && Number.isSafeInteger(p) ? hexOfNumber(p) : hexOfBigint(BigInt(Math.trunc(p)));
  if (p instanceof NativePointer) return p.toString() as Hex;
  if (p instanceof Int64) return hexOfBigint(BigInt(p.toString()));
  return hexOfBigint(BigInt(p.toString()));
};

/** NativePointer → bigint (unsigned). */
export const big = (p: NativePointer | UInt64): bigint => BigInt(p.toString());

/** bigint / Hex → NativePointer. */
export const toPtr = (v: bigint | Hex | string): NativePointer => {
  if (typeof v === "bigint") return ptr(`0x${(v & ((1n << 64n) - 1n)).toString(16)}`);
  const parsed = parseHexText(v);
  if (parsed === null) raise(badParam("address", `"${v}" is not a 0x-prefixed hex address`));
  return ptr(`0x${(parsed as bigint).toString(16)}`);
};

/** Bytes of an ArrayBuffer (or a slice) as lowercase hex. @public */
export const hexBytes = (ab: ArrayBuffer, off = 0, len?: number): HexBytes =>
  bytesHex(new Uint8Array(ab), off, len ?? ab.byteLength - off);

/** f32 bits from an xmm ArrayBuffer (lane 0), exact. @public */
export const f32Bits = (ab16: ArrayBuffer): Hex => {
  const lanes = new Uint32Array(ab16, 0, 1);
  return hexOfBigint(BigInt(lanes[0] ?? 0));
};

/** f64 bits from an xmm ArrayBuffer (lanes 0..1), exact. @public */
export const f64Bits = (ab16: ArrayBuffer): Hex => {
  const lanes = new Uint32Array(ab16, 0, 2);
  return hexOfBigint(u64FromLanes(lanes[0] ?? 0, lanes[1] ?? 0));
};

/** Exact bits of a ScalarInput for type `t` (BadParams on bad input). */
export const scalarToBits = (v: ScalarInput, t: ValueType, path = "value"): bigint => {
  const r = scalarBits(v, t);
  if (!r.ok) return raise(badParam(path, r.problem));
  return r.bits;
};

/**
 * ScalarInput → the value a NativeFunction/NativeCallback argument takes for type `t`. Float NaN payloads may be
 * canonicalized on this path (S4 A-9); oracle calls use the exact-bits thunk instead (D-INT-8).
 * @public
 */
export const scalarToNative = (v: ScalarInput, t: ValueType): number | Int64 | UInt64 | NativePointer | boolean => {
  const bits = scalarToBits(v, t);
  const out = typedOutOfBits(t, bits);
  switch (t) {
    case "ptr":
      return toPtr(bits);
    case "i64":
      return int64(String(out.value));
    case "u64":
      return uint64(String(out.value));
    case "bool8":
    case "bool32":
      return out.value === true;
    case "f32":
    case "f64":
      return typeof out.value === "number" ? out.value : Number(out.value);
    default:
      return typeof out.value === "number" ? out.value : 0;
  }
};

/** Exact float output from bits (S4 §5.3 floatOut). @public */
export const floatOut = (t: "f32" | "f64", bits: Hex): TypedOut => {
  const raw = parseHexText(bits);
  return typedOutOfBits(t, raw ?? 0n);
};

/** UInt64/Int64/number/NativePointer bits → ValueCell for a scalar type. @public */
export const cellOf = (t: ValueType, v: NativePointer | UInt64 | Int64 | number): ValueCell => {
  const bits =
    typeof v === "number"
      ? BigInt.asUintN(64, BigInt(Math.trunc(v)))
      : BigInt.asUintN(64, BigInt(v instanceof NativePointer ? v.toString() : v.toString()));
  return cellOfBits(t, bits);
};

/** Read one scalar of type `t` at `p` as raw bits (throws on access violation; callers guard). @public */
export const readBits = (p: NativePointer, t: ValueType): bigint => {
  switch (t) {
    case "i8":
    case "u8":
    case "bool8":
      return BigInt(p.readU8());
    case "i16":
    case "u16":
      return BigInt(p.readU16());
    case "i32":
    case "u32":
    case "bool32":
    case "f32":
      return BigInt(p.readU32());
    default:
      return BigInt(p.readU64().toString());
  }
};
