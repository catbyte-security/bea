// =================================================================================================
// src/application/watch/values.ts — value views, operands and struct bases of watch hits (S6 §2.3, §4.22, CI-M12;
// WP9-WATCH). Pure functions: no I/O.
// =================================================================================================
import { hexToBytes, type Hex } from "../../domain/hex.js";
import type { WatchMemOperand } from "../../shared/agentProtocol.js";

export const WATCH_VIEWS = ["hex", "i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "f32", "f64"] as const;
export type WatchView = (typeof WATCH_VIEWS)[number];
export type ScalarOut = number | string | null;

const WIDTH: { readonly [V in WatchView]: number } = {
  hex: 1,
  i8: 1,
  u8: 1,
  i16: 2,
  u16: 2,
  i32: 4,
  u32: 4,
  i64: 8,
  u64: 8,
  f32: 4,
  f64: 8,
};

/**
 * Element width poll uses to split its 8-byte change cells: the view width; the hex view uses 4-byte cells when the
 * size allows (a float or int field changes as one element), else bytes.
 */
export const pollElementWidth = (view: WatchView, size: number): number =>
  view === "hex" ? (size % 4 === 0 ? 4 : 1) : WIDTH[view];

/** Shortest decimal that round-trips through f32 (S6 §2.3); non-finite values as text. */
export const f32Out = (x: number): number | string => {
  if (Number.isNaN(x)) return "NaN";
  if (!Number.isFinite(x)) return x > 0 ? "Infinity" : "-Infinity";
  for (let p = 1; p <= 9; p++) {
    const candidate = Number(x.toPrecision(p));
    if (Math.fround(candidate) === x) return candidate;
  }
  return x;
};
const f64Out = (x: number): number | string =>
  Number.isNaN(x) ? "NaN" : Number.isFinite(x) ? x : x > 0 ? "Infinity" : "-Infinity";

/** Little-endian decode of exactly one view element; null when the bytes do not fit the view. */
export const decodeElement = (bytes: Uint8Array, view: WatchView): ScalarOut => {
  if (view === "hex") return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  if (bytes.length !== WIDTH[view]) return null;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  switch (view) {
    case "i8":
      return dv.getInt8(0);
    case "u8":
      return dv.getUint8(0);
    case "i16":
      return dv.getInt16(0, true);
    case "u16":
      return dv.getUint16(0, true);
    case "i32":
      return dv.getInt32(0, true);
    case "u32":
      return dv.getUint32(0, true);
    case "i64":
      return dv.getBigInt64(0, true).toString();
    case "u64":
      return dv.getBigUint64(0, true).toString();
    case "f32":
      return f32Out(dv.getFloat32(0, true));
    case "f64":
      return f64Out(dv.getFloat64(0, true));
  }
};

/** A watch hit's value: the decoded element when the watched size equals the view width, else the bytes as hex. */
export const decodeWatched = (hex: string | null, view: WatchView): ScalarOut => {
  if (hex === null) return null;
  let bytes: Uint8Array;
  try {
    bytes = hexToBytes(hex);
  } catch {
    return null;
  }
  const one = decodeElement(bytes, view);
  return one ?? decodeElement(bytes, "hex");
};

/** Numeric ordering for min/max of a view (64-bit ints compare as BigInt); null for hex or non-finite floats. */
export const numericKey = (value: ScalarOut, view: WatchView): number | bigint | null => {
  if (value === null || view === "hex") return null;
  if (view === "i64" || view === "u64") return typeof value === "string" ? BigInt(value) : null;
  return typeof value === "number" ? value : null;
};

export type InsnConfidence = "exact" | "recovered" | "ambiguous";
/**
 * Agent confidence → tool confidence (S6 §4.22): page-guard and execute hits are exact; a debug-register writer found
 * by sweeping from its .pdata function start is exact; a unique back-scan candidate is recovered; anything else
 * (no candidate, several, Stalker's code cache) is ambiguous.
 */
export const insnConfidence = (agent: string): InsnConfidence =>
  agent === "exact" || agent === "swept" ? "exact" : agent === "heuristic" ? "recovered" : "ambiguous";

export interface OperandOut {
  readonly base: string | null;
  readonly index: string | null;
  readonly scale: number;
  readonly disp: number;
}
export interface StructBase {
  readonly operand: OperandOut | null;
  /** value of the base register at the access; null when unknown, RIP-relative, or clobbered by the instruction */
  readonly struct_base: Hex | null;
  /** the displacement as signed hex ("0x8", "-0x10") */
  readonly disp: string | null;
}

const signedHex = (n: number): string => (n < 0 ? `-0x${(-n).toString(16)}` : `0x${n.toString(16)}`);
const HEX_RE = /^0x[0-9a-f]{1,16}$/u;

/**
 * Struct base from the decoded memory operand (CI-M12). `base_written` from a debug-register trap means the base
 * register was overwritten by the access itself (trap-after context), so the base value is not the struct's.
 */
export const structBaseOf = (mem: WatchMemOperand | null): StructBase => {
  if (mem === null) return { operand: null, struct_base: null, disp: null };
  const operand: OperandOut = { base: mem.base, index: mem.index, scale: mem.scale, disp: mem.disp };
  const usable =
    mem.base !== null &&
    mem.base !== "rip" &&
    !mem.base_written &&
    typeof mem.base_value === "string" &&
    HEX_RE.test(mem.base_value);
  return { operand, struct_base: usable ? (mem.base_value as Hex) : null, disp: signedHex(mem.disp) };
};
