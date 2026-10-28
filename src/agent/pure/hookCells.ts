// =================================================================================================
// src/agent/pure/hookCells.ts — WP7-HOOK pure value encoding for hook rows (S4 §4.1 ValueCell, §5.3 float rules).
// Raw register / stack / memory bytes become ValueCells without ever passing a float through a JS number, so float
// captures stay bit-exact (NaN payloads included). No GumJS globals; unit-tested from tests/unit/instrument/.
// =================================================================================================
import type { Hex, ValueCell, ValueType } from "../../shared/agentProtocol.js";
import { TYPE_BYTES } from "./hookPlan.js";

const HEX = "0123456789abcdef";

/** Minimal-digit lowercase hex of an unsigned 64-bit value given as little-endian bytes. */
export function hexLE(bytes: Uint8Array, offset: number, length: number, pad = false): Hex {
  let s = "";
  for (let i = offset + length - 1; i >= offset; i--) {
    const b = bytes[i] ?? 0;
    s += (HEX[b >> 4] ?? "0") + (HEX[b & 15] ?? "0");
  }
  if (!pad) s = s.replace(/^0+(?=.)/u, "");
  return `0x${s}`;
}

/** Plain hex of a byte run ("HexBytes": even length, no prefix). */
export function hexBytes(bytes: Uint8Array, offset = 0, length = bytes.length - offset): string {
  let s = "";
  for (let i = offset; i < offset + length; i++) {
    const b = bytes[i] ?? 0;
    s += (HEX[b >> 4] ?? "0") + (HEX[b & 15] ?? "0");
  }
  return s;
}

/** "0x…" (≤ 16 digits) → 8 little-endian bytes (two's complement already applied by the producer). */
export function bytesOfHex64(hex: string): Uint8Array {
  const digits = hex.replace(/^0x/iu, "").padStart(16, "0").slice(-16);
  const out = new Uint8Array(8);
  for (let i = 0; i < 8; i++) out[7 - i] = Number.parseInt(digits.slice(2 * i, 2 * i + 2), 16) || 0;
  return out;
}

/**
 * One scalar cell from little-endian bytes at `offset` (S4 ValueCell): ≤ 32-bit ints and bools as numbers, 64-bit
 * ints and pointers as Hex bits, f32 as 8-digit bits, f64 as 16-digit bits. Text and bytes types are not scalar.
 */
export function scalarCell(type: ValueType, b: Uint8Array, offset = 0): ValueCell {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const need = TYPE_BYTES[type];
  if (need === undefined) return { e: "unsupported" };
  if (offset + need > b.byteLength) return { e: "unsupported" };
  switch (type) {
    case "i8":
      return dv.getInt8(offset);
    case "u8":
      return dv.getUint8(offset);
    case "bool8":
      return dv.getUint8(offset) !== 0 ? 1 : 0;
    case "i16":
      return dv.getInt16(offset, true);
    case "u16":
      return dv.getUint16(offset, true);
    case "i32":
      return dv.getInt32(offset, true);
    case "u32":
      return dv.getUint32(offset, true);
    case "bool32":
      return dv.getUint32(offset, true) !== 0 ? 1 : 0;
    case "f32":
      return hexLE(b, offset, 4, true);
    case "f64":
      return hexLE(b, offset, 8, true);
    default:
      return hexLE(b, offset, 8); // i64 / u64 / ptr
  }
}

/** `count` consecutive elements (count 1 = a single cell). */
export function arrayCell(type: ValueType, b: Uint8Array, count: number): ValueCell {
  const size = TYPE_BYTES[type] ?? 0;
  if (count <= 1) return scalarCell(type, b, 0);
  const out: ValueCell[] = [];
  for (let i = 0; i < count; i++) out.push(scalarCell(type, b, i * size));
  return out;
}

/** Cell of a 64-bit register value (pointer-sized GPR or integer slot) viewed as `type`. */
export const cellOfWord = (type: ValueType, hex: string): ValueCell => scalarCell(type, bytesOfHex64(hex), 0);

/** Text decoding with a character cap; stops at the first NUL. Invalid UTF-8 bytes become U+FFFD. */
export function decodeText(
  bytes: Uint8Array,
  encoding: "utf8" | "utf16" | "ansi",
  maxChars: number,
): { readonly s: string; readonly trunc: boolean } {
  let out = "";
  let chars = 0;
  if (encoding === "utf16") {
    for (let i = 0; i + 1 < bytes.length; i += 2) {
      const u = (bytes[i] ?? 0) | ((bytes[i + 1] ?? 0) << 8);
      if (u === 0) return { s: out, trunc: false };
      if (chars >= maxChars) return { s: out, trunc: true };
      out += String.fromCharCode(u);
      chars++;
    }
    return { s: out, trunc: bytes.length >= 2 * maxChars };
  }
  if (encoding === "ansi") {
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i] ?? 0;
      if (b === 0) return { s: out, trunc: false };
      if (chars >= maxChars) return { s: out, trunc: true };
      out += String.fromCharCode(b);
      chars++;
    }
    return { s: out, trunc: bytes.length >= maxChars };
  }
  let i = 0;
  while (i < bytes.length) {
    const b0 = bytes[i] ?? 0;
    if (b0 === 0) return { s: out, trunc: false };
    if (chars >= maxChars) return { s: out, trunc: true };
    let cp = 0xfffd;
    let len = 1;
    const cont = (k: number): number => {
      const c = bytes[i + k];
      return c !== undefined && (c & 0xc0) === 0x80 ? c & 0x3f : -1;
    };
    if (b0 < 0x80) cp = b0;
    else if (b0 >= 0xc2 && b0 < 0xe0 && cont(1) >= 0) {
      cp = ((b0 & 0x1f) << 6) | cont(1);
      len = 2;
    } else if (b0 >= 0xe0 && b0 < 0xf0 && cont(1) >= 0 && cont(2) >= 0) {
      cp = ((b0 & 0x0f) << 12) | (cont(1) << 6) | cont(2);
      len = 3;
    } else if (b0 >= 0xf0 && b0 < 0xf5 && cont(1) >= 0 && cont(2) >= 0 && cont(3) >= 0) {
      cp = ((b0 & 0x07) << 18) | (cont(1) << 12) | (cont(2) << 6) | cont(3);
      len = 4;
    }
    out += String.fromCodePoint(cp);
    chars++;
    i += len;
  }
  return { s: out, trunc: bytes.length >= maxChars };
}

/** Bytes to read for a text capture of `maxChars` characters (UTF-8 can need up to 4 bytes per character). */
export const textReadBytes = (encoding: "utf8" | "utf16" | "ansi", maxChars: number): number =>
  encoding === "utf16" ? 2 * maxChars + 2 : encoding === "ansi" ? maxChars + 1 : 4 * maxChars + 1;

/** Backtrace frame text (S4 FrameRef): "module+0xrva" inside a module, else the bare VA. */
export const frameRefText = (va: bigint, mod: { readonly name: string; readonly base: bigint } | null): string =>
  mod === null ? `0x${va.toString(16)}` : `${mod.name}+0x${(va - mod.base).toString(16)}`;

/** Rough JSON size of a row (flow-control estimate, S4 §6.2: 12 per number, 2+len per string, 20 per Hex). */
export function estimateBytes(value: unknown): number {
  if (value === null || value === undefined) return 4;
  if (typeof value === "number" || typeof value === "boolean") return 12;
  if (typeof value === "string") return 2 + value.length;
  if (Array.isArray(value)) {
    let n = 2;
    for (const v of value) n += estimateBytes(v) + 1;
    return n;
  }
  if (typeof value === "object") {
    let n = 2;
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) n += k.length + 3 + estimateBytes(v);
    return n;
  }
  return 4;
}
