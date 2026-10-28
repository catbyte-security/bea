// =================================================================================================
// src/agent/pure/scanValue.ts — WP10-SCAN: comparand parsing and value decoding for scans (S4 §9.2 "Value
// encoding", S6 §2.3). Pure TypeScript (QJS has BigInt): no GumJS globals.
// =================================================================================================
import type { ScalarInput, ScanValueType, TypedOut } from "../../shared/agentProtocol.js";
import { bytesToHex, formatHex, type Hex } from "../../shared/hex.js";
import { MAX_ELEM_BYTES, NUMERIC_ELEM, type Bits64, type NumericScanType } from "./scanTypes.js";

export type Parsed<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly problem: string };
const bad = (problem: string): Parsed<never> => ({ ok: false, problem });
const good = <T>(value: T): Parsed<T> => ({ ok: true, value });

/** A numeric comparand: element bytes (little-endian), the 64-bit operand bits, and how it was given. */
export interface NumericOperand {
  readonly bytes: Uint8Array;
  readonly bits: Bits64;
  /** a float given as raw bits ("0x…" or {bits}): compared bit for bit */
  readonly exactBits: boolean;
  /** floats: ±0 (IEEE == matches both zeros, so the engine never uses a byte pattern for it) */
  readonly zero: boolean;
  readonly nan: boolean;
}

const TWO64 = 1n << 64n;
const INT_RANGE: Readonly<Record<Exclude<NumericScanType, "f32" | "f64">, readonly [bigint, bigint]>> = {
  i8: [-128n, 127n],
  u8: [0n, 255n],
  i16: [-32_768n, 32_767n],
  u16: [0n, 65_535n],
  i32: [-2_147_483_648n, 2_147_483_647n],
  u32: [0n, 4_294_967_295n],
  i64: [-(1n << 63n), (1n << 63n) - 1n],
  u64: [0n, TWO64 - 1n],
  ptr: [0n, TWO64 - 1n],
};
const HEX_RE = /^0[xX][0-9a-fA-F]{1,16}$/u;
const DEC_RE = /^-?\d{1,20}$/u;

const bitsOf = (v: bigint): Bits64 => {
  const u = ((v % TWO64) + TWO64) % TWO64;
  return { lo: Number(u & 0xffff_ffffn), hi: Number(u >> 32n) };
};
const leBytes = (v: bigint, elem: number): Uint8Array => {
  const out = new Uint8Array(elem);
  let u = ((v % TWO64) + TWO64) % TWO64;
  for (let i = 0; i < elem; i++) {
    out[i] = Number(u & 0xffn);
    u >>= 8n;
  }
  return out;
};

/** "0x…" for an integer type = raw bits of that width (two's complement for signed types). */
const rawIntBits = (vt: Exclude<NumericScanType, "f32" | "f64">, text: string): Parsed<bigint> => {
  const raw = BigInt(text.toLowerCase());
  const width = BigInt(NUMERIC_ELEM[vt] * 8);
  if (raw >= 1n << width) return bad(`hex value ${text} does not fit ${vt}`);
  const signed = vt.startsWith("i");
  return good(signed && raw >= 1n << (width - 1n) ? raw - (1n << width) : raw);
};

const parseInt64 = (vt: Exclude<NumericScanType, "f32" | "f64">, input: ScalarInput): Parsed<NumericOperand> => {
  let v: bigint;
  if (typeof input === "boolean") v = input ? 1n : 0n;
  else if (typeof input === "number") {
    if (!Number.isSafeInteger(input)) return bad(`${vt} value must be an integer within ±(2^53-1); use a string`);
    v = BigInt(input);
  } else if (typeof input === "string") {
    if (HEX_RE.test(input)) {
      const raw = rawIntBits(vt, input);
      if (!raw.ok) return raw;
      v = raw.value;
    } else if (DEC_RE.test(input)) v = BigInt(input);
    else return bad(`${vt} value must be a number, a decimal string or a 0x… hex string`);
  } else {
    if (!HEX_RE.test(input.bits)) return bad("bits must be a 0x… hex string of 1..16 digits");
    const raw = rawIntBits(vt, input.bits);
    if (!raw.ok) return raw;
    v = raw.value;
  }
  const [lo, hi] = INT_RANGE[vt];
  if (v < lo || v > hi) return bad(`${vt} value ${v.toString()} is out of range ${lo.toString()}..${hi.toString()}`);
  return good({ bytes: leBytes(v, NUMERIC_ELEM[vt]), bits: bitsOf(v), exactBits: false, zero: v === 0n, nan: false });
};

// ---------------------------------------------------------------- IEEE specials from bits

/**
 * IEEE class of a float's raw bits. Frida 17.23.2's QJS on Windows has no infinities: every ±Infinity (the global,
 * 1/0, getFloat32 of 0x7f800000) is the canonical NaN, and NaN === x is true for every x (probed in the target during
 * WP10 acceptance; V8 and Node are correct). Agent code therefore classifies float specials from their bits and
 * compares JS numbers only once both sides are known finite.
 */
export type FloatClass = "finite" | "nan" | "+inf" | "-inf";
export const floatClass = (is64: boolean, bits: Bits64): FloatClass => {
  const lo = bits.lo >>> 0;
  const hi = bits.hi >>> 0;
  const top = is64 ? hi : lo;
  const special = is64 ? ((hi >>> 20) & 0x7ff) === 0x7ff : ((lo >>> 23) & 0xff) === 0xff;
  if (!special) return "finite";
  const mantissa = is64 ? (hi & 0xf_ffff) !== 0 || lo !== 0 : (lo & 0x7f_ffff) !== 0;
  return mantissa ? "nan" : top >>> 31 === 1 ? "-inf" : "+inf";
};

/** A float element read from little-endian bytes: its class and, when finite, its value. */
export interface FloatRead {
  readonly cls: FloatClass;
  readonly x: number;
}
export const readFloat = (is64: boolean, bytes: Uint8Array): FloatRead => {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const bits = { lo: view.getUint32(0, true), hi: is64 ? view.getUint32(4, true) : 0 };
  const cls = floatClass(is64, bits);
  return { cls, x: cls !== "finite" ? 0 : is64 ? view.getFloat64(0, true) : view.getFloat32(0, true) };
};

/** IEEE order of two floats: -1, 0 or 1, null when either is NaN (unordered; -0 equals +0). */
export const floatOrder = (a: FloatRead, b: FloatRead): -1 | 0 | 1 | null => {
  if (a.cls === "nan" || b.cls === "nan") return null;
  const rank = (f: FloatRead): number => (f.cls === "-inf" ? -1 : f.cls === "+inf" ? 1 : 0);
  const ra = rank(a);
  const rb = rank(b);
  if (ra !== rb) return ra < rb ? -1 : 1;
  if (ra !== 0) return 0;
  return a.x < b.x ? -1 : a.x > b.x ? 1 : 0;
};

/** The words' canonical bits (never JS Infinity, see floatClass). */
const FLOAT_WORD_BITS: Readonly<Record<"f32" | "f64", Readonly<Record<string, bigint>>>> = {
  f32: { NaN: 0x7fc0_0000n, Infinity: 0x7f80_0000n, "-Infinity": 0xff80_0000n },
  f64: { NaN: 0x7ff8_0000_0000_0000n, Infinity: 0x7ff0_0000_0000_0000n, "-Infinity": 0xfff0_0000_0000_0000n },
};

const floatOperand = (vt: "f32" | "f64", bytes: Uint8Array, bits: Bits64, exactBits: boolean): NumericOperand => {
  const f = readFloat(vt === "f64", bytes);
  return { bytes, bits, exactBits, zero: f.cls === "finite" && f.x === 0, nan: f.cls === "nan" };
};
const floatFromBits = (vt: "f32" | "f64", raw: bigint, exactBits = true): NumericOperand =>
  floatOperand(vt, leBytes(raw, NUMERIC_ELEM[vt]), bitsOf(raw), exactBits);
const floatFromNumber = (vt: "f32" | "f64", x: number): NumericOperand => {
  const bytes = new Uint8Array(NUMERIC_ELEM[vt]);
  const view = new DataView(bytes.buffer);
  if (vt === "f32") view.setFloat32(0, x, true);
  else view.setFloat64(0, x, true);
  const lo = view.getUint32(0, true);
  const hi = vt === "f64" ? view.getUint32(4, true) : 0;
  return floatOperand(vt, bytes, { lo, hi }, false);
};

const parseFloatOperand = (vt: "f32" | "f64", input: ScalarInput): Parsed<NumericOperand> => {
  const digits = vt === "f32" ? 8 : 16;
  const fromBits = (text: string): Parsed<NumericOperand> =>
    HEX_RE.test(text) && text.length - 2 <= digits
      ? good(floatFromBits(vt, BigInt(text.toLowerCase())))
      : bad(`${vt} bits must be 0x followed by at most ${String(digits)} hex digits`);
  if (typeof input === "boolean")
    return bad(`${vt} value must be a number, "NaN", "Infinity", "-Infinity" or 0x… bits`);
  if (typeof input === "object") return fromBits(input.bits);
  if (typeof input === "number") return good(floatFromNumber(vt, input));
  if (/^0[xX]/u.test(input)) return fromBits(input);
  const word = FLOAT_WORD_BITS[vt][input];
  // a word compares as a value (IEEE ==: "NaN" never matches), not bit for bit
  if (word !== undefined) return good(floatFromBits(vt, word, false));
  const x = Number(input);
  return input.trim() !== "" && Number.isFinite(x)
    ? good(floatFromNumber(vt, x))
    : bad(`${vt} value must be a number, "NaN", "Infinity", "-Infinity" or 0x… bits`);
};

/** Parse a comparand for a numeric scan type (S6 §2.3 inputs: "0x…" = raw bits of the declared type). */
export const parseNumericOperand = (vt: NumericScanType, input: ScalarInput): Parsed<NumericOperand> =>
  vt === "f32" || vt === "f64" ? parseFloatOperand(vt, input) : parseInt64(vt, input);

// ---------------------------------------------------------------- text and byte strings

/** UTF-8 without TextEncoder (not every GumJS runtime has it). Lone surrogates become U+FFFD. */
export const utf8Encode = (text: string): Uint8Array => {
  const out: number[] = [];
  for (const ch of text) {
    let cp = ch.codePointAt(0) ?? 0xfffd;
    if (cp >= 0xd800 && cp <= 0xdfff) cp = 0xfffd;
    if (cp < 0x80) out.push(cp);
    else if (cp < 0x800) out.push(0xc0 | (cp >> 6), 0x80 | (cp & 0x3f));
    else if (cp < 0x10000) out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
    else out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
  }
  return Uint8Array.from(out);
};

/** Lenient UTF-8 decode: malformed sequences become U+FFFD. */
export const utf8Decode = (bytes: Uint8Array): string => {
  let out = "";
  let i = 0;
  while (i < bytes.length) {
    const b = bytes[i] ?? 0;
    if (b < 0x80) {
      out += String.fromCharCode(b);
      i += 1;
      continue;
    }
    const need = b >= 0xf0 && b < 0xf8 ? 3 : b >= 0xe0 && b < 0xf0 ? 2 : b >= 0xc0 && b < 0xe0 ? 1 : -1;
    if (need < 0 || i + need >= bytes.length) {
      out += "�";
      i += 1;
      continue;
    }
    let cp = b & (0x3f >> need);
    let valid = true;
    for (let k = 1; k <= need; k++) {
      const c = bytes[i + k] ?? 0;
      if ((c & 0xc0) !== 0x80) valid = false;
      cp = (cp << 6) | (c & 0x3f);
    }
    if (!valid) {
      out += "�";
      i += 1;
      continue;
    }
    out += String.fromCodePoint(cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff) ? 0xfffd : cp);
    i += need + 1;
  }
  return out;
};

export const utf16Encode = (text: string): Uint8Array => {
  const out = new Uint8Array(text.length * 2);
  for (let i = 0; i < text.length; i++) {
    const u = text.charCodeAt(i);
    out[2 * i] = u & 0xff;
    out[2 * i + 1] = u >> 8;
  }
  return out;
};
export const utf16Decode = (bytes: Uint8Array): string => {
  let out = "";
  for (let i = 0; i + 1 < bytes.length; i += 2)
    out += String.fromCharCode((bytes[i] ?? 0) | ((bytes[i + 1] ?? 0) << 8));
  return out;
};

/** Exact byte pattern for Memory.scanSync ("de ad be ef"). */
export const patternOf = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join(" ");

export interface ParsedPattern {
  readonly pattern: string;
  /** match length in bytes */
  readonly elem: number;
  /** no wildcard and no mask: the match bytes are known without reading memory */
  readonly exact: Uint8Array | null;
}

const PATTERN_TOKEN = /^[0-9a-fA-F?]{2}$/u;
const MASK_TOKEN = /^[0-9a-fA-F]{2}$/u;
/**
 * Frida match patterns (VERIFIED forms, ext-frida §3.4): exact "48 8b", byte wildcard "??", nibble "4?", and the
 * r2-style mask "40 45 : f0 ff". "/regex/" is refused: its match length varies, so no element size exists (S4 §9.2).
 */
export const parsePattern = (text: string): Parsed<ParsedPattern> => {
  const trimmed = text.trim();
  if (trimmed.startsWith("/")) return bad("regex patterns are not supported by scans (their match length varies)");
  const [valuePart = "", maskPart, extra] = trimmed.split(":");
  if (extra !== undefined) return bad("invalid match pattern: more than one ':' mask separator");
  const tokens = valuePart
    .trim()
    .split(/\s+/u)
    .filter((t) => t !== "");
  if (tokens.length === 0) return bad("invalid match pattern: empty");
  if (tokens.length > MAX_ELEM_BYTES) return bad(`invalid match pattern: longer than ${String(MAX_ELEM_BYTES)} bytes`);
  if (!tokens.every((t) => PATTERN_TOKEN.test(t)))
    return bad('invalid match pattern: use hex byte tokens, "??" or nibble wildcards such as "4?"');
  if (tokens.every((t) => t === "??")) return bad("invalid match pattern: it needs at least one non-wildcard byte");
  let masked = false;
  if (maskPart !== undefined) {
    const mask = maskPart
      .trim()
      .split(/\s+/u)
      .filter((t) => t !== "");
    if (mask.length !== tokens.length || !mask.every((t) => MASK_TOKEN.test(t)))
      return bad("invalid match pattern: the mask needs one hex byte per pattern byte");
    masked = true;
  }
  const wild = masked || tokens.some((t) => t.includes("?"));
  const exact = wild ? null : Uint8Array.from(tokens.map((t) => Number.parseInt(t, 16)));
  const pattern = masked ? `${tokens.join(" ")} : ${(maskPart ?? "").trim()}` : tokens.join(" ").toLowerCase();
  return good({ pattern, elem: tokens.length, exact });
};

// ---------------------------------------------------------------- outputs (S6 §2.3)

/** Shortest decimal that round-trips through f32 (S6 §2.3: 14.905, not 14.904999732971191). */
export const shortestF32 = (x: number): number => {
  for (let p = 1; p <= 9; p++) {
    const candidate = Number(x.toPrecision(p));
    if (Math.fround(candidate) === x) return candidate;
  }
  return x;
};

/** S6 §2.3 float cell: the number, or "NaN" / "Infinity" / "-Infinity" decided from the bits (see floatClass). */
const floatValue = (is64: boolean, bytes: Uint8Array): number | "NaN" | "Infinity" | "-Infinity" => {
  const f = readFloat(is64, bytes);
  if (f.cls === "nan") return "NaN";
  if (f.cls === "+inf") return "Infinity";
  if (f.cls === "-inf") return "-Infinity";
  return is64 ? f.x : shortestF32(f.x);
};

const u64Of = (bytes: Uint8Array): bigint => {
  let v = 0n;
  for (let i = Math.min(bytes.length, 8) - 1; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i] ?? 0);
  return v;
};

/** Typed output of one stored or current element (floats always carry exact bits). */
export const decodeValue = (vt: ScanValueType, bytes: Uint8Array): TypedOut => {
  if (vt === "bytes") return { type: "bytes", value: null, hex: bytesToHex(bytes) };
  if (vt === "utf8") return { type: "utf8", value: utf8Decode(bytes), hex: bytesToHex(bytes) };
  if (vt === "utf16") return { type: "utf16", value: utf16Decode(bytes), hex: bytesToHex(bytes) };
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  switch (vt) {
    case "i8":
      return { type: vt, value: view.getInt8(0) };
    case "u8":
      return { type: vt, value: view.getUint8(0) };
    case "i16":
      return { type: vt, value: view.getInt16(0, true) };
    case "u16":
      return { type: vt, value: view.getUint16(0, true) };
    case "i32":
      return { type: vt, value: view.getInt32(0, true) };
    case "u32":
      return { type: vt, value: view.getUint32(0, true) };
    case "f32":
      return { type: vt, value: floatValue(false, bytes), bits: formatHex(u64Of(bytes)) };
    case "f64":
      return { type: vt, value: floatValue(true, bytes), bits: formatHex(u64Of(bytes)) };
    case "ptr":
      return { type: vt, value: formatHex(u64Of(bytes)) };
    case "u64":
      return { type: vt, value: u64Of(bytes).toString(), bits: formatHex(u64Of(bytes)) };
    case "i64": {
      const u = u64Of(bytes);
      return { type: vt, value: (u >= 1n << 63n ? u - TWO64 : u).toString(), bits: formatHex(u) };
    }
  }
};

/** Canonical hex of a JS-number address (user-mode VAs are < 2^53). */
export const hexAddr = (va: number): Hex => `0x${va.toString(16)}`;
