// =================================================================================================
// src/shared/hex.ts — 64-bit values on every wire (host <-> agent, host <-> bridge, tool outputs).
// Pure TypeScript: no node:*, no zod, no GumJS globals. Staged into the agent build (QJS has BigInt).
// =================================================================================================

/** Canonical address / 64-bit bits text: lowercase, "0x" prefix, no leading zeros ("0x0" for zero). */
export type Hex = `0x${string}`;
/** Even-length lowercase hex byte string without prefix or spaces ("" for zero bytes). */
export type HexBytes = string;

export const HEX_CANONICAL_RE = /^0x(?:0|[1-9a-f][0-9a-f]{0,15})$/u;
/** Inputs: any case, leading zeros allowed, 1..16 digits. */
export const HEX_INPUT_RE = /^0[xX][0-9a-fA-F]{1,16}$/u;
export const HEX_BYTES_RE = /^(?:[0-9a-f]{2})*$/u;

export const MASK64 = (1n << 64n) - 1n;

/** Format a non-negative bigint/number (or a negative one as two's complement 64-bit) canonically. */
export const formatHex = (value: bigint | number): Hex => {
  const v = BigInt(value) & MASK64;
  return `0x${v.toString(16)}`;
};

/** Parse a hex input ("0x…", any case). Throws RangeError on malformed input (callers validate first). */
export const parseHex = (text: string): bigint => {
  if (!HEX_INPUT_RE.test(text)) throw new RangeError("not a 0x-prefixed hex value of 1..16 digits");
  return BigInt(`0x${text.slice(2)}`);
};

/** @public */
export const isCanonicalHex = (text: string): text is Hex => HEX_CANONICAL_RE.test(text);

/** Normalize any accepted hex input to canonical form. */
export const canonicalHex = (text: string): Hex => formatHex(parseHex(text));

export const bytesToHex = (bytes: Uint8Array): HexBytes => {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
};

export const hexToBytes = (hex: HexBytes): Uint8Array => {
  if (!HEX_BYTES_RE.test(hex)) throw new RangeError("not an even-length lowercase hex byte string");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
};
