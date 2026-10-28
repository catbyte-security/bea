// =================================================================================================
// src/agent/pure/codeDisasm.ts — pure helpers of the agent `disassemble` RPC (WP6-INSPECT; S4 §8.4).
// No GumJS globals or types: imported by the agent (frida.Compiler) and by vitest (tests/unit/inspect/agent/).
// The agent decodes every window from a scratch copy (live bytes with BEA's original bytes overlaid), so every
// address Capstone prints is relative to the scratch buffer; these helpers move them back to the real addresses.
// =================================================================================================
import { formatHex, MASK64, type Hex } from "../../shared/hex.js";

/** Longest x86-64 instruction. */
export const MAX_INSN_BYTES = 15;
/** Function mode decodes at most this many instructions (the tool's `function:true` bound, DESIGN §6.2 #12). */
export const FUNCTION_MAX_INSNS = 4096;
/** Zero padding written after the copied bytes so a decode never reads stale scratch memory. */
export const SCRATCH_PAD = 16;
/** ControlFlowGraph blocks returned when `cfg:true` (S4 §8.4 step 5). */
export const CFG_MAX_BLOCKS = 4096;

export type DisasmMode = "count" | "function" | "range";

/**
 * The byte window one call decodes.
 * - `count`: up to count × 15 bytes (the most `count` instructions can occupy), never above `maxBytes`;
 * - `function` / `range`: the requested size, clipped to `maxBytes` (`clipped` → the result is truncated).
 */
export interface DisasmWindow {
  readonly bytes: number;
  readonly maxInsns: number;
  readonly clipped: boolean;
}
export const planWindow = (
  mode: DisasmMode,
  wanted: number,
  limits: { readonly maxBytes: number; readonly maxInsns: number },
): DisasmWindow => {
  const maxBytes = Math.max(1, Math.floor(limits.maxBytes));
  const maxInsns = Math.max(1, Math.floor(limits.maxInsns));
  if (mode === "count") {
    const count = Math.max(1, Math.min(Math.floor(wanted), maxInsns));
    return { bytes: Math.min(count * MAX_INSN_BYTES, maxBytes), maxInsns: count, clipped: false };
  }
  const size = Math.max(1, Math.floor(wanted));
  return { bytes: Math.min(size, maxBytes), maxInsns, clipped: size > maxBytes };
};

/** Page-aligned chunks covering [start, start + length): the readable prefix is found chunk by chunk. */
export const pageChunks = (
  start: bigint,
  length: number,
  pageSize: number,
): { readonly offset: number; readonly length: number }[] => {
  const out: { offset: number; length: number }[] = [];
  const page = BigInt(Math.max(1, pageSize));
  let offset = 0;
  while (offset < length) {
    const at = start + BigInt(offset);
    const toBoundary = Number(page - (at % page));
    const n = Math.min(toBoundary, length - offset);
    out.push({ offset, length: n });
    offset += n;
  }
  return out;
};

/**
 * An immediate operand as Frida reports it: a decimal string on x64 [ext-frida §3.12], a number, an Int64-like
 * object (toString() gives decimal) or a "0x…" string. Null when it is not an integer.
 */
export const immToBigInt = (value: unknown): bigint | null => {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") return Number.isInteger(value) ? BigInt(value) : null;
  const text = typeof value === "string" ? value : value !== null && typeof value === "object" ? String(value) : null;
  if (text === null) return null;
  const trimmed = text.trim();
  if (/^-?\d+$/u.test(trimmed)) return BigInt(trimmed);
  if (/^0x[0-9a-f]+$/iu.test(trimmed)) return BigInt(trimmed);
  return null;
};

/** A scratch-relative address moved to the real code location (64-bit wrap-around). */
export const relocate = (value: bigint, scratchBase: bigint, realBase: bigint): bigint =>
  (value - scratchBase + realBase) & MASK64;

/** RIP-relative memory operand: `disp` is relative to the NEXT instruction [ext-frida §3.12]. */
export const ripRelative = (next: bigint, disp: number): bigint => (next + BigInt(disp)) & MASK64;

/** Capstone groups of a direct relative branch or call (jmp/jcc/call/loop/jrcxz with a rel operand). */
export const isRelativeBranch = (groups: readonly string[]): boolean => groups.includes("branch_relative");

/**
 * Rebuild the operand text of a relative branch decoded in scratch. Capstone prints the target as `0x<hex>`; the
 * scratch spelling is replaced by the real one. When the scratch spelling is absent (unexpected formatting), the
 * operand text becomes the real target alone (S4 §8.4: `${mnemonic} 0x${target}`).
 */
export const rewriteBranchText = (opStr: string, scratchTarget: bigint, realTarget: bigint): string => {
  const scratchText = formatHex(scratchTarget);
  const realText = formatHex(realTarget);
  const at = opStr.toLowerCase().indexOf(scratchText);
  if (at < 0) return realText;
  return `${opStr.slice(0, at)}${realText}${opStr.slice(at + scratchText.length)}`;
};

/** Byte-wise difference mask of the overlay (1 = the original byte differs from the live byte). */
export const overlayMask = (live: Uint8Array, original: Uint8Array): Uint8Array => {
  const n = Math.min(live.length, original.length);
  const mask = new Uint8Array(n);
  for (let i = 0; i < n; i++) mask[i] = live[i] === original[i] ? 0 : 1;
  return mask;
};

/** True when any byte of [offset, offset + size) was replaced by the overlay. */
export const touchesOverlay = (mask: Uint8Array, offset: number, size: number): boolean => {
  const end = Math.min(mask.length, offset + size);
  for (let i = Math.max(0, offset); i < end; i++) if (mask[i] === 1) return true;
  return false;
};

export const anyOverlay = (mask: Uint8Array): boolean => touchesOverlay(mask, 0, mask.length);

/** Canonical hex for a real address computed from a base plus an offset. */
export const hexAt = (base: bigint, offset: number): Hex => formatHex((base + BigInt(offset)) & MASK64);

/**
 * Why decoding ended before the window was consumed (S4 §4 `DisassembleResult.stop`):
 * - an instruction that does not fit in the readable bytes: `access-violation` when the read stopped short of the
 *   window (the next page is unreadable), else `limit` (the window itself ended: byte cap or count window);
 * - the instruction cap reached before the end of a function/range window: `limit`.
 */
export const stopForOverrun = (readable: number, window: number): "access-violation" | "limit" =>
  readable < window ? "access-violation" : "limit";
