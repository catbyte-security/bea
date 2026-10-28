// =================================================================================================
// src/agent/pure/coreDisasm.ts — WP3-AGENT pure helpers for the overlay-aware decoder (S4 §8.4): fix-ups of an
// instruction decoded from a scratch copy, and the access-instruction recovery used by debug-register watches
// (sweep from the .pdata start, else a 1..15-byte back-scan). The decoder itself is injected (Instruction.parse in
// the agent, a fake in unit tests).
// =================================================================================================

/** The fields of a decoded instruction the fix-ups need (Capstone via GumJS Instruction). */
export interface DecodedInsn {
  readonly size: number;
  readonly mnemonic: string;
  readonly opStr: string;
  readonly groups: readonly string[];
  /** immediate operand values in operand order (GumJS gives decimal strings; callers convert) */
  readonly imms: readonly bigint[];
}

const BRANCH_GROUPS: ReadonlySet<string> = new Set(["call", "jump", "branch_relative"]);

/** A relative branch/call whose target Capstone computed from the decode address. */
export const isRelativeBranch = (insn: DecodedInsn): boolean =>
  insn.groups.some((g) => BRANCH_GROUPS.has(g)) && insn.imms.length > 0 && /^0x[0-9a-f]+$/iu.test(insn.opStr.trim());

/**
 * Relocate a branch decoded at `scratchAddr` back to `realAddr`: target = imm − scratch + real, op_str rebuilt.
 * Non-branches keep their text (RIP-relative displacements are relative to `next`, already correct).
 */
export const relocateDecoded = (
  insn: DecodedInsn,
  scratchAddr: bigint,
  realAddr: bigint,
): { readonly opStr: string; readonly branchTarget: bigint | null } => {
  if (!isRelativeBranch(insn)) return { opStr: insn.opStr, branchTarget: null };
  const target = (insn.imms[0]! - scratchAddr + realAddr) & ((1n << 64n) - 1n);
  return { opStr: `0x${target.toString(16)}`, branchTarget: target };
};

/** Branch target of an instruction decoded in place (no relocation needed). */
export const branchTargetInPlace = (insn: DecodedInsn): bigint | null =>
  isRelativeBranch(insn) ? insn.imms[0]! & ((1n << 64n) - 1n) : null;

export type AccessConfidence = "exact" | "swept" | "heuristic" | "unknown";

export interface AccessInsn {
  readonly address: bigint | null;
  readonly size: number | null;
  readonly conf: AccessConfidence;
}

/** Decoder for the recovery algorithms: size of the instruction at `addr`, or null when it cannot be decoded. */
export type SizeDecoder = (addr: bigint) => number | null;

/** Sweep [start, pcAfter): the instruction whose next == pcAfter (≤ cap instructions). */
export const sweepToPc = (decode: SizeDecoder, start: bigint, pcAfter: bigint, cap = 4096): bigint | null => {
  let p = start;
  for (let i = 0; i < cap && p < pcAfter; i++) {
    const size = decode(p);
    if (size === null || size <= 0) return null;
    if (p + BigInt(size) === pcAfter) return p;
    p += BigInt(size);
  }
  return null;
};

/** Back-scan k = 1..15: candidates decoded at pcAfter − k with size k; exactly one → heuristic, else unknown. */
export const backScan = (decode: SizeDecoder, pcAfter: bigint): AccessInsn => {
  const found: bigint[] = [];
  for (let k = 1; k <= 15; k++) {
    const at = pcAfter - BigInt(k);
    if (decode(at) === k) found.push(at);
  }
  return found.length === 1
    ? { address: found[0]!, size: Number(pcAfter - found[0]!), conf: "heuristic" }
    : { address: null, size: null, conf: "unknown" };
};

/** findAccessInsn (S4 §8.4): sweep from the function start when known, else back-scan. */
export const recoverAccessInsn = (decode: SizeDecoder, pcAfter: bigint, functionStart: bigint | null): AccessInsn => {
  if (functionStart !== null && functionStart < pcAfter) {
    const at = sweepToPc(decode, functionStart, pcAfter);
    if (at !== null) return { address: at, size: Number(pcAfter - at), conf: "swept" };
  }
  return backScan(decode, pcAfter);
};

/** Overlay original bytes onto a copy of live bytes: `originals` are [address, bytes] pairs (any order). */
export const overlayBytes = (
  live: Uint8Array,
  base: bigint,
  originals: readonly { readonly address: bigint; readonly bytes: Uint8Array }[],
): { readonly bytes: Uint8Array; readonly changed: boolean } => {
  const out = live.slice();
  let changed = false;
  const end = base + BigInt(live.length);
  for (const o of originals) {
    for (let i = 0; i < o.bytes.length; i++) {
      const at = o.address + BigInt(i);
      if (at < base || at >= end) continue;
      const idx = Number(at - base);
      if (out[idx] !== o.bytes[i]) {
        out[idx] = o.bytes[i]!;
        changed = true;
      }
    }
  }
  return { bytes: out, changed };
};
