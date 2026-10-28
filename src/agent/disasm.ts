// =================================================================================================
// src/agent/disasm.ts — WP3-AGENT disassembly that tells the truth (S4 §8.4). Every decode copies ≤ 16 bytes through
// the guard-aware reader into a scratch buffer, overlays BEA's original bytes when the range is patched
// (Instruction.parse at a hooked address shows the hook's jmp [ext-frida §3.6]), decodes there and relocates relative
// branch targets back to the real address (RIP-relative displacements are relative to `next`, already correct).
// findAccessInsn(pcAfter) recovers the instruction a debug-register data watch trapped after (trap-after semantics):
// sweep from the .pdata start (`swept`), else a 1..15-byte back-scan (`heuristic` / `unknown`); LRU-cached because
// watch traps repeat at the same pc. WP6's `disassemble` RPC (code.ts) builds on decodeAt.
// =================================================================================================
import type { Hex, HexBytes } from "../shared/agentProtocol.js";
import { big, hex } from "./encode.js";
import { safeReadBytes } from "./memory.js";
import { bytesHex, hexOfBigint } from "./pure/coreHex.js";
import {
  overlayBytes,
  recoverAccessInsn,
  relocateDecoded,
  type AccessConfidence,
  type DecodedInsn,
} from "./pure/coreDisasm.js";
import { LruMap } from "./pure/coreRate.js";
import type { AgentCore } from "./state.js";

export interface DecodedRow {
  readonly address: NativePointer;
  readonly size: number;
  readonly bytes: HexBytes;
  readonly mnemonic: string;
  readonly opStr: string;
  readonly text: string;
  readonly groups: readonly string[];
  readonly branchTarget: Hex | null;
  /** absolute addresses of RIP-relative memory operands */
  readonly memTargets: readonly Hex[];
  /** decoded with BEA's original bytes overlaid */
  readonly overlay: boolean;
  /** raw Capstone operands (WP9 WatchRow.mem; displacements are real) */
  readonly operands: readonly X86Operand[];
  readonly regsRead: readonly string[];
  readonly regsWritten: readonly string[];
}

export interface AccessInsnResult {
  readonly address: Hex | null;
  readonly size: number | null;
  readonly text: string | null;
  readonly conf: AccessConfidence;
}

const MAX_INSN = 16;
let scratchBuf: NativePointer | null = null;
const SCRATCH_BYTES = 64 * 1024;

/** One reusable rw- scratch allocation (≥ 64 KiB) for overlay decoding; module scope keeps it alive. */
export const disasmScratch = (): NativePointer => {
  scratchBuf ??= Memory.alloc(SCRATCH_BYTES);
  return scratchBuf;
};

const immsOf = (operands: readonly X86Operand[]): bigint[] => {
  const out: bigint[] = [];
  for (const op of operands) {
    if (op.type !== "imm") continue;
    try {
      out.push(BigInt.asUintN(64, BigInt(String(op.value))));
    } catch {
      // not an integer immediate
    }
  }
  return out;
};

const memTargetsOf = (operands: readonly X86Operand[], next: bigint): Hex[] => {
  const out: Hex[] = [];
  for (const op of operands) {
    if (op.type !== "mem") continue;
    if (op.value.base === "rip") out.push(hexOfBigint(next + BigInt(op.value.disp)));
  }
  return out;
};

/** Decode one instruction at `address` (overlay-aware); null when unreadable or undecodable. */
export const decodeAt = (c: AgentCore, address: NativePointer, overlay = true): DecodedRow | null => {
  const r = safeReadBytes(c, address, MAX_INSN, true);
  if (r.bytes.length === 0) return null;
  let bytes = r.bytes;
  let overlaid = false;
  if (overlay) {
    const originals = c.originals.intersecting(address, bytes.length);
    if (originals.length > 0) {
      const o = overlayBytes(bytes, big(address), originals);
      bytes = o.bytes;
      overlaid = o.changed;
    }
  }
  const s = disasmScratch();
  s.writeByteArray(Array.from(bytes));
  if (bytes.length < MAX_INSN) s.add(bytes.length).writeByteArray(new ArrayBuffer(MAX_INSN - bytes.length));
  let insn: X86Instruction;
  try {
    insn = Instruction.parse(s) as X86Instruction;
  } catch {
    return null;
  }
  if (insn.size <= 0 || insn.size > bytes.length) return null;
  const operands = insn.operands;
  const decoded: DecodedInsn = {
    size: insn.size,
    mnemonic: insn.mnemonic,
    opStr: insn.opStr,
    groups: insn.groups,
    imms: immsOf(operands),
  };
  const real = big(address);
  const fixed = relocateDecoded(decoded, big(s), real);
  return {
    address,
    size: insn.size,
    bytes: bytesHex(bytes, 0, insn.size),
    mnemonic: insn.mnemonic,
    opStr: fixed.opStr,
    text: `${insn.mnemonic} ${fixed.opStr}`.trim(),
    groups: insn.groups,
    branchTarget: fixed.branchTarget === null ? null : hexOfBigint(fixed.branchTarget),
    memTargets: memTargetsOf(operands, real + BigInt(insn.size)),
    overlay: overlaid,
    operands,
    regsRead: insn.regsAccessed.read,
    regsWritten: insn.regsAccessed.written,
  };
};

const accessCache = new LruMap<string, AccessInsnResult>(4096);

/** The .pdata (or dynamic function table) start of the function containing `pc`, or null. */
const functionStart = (c: AgentCore, pc: NativePointer): bigint | null => {
  const fr = c.modules.functionRange(pc);
  if (fr !== null) return big(fr.base);
  if (c.modules.find(pc) !== null) return null;
  const dyn = Process.findFunctionRange(pc);
  return dyn === null ? null : big(dyn.base);
};

/** Recover the accessing instruction from the trap-after pc of a data watch (S4 §8.4). */
export const findAccessInsn = (c: AgentCore, pcAfter: NativePointer): AccessInsnResult => {
  const key = pcAfter.toString();
  const hit = accessCache.get(key);
  if (hit !== undefined) return hit;
  const decodeSize = (a: bigint): number | null => decodeAt(c, ptr(hexOfBigint(a)), true)?.size ?? null;
  const found = recoverAccessInsn(decodeSize, big(pcAfter), functionStart(c, pcAfter));
  let result: AccessInsnResult;
  if (found.address === null) result = { address: null, size: null, text: null, conf: found.conf };
  else {
    const row = decodeAt(c, ptr(hexOfBigint(found.address)), true);
    result = { address: hexOfBigint(found.address), size: found.size, text: row?.text ?? null, conf: found.conf };
  }
  accessCache.set(key, result);
  return result;
};

/** Forget cached recoveries (code patched or unloaded). @public */
export const clearAccessCache = (): void => accessCache.clear();

/** Convenience for rows: the instruction text at an address, or null. @public */
export const textAt = (c: AgentCore, address: NativePointer): string | null => decodeAt(c, address, true)?.text ?? null;

/** Canonical hex of a decoded row's address (rows / results). @public */
export const rowAddress = (row: DecodedRow): Hex => hex(row.address);
