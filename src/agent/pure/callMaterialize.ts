// =================================================================================================
// src/agent/pure/callMaterialize.ts — executor-side lowering of one vector (S5 §9.5 rule 3; DESIGN §5.3):
// scratch arena layout, buffer images (template -> column patches -> ptrFields) and the Win64 register file.
// Pure: no GumJS globals or types. The agent writes these bytes into its CallBlock and scratch; test fakes use the
// same functions, so the plan semantics are pinned on both sides of the wire.
// =================================================================================================
import type { BufferWire, PlanWire, VectorsWire } from "../../shared/callPlan.js";
import { CALL_BLOCK, GPR_ORDER, XMM_ORDER } from "./callBlock.js";

const MASK64 = (1n << 64n) - 1n;

export interface PlanIssue {
  readonly path: string;
  readonly problem: string;
}

export interface ScratchLayout {
  /** byte offset of each buffer from the (max-aligned) arena base */
  readonly offsets: ReadonlyMap<string, number>;
  readonly total: number;
  readonly maxAlign: number;
}

export const layoutScratch = (buffers: readonly BufferWire[]): ScratchLayout => {
  const offsets = new Map<string, number>();
  let cursor = 0;
  let maxAlign = 16;
  for (const buffer of buffers) {
    const align = Math.max(1, buffer.align);
    maxAlign = Math.max(maxAlign, align);
    cursor = Math.ceil(cursor / align) * align;
    offsets.set(buffer.name, cursor);
    cursor += buffer.size;
  }
  return { offsets, total: Math.max(cursor, 16), maxAlign };
};

const isPow2 = (n: number): boolean => n > 0 && (n & (n - 1)) === 0;

/** Structural checks (the host validated with zod; the agent re-checks bounds it must never exceed, S4 §5.2). */
export const checkPlan = (
  plan: PlanWire,
  vectors: VectorsWire,
  limits: { readonly scratchBytes: number; readonly bufferBytes: number },
): PlanIssue[] => {
  const issues: PlanIssue[] = [];
  const names = new Map<string, BufferWire>();
  plan.buffers.forEach((buffer, i) => {
    const path = `plan.buffers[${String(i)}]`;
    if (names.has(buffer.name)) issues.push({ path, problem: "duplicate buffer name" });
    names.set(buffer.name, buffer);
    if (!Number.isInteger(buffer.size) || buffer.size < 1 || buffer.size > limits.bufferBytes)
      issues.push({ path: `${path}.size`, problem: `size must be 1..${String(limits.bufferBytes)}` });
    if (!isPow2(buffer.align) || buffer.align > 4096)
      issues.push({ path: `${path}.align`, problem: "align must be a power of two ≤ 4096" });
    if (buffer.template.length !== buffer.size * 2)
      issues.push({ path: `${path}.template`, problem: "template must be size bytes" });
    for (const c of buffer.columns)
      if (c.offset + c.width * c.count > buffer.size)
        issues.push({ path: `${path}.columns`, problem: `${c.column} ends past the buffer` });
    for (const p of buffer.ptrFields)
      if (p.offset + 8 > buffer.size)
        issues.push({ path: `${path}.ptrFields`, problem: "pointer field ends past the buffer" });
  });
  for (const buffer of plan.buffers)
    for (const p of buffer.ptrFields)
      if (!names.has(p.buffer))
        issues.push({ path: "plan.buffers", problem: `ptr field names unknown buffer ${p.buffer}` });
  const { total, maxAlign } = layoutScratch(plan.buffers);
  if (total + maxAlign > limits.scratchBytes)
    issues.push({ path: "plan.buffers", problem: `scratch exceeds ${String(limits.scratchBytes)} bytes` });
  const regs = new Set<string>();
  const stack = new Set<number>();
  plan.slots.forEach((slot, i) => {
    const path = `plan.slots[${String(i)}]`;
    if (slot.reg === "stack") {
      const k = slot.stackIndex ?? -1;
      if (!Number.isInteger(k) || k < 0 || k >= CALL_BLOCK.maxStack || stack.has(k))
        issues.push({
          path: `${path}.stackIndex`,
          problem: `stack slots are unique indices 0..${String(CALL_BLOCK.maxStack - 1)}`,
        });
      stack.add(k);
    } else {
      if (regs.has(slot.reg)) issues.push({ path: `${path}.reg`, problem: "register used twice" });
      regs.add(slot.reg);
    }
    const src = slot.source;
    if ((src.kind === "buffer" || src.kind === "byval") && !names.has(src.buffer))
      issues.push({ path: `${path}.source.buffer`, problem: "unknown buffer" });
    if (src.kind === "byval") {
      const size = names.get(src.buffer)?.size;
      if (size !== 1 && size !== 2 && size !== 4 && size !== 8)
        issues.push({ path, problem: "byval buffers are 1, 2, 4 or 8 bytes" });
    }
    if (src.kind === "column" && vectors.columns[src.column] === undefined)
      issues.push({ path: `${path}.source.column`, problem: `vectors lack column ${src.column}` });
  });
  for (const buffer of plan.buffers)
    for (const c of buffer.columns)
      if (vectors.columns[c.column] === undefined)
        issues.push({ path: "vectors.columns", problem: `vectors lack column ${c.column}` });
  for (const [name, cells] of Object.entries(vectors.columns))
    if (cells.length < vectors.count)
      issues.push({ path: `vectors.columns.${name}`, problem: "fewer cells than count" });
  return issues;
};

/** Cell i of a column: 64-bit-lane bits (scalars) or one row of element bits (arrays). */
const cellOf = (vectors: VectorsWire, column: string, i: number): bigint | readonly bigint[] => {
  const cell = vectors.columns[column]?.[i];
  if (cell === undefined) return 0n;
  return typeof cell === "string" ? BigInt(cell) : cell.map((bits) => BigInt(bits));
};

export const writeLE = (bytes: Uint8Array, offset: number, width: number, bits: bigint): void => {
  const v = bits & MASK64;
  for (let k = 0; k < width; k++) bytes[offset + k] = Number((v >> BigInt(8 * k)) & 0xffn);
};
const readLE = (bytes: Uint8Array, offset: number, width: number): bigint => {
  let v = 0n;
  for (let k = width - 1; k >= 0; k--) v = (v << 8n) | BigInt(bytes[offset + k] ?? 0);
  return v;
};

const templateBytes = (hex: string, size: number): Uint8Array => {
  const out = new Uint8Array(size);
  for (let i = 0; i < size && 2 * i + 1 < hex.length; i++) out[i] = Number.parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
};

/** The bytes of one buffer for vector i: template, then column patches, then pointer fields (S5 §9.5 rule 3). */
export const materializeBuffer = (
  buffer: BufferWire,
  vectors: VectorsWire,
  i: number,
  addressOf: (name: string) => bigint,
): Uint8Array => {
  const bytes = templateBytes(buffer.template, buffer.size);
  for (const c of buffer.columns) {
    const cell = cellOf(vectors, c.column, i);
    if (typeof cell === "bigint") writeLE(bytes, c.offset, c.width, cell);
    else for (let k = 0; k < c.count; k++) writeLE(bytes, c.offset + k * c.width, c.width, cell[k] ?? 0n);
  }
  for (const p of buffer.ptrFields) writeLE(bytes, p.offset, 8, addressOf(p.buffer) + BigInt(p.plus));
  return bytes;
};

export interface RegisterFile {
  /** rcx, rdx, r8, r9 */
  readonly gpr: bigint[];
  /** low 64 bits of xmm0..3 (upper halves are zero) */
  readonly xmm: bigint[];
  readonly stack: bigint[];
}

/** Win64 register file of vector i; byval reads the vector's materialized buffer bytes as an integer. */
export const registerFile = (
  plan: PlanWire,
  vectors: VectorsWire,
  i: number,
  addressOf: (name: string) => bigint,
  bytesOf: (name: string) => Uint8Array,
): RegisterFile => {
  const gpr = [0n, 0n, 0n, 0n];
  const xmm = [0n, 0n, 0n, 0n];
  const stack: bigint[] = [];
  for (const slot of plan.slots) {
    const src = slot.source;
    let bits: bigint;
    if (src.kind === "column") {
      const cell = cellOf(vectors, src.column, i);
      bits = typeof cell === "bigint" ? cell : (cell[0] ?? 0n);
    } else if (src.kind === "const") bits = BigInt(src.bits);
    else if (src.kind === "buffer") bits = addressOf(src.buffer) + BigInt(src.offset);
    else {
      const bytes = bytesOf(src.buffer);
      bits = readLE(bytes, 0, bytes.length);
    }
    bits &= MASK64;
    const g = (GPR_ORDER as readonly string[]).indexOf(slot.reg);
    const x = (XMM_ORDER as readonly string[]).indexOf(slot.reg);
    if (g >= 0) gpr[g] = bits;
    else if (x >= 0) xmm[x] = bits;
    else stack[slot.stackIndex ?? 0] = bits;
    if (slot.dupGpr !== undefined) gpr[(GPR_ORDER as readonly string[]).indexOf(slot.dupGpr)] = bits;
  }
  for (let k = 0; k < stack.length; k++) stack[k] ??= 0n;
  return { gpr, xmm, stack };
};

/** Lowercase hex of bytes (out-buffer read-back on the wire). */
export const bytesHex = (bytes: Uint8Array): string => {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
};

/** "0x…" canonical form of 64-bit bits (the Hex wire form; no leading zeros). */
export const bitsHex = (bits: bigint): `0x${string}` => `0x${(bits & MASK64).toString(16)}`;

/** The CallBlock image of one vector: target, GPR/XMM/stack slots, nstack, MXCSR (status bits cleared), FPCW. */
export const buildBlock = (
  target: bigint,
  regs: RegisterFile,
  fp: { readonly mxcsr: number; readonly fpcw: number },
): Uint8Array => {
  const block = new Uint8Array(CALL_BLOCK.size);
  writeLE(block, CALL_BLOCK.target, 8, target);
  regs.gpr.forEach((bits, k) => writeLE(block, CALL_BLOCK.gpr + 8 * k, 8, bits));
  regs.xmm.forEach((bits, k) => writeLE(block, CALL_BLOCK.xmm + 16 * k, 8, bits));
  writeLE(block, CALL_BLOCK.nstack, 8, BigInt(regs.stack.length));
  regs.stack.forEach((bits, k) => writeLE(block, CALL_BLOCK.stack + 8 * k, 8, bits));
  writeLE(block, CALL_BLOCK.mxcsrIn, 4, BigInt(fp.mxcsr & 0xffc0));
  writeLE(block, CALL_BLOCK.fpcwIn, 2, BigInt(fp.fpcw & 0xffff));
  return block;
};

export interface BlockOut {
  readonly status: number;
  readonly rax: bigint;
  readonly xmm0lo: bigint;
  readonly mxcsrOut: number;
  readonly fpcwOut: number;
  readonly code: number;
  readonly flags: number;
  readonly nparams: number;
  readonly exceptionAddress: bigint;
  readonly info: readonly bigint[];
  readonly faultRip: bigint;
  readonly faultRsp: bigint;
}

/** Reads a CallBlock back after the thunk returned (status 1) or unwound to its recovery label (status 2). */
export const parseBlock = (block: Uint8Array): BlockOut => ({
  status: Number(readLE(block, CALL_BLOCK.status, 4)),
  rax: readLE(block, CALL_BLOCK.raxOut, 8),
  xmm0lo: readLE(block, CALL_BLOCK.xmm0Out, 8),
  mxcsrOut: Number(readLE(block, CALL_BLOCK.mxcsrOut, 4)),
  fpcwOut: Number(readLE(block, CALL_BLOCK.fpcwOut, 2)),
  code: Number(readLE(block, CALL_BLOCK.code, 4)),
  flags: Number(readLE(block, CALL_BLOCK.flags, 4)),
  nparams: Number(readLE(block, CALL_BLOCK.nparams, 4)),
  exceptionAddress: readLE(block, CALL_BLOCK.exceptionAddress, 8),
  info: [0, 1, 2].map((k) => readLE(block, CALL_BLOCK.info + 8 * k, 8)),
  faultRip: readLE(block, CALL_BLOCK.faultRip, 8),
  faultRsp: readLE(block, CALL_BLOCK.faultRsp, 8),
});
