// =================================================================================================
// src/agent/pure/dumpPlan.ts — pure helpers of the agent dump feature (S4 §15; WP-DUMP). No GumJS globals or types:
// importable by vitest (tests/unit/dump/agentDumpPlan.test.ts) and staged into the agent build.
// =================================================================================================
import { formatHex, type Hex } from "../../shared/hex.js";

const PAGE = 0x1000;
const PAGE_N = 0x1000n;

/** A byte span at an absolute address. */
export interface Span {
  readonly start: bigint;
  readonly size: number;
}
/** A byte span relative to a region start. */
export interface Rel {
  readonly offset: number;
  readonly size: number;
}

const alignDown = (value: bigint, to: bigint = PAGE_N): bigint => value - (value % to);
const alignUp = (value: bigint, to: bigint = PAGE_N): bigint => {
  const rest = value % to;
  return rest === 0n ? value : value + (to - rest);
};

/** The smallest run of whole pages covering [start, start+size). */
export const pageSpan = (start: bigint, size: number): Span => {
  const lo = alignDown(start);
  const hi = alignUp(start + BigInt(Math.max(size, 1)));
  return { start: lo, size: Number(hi - lo) };
};

/** Intersection of two spans, or null. */
export const intersect = (a: Span, b: Span): Span | null => {
  const start = a.start > b.start ? a.start : b.start;
  const aEnd = a.start + BigInt(a.size);
  const bEnd = b.start + BigInt(b.size);
  const end = aEnd < bEnd ? aEnd : bEnd;
  return end > start ? { start, size: Number(end - start) } : null;
};

/** Sorts and merges overlapping or adjacent relative spans. */
export const coalesce = (spans: readonly Rel[]): Rel[] => {
  const sorted = spans.filter((s) => s.size > 0).sort((a, b) => a.offset - b.offset);
  const out: Rel[] = [];
  for (const s of sorted) {
    const last = out[out.length - 1];
    if (last !== undefined && s.offset <= last.offset + last.size) {
      const end = Math.max(last.offset + last.size, s.offset + s.size);
      out[out.length - 1] = { offset: last.offset, size: end - last.offset };
    } else out.push({ offset: s.offset, size: s.size });
  }
  return out;
};

/** The parts of `region` NOT covered by `readable` (absolute spans), relative to the region start. */
export const holesOf = (region: Span, readable: readonly Span[]): Rel[] => {
  const covered = coalesce(
    readable
      .map((r) => intersect(region, r))
      .filter((r): r is Span => r !== null)
      .map((r) => ({ offset: Number(r.start - region.start), size: r.size })),
  );
  const holes: Rel[] = [];
  let at = 0;
  for (const c of covered) {
    if (c.offset > at) holes.push({ offset: at, size: c.offset - at });
    at = Math.max(at, c.offset + c.size);
  }
  if (at < region.size) holes.push({ offset: at, size: region.size - at });
  return holes;
};

/** The readable parts of [offset, offset+size) of a region given its (relative) holes. */
export const readableParts = (offset: number, size: number, holes: readonly Rel[]): Rel[] => {
  const parts: Rel[] = [];
  let at = offset;
  const end = offset + size;
  for (const h of coalesce(holes)) {
    const hEnd = h.offset + h.size;
    if (hEnd <= at || h.offset >= end) continue;
    if (h.offset > at) parts.push({ offset: at, size: h.offset - at });
    at = Math.max(at, hEnd);
  }
  if (at < end) parts.push({ offset: at, size: end - at });
  return parts;
};

/** Chunk offsets of a region (each ≤ chunk bytes). */
export const chunksOf = (size: number, chunk: number): Rel[] => {
  const step = Math.max(PAGE, chunk);
  const out: Rel[] = [];
  for (let offset = 0; offset < size; offset += step) out.push({ offset, size: Math.min(step, size - offset) });
  return out;
};

/** Coalesced ranges where `before` and `after` differ (both the same length). */
export const changedRanges = (before: Uint8Array, after: Uint8Array): Rel[] => {
  const out: Rel[] = [];
  const n = Math.min(before.length, after.length);
  let start = -1;
  for (let i = 0; i < n; i++) {
    const differs = before[i] !== after[i];
    if (differs && start < 0) start = i;
    else if (!differs && start >= 0) {
      out.push({ offset: start, size: i - start });
      start = -1;
    }
  }
  if (start >= 0) out.push({ offset: start, size: n - start });
  return out;
};

/** Original bytes under one BEA patch (address + bytes saved before patching). */
export interface OriginalPatch {
  readonly address: bigint;
  readonly bytes: Uint8Array;
}

/**
 * CT-I6: copy BEA's original bytes over a chunk read at `base` (live code patched by BEA hooks/overrides/writes).
 * Returns the restored ranges relative to the chunk (only where the bytes actually changed).
 */
export const spliceOriginals = (buf: Uint8Array, base: bigint, patches: readonly OriginalPatch[]): Rel[] => {
  const before = buf.slice();
  const end = base + BigInt(buf.length);
  for (const patch of patches) {
    const pEnd = patch.address + BigInt(patch.bytes.length);
    if (pEnd <= base || patch.address >= end) continue;
    const from = patch.address > base ? patch.address : base;
    const to = pEnd < end ? pEnd : end;
    const src = Number(from - patch.address);
    buf.set(patch.bytes.subarray(src, src + Number(to - from)), Number(from - base));
  }
  return changedRanges(before, buf);
};

// ---------------------------------------------------------------- CONTEXT (x64, winnt.h; S4 §5.6)
/** CONTEXT_AMD64 | CONTROL | INTEGER | SEGMENTS | FLOATING_POINT | DEBUG_REGISTERS (= CONTEXT_ALL) */
export const CONTEXT_ALL = 0x10001f;
export const CONTEXT_BYTES = 0x4d0;
export const CONTEXT_FLAGS_OFFSET = 0x30;
export const CONTEXT_GPR_OFFSETS = {
  rax: 0x78,
  rcx: 0x80,
  rdx: 0x88,
  rbx: 0x90,
  rsp: 0x98,
  rbp: 0xa0,
  rsi: 0xa8,
  rdi: 0xb0,
  r8: 0xb8,
  r9: 0xc0,
  r10: 0xc8,
  r11: 0xd0,
  r12: 0xd8,
  r13: 0xe0,
  r14: 0xe8,
  r15: 0xf0,
  rip: 0xf8,
} as const;
const MXCSR_OFFSET = 0x34;
const EFLAGS_OFFSET = 0x44;
const FPCW_OFFSET = 0x100; // FltSave.ControlWord
const XMM_OFFSET = 0x1a0;

export interface ParsedContext {
  readonly registers: Record<string, Hex>;
  readonly eflags: Hex;
  readonly mxcsr: Hex;
  readonly fpcw: Hex;
  readonly xmm: Hex[] | null;
}

/** 128-bit little-endian value at `offset` as canonical hex (up to 32 digits). */
const read128 = (view: DataView, offset: number): Hex => {
  const lo = view.getBigUint64(offset, true);
  const hi = view.getBigUint64(offset + 8, true);
  return `0x${((hi << 64n) | lo).toString(16)}`;
};

/** Registers from a GetThreadContext(CONTEXT_ALL) buffer. */
export const parseContext = (bytes: Uint8Array, withXmm: boolean): ParsedContext => {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const registers: Record<string, Hex> = {};
  for (const [name, offset] of Object.entries(CONTEXT_GPR_OFFSETS))
    registers[name] = formatHex(view.getBigUint64(offset, true));
  const xmm: Hex[] = [];
  if (withXmm) for (let i = 0; i < 16; i++) xmm.push(read128(view, XMM_OFFSET + 16 * i));
  return {
    registers,
    eflags: formatHex(view.getUint32(EFLAGS_OFFSET, true)),
    mxcsr: formatHex(view.getUint32(MXCSR_OFFSET, true)),
    fpcw: formatHex(view.getUint16(FPCW_OFFSET, true)),
    xmm: withXmm ? xmm : null,
  };
};

// ---------------------------------------------------------------- TEB / TLS (S4 §15.1, S5 R2/R5/R6)
export const TEB_STACK_BASE = 0x08;
export const TEB_STACK_LIMIT = 0x10;
export const TEB_TLS_POINTER = 0x58;
export const TEB_PEB = 0x60;
export const TEB_TLS_SLOTS = 0x1480;
export const TEB_TLS_SLOT_COUNT = 64;
/** x64 TEB is 0x1838 bytes: two pages. */
export const TEB_BYTES = 0x2000;
export const PEB_BYTES = 0x1000;

/** Data directory (rva, size) from a mapped PE header, or null (not PE32+, out of range, empty). */
export const peDirectory = (header: Uint8Array, index: number): { rva: number; size: number } | null => {
  if (header.length < 0x40) return null;
  const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
  if (view.getUint16(0, true) !== 0x5a4d) return null;
  const nt = view.getUint32(0x3c, true);
  const opt = nt + 24;
  if (opt + 112 + 16 * 8 > header.length || view.getUint32(nt, true) !== 0x4550) return null;
  if (view.getUint16(opt, true) !== 0x20b) return null;
  const count = view.getUint32(opt + 108, true);
  if (index >= count) return null;
  const rva = view.getUint32(opt + 112 + 8 * index, true);
  const size = view.getUint32(opt + 112 + 8 * index + 4, true);
  return rva === 0 || size === 0 ? null : { rva, size };
};
export const DIR_TLS = 9;

export interface TlsDirectory64 {
  readonly start: bigint;
  readonly end: bigint;
  readonly indexAddress: bigint;
  readonly zeroFill: number;
}
export const TLS_DIRECTORY_BYTES = 0x28;
/** IMAGE_TLS_DIRECTORY64 (VAs are runtime values in a mapped image). */
export const parseTlsDirectory = (bytes: Uint8Array): TlsDirectory64 | null => {
  if (bytes.length < TLS_DIRECTORY_BYTES) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return {
    start: view.getBigUint64(0, true),
    end: view.getBigUint64(8, true),
    indexAddress: view.getBigUint64(16, true),
    zeroFill: view.getUint32(32, true),
  };
};
/** Size of one static TLS block: End − Start + SizeOfZeroFill (0 when malformed). */
export const tlsBlockSize = (dir: TlsDirectory64): number => {
  const raw = dir.end > dir.start ? Number(dir.end - dir.start) : 0;
  const size = raw + dir.zeroFill;
  return size > 0 && size <= 64 * 1024 * 1024 ? size : 0;
};

/** The stack span captured for a thread: whole pages from the page of rsp up to min(stack base, rsp + bytes). */
export const stackSpan = (rsp: bigint, stackBase: bigint, bytes: number): Span | null => {
  if (bytes <= 0 || rsp >= stackBase) return null;
  const lo = alignDown(rsp);
  const want = lo + alignUp(BigInt(bytes));
  const hi = want < stackBase ? want : alignUp(stackBase);
  return hi > lo ? { start: lo, size: Number(hi - lo) } : null;
};

/** Parse a module item's selector: "0x<base>" selects by base, anything else by name (case-insensitive). */
export const moduleSelector = (text: string): { kind: "base"; base: bigint } | { kind: "name"; name: string } =>
  /^0x[0-9a-fA-F]{1,16}$/u.test(text)
    ? { kind: "base", base: BigInt(text) }
    : { kind: "name", name: text.toLowerCase() };
