// =================================================================================================
// src/agent/pure/scanTypes.ts — WP10-SCAN: codes, element sizes and the platform seam of the scan engine
// (S4 §9). Pure TypeScript: no GumJS globals or types, so vitest can drive the engine with a fake platform and the
// agent binds the real one (src/agent/scan.ts, src/agent/scanKernels.ts).
// =================================================================================================
import type { AgentLimits, ScanNextOp, ScanValueType } from "../../shared/agentProtocol.js";

/** Kernel value-type codes (S4 §9.4: 0 i8 … 10 ptr; 11 = byte strings compared with memcmp). */
export const VT_CODE = {
  i8: 0,
  u8: 1,
  i16: 2,
  u16: 3,
  i32: 4,
  u32: 5,
  i64: 6,
  u64: 7,
  f32: 8,
  f64: 9,
  ptr: 10,
  bytes: 11,
  utf8: 11,
  utf16: 11,
} as const satisfies Record<ScanValueType, number>;

export type NumericScanType = Exclude<ScanValueType, "bytes" | "utf8" | "utf16">;
export const NUMERIC_ELEM = {
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
  ptr: 8,
} as const satisfies Record<NumericScanType, number>;

export const isNumericType = (vt: ScanValueType): vt is NumericScanType => vt in NUMERIC_ELEM;
export const isFloatType = (vt: ScanValueType): vt is "f32" | "f64" => vt === "f32" || vt === "f64";

/** Natural alignment (the tool's `aligned:true`): the element size for numbers, 2 for UTF-16, else 1. */
export const naturalAlign = (vt: ScanValueType): 1 | 2 | 4 | 8 =>
  isNumericType(vt) ? NUMERIC_ELEM[vt] : vt === "utf16" ? 2 : 1;

/**
 * Kernel operation codes. 0..12 follow the S4 §9.3 op list; 13 is internal: `eq` with exact bits (a float operand
 * given as `{bits}`), which compares the element bytes instead of IEEE values.
 */
export const OP_CODE = {
  eq: 0,
  ne: 1,
  approx: 2,
  gt: 3,
  lt: 4,
  range: 5,
  changed: 6,
  unchanged: 7,
  increased: 8,
  decreased: 9,
  increased_by: 10,
  decreased_by: 11,
  same_as_first: 12,
  eq_bits: 13,
} as const satisfies Record<ScanNextOp | "eq_bits", number>;
export type KernelOp = keyof typeof OP_CODE;

/** Ops a byte-string scan (bytes, utf8, utf16) supports: memcmp only (S4 §9.4). */
export const BYTE_OPS: ReadonlySet<KernelOp> = new Set([
  "eq",
  "eq_bits",
  "ne",
  "changed",
  "unchanged",
  "same_as_first",
]);

/** Longest element (pattern, text, byte string) a scan stores per candidate. */
export const MAX_ELEM_BYTES = 256;
/** Most pointer targets of one `pointers-to` scan (protocol: ≤ 16). */
export const MAX_POINTER_TARGETS = 16;

/** A 64-bit operand as two u32 halves (raw bits of the declared type; signed values sign-extended). */
export interface Bits64 {
  readonly lo: number;
  readonly hi: number;
}
export const ZERO_BITS: Bits64 = { lo: 0, hi: 0 };

/** Everything a kernel needs to compare one element. */
export interface KernelSpec {
  readonly vt: number;
  readonly elem: number;
  readonly align: number;
  readonly op: KernelOp;
  readonly a: Bits64;
  readonly b: Bits64;
  readonly eps: number;
  /** byte-string comparand (vt 11 with eq/ne), else null */
  readonly operand: Uint8Array | null;
}

/** A buffer the engine owns: agent = Memory.alloc + ArrayBuffer.wrap (native carries the pointer); tests = ArrayBuffer. */
export interface ScanBuf {
  readonly u8: Uint8Array;
  readonly bytes: number;
  readonly native: unknown;
}

/**
 * Parallel candidate arrays (S4 §9.1): addrs u64[cap] (little-endian), vals u8[cap*elem] (last observed value),
 * firsts u8[cap*elem] (value at the first scan; null when not kept).
 */
export interface Candidates {
  readonly addrs: ScanBuf;
  readonly vals: ScanBuf;
  readonly firsts: ScanBuf | null;
  readonly cap: number;
}

/** What one kernel call reports. `fault`: a stolen access violation at index/offset `progress`. */
export interface KernelOutcome {
  /** cmp/snap: next free output index; next: candidates kept so far */
  readonly at: number;
  /** cmp/snap: next element offset to examine; next: next candidate index to examine */
  readonly progress: number;
  readonly fault: boolean;
}

export interface CmpCall {
  /** target VA of the slice */
  readonly va: number;
  /** element start offsets examined: [progress, len) step align */
  readonly len: number;
  /** readable bytes from va (an element must fit: offset + elem ≤ avail) */
  readonly avail: number;
  readonly progress: number;
  readonly out: Candidates;
  readonly at: number;
}
export interface NextCall {
  readonly store: Candidates;
  /** first candidate index to examine */
  readonly progress: number;
  readonly end: number;
  /** candidates kept before `progress` (compaction target index) */
  readonly kept: number;
}
export interface SnapCall {
  readonly va: number;
  readonly snap: ScanBuf;
  readonly snapOff: number;
  /** element start offsets examined: [progress, len) */
  readonly len: number;
  /** bytes of the snapshot (and target region) from va */
  readonly avail: number;
  readonly progress: number;
  readonly out: Candidates;
  readonly at: number;
}

/** The three compare kernels (C in the agent, src/agent/pure/scanKernelSource.ts; JS reference in scanReference.ts). */
export interface ScanKernels {
  readonly native: boolean;
  cmp(k: KernelSpec, c: CmpCall): KernelOutcome;
  next(k: KernelSpec, c: NextCall): KernelOutcome;
  snap(k: KernelSpec, c: SnapCall): KernelOutcome;
}

/** One committed range as the platform enumerates it (module = loader name of the image it belongs to). */
export interface RawRange {
  readonly base: number;
  readonly size: number;
  readonly protection: string;
  readonly module: string | null;
}

/** GumJS (or a fake) behind the engine. Every target access goes through here. */
export interface ScanPlatform {
  /** monotonic milliseconds (slice budgets) */
  nowMs(): number;
  /** agent TimeUs (history rows) */
  nowUs(): number;
  /** null when the allocation fails */
  alloc(bytes: number): ScanBuf | null;
  free(buf: ScanBuf): void;
  /** committed ranges with at least `protection` (BEA-guarded pages re-inserted), unsorted */
  ranges(protection: string): readonly RawRange[];
  /** Memory.scanSync: match addresses; throws on an unreadable range or a bad pattern ("invalid match pattern") */
  scanPattern(base: number, size: number, pattern: string): readonly number[];
  /** Memory.findPointers: pointer-aligned words equal to one of `targets`; throws on an unreadable range */
  findPointers(base: number, size: number, targets: readonly number[]): readonly { address: number; value: number }[];
  /** guard-aware read; null when unreadable */
  read(va: number, len: number): Uint8Array | null;
  /** Memory.copy into a buffer; false when unreadable */
  copyIn(dst: ScanBuf, dstOff: number, va: number, len: number): boolean;
  /** CT-I5: run `fn` with BEA's own guard pages in the span suspended (withBeaGuardsSuspended) */
  suspendGuards<T>(span: { readonly base: number; readonly size: number }, fn: () => T): T;
  readonly kernels: ScanKernels;
}

/** The agent limits the engine reads (re-read on every call: hello may change them). */
export type ScanLimits = Pick<
  AgentLimits,
  "scan_max_concurrent" | "scan_max_candidates" | "scan_snapshot_bytes" | "scan_page_rows"
>;

export const PAGE_BYTES = 4096;
/** Slice sizes (S4 §9.2: ≤ 8 MiB of region per kernel call; findPointers ≤ 256 MiB at ~30 GB/s). */
export const CHUNK_BYTES = 8 * 1024 * 1024;
export const POINTER_CHUNK_BYTES = 64 * 1024 * 1024;
/** Pattern scans materialize one JS object per match: short patterns get small chunks. */
export const SHORT_PATTERN_CHUNK_BYTES = 256 * 1024;
export const PATTERN_CHUNK_BYTES = 2 * 1024 * 1024;
/** Next-scan kernel calls examine at most this many candidates (S4 §9.3: ≤ 1M per slice). */
export const NEXT_CHUNK = 262_144;
/** Initial candidate capacity; arrays grow ×4 up to the scan's cap. */
export const INITIAL_CAPACITY = 65_536;
