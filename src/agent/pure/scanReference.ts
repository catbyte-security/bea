// =================================================================================================
// src/agent/pure/scanReference.ts — WP10-SCAN: the JavaScript reference of the C compare kernels
// (scanKernelSource.ts). Same semantics element for element; tests/unit/scan/scanKernels.gcc.test.ts proves the C
// against it. In the agent it is the fallback when the kernel CModule cannot be compiled (QJS loops run at about
// 33 MB/s, ext-frida §3.4, so slices stay small; the job runner keeps RPCs responsive either way).
// =================================================================================================
import type {
  Bits64,
  Candidates,
  CmpCall,
  KernelOutcome,
  KernelSpec,
  NextCall,
  ScanBuf,
  ScanKernels,
  SnapCall,
} from "./scanTypes.js";
import { OP_CODE } from "./scanTypes.js";
import { floatOrder, readFloat, type FloatRead } from "./scanValue.js";

const U64_MAX = (1n << 64n) - 1n;
const TWO32 = 4_294_967_296;

const bitsU = (b: Bits64): bigint => (BigInt(b.hi >>> 0) << 32n) | BigInt(b.lo >>> 0);
const bitsS = (b: Bits64): bigint => BigInt.asIntN(64, bitsU(b));
/** A float operand from its bits, classified there (QJS has no infinities: scanValue floatClass). */
const bitsF = (b: Bits64, vt: number): FloatRead => {
  const view = new DataView(new ArrayBuffer(8));
  view.setUint32(0, b.lo >>> 0, true);
  view.setUint32(4, b.hi >>> 0, true);
  return readFloat(vt === 9, new Uint8Array(view.buffer, 0, vt === 8 ? 4 : 8));
};

/** 0 signed, 1 unsigned, 2 float, 3 bytes (the C bea_class). */
const valueClass = (vt: number): 0 | 1 | 2 | 3 =>
  vt === 0 || vt === 2 || vt === 4 || vt === 6 ? 0 : vt === 8 || vt === 9 ? 2 : vt === 11 ? 3 : 1;

const viewOf = (x: Uint8Array): DataView => new DataView(x.buffer, x.byteOffset, x.byteLength);
const loadS = (x: Uint8Array, vt: number): bigint => {
  const v = viewOf(x);
  if (vt === 0) return BigInt(v.getInt8(0));
  if (vt === 2) return BigInt(v.getInt16(0, true));
  if (vt === 4) return BigInt(v.getInt32(0, true));
  return BigInt.asIntN(64, (BigInt(v.getUint32(4, true)) << 32n) | BigInt(v.getUint32(0, true)));
};
const loadU = (x: Uint8Array, vt: number): bigint => {
  const v = viewOf(x);
  if (vt === 1) return BigInt(v.getUint8(0));
  if (vt === 3) return BigInt(v.getUint16(0, true));
  if (vt === 5) return BigInt(v.getUint32(0, true));
  return (BigInt(v.getUint32(4, true)) << 32n) | BigInt(v.getUint32(0, true));
};
const loadF = (x: Uint8Array, vt: number): FloatRead => readFloat(vt === 9, x);

const memeq = (x: Uint8Array, y: Uint8Array, n: number): boolean => {
  for (let i = 0; i < n; i++) if (x[i] !== y[i]) return false;
  return true;
};
const near = (x: number, y: number, eps: number): boolean => x - y <= eps && y - x <= eps;
const epsInt = (eps: number): bigint => (eps >= 2 ** 64 ? U64_MAX : BigInt(Math.floor(eps)));

/*
 * Float semantics are the C kernel's IEEE ones, written over classified values so they hold in the agent's QJS too
 * (no infinities there, and NaN === x is true): NaN is unordered (eq false, ne true), ±Inf order as usual, and any
 * |difference| test (approx, eps changes, *_by) is false as soon as a non-finite value takes part, exactly what
 * IEEE gives for Inf - Inf = NaN and Inf - x = Inf.
 */
const nearF = (x: FloatRead, y: FloatRead, eps: number): boolean =>
  x.cls === "finite" && y.cls === "finite" && near(x.x, y.x, eps);
const FINITE_ZERO: FloatRead = { cls: "finite", x: 0 };

const matchFloat = (k: KernelSpec, cur: Uint8Array, prev: Uint8Array | null): boolean => {
  const x = loadF(cur, k.vt);
  const fa = bitsF(k.a, k.vt);
  const fb = bitsF(k.b, k.vt);
  const pv = prev === null ? FINITE_ZERO : loadF(prev, k.vt);
  switch (k.op) {
    case "eq":
      return floatOrder(x, fa) === 0;
    case "ne":
      return floatOrder(x, fa) !== 0;
    case "approx":
      return nearF(x, fa, k.eps);
    case "gt":
      return floatOrder(x, fa) === 1;
    case "lt":
      return floatOrder(x, fa) === -1;
    case "range": {
      const lo = floatOrder(x, fa);
      const hi = floatOrder(x, fb);
      return lo !== null && lo >= 0 && hi !== null && hi <= 0;
    }
    case "changed":
      return k.eps > 0 ? !nearF(x, pv, k.eps) : prev !== null && !memeq(cur, prev, k.elem);
    case "unchanged":
      return k.eps > 0 ? nearF(x, pv, k.eps) : prev !== null && memeq(cur, prev, k.elem);
    case "increased":
      return floatOrder(x, pv) === 1;
    case "decreased":
      return floatOrder(x, pv) === -1;
    case "increased_by":
      return x.cls === "finite" && pv.cls === "finite" && fa.cls === "finite" && near(x.x - pv.x, fa.x, k.eps);
    case "decreased_by":
      return x.cls === "finite" && pv.cls === "finite" && fa.cls === "finite" && near(pv.x - x.x, fa.x, k.eps);
    default:
      return false;
  }
};

const matchInt = (k: KernelSpec, cur: Uint8Array, prev: Uint8Array | null): boolean => {
  const signed = valueClass(k.vt) === 0;
  const load = signed ? loadS : loadU;
  const x = load(cur, k.vt);
  const a = signed ? bitsS(k.a) : bitsU(k.a);
  const b = signed ? bitsS(k.b) : bitsU(k.b);
  const pv = prev === null ? 0n : load(prev, k.vt);
  const e = epsInt(k.eps);
  switch (k.op) {
    case "eq":
      return x === a;
    case "ne":
      return x !== a;
    case "approx":
      return (x >= a ? x - a : a - x) <= e;
    case "gt":
      return x > a;
    case "lt":
      return x < a;
    case "range":
      return x >= a && x <= b;
    case "increased":
      return x > pv;
    case "decreased":
      return x < pv;
    case "increased_by":
      return BigInt.asUintN(64, x - pv) === BigInt.asUintN(64, a);
    case "decreased_by":
      return BigInt.asUintN(64, pv - x) === BigInt.asUintN(64, a);
    default:
      return false;
  }
};

/** One element against the operands, the previous and the first value (the C bea_match). */
const matchElement = (k: KernelSpec, cur: Uint8Array, prev: Uint8Array | null, first: Uint8Array | null): boolean => {
  const cls = valueClass(k.vt);
  if (k.op === "same_as_first") return first !== null && memeq(cur, first, k.elem);
  if (cls === 3 || k.op === "eq_bits") {
    const operand = k.operand ?? new Uint8Array(k.elem);
    if (k.op === "eq" || k.op === "eq_bits") return memeq(cur, operand, k.elem);
    if (k.op === "ne") return !memeq(cur, operand, k.elem);
    if (k.op === "changed") return prev !== null && !memeq(cur, prev, k.elem);
    if (k.op === "unchanged") return prev !== null && memeq(cur, prev, k.elem);
    return false;
  }
  if (cls === 2) return matchFloat(k, cur, prev);
  if (k.op === "changed") return prev !== null && !memeq(cur, prev, k.elem);
  if (k.op === "unchanged") return prev !== null && memeq(cur, prev, k.elem);
  return matchInt(k, cur, prev);
};

// ---------------------------------------------------------------- candidate array helpers (also used by the engine)

export const addrAt = (buf: ScanBuf, i: number): number => {
  const v = new DataView(buf.u8.buffer, buf.u8.byteOffset + i * 8, 8);
  return v.getUint32(0, true) + v.getUint32(4, true) * TWO32;
};
export const setAddrAt = (buf: ScanBuf, i: number, va: number): void => {
  const v = new DataView(buf.u8.buffer, buf.u8.byteOffset + i * 8, 8);
  v.setUint32(0, va % TWO32, true);
  v.setUint32(4, Math.floor(va / TWO32), true);
};
const elemAt = (buf: ScanBuf, i: number, elem: number): Uint8Array => buf.u8.subarray(i * elem, (i + 1) * elem);

const emit = (out: Candidates, at: number, va: number, val: Uint8Array, first: Uint8Array | null, elem: number) => {
  setAddrAt(out.addrs, at, va);
  out.vals.u8.set(val.subarray(0, elem), at * elem);
  if (out.firsts !== null && first !== null) out.firsts.u8.set(first.subarray(0, elem), at * elem);
};

/** The reference kernels over a reader of target memory (null = unreadable). */
export const createReferenceKernels = (read: (va: number, len: number) => Uint8Array | null): ScanKernels => {
  const cmp = (k: KernelSpec, c: CmpCall): KernelOutcome => {
    if (c.progress >= c.len) return { at: c.at, progress: c.progress, fault: false };
    const span = Math.min(c.avail, c.len - 1 + k.elem);
    const data = read(c.va, span);
    if (data === null) return { at: c.at, progress: c.progress, fault: true };
    let at = c.at;
    let o = c.progress;
    for (; o < c.len && o + k.elem <= c.avail; o += k.align) {
      if (at >= c.out.cap) break;
      const cur = data.subarray(o, o + k.elem);
      if (matchElement(k, cur, null, null)) emit(c.out, at++, c.va + o, cur, null, k.elem);
    }
    return { at, progress: o, fault: false };
  };
  const next = (k: KernelSpec, c: NextCall): KernelOutcome => {
    let kept = c.kept;
    const s = c.store;
    for (let i = c.progress; i < c.end; i++) {
      const va = addrAt(s.addrs, i);
      const cur = read(va, k.elem);
      if (cur === null) return { at: kept, progress: i, fault: true };
      const first = s.firsts === null ? null : elemAt(s.firsts, i, k.elem).slice();
      if (matchElement(k, cur, elemAt(s.vals, i, k.elem), first)) emit(s, kept++, va, cur, first, k.elem);
    }
    return { at: kept, progress: c.end, fault: false };
  };
  const snap = (k: KernelSpec, c: SnapCall): KernelOutcome => {
    if (c.progress >= c.len) return { at: c.at, progress: c.progress, fault: false };
    const span = Math.min(c.avail, c.len - 1 + k.elem);
    const data = read(c.va, span);
    if (data === null) return { at: c.at, progress: c.progress, fault: true };
    const old = c.snap.u8.subarray(c.snapOff, c.snapOff + span);
    let at = c.at;
    let o = c.progress;
    for (; o < c.len && o + k.elem <= c.avail; o += k.align) {
      if (at >= c.out.cap) break;
      const cur = data.subarray(o, o + k.elem);
      const was = old.subarray(o, o + k.elem);
      if (matchElement(k, cur, was, was)) emit(c.out, at++, c.va + o, cur, was, k.elem);
    }
    return { at, progress: o, fault: false };
  };
  return { native: false, cmp, next, snap };
};

/** Kernel op codes as numbers (for the native adapter and the gcc harness). */
export const opCode = (k: KernelSpec): number => OP_CODE[k.op];
