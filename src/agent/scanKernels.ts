import { ARG, ARGS_BYTES, SCAN_KERNEL_SOURCE, SCAN_KERNEL_SYMBOLS } from "./pure/scanKernelSource.js";
import { createReferenceKernels, opCode } from "./pure/scanReference.js";
import type { Bits64, Candidates, KernelOutcome, KernelSpec, ScanBuf, ScanKernels } from "./pure/scanTypes.js";

/**
 * WP10-SCAN: the scan compare kernels as a CModule (S4 §9.4; TinyCC). One CModule per agent, compiled on first
 * use and pinned at module scope for the agent's lifetime (QJS frees unreferenced CModules eagerly, ext-frida §3.8).
 * Each kernel is a NativeFunction {exceptions:"steal", scheduling:"exclusive"} over one BeaScanArgs block: a stolen
 * access violation surfaces as a JS throw, after which `progress`/`at` in the block say where to resume. If TinyCC
 * fails to compile the source, the JS reference kernels (same semantics, slower) take over.
 */
type KernelFn = (args: NativePointer) => void;

let pinned: { readonly module: CModule; readonly fns: readonly NativeFunction<void, [NativePointerValue]>[] } | null =
  null;
const ARGS = Memory.alloc(ARGS_BYTES);
const OPERAND = Memory.alloc(256);

const bufPtr = (b: ScanBuf | null): NativePointer => (b === null ? NULL : (b.native as NativePointer));

const U64_MAX = uint64("0xffffffffffffffff");
/** floor(eps) as u64, saturated (the C side has no double→u64 conversion under TinyCC). */
const epsInteger = (eps: number): UInt64 =>
  eps >= 2 ** 64 ? U64_MAX : uint64(BigInt(Math.floor(Math.max(0, eps))).toString());

const writeBits = (at: number, bits: Bits64): void => {
  ARGS.add(at).writeU32(bits.lo >>> 0);
  ARGS.add(at + 4).writeU32(bits.hi >>> 0);
};

const fillSpec = (k: KernelSpec): void => {
  ARGS.add(ARG.vt).writeU64(k.vt);
  ARGS.add(ARG.elem).writeU64(k.elem);
  ARGS.add(ARG.align).writeU64(k.align);
  ARGS.add(ARG.op).writeU64(opCode(k));
  writeBits(ARG.a, k.a);
  writeBits(ARG.b, k.b);
  ARGS.add(ARG.eps).writeDouble(k.eps);
  ARGS.add(ARG.epsi).writeU64(epsInteger(k.eps));
  if (k.operand !== null) OPERAND.writeByteArray(Array.from(k.operand));
  ARGS.add(ARG.operand).writePointer(OPERAND);
};

const fillOut = (out: Candidates, at: number): void => {
  ARGS.add(ARG.addrs).writePointer(bufPtr(out.addrs));
  ARGS.add(ARG.vals).writePointer(bufPtr(out.vals));
  ARGS.add(ARG.firsts).writePointer(bufPtr(out.firsts));
  ARGS.add(ARG.at).writeU64(at);
  ARGS.add(ARG.cap).writeU64(out.cap);
};

const run = (fn: KernelFn): KernelOutcome => {
  let fault = false;
  try {
    fn(ARGS);
  } catch {
    // the stolen access violation: progress/at in the block point at the faulting element (S4 §9.4)
    fault = true;
  }
  return {
    at: ARGS.add(ARG.at).readU64().toNumber(),
    progress: ARGS.add(ARG.progress).readU64().toNumber(),
    fault,
  };
};

let compileError: string | null = null;
/** Why the CModule kernels are unavailable (null when compiled or not tried yet); diagnostics and tests. */
export const scanKernelCompileError = (): string | null => compileError;

const compile = (): readonly KernelFn[] | null => {
  if (pinned === null) {
    try {
      const module = new CModule(SCAN_KERNEL_SOURCE);
      const fns = SCAN_KERNEL_SYMBOLS.map(
        (name) =>
          new NativeFunction(module[name] as NativePointer, "void", ["pointer"], {
            exceptions: "steal",
            scheduling: "exclusive",
          }),
      );
      pinned = { module, fns };
    } catch (e) {
      compileError = String(e).slice(0, 512);
      return null;
    }
  }
  return pinned.fns.map((f) => (args: NativePointer) => f(args));
};

/** Native kernels when TinyCC compiles them, else the JS reference over `read`. */
export function createScanKernels(read: (va: number, len: number) => Uint8Array | null): ScanKernels {
  const fns = compile();
  const [cmpFn, nextFn, snapFn] = fns ?? [];
  if (cmpFn === undefined || nextFn === undefined || snapFn === undefined) return createReferenceKernels(read);
  return {
    native: true,
    cmp: (k, c) => {
      fillSpec(k);
      fillOut(c.out, c.at);
      ARGS.add(ARG.p).writePointer(ptr(c.va));
      ARGS.add(ARG.len).writeU64(c.len);
      ARGS.add(ARG.avail).writeU64(c.avail);
      ARGS.add(ARG.progress).writeU64(c.progress);
      return run(cmpFn);
    },
    next: (k, c) => {
      fillSpec(k);
      fillOut(c.store, c.kept);
      ARGS.add(ARG.progress).writeU64(c.progress);
      ARGS.add(ARG.end).writeU64(c.end);
      return run(nextFn);
    },
    snap: (k, c) => {
      fillSpec(k);
      fillOut(c.out, c.at);
      ARGS.add(ARG.p).writePointer(ptr(c.va));
      ARGS.add(ARG.snap).writePointer(bufPtr(c.snap).add(c.snapOff));
      ARGS.add(ARG.len).writeU64(c.len);
      ARGS.add(ARG.avail).writeU64(c.avail);
      ARGS.add(ARG.progress).writeU64(c.progress);
      return run(snapFn);
    },
  };
}
