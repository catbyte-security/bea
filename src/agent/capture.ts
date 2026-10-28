// =================================================================================================
// src/agent/capture.ts — WP3-AGENT Win64 capture readers (S4 §10.3), shared by hooks (WP7), profiles (WP8), watch
// rows (WP9), overrides (WP12) and crash reports. Slot → source by POSITION (a float 2nd parameter is in xmm1 and
// args[1] is garbage, VERIFIED [ext-frida §3.6]); floats are captured as exact bits from the 16-byte xmm ArrayBuffer;
// stack slots p ≥ 4 at [rsp + 8 + 8p] at entry. Deref chains follow ArgCapture.deref ("last = field offset") and
// return failure cells instead of throwing: null → {e:"null"}, AV → {e:"av"}, a TARGET guard page → {e:"guard"} (never
// touched, A-18); BEA guard pages are read through withBeaGuardsSuspended (CT-I5). QJS context objects have no own
// keys, so registers are always read through explicit name lists.
// =================================================================================================
import type {
  ArgCapture,
  CaptureRegister,
  CrashReport,
  FrameRef,
  Hex,
  RetCapture,
  ValueCell,
  ValueType,
} from "../shared/agentProtocol.js";
import { hex } from "./encode.js";
import { safeReadBytes } from "./memory.js";
import { bytesHex, hexOfBigint, readLeBigint } from "./pure/coreHex.js";
import { bitsFromBytes, cellOfBits, VALUE_TYPE_BYTES } from "./pure/coreScalar.js";
import { CTX, GPR_NAMES, parseContext, slotSource, type GprName, type ParsedContext } from "./pure/coreWin64.js";
import type { AgentCore } from "./state.js";

type X64Context = X64CpuContext;

/** GPRs (+ rip) of a GumJS CpuContext as Hex (explicit names: QJS contexts have no own keys). */
export const capturedGprs = (ctx: CpuContext): Record<GprName, Hex> => {
  const x = ctx as X64Context;
  const out = {} as Record<GprName, Hex>;
  for (const name of GPR_NAMES) out[name] = hex(x[name]);
  return out;
};

/** GPRs plus xmm0..15 (32-digit Hex) for `registers: "all"`. */
export const allRegisters = (ctx: CpuContext): Record<string, Hex> => {
  const x = ctx as X64Context;
  const out: Record<string, Hex> = { ...capturedGprs(ctx) };
  for (let i = 0; i < 16; i++) {
    const ab = (x as unknown as Record<string, ArrayBuffer | undefined>)[`xmm${i}`];
    if (ab !== undefined) out[`xmm${i}`] = xmmText(ab);
  }
  return out;
};

const xmmText = (ab: ArrayBuffer): Hex => {
  const b = new Uint8Array(ab);
  let s = "";
  for (let i = 15; i >= 0; i--) s += (b[i] ?? 0).toString(16).padStart(2, "0");
  return `0x${s}`;
};

/** Decode a CONTEXT at a native pointer (exception nativeContext, UEF ContextRecord); null when unreadable. */
export const readContextAt = (
  p: NativePointer,
): { parsed: ParsedContext; registers: CrashReport["registers"] } | null => {
  try {
    const ab = p.readByteArray(CTX.size);
    if (ab === null) return null;
    const parsed = parseContext(new Uint8Array(ab));
    const registers = {} as CrashReport["registers"];
    for (const name of GPR_NAMES) registers[name] = hexOfBigint(parsed.gpr[name]);
    return { parsed, registers };
  } catch {
    return null;
  }
};

/** A guard-aware stack window from `rsp` (crash reports). */
export const stackWindow = (c: AgentCore, rsp: bigint, bytes: number): { address: Hex; hex: string } | null => {
  if (bytes <= 0 || rsp === 0n) return null;
  const at = ptr(hexOfBigint(rsp));
  const r = safeReadBytes(c, at, Math.min(bytes, 4096), true);
  return r.bytes.length === 0 ? null : { address: hex(at), hex: bytesHex(r.bytes) };
};

/** FrameRef backtrace from a context (ACCURATE return addresses; S4 §10.3). @public */
export const backtraceRefs = (c: AgentCore, ctx: CpuContext, depth: number): FrameRef[] =>
  Thread.backtrace(ctx, Backtracer.ACCURATE)
    .slice(0, Math.min(depth, c.limits.max_backtrace_depth))
    .map((p) => c.modules.frameRef(p));

/** The raw value of a Win64 parameter slot at function entry. */
export type SlotRaw =
  | { readonly kind: "int"; readonly value: NativePointer }
  | { readonly kind: "xmm"; readonly bytes: Uint8Array }
  | { readonly kind: "stack"; readonly bits: bigint | null; readonly address: NativePointer };

export const slotRaw = (
  c: AgentCore,
  ctx: CpuContext,
  args: InvocationArguments,
  slot: number,
  cls: "int" | "float",
  hiddenRetPtr: boolean,
): SlotRaw => {
  const src = slotSource(slot, cls, hiddenRetPtr);
  if (src.kind === "reg") return { kind: "int", value: args[slot + (hiddenRetPtr ? 1 : 0)]! };
  if (src.kind === "xmm") {
    const ab = (ctx as unknown as Record<string, ArrayBuffer>)[`xmm${src.index}`];
    return { kind: "xmm", bytes: new Uint8Array(ab ?? new ArrayBuffer(16)) };
  }
  const address = (ctx as X64Context).rsp.add(src.rspOffset);
  const r = safeReadBytes(c, address, 8, true);
  return { kind: "stack", bits: r.bytes.length === 8 ? readLeBigint(r.bytes, 0, 8) : null, address };
};

const rawBits = (raw: SlotRaw): bigint | null => {
  if (raw.kind === "int") return BigInt(raw.value.toString());
  if (raw.kind === "xmm") return readLeBigint(raw.bytes, 0, 8);
  return raw.bits;
};

const failCell = (e: "av" | "guard" | "null" | "too_deep" | "unsupported", a?: NativePointer): ValueCell =>
  a === undefined ? { e } : { e, a: hex(a) };

/**
 * Follow a deref chain (ArgCapture semantics): v = base; for i < n−1: v = readPointer(v + o_i); final = v + o_{n−1}.
 * Returns the final address or a failure cell.
 */
export const derefChain = (
  c: AgentCore,
  base: NativePointer,
  offsets: readonly number[],
): NativePointer | ValueCell => {
  if (offsets.length > c.limits.max_deref_depth) return failCell("too_deep");
  let v = base;
  for (let i = 0; i < offsets.length - 1; i++) {
    if (v.isNull()) return failCell("null", v);
    const at = v.add(offsets[i]!);
    const r = safeReadBytes(c, at, 8, true);
    if (r.bytes.length < 8) return failCell(r.stop?.reason === "guard-page" ? "guard" : "av", at);
    v = ptr(hexOfBigint(readLeBigint(r.bytes, 0, 8)));
  }
  if (offsets.length > 0 && v.isNull()) return failCell("null", v);
  return offsets.length === 0 ? v : v.add(offsets[offsets.length - 1]!);
};

const STR_UNIT: Partial<Record<ValueType, number>> = { utf8: 1, ansi: 1, utf16: 2 };

/** A value cell read at `address` (strings/bytes bounded by max_len; arrays by count ≤ 64). */
export const readCellAt = (
  c: AgentCore,
  address: NativePointer,
  type: ValueType,
  count = 1,
  maxLen?: number,
): ValueCell => {
  if (address.isNull()) return failCell("null", address);
  const width = VALUE_TYPE_BYTES[type];
  if (width === null) return readTextCell(c, address, type, maxLen);
  const n = Math.max(1, Math.min(count, 64));
  const r = safeReadBytes(c, address, width * n, true);
  if (r.bytes.length < width) return failCell(r.stop?.reason === "guard-page" ? "guard" : "av", address);
  const cells: ValueCell[] = [];
  for (let i = 0; i + width <= r.bytes.length && cells.length < n; i += width)
    cells.push(cellOfBits(type, bitsFromBytes(r.bytes, i, type)));
  return n === 1 ? cells[0]! : cells;
};

const readTextCell = (c: AgentCore, address: NativePointer, type: ValueType, maxLen?: number): ValueCell => {
  if (type === "bytes") {
    const n = Math.min(maxLen ?? 64, c.limits.max_capture_bytes);
    const r = safeReadBytes(c, address, n, true);
    if (r.bytes.length === 0) return failCell(r.stop?.reason === "guard-page" ? "guard" : "av", address);
    return r.bytes.length < n ? { x: bytesHex(r.bytes), trunc: true } : { x: bytesHex(r.bytes) };
  }
  const unit = STR_UNIT[type] ?? 1;
  const max = Math.min(maxLen ?? 256, c.limits.max_string_chars);
  const r = safeReadBytes(c, address, (max + 1) * unit, true);
  if (r.bytes.length === 0) return failCell(r.stop?.reason === "guard-page" ? "guard" : "av", address);
  let text = "";
  let terminated = false;
  for (let i = 0; i + unit <= r.bytes.length && text.length < max; i += unit) {
    const code = unit === 2 ? r.bytes[i]! | (r.bytes[i + 1]! << 8) : r.bytes[i]!;
    if (code === 0) {
      terminated = true;
      break;
    }
    text += String.fromCharCode(code);
  }
  return terminated ? { s: text } : { s: text, trunc: true };
};

/** The value of a captured register (xmm viewed as `type`; `bytes` = the 16 raw bytes). */
export const registerCell = (ctx: CpuContext, reg: CaptureRegister, type: ValueType): ValueCell => {
  if (reg.startsWith("xmm")) {
    const ab = (ctx as unknown as Record<string, ArrayBuffer>)[reg];
    const bytes = new Uint8Array(ab ?? new ArrayBuffer(16));
    return type === "bytes" ? { x: bytesHex(bytes) } : cellOfBits(type, readLeBigint(bytes, 0, 8));
  }
  const v = (ctx as unknown as Record<string, NativePointer>)[reg]!;
  return cellOfBits(type === "bytes" ? "ptr" : type, BigInt(v.toString()));
};

/** One ArgCapture at enter (or at leave with the base saved at enter). @public */
export const captureArg = (
  c: AgentCore,
  ctx: CpuContext,
  args: InvocationArguments,
  spec: ArgCapture,
  hiddenRetPtr: boolean,
): ValueCell => {
  try {
    if (spec.reg !== undefined) {
      if (spec.deref === undefined || spec.deref.length === 0) return registerCell(ctx, spec.reg, spec.type);
      const base = (ctx as unknown as Record<string, NativePointer>)[spec.reg];
      return base === undefined ? failCell("unsupported") : captureAtBase(c, base, spec);
    }
    const raw = slotRaw(c, ctx, args, spec.slot ?? 0, spec.class ?? "int", hiddenRetPtr);
    const bits = rawBits(raw);
    if (bits === null) return failCell("av", raw.kind === "stack" ? raw.address : undefined);
    if (spec.deref === undefined || spec.deref.length === 0) {
      if (VALUE_TYPE_BYTES[spec.type] !== null) return cellOfBits(spec.type, bits);
      return readCellAt(c, ptr(hexOfBigint(bits)), spec.type, spec.count ?? 1, spec.max_len);
    }
    return captureAtBase(c, ptr(hexOfBigint(bits)), spec);
  } catch (e) {
    c.guards.noteThrown(e);
    return failCell("av");
  }
};

/** Deref from a base pointer and read the final value (shared by arg and ret captures). */
export const captureAtBase = (
  c: AgentCore,
  base: NativePointer,
  spec: {
    readonly type: ValueType;
    readonly deref?: readonly number[];
    readonly count?: number;
    readonly max_len?: number;
  },
): ValueCell => {
  const final = derefChain(c, base, spec.deref ?? []);
  if (!(final instanceof NativePointer)) return final;
  return readCellAt(c, final, spec.type, spec.count ?? 1, spec.max_len);
};

/** The return value at leave: f32/f64 from xmm0 bits, else rax (retval); hidden-return reads the saved rcx. @public */
export const captureRet = (
  c: AgentCore,
  ctx: CpuContext,
  retval: InvocationReturnValue,
  spec: RetCapture,
  savedHiddenRet: NativePointer | null,
): ValueCell => {
  try {
    if (savedHiddenRet !== null) return captureAtBase(c, savedHiddenRet, spec);
    if ((spec.type === "f32" || spec.type === "f64") && (spec.deref === undefined || spec.deref.length === 0))
      return registerCell(ctx, "xmm0", spec.type);
    const v = ptr(retval.toString());
    if (spec.deref === undefined || spec.deref.length === 0) {
      if (VALUE_TYPE_BYTES[spec.type] !== null) return cellOfBits(spec.type, BigInt(v.toString()));
      return readCellAt(c, v, spec.type, spec.count ?? 1, spec.max_len);
    }
    return captureAtBase(c, v, spec);
  } catch (e) {
    c.guards.noteThrown(e);
    return failCell("av");
  }
};
