import type { Attribution, CallStatus, RawBatchColumns, StatusCode } from "../../shared/callPlan.js";
import { hexToBytes, type Hex } from "../../shared/hex.js";
import { codecDecode } from "./codecs.js";
import { floatDisplay, hexOf, isSignedType, maskTo, SCALAR_WIDTH, signedOf } from "./floatBits.js";
import { elementTypeOf, type BufferInput, type FieldType } from "./normalize.js";
import type { CallOutcomeColumns, CallPlan, CallScalarType, TypedValue } from "./types.js";

/**
 * Outcome decoding (S5 §7.5), shared by the live leg (agent RawBatchColumns) and the emulator leg (bridge batch
 * columns): status codes -> CallStatus, return bits per the plan, out-buffer fields codec-decoded, faults, and the
 * FP control state after each call. Display values never replace bits.
 */
export const STATUS_OF: { readonly [S in StatusCode]: CallStatus } = {
  ok: "returned",
  fault: "fault",
  cpu: "cpu_exception",
  inv: "invalid_instruction",
  unsup: "unsupported_instruction",
  imp: "unhandled_import",
  sys: "syscall",
  raised: "raised",
  term: "terminated",
  budget: "budget_exhausted",
  timeout: "timeout",
  cancel: "cancelled",
  eng: "engine_error",
};

/** MXCSR status flags (bits 0..5) are outcome noise; comparisons and fp_after keep the control bits only (S5-D9). */
export const MXCSR_CONTROL_MASK = 0xffc0n;

/** TypedValue (S5 §7.5): bits are the type-width pattern; value per S6 §2.3. */
export const typedValue = (type: CallScalarType, lane: bigint): TypedValue => {
  const width = SCALAR_WIDTH[type];
  const bits = maskTo(lane, width);
  let value: TypedValue["value"];
  if (type === "f32" || type === "f64") value = floatDisplay(type, bits);
  else if (type === "bool") value = bits !== 0n;
  else if (type === "ptr") value = hexOf(bits);
  else if (type === "i64") value = signedOf(bits, 8).toString();
  else if (type === "u64") value = bits.toString();
  else value = Number(isSignedType(type) ? signedOf(bits, width) : bits);
  return { type, bits: hexOf(bits), value };
};

/** Field layout of the out buffers (the CallPlan carries only patched fields; decoding needs every declared one). */
export interface OutField {
  readonly name: string;
  readonly offset: number;
  readonly type: FieldType;
  readonly count: number;
}
export type OutLayout = ReadonlyMap<string, readonly OutField[]>;

/** Declared scalar/array fields of every buffer the plan reads back (out buffers and a via-rax struct return). */
export const outLayout = (plan: CallPlan, buffers: readonly BufferInput[]): OutLayout => {
  const reads = new Set(plan.buffers.filter((b) => b.out).map((b) => b.name));
  if (plan.returns.kind === "struct") reads.add(plan.returns.buffer);
  const layout = new Map<string, OutField[]>();
  for (const buffer of buffers) {
    if (!reads.has(buffer.name)) continue;
    layout.set(
      buffer.name,
      buffer.fields
        .filter((f) => f.type !== "ptr_to")
        .map((f) => ({
          name: f.name,
          offset: f.offset,
          type: f.type,
          count: f.type.endsWith("[]") ? (f.count ?? 1) : 1,
        })),
    );
  }
  return layout;
};

/**
 * Layout for callers that hold only a CallPlan (the frozen OracleBatchRequest carries no field list): every out
 * buffer reads back as one `<buffer>.__bytes` u8[] field, so legs still compare out buffers bit for bit.
 */
export const RAW_BYTES_FIELD = "__bytes";
export const rawOutLayout = (plan: CallPlan): OutLayout =>
  new Map(
    plan.buffers
      .filter((b) => b.out)
      .map((b) => [b.name, [{ name: RAW_BYTES_FIELD, offset: 0, type: "u8[]" as const, count: b.size }]] as const),
  );

const readLE = (bytes: Uint8Array, offset: number, width: number): bigint => {
  let v = 0n;
  for (let i = width - 1; i >= 0; i--) v = (v << 8n) | BigInt(bytes[offset + i] ?? 0);
  return v;
};

/** Return bits per the plan (type-width pattern); null for void and hidden-pointer struct returns. */
export const returnBits = (returns: CallPlan["returns"], rax: bigint, xmm0lo: bigint): bigint | null => {
  switch (returns.kind) {
    case "void":
      return null;
    case "f32":
      return xmm0lo & 0xffff_ffffn;
    case "f64":
      return xmm0lo & 0xffff_ffff_ffff_ffffn;
    case "int":
      return returns.type === "bool" ? ((rax & 0xffn) !== 0n ? 1n : 0n) : maskTo(rax, returns.width);
    case "struct":
      return returns.via === "rax" ? maskTo(rax, returns.size as 1 | 2 | 4 | 8) : null;
  }
};

/** Out-buffer bytes of vector i: the read-back hex, or the RAX bytes of a struct returned in RAX. */
export const outBytes = (plan: CallPlan, raw: RawBatchColumns, buffer: string, i: number): Uint8Array | null => {
  if (plan.returns.kind === "struct" && plan.returns.via === "rax" && plan.returns.buffer === buffer) {
    const rax = BigInt(raw.rax[i] ?? "0x0");
    const bytes = new Uint8Array(plan.returns.size);
    for (let k = 0; k < bytes.length; k++) bytes[k] = Number((rax >> BigInt(8 * k)) & 0xffn);
    return bytes;
  }
  const hex = raw.out[buffer]?.[i];
  return hex === undefined ? null : hexToBytes(hex.toLowerCase());
};

const fieldBits = (plan: CallPlan, buffer: string, field: OutField, bytes: Uint8Array): bigint | bigint[] => {
  const element = elementTypeOf(field.type) ?? "u64";
  const width = SCALAR_WIDTH[element];
  const codec = plan.buffers.find((b) => b.name === buffer)?.codecs.find((c) => c.field === field.name);
  const one = (offset: number): bigint => {
    const stored = readLE(bytes, offset, width);
    return codec === undefined ? stored : codecDecode(codec.kind, codec.key, stored, codec.width);
  };
  if (!field.type.endsWith("[]")) return one(field.offset);
  return Array.from({ length: field.count }, (_, k) => one(field.offset + k * width));
};

export interface LiveFault {
  readonly index: number;
  readonly type: string;
  readonly module: string | null;
  readonly rva: Hex | null;
  /** NTSTATUS of the exception (refines the CPU-exception cause: privileged vs invalid opcode, x87 vs SIMD) */
  readonly code?: Hex | null;
}

/**
 * Review fix EMU-3 (S5 §9.3.2): a live exception the CPU raised for the instruction itself is the same event the
 * emulator reports as cpu_exception/<cause>, so it gets that status and the bridge's cause name (#DE div_error, #UD
 * ud, #GP gp for a privileged instruction, #BP breakpoint, #MF x87_fp, #XM simd_fp). Memory faults stay `fault`.
 * Null: not a CPU exception.
 */
export const cpuExceptionCause = (type: string, code: Hex | null | undefined): string | null => {
  const ntstatus = code === null || code === undefined ? null : Number(BigInt(code) & 0xffff_ffffn);
  switch (type) {
    case "arithmetic":
      if (ntstatus !== null && ntstatus >= 0xc000_008d && ntstatus <= 0xc000_0093) return "x87_fp";
      if (ntstatus === 0xc000_02b4 || ntstatus === 0xc000_02b5) return "simd_fp";
      return "div_error";
    case "illegal-instruction":
      return ntstatus === 0xc000_0096 ? "gp" : "ud";
    case "breakpoint":
      return "breakpoint";
    default:
      return null;
  }
};

/**
 * decodeOutcome(plan, raw) -> CallOutcomeColumns for the vectors [offset, offset + completed). Not-returned vectors
 * carry return bits "0x0" (their status says why); live faults are target-attributed.
 */
export const decodeOutcome = (
  plan: CallPlan,
  raw: RawBatchColumns,
  offset: number,
  layout: OutLayout,
  faults: readonly LiveFault[] = [],
): CallOutcomeColumns => {
  const count = raw.completed;
  const status = raw.status.slice(0, count).map((code) => STATUS_OF[code]);
  // EMU-3: a caught CPU exception is cpu_exception (the emulator's family), not a generic fault
  const causes = new Map<number, string>();
  for (const f of faults) {
    const cause = cpuExceptionCause(f.type, f.code);
    const k = f.index - offset;
    if (cause === null || k < 0 || k >= count || status[k] !== "fault") continue;
    status[k] = "cpu_exception";
    causes.set(f.index, cause);
  }
  const ret =
    plan.returns.kind === "void" || (plan.returns.kind === "struct" && plan.returns.via === "hidden")
      ? null
      : Array.from({ length: count }, (_, i) => {
          if (status[i] !== "returned") return "0x0" as Hex;
          return hexOf(returnBits(plan.returns, BigInt(raw.rax[i] ?? "0x0"), BigInt(raw.xmm0lo[i] ?? "0x0")) ?? 0n);
        });
  const fields: Record<string, Hex[] | Hex[][]> = {};
  for (const [buffer, declared] of layout)
    for (const field of declared) {
      const cells = Array.from({ length: count }, (_, i) => {
        const bytes = outBytes(plan, raw, buffer, i);
        const bits = bytes === null ? 0n : fieldBits(plan, buffer, field, bytes);
        return typeof bits === "bigint" ? hexOf(bits) : bits.map(hexOf);
      });
      fields[`${buffer}.${field.name}`] = cells as Hex[] | Hex[][];
    }
  const attribution: (Attribution | null)[] = status.map((s) => (s === "returned" ? null : "target"));
  return {
    count,
    offset,
    status,
    attribution,
    ret,
    fields,
    faults: faults.map((f) => ({
      index: f.index,
      status: status[f.index - offset] ?? "fault",
      attribution: "target" as const,
      cause: causes.get(f.index) ?? f.type,
      site: { module: f.module, rva: f.rva },
    })),
    fp_after: {
      mxcsr_control: raw.mxcsrOut.slice(0, count).map((m) => hexOf(BigInt(m) & MXCSR_CONTROL_MASK)),
      fpcw: raw.fpcwOut.slice(0, count).map((f) => hexOf(BigInt(f))),
    },
  };
};

/** Typed display of one decoded field cell (scalar or array). */
export const typedField = (type: FieldType, cell: Hex | readonly Hex[]): TypedValue | TypedValue[] => {
  const element = elementTypeOf(type) ?? "u64";
  return typeof cell === "string"
    ? typedValue(element, BigInt(cell))
    : cell.map((bits) => typedValue(element, BigInt(bits)));
};

/** The return's scalar type for display (struct returns in RAX display as raw u64-style bits). */
export const returnType = (returns: CallPlan["returns"]): CallScalarType | null => {
  switch (returns.kind) {
    case "void":
      return null;
    case "f32":
    case "f64":
      return returns.kind;
    case "int":
      return returns.type;
    case "struct":
      return returns.via === "rax"
        ? returns.size === 8
          ? "u64"
          : returns.size === 4
            ? "u32"
            : returns.size === 2
              ? "u16"
              : "u8"
        : null;
  }
};
