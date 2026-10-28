import { canonicalDigest } from "../canonical.js";
import type { InputIssue } from "../errors/beaError.js";
import { err, ok, type Result } from "../result.js";
import type { ArgReg, BufferWire, GprName, PlanWire, ReturnWire, SlotWire } from "../../shared/callPlan.js";
import { bytesToHex, type Hex } from "../../shared/hex.js";
import { codecEncode, codecKeyProblem, type CodecWidth } from "./codecs.js";
import { hexOf, SCALAR_WIDTH } from "./floatBits.js";
import {
  elementTypeOf,
  fieldColumnName,
  isBufferSlot,
  normalizeScalar,
  slotColumnName,
  splitElements,
  type AddressBits,
  type BufferInput,
  type FieldInput,
  type SignatureInput,
} from "./normalize.js";
import type { CallPlan, CallScalarType, NormalizedBuffer } from "./types.js";

/**
 * Win64 positional classification (S5 §7.4): argument i uses RCX/RDX/R8/R9 or XMM0–3 BY POSITION; position ≥ 4 is
 * stack slot p−4 at [rsp+0x28+8(p−4)] on entry; a struct return wider than 8 bytes (or not 1/2/4/8) is a hidden
 * pointer at position 0; variadic floats in registers are duplicated into the GPR; byval buffers of 1/2/4/8 bytes
 * travel as integers, larger ones as a pointer to a hidden copy. The plan is leg-independent: ptr AddrExpr slot
 * defaults stay `address-const` and each leg resolves them when lowering (planToWire/planToAgent).
 */
const GPRS: readonly GprName[] = ["rcx", "rdx", "r8", "r9"];
const XMMS: readonly ArgReg[] = ["xmm0", "xmm1", "xmm2", "xmm3"];
/** The CallBlock holds 4 register positions + 28 stack qwords (0xA0..0x180, DESIGN §5.3.1). */
export const MAX_CALL_POSITIONS = 32;
export const SYNTHETIC_RETURN_BUFFER = "__ret";
export const byvalCopyName = (position: number): string => `__byval_${String(position)}`;

export interface ClassifyInput {
  readonly signature: SignatureInput;
  readonly buffers: readonly BufferInput[];
  /** columns the vectors supply per vector; every other slot/field takes its default (else zero) as a constant */
  readonly supplied: ReadonlySet<string>;
  /** CI-I2: init_from bytes, read ONCE per call (diff: once per diff) and used as the template of every vector/leg */
  readonly initFrom?: ReadonlyMap<string, Uint8Array>;
  /** AddrExpr defaults of ptr buffer fields (resolved by the caller in the current leg) */
  readonly resolve?: AddressBits;
}
export interface Classified {
  readonly plan: CallPlan;
  /** supplied array columns: the field default's elements (missing cell elements fall back to these, else 0) */
  readonly arrayDefaults: ReadonlyMap<string, readonly bigint[]>;
}

type Slot = CallPlan["slots"][number];
type ColumnDecl = CallPlan["columns"][number];

interface Work {
  readonly issues: InputIssue[];
  readonly buffers: NormalizedBuffer[];
  readonly byName: Map<string, NormalizedBuffer>;
  readonly known: Map<string, ColumnDecl>;
  readonly arrayDefaults: Map<string, readonly bigint[]>;
}

const issue = (path: string, message: string, reason: InputIssue["reason"] = "invalid_value"): InputIssue => ({
  path,
  reason,
  message,
});

const writeLE = (bytes: Uint8Array, offset: number, width: number, bits: bigint): void => {
  for (let i = 0; i < width; i++) bytes[offset + i] = Number((bits >> BigInt(8 * i)) & 0xffn);
};

const initialBytes = (
  buffer: BufferInput,
  path: string,
  work: Work,
  initFrom: ClassifyInput["initFrom"],
): Uint8Array => {
  const bytes = new Uint8Array(buffer.size);
  if (buffer.init_hex !== undefined) {
    if (buffer.init_hex.length / 2 > buffer.size)
      work.issues.push(
        issue(`${path}.init_hex`, `init_hex is longer than the buffer (${String(buffer.size)} bytes).`, "out_of_range"),
      );
    else
      for (let i = 0; i < buffer.init_hex.length / 2; i++)
        bytes[i] = Number.parseInt(buffer.init_hex.slice(2 * i, 2 * i + 2), 16);
  } else if (buffer.init_fill !== undefined) bytes.fill(buffer.init_fill);
  else if (buffer.init_from !== undefined) {
    const copied = initFrom?.get(buffer.name);
    if (copied?.length !== buffer.size)
      work.issues.push(issue(`${path}.init_from`, "The init_from bytes were not read for this buffer."));
    else bytes.set(copied);
  }
  return bytes;
};

const fieldWidth = (field: FieldInput): CodecWidth => {
  const element = elementTypeOf(field.type);
  return element === null ? 8 : SCALAR_WIDTH[element];
};

/** A non-supplied field default goes into the template (codec applied); supplied arrays keep it as the fallback. */
const applyFieldDefault = (
  ctx: { buffer: BufferInput; field: FieldInput; path: string; template: Uint8Array; supplied: boolean },
  codec: { kind: "xor" | "add" | "mul"; key: bigint } | null,
  work: Work,
  resolve: AddressBits | undefined,
): void => {
  const { field, path } = ctx;
  const element = elementTypeOf(field.type);
  if (element === null || field.default === undefined) return;
  const width = SCALAR_WIDTH[element];
  const isArray = field.type.endsWith("[]");
  const texts = isArray ? splitElements(field.default) : [field.default];
  const count = isArray ? (field.count ?? 1) : 1;
  if (texts.length > count) {
    work.issues.push(issue(`${path}.default`, `At most ${String(count)} default elements.`, "out_of_range"));
    return;
  }
  const values: bigint[] = [];
  for (const [i, text] of texts.entries()) {
    const normalized = normalizeScalar(element, text);
    if (!normalized.ok) {
      work.issues.push(
        issue(`${path}.default`, isArray ? `Element ${String(i)}: ${normalized.error}` : normalized.error),
      );
      return;
    }
    const bits = normalized.value.kind === "bits" ? normalized.value.bits : resolve?.(normalized.value.expr);
    if (bits === undefined) {
      work.issues.push(issue(`${path}.default`, "The address expression could not be resolved in this session."));
      return;
    }
    values.push(bits);
  }
  if (ctx.supplied) {
    if (isArray) work.arrayDefaults.set(fieldColumnName(ctx.buffer.name, field.name), values);
    return;
  }
  values.forEach((bits, i) => {
    const stored = codec === null ? bits : codecEncode(codec.kind, codec.key, bits, width);
    writeLE(ctx.template, field.offset + i * width, width, stored);
  });
};

const normalizeBuffer = (
  buffer: BufferInput,
  index: number,
  input: ClassifyInput,
  userNames: ReadonlySet<string>,
  work: Work,
): void => {
  const path = `buffers[${String(index)}]`;
  const template = initialBytes(buffer, path, work, input.initFrom);
  const columns: NormalizedBuffer["columns"][number][] = [];
  const ptrFields: NormalizedBuffer["ptrFields"][number][] = [];
  const codecs: NormalizedBuffer["codecs"][number][] = [];
  const fieldNames = new Set<string>();
  buffer.fields.forEach((field, fi) => {
    const fpath = `${path}.fields[${String(fi)}]`;
    if (fieldNames.has(field.name))
      work.issues.push(issue(`${fpath}.name`, "Field names must be unique within a buffer."));
    fieldNames.add(field.name);
    const width = fieldWidth(field);
    const count = field.type.endsWith("[]") ? (field.count ?? 1) : 1;
    if (field.offset + width * count > buffer.size) {
      work.issues.push(
        issue(`${fpath}.offset`, `The field ends past the buffer (${String(buffer.size)} bytes).`, "out_of_range"),
      );
      return;
    }
    if (field.type === "ptr_to") {
      if (field.buffer === undefined || !userNames.has(field.buffer))
        work.issues.push(issue(`${fpath}.buffer`, "ptr_to must name one of buffers[].name."));
      else ptrFields.push({ offset: field.offset, buffer: field.buffer, plus: field.plus ?? 0 });
      return;
    }
    const column = fieldColumnName(buffer.name, field.name);
    const supplied = input.supplied.has(column);
    let codec: { kind: "xor" | "add" | "mul"; key: bigint } | null = null;
    if (field.codec_kind !== undefined && field.codec_key !== undefined) {
      const key = BigInt(field.codec_key);
      const problem = field.type.endsWith("[]")
        ? "Codecs apply to scalar fields only."
        : codecKeyProblem(field.codec_kind, key, width);
      if (problem !== null) work.issues.push(issue(`${fpath}.codec_key`, problem));
      else {
        codec = { kind: field.codec_kind, key };
        codecs.push({ field: field.name, offset: field.offset, width, kind: field.codec_kind, key });
      }
    }
    if (work.known.has(column)) work.issues.push(issue(`${fpath}.name`, `Column ${column} is defined twice.`));
    work.known.set(column, { name: column, type: field.type, count });
    if (supplied) columns.push({ column, offset: field.offset, width, count });
    applyFieldDefault({ buffer, field, path: fpath, template, supplied }, codec, work, input.resolve);
  });
  const normalized: NormalizedBuffer = {
    name: buffer.name,
    size: buffer.size,
    align: buffer.align,
    placement: buffer.placement,
    template,
    columns,
    ptrFields,
    out: buffer.out,
    codecs,
  };
  work.buffers.push(normalized);
  work.byName.set(buffer.name, normalized);
};

const classifyReturn = (input: ClassifyInput, work: Work): { returns: CallPlan["returns"]; hidden: string | null } => {
  const returns = input.signature.returns;
  if (returns === "void") return { returns: { kind: "void" }, hidden: null };
  if (typeof returns === "string") {
    if (returns === "f32" || returns === "f64") return { returns: { kind: returns }, hidden: null };
    return { returns: { kind: "int", type: returns, width: SCALAR_WIDTH[returns] }, hidden: null };
  }
  const named = returns.buffer;
  if (named !== undefined) {
    const target = work.byName.get(named);
    if (target === undefined)
      work.issues.push(issue("signature.returns.buffer", "returns.buffer must name one of buffers[].name."));
    else if (target.size < returns.size)
      work.issues.push(
        issue("signature.returns.buffer", "The return buffer is smaller than the struct.", "out_of_range"),
      );
  }
  // EMU-13: an MSVC instance method returns every user-defined type indirectly
  const viaRax =
    input.signature.convention !== "msvc_method" &&
    (returns.size === 1 || returns.size === 2 || returns.size === 4 || returns.size === 8);
  const buffer = named ?? SYNTHETIC_RETURN_BUFFER;
  if (viaRax) return { returns: { kind: "struct", size: returns.size, via: "rax", buffer }, hidden: null };
  if (named === undefined) {
    const synthetic: NormalizedBuffer = {
      name: SYNTHETIC_RETURN_BUFFER,
      size: returns.size,
      align: 16,
      placement: "scratch",
      template: new Uint8Array(returns.size),
      columns: [],
      ptrFields: [],
      out: true,
      codecs: [],
    };
    work.buffers.push(synthetic);
    work.byName.set(synthetic.name, synthetic);
  } else {
    const target = work.byName.get(named);
    if (target !== undefined) {
      const index = work.buffers.indexOf(target);
      const forcedOut = { ...target, out: true };
      work.buffers[index] = forcedOut;
      work.byName.set(named, forcedOut);
    }
  }
  return { returns: { kind: "struct", size: returns.size, via: "hidden", buffer }, hidden: buffer };
};

const registerFor = (position: number, isFloat: boolean): { reg: ArgReg; stackIndex?: number } =>
  position < 4
    ? { reg: (isFloat ? XMMS[position] : GPRS[position]) ?? "stack" }
    : { reg: "stack", stackIndex: position - 4 };

const scalarSlotSource = (
  slot: SignatureInput["args"][number] & { readonly type: CallScalarType },
  column: string,
  input: ClassifyInput,
  path: string,
  work: Work,
): Slot["source"] => {
  if (input.supplied.has(column)) return { kind: "column", column, type: slot.type };
  if (slot.default === undefined) return { kind: "const", bits: 0n, type: slot.type };
  const normalized = normalizeScalar(slot.type, slot.default);
  if (!normalized.ok) {
    work.issues.push(issue(`${path}.default`, normalized.error));
    return { kind: "const", bits: 0n, type: slot.type };
  }
  return normalized.value.kind === "bits"
    ? { kind: "const", bits: normalized.value.bits, type: slot.type }
    : { kind: "address-const", expr: normalized.value.expr };
};

const byvalSource = (buffer: NormalizedBuffer, position: number, work: Work): Slot["source"] => {
  if (buffer.size === 1 || buffer.size === 2 || buffer.size === 4 || buffer.size === 8)
    return { kind: "byval", buffer: buffer.name };
  // Win64 passes larger aggregates as a pointer to a caller-made temporary copy.
  const copy: NormalizedBuffer = { ...buffer, name: byvalCopyName(position), out: false, codecs: [] };
  work.buffers.push(copy);
  work.byName.set(copy.name, copy);
  return { kind: "buffer", buffer: copy.name, offset: 0 };
};

const classifySlots = (input: ClassifyInput, hidden: string | null, work: Work): Slot[] => {
  const slots: Slot[] = [];
  // EMU-13: Win64 C (and GCC methods) put the hidden result pointer first; an MSVC instance method keeps `this`
  // (args[0]) in RCX and passes the hidden pointer in RDX
  const method = input.signature.convention === "msvc_method";
  if (method && input.signature.args.length === 0)
    work.issues.push(issue("signature.args", "convention msvc_method needs `this` as args[0] (a ptr or buffer_ptr)."));
  const hiddenPosition = method ? 1 : 0;
  if (hidden !== null)
    slots.push({
      position: hiddenPosition,
      reg: GPRS[hiddenPosition] ?? "rdx",
      source: { kind: "buffer", buffer: hidden, offset: 0 },
    });
  const positionOf = (index: number): number =>
    hidden === null ? index : method ? (index === 0 ? 0 : index + 1) : index + 1;
  input.signature.args.forEach((slot, index) => {
    const path = `signature.args[${String(index)}]`;
    const position = positionOf(index);
    if (position >= MAX_CALL_POSITIONS) {
      work.issues.push(
        issue(
          path,
          `At most ${String(MAX_CALL_POSITIONS)} argument positions (4 registers + 28 stack slots), including a hidden return pointer.`,
          "out_of_range",
        ),
      );
      return;
    }
    if (isBufferSlot(slot)) {
      const buffer = slot.buffer === undefined ? undefined : work.byName.get(slot.buffer);
      if (buffer === undefined || buffer.name.startsWith("__")) {
        work.issues.push(issue(`${path}.buffer`, "buffer must name one of buffers[].name."));
        return;
      }
      const offset = slot.offset ?? 0;
      if (slot.type === "buffer_ptr" && offset > buffer.size)
        work.issues.push(issue(`${path}.offset`, "offset points past the end of the buffer.", "out_of_range"));
      const source =
        slot.type === "buffer_ptr"
          ? { kind: "buffer" as const, buffer: buffer.name, offset }
          : byvalSource(buffer, position, work);
      slots.push({ position, ...registerFor(position, false), source });
      return;
    }
    const scalar = slot as typeof slot & { readonly type: CallScalarType };
    const column = slotColumnName(slot, index);
    if (work.known.has(column)) work.issues.push(issue(`${path}.name`, `Column ${column} is defined twice.`));
    work.known.set(column, { name: column, type: scalar.type, count: 1 });
    const isFloat = scalar.type === "f32" || scalar.type === "f64";
    const register = registerFor(position, isFloat);
    const dup = input.signature.variadic && isFloat && position < 4 ? { dupGpr: GPRS[position] ?? "rcx" } : {};
    slots.push({ position, ...register, ...dup, source: scalarSlotSource(scalar, column, input, path, work) });
  });
  return slots.sort((a, b) => a.position - b.position);
};

/** classifyWin64(signature, buffers, supplied columns) -> leg-independent CallPlan, or every issue found. */
export const classifyWin64 = (input: ClassifyInput): Result<Classified, InputIssue[]> => {
  const work: Work = { issues: [], buffers: [], byName: new Map(), known: new Map(), arrayDefaults: new Map() };
  const userNames = new Set<string>();
  input.buffers.forEach((buffer, index) => {
    if (buffer.name.startsWith("__"))
      work.issues.push(issue(`buffers[${String(index)}].name`, 'Buffer names starting with "__" are reserved.'));
    else if (userNames.has(buffer.name))
      work.issues.push(issue(`buffers[${String(index)}].name`, "Buffer names must be unique."));
    userNames.add(buffer.name);
  });
  input.buffers.forEach((buffer, index) => normalizeBuffer(buffer, index, input, userNames, work));
  const { returns, hidden } = classifyReturn(input, work);
  const slots = classifySlots(input, hidden, work);
  const columns: ColumnDecl[] = [];
  for (const name of [...input.supplied].sort()) {
    const declared = work.known.get(name);
    if (declared === undefined) {
      const valid = [...work.known.keys()].sort();
      work.issues.push(
        issue(
          name,
          valid.length === 0
            ? `Unknown column ${name}: this signature takes no per-vector values.`
            : `Unknown column ${name}; valid columns: ${valid.slice(0, 24).join(", ")}${valid.length > 24 ? ", …" : ""}.`,
        ),
      );
      continue;
    }
    columns.push(declared);
  }
  if (work.issues.length > 0) return err(work.issues.slice(0, 64));
  return ok({ plan: { slots, returns, buffers: work.buffers, columns }, arrayDefaults: work.arrayDefaults });
};

// ---------------------------------------------------------------- lowering

const returnWire = (returns: CallPlan["returns"]): ReturnWire => {
  switch (returns.kind) {
    case "void":
      return { kind: "void" };
    case "int":
      return { kind: "int", width: returns.width };
    case "f32":
    case "f64":
      return { kind: returns.kind };
    case "struct":
      return returns.via === "rax"
        ? { kind: "struct", size: returns.size, via: "rax" }
        : { kind: "struct", size: returns.size, via: "hidden", buffer: returns.buffer };
  }
};

const bufferWire = (buffer: NormalizedBuffer): BufferWire => ({
  name: buffer.name,
  size: buffer.size,
  align: buffer.align,
  placement: buffer.placement,
  template: bytesToHex(buffer.template),
  columns: buffer.columns.map((c) => ({ column: c.column, offset: c.offset, width: c.width, count: c.count })),
  ptrFields: buffer.ptrFields.map((p) => ({ offset: p.offset, buffer: p.buffer, plus: p.plus })),
  out: buffer.out,
});

/**
 * planToWire / planToAgent (S5 §7.4, §9.4): resolve the target and every ptr AddrExpr constant in ONE leg's address
 * space and emit the executor plan. Both executors take the same PlanWire, so the live agent and the bridge run
 * identical lowered plans by construction.
 */
export const planToWire = (plan: CallPlan, target: Hex, resolve: AddressBits): Result<PlanWire, InputIssue[]> => {
  const issues: InputIssue[] = [];
  const slots: SlotWire[] = plan.slots.map((slot) => {
    const base: Omit<SlotWire, "source"> = {
      reg: slot.reg,
      ...(slot.stackIndex === undefined ? {} : { stackIndex: slot.stackIndex }),
      ...(slot.dupGpr === undefined ? {} : { dupGpr: slot.dupGpr }),
    };
    const source = slot.source;
    switch (source.kind) {
      case "column":
        return { ...base, source: { kind: "column", column: source.column } };
      case "const":
        return { ...base, source: { kind: "const", bits: hexOf(source.bits) } };
      case "address-const": {
        const va = resolve(source.expr);
        if (va === undefined)
          issues.push(
            issue(
              `signature.args[${String(slot.position)}].default`,
              "The address expression could not be resolved in this session.",
            ),
          );
        return { ...base, source: { kind: "const", bits: hexOf(va ?? 0n) } };
      }
      case "buffer":
        return { ...base, source: { kind: "buffer", buffer: source.buffer, offset: source.offset } };
      case "byval":
        return { ...base, source: { kind: "byval", buffer: source.buffer } };
    }
  });
  if (issues.length > 0) return err(issues);
  return ok({ target, slots, returns: returnWire(plan.returns), buffers: plan.buffers.map(bufferWire) });
};
export const planToAgent = (plan: CallPlan, target: Hex, resolve: AddressBits): Result<PlanWire, InputIssue[]> =>
  planToWire(plan, target, resolve);

/** Every AddrExpr constant the plan's slots carry (resolved per leg before lowering). */
export const planAddressExprs = (plan: CallPlan): string[] =>
  [...new Set(plan.slots.flatMap((slot) => (slot.source.kind === "address-const" ? [slot.source.expr] : [])))].sort();

/** sha256 of the canonical plan with the target given as module+rva (or va): evidence parameters and diff identity. */
export const planDigest = (
  plan: CallPlan,
  target: { readonly module: string | null; readonly rva: Hex | null; readonly va: Hex },
): string =>
  canonicalDigest({
    target:
      target.module !== null && target.rva !== null
        ? { module: target.module.toLowerCase(), rva: target.rva }
        : { va: target.va },
    slots: plan.slots.map((slot) => ({
      position: slot.position,
      reg: slot.reg,
      ...(slot.stackIndex === undefined ? {} : { stackIndex: slot.stackIndex }),
      ...(slot.dupGpr === undefined ? {} : { dupGpr: slot.dupGpr }),
      source:
        slot.source.kind === "const"
          ? { kind: "const", bits: hexOf(slot.source.bits), type: slot.source.type }
          : { ...slot.source },
    })),
    returns: { ...plan.returns },
    buffers: plan.buffers.map((buffer) => ({
      ...bufferWire(buffer),
      codecs: buffer.codecs.map((c) => ({
        field: c.field,
        offset: c.offset,
        width: c.width,
        kind: c.kind,
        key: hexOf(c.key),
      })),
    })),
    columns: plan.columns.map((c) => ({ ...c })),
  });
