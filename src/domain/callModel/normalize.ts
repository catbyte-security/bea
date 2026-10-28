import { canonicalDigest } from "../canonical.js";
import type { InputIssue } from "../errors/beaError.js";
import { err, ok, type Result } from "../result.js";
import type { Hex } from "../../shared/hex.js";
import { codecEncode, type CodecWidth } from "./codecs.js";
import {
  extendTo64,
  F32_INF,
  F32_QNAN,
  F32_SIGN,
  F64_INF,
  F64_QNAN,
  F64_SIGN,
  f32ToBits,
  f64ToBits,
  hexOf,
  SCALAR_WIDTH,
} from "./floatBits.js";
import type { CallPlan, CallScalarType, NormalizedVectors } from "./types.js";

/**
 * Call-model input normalization (S5 §7.1–7.3 as flattened by D-INT-9). The structural input types below mirror the
 * zod OUTPUT of src/contracts/schemas/callModel.ts (the domain may not import contracts); handlers pass parsed input
 * straight through. Every value becomes raw bits (bigint) here; a "0x…" string is ALWAYS the raw bit pattern of the
 * declared type, floats also take "NaN", "Infinity", "-Infinity", "-0" and decimals, ptr also takes an AddrExpr that
 * each leg resolves in its own address space.
 */
export type ScalarInput = number | string | boolean;
export type ArrayElementType = Exclude<CallScalarType, "ptr" | "bool">;
export type FieldType = CallScalarType | `${ArrayElementType}[]` | "ptr_to";

export interface ArgSlotInput {
  readonly type: CallScalarType | "buffer_ptr" | "buffer_byval";
  readonly name?: string | undefined;
  readonly default?: ScalarInput | undefined;
  readonly buffer?: string | undefined;
  readonly offset?: number | undefined;
}
export type ReturnInput =
  | "void"
  | CallScalarType
  | { readonly type: "struct"; readonly size: number; readonly buffer?: string | undefined };
export interface FieldInput {
  readonly name: string;
  readonly offset: number;
  readonly type: FieldType;
  readonly count?: number | undefined;
  readonly default?: string | undefined;
  readonly buffer?: string | undefined;
  readonly plus?: number | undefined;
  readonly codec_kind?: "xor" | "add" | "mul" | undefined;
  readonly codec_key?: string | undefined;
}
export interface BufferInput {
  readonly name: string;
  readonly size: number;
  readonly align: number;
  readonly placement: "scratch" | "heap";
  readonly init_hex?: string | undefined;
  readonly init_fill?: number | undefined;
  readonly init_from?: string | undefined;
  readonly fields: readonly FieldInput[];
  readonly out: boolean;
}
export interface SignatureInput {
  readonly args: readonly ArgSlotInput[];
  readonly returns: ReturnInput;
  readonly variadic: boolean;
  /**
   * Review fix EMU-13: "msvc_method" = an MSVC/clang-cl C++ instance method: `this` (args[0]) stays in RCX, the
   * hidden result pointer goes to RDX, and EVERY user-defined type is returned through it (even 1/2/4/8-byte ones).
   * Default "c": free functions (and GCC/MinGW methods, whose hidden pointer precedes `this`).
   */
  readonly convention?: "c" | "msvc_method";
}

/** A normalized scalar: raw bits, or an address expression the leg resolves (ptr only). */
export type NormalizedScalar =
  | { readonly kind: "bits"; readonly bits: bigint }
  | { readonly kind: "address"; readonly expr: string };

const HEX_BITS_RE = /^0[xX]([0-9a-fA-F]{1,16})$/u;
const DECIMAL_INT_RE = /^[+-]?\d{1,20}$/u;
const DECIMAL_FLOAT_RE = /^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d{1,4})?$/u;

const RANGE: { readonly [T in CallScalarType]?: readonly [bigint, bigint] } = {
  i8: [-(1n << 7n), (1n << 7n) - 1n],
  i16: [-(1n << 15n), (1n << 15n) - 1n],
  i32: [-(1n << 31n), (1n << 31n) - 1n],
  i64: [-(1n << 63n), (1n << 63n) - 1n],
  u8: [0n, (1n << 8n) - 1n],
  u16: [0n, (1n << 16n) - 1n],
  u32: [0n, (1n << 32n) - 1n],
  u64: [0n, (1n << 64n) - 1n],
  ptr: [0n, (1n << 64n) - 1n],
};

/** "0x…" = the raw bits of the declared type: they must fit its width. */
const rawBits = (type: CallScalarType, digits: string): Result<bigint, string> => {
  const bits = BigInt(`0x${digits}`);
  const width = SCALAR_WIDTH[type];
  if (bits >> BigInt(width * 8) !== 0n)
    return err(`A "0x…" value is the raw bit pattern of ${type} and must fit ${String(width * 8)} bits.`);
  return ok(extendTo64(type, bits));
};

const integerBits = (type: CallScalarType, value: bigint): Result<bigint, string> => {
  const range = RANGE[type];
  if (range !== undefined && (value < range[0] || value > range[1]))
    return err(
      `The value is out of range for ${type} (${String(range[0])}..${String(range[1])}); pass "0x…" bits for raw patterns.`,
    );
  return ok(extendTo64(type, BigInt.asUintN(64, value)));
};

const floatLiteral = (type: "f32" | "f64", text: string): bigint | null => {
  const f32 = type === "f32";
  switch (text) {
    case "NaN":
      return f32 ? F32_QNAN : F64_QNAN;
    case "Infinity":
    case "+Infinity":
      return f32 ? F32_INF : F64_INF;
    case "-Infinity":
      return f32 ? F32_INF | F32_SIGN : F64_INF | F64_SIGN;
    case "-0":
      return f32 ? F32_SIGN : F64_SIGN;
    default:
      return null;
  }
};

const floatBits = (type: "f32" | "f64", value: number): Result<bigint, string> => {
  if (type === "f32" && Number.isFinite(value) && !Number.isFinite(Math.fround(value)))
    return err('The value overflows f32; pass "0x…" bits or "Infinity".');
  return ok(type === "f32" ? f32ToBits(value) : f64ToBits(value));
};

const normalizeBool = (input: ScalarInput): Result<bigint, string> => {
  if (typeof input === "boolean") return ok(input ? 1n : 0n);
  if (input === 0 || input === 1 || input === "0" || input === "1") return ok(BigInt(input));
  if (input === "true" || input === "false") return ok(input === "true" ? 1n : 0n);
  if (typeof input === "string") {
    const hex = HEX_BITS_RE.exec(input);
    if (hex?.[1] !== undefined) return rawBits("bool", hex[1]);
  }
  return err('bool takes true, false, 0, 1 or a "0x…" byte.');
};

const normalizeFloat = (type: "f32" | "f64", input: ScalarInput): Result<bigint, string> => {
  if (typeof input === "boolean")
    return err(`${type} takes a number, a decimal string, "0x…" bits or NaN/Infinity/-Infinity/-0.`);
  if (typeof input === "number") return floatBits(type, input);
  const literal = floatLiteral(type, input.trim());
  if (literal !== null) return ok(literal);
  const hex = HEX_BITS_RE.exec(input.trim());
  if (hex?.[1] !== undefined) return rawBits(type, hex[1]);
  if (DECIMAL_FLOAT_RE.test(input.trim())) return floatBits(type, Number(input.trim()));
  return err(`${type} takes a number, a decimal string, "0x…" bits or NaN/Infinity/-Infinity/-0.`);
};

const normalizeInteger = (type: CallScalarType, input: ScalarInput): Result<bigint, string> => {
  if (typeof input === "boolean") return err("Booleans are accepted only for bool.");
  if (typeof input === "number") {
    if (!Number.isSafeInteger(input))
      return err('Integers given as JSON numbers must be safe integers; pass a decimal or "0x…" string.');
    return integerBits(type, BigInt(input));
  }
  const text = input.trim();
  const hex = HEX_BITS_RE.exec(text);
  if (hex?.[1] !== undefined) return rawBits(type, hex[1]);
  if (DECIMAL_INT_RE.test(text)) return integerBits(type, BigInt(text));
  return err(`${type} takes an integer, a decimal string or "0x…" bits.`);
};

/**
 * normalizeScalar(type, input) -> 64-bit lane bits (S5 §7.2): signed integers sign-extended, everything else
 * zero-extended; ptr strings that are neither "0x…" nor decimal are AddrExprs, resolved per leg.
 */
export const normalizeScalar = (type: CallScalarType, input: ScalarInput): Result<NormalizedScalar, string> => {
  let bits: Result<bigint, string>;
  if (type === "bool") bits = normalizeBool(input);
  else if (type === "f32" || type === "f64") bits = normalizeFloat(type, input);
  else if (
    type === "ptr" &&
    typeof input === "string" &&
    !HEX_BITS_RE.test(input.trim()) &&
    !DECIMAL_INT_RE.test(input.trim())
  ) {
    const expr = input.trim();
    return expr.length >= 2
      ? ok({ kind: "address", expr })
      : err('ptr takes an integer, "0x…" bits or an address expression.');
  } else bits = normalizeInteger(type, input);
  return bits.ok ? ok({ kind: "bits", bits: bits.value }) : bits;
};

/** Element type and count of a field type ("f32[]" -> f32). */
export const elementTypeOf = (type: FieldType): CallScalarType | null =>
  type === "ptr_to" ? null : type.endsWith("[]") ? (type.slice(0, -2) as CallScalarType) : (type as CallScalarType);

/** Comma-separated array cells / defaults; empty text = no elements. */
export const splitElements = (text: string): string[] =>
  text.trim() === "" ? [] : text.split(",").map((e) => e.trim());

// ---------------------------------------------------------------- columns

/** S5 §7.1: a scalar slot's column is its name, otherwise argN (0-based, excluding a hidden return pointer). */
export const slotColumnName = (slot: ArgSlotInput, index: number): string => slot.name ?? `arg${String(index)}`;
export const fieldColumnName = (buffer: string, field: string): string => `${buffer}.${field}`;
export const isBufferSlot = (slot: ArgSlotInput): boolean => slot.type === "buffer_ptr" || slot.type === "buffer_byval";

/** Values of one request before typing: column -> cells (single calls become one-vector batches). */
export interface ColumnInput {
  readonly count: number;
  readonly columns: Readonly<Record<string, readonly ScalarInput[]>>;
  /** input path of each column (issue paths point at the caller's own field) */
  readonly paths: Readonly<Record<string, string>>;
  /** batch columns: issue paths carry the cell index */
  readonly indexed: boolean;
}

/** Single call: positional `args` (null = default) + `fields` overrides -> a one-vector ColumnInput. */
export const singleCallColumns = (
  signature: SignatureInput,
  args: readonly (ScalarInput | null)[] | undefined,
  fields: Readonly<Record<string, ScalarInput>> | undefined,
): Result<ColumnInput, InputIssue[]> => {
  const issues: InputIssue[] = [];
  const columns: Record<string, readonly ScalarInput[]> = {};
  const paths: Record<string, string> = {};
  (args ?? []).forEach((value, index) => {
    if (value === null) return;
    const slot = signature.args[index];
    if (slot === undefined) {
      issues.push({
        path: `args[${String(index)}]`,
        reason: "out_of_range",
        message: `args has more values than signature.args (${String(signature.args.length)}).`,
        maximum: signature.args.length,
      });
      return;
    }
    if (isBufferSlot(slot)) {
      issues.push({
        path: `args[${String(index)}]`,
        reason: "invalid_value",
        message: "This slot passes a buffer; set its content with buffers[].init_* or fields, and use null here.",
      });
      return;
    }
    const column = slotColumnName(slot, index);
    columns[column] = [value];
    paths[column] = `args[${String(index)}]`;
  });
  for (const [column, value] of Object.entries(fields ?? {})) {
    if (columns[column] !== undefined) {
      issues.push({
        path: `fields.${column}`,
        reason: "conflicting_arguments",
        message: "This column is already set by args; give it once.",
      });
      continue;
    }
    columns[column] = [value];
    paths[column] = `fields.${column}`;
  }
  return issues.length > 0 ? err(issues) : ok({ count: 1, columns, paths, indexed: false });
};

/** Batch `vectors`: equal-length columns, or `count` all-default vectors. */
export const batchColumns = (vectors: {
  readonly count?: number | undefined;
  readonly columns?: Readonly<Record<string, readonly ScalarInput[]>> | undefined;
}): Result<ColumnInput, InputIssue[]> => {
  const entries = Object.entries(vectors.columns ?? {});
  const lengths = new Set(entries.map(([, cells]) => cells.length));
  if (lengths.size > 1)
    return err([
      {
        path: "vectors.columns",
        reason: "invalid_value",
        message: `Every column needs the same number of cells (got ${[...lengths].sort((a, b) => a - b).join(", ")}).`,
      },
    ]);
  const length = entries[0]?.[1].length;
  if (length !== undefined && vectors.count !== undefined && vectors.count !== length)
    return err([
      {
        path: "vectors.count",
        reason: "conflicting_arguments",
        message: `count must equal the column length (${String(length)}).`,
      },
    ]);
  const count = length ?? vectors.count ?? 0;
  if (count < 1)
    return err([
      { path: "vectors", reason: "invalid_value", message: "Give at least one vector (columns with cells, or count)." },
    ]);
  const paths: Record<string, string> = {};
  for (const [column] of entries) paths[column] = `vectors.columns.${column}`;
  return ok({ count, columns: Object.fromEntries(entries), paths, indexed: true });
};

// ---------------------------------------------------------------- typed columns

/** Logical (pre-codec) 64-bit-lane bits per column: scalars bigint[], arrays bigint[][] (one row per vector). */
export interface ColumnBits {
  readonly count: number;
  readonly columns: ReadonlyMap<string, readonly bigint[] | readonly (readonly bigint[])[]>;
}

/** Resolves a ptr AddrExpr in the current leg (pre-resolved by the caller; undefined = unresolved). */
export type AddressBits = (expr: string) => bigint | undefined;

const scalarCell = (
  type: CallScalarType,
  cell: ScalarInput,
  path: string,
  resolve: AddressBits,
): Result<bigint, InputIssue> => {
  const normalized = normalizeScalar(type, cell);
  if (!normalized.ok) return err({ path, reason: "invalid_value", message: normalized.error });
  if (normalized.value.kind === "bits") return ok(normalized.value.bits);
  const va = resolve(normalized.value.expr);
  return va === undefined
    ? err({ path, reason: "invalid_value", message: "The address expression could not be resolved in this session." })
    : ok(va);
};

/** Elements of one array cell; missing trailing elements take the default's elements, else 0. */
export const arrayCell = (
  element: CallScalarType,
  count: number,
  cell: ScalarInput | undefined,
  fallback: readonly bigint[],
  path: string,
): Result<bigint[], InputIssue> => {
  const texts = cell === undefined ? [] : typeof cell === "string" ? splitElements(cell) : [cell];
  if (texts.length > count)
    return err({ path, reason: "out_of_range", message: `At most ${String(count)} elements.`, maximum: count });
  const out: bigint[] = [];
  for (let i = 0; i < count; i++) {
    const text = texts[i];
    if (text === undefined || text === "") {
      out.push(fallback[i] ?? 0n);
      continue;
    }
    const normalized = normalizeScalar(element, text);
    if (!normalized.ok)
      return err({ path, reason: "invalid_value", message: `Element ${String(i)}: ${normalized.error}` });
    if (normalized.value.kind !== "bits")
      return err({ path, reason: "invalid_value", message: "Array elements cannot be address expressions." });
    out.push(normalized.value.bits);
  }
  return ok(out);
};

/**
 * Typed columns of a request against a classified plan (plan.columns lists exactly the supplied columns, with
 * types). Array columns fill missing elements from `arrayDefaults` (the field default), else 0.
 */
export const typeColumns = (
  plan: CallPlan,
  input: ColumnInput,
  resolve: AddressBits,
  arrayDefaults: ReadonlyMap<string, readonly bigint[]>,
): Result<ColumnBits, InputIssue[]> => {
  const issues: InputIssue[] = [];
  const out = new Map<string, readonly bigint[] | readonly (readonly bigint[])[]>();
  for (const column of plan.columns) {
    const cells = input.columns[column.name] ?? [];
    const path = input.paths[column.name] ?? column.name;
    if (column.type.endsWith("[]")) {
      const element = column.type.slice(0, -2) as CallScalarType;
      const rows: bigint[][] = [];
      for (const [i, cell] of cells.entries()) {
        const at = input.indexed ? `${path}[${String(i)}]` : path;
        const row = arrayCell(element, column.count, cell, arrayDefaults.get(column.name) ?? [], at);
        if (row.ok) rows.push(row.value);
        else issues.push(row.error);
      }
      out.set(column.name, rows);
    } else {
      const values: bigint[] = [];
      for (const [i, cell] of cells.entries()) {
        const at = input.indexed ? `${path}[${String(i)}]` : path;
        const bits = scalarCell(column.type as CallScalarType, cell, at, resolve);
        if (bits.ok) values.push(bits.value);
        else issues.push(bits.error);
      }
      out.set(column.name, values);
    }
    if (issues.length >= 32) break;
  }
  return issues.length > 0 ? err(issues) : ok({ count: input.count, columns: out });
};

/**
 * Stored bits: field columns with a codec are encoded (stored = encode(logical), S5 §7.2); everything else passes.
 * Generated and inline vectors both go through here before they reach a leg.
 */
export const encodeColumns = (plan: CallPlan, logical: ColumnBits): ColumnBits => {
  const codecs = new Map<string, { kind: "xor" | "add" | "mul"; key: bigint; width: CodecWidth }>();
  for (const buffer of plan.buffers)
    for (const codec of buffer.codecs)
      codecs.set(fieldColumnName(buffer.name, codec.field), { kind: codec.kind, key: codec.key, width: codec.width });
  const out = new Map<string, readonly bigint[] | readonly (readonly bigint[])[]>();
  for (const [name, cells] of logical.columns) {
    const codec = codecs.get(name);
    out.set(
      name,
      codec === undefined
        ? cells
        : (cells as readonly bigint[]).map((bits) => codecEncode(codec.kind, codec.key, bits, codec.width)),
    );
  }
  return { count: logical.count, columns: out };
};

/** NormalizedVectors (S5 §7.3): hex cells + sha256 digest of JCS({count, columns}) for evidence identity. */
export const finalizeVectors = (bits: ColumnBits, source: NormalizedVectors["source"]): NormalizedVectors => {
  const columns: Record<string, Hex[] | Hex[][]> = {};
  for (const name of [...bits.columns.keys()].sort()) {
    const cells = bits.columns.get(name) ?? [];
    columns[name] = cells.map((cell) => (typeof cell === "bigint" ? hexOf(cell) : cell.map(hexOf))) as Hex[] | Hex[][];
  }
  return {
    count: bits.count,
    columns,
    digest: `sha256:${canonicalDigest({ count: bits.count, columns })}`,
    source,
  };
};

/**
 * Every AddrExpr a request carries in ptr positions (slot defaults, ptr field defaults, ptr column cells), so the
 * caller can resolve them once per leg before the synchronous classification and normalization.
 */
export const collectAddressExprs = (
  signature: SignatureInput,
  buffers: readonly BufferInput[],
  input: ColumnInput,
): string[] => {
  const found = new Set<string>();
  const note = (value: ScalarInput | undefined): void => {
    if (value === undefined) return;
    const normalized = normalizeScalar("ptr", value);
    if (normalized.ok && normalized.value.kind === "address") found.add(normalized.value.expr);
  };
  signature.args.forEach((slot, index) => {
    if (slot.type !== "ptr") return;
    note(slot.default);
    for (const cell of input.columns[slotColumnName(slot, index)] ?? []) note(cell);
  });
  for (const buffer of buffers)
    for (const field of buffer.fields) {
      if (field.type !== "ptr") continue;
      note(field.default);
      for (const cell of input.columns[fieldColumnName(buffer.name, field.name)] ?? []) note(cell);
    }
  return [...found].sort();
};
