import { classifyWin64, planToWire } from "../../domain/callModel/classify.js";
import { outLayout, type OutLayout } from "../../domain/callModel/decode.js";
import { SCALAR_WIDTH } from "../../domain/callModel/floatBits.js";
import { generateWindow, type GenerateInput } from "../../domain/callModel/generators.js";
import {
  batchColumns,
  collectAddressExprs,
  encodeColumns,
  fieldColumnName,
  finalizeVectors,
  normalizeScalar,
  singleCallColumns,
  slotColumnName,
  splitElements,
  typeColumns,
  type BufferInput,
  type ColumnBits,
  type ColumnInput,
  type ScalarInput,
  type SignatureInput,
} from "../../domain/callModel/normalize.js";
import type { CallPlan, CallScalarType, NormalizedVectors } from "../../domain/callModel/types.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { inputError } from "../../domain/errors/constructors.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { PlanWire, VectorsWire } from "../../shared/callPlan.js";
import { bytesToHex, formatHex, type Hex } from "../../shared/hex.js";

/**
 * The shared call model on the emulation side (S5 §7; DESIGN §5.6): request columns (single `args`/`fields`, batch
 * `vectors`, seeded `generate`) -> every AddrExpr in ptr positions (resolved by the caller in its leg) -> Win64
 * classification (WP-CALL's classifyWin64) -> typed, codec-encoded vectors of this call's window -> the executor plan
 * (planToWire). emu_call and diff_function's emulation leg both build their plans here; the live leg lowers the SAME
 * classified plan through OracleCallPort (planToAgent), so the legs execute identical register plans.
 */
export interface CallModelRequest {
  readonly signature: SignatureInput;
  readonly buffers: readonly BufferInput[];
  readonly args?: readonly (ScalarInput | null)[] | undefined;
  readonly fields?: Readonly<Record<string, ScalarInput>> | undefined;
  readonly vectors?:
    | {
        readonly count?: number | undefined;
        readonly columns?: Readonly<Record<string, readonly ScalarInput[]>> | undefined;
      }
    | undefined;
  readonly generate?: GenerateInput | undefined;
  readonly vector_offset: number;
}

/** generate: rows materialized per emulation call; the rest continues with vector_offset. */
const EMU_GENERATE_WINDOW = 100_000;

export const invalid = (operation: string, path: string, message: string): BeaError =>
  inputError(operation, [{ path, reason: "invalid_value", message }]);

/** Columns the request supplies (generated columns are supplied with no cells yet). */
export const requestColumns = (request: CallModelRequest, operation: string): Result<ColumnInput, BeaError> => {
  if (request.generate !== undefined) {
    const names = Object.keys(request.generate.columns);
    return ok({ count: 0, columns: Object.fromEntries(names.map((n) => [n, []])), paths: {}, indexed: true });
  }
  const columns =
    request.vectors !== undefined
      ? batchColumns(request.vectors)
      : singleCallColumns(request.signature, request.args ?? undefined, request.fields);
  return columns.ok ? columns : err(inputError(operation, columns.error));
};

const ptrColumns = (request: CallModelRequest): Set<string> => {
  const out = new Set<string>();
  request.signature.args.forEach((slot, i) => {
    if (slot.type === "ptr") out.add(slotColumnName(slot, i));
  });
  for (const buffer of request.buffers)
    for (const field of buffer.fields) if (field.type === "ptr") out.add(fieldColumnName(buffer.name, field.name));
  return out;
};

/** Every AddrExpr in ptr positions: slot/field defaults, column cells, generate grids and constants. */
export const requestAddressExprs = (request: CallModelRequest, columns: ColumnInput): string[] => {
  const found = new Set(collectAddressExprs(request.signature, request.buffers, columns));
  const ptr = ptrColumns(request);
  for (const [name, dist] of Object.entries(request.generate?.columns ?? {})) {
    if (!ptr.has(name)) continue;
    const texts =
      dist.dist === "grid"
        ? splitElements(dist.values ?? "")
        : dist.dist === "constant"
          ? [String(dist.value ?? "")]
          : [];
    for (const text of texts) {
      const n = normalizeScalar("ptr", text);
      if (n.ok && n.value.kind === "address") found.add(n.value.expr);
    }
  }
  return [...found].sort();
};

export interface ClassifiedRequest {
  readonly plan: CallPlan;
  readonly arrayDefaults: ReadonlyMap<string, readonly bigint[]>;
  readonly layout: OutLayout;
}

export const classifyRequest = (
  request: CallModelRequest,
  columns: ColumnInput,
  initFrom: ReadonlyMap<string, Uint8Array>,
  resolve: (expr: string) => bigint | undefined,
  operation: string,
): Result<ClassifiedRequest, BeaError> => {
  const classified = classifyWin64({
    signature: request.signature,
    buffers: request.buffers,
    supplied: new Set(Object.keys(columns.columns)),
    initFrom,
    resolve,
  });
  if (!classified.ok) return err(inputError(operation, classified.error));
  return ok({ ...classified.value, layout: outLayout(classified.value.plan, request.buffers) });
};

const windowBits = (bits: ColumnBits, from: number): ColumnBits => {
  const columns = new Map<string, readonly bigint[] | readonly (readonly bigint[])[]>();
  for (const [name, cells] of bits.columns) columns.set(name, cells.slice(from));
  return { count: Math.max(0, bits.count - from), columns };
};

export interface WindowVectors {
  /** the vectors of this call: cell 0 is the absolute vector `offset` */
  readonly vectors: NormalizedVectors;
  readonly offset: number;
  /** vectors the request defines in total */
  readonly total: number;
  /** generate only: the window stopped before `total` */
  readonly windowCapped: boolean;
}

export const requestVectors = (
  request: CallModelRequest,
  classified: ClassifiedRequest,
  columns: ColumnInput,
  resolve: (expr: string) => bigint | undefined,
  operation: string,
  window = EMU_GENERATE_WINDOW,
): Result<WindowVectors, BeaError> => {
  const offset = request.vector_offset;
  const { plan, arrayDefaults } = classified;
  if (request.generate !== undefined) {
    const generated = generateWindow(plan, request.generate, { from: offset, to: offset + window }, resolve);
    if (!generated.ok) return err(inputError(operation, generated.error));
    const { total, bits, specDigest } = generated.value;
    if (offset >= total)
      return err(invalid(operation, "vector_offset", `vector_offset is past the last vector (${String(total)}).`));
    const vectors = finalizeVectors(encodeColumns(plan, bits), {
      kind: "generated",
      seed: request.generate.seed,
      spec_digest: specDigest,
    });
    return ok({ vectors, offset, total, windowCapped: offset + bits.count < total });
  }
  const typed = typeColumns(plan, columns, resolve, arrayDefaults);
  if (!typed.ok) return err(inputError(operation, typed.error));
  if (offset >= typed.value.count)
    return err(
      invalid(operation, "vector_offset", `vector_offset is past the last vector (${String(typed.value.count)}).`),
    );
  const vectors = finalizeVectors(encodeColumns(plan, windowBits(typed.value, offset)), { kind: "inline" });
  return ok({ vectors, offset, total: typed.value.count, windowCapped: false });
};

/** The executor's view of a vector window (cells stay 64-bit-lane hex). */
export const wireVectors = (
  vectors: NormalizedVectors,
  offset: number,
  from = 0,
  count = vectors.count,
): VectorsWire => {
  const columns: Record<string, Hex[] | Hex[][]> = {};
  for (const [name, cells] of Object.entries(vectors.columns))
    columns[name] = cells.slice(from, from + count) as Hex[] | Hex[][];
  return { offset: offset + from, count, columns };
};

export const lowerPlan = (
  plan: CallPlan,
  target: Hex,
  resolve: (expr: string) => bigint | undefined,
  operation: string,
): Result<PlanWire, BeaError> => {
  const wire = planToWire(plan, target, resolve);
  return wire.ok ? wire : err(inputError(operation, wire.error));
};

/**
 * Little-endian bytes of a typed scalar (state.writes / emu_open patches given as type + value). ptr AddrExprs are
 * resolved by the caller first; the 64-bit lane is truncated to the type width.
 */
export const scalarBytes = (
  type: CallScalarType,
  value: ScalarInput,
  resolve: (expr: string) => bigint | undefined,
): Result<string, string> => {
  const normalized = normalizeScalar(type, value);
  if (!normalized.ok) return normalized;
  const bits = normalized.value.kind === "bits" ? normalized.value.bits : resolve(normalized.value.expr);
  if (bits === undefined) return err("The address expression could not be resolved in this session.");
  const width = SCALAR_WIDTH[type];
  const bytes = new Uint8Array(width);
  for (let i = 0; i < width; i++) bytes[i] = Number((bits >> BigInt(8 * i)) & 0xffn);
  return ok(bytesToHex(bytes));
};

/** "0x…" -> canonical lowercase hex (inputs accept any case and leading zeros). */
export const canonical = (text: string): Hex => formatHex(BigInt(text));
