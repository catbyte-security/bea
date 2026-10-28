import type { CallFunctionInput } from "../../contracts/areas/call.js";
import type { AddressRef } from "../../domain/address/addressRef.js";
import { classifyWin64, planToAgent } from "../../domain/callModel/classify.js";
import { outLayout, type OutLayout } from "../../domain/callModel/decode.js";
import { fpThreadToRead, resolveFpEnv, type FpEnvResolution } from "../../domain/callModel/fpEnv.js";
import { generateWindow } from "../../domain/callModel/generators.js";
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
  type ColumnBits,
  type ColumnInput,
} from "../../domain/callModel/normalize.js";
import type { CallPlan, NormalizedVectors } from "../../domain/callModel/types.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { inputError } from "../../domain/errors/constructors.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { AddressService } from "../../ports/address.js";
import type { LiveSession, OperationContext } from "../../ports/sessions.js";
import { AGENT_LIMIT_DEFAULTS, AGENT_LIMIT_HARD } from "../../shared/agentLimits.js";
import type { CallFunctionParams } from "../../shared/agentProtocol.js";
import type { PlanWire } from "../../shared/callPlan.js";
import { formatHex, type Hex } from "../../shared/hex.js";

/**
 * call_function preparation (DESIGN §6.2 #26): request columns -> address resolution (target, thread_at, every ptr
 * AddrExpr) -> init_from bytes read ONCE through the agent's guard-aware readMemory (CI-I2, CT-I5) -> Win64
 * classification -> typed, codec-encoded vectors of this call's window -> FP environment (D-INT-43) -> live lowering.
 * Everything that can refuse the request happens here, before the first callFunction RPC.
 */
type Input = CallFunctionInput;

/** generate: rows materialized per call; the rest continues with vector_offset. */
export const GENERATE_WINDOW = 65_536;

export interface PreparedCall {
  readonly mode: "single" | "batch";
  readonly target: AddressRef;
  readonly targetVa: bigint;
  readonly plan: CallPlan;
  readonly layout: OutLayout;
  readonly wire: PlanWire;
  readonly vectors: NormalizedVectors;
  readonly offset: number;
  /** vectors the request defines in total (vectors: column length; generate: spec count; single: 1) */
  readonly total: number;
  /** generate only: the window stopped before `total` */
  readonly windowCapped: boolean;
  readonly fp: FpEnvResolution;
  readonly thread: CallFunctionParams["thread"];
}

const invalid = (operation: string, path: string, message: string): BeaError =>
  inputError(operation, [{ path, reason: "invalid_value", message }]);

/** Columns whose type is ptr (only those may carry AddrExprs). */
const ptrColumns = (input: Input): Set<string> => {
  const out = new Set<string>();
  input.signature.args.forEach((slot, i) => {
    if (slot.type === "ptr") out.add(slotColumnName(slot, i));
  });
  for (const buffer of input.buffers)
    for (const field of buffer.fields) if (field.type === "ptr") out.add(fieldColumnName(buffer.name, field.name));
  return out;
};

const columnInputOf = (input: Input, operation: string): Result<ColumnInput, BeaError> => {
  if (input.generate !== undefined) {
    const names = Object.keys(input.generate.columns);
    return ok({ count: 0, columns: Object.fromEntries(names.map((n) => [n, []])), paths: {}, indexed: true });
  }
  const r =
    input.vectors !== undefined
      ? batchColumns(input.vectors)
      : singleCallColumns(input.signature, input.args ?? undefined, input.fields);
  return r.ok ? r : err(inputError(operation, r.error));
};

/** Every AddrExpr of the request in ptr positions, including generate constants and grids of ptr columns. */
const addressExprs = (input: Input, columns: ColumnInput): string[] => {
  const found = new Set(collectAddressExprs(input.signature, input.buffers, columns));
  const ptr = ptrColumns(input);
  for (const [name, d] of Object.entries(input.generate?.columns ?? {})) {
    if (!ptr.has(name)) continue;
    const texts =
      d.dist === "grid" ? splitElements(d.values ?? "") : d.dist === "constant" ? [String(d.value ?? "")] : [];
    for (const text of texts) {
      const n = normalizeScalar("ptr", text);
      if (n.ok && n.value.kind === "address") found.add(n.value.expr);
    }
  }
  return [...found].sort();
};

/** Reads `size` bytes at `va` through the agent (≤ read_max_bytes per RPC); unreadable -> memory_access_failed. */
const readInitFrom = async (
  session: LiveSession,
  va: bigint,
  size: number,
  op: OperationContext,
): Promise<Result<Uint8Array, BeaError>> => {
  const out = new Uint8Array(size);
  for (let at = 0; at < size; at += AGENT_LIMIT_DEFAULTS.read_max_bytes) {
    const want = Math.min(AGENT_LIMIT_DEFAULTS.read_max_bytes, size - at);
    const address = formatHex(va + BigInt(at));
    const reply = await session.agent.call("readMemory", { address, size: want }, { op });
    if (!reply.ok) return reply;
    const { value, data } = reply.value;
    if (!value.complete || data.length < want)
      return err({
        _tag: "MemoryAccessFailed",
        operation: op.name,
        address: value.stop?.at ?? formatHex(va + BigInt(at + data.length)),
        access: "read",
        size,
        message: "init_from: the source memory is not readable for the whole buffer size.",
      });
    out.set(data.subarray(0, want), at);
  }
  return ok(out);
};

const resolveAll = async (
  address: AddressService,
  session: LiveSession,
  exprs: readonly string[],
  op: OperationContext,
): Promise<Result<Map<string, bigint>, BeaError>> => {
  const map = new Map<string, bigint>();
  for (const expr of exprs) {
    const r = await address.resolve({ kind: "live", session }, expr, op, { path: "signature.args" });
    if (!r.ok) return r;
    map.set(expr, r.value.va);
  }
  return ok(map);
};

const windowBits = (bits: ColumnBits, from: number): ColumnBits => {
  const columns = new Map<string, readonly bigint[] | readonly (readonly bigint[])[]>();
  for (const [name, cells] of bits.columns) columns.set(name, cells.slice(from));
  return { count: Math.max(0, bits.count - from), columns };
};

const vectorsOf = (
  input: Input,
  plan: CallPlan,
  columns: ColumnInput,
  arrayDefaults: ReadonlyMap<string, readonly bigint[]>,
  resolve: (expr: string) => bigint | undefined,
  operation: string,
): Result<{ vectors: NormalizedVectors; total: number; windowCapped: boolean }, BeaError> => {
  const offset = input.vector_offset;
  if (input.generate !== undefined) {
    const generated = generateWindow(plan, input.generate, { from: offset, to: offset + GENERATE_WINDOW }, resolve);
    if (!generated.ok) return err(inputError(operation, generated.error));
    const { total, bits, specDigest } = generated.value;
    if (offset >= total)
      return err(invalid(operation, "vector_offset", `vector_offset is past the last vector (${String(total)}).`));
    const vectors = finalizeVectors(encodeColumns(plan, bits), {
      kind: "generated",
      seed: input.generate.seed,
      spec_digest: specDigest,
    });
    return ok({ vectors, total, windowCapped: offset + bits.count < total });
  }
  const typed = typeColumns(plan, columns, resolve, arrayDefaults);
  if (!typed.ok) return err(inputError(operation, typed.error));
  if (offset >= typed.value.count)
    return err(
      invalid(operation, "vector_offset", `vector_offset is past the last vector (${String(typed.value.count)}).`),
    );
  const vectors = finalizeVectors(encodeColumns(plan, windowBits(typed.value, offset)), { kind: "inline" });
  return ok({ vectors, total: typed.value.count, windowCapped: false });
};

const fpOf = async (
  input: Input,
  session: LiveSession,
  op: OperationContext,
): Promise<Result<FpEnvResolution, BeaError>> => {
  const known = input.fp?.thread_id ?? input.thread_id ?? null;
  const tid = fpThreadToRead(input.fp, known);
  let env: { mxcsr: number; fpcw: number } | null = null;
  if (tid !== null) {
    const state = await session.agent.call("captureThreadState", { tid, xmm: false, teb: false, tls: false }, { op });
    if (state.ok) env = { mxcsr: Number(BigInt(state.value.mxcsr)), fpcw: Number(BigInt(state.value.fpcw)) };
    else if ((input.fp?.source ?? "auto") === "thread") return state;
  }
  const resolved = resolveFpEnv(input.fp, { threadId: tid, env });
  return resolved.ok ? resolved : err(inputError(op.name, [resolved.error]));
};

const threadOf = (input: Input, at: bigint | null, budgetMs: number): CallFunctionParams["thread"] => {
  const timeout = Math.max(100, Math.min(AGENT_LIMIT_HARD.run_on_thread_timeout_ms, budgetMs));
  if (at !== null) return { kind: "hook", at: formatHex(at), tid: input.thread_id ?? null, timeout_ms: timeout };
  if (input.thread_id !== undefined) return { kind: "thread", tid: input.thread_id, timeout_ms: timeout };
  return { kind: "agent" };
};

export const prepareCall = async (
  deps: { readonly address: AddressService },
  input: Input,
  session: LiveSession,
  op: OperationContext,
  budgetMs: number,
): Promise<Result<PreparedCall, BeaError>> => {
  const operation = op.name;
  const mode = input.vectors === undefined && input.generate === undefined ? "single" : "batch";
  if (mode === "single" && input.vector_offset !== 0)
    return err(invalid(operation, "vector_offset", "vector_offset applies to batches (vectors or generate)."));
  const columns = columnInputOf(input, operation);
  if (!columns.ok) return columns;
  const space = { kind: "live" as const, session };
  const target = await deps.address.resolve(space, input.address, op, { path: "address" });
  if (!target.ok) return target;
  let at: bigint | null = null;
  if (input.thread_at !== undefined) {
    const r = await deps.address.resolve(space, input.thread_at, op, { path: "thread_at" });
    if (!r.ok) return r;
    at = r.value.va;
  }
  const resolvedExprs = await resolveAll(deps.address, session, addressExprs(input, columns.value), op);
  if (!resolvedExprs.ok) return resolvedExprs;
  const resolve = (expr: string): bigint | undefined => resolvedExprs.value.get(expr);
  const initFrom = new Map<string, Uint8Array>();
  for (const [i, buffer] of input.buffers.entries()) {
    if (buffer.init_from === undefined) continue;
    const source = await deps.address.resolve(space, buffer.init_from, op, { path: `buffers[${String(i)}].init_from` });
    if (!source.ok) return source;
    const bytes = await readInitFrom(session, source.value.va, buffer.size, op);
    if (!bytes.ok) return bytes;
    initFrom.set(buffer.name, bytes.value);
  }
  const classified = classifyWin64({
    signature: input.signature,
    buffers: input.buffers,
    supplied: new Set(Object.keys(columns.value.columns)),
    initFrom,
    resolve,
  });
  if (!classified.ok) return err(inputError(operation, classified.error));
  const { plan, arrayDefaults } = classified.value;
  const vectors = vectorsOf(input, plan, columns.value, arrayDefaults, resolve, operation);
  if (!vectors.ok) return vectors;
  const fp = await fpOf(input, session, op);
  if (!fp.ok) return fp;
  const wire = planToAgent(plan, target.value.ref.va as Hex, resolve);
  if (!wire.ok) return err(inputError(operation, wire.error));
  return ok({
    mode,
    target: target.value.ref,
    targetVa: target.value.va,
    plan,
    layout: outLayout(plan, input.buffers),
    wire: wire.value,
    vectors: vectors.value.vectors,
    offset: input.vector_offset,
    total: vectors.value.total,
    windowCapped: vectors.value.windowCapped,
    fp: fp.value,
    thread: threadOf(input, at, budgetMs),
  });
};
