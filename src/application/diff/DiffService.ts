import { randomUUID } from "node:crypto";

import { DIFF_INLINE_ROWS, type DiffFunctionInput, type DiffFunctionOutput } from "../../contracts/areas/emulation.js";
import { planDigest } from "../../domain/callModel/classify.js";
import { returnType, type OutLayout } from "../../domain/callModel/decode.js";
import { hexOf } from "../../domain/callModel/floatBits.js";
import { fpThreadToRead, resolveFpEnv } from "../../domain/callModel/fpEnv.js";
import {
  arrayCell,
  elementTypeOf,
  isBufferSlot,
  normalizeScalar,
  slotColumnName,
  type ColumnInput,
  type ScalarInput,
} from "../../domain/callModel/normalize.js";
import type { CallOutcomeColumns, CallPlan, NormalizedVectors } from "../../domain/callModel/types.js";
import { canonicalDigest } from "../../domain/canonical.js";
import type { BatchResult, DeviationKind } from "../../domain/emuProtocol.js";
import type { BeaError, InputIssue } from "../../domain/errors/beaError.js";
import { inputError, withPartial } from "../../domain/errors/constructors.js";
import { COMPLETE, mergeCoverage, type Coverage } from "../../domain/evidence/coverage.js";
import { EMULATION_LIMITATIONS as L } from "../../domain/evidence/limitations/emulation.js";
import type { Subject } from "../../domain/evidence/record.js";
import type { EvId, PiId, UnkId } from "../../domain/ids.js";
import type { JsonObject, JsonValue } from "../../domain/json.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { ResolvedAddress } from "../../ports/address.js";
import type {
  EmuRequestOptions,
  EmuSessionHandle,
  OracleBatchRequest,
  OracleBatchResult,
  ResolvedFpEnv,
} from "../../ports/emu.js";
import type { SensitiveLiterals } from "../../ports/evidence.js";
import type { LiveSession, OperationContext } from "../../ports/sessions.js";
import { AGENT_LIMIT_DEFAULTS } from "../../shared/agentLimits.js";
import type { CallStatus } from "../../shared/callPlan.js";
import { formatHex, type Hex } from "../../shared/hex.js";
import type { BeaApplication } from "../BeaApplication.js";
import {
  classifyRequest,
  invalid,
  lowerPlan,
  requestAddressExprs,
  requestColumns,
  requestVectors,
  wireVectors,
  type CallModelRequest,
  type ClassifiedRequest,
  type WindowVectors,
} from "../emu/callPrep.js";
import { assessEmulation, HARNESS_STATUSES } from "../emu/deviations.js";
import {
  emulationSubject,
  operationFor,
  statusCounts,
  toolError,
  type EmulationService,
} from "../emu/EmulationService.js";
import { deliver, DIFF_DECODERS, writeRowStream, type WrittenStream } from "../emu/envelope.js";
import { afterDigest, type SessionRecord } from "../emu/lineage.js";
import { byStatusOfSummary, emulatorOutcome, hex64 } from "../emu/views.js";
import type { HandlerContext } from "../handlerContext.js";
import { emuOp, liveOp } from "../sessionAccess.js";
import {
  compareLegs,
  type Cell,
  type ColumnSpec,
  type FaultSite,
  type Leg,
  type LegData,
  type OutcomeClass,
} from "./compare.js";
import { diffHints, hintProbes } from "./hints.js";

/**
 * diff_function (S5 §9, DESIGN §5.6/§6.2 #33): the same vectors through up to three legs — live (OracleCallPort ->
 * the agent's exact-bits SEH-frame thunk), emulation (EmuPort batch) and expected (caller columns or a hook
 * recording's captured return) — then a bit-exact comparison. Rules: the target resolves PER LEG (module+RVA) with an
 * image identity check; `init_from` buffers are read ONCE (live leg when present, else the emulator) and used by every
 * leg (CI-I2); the FP environment is resolved ONCE (D-INT-43) for both executing legs; the emulation leg runs first
 * (≤ 45 % of the budget), the live leg over exactly the range the emulator completed; a steal-fallback live leg makes
 * every faulting vector inconclusive; vectors that did not run are inconclusive and give a continuation. A
 * non-equivalence auto-records an unknown (deduplicated by image, rva, leg pair and verdict).
 */
const FINALIZE_RESERVE_MS = 1_500;
const EMULATION_SHARE = 0.45;
const DIFF_WINDOW = 100_000;
const RUN_ON_THREAD_TIMEOUT_MS = 30_000;
const SHA256_RE = /^[a-f0-9]{64}$/u;

type Legs = readonly Leg[];

interface LegContext {
  readonly handle: EmuSessionHandle | null;
  readonly opEmu: OperationContext | null;
  readonly session: LiveSession | null;
  readonly opLive: OperationContext | null;
}

const isRawVa = (address: string): boolean => /^0[xX][0-9a-fA-F]{1,16}$/u.test(address.trim());

/** NormalizedVectors restricted to [from, from + count) (cell 0 = absolute vector offset + from). */
const sliceVectors = (vectors: NormalizedVectors, from: number, count: number): NormalizedVectors => {
  const columns: Record<string, Hex[] | Hex[][]> = {};
  for (const [name, cells] of Object.entries(vectors.columns))
    columns[name] = cells.slice(from, from + count) as Hex[] | Hex[][];
  return {
    count,
    columns,
    digest: `sha256:${canonicalDigest({ count, columns } as unknown as JsonValue)}`,
    source: vectors.source,
  };
};

/**
 * The column types a diff compares: "ret" (unless void / hidden struct) and every declared out-buffer field, or the
 * requested subset. Review fix EMU-12: an unknown or repeated requested name is an input error listing the valid
 * names; it is never dropped silently (an equivalence verdict that never compared the asked-for column).
 */
const comparedColumns = (
  operation: string,
  plan: CallPlan,
  layout: OutLayout,
  requested: readonly string[] | undefined,
): Result<ColumnSpec[], BeaError> => {
  const all: ColumnSpec[] = [];
  const ret = returnType(plan.returns);
  if (ret !== null) all.push({ name: "ret", type: ret });
  for (const [buffer, fields] of layout)
    for (const field of fields) {
      const element = elementTypeOf(field.type);
      if (element !== null) all.push({ name: `${buffer}.${field.name}`, type: element });
    }
  if (requested === undefined) {
    if (all.length === 0)
      return err(
        invalid(
          operation,
          "compare.columns",
          "Nothing to compare: the function returns void and has no out-buffer fields.",
        ),
      );
    return ok(all);
  }
  if (requested.length === 0) return err(invalid(operation, "compare.columns", "compare.columns is empty."));
  const valid = all.length === 0 ? "(none: void return and no out-buffer fields)" : all.map((c) => c.name).join(", ");
  const issues: InputIssue[] = [];
  const seen = new Set<string>();
  const out: ColumnSpec[] = [];
  for (const [i, name] of requested.entries()) {
    const column = all.find((c) => c.name === name);
    if (column === undefined)
      issues.push({
        path: `compare.columns[${String(i)}]`,
        reason: "invalid_value",
        message: `Unknown column ${name.slice(0, 80)}; valid: ${valid.slice(0, 400)}.`,
      });
    else if (seen.has(name))
      issues.push({
        path: `compare.columns[${String(i)}]`,
        reason: "invalid_value",
        message: `Column ${name.slice(0, 80)} is listed twice.`,
      });
    else {
      seen.add(name);
      out.push(column);
    }
  }
  return issues.length > 0 ? err(inputError(operation, issues)) : ok(out);
};

const accessOf = (cause: string): FaultSite["access"] =>
  cause.startsWith("read")
    ? "read"
    : cause.startsWith("write")
      ? "write"
      : cause.startsWith("fetch")
        ? "execute"
        : null;

/** Leg data of an executing leg (live or emulation) from its decoded outcome columns. */
const executingLeg = (
  leg: "live" | "emulation",
  outcome: CallOutcomeColumns | null,
  count: number,
  columns: readonly ColumnSpec[],
  notRunWhy: string,
  steal: boolean,
): LegData => {
  const classes: OutcomeClass[] = [];
  const status: (CallStatus | null)[] = [];
  const reasons: (string | null)[] = [];
  const sites: (FaultSite | null)[] = [];
  const cells: Record<string, Cell[]> = Object.fromEntries(columns.map((c) => [c.name, [] as Cell[]]));
  const faults = new Map((outcome?.faults ?? []).map((f) => [f.index, f]));
  for (let k = 0; k < count; k++) {
    const s = outcome === null || k >= outcome.count ? null : (outcome.status[k] ?? null);
    status.push(s);
    if (s === null) {
      classes.push("not_run");
      reasons.push(`not_run:${notRunWhy}`);
      sites.push(null);
      for (const c of columns) cells[c.name]?.push(null);
      continue;
    }
    if (s === "returned") {
      classes.push("returned");
      reasons.push(null);
      sites.push(null);
      for (const c of columns) {
        const cell = c.name === "ret" ? (outcome?.ret?.[k] ?? null) : (outcome?.fields[c.name]?.[k] ?? null);
        cells[c.name]?.push(cell);
      }
      continue;
    }
    const attribution = outcome?.attribution[k] ?? (HARNESS_STATUSES.has(s) ? "harness" : "target");
    const fault = faults.get((outcome?.offset ?? 0) + k);
    const harness = attribution === "harness" || (leg === "live" && (steal || HARNESS_STATUSES.has(s)));
    classes.push(harness ? "harness_stop" : "target_stop");
    reasons.push(
      harness ? (steal && leg === "live" ? "live:steal_exception_model" : `${leg}:${fault?.cause ?? s}`) : null,
    );
    sites.push(
      harness
        ? null
        : {
            family: s,
            module: fault?.site.module ?? null,
            rva: fault?.site.rva ?? null,
            access: fault === undefined ? null : accessOf(fault.cause),
          },
    );
    for (const c of columns) cells[c.name]?.push(null);
  }
  return { leg, classes, status, reasons, sites, cells };
};

export class DiffService {
  readonly #app: BeaApplication;
  readonly #emulation: EmulationService;

  constructor(app: BeaApplication, emulation: EmulationService) {
    this.#app = app;
    this.#emulation = emulation;
  }

  run(input: DiffFunctionInput, ctx: HandlerContext): Promise<Result<DiffFunctionOutput, BeaError>> {
    const operation = ctx.operation;
    const available: Record<Leg, boolean> = {
      live: input.live_session_id !== undefined,
      emulation: input.emu_session_id !== undefined,
      expected: input.expected !== undefined || input.from_recording?.ret !== undefined,
    };
    for (const [i, leg] of (input.legs ?? []).entries())
      if (!available[leg])
        return Promise.resolve(
          err(
            invalid(
              operation,
              `legs[${String(i)}]`,
              leg === "live"
                ? "The live leg needs live_session_id."
                : leg === "emulation"
                  ? "The emulation leg needs emu_session_id."
                  : "The expected leg needs expected or from_recording.ret.",
            ),
          ),
        );
    const legs: Legs = [
      ...new Set(input.legs ?? (["live", "emulation", "expected"] as const).filter((l) => available[l])),
    ];
    if (legs.length < 2) return Promise.resolve(err(invalid(operation, "legs", "Give at least two distinct legs.")));
    if (!legs.includes("live") && !legs.includes("emulation"))
      return Promise.resolve(
        err(invalid(operation, "legs", "At least one executing leg (live or emulation) is needed.")),
      );
    if (input.from_recording !== undefined && input.signature.args.some(isBufferSlot))
      return Promise.resolve(
        err(
          invalid(
            operation,
            "from_recording",
            "Recordings cannot reproduce pointed-to memory; from_recording takes scalar-only signatures (capture a dump and use emu_open instead).",
          ),
        ),
      );
    const withLive = (
      fn: (session: LiveSession | null, op: OperationContext | null) => Promise<Result<DiffFunctionOutput, BeaError>>,
    ) =>
      legs.includes("live") && input.live_session_id !== undefined
        ? liveOp(
            this.#app,
            ctx,
            input.live_session_id,
            { mode: "exclusive", need: "agent", path: "live_session_id" },
            (s, op) => fn(s, op),
          )
        : fn(null, null);
    return legs.includes("emulation") && input.emu_session_id !== undefined
      ? emuOp(
          this.#app,
          ctx,
          input.emu_session_id,
          (handle, opEmu) =>
            withLive((session, opLive) => this.#run(input, ctx, legs, { handle, opEmu, session, opLive })),
          "emu_session_id",
        )
      : withLive((session, opLive) => this.#run(input, ctx, legs, { handle: null, opEmu: null, session, opLive }));
  }

  /** from_recording: vectors (scalar args) and expected returns from a hook recording's captured bits (S5 §9.3.3). */
  async #recordingColumns(
    input: DiffFunctionInput,
    op: OperationContext,
  ): Promise<
    Result<
      {
        readonly columns: ColumnInput;
        readonly expected: readonly (ScalarInput | null)[] | null;
        readonly headDigest: string;
      },
      BeaError
    >
  > {
    const spec = input.from_recording;
    if (spec === undefined) return err(invalid(op.name, "from_recording", "from_recording is missing."));
    const { recordings } = this.#app.services;
    if (recordings.get(spec.recording_id) === undefined)
      return err({
        _tag: "ReferenceNotFound",
        operation: op.name,
        reference: { kind: "recording", id: spec.recording_id },
      });
    const names = input.signature.args.map((slot, i) => slotColumnName(slot, i));
    const cells: ScalarInput[][] = names.map(() => []);
    const expected: (ScalarInput | null)[] = [];
    const digestParts: JsonValue[] = [];
    const toScalar = (value: JsonValue | undefined): ScalarInput | null => {
      if (value === undefined || value === null) return null;
      if (typeof value === "number" || typeof value === "string" || typeof value === "boolean") return value;
      if (typeof value === "object" && !Array.isArray(value)) {
        const bits = (value as Record<string, JsonValue>)["bits"];
        if (typeof bits === "string") return bits;
      }
      return null;
    };
    for await (const event of recordings.events(spec.recording_id, {}, op)) {
      if (expected.length >= spec.max_events) break;
      const row = spec.args.map((field) => toScalar(event[field]));
      if (row.some((v) => v === null)) continue; // this event lacks a captured argument: not representable
      row.forEach((v, i) => cells[i]?.push(v as ScalarInput));
      expected.push(spec.ret === undefined ? null : toScalar(event[spec.ret]));
      digestParts.push({ seq: event.seq, args: row as JsonValue[] });
    }
    if (expected.length === 0)
      return err(
        invalid(op.name, "from_recording.args", "The recording has no event with every named argument captured."),
      );
    const columns: Record<string, ScalarInput[]> = {};
    const paths: Record<string, string> = {};
    names.forEach((name, i) => {
      if (i < spec.args.length) {
        columns[name] = cells[i] ?? [];
        paths[name] = `from_recording.args[${String(i)}]`;
      }
    });
    return ok({
      columns: { count: expected.length, columns, paths, indexed: true },
      expected: spec.ret === undefined ? null : expected,
      headDigest: canonicalDigest(digestParts as JsonValue),
    });
  }

  async #resolve(
    space: "live" | "emulation",
    ctx: LegContext,
    exprs: readonly string[],
  ): Promise<Result<Map<string, ResolvedAddress>, BeaError>> {
    if (space === "emulation") {
      if (ctx.handle === null || ctx.opEmu === null) return ok(new Map());
      return this.#emulation.resolveAll(ctx.handle, exprs, ctx.opEmu, "address");
    }
    const session = ctx.session;
    const op = ctx.opLive;
    if (session === null || op === null) return ok(new Map());
    const out = new Map<string, ResolvedAddress>();
    for (const expr of exprs) {
      const r = await this.#app.services.address.resolve({ kind: "live", session }, expr, op, { path: "address" });
      if (!r.ok) return r;
      out.set(expr, r.value);
    }
    return ok(out);
  }

  /** CI-I2: init_from bytes read ONCE through the agent (guard-aware readMemory), ≤ read_max_bytes per RPC. */
  async #liveInitFrom(
    session: LiveSession,
    op: OperationContext,
    buffers: CallModelRequest["buffers"],
    resolved: ReadonlyMap<string, ResolvedAddress>,
  ): Promise<Result<Map<string, Uint8Array>, BeaError>> {
    const out = new Map<string, Uint8Array>();
    for (const [i, buffer] of buffers.entries()) {
      if (buffer.init_from === undefined) continue;
      const source = resolved.get(buffer.init_from);
      if (source === undefined)
        return err(invalid(op.name, `buffers[${String(i)}].init_from`, "The address could not be resolved."));
      const bytes = new Uint8Array(buffer.size);
      const step = AGENT_LIMIT_DEFAULTS.read_max_bytes;
      for (let at = 0; at < buffer.size; at += step) {
        const want = Math.min(step, buffer.size - at);
        const address = formatHex(source.va + BigInt(at));
        const reply = await session.agent.call("readMemory", { address, size: want }, { op });
        if (!reply.ok) return reply;
        const { value, data } = reply.value;
        if (!value.complete || data.length < want)
          return err({
            _tag: "MemoryAccessFailed",
            operation: op.name,
            address: value.stop?.at ?? address,
            access: "read",
            size: buffer.size,
            message: "init_from: the source memory is not readable for the whole buffer size.",
          });
        bytes.set(data.subarray(0, want), at);
      }
      out.set(buffer.name, bytes);
    }
    return ok(out);
  }

  /** D-INT-43: ONE FP environment for both executing legs (explicit > a known live thread > the dump's thread > default). */
  async #fp(
    input: DiffFunctionInput,
    ctx: LegContext,
    record: SessionRecord | null,
  ): Promise<Result<ResolvedFpEnv, BeaError>> {
    const known = input.fp?.thread_id ?? input.live?.thread_id ?? null;
    const tid = ctx.session === null ? null : fpThreadToRead(input.fp, known);
    let env: { mxcsr: number; fpcw: number } | null = null;
    if (tid !== null && ctx.session !== null && ctx.opLive !== null) {
      const state = await ctx.session.agent.call(
        "captureThreadState",
        { tid, xmm: false, teb: false, tls: false },
        { op: ctx.opLive },
      );
      if (state.ok) env = { mxcsr: Number(BigInt(state.value.mxcsr)), fpcw: Number(BigInt(state.value.fpcw)) };
      else if ((input.fp?.source ?? "auto") === "thread") return state;
    }
    const dumpThread =
      record !== null && record.fp.source === "dump-thread" ? { mxcsr: record.fp.mxcsr, fpcw: record.fp.fpcw } : null;
    const fpRequest =
      input.fp === undefined
        ? undefined
        : { ...input.fp, ...(ctx.session === null && input.fp.source === "thread" ? { source: "auto" as const } : {}) };
    const resolved = resolveFpEnv(fpRequest, { threadId: tid, env, dumpThread });
    if (!resolved.ok) return err(inputError(ctx.opLive?.name ?? ctx.opEmu?.name ?? "diff_function", [resolved.error]));
    return ok({
      mxcsr: resolved.value.mxcsr,
      fpcw: resolved.value.fpcw,
      source: resolved.value.source,
      threadId: resolved.value.threadId,
    });
  }

  /** Expected columns normalized per declared type; cell k = absolute vector offset + k (null = not compared). */
  #expectedCells(
    input: DiffFunctionInput,
    columns: readonly ColumnSpec[],
    recorded: readonly (ScalarInput | null)[] | null,
    offset: number,
    count: number,
    arrayCounts: ReadonlyMap<string, number>,
    operation: string,
  ): Result<Record<string, Cell[]>, BeaError> {
    const source: Record<string, readonly (ScalarInput | null)[]> = { ...input.expected?.columns };
    if (recorded !== null && source["ret"] === undefined) source["ret"] = recorded;
    const out: Record<string, Cell[]> = {};
    for (const [name, cellsIn] of Object.entries(source)) {
      const spec = columns.find((c) => c.name === name);
      if (spec === undefined)
        return err(
          invalid(
            operation,
            `expected.columns.${name}`,
            `Unknown compared column ${name}; valid: ${columns.map((c) => c.name).join(", ")}.`,
          ),
        );
      const cells: Cell[] = [];
      for (let k = 0; k < count; k++) {
        const value = cellsIn[offset + k];
        if (value === undefined || value === null) {
          cells.push(null);
          continue;
        }
        const elements = arrayCounts.get(name);
        if (elements !== undefined) {
          const row = arrayCell(spec.type, elements, value, [], `expected.columns.${name}[${String(offset + k)}]`);
          if (!row.ok) return err(inputError(operation, [row.error]));
          cells.push(row.value.map((bits) => hexOf(bits)));
          continue;
        }
        const normalized = normalizeScalar(spec.type, value);
        if (!normalized.ok)
          return err(invalid(operation, `expected.columns.${name}[${String(offset + k)}]`, normalized.error));
        if (normalized.value.kind !== "bits")
          return err(
            invalid(
              operation,
              `expected.columns.${name}[${String(offset + k)}]`,
              "Expected values cannot be address expressions.",
            ),
          );
        cells.push(hexOf(normalized.value.bits));
      }
      out[name] = cells;
    }
    return ok(out);
  }

  async #run(
    input: DiffFunctionInput,
    ctx: HandlerContext,
    legs: Legs,
    lc: LegContext,
  ): Promise<Result<DiffFunctionOutput, BeaError>> {
    const operation = ctx.operation;
    const { services } = this.#app;
    const now = (): number => this.#app.clock.monoMs();
    const budgetMs = Math.max(1_000, Math.min(input.timeout_ms, ctx.remainingMs()) - FINALIZE_RESERVE_MS);
    const deadlineAt = now() + budgetMs;
    const op = lc.opLive ?? lc.opEmu ?? operationFor(operation, ctx, budgetMs);
    if (lc.session !== null) {
      const gate = ctx.gates.requireUnlessOwned("call_attached", operation, lc.session.ownership);
      if (!gate.ok) return gate;
    }
    const literals = services.evidence.literals(undefined);
    if (!literals.ok) return literals;
    const record = lc.handle === null ? null : this.#emulation.record(lc.handle);

    // ---- vectors source
    let request: CallModelRequest = {
      signature: input.signature,
      buffers: input.buffers,
      vectors: input.vectors,
      generate: input.generate,
      vector_offset: input.vector_offset,
    };
    let columns: ColumnInput;
    let recordedExpected: readonly (ScalarInput | null)[] | null = null;
    let recordingSource: NormalizedVectors["source"] | null = null;
    if (input.from_recording !== undefined) {
      const recorded = await this.#recordingColumns(input, op);
      if (!recorded.ok) return recorded;
      columns = recorded.value.columns;
      recordedExpected = recorded.value.expected;
      recordingSource = {
        kind: "recording",
        recording_id: input.from_recording.recording_id,
        head_digest: recorded.value.headDigest,
      };
      request = { ...request, vectors: { count: columns.count, columns: columns.columns } };
    } else {
      const parsed = requestColumns(request, operation);
      if (!parsed.ok) return parsed;
      columns = parsed.value;
    }

    // ---- addresses per leg, identity, init_from (once)
    const exprs = new Set(requestAddressExprs(request, columns));
    for (const b of request.buffers) if (b.init_from !== undefined) exprs.add(b.init_from);
    exprs.add(input.address);
    const sorted = [...exprs].sort();
    const liveResolved = await this.#resolve("live", lc, legs.includes("live") ? sorted : []);
    if (!liveResolved.ok) return liveResolved;
    const emuResolved = await this.#resolve("emulation", lc, legs.includes("emulation") ? sorted : []);
    if (!emuResolved.ok) return emuResolved;
    const liveTarget = liveResolved.value.get(input.address) ?? null;
    const emuTarget = emuResolved.value.get(input.address) ?? null;
    let imageMismatch = false;
    if (liveTarget !== null && emuTarget !== null) {
      const a = liveTarget.ref.image_sha256 ?? null;
      const b = emuTarget.ref.image_sha256 ?? null;
      const rawShared =
        isRawVa(input.address) &&
        record?.producerInstance !== null &&
        record?.producerInstance === lc.session?.instanceId;
      if (isRawVa(input.address) && !rawShared)
        return err(
          invalid(
            operation,
            "address",
            "A raw 0x address means different code in the live process and the emulator; use module+0xRVA or module!export.",
          ),
        );
      imageMismatch = a === null || b === null || a !== b;
      if (imageMismatch && !input.allow_image_mismatch)
        return err(
          invalid(
            operation,
            "address",
            "The live module and the emulated image are different binaries (or a digest is unknown); pass allow_image_mismatch: true to compare anyway.",
          ),
        );
    }
    const emuOptions: EmuRequestOptions = { signal: op.signal, deadlineAt };
    const initFrom =
      lc.session !== null && lc.opLive !== null
        ? await this.#liveInitFrom(lc.session, lc.opLive, request.buffers, liveResolved.value)
        : lc.handle !== null
          ? await this.#emulation.readInitFrom(lc.handle, request.buffers, emuResolved.value, emuOptions, operation)
          : ok(new Map<string, Uint8Array>());
    if (!initFrom.ok) return initFrom;

    // ---- one classification per executing leg (ptr AddrExpr defaults resolve per leg)
    const liveVa = (expr: string): bigint | undefined => liveResolved.value.get(expr)?.va;
    const emuVa = (expr: string): bigint | undefined => emuResolved.value.get(expr)?.va;
    let emuPlan: ClassifiedRequest | null = null;
    let livePlan: ClassifiedRequest | null = null;
    let emuVectors: WindowVectors | null = null;
    let liveVectors: WindowVectors | null = null;
    if (legs.includes("emulation")) {
      const c = classifyRequest(request, columns, initFrom.value, emuVa, operation);
      if (!c.ok) return c;
      emuPlan = c.value;
      const v = requestVectors(request, emuPlan, columns, emuVa, operation, DIFF_WINDOW);
      if (!v.ok) return v;
      emuVectors = v.value;
    }
    if (legs.includes("live")) {
      const c = classifyRequest(request, columns, initFrom.value, liveVa, operation);
      if (!c.ok) return c;
      livePlan = c.value;
      const v = requestVectors(request, livePlan, columns, liveVa, operation, DIFF_WINDOW);
      if (!v.ok) return v;
      liveVectors = v.value;
    }
    const primaryPlan = (emuPlan ?? livePlan) as ClassifiedRequest;
    const primaryVectors = (emuVectors ?? liveVectors) as WindowVectors;
    const vectors =
      recordingSource === null ? primaryVectors.vectors : { ...primaryVectors.vectors, source: recordingSource };
    const count = vectors.count;
    const offset = primaryVectors.offset;
    const columnsChecked = comparedColumns(operation, primaryPlan.plan, primaryPlan.layout, input.compare?.columns);
    if (!columnsChecked.ok) return columnsChecked;
    const compared = columnsChecked.value;
    const fp = await this.#fp(input, lc, record);
    if (!fp.ok) return fp;

    // ---- emulation leg first
    const limitations: string[] = [];
    let emuOutcome: CallOutcomeColumns | null = null;
    let emuBatch: BatchResult | null = null;
    let emuEvidence: EvId | null = null;
    let emuCancelled = false;
    const deviationKinds = new Set<DeviationKind>();
    const importModels = new Set<string>();
    if (emuPlan !== null && lc.handle !== null && record !== null && emuTarget !== null) {
      const share = legs.includes("live") ? EMULATION_SHARE : 1;
      const emuDeadline = now() + Math.max(500, (deadlineAt - now()) * share);
      const wire = lowerPlan(emuPlan.plan, formatHex(emuTarget.va), emuVa, operation);
      if (!wire.ok) return wire;
      const from = input.emulation?.state_from ?? "baseline";
      const reply = await services.emulator.batch(
        lc.handle,
        {
          plan: wire.value,
          vectors: wireVectors(vectors, offset),
          state: { from, writes: [], saveAs: null },
          options: {
            maxInstructions: input.emulation?.max_instructions ?? 1_000_000,
            timeoutMs: 0,
            mxcsr: fp.value.mxcsr,
            fpcw: fp.value.fpcw,
            faultPolicy: record.faultPolicy,
            trace: {
              imports: "counts",
              blocks: false,
              coverage: false,
              countInstructions: false,
              memory: "off",
              instructions: false,
              disassemble: false,
              maxEvents: 10_000,
            },
            isolation: input.emulation?.isolation ?? "snapshot",
            stopOnFault: false,
            deadlineMs: Math.max(500, Math.round(emuDeadline - now() - 500)),
          },
        },
        { signal: op.signal, deadlineAt: emuDeadline },
      );
      if (reply.ok) emuBatch = reply.value;
      else if ("kind" in reply.error && reply.error.kind === "partial") {
        emuBatch = reply.error.result;
        emuCancelled = reply.error.reason === "cancelled";
      } else return err(toolError(reply.error as BeaError, operation, input.timeout_ms));
      emuOutcome = emulatorOutcome(emuPlan.plan, emuPlan.layout, emuBatch);
      for (const kind of Object.keys(emuBatch.aggregates.deviations)) deviationKinds.add(kind as DeviationKind);
      for (const value of Object.values(emuBatch.aggregates.imports)) importModels.add(value.model);
      const recorded = await this.#recordEmulationLeg(
        lc.handle,
        record,
        emuPlan,
        emuTarget,
        vectors,
        offset,
        emuBatch,
        emuOutcome,
        fp.value,
        from,
        input,
        literals.value,
        operation,
      );
      if (!recorded.ok) return recorded;
      emuEvidence = recorded.value;
      if (emuCancelled) return err(withPartial({ _tag: "Cancelled", operation, by: "client" }, emuEvidence));
    }

    // ---- live leg over exactly the range the emulator completed
    let liveResult: OracleBatchResult | null = null;
    if (livePlan !== null && lc.session !== null && lc.opLive !== null && liveTarget !== null && liveVectors !== null) {
      const range = emuOutcome === null ? count : emuOutcome.count;
      if (range > 0) {
        const thread: Parameters<typeof services.oracle.callPlanBatch>[1]["thread"] =
          input.live?.thread_id === undefined
            ? "agent"
            : {
                tid: input.live.thread_id,
                timeoutMs: Math.min(RUN_ON_THREAD_TIMEOUT_MS, Math.max(100, deadlineAt - now())),
              };
        const request: OracleBatchRequest = {
          target: { va: formatHex(liveTarget.va), module: liveTarget.ref.module, rva: liveTarget.ref.rva },
          plan: livePlan.plan,
          vectors: sliceVectors(liveVectors.vectors, 0, range),
          offset,
          fp: fp.value,
          thread,
          chunk: input.live?.chunk ?? 1000,
          coverage: false,
          deadlineAt,
          // the declared out-buffer layout, so the live leg decodes out fields by name like the emulation leg
          outLayout: livePlan.layout,
        };
        const reply = await services.oracle.callPlanBatch(lc.session, request, lc.opLive);
        if (!reply.ok) return err({ ...reply.error, operation });
        liveResult = reply.value;
      }
    }

    // ---- legs -> comparison
    const notRunWhy = op.signal.aborted ? "cancelled" : "deadline";
    const emuStopped = emuBatch?.summary.stopped ?? null;
    const legData: LegData[] = [];
    if (legs.includes("live"))
      legData.push(
        executingLeg(
          "live",
          liveResult?.outcome ?? null,
          count,
          compared,
          liveResult?.lostTarget === true ? "lost_target" : notRunWhy,
          liveResult?.exceptionModel === "steal",
        ),
      );
    if (legs.includes("emulation"))
      legData.push(
        executingLeg(
          "emulation",
          emuOutcome,
          count,
          compared,
          // review fix EMU-6: a chain batch that could not place a vector's buffers stops there (not a deadline)
          emuStopped === null ? notRunWhy : emuStopped.code,
          false,
        ),
      );
    if (legs.includes("expected")) {
      const arrayCounts = new Map(
        primaryPlan.plan.columns.filter((c) => c.type.endsWith("[]")).map((c) => [c.name, c.count]),
      );
      for (const [buffer, fields] of primaryPlan.layout)
        for (const field of fields)
          if (field.type.endsWith("[]")) arrayCounts.set(`${buffer}.${field.name}`, field.count);
      const expected = this.#expectedCells(input, compared, recordedExpected, offset, count, arrayCounts, operation);
      if (!expected.ok) return expected;
      const cells = expected.value;
      const classes: OutcomeClass[] = [];
      const reasons: (string | null)[] = [];
      for (let k = 0; k < count; k++) {
        const any = Object.values(cells).some((column) => column[k] !== null && column[k] !== undefined);
        classes.push(any ? "returned" : "not_run");
        reasons.push(any ? null : "not_run:no_expected_value");
      }
      legData.push({
        leg: "expected",
        classes,
        status: classes.map((c) => (c === "returned" ? "returned" : null)),
        reasons,
        sites: classes.map(() => null),
        cells,
      });
    }
    const compareResult = compareLegs({
      offset,
      count,
      legs: legData,
      columns: compared,
      options: {
        nan: input.compare?.nan ?? "bits",
        tolerance:
          input.compare?.tolerance_ulp === undefined &&
          input.compare?.tolerance_abs === undefined &&
          input.compare?.tolerance_rel === undefined
            ? undefined
            : { ulp: input.compare.tolerance_ulp, abs: input.compare.tolerance_abs, rel: input.compare.tolerance_rel },
        inconclusive: input.compare?.inconclusive ?? "count",
        compareFaultSites: input.compare?.compare_fault_sites ?? true,
      },
      inputs: vectors.columns,
    });

    // ---- continuation, verdict, hints
    const executed = [
      ...(legs.includes("emulation") ? [emuOutcome?.count ?? 0] : []),
      ...(legs.includes("live") ? [liveResult?.completed ?? 0] : []),
    ];
    const ranAll = Math.min(...executed, count);
    const nextOffset = ranAll < count ? offset + ranAll : primaryVectors.windowCapped ? offset + count : null;
    let verdict = compareResult.verdict;
    if (nextOffset !== null && verdict === "equivalent-on-tested-inputs") verdict = "unknown";
    const differences = compareResult.pairs.reduce((n, p) => n + p.differ, 0);
    const outcomeDifferences = compareResult.pairs.reduce((n, p) => n + p.outcome_mismatches, 0);
    const rawPointers =
      record?.source === "image" &&
      legs.includes("live") &&
      Object.values(columns.columns).some((cells) =>
        cells.some((cell) => typeof cell === "string" && /^0[xX]/u.test(cell)),
      ) &&
      input.signature.args.some((slot) => slot.type === "ptr");
    const hints = diffHints({
      verdict,
      differences,
      outcomeDifferences,
      profile: compareResult.profile,
      emulationDeviations: deviationKinds,
      emulationImportModels: importModels,
      imageBackedWithLive: record?.source === "image" && legs.includes("live"),
      liveWithSnapshotIsolation:
        legs.includes("live") &&
        legs.includes("emulation") &&
        (input.emulation?.isolation ?? "snapshot") === "snapshot",
      rawPointerInputs: rawPointers,
      imageMismatch,
      engineUnvalidated: record?.engineUnvalidated === true,
      emulationCompared: legs.includes("emulation"),
    });

    // ---- rows: compact inline rows (≤ min(inline_limit, 64)), else a diff stream with the full per-leg fields
    let stream: WrittenStream | null = null;
    let inlineRows: JsonObject[] | null = null;
    if (count <= Math.min(input.inline_limit, DIFF_INLINE_ROWS))
      inlineRows = this.#compactRows(compareResult.pairs, legData, offset, count);
    else {
      const rows = this.#rows(compareResult.pairs, legData, vectors, offset, count);
      const written = await writeRowStream(
        services.evidence,
        { kind: "diff", channel: "diff_function", decoders: DIFF_DECODERS },
        rows,
        literals.value,
      );
      if (!written.ok) return written;
      stream = written.value;
    }

    // ---- coverage and limitations
    const inconclusive = compareResult.pairs.reduce((n, p) => n + p.inconclusive, 0);
    const notRun = count - ranAll;
    const parts: Coverage[] = [COMPLETE, stream?.coverage ?? COMPLETE];
    // EMU-6: vectors after a stopped emulation chain did not run because of the stop, not a deadline
    const notRunReason = emuStopped !== null ? "stopped_early" : "deadline";
    if (inconclusive > 0)
      parts.push({
        status: "partial",
        truncated: false,
        reasons: [notRun > 0 ? notRunReason : "emulation_deviation"],
      });
    if (nextOffset !== null) parts.push({ status: "partial", truncated: false, reasons: [notRunReason] });
    if (emuStopped !== null) {
      const resource = emuStopped.data?.["resource"];
      limitations.push(
        L.EMU_BATCH_STOPPED(emuStopped.index, resource === "heap" || resource === "scratch" ? resource : null),
      );
    }
    if (verdict === "equivalent-on-tested-inputs") limitations.push(L.DIFF_TESTED_INPUTS_ONLY);
    if (compareResult.excluded > 0) limitations.push(L.DIFF_EXCLUDED(compareResult.excluded));
    if (nextOffset !== null)
      limitations.push(
        L.DIFF_NOT_RUN(
          Math.max(1, count - ranAll + (primaryVectors.windowCapped ? primaryVectors.total - offset - count : 0)),
        ),
      );
    if (imageMismatch) limitations.push(L.DIFF_IMAGE_MISMATCH);
    if (liveResult?.lostTarget === true) limitations.push(L.DIFF_LIVE_LOST);
    if (liveResult?.exceptionModel === "steal") limitations.push(L.DIFF_STEAL_MODEL);
    if (
      legs.includes("live") &&
      legs.includes("emulation") &&
      (input.emulation?.isolation ?? "snapshot") === "snapshot"
    )
      limitations.push(L.DIFF_LIVE_NOT_ISOLATED);
    if (recordingSource !== null) limitations.push(L.DIFF_RECORDING_VECTORS);
    if (emuBatch !== null) {
      const assessment = assessEmulation({
        deviations: Object.entries(emuBatch.aggregates.deviations).map(([kind, v]) => ({
          kind: kind as DeviationKind,
          count: v?.vectors ?? 0,
        })),
        importModels: [...importModels],
      });
      limitations.push(...assessment.limitations);
    }

    // ---- result, evidence, unknown
    const imageSha =
      sha256Of(liveTarget?.ref.image_sha256) ?? sha256Of(emuTarget?.ref.image_sha256) ?? record?.imageSha256 ?? null;
    const rva = liveTarget?.ref.rva ?? emuTarget?.ref.rva ?? null;
    const legRows = legs.map((leg) => {
      if (leg === "live")
        return {
          leg,
          completed: liveResult?.completed ?? 0,
          by_status: liveResult === null ? {} : statusCounts(liveResult.outcome),
          evidence_id: liveResult?.evidence_id ?? null,
          ...(liveResult === null ? {} : { effect_id: liveResult.effect_id, lost_target: liveResult.lostTarget }),
        };
      if (leg === "emulation")
        return {
          leg,
          completed: emuOutcome?.count ?? 0,
          by_status: emuBatch === null ? {} : byStatusOfSummary(emuBatch.summary),
          evidence_id: emuEvidence,
        };
      const filled = legData.find((l) => l.leg === "expected")?.classes.filter((c) => c === "returned").length ?? 0;
      return { leg, completed: filled, by_status: filled === 0 ? {} : { returned: filled }, evidence_id: null };
    });
    const result = {
      verdict,
      verdict_basis: "bit-exact" as const,
      fp: { mxcsr: formatHex(fp.value.mxcsr), fpcw: formatHex(fp.value.fpcw), source: fp.value.source },
      target: {
        ...(liveTarget === null ? {} : { live: liveTarget.ref }),
        ...(emuTarget === null ? {} : { emulation: emuTarget.ref }),
      },
      legs: legRows,
      vectors: {
        count,
        offset,
        digest: vectors.digest,
        source: vectors.source.kind,
        continuation: nextOffset === null ? null : { vector_offset: nextOffset },
      },
      pairs: compareResult.pairs.map(({ vectors: _vectors, columns: stats, ...pair }) => ({
        ...pair,
        columns: Object.entries(stats).map(([column, columnStats]) => ({ column, ...columnStats })),
      })),
      worst: compareResult.worst.map((w) => ({
        index: w.index,
        column: w.column,
        reason: w.reason,
        inputs: columnBits(w.inputs),
        values: (Object.entries(w.values) as [Leg, { status: CallStatus | null; bits: Hex | Hex[] | null }][]).map(
          ([leg, v]) => ({
            leg,
            status: v.status,
            bits: v.bits === null ? null : clipBits(v.bits),
          }),
        ),
        ulp: w.ulp,
      })),
      hints: hints.map((h) => ({ code: h.code, message: h.message })),
      unknown_id: null as UnkId | null,
      rows: inlineRows,
      stream_id: stream?.stream_id ?? null,
    };
    const subject: Subject | null =
      record !== null
        ? emulationSubject(
            record,
            input.emulation?.state_from ?? "baseline",
            record.current,
            (input.emulation?.state_from ?? "baseline") === "baseline",
          )
        : lc.session !== null
          ? { kind: "process-instance", instance_id: lc.session.instanceId as PiId, module_map_id: null }
          : null;
    const links = [emuEvidence, liveResult?.evidence_id ?? null, stream?.manifest ?? null].filter(
      (l): l is EvId => l !== null,
    );
    const parameters: JsonObject = {
      address: input.address,
      target: { module: liveTarget?.ref.module ?? emuTarget?.ref.module ?? null, rva },
      legs: [...legs],
      plan_digest: planDigest(primaryPlan.plan, {
        module: liveTarget?.ref.module ?? emuTarget?.ref.module ?? null,
        rva: rva as Hex | null,
        va: "0x0",
      }),
      vectors_digest: vectors.digest,
      slice: { offset, count },
      compare: (input.compare === undefined ? {} : JSON.parse(JSON.stringify(input.compare))) as JsonObject,
      fp: { mxcsr: fp.value.mxcsr, fpcw: fp.value.fpcw, source: fp.value.source },
      emulation: (input.emulation === undefined ? {} : JSON.parse(JSON.stringify(input.emulation))) as JsonObject,
      allow_image_mismatch: input.allow_image_mismatch,
      ...(links.length === 0 ? { run_nonce: randomUUID() } : {}),
    };
    const recorded = await services.evidence.recorder.record({
      predicate_type: "bea.diff",
      operation,
      input: parameters,
      subject,
      provider: { id: "bea", name: "bea diff_function", version: null },
      result: result as unknown as JsonObject,
      coverage: mergeCoverage(...parts),
      limitations,
      evidence_links: links,
      ...(liveResult === null ? {} : { effects: [liveResult.effect_id] }),
      literals: literals.value,
    });
    if (!recorded.ok)
      return err(liveResult === null ? recorded.error : { ...recorded.error, effects_applied: [liveResult.effect_id] });
    const evidenceId = recorded.value.record.evidence_id as EvId;
    let unknownId: UnkId | null = null;
    if (verdict !== "equivalent-on-tested-inputs" && input.record_unknown && imageSha !== null) {
      const pair = [...legs].sort().join("~");
      const where = rva === null ? "the target function" : `the function at rva ${rva}`;
      const question =
        verdict === "differ"
          ? `Why does ${where} of image ${imageSha} differ between the ${pair.replaceAll("~", " and ")} legs on tested inputs?`
          : `Is ${where} of image ${imageSha} equivalent between the ${pair.replaceAll("~", " and ")} legs? Some tested vectors were inconclusive.`;
      const severe =
        verdict === "differ" &&
        (outcomeDifferences > 0 || compareResult.profile.integerDiffs > 0 || (compareResult.profile.maxUlp ?? 0) > 4);
      const unknown = await services.evidence.unknowns.autoRecord(
        {
          question,
          domain: legs.includes("emulation") ? "emulation-fidelity" : "function-semantics",
          scope_image_sha256: imageSha,
          status: "open",
          severity: severe ? "high" : "medium",
          supporting: [evidenceId],
          contradicting: [],
          probes:
            hintProbes(hints).length > 0
              ? hintProbes(hints)
              : ['Inspect worst[]; run emu_call single with detail "complete" on a differing vector.'],
          resolution: null,
        },
        operation,
      );
      if (unknown.ok) unknownId = unknown.value.unknown_id;
      else this.#app.logger.warn("diff_function could not record its unknown", { code: unknown.error._tag });
    }
    const delivered = deliver(recorded.value) as unknown as DiffFunctionOutput;
    return ok({ ...delivered, unknown_id: unknownId });
  }

  /** Compact inline rows (bounded: per-leg status and return bits, per-pair outcome; no inputs, no out fields). */
  #compactRows(
    pairs: ReturnType<typeof compareLegs>["pairs"],
    legs: readonly LegData[],
    offset: number,
    count: number,
  ): JsonObject[] {
    const rows: JsonObject[] = [];
    for (let k = 0; k < count; k++) {
      rows.push({
        i: offset + k,
        legs: legs.map((leg) => {
          const ret = leg.cells["ret"]?.[k] ?? null;
          return {
            leg: leg.leg,
            s: leg.status[k] ?? null,
            r: ret === null ? null : clipBits(typeof ret === "string" ? ret : [...ret]),
          };
        }),
        pairs: pairs.flatMap((pair) => {
          const v = pair.vectors[k];
          return v === undefined
            ? []
            : [
                {
                  pair: `${pair.a}~${pair.b}`,
                  r: v.r,
                  u: v.ulp ?? null,
                  why: v.why === undefined ? null : v.why.slice(0, 64),
                },
              ];
        }),
      });
    }
    return rows;
  }

  /** Stream rows (S5 §11.3): {i, in, l: {leg: {s, r?, f?}}, p: {"a~b": {r, u?, why?}}}. */
  #rows(
    pairs: ReturnType<typeof compareLegs>["pairs"],
    legs: readonly LegData[],
    vectors: NormalizedVectors,
    offset: number,
    count: number,
  ): JsonObject[] {
    const rows: JsonObject[] = [];
    for (let k = 0; k < count; k++) {
      const inputs: Record<string, JsonValue> = {};
      for (const [name, cells] of Object.entries(vectors.columns)) {
        const cell = cells[k];
        if (cell !== undefined) inputs[name] = typeof cell === "string" ? cell : [...cell];
      }
      const perLeg: Record<string, JsonValue> = {};
      for (const leg of legs) {
        const entry: Record<string, JsonValue> = { s: leg.status[k] ?? null };
        const ret = leg.cells["ret"]?.[k];
        if (ret !== undefined && ret !== null) entry["r"] = typeof ret === "string" ? ret : [...ret];
        const fields: Record<string, JsonValue> = {};
        for (const [name, cells] of Object.entries(leg.cells)) {
          if (name === "ret") continue;
          const cell = cells[k];
          if (cell !== undefined && cell !== null) fields[name] = typeof cell === "string" ? cell : [...cell];
        }
        if (Object.keys(fields).length > 0) entry["f"] = fields;
        perLeg[leg.leg] = entry;
      }
      const perPair: Record<string, JsonValue> = {};
      for (const pair of pairs) {
        const v = pair.vectors[k];
        if (v === undefined) continue;
        perPair[`${pair.a}~${pair.b}`] = {
          r: v.r,
          ...(v.ulp === undefined || v.ulp === null ? {} : { u: v.ulp }),
          ...(v.why === undefined ? {} : { why: v.why }),
        };
      }
      rows.push({ i: offset + k, in: inputs, l: perLeg, p: perPair });
    }
    return rows;
  }

  async #recordEmulationLeg(
    handle: EmuSessionHandle,
    record: SessionRecord,
    plan: ClassifiedRequest,
    target: ResolvedAddress,
    vectors: NormalizedVectors,
    offset: number,
    batch: BatchResult,
    outcome: CallOutcomeColumns,
    fp: ResolvedFpEnv,
    from: string,
    input: DiffFunctionInput,
    literals: SensitiveLiterals,
    operation: string,
  ): Promise<Result<EvId, BeaError>> {
    const summary = batch.summary;
    const digest = planDigest(plan.plan, {
      module: target.ref.module,
      rva: target.ref.rva as Hex | null,
      va: formatHex(target.va),
    });
    const optionsDigest = canonicalDigest({
      max_instructions: input.emulation?.max_instructions ?? 1_000_000,
      isolation: input.emulation?.isolation ?? "snapshot",
      mxcsr: fp.mxcsr,
      fpcw: fp.fpcw,
    });
    const fromDigest =
      from === "baseline"
        ? record.baseline
        : from === "current"
          ? record.current
          : (record.named.get(from) ?? record.current);
    const fromWasBaseline = from === "baseline" || (from === "current" && record.currentIsBaseline);
    record.current = afterDigest(
      fromDigest,
      {
        method: "emu.batch",
        planDigest: digest,
        vectorsDigest: vectors.digest,
        slice: { offset, count: summary.completed },
        writesDigest: canonicalDigest([]),
        optionsDigest,
        isolation: input.emulation?.isolation ?? "snapshot",
      },
      summary.deterministic ? null : randomUUID(),
    );
    record.currentIsBaseline = false;
    const harness = outcome.attribution.filter((a) => a === "harness").length;
    const deviations = Object.entries(batch.aggregates.deviations).map(([kind, v]) => ({
      kind: kind as DeviationKind,
      count: v?.vectors ?? 0,
    }));
    const stopped = summary.stopped ?? null;
    const stoppedResource =
      stopped?.data?.["resource"] === "heap" || stopped?.data?.["resource"] === "scratch"
        ? (stopped.data["resource"] as "heap" | "scratch")
        : null;
    const assessment = assessEmulation({
      deviations,
      importModels: Object.values(batch.aggregates.imports).map((v) => v.model),
      harnessStops: harness,
      isaStops: outcome.status.filter((s) => s === "unsupported_instruction").length,
      endedEarly: summary.cancelled ? "cancelled" : summary.deadlineReached ? "deadline" : null,
      deterministic: summary.deterministic,
      extraLimitations: stopped === null ? [] : [L.EMU_BATCH_STOPPED(stopped.index, stoppedResource)],
    });
    const result: JsonObject = {
      mode: "batch",
      leg: "diff_function emulation leg",
      target: { module: target.ref.module, rva: target.ref.rva, va: target.ref.va },
      offset: summary.offset,
      vectors: vectors.count,
      completed: summary.completed,
      by_status: byStatusOfSummary(summary) as JsonObject,
      by_attribution: { target: outcome.attribution.filter((a) => a === "target").length, harness },
      deviations: deviations.map((d) => ({ kind: d.kind, vectors: d.count })),
      ret_bits_digest: canonicalDigest((outcome.ret ?? []) as unknown as JsonValue),
      state: { from, from_digest: fromDigest, after_digest: record.current },
    };
    const recorded = await this.#app.services.evidence.recorder.record({
      predicate_type: "bea.emu.batch",
      operation,
      input: {
        session_id: handle.sessionId,
        address: input.address,
        plan_digest: digest,
        vectors_digest: vectors.digest,
        slice: { offset, count: vectors.count },
        options_digest: optionsDigest,
        state_from: from,
        fp: { mxcsr: hex64(formatHex(fp.mxcsr)), fpcw: hex64(formatHex(fp.fpcw)), source: fp.source },
        ...(summary.deterministic ? {} : { run_nonce: randomUUID() }),
      },
      subject: emulationSubject(record, from, fromDigest, fromWasBaseline),
      provider: {
        id: "unicorn",
        name: "Unicorn via bea-emu bridge",
        version: this.#app.services.emulator.availability().versions?.unicorn ?? null,
      },
      result,
      coverage:
        stopped === null
          ? assessment.coverage
          : mergeCoverage(assessment.coverage, { status: "partial", truncated: false, reasons: ["stopped_early"] }),
      limitations: assessment.limitations,
      ...(record.sessionEvidence === null ? {} : { evidence_links: [record.sessionEvidence] }),
      literals,
    });
    return recorded.ok ? ok(recorded.value.record.evidence_id as EvId) : recorded;
  }
}

/** at most 16 elements of an array cell inline (the stream keeps them all) */
const clipBits = (bits: Hex | readonly Hex[]): Hex | Hex[] => (typeof bits === "string" ? bits : bits.slice(0, 16));
const columnBits = (inputs: Readonly<Record<string, Hex | readonly Hex[]>>): { column: string; bits: Hex | Hex[] }[] =>
  Object.entries(inputs)
    .slice(0, 16)
    .map(([column, bits]) => ({ column, bits: clipBits(bits) }));

const sha256Of = (text: string | null | undefined): string | null =>
  text !== null && text !== undefined && SHA256_RE.test(text) ? text : null;
