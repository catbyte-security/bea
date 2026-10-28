import { planToAgent, planAddressExprs, planDigest } from "../../domain/callModel/classify.js";
import { decodeOutcome, rawOutLayout, type LiveFault } from "../../domain/callModel/decode.js";
import type { NormalizedVectors } from "../../domain/callModel/types.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { inputError, internalError } from "../../domain/errors/constructors.js";
import { COMPLETE, mergeCoverage, type Coverage } from "../../domain/evidence/coverage.js";
import { LIMITATIONS } from "../../domain/evidence/limitations.js";
import type { EvId, FxId } from "../../domain/ids.js";
import type { JsonObject, JsonValue } from "../../domain/json.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { AddressService } from "../../ports/address.js";
import type { OracleBatchRequest, OracleBatchResult, OracleCallPort } from "../../ports/emu.js";
import type { EvidenceRuntime, SensitiveLiterals } from "../../ports/evidence.js";
import type { LiveSession, OperationContext } from "../../ports/sessions.js";
import { AGENT_LIMIT_DEFAULTS } from "../../shared/agentLimits.js";
import type {
  CallFunctionParams,
  CallFunctionResult,
  EffectHint,
  FaultInfo,
  ResolvedTarget,
} from "../../shared/agentProtocol.js";
import type { PlanWire, RawBatchColumns, VectorsWire } from "../../shared/callPlan.js";
import type { Hex } from "../../shared/hex.js";
import type { BeaCore } from "../BeaApplication.js";
import { batchRows, writeCallBatchStream } from "./callBatchStream.js";

/**
 * The live oracle executor (DESIGN §5.3, §5.3.1; S5 §9.4–9.5): lowers a classified plan for the live address space,
 * runs it through the agent's exact-bits SEH-frame thunk (`callFunction`) in chunks of ≤ `chunk` vectors and time
 * slices of `max_wall_ms`, accumulates the raw columns, and registers the one irreversible `function-called` effect.
 * call_function (src/application/call/callFunction.ts) and the diff_function live leg (OracleCallPort.callPlanBatch)
 * share this code, so both legs run identical lowered plans by construction (D-INT-8).
 */
const INLINE_BATCH_ROWS = 64;
/**
 * S4 §13.5 allowed 16 covered vectors per RPC; the agent runs ONE (a second current-thread Stalker follow in the same
 * JS turn wedges the script unload, VERIFIED in the WP11 lab), so coverage chunks are single vectors (≈ 100 ms each).
 */
const COVERAGE_CHUNK = 1;
/** Leave this much of the deadline for decoding, the stream and the evidence record. */
export const FINALIZE_RESERVE_MS = 1500;
const MIN_RPC_MS = 250;

export interface OracleExecRequest {
  readonly wire: PlanWire;
  /** the vectors of this call; cell 0 is absolute vector index `offset` */
  readonly vectors: NormalizedVectors;
  readonly offset: number;
  readonly fp: { readonly mxcsr: number; readonly fpcw: number };
  readonly thread: CallFunctionParams["thread"];
  readonly coverage: boolean;
  readonly hooks: "suppress" | "observe";
  readonly overrides: "apply" | "bypass";
  /** core.clock.monoMs() deadline; the loop stops early (continuation) before it */
  readonly deadlineAt: number;
  readonly chunk?: number;
  readonly maxWallMs?: number;
}

export interface OracleRawRun {
  /** completed vectors from `offset` on, in order */
  readonly raw: RawBatchColumns;
  /** absolute vector indices */
  readonly faults: readonly FaultInfo[];
  readonly coverage:
    | readonly {
        readonly index: number;
        readonly blocks: readonly (readonly [Hex, number])[];
        readonly truncated: boolean;
      }[]
    | null;
  /** absolute index of the first vector that did not run (continuation), null when all ran */
  readonly next: number | null;
  readonly stop: "complete" | "deadline" | "lost-target" | "failure";
  readonly exceptionModel: "seh-frame" | "steal";
  readonly calleeExceptions: number;
  readonly beaTraps: number;
  readonly threadIds: readonly number[];
  /** scratch address of each plan buffer during the last chunk (agent effect.targets[1..], DESIGN §5.3 note) */
  readonly bufferAddresses: ReadonlyMap<string, Hex>;
  readonly resolved: ResolvedTarget | null;
  readonly targetInstruments: readonly string[];
  readonly hooksSuppressed: number;
  readonly overridesBypassed: boolean;
  readonly wallUs: number;
  readonly rpcs: number;
  /** a failure after target code may have run (timeout, cancel, exit, agent loss): the caller records what completed */
  readonly failure: BeaError | null;
}

/** Errors that prove the agent did not start a vector of the failed RPC (refusals, bad params, gates). */
const NOT_EXECUTED: ReadonlySet<BeaError["_tag"]> = new Set([
  "InputError",
  "GateDisabled",
  "InvalidState",
  "UnsupportedTarget",
  "ResourceConstraint",
  "ReferenceNotFound",
  "CapabilityUnavailable",
  "AddressUnmapped",
  "MemoryAccessFailed",
  "SessionNotFound",
  // review fix EMU-14: a thread_at hook that cannot be installed fails before any vector (no function-called effect)
  "InstrumentationFailed",
]);

/** The RPC failed because the target process is gone (exited, or the agent died with it). */
const targetLost = (error: BeaError, session: LiveSession): boolean =>
  error._tag === "TargetExited" ||
  (error._tag === "CapabilityUnavailable" &&
    error.capability === "agent" &&
    error.reason === "agent-gone" &&
    session.liveness().state === "exited");

/** The agent's Timeout.started of a thread/hook-mode chunk (null: not an agent timeout, or an older agent). */
const calleeStarted = (error: BeaError): boolean | null => {
  if (error._tag !== "ProviderTimeout" || error.diagnostics?.["agent_tag"] !== "Timeout") return null;
  const started = error.diagnostics["started"];
  return typeof started === "boolean" ? started : null;
};

/**
 * Review fix AGENT-1: the callee started on the target thread and had not returned at the timeout. It is still
 * running there (it returns into BEA's thunk later, which the agent keeps mapped), so its effects may have happened
 * and a retry would start a second call.
 */
const stillRunning = (error: BeaError): BeaError => ({
  ...error,
  message:
    "The function was called on the target thread but did not return before the thread timeout; it may still be running there, and its effects may already have happened.",
  remediation:
    "Do not repeat the call while the earlier one may still run on that thread. Check session_status; close_session ends an owned target, and on an attached target the call keeps running until it returns.",
});

const emptyRaw = (): { -readonly [K in keyof RawBatchColumns]: RawBatchColumns[K] } => ({
  completed: 0,
  status: [],
  rax: [],
  xmm0lo: [],
  out: {},
  mxcsrOut: [],
  fpcwOut: [],
});

const sliceVectors = (vectors: NormalizedVectors, from: number, count: number, absolute: number): VectorsWire => {
  const columns: Record<string, Hex[] | Hex[][]> = {};
  for (const [name, cells] of Object.entries(vectors.columns))
    columns[name] = cells.slice(from, from + count) as Hex[] | Hex[][];
  return { offset: absolute, count, columns };
};

const appendRaw = (into: ReturnType<typeof emptyRaw>, raw: RawBatchColumns): void => {
  const n = raw.completed;
  into.completed += n;
  into.status.push(...raw.status.slice(0, n));
  into.rax.push(...raw.rax.slice(0, n));
  into.xmm0lo.push(...raw.xmm0lo.slice(0, n));
  into.mxcsrOut.push(...raw.mxcsrOut.slice(0, n));
  into.fpcwOut.push(...raw.fpcwOut.slice(0, n));
  for (const [name, cells] of Object.entries(raw.out)) (into.out[name] ??= []).push(...cells.slice(0, n));
};

const bufferAddressesOf = (wire: PlanWire, effect: EffectHint): Map<string, Hex> => {
  const map = new Map<string, Hex>();
  wire.buffers.forEach((buffer, i) => {
    const address = effect.targets[i + 1]?.address;
    if (address !== null && address !== undefined) map.set(buffer.name, address);
  });
  return map;
};

/** Runs every vector of `req` (or until the deadline) through the agent; never records evidence. */
export const runOracleChunks = async (
  core: BeaCore,
  session: LiveSession,
  req: OracleExecRequest,
  op: OperationContext,
): Promise<Result<OracleRawRun, BeaError>> => {
  const raw = emptyRaw();
  const faults: FaultInfo[] = [];
  const coverage: { index: number; blocks: (readonly [Hex, number])[]; truncated: boolean }[] = [];
  const threadIds = new Set<number>();
  const instruments = new Set<string>();
  let exceptionModel: "seh-frame" | "steal" = "seh-frame";
  let calleeExceptions = 0;
  let beaTraps = 0;
  let hooksSuppressed = 0;
  let overridesBypassed = false;
  let resolved: ResolvedTarget | null = null;
  let addresses: ReadonlyMap<string, Hex> = new Map();
  let failure: BeaError | null = null;
  let stop: OracleRawRun["stop"] = "complete";
  let rpcs = 0;
  let cursor = 0;
  const total = req.vectors.count;
  const chunkCap = Math.max(
    1,
    Math.min(
      req.chunk ?? AGENT_LIMIT_DEFAULTS.call_max_vectors,
      req.coverage ? COVERAGE_CHUNK : AGENT_LIMIT_DEFAULTS.call_max_vectors,
    ),
  );
  const started = core.clock.monoMs();
  while (cursor < total) {
    const remaining = Math.floor(req.deadlineAt - core.clock.monoMs());
    if (rpcs > 0 && remaining < MIN_RPC_MS) {
      stop = "deadline";
      break;
    }
    const count = Math.min(chunkCap, total - cursor);
    const thread: CallFunctionParams["thread"] =
      req.thread.kind === "agent"
        ? req.thread
        : { ...req.thread, timeout_ms: Math.max(100, Math.min(req.thread.timeout_ms, remaining - 100)) };
    const params: CallFunctionParams = {
      plan: req.wire,
      vectors: sliceVectors(req.vectors, cursor, count, req.offset + cursor),
      fp: { mxcsr: req.fp.mxcsr, fpcw: req.fp.fpcw },
      thread,
      chunk: count,
      max_wall_ms: req.maxWallMs ?? AGENT_LIMIT_DEFAULTS.call_max_wall_ms,
      coverage: req.coverage
        ? { mode: "blocks", modules: [], max_blocks: AGENT_LIMIT_DEFAULTS.call_coverage_blocks }
        : { mode: "none", modules: [], max_blocks: 0 },
      hooks: req.hooks,
      overrides: req.overrides,
    };
    const reply = await session.agent.call("callFunction", params, { op, timeoutMs: Math.max(1000, remaining) });
    rpcs += 1;
    if (!reply.ok) {
      if (targetLost(reply.error, session)) {
        // review fix EMU-10: the target exited during the chunk (e.g. the callee called ExitProcess). The agent dies
        // with it and cannot reply, so the host derives the loss; the chunk's vectors count as not run (cursor stays
        // at the chunk start), and the earlier chunks' results stand. The error is kept for call_function.
        failure = reply.error;
        stop = "lost-target";
        break;
      }
      const started = calleeStarted(reply.error);
      // review fix AGENT-1: a thread/hook chunk that timed out before its thread ran it (started:false) executed
      // nothing, and its closure returns without calling when it runs late
      if (rpcs === 1 && (NOT_EXECUTED.has(reply.error._tag) || started === false)) return reply;
      failure = started === true ? stillRunning(reply.error) : reply.error;
      stop = "failure";
      break;
    }
    const value: CallFunctionResult = reply.value;
    const done = Math.min(value.raw.completed, count);
    appendRaw(raw, { ...value.raw, completed: done });
    faults.push(...value.faults);
    for (const c of value.coverage ?? []) coverage.push({ index: c.index, blocks: c.blocks, truncated: c.truncated });
    threadIds.add(value.thread_id);
    if (value.exception_model === "steal") exceptionModel = "steal";
    calleeExceptions += value.callee_exceptions;
    beaTraps += value.bea_traps_during_call;
    hooksSuppressed += value.perturbation.hooks_suppressed;
    overridesBypassed ||= value.perturbation.overrides_bypassed;
    for (const id of value.perturbation.target_instruments) instruments.add(id);
    resolved = value.resolved;
    addresses = bufferAddressesOf(req.wire, value.effect);
    cursor += done;
    if (value.lost_target) {
      stop = "lost-target";
      break;
    }
    if (done === 0) {
      failure = internalError("call_function", new Error("the agent completed no vector of a chunk"));
      stop = "failure";
      break;
    }
  }
  return ok({
    raw,
    faults,
    coverage: req.coverage ? coverage : null,
    next: cursor < total ? req.offset + cursor : null,
    stop,
    exceptionModel,
    calleeExceptions,
    beaTraps,
    threadIds: [...threadIds],
    bufferAddresses: addresses,
    resolved,
    targetInstruments: [...instruments].sort(),
    hooksSuppressed,
    overridesBypassed,
    wallUs: Math.round((core.clock.monoMs() - started) * 1000),
    rpcs,
    failure,
  });
};

/** Coverage + limitations shared by every oracle record (S2 §7.5; DESIGN §6.2 #26 limitations). */
export const runCoverage = (run: OracleRawRun): { readonly coverage: Coverage; readonly limitations: string[] } => {
  const parts: Coverage[] = [];
  const limitations: string[] = [];
  if (run.exceptionModel === "steal") {
    parts.push({ status: "partial", truncated: false, reasons: ["callee_handlers_not_honoured"] });
    limitations.push(LIMITATIONS.CALL_SEH_UNAVAILABLE);
  }
  if (run.next !== null) {
    const reason =
      run.stop === "lost-target" ? "process_exited" : run.failure?._tag === "Cancelled" ? "cancelled" : "deadline";
    parts.push({ status: "partial", truncated: false, reasons: [reason] });
    limitations.push(
      LIMITATIONS.ENDED_EARLY(
        reason === "process_exited" ? "process exited" : reason === "cancelled" ? "cancelled" : "deadline",
      ),
    );
  }
  if (run.calleeExceptions > 0) limitations.push(LIMITATIONS.CALL_CALLEE_EXCEPTIONS(run.calleeExceptions));
  if (run.targetInstruments.length > 0 || run.hooksSuppressed > 0)
    limitations.push(LIMITATIONS.CALL_HOOKS_ON_PATH(Math.max(1, run.targetInstruments.length)));
  return { coverage: parts.length === 0 ? COMPLETE : mergeCoverage(...parts), limitations };
};

export const liveFaults = (faults: readonly FaultInfo[]): LiveFault[] =>
  faults.map((f) => ({ index: f.index, type: f.type, module: f.module, rva: f.rva, code: f.code }));

/** The one irreversible `function-called` effect of a call (S4 §13.7, S2 §6.1: execute class, taints the instance). */
export const applyCallEffect = async (
  evidence: EvidenceRuntime,
  session: LiveSession,
  parts: {
    readonly target: { readonly va: Hex; readonly module: string | null; readonly rva: Hex | null };
    readonly run: OracleRawRun;
    readonly planDigest: string;
    readonly vectors: NormalizedVectors;
    readonly offset: number;
    readonly fp: { readonly mxcsr: number; readonly fpcw: number };
    readonly literals: SensitiveLiterals;
  },
): Promise<Result<FxId, BeaError>> => {
  const map = evidence.modules.current(session.instanceId);
  const effect = await evidence.effects.apply({
    instance_id: session.instanceId,
    kind: "function-called",
    target: {
      address: {
        va: parts.target.va,
        module_map_id: map?.map().module_map_id ?? null,
        module_key: parts.target.module?.toLowerCase() ?? null,
        rva: parts.target.rva,
      },
      size: null,
      threads: [...parts.run.threadIds],
    },
    parameters: {
      plan_digest: parts.planDigest,
      vectors_digest: parts.vectors.digest,
      offset: parts.offset,
      completed: parts.run.raw.completed,
      fp: { mxcsr: parts.fp.mxcsr, fpcw: parts.fp.fpcw },
    },
    applied_by: "call_function",
    ...(parts.target.module !== null && parts.target.rva !== null
      ? { display_target: `${parts.target.module}+${parts.target.rva}` }
      : {}),
    literals: parts.literals,
  });
  return effect.ok ? ok(effect.value.effect_id as FxId) : effect;
};

/** Generic oracle record (the diff_function live leg); call_function records its tool result instead. */
const genericResult = (
  req: OracleBatchRequest,
  run: OracleRawRun,
  outcome: ReturnType<typeof decodeOutcome>,
  stream: { readonly stream_id: string | null },
  digest: string,
): JsonObject => ({
  target: { va: req.target.va, module: req.target.module, rva: req.target.rva },
  plan_digest: digest,
  vectors: { digest: req.vectors.digest, offset: req.offset, count: req.vectors.count, completed: run.raw.completed },
  fp: { mxcsr: `0x${req.fp.mxcsr.toString(16)}`, fpcw: `0x${req.fp.fpcw.toString(16)}`, source: req.fp.source },
  exception_model: run.exceptionModel,
  callee_exceptions: run.calleeExceptions,
  status: run.raw.completed <= INLINE_BATCH_ROWS ? [...outcome.status] : null,
  ret: run.raw.completed <= INLINE_BATCH_ROWS && outcome.ret !== null ? [...outcome.ret] : null,
  fields: run.raw.completed <= INLINE_BATCH_ROWS ? (JSON.parse(JSON.stringify(outcome.fields)) as JsonValue) : null,
  faults: outcome.faults
    .slice(0, 32)
    .map((f) => ({ index: f.index, cause: f.cause, module: f.site.module, rva: f.site.rva })),
  stream_id: stream.stream_id,
  continuation: run.next === null ? null : { vector_offset: run.next },
});

export interface OracleServiceDeps {
  readonly evidence: EvidenceRuntime;
  readonly address: AddressService;
}

/**
 * OracleCallPort (S5 §9.4) for the diff_function live leg: the gate is checked again here (defense in depth; the
 * caller checks it BEFORE address resolution), then the plan runs, the effect and a bea.call.oracle record are written,
 * and rows above 64 vectors go to a `call-batch` stream.
 */
export const createOracleCallPort = (core: BeaCore, deps: OracleServiceDeps): OracleCallPort => ({
  callPlanBatch: async (session, req, op): Promise<Result<OracleBatchResult, BeaError>> => {
    const gate = core.gates.requireUnlessOwned("call_attached", op.name, session.ownership);
    if (!gate.ok) return gate;
    const literals = deps.evidence.literals(undefined);
    if (!literals.ok) return literals;
    const space = { kind: "live" as const, session };
    const resolvedExprs = new Map<string, bigint>();
    for (const expr of planAddressExprs(req.plan)) {
      const r = await deps.address.resolve(space, expr, op, { path: "signature.args" });
      if (!r.ok) return r;
      resolvedExprs.set(expr, r.value.va);
    }
    const wire = planToAgent(req.plan, req.target.va, (expr) => resolvedExprs.get(expr));
    if (!wire.ok) return err(inputError(op.name, wire.error));
    const thread: CallFunctionParams["thread"] =
      req.thread === "agent"
        ? { kind: "agent" }
        : "at" in req.thread
          ? { kind: "hook", at: req.thread.at, tid: req.thread.tid, timeout_ms: req.thread.timeoutMs }
          : { kind: "thread", tid: req.thread.tid, timeout_ms: req.thread.timeoutMs };
    const ran = await runOracleChunks(
      core,
      session,
      {
        wire: wire.value,
        vectors: req.vectors,
        offset: req.offset,
        fp: req.fp,
        thread,
        coverage: req.coverage,
        hooks: "suppress",
        overrides: "bypass",
        deadlineAt: req.deadlineAt - FINALIZE_RESERVE_MS,
        chunk: req.chunk,
      },
      op,
    );
    if (!ran.ok) return ran;
    const run = ran.value;
    const capture = deps.evidence.instances.capture(session.instanceId);
    const digest = planDigest(req.plan, req.target);
    const effect = await applyCallEffect(deps.evidence, session, {
      target: req.target,
      run,
      planDigest: digest,
      vectors: req.vectors,
      offset: req.offset,
      fp: req.fp,
      literals: literals.value,
    });
    if (!effect.ok) return effect;
    // out buffers decode by field when the caller passes the declared layout (diff_function), else as raw bytes
    const layout = req.outLayout ?? rawOutLayout(req.plan);
    const outcome = decodeOutcome(req.plan, run.raw, req.offset, layout, liveFaults(run.faults));
    const stream =
      run.raw.completed > INLINE_BATCH_ROWS
        ? await writeCallBatchStream(deps.evidence, session, effect.value, batchRows(outcome), literals.value)
        : ok({ stream_id: null, manifest: null, coverage: COMPLETE });
    if (!stream.ok) return stream;
    const written = stream.value;
    const { coverage, limitations } = runCoverage(run);
    const recorded = await deps.evidence.recorder.record({
      predicate_type: "bea.call.oracle",
      operation: op.name,
      input: { plan_digest: digest, vectors_digest: req.vectors.digest, offset: req.offset, fp_source: req.fp.source },
      subject: { kind: "process-instance", instance_id: session.instanceId },
      capture,
      provider: { id: "frida", name: "frida", version: null },
      agent: deps.evidence.instances.get(session.instanceId)?.agent ?? null,
      authority: "live-process",
      result: genericResult(req, run, outcome, written, digest),
      coverage: mergeCoverage(coverage, written.coverage),
      limitations,
      effects: [effect.value],
      ...(written.manifest === null ? {} : { evidence_links: [written.manifest] }),
      literals: literals.value,
    });
    if (!recorded.ok) return recorded;
    // EMU-10: a lost target is a result (the live leg's remaining vectors are not run), not a failure of the diff
    if (run.failure !== null && run.stop !== "lost-target")
      return err({
        ...run.failure,
        effects_applied: [effect.value],
        partial: { kind: "retained-evidence", evidence_id: recorded.value.record.evidence_id },
      });
    return ok({
      outcome,
      completed: run.raw.completed,
      nextOffset: run.next,
      lostTarget: run.stop === "lost-target",
      evidence_id: recorded.value.record.evidence_id as EvId,
      effect_id: effect.value,
      coverageBlob: null,
      exceptionModel: run.exceptionModel,
      calleeExceptions: run.calleeExceptions,
    });
  },
});
