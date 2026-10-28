import type { CallFunctionInput, CallFunctionOutput } from "../../contracts/areas/call.js";
import { planDigest } from "../../domain/callModel/classify.js";
import { decodeOutcome } from "../../domain/callModel/decode.js";
import { canonicalDigest } from "../../domain/canonical.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { inputError, internalError, withEffects, withPartial } from "../../domain/errors/constructors.js";
import { COMPLETE, mergeCoverage, type Coverage } from "../../domain/evidence/coverage.js";
import type { BlobRef } from "../../domain/evidence/record.js";
import type { EvId, StId } from "../../domain/ids.js";
import type { JsonObject, JsonValue } from "../../domain/json.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { EvidenceRuntime, SensitiveLiterals } from "../../ports/evidence.js";
import type { LiveSession, OperationContext } from "../../ports/sessions.js";
import type { BeaApplication } from "../BeaApplication.js";
import type { HandlerContext } from "../handlerContext.js";
import { liveOp } from "../sessionAccess.js";
import { batchRows, writeCallBatchStream } from "./callBatchStream.js";
import { deliver } from "./envelope.js";
import {
  applyCallEffect,
  FINALIZE_RESERVE_MS,
  liveFaults,
  runCoverage,
  runOracleChunks,
  type OracleRawRun,
} from "./OracleService.js";
import { prepareCall, type PreparedCall } from "./prepareCall.js";
import { batchView, blockCoverage, callNotes, fpView, singleView } from "./shapeResult.js";

/**
 * call_function (DESIGN §6.2 #26). Order of refusals: session/agent state (sessionAccess) -> the call_attached gate
 * for attached targets BEFORE any agent RPC (F3, CT-I1 spy test) -> paused-thread refusal -> request preparation
 * (addresses, init_from reads, classification, vectors, FP environment) -> execution. Once target code may have run,
 * the function-called effect is registered and every outcome (also a timeout or cancel after some vectors) is
 * recorded as bea.call.oracle before the tool answers.
 */
type Input = CallFunctionInput;
type Output = CallFunctionOutput;

/** Inputs above these sizes are retained as a blob and cited by digest (S5 §7.3; records stay far below 4 MiB). */
const PARAM_INLINE_VECTORS_CHARS = 64 * 1024;
const PARAM_INLINE_TEXT_CHARS = 4096;

/** Evidence parameters: the validated input, with bulky vectors/init_hex/defaults replaced by digests. */
const evidenceInput = async (
  evidence: EvidenceRuntime,
  input: Input,
  prepared: PreparedCall,
  literals: SensitiveLiterals,
): Promise<{ readonly params: JsonObject; readonly blob: BlobRef | null }> => {
  const json = JSON.parse(JSON.stringify(input)) as Record<string, JsonValue>;
  let bulky = false;
  if (
    input.vectors?.columns !== undefined &&
    JSON.stringify(input.vectors.columns).length > PARAM_INLINE_VECTORS_CHARS
  ) {
    json["vectors"] = { count: prepared.total, columns_digest: prepared.vectors.digest };
    bulky = true;
  }
  json["buffers"] = input.buffers.map((buffer) => {
    const b = JSON.parse(JSON.stringify(buffer)) as Record<string, JsonValue>;
    if (buffer.init_hex !== undefined && buffer.init_hex.length > PARAM_INLINE_TEXT_CHARS) {
      b["init_hex"] = `sha256:${canonicalDigest(buffer.init_hex.toLowerCase())}`;
      bulky = true;
    }
    b["fields"] = buffer.fields.map((field) => {
      if (field.default === undefined || field.default.length <= PARAM_INLINE_TEXT_CHARS)
        return field as unknown as JsonValue;
      bulky = true;
      return { ...field, default: `sha256:${canonicalDigest(field.default)}` } as unknown as JsonValue;
    });
    return b;
  });
  if (!bulky) return { params: json, blob: null };
  const stored = await evidence.blobs.put(new TextEncoder().encode(JSON.stringify(input)), {
    role: "call-input",
    media_type: "application/json",
    literals,
  });
  return { params: json, blob: stored.ok && !("redacted" in stored.value) ? stored.value : null };
};

const rawDetail = (prepared: PreparedCall, run: OracleRawRun, digest: string): JsonObject => ({
  plan_digest: digest,
  vectors_digest: prepared.vectors.digest,
  thread_ids: [...run.threadIds],
  bea_traps_during_call: run.beaTraps,
  hooks_suppressed: run.hooksSuppressed,
  target_instruments: [...run.targetInstruments],
  overrides_bypassed: run.overridesBypassed,
  rpcs: run.rpcs,
  resolved: run.resolved === null ? null : (JSON.parse(JSON.stringify(run.resolved)) as JsonValue),
});

const finish = async (
  app: BeaApplication,
  ctx: HandlerContext,
  input: Input,
  session: LiveSession,
  op: OperationContext,
  parts: { readonly prepared: PreparedCall; readonly run: OracleRawRun; readonly literals: SensitiveLiterals },
): Promise<Result<Output, BeaError>> => {
  const { prepared, run, literals } = parts;
  const evidence = app.services.evidence;
  const capture = evidence.instances.capture(session.instanceId);
  const digest = planDigest(prepared.plan, prepared.target);
  const effect = await applyCallEffect(evidence, session, {
    target: prepared.target,
    run,
    planDigest: digest,
    vectors: prepared.vectors,
    offset: prepared.offset,
    fp: prepared.fp,
    literals,
  });
  if (!effect.ok) return effect;
  const effects = [effect.value];
  if (run.raw.completed === 0)
    return err(withEffects(run.failure ?? internalError(ctx.operation, new Error("no vector completed")), effects));
  const outcome = decodeOutcome(prepared.plan, run.raw, prepared.offset, prepared.layout, liveFaults(run.faults));
  const rows = prepared.mode === "batch" && run.raw.completed > input.inline_limit ? batchRows(outcome) : null;
  let stream: { stream_id: StId | null; manifest: EvId | null; coverage: Coverage } = {
    stream_id: null,
    manifest: null,
    coverage: COMPLETE,
  };
  if (rows !== null) {
    const written = await writeCallBatchStream(evidence, session, effect.value, rows, literals);
    if (!written.ok) return err(withEffects(written.error, effects));
    stream = written.value;
  }
  const deps = { evidence, address: app.services.address };
  const cov = await blockCoverage(deps, session, run, literals, op);
  const shapeNotes = { truncatedValues: false };
  const view =
    prepared.mode === "single"
      ? { call: await singleView({ address: deps.address, session }, prepared, run, outcome, shapeNotes) }
      : {
          batch: await batchView(
            { address: deps.address, session },
            prepared,
            run,
            outcome,
            { inlineLimit: input.inline_limit, rows, streamId: stream.stream_id },
            shapeNotes,
          ),
        };
  const result = {
    target: prepared.target,
    mode: prepared.mode,
    fp: fpView(prepared.fp),
    exception_model: run.exceptionModel,
    callee_exceptions: run.calleeExceptions,
    ...view,
    block_coverage: cov.view,
  };
  const base = runCoverage(run);
  const extra = callNotes(prepared, run, session, {
    truncatedValues: shapeNotes.truncatedValues,
    coverageTruncated: cov.truncated,
  });
  const params = await evidenceInput(evidence, input, prepared, literals);
  const recorded = await evidence.recorder.record({
    predicate_type: "bea.call.oracle",
    operation: ctx.operation,
    input: params.params,
    identityExclude: ["inline_limit"],
    subject: { kind: "process-instance", instance_id: session.instanceId },
    capture,
    provider: { id: "frida", name: "frida", version: null },
    agent: evidence.instances.get(session.instanceId)?.agent ?? null,
    authority: "live-process",
    result: JSON.parse(JSON.stringify(result)) as JsonObject,
    raw_result: rawDetail(prepared, run, digest),
    blobs: [...(cov.blob === null ? [] : [cov.blob]), ...(params.blob === null ? [] : [params.blob])],
    coverage: mergeCoverage(base.coverage, stream.coverage, ...extra.coverage),
    limitations: [...base.limitations, ...extra.limitations],
    effects,
    ...(stream.manifest === null ? {} : { evidence_links: [stream.manifest] }),
    literals,
  });
  if (!recorded.ok) return err(withEffects(recorded.error, effects));
  if (run.failure !== null)
    return err(withPartial(withEffects(run.failure, effects), recorded.value.record.evidence_id));
  return ok(deliver(recorded.value) as unknown as Output);
};

const callLive = async (
  app: BeaApplication,
  ctx: HandlerContext,
  input: Input,
  session: LiveSession,
  op: OperationContext,
): Promise<Result<Output, BeaError>> => {
  // F3: attached targets need the call_attached gate, checked once ownership is known and before ANY agent RPC.
  const gate = ctx.gates.requireUnlessOwned("call_attached", ctx.operation, session.ownership);
  if (!gate.ok) return gate;
  if (session.paused && (input.thread_id !== undefined || input.thread_at !== undefined))
    return err(
      inputError(ctx.operation, [
        {
          path: input.thread_id !== undefined ? "thread_id" : "thread_at",
          reason: "invalid_value",
          message:
            "The target is paused (spawned, not resumed): call resume_process first, or call on the agent thread.",
        },
      ]),
    );
  const literals = app.services.evidence.literals(input.sensitive_values);
  if (!literals.ok) return literals;
  const budgetMs = Math.max(0, Math.min(ctx.remainingMs(), input.timeout_ms));
  const deadlineAt = app.clock.monoMs() + budgetMs;
  const prepared = await prepareCall({ address: app.services.address }, input, session, op, budgetMs);
  if (!prepared.ok) return prepared;
  const p = prepared.value;
  const ran = await runOracleChunks(
    app,
    session,
    {
      wire: p.wire,
      vectors: p.vectors,
      offset: p.offset,
      fp: p.fp,
      thread: p.thread,
      coverage: input.coverage,
      hooks: input.hooks,
      overrides: input.overrides,
      deadlineAt: deadlineAt - FINALIZE_RESERVE_MS,
    },
    op,
  );
  if (!ran.ok) return ran;
  return finish(app, ctx, input, session, op, { prepared: p, run: ran.value, literals: literals.value });
};

export const runCallFunction = (
  app: BeaApplication,
  input: Input,
  ctx: HandlerContext,
): Promise<Result<Output, BeaError>> =>
  liveOp(app, ctx, input.session_id, { mode: "exclusive", need: "agent" }, (session, op) =>
    callLive(app, ctx, input, session, op),
  );
