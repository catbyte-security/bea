// =================================================================================================
// src/application/watch/install.ts — the host half of installing a watch/poll/trace instrument (S3 §12, S2 §6–§10,
// D-INT-7; WP9-WATCH). After the agent RPC armed the instrument (inside the session's exclusive section):
//   anchor capture → effect (watch-armed / trace-following; poll records none) → StreamBinder.bind (announcement
//   rule: right after the RPC that created the stream) → RecordingRegistry.create (rec_ handle) → bea.instrument.install
// Record-before-reference: the fx line exists before the stream descriptor that names it, and both before the
// evidence that cites them. A failure after the RPC stops the agent instrument so nothing stays armed unrecorded.
// =================================================================================================
import type { AddressRef } from "../../domain/address/addressRef.js";
import type { Effect } from "../../domain/effects/effect.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { COMPLETE } from "../../domain/evidence/coverage.js";
import type { FxId, StId } from "../../domain/ids.js";
import type { JsonObject, JsonValue } from "../../domain/json.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { AnchorCapture, RecordedEvidence, StreamEncoding } from "../../ports/evidence.js";
import type { Recording, RecordingKind } from "../../ports/recordings.js";
import type { LiveSession, OperationContext, WaitCondition } from "../../ports/sessions.js";
import type { BeaApplication } from "../BeaApplication.js";
import type { HandlerContext } from "../handlerContext.js";
import { liveOp } from "../sessionAccess.js";

export interface InstallFlow {
  readonly tool: "watch_memory" | "trace_execution";
  readonly kind: Extract<RecordingKind, "watch" | "poll" | "trace">;
  readonly agentInstrumentId: string;
  readonly agentStream: string;
  readonly encoding: StreamEncoding;
  readonly decoders: JsonObject;
  readonly effect: {
    readonly kind: "watch-armed" | "trace-following";
    readonly target: Effect["target"];
    readonly parameters: JsonObject;
    readonly display: string | null;
  } | null;
  readonly durationMs: number;
  readonly maxEvents: number;
  /** the validated tool input (the Recorder strips delivery keys) */
  readonly input: JsonObject;
  readonly target: { readonly ref: AddressRef; readonly size: number | null } | null;
  readonly limitations: readonly string[];
  readonly capture: AnchorCapture;
  /** bea.instrument.install result, given the handles the flow created */
  readonly result: (ids: { recordingId: string; streamId: StId; effectId: FxId | null }) => JsonObject;
}
export interface Installed {
  readonly recording: Recording;
  readonly evidence: RecordedEvidence<JsonValue>;
  readonly effectId: FxId | null;
  readonly streamId: StId;
}

const stopAgentInstrument = async (session: LiveSession, op: OperationContext, id: string): Promise<void> => {
  try {
    await session.agent.call("instrumentStop", { id, final_flush: false }, { op });
  } catch {
    // best effort: the session may be going away
  }
};

export const completeInstall = async (
  app: BeaApplication,
  session: LiveSession,
  op: OperationContext,
  flow: InstallFlow,
): Promise<Result<Installed, BeaError>> => {
  const evidence = app.services.evidence;
  let effectId: FxId | null = null;
  let bound = false;
  const fail = async (error: BeaError): Promise<Result<never, BeaError>> => {
    await stopAgentInstrument(session, op, flow.agentInstrumentId);
    if (bound) await session.streams.end(flow.agentStream, "install-failed").catch(() => undefined);
    if (effectId !== null)
      await evidence.effects
        .transition(effectId, "reverted", { reason: "stop-requested", verification: null, residue: [] })
        .catch(() => undefined);
    return err(effectId === null ? error : { ...error, effects_applied: [...(error.effects_applied ?? []), effectId] });
  };
  const literals = evidence.literals(undefined);
  if (!literals.ok) return fail(literals.error);
  if (flow.effect !== null) {
    const applied = await evidence.effects.apply({
      instance_id: session.instanceId,
      kind: flow.effect.kind,
      target: flow.effect.target,
      parameters: flow.effect.parameters,
      lifetime: { duration_ms: flow.durationMs, max_hits: flow.maxEvents },
      applied_by: flow.tool,
      ...(flow.effect.display === null ? {} : { display_target: flow.effect.display }),
      literals: literals.value,
    });
    if (!applied.ok) return fail(applied.error);
    effectId = applied.value.effect_id;
  }
  const writer = await session.streams.bind(flow.agentStream, {
    source: { kind: flow.kind, instance_id: session.instanceId, effect_id: effectId, channel: flow.agentStream },
    encoding: flow.encoding,
    decoders: flow.decoders,
    literals: literals.value,
  });
  if (!writer.ok) return fail(writer.error);
  bound = true;
  const recording = app.services.recordings.create({
    sessionId: session.id,
    kind: flow.kind,
    agentInstrumentId: flow.agentInstrumentId,
    agentStream: flow.agentStream,
    streamId: writer.value.stream_id,
    effectId,
    durationMs: flow.durationMs,
    maxEvents: flow.maxEvents,
    startsAtResume: session.paused,
    decoders: flow.decoders,
  });
  const recorded = await evidence.recorder.record({
    predicate_type: "bea.instrument.install",
    operation: flow.tool,
    input: flow.input,
    identityExclude: ["wait_ms"],
    subject: { kind: "process-instance", instance_id: session.instanceId },
    capture: flow.capture,
    provider: { id: "frida", name: "bea-agent", version: null },
    agent: evidence.instances.get(session.instanceId)?.agent ?? null,
    result: flow.result({ recordingId: recording.id, streamId: writer.value.stream_id, effectId }),
    coverage: COMPLETE,
    limitations: flow.limitations,
    locations: flow.target === null ? [] : [evidence.locationOf(flow.target.ref, flow.target.size ?? undefined)],
    effects: effectId === null ? [] : [effectId],
    literals: literals.value,
  });
  if (!recorded.ok) return fail(recorded.error);
  return ok({
    recording,
    evidence: recorded.value as RecordedEvidence<JsonValue>,
    effectId,
    streamId: writer.value.stream_id,
  });
};

/** One waitFor slice, and the poll after a satisfied wait while the registry's end is still in flight. */
const WAIT_SLICE_MS = 250;
const SETTLE_POLL_MS = 25;
const delay = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * wait_ms (S6 §2.5): block until the recording ended or the wait ran out (a poll, never an error), outside the
 * exclusive section so stop/wait/status of the same session are not queued behind it. The agent stream ending is
 * only the hint: the registry ends the recording (final batch decoded, summary finalized) on the agent's "instrument
 * ended" message right after, so the loop polls until the recording itself is no longer active.
 */
export const waitForEnd = async (
  app: BeaApplication,
  ctx: HandlerContext,
  recording: Recording,
  waitMs: number,
): Promise<void> => {
  const sessionId = recording.create.sessionId;
  const agentStream = recording.create.agentStream;
  if (waitMs <= 0 || agentStream === null || recording.view().state !== "active") return;
  await liveOp(app, ctx, sessionId, { mode: "concurrent", need: "host" }, async (session, op) => {
    // UX-3: a paused target's resume-clocked watch/trace cannot end before resume_process
    if (session.paused && recording.create.startsAtResume) return ok(undefined);
    const until = performance.now() + Math.max(0, Math.min(waitMs, op.deadline.remaining() - 250));
    const hint: WaitCondition = {
      kind: "any",
      of: [{ kind: "stream-end", agentStream }, { kind: "process-exit" }, { kind: "detach" }],
    };
    for (;;) {
      if (recording.view().state !== "active" || ctx.signal.aborted) break;
      const left = until - performance.now();
      if (left <= 0) break;
      const outcome = await session.waitFor(hint, op, Math.min(left, WAIT_SLICE_MS));
      if (outcome.satisfied && recording.view().state === "active") await delay(Math.min(SETTLE_POLL_MS, left));
    }
    return ok(undefined);
  });
};
