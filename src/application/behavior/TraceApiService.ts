import type { z } from "zod";

import type { BEHAVIOR_TOOLS } from "../../contracts/areas/behavior.js";
import { COMPLETE } from "../../domain/evidence/coverage.js";
import { BEHAVIOR_LIMITATIONS, TRACE_API_ALWAYS } from "../../domain/evidence/limitations/behavior.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { withEffects } from "../../domain/errors/constructors.js";
import type { JsonObject, JsonValue } from "../../domain/json.js";
import { err, ok, type Result } from "../../domain/result.js";
import { compactOf } from "../../domain/time.js";
import type { RecordedEvidence, SensitiveLiterals } from "../../ports/evidence.js";
import type { InstrumentStateView } from "../../ports/recordings.js";
import type { LiveSession, OperationContext } from "../../ports/sessions.js";
import type {
  AgentError,
  ProfileInstallParams,
  ProfileInstallResult,
  ProfileOptions,
} from "../../shared/agentProtocol.js";
import type { BeaApplication } from "../BeaApplication.js";
import type { HandlerContext } from "../handlerContext.js";
import { abortedAfter, detachedOp, INSTALL_RPC_MS } from "../instruments/installOp.js";
import { liveOp } from "../sessionAccess.js";
import type { ApiDecoders } from "./apiEvents.js";

type TraceApiContract = (typeof BEHAVIOR_TOOLS)[0];
export type TraceApiInput = z.output<TraceApiContract["inputSchema"]>;
export type TraceApiOutput = z.output<TraceApiContract["outputSchema"]>;

/**
 * trace_api (DESIGN §6.2 #22; S6 §4.21): agent `profileInstall` inside the session's exclusive section, then the
 * api/1 stream binding, ONE hook-installed effect for all APIs, the recording (kind "api") and the
 * `bea.instrument.install` evidence (record-before-reference: stream descriptor and effect first). An optional
 * `wait_ms` blocks outside the exclusive section for the recording to end (a wait that runs out is not an error).
 *
 * Sub-options are not tool inputs; trace_api fixes them so the summary has what S6 §6 lists: file I/O byte counts
 * (io on), Winsock + DNS + HTTP, remote-process memory calls, procedure resolution, frees (aggregated; they also
 * drive the free-time executable-region probe) and the memory-map watcher at 1 s. Payload capture stays 0.
 */
export const TRACE_API_OPTIONS: ProfileOptions = {
  file: { io: true, capture_bytes: 0, track_handles: true },
  registry: { capture_value_bytes: 0, query_key: false, enumerate: false },
  network: { capture_payload_bytes: 0, http: true, dns: true },
  process: { cross_process_memory: true, apc_and_context: false },
  module_load: { resolve_procedures: true },
  memory_protection: { frees: true, sections: false, exec_region_scan_ms: 1000 },
};

const PROVIDER = { id: "frida", name: "frida", version: null } as const;
const FAILED_LIST_CAP = 64;

const failReason = (e: AgentError): string => {
  switch (e._tag) {
    case "ModuleNotFound":
      return "module-not-loaded";
    case "ExportNotFound":
      return "export-not-found";
    case "HookDenied":
      return e.reason;
    case "HookInstallFailed":
      return "install-failed";
    default:
      return "agent-error";
  }
};

/** Agent install result → the failed list (agent failures + deny-list refusals), capped at 64. */
const hooksFailed = (r: ProfileInstallResult): { api: string; reason: string }[] =>
  [
    ...r.failed.map((f) => ({ api: f.api, reason: failReason(f.error) })),
    ...r.denied.map((d) => ({ api: d.api, reason: d.reason.slice(0, 64) })),
  ].slice(0, FAILED_LIST_CAP);

const profileInstallParams = (input: TraceApiInput, paused: boolean): ProfileInstallParams => ({
  profiles: [...input.profiles],
  options: TRACE_API_OPTIONS,
  lifetime: { duration_ms: input.duration_ms, max_hits: input.max_events, clock: paused ? "resume" : "install" },
  label: "trace_api",
});

const traceApiLimitations = (input: TraceApiInput, failed: number): string[] => {
  const out: string[] = [...TRACE_API_ALWAYS];
  if (failed > 0) out.push(BEHAVIOR_LIMITATIONS.API_HOOKS_FAILED(failed));
  if (input.backtrace > 0) out.push(BEHAVIOR_LIMITATIONS.API_BACKTRACE_UNAVAILABLE);
  if (!input.include_failed) out.push(BEHAVIOR_LIMITATIONS.API_FAILED_EXCLUDED);
  if (input.profiles.includes("memory_protection")) out.push(BEHAVIOR_LIMITATIONS.API_EXEC_REGIONS_SAMPLED);
  return out;
};

interface Installed {
  readonly recordingId: string;
  readonly agentStream: string;
  readonly evidence: RecordedEvidence<JsonObject>;
  readonly result: ProfileInstallResult;
  readonly effectId: string;
}

const viewOrFallback = (app: BeaApplication, id: string): InstrumentStateView | undefined =>
  app.services.recordings.get(id)?.view();

/** Best-effort removal of an installed agent instrument whose host side could not be set up; returns the error. */
const abandon = async (
  session: LiveSession,
  op: OperationContext,
  instrumentId: string,
  error: BeaError,
): Promise<Result<never, BeaError>> => {
  // LIFE-6: the rollback never takes the caller's (possibly aborted) signal
  const internal = detachedOp(op, INSTALL_RPC_MS);
  try {
    await session.agent.call("instrumentStop", { id: instrumentId, final_flush: false }, { op: internal.op });
  } finally {
    internal.dispose();
  }
  return err(error);
};

/** The exclusive part: install, bind, effect, recording, evidence. */
const install = async (
  app: BeaApplication,
  ctx: HandlerContext,
  input: TraceApiInput,
  session: LiveSession,
  op: OperationContext,
  literals: SensitiveLiterals,
): Promise<Result<Installed, BeaError>> => {
  const evidence = app.services.evidence;
  const params = profileInstallParams(input, session.paused);
  // LIFE-6: a non-cancellable install; the caller's abort is checked once the agent answered
  const internal = detachedOp(op, INSTALL_RPC_MS);
  const installed = await session.agent.call("profileInstall", params, { op: internal.op }).finally(() => {
    internal.dispose();
  });
  if (!installed.ok) return installed;
  const r = installed.value;
  const aborted = abortedAfter(op);
  if (aborted !== null) return abandon(session, op, r.instrument_id, aborted);
  const decoders: ApiDecoders = {
    catalog_minor: r.catalog_minor,
    include_failed: input.include_failed,
    caller: input.caller,
    user_sid: null,
  };
  const decodersJson = { ...decoders } as unknown as JsonObject;
  const writer = await session.streams.bind(r.stream_id, {
    source: { kind: "api", instance_id: session.instanceId, effect_id: null, channel: r.stream_id },
    encoding: { kind: "json-rows", row_kind: "api/1" },
    decoders: decodersJson,
    literals,
  });
  if (!writer.ok) return abandon(session, op, r.instrument_id, writer.error);
  const effect = await evidence.effects.apply({
    instance_id: session.instanceId,
    kind: "hook-installed",
    target: { address: null, size: null, threads: "all" },
    parameters: {
      profiles: [...input.profiles],
      agent_instrument: r.instrument_id,
      apis: r.installed.length,
      pending: r.pending.length,
    },
    lifetime: { duration_ms: input.duration_ms, max_hits: input.max_events },
    stream_ids: [writer.value.stream_id],
    applied_by: ctx.operation,
    display_target: `trace_api ${input.profiles.join(",")}`,
    literals,
  });
  if (!effect.ok) {
    await session.streams.end(r.stream_id, "install-failed");
    return abandon(session, op, r.instrument_id, effect.error);
  }
  const effectId = effect.value.effect_id;
  const recording = app.services.recordings.create({
    sessionId: session.id,
    kind: "api",
    agentInstrumentId: r.instrument_id,
    agentStream: r.stream_id,
    streamId: writer.value.stream_id,
    effectId,
    durationMs: input.duration_ms,
    maxEvents: input.max_events,
    startsAtResume: session.paused,
    decoders: decodersJson,
  });
  const failed = hooksFailed(r);
  const result: JsonObject = {
    recording_id: recording.id,
    kind: "api",
    profiles: [...input.profiles],
    agent_instrument: r.instrument_id,
    stream_id: writer.value.stream_id,
    catalog_minor: r.catalog_minor,
    installed: r.installed.map((i) => i.api),
    pending: r.pending.map((p) => p.api),
    failed,
  };
  const recorded = await evidence.recorder.record<JsonObject>({
    predicate_type: "bea.instrument.install",
    operation: ctx.operation,
    input: { ...input, profiles: [...input.profiles] } as unknown as JsonObject,
    identityExclude: ["wait_ms"],
    subject: { kind: "process-instance", instance_id: session.instanceId },
    capture: evidence.instances.capture(session.instanceId),
    provider: PROVIDER,
    result,
    coverage: COMPLETE,
    limitations: traceApiLimitations(input, failed.length),
    effects: [effectId],
    literals,
  });
  if (!recorded.ok) return err(withEffects(recorded.error, [effectId]));
  return ok({ recordingId: recording.id, agentStream: r.stream_id, evidence: recorded.value, result: r, effectId });
};

const envelope = (rec: RecordedEvidence<JsonObject>) => {
  const e = rec.record;
  const subject = e.subject;
  return {
    evidence_id: e.evidence_id,
    predicate_type: e.predicate_type,
    confidence: e.confidence,
    authority: e.authority,
    coverage: e.coverage,
    limitations: [...e.limitations],
    ...(subject?.kind === "process-instance" ? { instance_id: subject.instance_id } : {}),
    ...(subject?.kind === "process-instance" && subject.module_map_id !== null
      ? { module_map_id: subject.module_map_id }
      : {}),
    ...(e.observed_at !== null ? { observed_at: compactOf(e.observed_at) } : {}),
    perturbation: {
      level: e.perturbation.level,
      active_effect_ids: [...e.perturbation.active_effect_ids],
      tainted: e.perturbation.tainted_by.length > 0,
    },
    ...(e.effects.length > 0 ? { effects_applied: [...e.effects] } : {}),
    ...(e.redactions.length > 0 ? { redactions: e.redactions.length } : {}),
  };
};

const pendingView = (recordingId: string, durationMs: number): InstrumentStateView => ({
  recording_id: recordingId,
  kind: "api",
  state: "active",
  events: 0,
  dropped: 0,
  ends_in_ms: durationMs,
  end_reason: null,
});

const toInstrumentState = (v: InstrumentStateView): TraceApiOutput["instrument"] => ({
  recording_id: v.recording_id,
  kind: v.kind,
  state: v.state,
  events: v.events,
  dropped: v.dropped,
  ends_in_ms: v.ends_in_ms,
  end_reason: v.end_reason,
  ...(v.summary !== undefined ? { summary: v.summary as { [k: string]: JsonValue } } : {}),
});

export const traceApi = async (
  app: BeaApplication,
  input: TraceApiInput,
  ctx: HandlerContext,
): Promise<Result<TraceApiOutput, BeaError>> => {
  if (process.platform !== "win32")
    return err({
      _tag: "CapabilityUnavailable",
      operation: ctx.operation,
      capability: "platform",
      reason: "windows-only",
      retryable: false,
    });
  const literals = app.services.evidence.literals(undefined);
  if (!literals.ok) return literals;
  const done = await liveOp(app, ctx, input.session_id, { mode: "exclusive", need: "agent" }, (session, op) =>
    install(app, ctx, input, session, op, literals.value),
  );
  if (!done.ok) return done;
  const installed = done.value;
  if (input.wait_ms > 0) {
    // UX-3: nothing records on a paused target before resume_process: do not block out the whole wait_ms
    const waited = await liveOp(app, ctx, input.session_id, { mode: "concurrent", need: "host" }, async (s, op) =>
      s.paused
        ? ok(null)
        : ok(await s.waitFor({ kind: "stream-end", agentStream: installed.agentStream }, op, input.wait_ms)),
    );
    // a wait that runs out (or a session that ended meanwhile) is still a successful install
    void waited;
  }
  const view = viewOrFallback(app, installed.recordingId) ?? pendingView(installed.recordingId, input.duration_ms);
  const failed = hooksFailed(installed.result);
  return ok({
    instrument: toInstrumentState(view),
    hooks_installed: installed.result.installed.length,
    hooks_pending: installed.result.pending.length,
    hooks_failed: failed,
    ...envelope(installed.evidence),
  });
};
