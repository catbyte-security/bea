import { Deadline } from "../../domain/deadline.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { LIMITATIONS } from "../../domain/evidence/limitations.js";
import type { FxId } from "../../domain/ids.js";
import type { Logger } from "../../domain/logger.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { SessionEvidenceSink } from "../../application/sessions/SessionEvidenceSink.js";
import type { StreamEndReason } from "../../ports/evidence.js";
import type { RecordingEndReason, RecordingRegistry } from "../../ports/recordings.js";
import type { CloseOptions, CloseReport } from "../../ports/sessions.js";
import type { ShutdownResult } from "../../shared/agentProtocol.js";
import type { CancellableLike } from "./fridaPorts.js";
import type { HostLimits } from "./hostLimits.js";
import { createNativeCancel } from "./NativeCancel.js";
import type { SessionRecord } from "./SessionRecord.js";

/**
 * close_session (S3 §7.5; DESIGN §5.1). Owned, kill first: abort the session's ops → ackAll → jobHost.kill (VERIFIED ~3 ms
 * to settled) → wait ≤ 500 ms for the detach → drain the queue ≤ 2 s → output EOF ≤ 200 ms → end streams → disconnect →
 * sink.sessionEnded → closed. Attached: drain → agent shutdown({revert:true}) → unreverted and not forced →
 * cleanup_pending + effect_unreverted (the agent stays loaded for a retry) → unload → detach → watcher stop (the target
 * is never touched) → sessionEnded → closed. Never unload an attached agent with armed watches before `shutdown`.
 */
export interface CloseDeps {
  readonly sink: SessionEvidenceSink;
  readonly recordings: RecordingRegistry;
  readonly limits: HostLimits;
  readonly logger: Logger;
  readonly now: () => number;
  readonly createCancellable: () => CancellableLike;
}

export interface CloseBudget {
  readonly killEscalateMs: number;
  readonly detachWaitMs: number;
  readonly queueDrainMs: number;
  readonly revertMs: number;
  readonly unloadMs: number;
  readonly detachMs: number;
  readonly outputEofWaitMs: number;
  readonly sinkMs: number;
}

export const closeBudget = (limits: HostLimits): CloseBudget => limits.closeSession;

const timeout = (ms: number): Promise<"timeout"> =>
  new Promise((resolve) => {
    const timer = setTimeout(() => resolve("timeout"), Math.max(0, ms));
    timer.unref?.();
  });

const raceTimeout = async <T>(work: Promise<T>, ms: number): Promise<T | "timeout"> =>
  Promise.race([work, timeout(ms)]);

/** Aborts every admitted op of the session except the closing one. */
export const abortSessionOps = (record: SessionRecord, except: AbortController | null, reason: unknown): void => {
  for (const controller of [...record.ops]) if (controller !== except) controller.abort(reason);
  if (!record.closeController.signal.aborted) record.closeController.abort(reason);
};

const internalOp = (record: SessionRecord, name: string, ms: number) => record.internalOpDetached(name, ms);

/** End the session's streams and recordings, collecting the manifest evidence ids on the record. */
export const endSessionStreams = async (
  deps: Pick<CloseDeps, "recordings" | "logger">,
  record: SessionRecord,
  streamReason: StreamEndReason,
  recordingReason: RecordingEndReason,
  ms: number,
): Promise<void> => {
  const internal = internalOp(record, "session.close-streams", ms);
  try {
    const ended = await raceTimeout(record.binder.endAll(streamReason, ms), ms);
    if (ended !== "timeout") record.noteManifests(ended.manifests.map((m) => m.record.evidence_id as `ev_${string}`));
    for (const recording of deps.recordings.list(record.id))
      if (recording.view().state === "active") await deps.recordings.end(recording.id, recordingReason, internal.op);
  } catch (cause) {
    deps.logger.warn("ending session streams failed", { cause: cause instanceof Error ? cause : String(cause) });
  } finally {
    internal.dispose();
  }
};

/**
 * The owned target's state after a kill (close_session and closeAll). A root that exited on its own is
 * `already-exited` unless its job still held processes (stragglers such as behavior's lingering child) that this kill
 * terminated: then BEA killed part of the target tree and the state is `killed` (S6 §10.8 close_session row).
 * `activeBefore` is the job's active count the helper reported with its `killed` event (null when the job had
 * already settled on its own, i.e. nothing was left to kill).
 */
export const ownedTargetState = (
  rootExited: boolean,
  killSettled: boolean,
  termination: CloseReport["termination"],
): "killed" | "already-exited" | "unknown" => {
  if (!killSettled) return rootExited ? "already-exited" : "unknown";
  if (!rootExited) return "killed";
  return (termination?.activeBefore ?? 0) > 0 ? "killed" : "already-exited";
};

const baseReport = (
  record: SessionRecord,
): Omit<CloseReport, "targetState" | "termination" | "revert" | "agentUnloaded" | "fridaDetached" | "cleanup"> => ({
  sessionId: record.id,
  kind: "live",
  ownership: record.ownership,
  exit: record.exit,
  streamsFinalized: record.binder
    .boundStreams()
    .map((stream) => record.binder.streamIdOf(stream))
    .filter((id): id is `st_${string}` => id !== null),
  limitations: [...record.limitations],
});

export const closeOwned = async (
  deps: CloseDeps,
  record: SessionRecord,
  budget: CloseBudget,
  operation: string,
): Promise<Result<CloseReport, BeaError>> => {
  const started = deps.now();
  const alreadyExited = record.exit !== null || record.detach?.reason === "process-terminated";
  record.killRequested = true;
  record.crash.ackAll("closing");
  let termination: CloseReport["termination"] = null;
  const jobHost = record.jobHost;
  if (jobHost !== null) {
    const settlement = await jobHost.kill("close-session", budget.killEscalateMs);
    termination = {
      method: settlement.method === "helper-terminated" ? "helper-terminated" : "terminate-job",
      activeBefore: settlement.activeBefore,
      settled: settlement.observation,
      elapsedMs: Math.round(deps.now() - started),
    };
  }
  await record.waitDetached(budget.detachWaitMs);
  const fridaDetached = await detachSession(deps, record, budget.detachMs);
  await raceTimeout(record.queue.drained(), budget.queueDrainMs);
  if (record.output !== null) await record.output.waitEof(budget.outputEofWaitMs);
  await endSessionStreams(
    deps,
    record,
    alreadyExited ? "process-exited" : "process-killed",
    alreadyExited ? "target_exited" : "stopped",
    budget.sinkMs,
  );
  record.runDisconnectors();
  record.output?.close();
  record.flow.stop();
  const killed = termination !== null && termination.settled !== "timed-out-with-active";
  const report: CloseReport = {
    ...baseReport(record),
    targetState: ownedTargetState(alreadyExited, killed, termination),
    termination,
    revert: null,
    agentUnloaded: null,
    fridaDetached,
    cleanup:
      killed || alreadyExited
        ? { status: "complete" }
        : {
            status: "incomplete",
            resources: [`jobhost:${String(jobHost?.helperPid ?? 0)}`],
            reason: "the job did not settle",
          },
  };
  await deps.sink.sessionEnded({
    sessionId: record.id,
    report,
    deadline: Deadline.after(budget.sinkMs, deps.now),
    operation,
  });
  return ok(report);
};

export const closeAttached = async (
  deps: CloseDeps,
  record: SessionRecord,
  options: CloseOptions,
  budget: CloseBudget,
  operation: string,
): Promise<Result<CloseReport, BeaError>> => {
  const exitedBefore = record.exit !== null || record.detach?.reason === "process-terminated";
  await raceTimeout(record.queue.drained(), budget.queueDrainMs);
  let revert: ShutdownResult | null = null;
  const agentAlive =
    !exitedBefore && record.detach === null && record.rpc !== null && record.script?.isDestroyed !== true;
  if (agentAlive && record.rpc !== null) {
    const internal = internalOp(record, operation, budget.revertMs + 1_000);
    try {
      const shutdown = await record.rpc.call(
        "shutdown",
        { revert: true, timeout_ms: budget.revertMs },
        { op: internal.op, timeoutMs: budget.revertMs + 500 },
      );
      if (shutdown.ok) revert = shutdown.value;
      else if (!options.force && record.exit === null && record.detach === null)
        return err(
          wedged(record)
            ? wedgedError(record, operation)
            : unrevertedError(deps, record, operation, [], "the agent did not confirm its revert"),
        );
    } finally {
      internal.dispose();
    }
    if (revert !== null && revert.unreverted.length > 0 && !options.force)
      return err(
        unrevertedError(
          deps,
          record,
          operation,
          revert.unreverted.map((u) => u.id),
          "instruments could not be reverted",
        ),
      );
  }
  record.crash.ackAll("closing");
  const agentUnloaded = await unloadScript(deps, record, budget.unloadMs);
  if (agentUnloaded === false && !options.force)
    return err(
      wedged(record)
        ? wedgedError(record, operation)
        : unrevertedError(deps, record, operation, [], "the agent could not be unloaded"),
    );
  const fridaDetached = await detachSession(deps, record, budget.detachMs);
  if (record.watcher !== null) await raceTimeout(record.watcher.stop(), 1_000);
  const exitedDuring = !exitedBefore && record.exit !== null;
  await endSessionStreams(
    deps,
    record,
    exitedBefore || exitedDuring ? "process-exited" : "detached",
    exitedBefore || exitedDuring ? "target_exited" : "detached",
    budget.sinkMs,
  );
  record.runDisconnectors();
  record.flow.stop();
  // review fix LIFE-8: a forced close that could not unload the agent from a live process detached BEA, but the
  // agent stays loaded; the report says so instead of a complete cleanup
  const agentStays = agentUnloaded === false && !exitedBefore && !exitedDuring;
  const base = baseReport(record);
  const report: CloseReport = {
    ...base,
    targetState: exitedBefore ? "already-exited" : exitedDuring ? "exited-during-close" : "alive-detached",
    termination: null,
    revert,
    agentUnloaded,
    fridaDetached,
    cleanup: agentStays
      ? {
          status: "incomplete",
          resources: [`agent:pid:${String(record.pid ?? 0)}`],
          reason: "the agent could not be unloaded; it stays in the process until the process exits",
        }
      : { status: "complete" },
    limitations: agentStays ? [...base.limitations, LIMITATIONS.AGENT_LEFT_LOADED] : base.limitations,
  };
  await deps.sink.sessionEnded({
    sessionId: record.id,
    report,
    deadline: Deadline.after(budget.sinkMs, deps.now),
    operation,
  });
  return ok(report);
};

/** The agent's RPC channel is unresponsive (a call that never returned holds the agent's thread). */
const wedged = (record: SessionRecord): boolean => record.rpc !== null && record.rpc.health.state === "unresponsive";

/**
 * Review fix LIFE-8: an unresponsive agent cannot revert or unload, so "retry close_session" cannot succeed. The
 * error says so and names the only way out (force:true detaches BEA; the agent stays until the process exits).
 */
const wedgedError = (record: SessionRecord, operation: string): BeaError => {
  record.retained = { resources: [`agent:pid:${String(record.pid ?? 0)}`], reason: "the agent is unresponsive" };
  return {
    _tag: "EffectUnreverted",
    operation,
    effect_ids: [],
    message:
      "BEA's agent in the attached process does not respond (a call that never returned holds its thread), so it cannot revert its instruments or unload.",
    remediation:
      "A retry cannot succeed. close_session with force:true detaches BEA, but frida-agent.dll, its threads and the running call stay in the process until it exits.",
    diagnostics: { reason: "agent-unresponsive", health: record.rpc?.health.state ?? "gone" },
  };
};

/** EffectUnreverted with the fx ids of the instruments the agent could not revert (the session stays retryable). */
const unrevertedError = (
  deps: Pick<CloseDeps, "recordings">,
  record: SessionRecord,
  operation: string,
  instrumentIds: readonly string[],
  reason: string,
): BeaError => {
  const recordings = deps.recordings.list(record.id);
  const effectIds = instrumentIds
    .map((id) => recordings.find((r) => r.create.agentInstrumentId === id)?.create.effectId ?? null)
    .filter((id): id is FxId => id !== null);
  record.retained = { resources: instrumentIds.map((id) => `instrument:${id}`), reason };
  return {
    _tag: "EffectUnreverted",
    operation,
    effect_ids: effectIds,
    effects_applied: effectIds,
    diagnostics: { reason, instruments: [...instrumentIds] },
    remediation:
      "Retry close_session; to detach anyway and leave the listed effects in place, call close_session with force:true (they are reported revert-failed).",
  };
};

/** undefined: no script to unload; true/false: unload outcome. */
const unloadScript = async (deps: CloseDeps, record: SessionRecord, ms: number): Promise<boolean | null> => {
  const script = record.script;
  if (script === null) return null;
  if (script.isDestroyed) return true;
  const cancel = createNativeCancel(deps.createCancellable(), { deadline: Deadline.after(ms, deps.now) });
  try {
    await script.unload(cancel.token);
    return true;
  } catch {
    return script.isDestroyed;
  } finally {
    cancel.dispose();
  }
};

/** Detach the Frida session if still attached; true when it is detached afterwards. */
export const detachSession = async (
  deps: Pick<CloseDeps, "createCancellable" | "now">,
  record: SessionRecord,
  ms: number,
): Promise<boolean> => {
  const session = record.fridaSession;
  if (session === null) return true;
  if (session.isDetached()) return true;
  record.killRequested = true;
  const cancel = createNativeCancel(deps.createCancellable(), { deadline: Deadline.after(ms, deps.now) });
  try {
    await session.detach(cancel.token);
  } catch {
    // reported through the return value
  } finally {
    cancel.dispose();
  }
  return session.isDetached();
};
