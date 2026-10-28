import type { ScanToolValueType } from "../../contracts/areas/scan.js";
import type { IdSource } from "../../domain/canonical.js";
import type { Clock } from "../../domain/clock.js";
import { Deadline } from "../../domain/deadline.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { invalidState } from "../../domain/errors/constructors.js";
import { mapAgentError } from "../../domain/errors/agentErrorMap.js";
import type { Logger } from "../../domain/logger.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { HandleKindSpec, HandleRegistry, HandleStopOutcome, HandleView } from "../../ports/handles.js";
import type {
  AgentJobOutcome,
  DynamicSessionPort,
  LiveSession,
  OperationContext,
  SessionEndedEvent,
  SessionId,
  WaitCondition,
} from "../../ports/sessions.js";
import type { ScanNextParams, ScanStartParams, ScanStatus } from "../../shared/agentProtocol.js";
import type { HitStore } from "./scanHitStore.js";

/**
 * WP10-SCAN ScanService (DESIGN §6.2 #15–17, CI-B6): host handles (`scan_xxxxxxxx`) over agent scans (`sc<n>`).
 * - at most 8 scans per session (S6 §2.5); the 9th is resource_constraint;
 * - each agent job is awaited ONCE, in the background, through `LiveSession.jobs.await` (passive: no agent RPC, so
 *   it never holds the session's exclusive section); handlers wait on that promise for up to wait_ms;
 * - registers the `scan` kind in the HandleRegistry so wait / stop_instrumentation / session_status see scans;
 * - on `onSessionEnded`: "closed"/"shutdown" release every scan of the session with its host hit store;
 *   "exited"/"detached" (fired once, while the session stays open) orphan them: no agent RPC any more, a running
 *   iteration fails, and the stored hits stay readable (scan_results {values:false}) until released (bounded).
 */
export const MAX_SCANS_PER_SESSION = 8;
/** Background job await ceiling; a scan still running after it is refreshed with scanStatus on the next call. */
const BACKGROUND_WAIT_MS = 30 * 60_000;
/** Released scans answer stop_instrumentation with already_ended for a while (bounded). */
const MAX_TOMBSTONES = 256;
/**
 * Scans of exited/detached targets keep their host hit store (scan_results {values:false} after exit, DESIGN §6.2
 * #17) until stopped, the session is closed by name, or this many newer orphans exist.
 */
const MAX_ORPHANS = 64;
const SCAN_ID_RE = /^scan_[0-9a-f]{8}$/u;

type ScanRecordState = "running" | "done" | "failed" | "released";

export interface ScanRecord {
  readonly id: string;
  readonly sessionId: SessionId;
  readonly instanceId: string;
  readonly agentScanId: string;
  readonly valueType: ScanToolValueType;
  readonly firstCompare: string;
  readonly maxHits: number;
  iteration: number;
  state: ScanRecordState;
  mode: "explicit" | "snapshot";
  count: number;
  previousCount: number | null;
  /** the hit cap stopped a scan iteration (sticky: later iterations narrow a truncated set) */
  truncated: boolean;
  cap: number | null;
  cancelled: boolean;
  /** the target exited or the agent detached: no agent RPC is possible any more (host store only) */
  agentGone: boolean;
  scannedBytes: number;
  rangesFailed: number;
  faultedDropped: number;
  jobId: string | null;
  startedMs: number;
  elapsedMs: number;
  /** the failure of a failed iteration */
  error: BeaError | null;
  pending: Promise<void> | null;
  controller: AbortController | null;
}

export interface ScanServiceDeps {
  readonly clock: Clock;
  readonly ids: IdSource;
  readonly sessions: DynamicSessionPort;
  readonly handles: HandleRegistry;
  readonly store: HitStore;
  readonly logger: Logger;
}

export interface ScanMeta {
  readonly operation: string;
  readonly valueType: ScanToolValueType;
  readonly compare: string;
  readonly maxHits: number;
}

const agentUsable = (session: LiveSession): boolean => session.state === "running" || session.state === "paused";

export class ScanService {
  readonly #deps: ScanServiceDeps;
  readonly #records = new Map<string, ScanRecord>();
  readonly #tombstones: string[] = [];
  readonly #orphans: ScanRecord[] = [];
  #watching = false;
  #opSeq = 0;
  readonly spec: HandleKindSpec;

  constructor(deps: ScanServiceDeps) {
    this.#deps = deps;
    this.spec = this.#createSpec();
    deps.handles.register(this.spec);
    this.#watchSessions();
  }

  get(id: string): ScanRecord | undefined {
    return this.#records.get(id);
  }

  /** Scans of a session that still hold agent state. */
  active(sessionId: SessionId): ScanRecord[] {
    return [...this.#records.values()].filter((r) => r.sessionId === sessionId && r.state !== "released");
  }

  /** scanStart under the caller's exclusive section; the job is then awaited in the background. */
  async begin(
    session: LiveSession,
    op: OperationContext,
    params: ScanStartParams,
    meta: ScanMeta,
  ): Promise<Result<ScanRecord, BeaError>> {
    this.#watchSessions();
    const open = this.active(session.id).length;
    if (open >= MAX_SCANS_PER_SESSION)
      return err({
        _tag: "ResourceConstraint",
        operation: meta.operation,
        resource: "capacity",
        limits: { max_scans_per_session: MAX_SCANS_PER_SESSION, open },
        remediation: 'Release a scan with stop_instrumentation {"ids":["scan_…"]} (session_status lists them).',
      });
    const started = await session.agent.call("scanStart", params, { op });
    if (!started.ok) return started;
    const rec: ScanRecord = {
      id: this.#newId(),
      sessionId: session.id,
      instanceId: session.instanceId,
      agentScanId: started.value.scan_id,
      valueType: meta.valueType,
      firstCompare: meta.compare,
      maxHits: meta.maxHits,
      iteration: 0,
      state: "running",
      mode: params.kind === "unknown" ? "snapshot" : "explicit",
      count: 0,
      previousCount: null,
      truncated: false,
      cap: null,
      cancelled: false,
      agentGone: false,
      scannedBytes: 0,
      rangesFailed: 0,
      faultedDropped: 0,
      jobId: started.value.job_id,
      startedMs: this.#deps.clock.monoMs(),
      elapsedMs: 0,
      error: null,
      pending: null,
      controller: null,
    };
    this.#records.set(rec.id, rec);
    this.#track(session, rec, meta.operation);
    return ok(rec);
  }

  /** scanNext under the caller's exclusive section. */
  async narrow(
    session: LiveSession,
    op: OperationContext,
    rec: ScanRecord,
    params: Omit<ScanNextParams, "scan_id">,
  ): Promise<Result<ScanRecord, BeaError>> {
    if (rec.state === "running") return err(this.#runningError(op.name, rec));
    const next = await session.agent.call("scanNext", { scan_id: rec.agentScanId, ...params }, { op });
    if (!next.ok) return next;
    rec.previousCount = rec.count;
    rec.iteration += 1;
    rec.state = "running";
    rec.cancelled = false;
    rec.error = null;
    rec.jobId = next.value.job_id;
    rec.startedMs = this.#deps.clock.monoMs();
    this.#track(session, rec, op.name);
    return ok(rec);
  }

  /** Waits up to `waitMs` (or the abort of `signal`) for the running iteration. */
  async settle(rec: ScanRecord, waitMs: number, signal: AbortSignal): Promise<void> {
    const pending = rec.pending;
    if (rec.state !== "running" || pending === null || waitMs <= 0 || signal.aborted) return;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let onAbort: (() => void) | undefined;
    await Promise.race([
      pending,
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, waitMs);
        timer.unref?.();
      }),
      new Promise<void>((resolve) => {
        onAbort = resolve;
        signal.addEventListener("abort", onAbort, { once: true });
      }),
    ]);
    clearTimeout(timer);
    if (onAbort !== undefined) signal.removeEventListener("abort", onAbort);
  }

  /** A running record whose background await gave up: ask the agent directly (exclusive section). */
  async refresh(session: LiveSession, op: OperationContext, rec: ScanRecord): Promise<Result<void, BeaError>> {
    if (rec.state !== "running" || rec.pending !== null || rec.agentGone || !agentUsable(session)) return ok(undefined);
    const status = await session.agent.call("scanStatus", { scan_id: rec.agentScanId }, { op });
    if (!status.ok) return status;
    this.#applyStatus(rec, status.value, op.name);
    return ok(undefined);
  }

  /** Frees the agent scan (when the agent is reachable) and the host store. Idempotent. */
  async release(
    rec: ScanRecord,
    session: LiveSession | null,
    op: OperationContext | null,
  ): Promise<HandleStopOutcome["status"]> {
    if (rec.state === "released") return "already_ended";
    rec.state = "released";
    rec.controller?.abort();
    if (session !== null && op !== null && !rec.agentGone && agentUsable(session)) {
      // the agent answers NotFound when the scan is already gone: released either way
      await session.agent.call("scanClose", { scan_id: rec.agentScanId }, { op });
    }
    await this.#deps.store.remove(rec.id);
    this.#tombstones.push(rec.id);
    while (this.#tombstones.length > MAX_TOMBSTONES) {
      const old = this.#tombstones.shift();
      if (old !== undefined) this.#records.delete(old);
    }
    return "released";
  }

  view(rec: ScanRecord): HandleView {
    return {
      id: rec.id,
      kind: "scan",
      sessionId: rec.sessionId,
      state: rec.state === "done" ? "ready" : rec.state,
      summary: { value_type: rec.valueType, count: rec.count, iteration: rec.iteration, state: rec.state },
    };
  }

  // ------------------------------------------------------------------ internals

  #newId(): string {
    for (;;) {
      const id = this.#deps.ids.handle("scan");
      if (!this.#records.has(id)) return id;
    }
  }

  #runningError(operation: string, rec: ScanRecord): BeaError {
    return {
      ...invalidState(operation, "running", ["done", "failed"]),
      remediation: `Wait for the scan with wait {"ids":["${rec.id}"]}.`,
    };
  }

  #track(session: LiveSession, rec: ScanRecord, operation: string): void {
    const jobId = rec.jobId;
    if (jobId === null) return;
    const controller = new AbortController();
    const deadline = Deadline.after(BACKGROUND_WAIT_MS);
    this.#opSeq += 1;
    const op: OperationContext = { opId: -this.#opSeq, name: `${operation}.job`, signal: controller.signal, deadline };
    rec.controller = controller;
    rec.pending = session.jobs
      .await(jobId, op, BACKGROUND_WAIT_MS)
      .then(
        (outcome) => {
          if (rec.jobId === jobId && rec.state !== "released") this.#applyOutcome(rec, outcome, operation);
        },
        (cause: unknown) => {
          this.#deps.logger.debug("scan job await failed", { cause: String(cause) });
        },
      )
      .finally(() => {
        deadline.dispose();
        if (rec.jobId === jobId) {
          rec.pending = null;
          rec.controller = null;
        }
      });
  }

  #applyOutcome(rec: ScanRecord, outcome: Result<AgentJobOutcome, BeaError>, operation: string): void {
    if (!outcome.ok) return; // timeout / session gone: refreshed with scanStatus later, or released
    const o = outcome.value;
    const status = o.result !== null && "scan_id" in o.result ? o.result : null;
    if (status !== null) this.#applyStatus(rec, status, operation);
    else if (o.info.state !== "running" && o.info.state !== "queued") {
      rec.state = "failed";
      rec.error =
        o.error === null
          ? { _tag: "ProviderFailure", operation, provider: "agent" }
          : mapAgentError(o.error, { operation, instance_id: rec.instanceId });
    }
    rec.elapsedMs = Math.round(this.#deps.clock.monoMs() - rec.startedMs);
  }

  #applyStatus(rec: ScanRecord, st: ScanStatus, operation: string): void {
    rec.count = st.count;
    rec.scannedBytes = st.bytes_scanned;
    rec.rangesFailed = st.unreadable_regions;
    rec.faultedDropped = st.faulted_candidates_dropped;
    rec.mode = st.mode;
    rec.elapsedMs = Math.round(this.#deps.clock.monoMs() - rec.startedMs);
    if (st.state === "running") return;
    if (st.state === "ready") {
      rec.state = "done";
      return;
    }
    const e = st.error;
    if (st.state === "failed" && e?._tag === "ResourceLimit" && e.resource === "scan_candidates") {
      rec.state = "done";
      rec.truncated = true;
      rec.cap = e.limit;
    } else if (st.state === "failed" && e?._tag === "Cancelled") {
      rec.state = "done";
      rec.cancelled = true;
    } else {
      rec.state = "failed";
      rec.error =
        e === null || e === undefined
          ? { _tag: "ProviderFailure", operation, provider: "agent" }
          : mapAgentError(e, { operation, instance_id: rec.instanceId });
    }
  }

  #watchSessions(): void {
    if (this.#watching) return;
    try {
      this.#deps.sessions.onSessionEnded((event) => this.#onSessionEnded(event));
      this.#watching = true;
    } catch {
      // a not-yet-implemented sessions port (day-0 fakes): retried on the first scan
    }
  }

  #onSessionEnded(event: SessionEndedEvent): void {
    for (const rec of this.active(event.sessionId)) {
      if (event.reason === "exited" || event.reason === "detached") this.#orphan(rec, event.reason);
      else this.#releaseQuietly(rec);
    }
  }

  #releaseQuietly(rec: ScanRecord): void {
    void this.release(rec, null, null).catch((cause: unknown) =>
      this.#deps.logger.debug("scan release failed", { cause: String(cause) }),
    );
  }

  /** The agent state died with the target; the host keeps what it stored (bounded). */
  #orphan(rec: ScanRecord, reason: "exited" | "detached"): void {
    rec.agentGone = true;
    rec.controller?.abort();
    if (rec.state === "running") {
      rec.state = "failed";
      rec.error =
        reason === "exited"
          ? {
              _tag: "TargetExited",
              operation: "scan",
              instance_id: rec.instanceId,
              exit: { code: null, code_hex: null, kind: "unknown", name: null },
              detach_reason: null,
            }
          : {
              _tag: "CapabilityUnavailable",
              operation: "scan",
              capability: "agent",
              reason: "agent-gone",
              retryable: false,
            };
    }
    this.#orphans.push(rec);
    while (this.#orphans.length > MAX_ORPHANS) {
      const old = this.#orphans.shift();
      if (old !== undefined) this.#releaseQuietly(old);
    }
  }

  #createSpec(): HandleKindSpec {
    return {
      kind: "scan",
      owns: (id) => SCAN_ID_RE.test(id) && this.#records.has(id),
      list: (sessionId) => this.active(sessionId).map((r) => this.view(r)),
      get: (id) => {
        const rec = this.#records.get(id);
        return rec === undefined ? undefined : this.view(rec);
      },
      doneCondition: (id): WaitCondition | null => {
        const rec = this.#records.get(id);
        return rec?.state === "running" && rec.jobId !== null ? { kind: "agent-job", jobId: rec.jobId } : null;
      },
      stop: async (session, id, op) => {
        const rec = this.#records.get(id);
        if (rec === undefined || rec.sessionId !== session.id)
          return err({ _tag: "ReferenceNotFound", operation: op.name, reference: { kind: "scan", id } });
        return ok({ id, kind: "scan", status: await this.release(rec, session, op) });
      },
    };
  }
}
