import { composeSignal } from "../../domain/abort.js";
import type { Loc } from "../../domain/address/addressRef.js";
import { Deadline } from "../../domain/deadline.js";
import type { EffectTransition } from "../../domain/effects/effect.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { COMPLETE } from "../../domain/evidence/coverage.js";
import { LIMITATIONS } from "../../domain/evidence/limitations.js";
import type { EvId, FxId, MmId, PiId } from "../../domain/ids.js";
import type { JsonObject } from "../../domain/json.js";
import type { Logger } from "../../domain/logger.js";
import { exitInfoOf } from "../../domain/process/ntstatus.js";
import { err, ok, type Result } from "../../domain/result.js";
import { buildDerivedCrash, deriveCrashVerdict, fallbackLoc } from "../../application/sessions/crashDerivation.js";
import type { SessionContainmentView, SessionHostFacts } from "../../application/sessions/hostFacts.js";
import type { SessionEvidenceSink } from "../../application/sessions/SessionEvidenceSink.js";
import type { AgentRpc } from "../../ports/agentRpc.js";
import type { EvidenceRuntime, SensitiveLiterals } from "../../ports/evidence.js";
import type { JobHostPort, ProcessWatcherPort, RootExit } from "../../ports/jobhost.js";
import type { RecordingEndReason, RecordingRegistry } from "../../ports/recordings.js";
import type {
  AgentReadyFacts,
  CloseReport,
  ContainmentFacts,
  DerivedCrash,
  DetachInfo,
  DetachReason,
  LiveSession,
  Liveness,
  OperationContext,
  ProcessExit,
  ProcessIdentityFacts,
  SessionId,
  SessionObservation,
  SessionState,
  UserScriptPort,
} from "../../ports/sessions.js";
import type { AddressService } from "../../ports/address.js";
import type { CrashReport, EndReason, InstrumentMessage, RowKind } from "../../shared/agentProtocol.js";
import type { AgentChannel } from "./AgentChannel.js";
import { AgentJobs } from "./AgentJobs.js";
import type { AgentRpcClient } from "./AgentRpcClient.js";
import { ConditionHub, type ConditionFacts } from "./ConditionHub.js";
import { CrashProtocol } from "./CrashProtocol.js";
import { FlowTracker } from "./flowTracker.js";
import type { CancellableLike, FridaScriptLike, FridaSessionLike } from "./fridaPorts.js";
import type { HostLimits } from "./hostLimits.js";
import type { BoundedOutputCapture } from "./outputCapture.js";
import { assertTransition } from "./sessionStates.js";
import { SerialQueue } from "./SerialQueue.js";
import { SessionStreamBinder } from "./StreamBinder.js";
import type { TerminalView } from "./rpcErrors.js";

/**
 * The internal record of one live session (S3 §6.1). Never handed to services: they get `facade` (LiveSession plus
 * the sessions area's host facts). All Frida, jobhost and watcher callbacks land here; they are O(1), never await and
 * never throw. Exit, detach and close converge whatever the event order (the lab saw `detached` 1 ms before
 * `root-exit`): `exited` keeps the earliest observation and later events add the exit code and tree data.
 */
export interface RecordDeps {
  readonly evidence: EvidenceRuntime;
  readonly recordings: RecordingRegistry;
  readonly address: AddressService;
  readonly sink: SessionEvidenceSink;
  readonly limits: HostLimits;
  readonly logger: Logger;
  readonly now: () => number;
  readonly monoNs: () => bigint;
  readonly wallIso: () => string;
  readonly createCancellable: () => CancellableLike;
  readonly fridaVersion: () => string | null;
  /** fired once per session (closed, exited, detached, shutdown) */
  readonly onEnded: (record: SessionRecord, reason: "closed" | "exited" | "detached" | "shutdown") => void;
}

export interface ProcessTree {
  active: number | null;
  settled: boolean;
  readonly children: number[];
  procExited: number;
}

export type BuiltinKind = "exceptions" | "modules" | "output";

const END_REASONS: Readonly<Record<EndReason, RecordingEndReason>> = {
  requested: "stopped",
  duration: "duration",
  max_hits: "max_events",
  max_events: "max_events",
  error: "stopped",
  "process-exit": "target_exited",
  "module-unloaded": "stopped",
  shutdown: "stopped",
  "thread-exit": "stopped",
  "rate-limit": "rate-limit",
  invocations: "invocations",
};

export const HOST_OUTPUT_STREAM = "host:output";

/** The `detail` of an agent `instrument ended` message (InstrumentSummary fields the host reads; S4 §5.7). */
export interface EndedDetail {
  readonly end_reason?: EndReason | null;
  readonly stream?: string | null;
  readonly reverted?: boolean;
  readonly verification?: { readonly kind: "bytes" | "dr7" | "protection"; readonly ok: boolean } | null;
}

/**
 * The transition an agent-ended instrument's still-active effect takes (S2 §6.3): `expired` at its lifetime
 * (duration, max hits; agent-confirmed), `revert-failed` whenever the agent could not verify the revert, null when
 * another path owns the effect (a requested stop, a shutdown) or nothing changed it (an end the agent verified that
 * is not a lifetime end stays with the session-end path).
 */
export const endedEffectTransition = (
  detail: EndedDetail,
): {
  readonly to: "expired" | "revert-failed";
  readonly detail: Pick<EffectTransition, "reason" | "verification" | "residue">;
} | null => {
  if (detail.end_reason === "requested" || detail.end_reason === "shutdown") return null;
  const lifetime =
    detail.end_reason === "duration"
      ? ("lifetime-duration" as const)
      : // review fix UX-11: an on_call trace that completed its requested invocations ends by its lifetime too
        detail.end_reason === "max_hits" || detail.end_reason === "max_events" || detail.end_reason === "invocations"
        ? ("lifetime-max-hits" as const)
        : null;
  const verified = detail.reverted !== false && detail.verification?.ok !== false;
  if (lifetime === null && verified) return null;
  const check = detail.verification ?? null;
  return {
    to: verified ? "expired" : "revert-failed",
    detail: {
      reason: lifetime ?? "revert-error",
      verification:
        check === null
          ? { method: "agent-confirmed", ok: verified, evidence_id: null }
          : { method: check.kind === "dr7" ? "thread-context" : "read-back", ok: check.ok, evidence_id: null },
      residue: verified ? [] : ["the agent could not verify that the instrument was removed"],
    },
  };
};

let internalOps = 0;

export class SessionRecord {
  readonly id: SessionId;
  readonly ownership: "owned" | "attached";
  readonly createdAt: number;
  readonly deps: RecordDeps;
  #state: SessionState;
  readonly history: { readonly state: SessionState; readonly at: number; readonly cause: string }[] = [];
  visible = false;
  pid: number | null = null;
  imagePath: string | null = null;
  piped = false;
  literals: SensitiveLiterals | null = null;
  identity: ProcessIdentityFacts | null = null;
  containment: ContainmentFacts | null = null;
  instanceId: PiId | null = null;
  moduleMapId: MmId | null = null;
  agentFacts: AgentReadyFacts | null = null;
  observation: SessionObservation | null = null;
  fridaSession: FridaSessionLike | null = null;
  script: FridaScriptLike | null = null;
  /**
   * Review fix LIFE-1: the in-flight createScript/load of a startup that gave up on it (step timeout). Detaching while
   * it is in flight strands frida-agent.dll in the target, so cleanup waits for it (bounded) before unload + detach.
   */
  pendingStartup: Promise<unknown> | null = null;
  /** the createScript promise of a startup whose create-script step timed out (its script was never assigned) */
  pendingScript: Promise<FridaScriptLike> | null = null;
  channel: AgentChannel | null = null;
  rpc: AgentRpcClient | null = null;
  output: BoundedOutputCapture | null = null;
  jobHost: JobHostPort | null = null;
  watcher: ProcessWatcherPort | null = null;
  readonly binder: SessionStreamBinder;
  readonly jobs: AgentJobs;
  readonly crash: CrashProtocol;
  readonly flow: FlowTracker;
  readonly hub: ConditionHub;
  readonly queue: SerialQueue;
  readonly closeController = new AbortController();
  /** controllers of admitted operations bound to this session (aborted at close) */
  readonly ops = new Set<AbortController>();
  readonly #disconnectors: (() => void)[] = [];
  detach: DetachInfo | null = null;
  exit: ProcessExit | null = null;
  exitAt: number | null = null;
  readonly tree: ProcessTree = { active: null, settled: false, children: [], procExited: 0 };
  resumedAt: number | null = null;
  closing: Promise<Result<CloseReport, BeaError>> | null = null;
  closeReport: CloseReport | null = null;
  retained: { readonly resources: readonly string[]; readonly reason: string } | null = null;
  readonly manifests: EvId[] = [];
  readonly limitations: string[] = [];
  readonly builtins = new Map<BuiltinKind, string>();
  systemStreams: {
    readonly exceptions: string | null;
    readonly modules: string;
    readonly threads: string | null;
  } | null = null;
  exceptionRows = 0;
  killRequested = false;
  #endedFired = false;
  #exitMarked = false;
  /** armed by Frida's process-terminated detach while the jobhost/watcher exit report is still due */
  #exitGrace: ReturnType<typeof setTimeout> | null = null;
  #derived: { readonly exitAt: number; readonly promise: Promise<Result<DerivedCrash | null, BeaError>> } | null = null;
  #background = new Set<Promise<unknown>>();
  readonly #detachWaiters = new Set<() => void>();
  readonly scripts: UserScriptPort;
  readonly facade: LiveSession & SessionHostFacts;

  constructor(input: {
    readonly id: SessionId;
    readonly ownership: "owned" | "attached";
    readonly initial: SessionState;
    readonly deps: RecordDeps;
    readonly scripts: (record: SessionRecord) => UserScriptPort;
  }) {
    this.id = input.id;
    this.ownership = input.ownership;
    this.deps = input.deps;
    this.createdAt = input.deps.now();
    this.#state = input.initial;
    this.queue = new SerialQueue(input.deps.limits.maxPendingOpsPerSession);
    this.hub = new ConditionHub(this.#conditionFacts(), input.deps.now);
    this.flow = new FlowTracker({
      post: (received) => this.script?.post({ type: "flow", received_bytes: received }),
      everyBytes: input.deps.limits.flow.ackEveryBytes,
      everyMs: input.deps.limits.flow.ackEveryMs,
    });
    this.binder = new SessionStreamBinder({
      streams: input.deps.evidence.streams,
      flushAgent: (stream, signal) => this.#flushAgent(stream, signal),
      flow: this.flow,
      moduleEpoch: () =>
        this.instanceId === null ? null : (input.deps.evidence.modules.current(this.instanceId)?.epoch ?? null),
      onRows: (stream, kind, rows) => this.#onRows(stream, kind, rows),
      onQuota: (stream) => this.#onQuota(stream),
      notify: () => this.hub.notify(),
      logger: input.deps.logger,
      now: input.deps.now,
      parking: input.deps.limits.parking,
    });
    this.jobs = new AgentJobs({
      blobs: input.deps.evidence.blobs,
      literals: () => this.literals ?? { count: 0, texts: [], spellings: [] },
      flow: this.flow,
      jobStatus: async (jobId, op) => {
        const rpc = this.rpc;
        if (rpc === null)
          return err({
            _tag: "CapabilityUnavailable",
            operation: op.name,
            capability: "agent",
            reason: "agent-gone",
            retryable: false,
          });
        return rpc.call("jobStatus", { job_id: jobId }, { op, timeoutMs: 2_000 });
      },
      notify: () => this.hub.notify(),
      logger: input.deps.logger,
    });
    this.crash = new CrashProtocol({
      post: (message) => this.script?.post(message),
      recordCrash: (report, deadline) => input.deps.sink.crashReport({ sessionId: this.id, report, deadline }),
      recordExit: (message, deadline) => input.deps.sink.exitReport({ sessionId: this.id, report: message, deadline }),
      ackTimeoutMs: input.deps.limits.crashAckTimeoutMs,
      ringSize: input.deps.limits.capture.crashes,
      now: input.deps.now,
      logger: input.deps.logger,
      onReport: () => this.hub.notify(),
    });
    this.scripts = input.scripts(this);
    this.facade = this.#buildFacade();
  }

  get state(): SessionState {
    return this.#state;
  }

  transition(to: SessionState, cause: string): void {
    const from = this.#state;
    if (from === to) return;
    assertTransition(from, to);
    this.#state = to;
    this.history.push({ state: to, at: this.deps.now(), cause });
    if (this.history.length > this.deps.limits.capture.stateHistory) this.history.shift();
    try {
      this.deps.sink.stateChanged({
        sessionId: this.id,
        from,
        to,
        cause,
        at: { monoNs: this.deps.monoNs().toString(), wall: this.deps.wallIso() },
      });
    } catch {
      // the sink never throws by contract; a broken sink must not break the state machine
    }
    this.hub.notify();
    if (to === "closed" || to === "cleanup_pending") this.hub.flushNow();
  }

  /** LIFO handler disconnectors, each wrapped (S3 §6.1). */
  onDisconnect(fn: () => void): void {
    this.#disconnectors.push(fn);
  }

  runDisconnectors(): void {
    if (this.#exitGrace !== null) {
      clearTimeout(this.#exitGrace);
      this.#exitGrace = null;
    }
    for (const fn of this.#disconnectors.splice(0).reverse()) {
      try {
        fn();
      } catch (cause) {
        this.deps.logger.debug("disconnect failed", { cause: cause instanceof Error ? cause : String(cause) });
      }
    }
  }

  /** Track a background promise so close and closeAll can await it. */
  track<T>(promise: Promise<T>): Promise<T> {
    this.#background.add(promise);
    void promise.finally(() => this.#background.delete(promise));
    return promise;
  }

  async drainBackground(ms: number): Promise<void> {
    if (this.#background.size === 0) return;
    await Promise.race([Promise.allSettled(this.#background), sleep(ms)]);
  }

  addLimitation(sentence: string): void {
    if (!this.limitations.includes(sentence)) this.limitations.push(sentence);
  }

  fireEnded(reason: "closed" | "exited" | "detached" | "shutdown"): void {
    if (this.#endedFired || !this.visible) return;
    this.#endedFired = true;
    try {
      this.deps.onEnded(this, reason);
    } catch (cause) {
      this.deps.logger.warn("session-ended listener failed", { cause: cause instanceof Error ? cause : String(cause) });
    }
  }

  /** Host-initiated work that must survive the session's own close (close and shutdown sequences). */
  internalOpDetached(name: string, ms: number): { readonly op: OperationContext; readonly dispose: () => void } {
    const deadline = Deadline.after(ms, this.deps.now);
    internalOps -= 1;
    return { op: { opId: internalOps, name, signal: deadline.signal(), deadline }, dispose: () => deadline.dispose() };
  }

  /** Resolves true once Frida reported the detach, false after `ms` (unaffected by the closing state). */
  waitDetached(ms: number): Promise<boolean> {
    if (this.detach !== null) return Promise.resolve(true);
    return new Promise((resolve) => {
      const done = (value: boolean): void => {
        clearTimeout(timer);
        this.#detachWaiters.delete(onDetach);
        resolve(value);
      };
      const onDetach = (): void => done(true);
      const timer = setTimeout(() => done(false), Math.max(0, ms));
      timer.unref?.();
      this.#detachWaiters.add(onDetach);
    });
  }

  /** A short-lived operation context for host-initiated work (stream flush, instrument stop, recording end). */
  internalOp(name: string, ms: number): { readonly op: OperationContext; readonly dispose: () => void } {
    const deadline = Deadline.after(ms, this.deps.now);
    const composed = composeSignal([this.closeController.signal, deadline.signal()]);
    internalOps -= 1;
    return {
      op: { opId: internalOps, name, signal: composed.signal, deadline },
      dispose: () => {
        composed.dispose();
        deadline.dispose();
      },
    };
  }

  // ---------------------------------------------------------------- liveness and terminal facts (S3 §6.4)
  liveness(): Liveness {
    const exit = this.exit;
    const tree = { activeAfterRoot: this.tree.active, settled: this.tree.settled };
    if (exit !== null)
      return {
        state: "exited",
        basis:
          exit.source === "jobhost"
            ? this.jobHost?.state === "helper-lost"
              ? "helper-lost-kernel-kill"
              : "jobhost-root-exit"
            : exit.source === "watcher"
              ? "watcher-root-exit"
              : "frida-process-terminated",
        exit,
        tree: this.ownership === "owned" ? tree : null,
      };
    if (this.detach?.reason === "process-terminated" || this.jobHost?.state === "helper-lost")
      return {
        state: "exited",
        basis: this.jobHost?.state === "helper-lost" ? "helper-lost-kernel-kill" : "frida-process-terminated",
        exit: null,
        tree: this.ownership === "owned" ? tree : null,
      };
    if (this.jobHost !== null) return { state: "alive", basis: "jobhost" };
    if (this.watcher !== null && this.watcher.rootExit === null) return { state: "alive", basis: "watcher" };
    if (this.detach === null && this.fridaSession !== null) return { state: "alive", basis: "frida-session" };
    return { state: "unknown", reason: this.detach === null ? "no-observer" : `detached:${this.detach.reason}` };
  }

  /** For "Script is destroyed": waits ≤ 50 ms for the exit/detach facts that explain it. */
  async terminalView(): Promise<TerminalView> {
    if (this.exit === null && this.detach === null)
      await this.hub.waitFor(
        { kind: "any", of: [{ kind: "process-exit" }, { kind: "detach" }] },
        { signal: this.closeController.signal },
        50,
      );
    const exited = this.exit !== null || this.detach?.reason === "process-terminated";
    return {
      closing: this.#state === "closing" || this.closeController.signal.aborted,
      exited: exited ? { exit: this.exit } : null,
      detachReason: this.detach?.reason ?? null,
      instanceId: this.instanceId ?? "",
    };
  }

  // ---------------------------------------------------------------- events from Frida, jobhost and watcher
  /** Frida session `detached` (connected at the subscribe step; S3 §14.1). */
  onDetached(reason: DetachReason | "unknown-before-subscribe", requestedByBea: boolean): void {
    if (this.detach !== null) return;
    this.detach = { reason, requestedByBea, at: { monoNs: this.deps.monoNs().toString(), wall: this.deps.wallIso() } };
    for (const waiter of [...this.#detachWaiters]) waiter();
    this.rpc?.markGone(reason);
    this.crash.ackAll("destroyed");
    this.jobs.closeAll("detached");
    try {
      this.deps.sink.detached({ sessionId: this.id, info: this.detach });
    } catch {
      // never throws by contract
    }
    if (reason === "process-terminated") this.#onTerminated();
    else if (!requestedByBea && (this.#state === "paused" || this.#state === "running")) {
      this.transition("detached", `detached:${reason}`);
      this.#endStreams("detached", "detached");
      this.fireEnded("detached");
    }
    this.hub.notify();
  }

  /** bea-jobhost root-exit (owned) or watcher root-exit (attached). */
  onRootExit(rootExit: RootExit, source: "jobhost" | "watcher"): void {
    if (this.exit !== null) return;
    this.exit = { ...exitInfoOf(rootExit.code, rootExit.byKill), source };
    this.exitAt = this.deps.now();
    this.tree.active = rootExit.activeAfterRoot;
    // Review fixes UX-4/ONBOARD-5: a fast clean exit is only the trigger, never the evidence (it describes every short
    // CLI run). The evidence of a hand-off is a child the root started that had already exited (beside a console host
    // still active); an unknown process count is no evidence either
    const active = rootExit.activeAfterRoot;
    if (
      this.ownership === "owned" &&
      !rootExit.byKill &&
      rootExit.code === 0 &&
      this.resumedAt !== null &&
      this.exitAt - this.resumedAt <= this.deps.limits.brokeredLaunchWindowMs &&
      active !== null &&
      active <= 1 &&
      this.tree.children.length - active > 0
    )
      this.addLimitation(LIMITATIONS.BROKERED_LAUNCH);
    try {
      this.deps.sink.rootExit({
        sessionId: this.id,
        exit: this.exit,
        activeAfterRoot: rootExit.activeAfterRoot,
        at: { monoNs: this.deps.monoNs().toString(), wall: this.deps.wallIso() },
      });
    } catch {
      // never throws by contract
    }
    this.#markExited();
  }

  onHelperLost(): void {
    this.addLimitation(LIMITATIONS.HELPER_LOST);
    this.#markExited();
  }

  /**
   * Frida's process-terminated detach usually arrives a few ms BEFORE the jobhost/watcher root-exit that carries the
   * exit code (measured: < 100 ms). The session is marked exited when that report arrives, or after
   * limits.exitReportGraceMs without it (EXIT_REPORT_LATE), so "process-exit" waits return the exit code and the
   * crash verdict instead of exit:null.
   */
  #onTerminated(): void {
    const reported = this.jobHost?.rootExit ?? this.watcher?.rootExit ?? null;
    if (this.exit === null && reported !== null) {
      this.onRootExit(reported, this.jobHost !== null ? "jobhost" : "watcher");
      return;
    }
    if (!this.#exitReportDue()) {
      this.#markExited();
      return;
    }
    if (this.#exitGrace !== null) return;
    this.#exitGrace = setTimeout(() => {
      this.#exitGrace = null;
      if (this.exit !== null) return;
      this.addLimitation(LIMITATIONS.EXIT_REPORT_LATE);
      this.#markExited();
    }, this.deps.limits.exitReportGraceMs);
    this.#exitGrace.unref?.();
  }

  #exitReportDue(): boolean {
    if (this.exit !== null) return false;
    const host = this.jobHost;
    if (host !== null) return host.state === "contained" || host.state === "root-exited" || host.state === "killing";
    return this.watcher !== null;
  }

  onTreeEvent(event: {
    readonly kind: "proc-start" | "proc-exit";
    readonly pid: number;
    readonly abnormal: boolean | null;
  }): void {
    if (event.kind === "proc-start" && event.pid !== this.pid && this.tree.children.length < 64)
      this.tree.children.push(event.pid);
    if (event.kind === "proc-exit") this.tree.procExited += 1;
    try {
      this.deps.sink.procEvent({
        sessionId: this.id,
        kind: event.kind,
        pid: event.pid,
        abnormal: event.abnormal,
        at: { monoNs: this.deps.monoNs().toString(), wall: this.deps.wallIso() },
      });
    } catch {
      // never throws by contract
    }
  }

  /** agent `instrument` messages: the agent ended an instrument (duration, max hits, exit…). */
  onInstrument(message: InstrumentMessage): void {
    if (message.event !== "ended") {
      this.deps.logger.debug("instrument notice", { session: this.id, instrument: message.id, event: message.event });
      return;
    }
    const detail = message.detail as EndedDetail;
    const recording = this.deps.recordings.list(this.id).find((r) => r.create.agentInstrumentId === message.id);
    const stream = recording?.create.agentStream ?? (typeof detail.stream === "string" ? detail.stream : null);
    if (stream !== null) this.binder.markEnded(stream);
    if (recording === undefined) return;
    const reason = END_REASONS[detail.end_reason ?? "requested"];
    const internal = this.internalOp("instrument.ended", 5_000);
    this.track(
      (async () => {
        try {
          if (stream !== null)
            await this.binder.endWith(stream, reason === "duration" || reason === "max_events" ? "expired" : "stopped");
          await this.deps.recordings.end(recording.id, reason, internal.op);
          await this.#settleEndedEffect(recording.create.effectId, detail);
        } finally {
          internal.dispose();
        }
      })(),
    );
  }

  /**
   * S2 §6.3: an instrument the agent removed on its own moves its effect out of `active`, so perturbation and
   * session_status stop counting it — `expired` at its lifetime (duration, max hits; agent-confirmed), `revert-failed`
   * whenever the agent could not verify the revert. Requested stops and session ends settle their effects themselves
   * (stop_instrumentation, the shutdown revert report, endAll), and an effect another path already moved is left alone.
   */
  async #settleEndedEffect(effectId: FxId | null, detail: EndedDetail): Promise<void> {
    const transition = endedEffectTransition(detail);
    if (effectId === null || transition === null) return;
    const effects = this.deps.evidence.effects;
    if (effects.state(effectId)?.status !== "active") return;
    const moved = await effects.transition(effectId, transition.to, transition.detail);
    if (!moved.ok && effects.state(effectId)?.status === "active")
      this.deps.logger.warn("instrument effect not settled", { session: this.id, error: moved.error._tag });
  }

  // ---------------------------------------------------------------- derived crash (CI-I9)
  crashOf(op: OperationContext): Promise<Result<DerivedCrash | null, BeaError>> {
    const exitAt = this.exitAt;
    if (this.exit === null || exitAt === null) return Promise.resolve(ok(null));
    if (this.#derived?.exitAt === exitAt) return this.#derived.promise;
    void op;
    const promise = this.#deriveCrash();
    this.#derived = { exitAt, promise };
    void promise.then((result) => {
      if (!result.ok && this.#derived?.promise === promise) this.#derived = null;
    });
    return promise;
  }

  async #deriveCrash(): Promise<Result<DerivedCrash | null, BeaError>> {
    const verdict = deriveCrashVerdict({
      exit: this.exit,
      exitAt: this.exitAt,
      reports: this.crash.crashes,
      windowMs: this.deps.limits.crashReportWindowMs,
      exceptionRows: this.exceptionRows,
    });
    if (verdict.kind === "none") return ok(null);
    for (const sentence of verdict.limitations) this.addLimitation(sentence);
    const describe = async (frame: {
      readonly va: string;
      readonly module: string | null;
      readonly rva: string | null;
    }): Promise<Loc> => {
      try {
        return await this.deps.address.describeCode({ kind: "live", session: this.facade }, BigInt(frame.va));
      } catch {
        return fallbackLoc(frame);
      }
    };
    const unrecorded = await buildDerivedCrash(verdict, describe, null, false);
    const instanceId = this.instanceId;
    if (instanceId === null) return ok(unrecorded);
    const links =
      verdict.report === null
        ? []
        : [this.deps.sink.crashEvidenceId(this.id, verdict.report.report_id)].filter((id): id is EvId => id !== null);
    const recorded = await this.deps.evidence.recorder.record({
      predicate_type: "bea.process.crash",
      operation: "crash_derivation",
      input: { session_exit: this.exit?.code_hex ?? "unknown" },
      subject: { kind: "process-instance", instance_id: instanceId },
      provider: { id: "bea", name: "bea", version: null },
      agent: null,
      confidence: "derived",
      authority: "live-process",
      result: { ...(unrecorded as unknown as JsonObject), evidence_id: null },
      coverage:
        verdict.report === null ? { status: "partial", truncated: false, reasons: ["unknown_completeness"] } : COMPLETE,
      limitations: verdict.limitations,
      evidence_links: links,
      literals: this.literals ?? { count: 0, texts: [], spellings: [] },
    });
    if (!recorded.ok) return recorded;
    return ok({ ...unrecorded, evidence_id: recorded.value.record.evidence_id });
  }

  // ---------------------------------------------------------------- internals
  #markExited(): void {
    if (this.#exitGrace !== null) {
      clearTimeout(this.#exitGrace);
      this.#exitGrace = null;
    }
    if (this.#exitMarked) {
      this.hub.notify();
      return;
    }
    this.#exitMarked = true;
    if (this.#state === "paused" || this.#state === "running" || this.#state === "detached")
      this.transition("exited", this.exit === null ? "process-terminated" : `root-exit:${this.exit.code_hex ?? "?"}`);
    this.rpc?.markGone("process-terminated");
    this.crash.ackAll("destroyed");
    this.jobs.closeAll("process exited");
    // a close or shutdown in progress ends the streams itself, with its own reason (process-killed, server-shutdown)
    if (!this.killRequested && this.#state !== "closing") {
      this.#endStreams("process-exited", "target_exited");
      this.fireEnded("exited");
    }
    this.hub.notify();
  }

  #endStreams(streamReason: "process-exited" | "detached", recordingReason: RecordingEndReason): void {
    if (!this.visible) return;
    const internal = this.internalOp("session.streams-ended", 5_000);
    this.track(
      (async () => {
        try {
          const { manifests } = await this.binder.endAll(streamReason);
          for (const manifest of manifests) this.#noteManifest(manifest.record.evidence_id as EvId);
          for (const recording of this.deps.recordings.list(this.id))
            if (recording.view().state === "active")
              await this.deps.recordings.end(recording.id, recordingReason, internal.op);
        } catch (cause) {
          this.deps.logger.warn("ending session streams failed", {
            cause: cause instanceof Error ? cause : String(cause),
          });
        } finally {
          internal.dispose();
        }
      })(),
    );
  }

  noteManifests(ids: readonly EvId[]): void {
    for (const id of ids) this.#noteManifest(id);
  }

  #noteManifest(id: EvId): void {
    if (!this.manifests.includes(id) && this.manifests.length < 64) this.manifests.push(id);
  }

  async #flushAgent(agentStream: string, signal: AbortSignal): Promise<void> {
    const rpc = this.rpc;
    if (rpc === null || this.exit !== null || this.detach !== null) return;
    const deadline = Deadline.after(5_000, this.deps.now);
    const composed = composeSignal([signal, this.closeController.signal, deadline.signal()]);
    try {
      await rpc.call(
        "flush",
        { streams: [agentStream] },
        { op: { opId: -1, name: "stream.flush", signal: composed.signal, deadline } },
      );
      await new Promise<void>((resolve) => setImmediate(resolve));
    } finally {
      composed.dispose();
      deadline.dispose();
    }
  }

  #onRows(agentStream: string, kind: RowKind, rows: readonly unknown[]): void {
    const streams = this.systemStreams;
    if (streams === null) return;
    if (kind === "exception/1" && agentStream === streams.exceptions) {
      for (const row of rows) if (Array.isArray(row) && row[7] !== "in-call") this.exceptionRows += 1;
      return;
    }
    if (kind === "module/1" && agentStream === streams.modules && this.instanceId !== null) {
      for (const row of rows) {
        if (!Array.isArray(row) || row.length < 8) continue;
        const [, , ev, name, path, base, size, epoch] = row as unknown[];
        if (
          (ev !== "L" && ev !== "U") ||
          typeof name !== "string" ||
          typeof path !== "string" ||
          typeof base !== "string" ||
          !/^0x[0-9a-f]{1,16}$/u.test(base) ||
          typeof size !== "number" ||
          typeof epoch !== "number"
        )
          continue;
        this.deps.evidence.modules.apply(this.instanceId, {
          op: ev === "L" ? "load" : "unload",
          epoch,
          modules: [{ name, base: base as `0x${string}`, size, path }],
        });
      }
    }
  }

  #onQuota(agentStream: string): void {
    const recording = this.deps.recordings.list(this.id).find((r) => r.create.agentStream === agentStream);
    if (recording === undefined || recording.view().state !== "active") return;
    const internal = this.internalOp("stream.quota", 5_000);
    this.track(
      (async () => {
        try {
          const instrument = recording.create.agentInstrumentId;
          if (instrument !== null && this.rpc !== null)
            await this.rpc.call("instrumentStop", { id: instrument, final_flush: false }, { op: internal.op });
          await this.deps.recordings.end(recording.id, "quota", internal.op);
        } finally {
          internal.dispose();
        }
      })(),
    );
  }

  #conditionFacts(): ConditionFacts {
    const record = this;
    return {
      get state() {
        return record.#state;
      },
      get exited() {
        // not Frida's process-terminated alone: the exit report (code) follows it within ms (#onTerminated)
        return record.exit !== null || record.#exitMarked || record.#state === "exited";
      },
      get detached() {
        return record.detach !== null;
      },
      get closed() {
        return record.#state === "closed" || record.#state === "closing" || record.#state === "cleanup_pending";
      },
      streamReceived: (stream) => record.binder.counters(stream)?.received ?? 0,
      streamEnded: (stream) => record.binder.counters(stream)?.ended ?? false,
      jobDone: (jobId) => record.jobs.jobDone(jobId),
      outputContains: (text) => record.output?.contains(text) ?? false,
    };
  }

  #buildFacade(): LiveSession & SessionHostFacts {
    const record = this;
    const goneAgent: AgentRpc = {
      health: { state: "gone", reason: "no-agent" },
      call: async (_method, _params, opts) =>
        err({
          _tag: "CapabilityUnavailable",
          operation: opts.op.name,
          capability: "agent",
          reason: "agent-gone",
          retryable: false,
        }),
    };
    return {
      id: record.id,
      kind: "live",
      ownership: record.ownership,
      get state() {
        return record.#state;
      },
      get instanceId() {
        return (record.instanceId ?? `pi_${"0".repeat(64)}`) as PiId;
      },
      get identity() {
        return record.identity as ProcessIdentityFacts;
      },
      get agent() {
        return record.#state === "closed" ? goneAgent : (record.rpc ?? goneAgent);
      },
      streams: record.binder,
      get output() {
        return record.output;
      },
      get lastCrash(): CrashReport | null {
        return record.crash.crashes.at(-1)?.report ?? null;
      },
      get paused() {
        return record.#state === "paused";
      },
      jobs: record.jobs,
      scripts: record.scripts,
      liveness: () => record.liveness(),
      waitFor: (cond, op, timeoutMs) => record.hub.waitFor(cond, op, Math.min(timeoutMs, record.deps.limits.maxWaitMs)),
      crash: (op) => record.crashOf(op),
      beaHostFacts: 1,
      get observation() {
        return record.observation;
      },
      containment: (): SessionContainmentView | null =>
        record.containment === null
          ? null
          : {
              kind: record.containment.kind,
              activeProcesses: record.ownership === "owned" ? (record.jobHost?.lastActive ?? record.tree.active) : null,
              childrenSeen: [...record.tree.children],
            },
      manifests: () => [...record.manifests],
      lifecycleEffects: () => record.deps.sink.lifecycleEffects(record.id),
      limitations: () => [...record.limitations],
    };
  }
}

const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    timer.unref?.();
  });
