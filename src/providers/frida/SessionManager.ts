import { composeSignal } from "../../domain/abort.js";
import type { IdSource } from "../../domain/canonical.js";
import type { Clock } from "../../domain/clock.js";
import { Deadline } from "../../domain/deadline.js";
import { isBeaError, type BeaError } from "../../domain/errors/beaError.js";
import { internalError, sessionNotFound, serverShuttingDown } from "../../domain/errors/constructors.js";
import type { Logger } from "../../domain/logger.js";
import type { TimeMark } from "../../domain/time.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { SessionEvidenceSink } from "../../application/sessions/SessionEvidenceSink.js";
import type { AddressService } from "../../ports/address.js";
import type { EvidenceRuntime, SensitiveLiterals } from "../../ports/evidence.js";
import type { JobHostFactory } from "../../ports/jobhost.js";
import type { RecordingRegistry } from "../../ports/recordings.js";
import type {
  AdmitRequest,
  AttachInput,
  CloseAllReport,
  CloseOptions,
  CloseReport,
  DynamicSessionPort,
  ExternalSessionDriver,
  ExternalSessionFactory,
  HostStatus,
  LiveSession,
  OperationContext,
  OwnedTargetRecord,
  ProcessListing,
  SessionEndedEvent,
  SessionId,
  SessionObservation,
  SessionState,
  SessionSummary,
  ShutdownReason,
  SpawnInput,
} from "../../ports/sessions.js";
import { TimeMarkOf } from "./timeMark.js";
import { classifyAbort } from "./aborts.js";
import { machineWideAntiCheat } from "./antiCheatSignals.js";
import type { AttachSelfFacts } from "./attachPolicy.js";
import { runAttach, type AttachDeps } from "./attachSession.js";
import { runCloseAll } from "./closeAll.js";
import { abortSessionOps, closeAttached, closeBudget, closeOwned, type CloseDeps } from "./closeSession.js";
import type { FridaHost } from "./FridaHost.js";
import type { CancellableLike } from "./fridaPorts.js";
import { NO_RUNTIME_OVERRIDE, type HostLimits } from "./hostLimits.js";
import type { PeHeaderFacts } from "./peHeader.js";
import { SessionRecord } from "./SessionRecord.js";
import { isStartupState, visibleState } from "./sessionStates.js";
import { guard, preflightSpawn, runSpawn, type SpawnDeps } from "./spawnSession.js";
import { StepClock, type StartupContext } from "./startup.js";
import { createUserScriptPort } from "./userScript.js";

/**
 * The session surface (S3 §7; port DynamicSessionPort). Admission with a per-op composed signal (caller ∪ shutdown ∪
 * session ops ∪ deadline), the session registry with reservations (live ≤ config, piped ≤ 3), per-session FIFO,
 * deduplicated closes, tombstones for closed sessions, external (emulation) sessions in the same id space, and the
 * memoized kill-first closeAll. Startup records are invisible until promotion.
 */
export interface ManagerDeps {
  readonly host: FridaHost;
  readonly jobhost: JobHostFactory;
  readonly evidence: EvidenceRuntime;
  readonly recordings: RecordingRegistry;
  readonly address: AddressService;
  readonly sink: SessionEvidenceSink;
  readonly limits: HostLimits;
  readonly logger: Logger;
  readonly clock: Clock;
  readonly ids: IdSource;
  readonly lifecycleShutdown: AbortSignal;
  readonly serverEnv: Readonly<Record<string, string | undefined>>;
  readonly selfPid: number;
  readonly selfPpid: number | null;
  readonly hostPlatform: NodeJS.Platform;
  readonly beaVersion: string;
  readonly gates: { readonly writeMemory: boolean; readonly overrideFunction: boolean; readonly callAttached: boolean };
  readonly policy: SpawnDeps["policy"] & {
    readonly allowSession0: boolean;
    readonly extraDenylist: readonly string[];
  };
  readonly maxEmulationSessions: number;
  readonly files: {
    readonly hashFile: SpawnDeps["hashFile"];
    readonly listNeighbourhood: SpawnDeps["listNeighbourhood"];
    readonly readPe: (path: string, operation: string) => Promise<Result<PeHeaderFacts, BeaError>>;
    /** SEC-1: the final path of a spawn program (null when unresolvable); tests may omit it */
    readonly realPath?: (path: string) => Promise<string | null>;
    /** SEC-2: what a spawn cwd is; tests may omit it */
    readonly inspectDirectory?: SpawnDeps["inspectDirectory"];
    /** LIFE-3: the BEA-owned directory Frida extracts its agent into at the first attach (null: the user's TEMP) */
    readonly fridaTempDir?: () => string | null;
  };
  readonly systemRoot: string;
}

interface ExternalEntry {
  readonly id: SessionId;
  readonly driver: ExternalSessionDriver;
}

interface Tombstone {
  readonly kind: "live" | "emulation";
  readonly record: SessionRecord | null;
  readonly driver: ExternalSessionDriver | null;
  readonly report: CloseReport | null;
}

interface AdmittedOp {
  readonly opId: number;
  readonly name: string;
  readonly sessionId: SessionId | null;
  done: Promise<unknown>;
}

const MAX_TOMBSTONES = 256;

const capacityError = (operation: string, limits: Record<string, number>, message: string): BeaError => ({
  _tag: "ResourceConstraint",
  operation,
  resource: "capacity",
  limits,
  retryable: true,
  message,
});

export class SessionManager implements DynamicSessionPort {
  readonly #deps: ManagerDeps;
  readonly #records = new Map<SessionId, SessionRecord>();
  readonly #startups = new Set<SessionRecord>();
  /** failed startups whose cleanup could not finish (closeAll retries them) */
  readonly #retained = new Set<SessionRecord>();
  readonly #externals = new Map<SessionId, ExternalEntry>();
  readonly #tombstones = new Map<SessionId, Tombstone>();
  readonly #ops = new Map<AbortController, AdmittedOp>();
  readonly #listeners = new Set<(event: SessionEndedEvent) => void>();
  readonly #shutdown = new AbortController();
  #reservations = { live: 0, piped: 0, external: 0 };
  #closeAll: Promise<Result<CloseAllReport, BeaError>> | null = null;
  #closing = false;
  #opIds = 0;
  #machineWide: readonly string[] = [];
  #selfFacts: Promise<{ readonly elevated: boolean | null; readonly integrityRid: number | null }> | null = null;

  constructor(deps: ManagerDeps) {
    this.#deps = deps;
  }

  get closing(): boolean {
    return this.#closing || this.#deps.lifecycleShutdown.aborted;
  }

  /** Machine-wide anti-cheat labels from the last process listing (bea_status note). */
  get machineWideAntiCheat(): readonly string[] {
    return this.#machineWide;
  }

  // ---------------------------------------------------------------- admission (S3 §7.2)
  async admit<T>(
    name: string,
    req: AdmitRequest,
    fn: (op: OperationContext) => Promise<Result<T, BeaError>>,
  ): Promise<Result<T, BeaError>> {
    if (this.closing) return err(serverShuttingDown(name));
    const deadline = Deadline.after(
      Math.min(req.timeoutMs ?? this.#deps.limits.maxToolCallMs, this.#deps.limits.maxToolCallMs),
      () => this.#deps.clock.monoMs(),
    );
    const controller = new AbortController();
    const sources = [deadline.signal(), controller.signal, this.#shutdown.signal, this.#deps.lifecycleShutdown];
    if (req.signal !== undefined) sources.push(req.signal);
    const composed = composeSignal(sources);
    const record = req.sessionId === undefined ? undefined : this.#records.get(req.sessionId);
    this.#opIds += 1;
    const admitted: AdmittedOp = { opId: this.#opIds, name, sessionId: req.sessionId ?? null, done: Promise.resolve() };
    this.#ops.set(controller, admitted);
    record?.ops.add(controller);
    const op: OperationContext = { opId: this.#opIds, name, signal: composed.signal, deadline };
    try {
      if (composed.signal.aborted) return err(classifyAbort(composed.signal, name, { deadline }));
      const running = fn(op);
      admitted.done = running.catch(() => undefined);
      return await running;
    } catch (cause) {
      return err(isBeaError(cause) ? cause : internalError(name, cause));
    } finally {
      composed.dispose();
      deadline.dispose();
      this.#ops.delete(controller);
      record?.ops.delete(controller);
    }
  }

  // ---------------------------------------------------------------- startup
  async spawn(input: SpawnInput, op: OperationContext): Promise<Result<SessionObservation, BeaError>> {
    return this.spawnWith(input, op, false);
  }

  /** `internal` = BEA's own probes (doctor inject probe): skips the interpreter policy, never model input. */
  async spawnWith(
    input: SpawnInput,
    op: OperationContext,
    internal: boolean,
  ): Promise<Result<SessionObservation, BeaError>> {
    const clock = new StepClock(() => this.#deps.clock.monoMs());
    const deps = this.#spawnDeps();
    const pre = await preflightSpawn(deps, input, op, internal);
    if (!pre.ok) return pre;
    clock.mark("preflight");
    const reserved = this.#reserve(op.name, input.captureOutput);
    if (!reserved.ok) return reserved;
    clock.mark("reserve");
    const record = this.#newRecord("owned", "spawning");
    this.#startups.add(record);
    try {
      const live = await this.#deps.host.device(op);
      if (!live.ok) return live;
      const bundle = await this.#deps.host.agentBundle();
      if (!bundle.ok) return err({ ...bundle.error, operation: op.name });
      const observed = await runSpawn(deps, record, input, pre.value, op, clock, bundle.value, live.value);
      if (!observed.ok) {
        this.#failStartup(record);
        return observed;
      }
      this.#promote(record, input.captureOutput);
      if (input.resume) {
        const resumed = await this.#resumeRecord(record, op);
        if (!resumed.ok) return resumed;
        return ok({ ...observed.value, state: "running" });
      }
      return observed;
    } finally {
      this.#startups.delete(record);
      this.#release(input.captureOutput);
    }
  }

  async attach(input: AttachInput, op: OperationContext): Promise<Result<SessionObservation, BeaError>> {
    const clock = new StepClock(() => this.#deps.clock.monoMs());
    if (this.#deps.hostPlatform === "darwin")
      return err({
        _tag: "CapabilityUnavailable",
        operation: op.name,
        capability: "platform",
        reason: "macos-unsupported",
        retryable: false,
      });
    const reserved = this.#reserve(op.name, false);
    if (!reserved.ok) return reserved;
    clock.mark("reserve");
    const record = this.#newRecord("attached", "inspecting");
    this.#startups.add(record);
    try {
      const live = await this.#deps.host.device(op);
      if (!live.ok) return live;
      const bundle = await this.#deps.host.agentBundle();
      if (!bundle.ok) return err({ ...bundle.error, operation: op.name });
      const observed = await runAttach(this.#attachDeps(), record, input, op, clock, bundle.value, live.value);
      if (!observed.ok) {
        this.#failStartup(record);
        return observed;
      }
      this.#promote(record, false);
      return observed;
    } finally {
      this.#startups.delete(record);
      this.#release(false);
    }
  }

  async processes(op: OperationContext): Promise<Result<readonly ProcessListing[], BeaError>> {
    const live = await this.#deps.host.device(op);
    if (!live.ok) return live;
    const cancel = this.#deps.host.nativeCancel({ deadline: op.deadline.min(10_000), signal: op.signal });
    try {
      const listed = await live.value.device.enumerateProcesses({ scope: "metadata" }, cancel.token);
      this.#machineWide = machineWideAntiCheat(listed.map((p) => p.name));
      return ok(
        listed.map((p) => {
          const params = p.parameters;
          const ppid = params["ppid"];
          const started = params["started"];
          return {
            pid: p.pid,
            name: p.name,
            path: typeof params["path"] === "string" ? params["path"] : null,
            ppid: typeof ppid === "bigint" ? Number(ppid) : typeof ppid === "number" ? ppid : null,
            started: typeof started === "string" ? started : null,
            user: typeof params["user"] === "string" ? params["user"] : null,
          };
        }),
      );
    } catch (cause) {
      if (op.signal.aborted) return err(classifyAbort(op.signal, op.name, { deadline: op.deadline }));
      this.#deps.logger.debug("process enumeration failed", {
        text: cause instanceof Error ? cause.message : String(cause),
      });
      return err({
        _tag: "ProviderFailure",
        operation: op.name,
        provider: "frida",
        diagnostics: { phase: "enumerate-processes" },
      });
    } finally {
      cancel.dispose();
    }
  }

  // ---------------------------------------------------------------- resume (S3 §8 step 15; CI-I3)
  async resume(
    sessionId: SessionId,
    op: OperationContext,
  ): Promise<Result<{ readonly state: "running"; readonly resumedAt: TimeMark }, BeaError>> {
    const record = this.#records.get(sessionId);
    if (record === undefined) return err(this.#notFoundOrWrongKind(op.name, sessionId));
    return record.queue.run(op.name, op.signal, () => this.#resumeRecord(record, op));
  }

  async #resumeRecord(
    record: SessionRecord,
    op: OperationContext,
  ): Promise<Result<{ readonly state: "running"; readonly resumedAt: TimeMark }, BeaError>> {
    const operation = op.name;
    if (record.ownership === "attached")
      return err({
        _tag: "InvalidState",
        operation,
        state: "running",
        expected: ["paused"],
        message: "resume_process applies only to a paused BEA-spawned target; an attached process is already running.",
      });
    switch (record.state) {
      case "paused":
        break;
      case "exited":
        return err({
          _tag: "TargetExited",
          operation,
          instance_id: record.instanceId ?? "",
          exit: record.exit ?? { code: null, code_hex: null, kind: "unknown", name: null },
          detach_reason: record.detach?.reason ?? null,
        });
      case "detached":
        return err({
          _tag: "CapabilityUnavailable",
          operation,
          capability: "agent",
          reason: "agent-gone",
          retryable: false,
        });
      default:
        return err({ _tag: "InvalidState", operation, state: visibleState(record.state), expected: ["paused"] });
    }
    const live = await this.#deps.host.device(op);
    if (!live.ok) return live;
    const pid = record.pid ?? 0;
    const resumed = await guard(live.value.device.resume(pid), this.#deps.limits.startup.resumeGuardMs);
    if (resumed.kind !== "value") {
      if (record.exit !== null || record.detach !== null)
        return err({
          _tag: "TargetExited",
          operation,
          instance_id: record.instanceId ?? "",
          exit: record.exit ?? { code: null, code_hex: null, kind: "unknown", name: null },
          detach_reason: record.detach?.reason ?? null,
        });
      return err(
        resumed.kind === "timeout"
          ? { _tag: "ProviderTimeout", operation, timeout_ms: this.#deps.limits.startup.resumeGuardMs, phase: "resume" }
          : { _tag: "ProviderFailure", operation, provider: "frida", diagnostics: { phase: "resume" } },
      );
    }
    record.resumedAt = this.#deps.clock.monoMs();
    try {
      record.script?.post({ type: "resumed" });
    } catch {
      // the agent is gone: its instruments end with the process anyway
    }
    if (record.state === "paused") record.transition("running", `tool:${operation}`);
    try {
      this.#deps.recordings.onResumed(record.id);
    } catch (cause) {
      this.#deps.logger.warn("recording clocks not started", { cause: cause instanceof Error ? cause : String(cause) });
    }
    const at = TimeMarkOf(this.#deps.clock);
    this.#deps.sink.targetEffect({ sessionId: record.id, kind: "process-resumed", facts: { operation }, at });
    return ok({ state: "running" as const, resumedAt: at });
  }

  // ---------------------------------------------------------------- close (S3 §7.5)
  async close(
    sessionId: SessionId,
    options: CloseOptions,
    op: OperationContext,
  ): Promise<Result<CloseReport, BeaError>> {
    const tomb = this.#tombstones.get(sessionId);
    if (tomb !== undefined) return tomb.report === null ? err(sessionNotFound(op.name, sessionId)) : ok(tomb.report);
    const external = this.#externals.get(sessionId);
    if (external !== undefined) return this.#closeExternal(external, op);
    const record = this.#records.get(sessionId);
    if (record === undefined) return err(sessionNotFound(op.name, sessionId));
    record.closing ??= this.#closeRecord(record, options, op).then((result) => {
      if (!result.ok) record.closing = null;
      return result;
    });
    return record.closing;
  }

  async #closeRecord(
    record: SessionRecord,
    options: CloseOptions,
    op: OperationContext,
  ): Promise<Result<CloseReport, BeaError>> {
    const own = [...this.#ops.entries()].find(([, admitted]) => admitted.opId === op.opId)?.[0] ?? null;
    record.transition("closing", `tool:${op.name}`);
    abortSessionOps(record, own, { kind: "session-closing", sessionId: record.id });
    const deps = this.#closeDeps();
    const result =
      record.ownership === "owned"
        ? await closeOwned(deps, record, closeBudget(this.#deps.limits), op.name)
        : await closeAttached(deps, record, options, closeBudget(this.#deps.limits), op.name);
    if (!result.ok) {
      record.transition("cleanup_pending", "close:incomplete");
      return result;
    }
    this.#retire(record, result.value, "closed");
    return result;
  }

  async #closeExternal(entry: ExternalEntry, op: OperationContext): Promise<Result<CloseReport, BeaError>> {
    const closed = await entry.driver.close(op.deadline);
    if (!closed.ok) return closed;
    this.#externals.delete(entry.id);
    this.#tomb(entry.id, {
      kind: "emulation",
      record: null,
      driver: tombstoneDriver(entry.driver),
      report: closed.value,
    });
    this.#fire({ sessionId: entry.id, kind: "emulation", reason: "closed" });
    return closed;
  }

  // ---------------------------------------------------------------- session access
  async withSession<T>(
    sessionId: SessionId,
    op: OperationContext,
    mode: "exclusive" | "concurrent",
    fn: (s: LiveSession) => Promise<Result<T, BeaError>>,
  ): Promise<Result<T, BeaError>> {
    const record = this.#records.get(sessionId);
    if (record === undefined) {
      const tomb = this.#tombstones.get(sessionId);
      if (tomb?.record !== null && tomb?.record !== undefined && mode === "concurrent") return fn(tomb.record.facade);
      return err(this.#notFoundOrWrongKind(op.name, sessionId));
    }
    if (mode === "concurrent") return fn(record.facade);
    return record.queue.run(op.name, op.signal, () => fn(record.facade));
  }

  kindOf(sessionId: SessionId): "live" | "emulation" | "closed" | null {
    if (this.#records.has(sessionId)) return "live";
    if (this.#externals.has(sessionId)) return "emulation";
    if (this.#tombstones.has(sessionId)) return "closed";
    return null;
  }

  external(sessionId: SessionId): ExternalSessionDriver | null {
    return this.#externals.get(sessionId)?.driver ?? this.#tombstones.get(sessionId)?.driver ?? null;
  }

  list(): readonly SessionSummary[] {
    return [
      ...[...this.#records.values()].map((record) => this.#summary(record)),
      ...[...this.#externals.values()].map((e) => e.driver.summary()),
    ];
  }

  hostStatus(): HostStatus {
    const records = [...this.#records.values(), ...this.#startups];
    return {
      limits: {
        liveSessions: { used: this.#liveCount() + this.#reservations.live, max: this.#deps.limits.maxLiveSessions },
        pipedTargets: { used: this.#pipedCount() + this.#reservations.piped, max: 3 },
        pendingOpsPerSession: 16,
      },
      sessions: this.list(),
      counters: {
        orphanOutputBytes: this.#deps.host.orphanOutputBytes,
        protocolViolations: records.reduce((n, r) => n + (r.channel?.protocolViolations ?? 0), 0),
        handlerErrors: records.reduce((n, r) => n + (r.channel?.handlerErrors ?? 0), 0),
        unboundStreamBatches: records.reduce((n, r) => n + r.binder.unboundBatches, 0),
      },
      closing: this.closing,
    };
  }

  ownedTargets(): readonly OwnedTargetRecord[] {
    return [...this.#records.values(), ...this.#startups]
      .filter((r) => r.ownership === "owned" && r.pid !== null)
      .map((r) => ({
        sessionId: r.id,
        pid: r.pid ?? 0,
        creationTime100ns: r.jobHost?.creationTime100ns.toString() ?? r.identity?.startTime.value ?? "",
        helperPid: r.jobHost?.helperPid ?? null,
      }));
  }

  async registerExternal(
    kind: "emulation",
    factory: ExternalSessionFactory,
    op: OperationContext,
  ): Promise<Result<SessionId, BeaError>> {
    void kind;
    if (this.closing) return err(serverShuttingDown(op.name));
    if (this.#externals.size + this.#reservations.external >= this.#deps.maxEmulationSessions)
      return err(
        capacityError(
          op.name,
          { max_emulation_sessions: this.#deps.maxEmulationSessions },
          `At most ${String(this.#deps.maxEmulationSessions)} emulation sessions can be open. Close one (close_session) first.`,
        ),
      );
    this.#reservations.external += 1;
    const id = this.#deps.ids.uuid();
    try {
      const created = await factory(id, op);
      if (!created.ok) return created;
      this.#externals.set(id, { id, driver: created.value });
      return ok(id);
    } finally {
      this.#reservations.external -= 1;
    }
  }

  onSessionEnded(listener: (event: SessionEndedEvent) => void): () => void {
    this.#listeners.add(listener);
    return () => {
      this.#listeners.delete(listener);
    };
  }

  // ---------------------------------------------------------------- closeAll (S3 §7.6)
  closeAll(reason: ShutdownReason, deadline: Deadline): Promise<Result<CloseAllReport, BeaError>> {
    this.#closing = true;
    if (!this.#shutdown.signal.aborted) this.#shutdown.abort({ kind: "shutdown" });
    void deadline;
    this.#closeAll ??= this.#runCloseAll(reason).then((result) => {
      if (!result.ok || result.value.failures.length > 0) this.#closeAll = null;
      return result;
    });
    return this.#closeAll;
  }

  async #runCloseAll(reason: ShutdownReason): Promise<Result<CloseAllReport, BeaError>> {
    const records = [...this.#records.values(), ...this.#startups, ...this.#retained];
    const device =
      this.#deps.host.availability().device === "ready"
        ? await this.#deps.host.device({ signal: new AbortController().signal })
        : null;
    const outcome = await runCloseAll(this.#closeDeps(), {
      records,
      externals: [...this.#externals.values()],
      ops: new Map(
        [...this.#ops.entries()].map(([controller, admitted]) => [
          controller,
          { name: admitted.name, done: admitted.done },
        ]),
      ),
      device: device?.ok === true ? device.value.device : null,
      reason,
    });
    for (const record of outcome.closed)
      if (this.#records.has(record.id) || this.#retained.has(record)) this.#retire(record, null, "shutdown");
    for (const id of outcome.closedExternals) {
      const entry = this.#externals.get(id);
      this.#externals.delete(id);
      if (entry !== undefined) {
        this.#tomb(id, { kind: "emulation", record: null, driver: tombstoneDriver(entry.driver), report: null });
        this.#fire({ sessionId: id, kind: "emulation", reason: "shutdown" });
      }
    }
    return ok(outcome.report);
  }

  // ---------------------------------------------------------------- internals
  #newRecord(ownership: "owned" | "attached", initial: "spawning" | "inspecting"): SessionRecord {
    const deps = this.#deps;
    const id = deps.ids.uuid();
    return new SessionRecord({
      id,
      ownership,
      initial,
      deps: {
        evidence: deps.evidence,
        recordings: deps.recordings,
        address: deps.address,
        sink: deps.sink,
        limits: deps.limits,
        logger: deps.logger.child({ session: id }),
        now: () => deps.clock.monoMs(),
        monoNs: () => deps.clock.monoNs(),
        wallIso: () => deps.clock.wallIso(),
        createCancellable: () => this.#cancellable(),
        fridaVersion: () => deps.host.module?.version ?? null,
        onEnded: (record, reason) => this.#fire({ sessionId: record.id, kind: "live", reason }),
      },
      scripts: (record) =>
        createUserScriptPort({
          session: () => record.fridaSession,
          createCancellable: () => this.#cancellable(),
          logger: deps.logger,
          now: () => deps.clock.monoMs(),
          maxMessageBytes: deps.limits.userScript.maxMessageBytes,
          maxErrors: deps.limits.userScript.maxErrors,
          unloadMs: deps.limits.userScript.unloadMs,
        }),
    });
  }

  #cancellable(): CancellableLike {
    const mod = this.#deps.host.module;
    if (mod === null) return { isCancelled: false, cancel: () => undefined };
    return mod.createCancellable();
  }

  #reserve(operation: string, piped: boolean): Result<void, BeaError> {
    const max = this.#deps.limits.maxLiveSessions;
    if (this.#liveCount() + this.#reservations.live >= max)
      return err(
        capacityError(
          operation,
          { max_live_sessions: max },
          `BEA already has ${String(max)} live sessions. Close a session (close_session) first. ${NO_RUNTIME_OVERRIDE}`,
        ),
      );
    if (piped && this.#pipedCount() + this.#reservations.piped >= 3)
      return err(
        capacityError(
          operation,
          { max_piped_targets: 3 },
          `At most 3 targets can capture output. Close a session, or spawn with capture_output:false. ${NO_RUNTIME_OVERRIDE}`,
        ),
      );
    this.#reservations.live += 1;
    if (piped) this.#reservations.piped += 1;
    return ok(undefined);
  }

  #release(piped: boolean): void {
    this.#reservations.live = Math.max(0, this.#reservations.live - 1);
    if (piped) this.#reservations.piped = Math.max(0, this.#reservations.piped - 1);
  }

  #liveCount(): number {
    return this.#records.size;
  }

  #pipedCount(): number {
    let n = 0;
    for (const record of this.#records.values()) if (record.piped) n += 1;
    return n;
  }

  #promote(record: SessionRecord, piped: boolean): void {
    void piped;
    this.#records.set(record.id, record);
  }

  #failStartup(record: SessionRecord): void {
    if (isStartupState(record.state)) record.transition("failed", "startup");
    if (record.retained !== null) {
      if (record.state === "failed") record.transition("cleanup_pending", "startup-cleanup");
      this.#retained.add(record);
      return;
    }
    if (record.state === "failed") record.transition("closed", "startup-cleanup");
    this.#deps.sink.forget(record.id);
  }

  #retire(record: SessionRecord, report: CloseReport | null, reason: "closed" | "shutdown"): void {
    const path: SessionState[] =
      record.state === "closed"
        ? []
        : record.state === "closing" || record.state === "failed"
          ? ["closed"]
          : isStartupState(record.state)
            ? ["failed", "closed"]
            : ["closing", "closed"];
    for (const to of path) record.transition(to, "retire");
    record.closeReport = report;
    this.#records.delete(record.id);
    this.#retained.delete(record);
    record.fireEnded(reason);
    if (record.visible) this.#tomb(record.id, { kind: "live", record, driver: null, report });
  }

  #tomb(id: SessionId, tomb: Tombstone): void {
    this.#tombstones.set(id, tomb);
    while (this.#tombstones.size > MAX_TOMBSTONES) {
      const oldest = this.#tombstones.keys().next().value;
      if (oldest === undefined) break;
      this.#tombstones.delete(oldest);
    }
  }

  #fire(event: SessionEndedEvent): void {
    for (const listener of [...this.#listeners])
      try {
        listener(event);
      } catch (cause) {
        this.#deps.logger.warn("onSessionEnded listener threw", {
          cause: cause instanceof Error ? cause : String(cause),
        });
      }
  }

  #notFoundOrWrongKind(operation: string, sessionId: SessionId): BeaError {
    if (this.#externals.has(sessionId))
      return {
        _tag: "InputError",
        operation,
        issues: [
          {
            path: "session_id",
            reason: "invalid_value",
            message: `session_id names an emulation session; ${operation} needs a live session (spawn_process or attach_process).`,
          },
        ],
      };
    return sessionNotFound(operation, sessionId);
  }

  #summary(record: SessionRecord): SessionSummary {
    const active = this.#deps.recordings
      .list(record.id)
      .filter((r) => r.view().state === "active" && r.create.agentInstrumentId !== null).length;
    return {
      session_id: record.id,
      kind: "live",
      state: visibleState(record.state),
      pid: record.pid,
      ownership: record.ownership,
      image: record.identity?.image.path ?? record.imagePath,
      instance_id: record.instanceId,
      active_instruments: active,
      active_effects: record.instanceId === null ? 0 : this.#deps.evidence.effects.active(record.instanceId).length,
    };
  }

  #startupContext(): StartupContext {
    const deps = this.#deps;
    return {
      host: deps.host,
      evidence: deps.evidence,
      recordings: deps.recordings,
      sink: deps.sink,
      limits: deps.limits,
      logger: deps.logger,
      now: () => deps.clock.monoMs(),
      monoNs: () => deps.clock.monoNs(),
      wallIso: () => deps.clock.wallIso(),
      beaVersion: deps.beaVersion,
      platform: deps.hostPlatform === "linux" ? "linux" : "win32",
      gates: deps.gates,
    };
  }

  #literals(perCall: readonly string[]): Result<SensitiveLiterals, BeaError> {
    return this.#deps.evidence.literals(perCall);
  }

  #spawnDeps(): SpawnDeps {
    const deps = this.#deps;
    return {
      ...this.#startupContext(),
      createCancellable: () => this.#cancellable(),
      jobhost: deps.jobhost,
      policy: deps.policy,
      serverEnv: deps.serverEnv,
      selfPid: deps.selfPid,
      hostPlatform: deps.hostPlatform,
      hashFile: deps.files.hashFile,
      listNeighbourhood: deps.files.listNeighbourhood,
      readPe: deps.files.readPe,
      ...(deps.files.realPath === undefined ? {} : { realPath: deps.files.realPath }),
      ...(deps.files.inspectDirectory === undefined ? {} : { inspectDirectory: deps.files.inspectDirectory }),
      ...(deps.files.fridaTempDir === undefined ? {} : { fridaTempDir: deps.files.fridaTempDir }),
      literals: (perCall) => this.#literals(perCall),
      noteMachineWide: (labels) => {
        this.#machineWide = labels;
      },
      machineWideLabels: () => this.#machineWide,
    };
  }

  #attachDeps(): AttachDeps {
    const deps = this.#deps;
    return {
      ...this.#startupContext(),
      createCancellable: () => this.#cancellable(),
      jobhost: deps.jobhost,
      policy: {
        allowSession0: deps.policy.allowSession0,
        extraDenylist: deps.policy.extraDenylist,
        allowAntiCheat: deps.policy.allowAntiCheat,
        allowAntiCheatImages: deps.policy.allowAntiCheatImages,
      },
      self: () => this.#selfPolicyFacts(),
      hashFile: deps.files.hashFile,
      listNeighbourhood: deps.files.listNeighbourhood,
      readPe: deps.files.readPe,
      ...(deps.files.fridaTempDir === undefined ? {} : { fridaTempDir: deps.files.fridaTempDir }),
      literals: (perCall) => this.#literals(perCall),
      noteMachineWide: (labels) => {
        this.#machineWide = labels;
      },
      machineWideLabels: () => this.#machineWide,
    };
  }

  async #selfPolicyFacts(): Promise<AttachSelfFacts> {
    this.#selfFacts ??= this.#deps.jobhost
      .inspect(this.#deps.selfPid, Deadline.after(3_000))
      .then((r) =>
        r.ok
          ? { elevated: r.value.elevated, integrityRid: r.value.integrityRid }
          : { elevated: null, integrityRid: null },
      );
    const self = await this.#selfFacts;
    const records = [...this.#records.values(), ...this.#startups];
    return {
      pid: this.#deps.selfPid,
      ppid: this.#deps.selfPpid,
      helperPids: records.flatMap((r) =>
        [r.jobHost?.helperPid, r.watcher?.helperPid].filter((p): p is number => typeof p === "number"),
      ),
      sessionPids: new Map(
        [...this.#records.values()].filter((r) => r.pid !== null).map((r) => [r.pid ?? 0, r.id] as const),
      ),
      elevated: self.elevated,
      integrityRid: self.integrityRid,
      systemRoot: this.#deps.systemRoot,
    };
  }

  #closeDeps(): CloseDeps {
    const deps = this.#deps;
    return {
      sink: deps.sink,
      recordings: deps.recordings,
      limits: deps.limits,
      logger: deps.logger,
      now: () => deps.clock.monoMs(),
      createCancellable: () => this.#cancellable(),
    };
  }
}

/** A closed emulation session answers session_status from a frozen driver (state "closed"). */
const tombstoneDriver = (driver: ExternalSessionDriver): ExternalSessionDriver => {
  const last = driver.summary();
  return {
    kind: "emulation",
    shutdown: async () => ok(undefined),
    close: async () => err({ _tag: "SessionNotFound", operation: "close_session", session_id: last.session_id }),
    summary: () => ({ ...last, state: "closed", active_instruments: 0, active_effects: 0 }),
    detail: async () => ok({ status: "closed" }),
  };
};
