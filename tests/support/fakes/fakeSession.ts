import { Deadline } from "../../../src/domain/deadline.js";
import type { BeaError } from "../../../src/domain/errors/beaError.js";
import { sessionNotFound } from "../../../src/domain/errors/constructors.js";
import { COMPLETE } from "../../../src/domain/evidence/coverage.js";
import type { BeaEvidence } from "../../../src/domain/evidence/record.js";
import { NO_PERTURBATION } from "../../../src/domain/evidence/record.js";
import { idOf, type PiId, type StId } from "../../../src/domain/ids.js";
import type { JsonObject } from "../../../src/domain/json.js";
import type { ExitInfo } from "../../../src/domain/process/instance.js";
import { err, ok, type Result } from "../../../src/domain/result.js";
import type {
  AppendOutcome,
  FrameBatchHeader,
  RecordedEvidence,
  StreamEndReason,
  StreamSpec,
  StreamStore,
  StreamWriter,
} from "../../../src/ports/evidence.js";
import type {
  AgentJobOutcome,
  AttachInput,
  CloseAllReport,
  CloseReport,
  DerivedCrash,
  DynamicSessionPort,
  ExternalSessionDriver,
  ExternalSessionFactory,
  HostStatus,
  LiveSession,
  Liveness,
  OperationContext,
  ProcessIdentityFacts,
  ProcessListing,
  SessionEndedEvent,
  SessionId,
  SessionObservation,
  SessionState,
  SpawnInput,
  StreamBinder,
  StreamCounters,
  UserScriptOutcome,
  UserScriptRequest,
  WaitCondition,
  WaitOutcome,
} from "../../../src/ports/sessions.js";
import { FakeAgentRpc } from "./fakeAgentRpc.js";

/**
 * Fake DynamicSessionPort + LiveSession (WP4-SESS test support; DESIGN §9.1 rule 4) for every area's unit and
 * boundary tests: sessions are plain objects whose agent is a FakeAgentRpc, whose StreamBinder writes to an in-memory
 * writer (or to a given StreamStore), and whose state, exit, crash, job outcomes and script outcomes are set by the
 * test. Admission composes the caller signal with a deadline; `exclusive` withSession calls are serialized per
 * session; closed sessions keep a tombstone (kindOf "closed", concurrent withSession still answers).
 */
export interface FakeLiveSessionOptions {
  readonly id?: SessionId;
  readonly ownership?: "owned" | "attached";
  readonly state?: SessionState;
  readonly pid?: number;
  readonly imagePath?: string;
  readonly instanceId?: PiId;
  readonly agent?: FakeAgentRpc;
  readonly streams?: StreamStore;
  readonly output?: string;
}

let fakeIds = 0;

export class FakeStreamWriter implements StreamWriter {
  readonly stream_id: StId;
  readonly descriptor_sha256 = "0".repeat(64);
  readonly frames: { readonly header: FrameBatchHeader; readonly payload: Uint8Array }[] = [];
  readonly counters = { records: 0, dropped: 0, redacted: 0, bytes: 0, state: "live" as "live" | "ended" };
  endReason: StreamEndReason | null = null;

  constructor(readonly spec: StreamSpec) {
    this.stream_id = idOf("st", { channel: spec.source.channel, n: (fakeIds += 1) });
  }

  append(header: FrameBatchHeader, payload: Uint8Array): AppendOutcome {
    if (this.counters.state === "ended") return "closed";
    this.frames.push({ header, payload });
    this.counters.records += header.count;
    this.counters.bytes += payload.length;
    return "accepted";
  }

  noteDropped(n: number): void {
    this.counters.dropped += n;
  }

  async checkpoint(): Promise<Result<RecordedEvidence<JsonObject>, BeaError>> {
    return ok(manifestOf(this));
  }

  async end(reason: StreamEndReason): Promise<Result<RecordedEvidence<JsonObject>, BeaError>> {
    this.endReason ??= reason;
    this.counters.state = "ended";
    return ok(manifestOf(this));
  }

  onQuota(): void {
    // quotas are not simulated
  }
}

const manifestOf = (writer: FakeStreamWriter): RecordedEvidence<JsonObject> => {
  const record: BeaEvidence<JsonObject> = {
    schema: "bea.evidence/1",
    evidence_id: idOf("ev", { manifest: writer.stream_id, records: writer.counters.records }),
    predicate_type: "bea.stream.manifest",
    operation: "stream_end",
    parameters: {},
    subject: null,
    observed_at: null,
    provider: { id: "bea", name: "bea", version: null },
    agent: null,
    confidence: "observed",
    authority: "live-process",
    perturbation: NO_PERTURBATION,
    result: { stream_id: writer.stream_id, records: writer.counters.records },
    raw_result: null,
    blobs: [],
    coverage: COMPLETE,
    limitations: [],
    locations: [],
    evidence_links: [],
    external_refs: [],
    effects: [],
    redactions: [],
    untrusted: false,
  };
  return { record, outcome: "added" };
};

/** In-memory StreamBinder: bind opens a writer (FakeStreamWriter unless a StreamStore is given). */
export class FakeStreamBinder implements StreamBinder {
  readonly writers = new Map<string, StreamWriter>();
  readonly #store: StreamStore | undefined;
  readonly #ended = new Set<string>();

  constructor(store?: StreamStore) {
    this.#store = store;
  }

  async bind(agentStream: string, spec: StreamSpec): Promise<Result<StreamWriter, BeaError>> {
    const existing = this.writers.get(agentStream);
    if (existing !== undefined) return ok(existing);
    const opened =
      this.#store === undefined ? ok(new FakeStreamWriter(spec) as StreamWriter) : await this.#store.open(spec);
    if (opened.ok) this.writers.set(agentStream, opened.value);
    return opened;
  }

  writer(agentStream: string): StreamWriter | undefined {
    return this.writers.get(agentStream);
  }

  counters(agentStream: string): StreamCounters | null {
    const writer = this.writers.get(agentStream);
    if (writer === undefined) return null;
    return {
      agentStream,
      streamId: writer.stream_id,
      kind: "bytes",
      received: writer.counters.records,
      batches: 0,
      agentDropped: 0,
      hostDropped: { bseqGap: 0, hostQueueFull: 0, quota: 0, malformed: 0, unbound: 0 },
      ended: this.#ended.has(agentStream) || writer.counters.state === "ended",
    };
  }

  /** Test helper: the agent ended the stream. */
  markEnded(agentStream: string): void {
    this.#ended.add(agentStream);
  }

  async end(
    agentStream: string,
    reason: "stopped" | "expired" | "install-failed" | "agent-error",
  ): Promise<Result<RecordedEvidence<JsonObject>, BeaError>> {
    const writer = this.writers.get(agentStream);
    if (writer === undefined)
      return err({
        _tag: "ReferenceNotFound",
        operation: "stream.end",
        reference: { kind: "stream", id: agentStream },
      });
    this.#ended.add(agentStream);
    return writer.end(reason);
  }
}

export class FakeLiveSession implements LiveSession {
  readonly id: SessionId;
  readonly kind = "live" as const;
  readonly ownership: "owned" | "attached";
  state: SessionState;
  readonly instanceId: PiId;
  identity: ProcessIdentityFacts;
  readonly agent: FakeAgentRpc;
  readonly streams: FakeStreamBinder;
  output: LiveSession["output"];
  lastCrash: LiveSession["lastCrash"] = null;
  exit: ExitInfo | null = null;
  derivedCrash: DerivedCrash | null = null;
  readonly jobOutcomes = new Map<string, AgentJobOutcome>();
  scriptOutcome: Result<UserScriptOutcome, BeaError> = ok({
    messages: [],
    errors: [],
    truncated: false,
    unloaded: true,
  });
  readonly scriptRuns: UserScriptRequest[] = [];
  readonly #waiters = new Set<() => void>();

  constructor(options: FakeLiveSessionOptions = {}) {
    this.id = options.id ?? `00000000-0000-4000-8000-${(fakeIds += 1).toString(16).padStart(12, "0")}`;
    this.ownership = options.ownership ?? "owned";
    this.state = options.state ?? (this.ownership === "owned" ? "paused" : "running");
    this.instanceId = options.instanceId ?? idOf("pi", { fake: this.id });
    this.agent = options.agent ?? new FakeAgentRpc({}, this.instanceId);
    this.streams = new FakeStreamBinder(options.streams);
    const path = options.imagePath ?? "C:\\fixtures\\game_sim.exe";
    this.identity = {
      deviceId: "local",
      pid: options.pid ?? 4242,
      startTime: { source: "os-creation-time", value: "133000000000000000" },
      image: { path, sha256: null, size: null, machine: "x64", peTimestamp: null, preferredBase: "0x140000000" },
      parentPid: null,
      osSessionId: 1,
      integrity: "medium",
      launchedByBea: this.ownership === "owned",
    };
    const text = options.output ?? null;
    this.output =
      text === null
        ? null
        : {
            observedBytes: { stdout: Buffer.byteLength(text), stderr: 0 },
            tail: (fd, maxBytes) => (fd === 1 ? text.slice(-maxBytes) : ""),
            contains: (needle) => text.includes(needle),
            truncated: false,
            eof: { stdout: false, stderr: false },
          };
  }

  get paused(): boolean {
    return this.state === "paused";
  }

  readonly jobs = {
    await: async (jobId: string, op: OperationContext): Promise<Result<AgentJobOutcome, BeaError>> => {
      const outcome = this.jobOutcomes.get(jobId);
      return outcome === undefined
        ? err({ _tag: "ProviderTimeout", operation: op.name, timeout_ms: 0, phase: "agent-job" })
        : ok(outcome);
    },
  };

  readonly scripts = {
    run: async (req: UserScriptRequest): Promise<Result<UserScriptOutcome, BeaError>> => {
      this.scriptRuns.push(req);
      return this.scriptOutcome;
    },
  };

  liveness(): Liveness {
    return this.exit === null && this.state !== "exited"
      ? { state: "alive", basis: this.ownership === "owned" ? "jobhost" : "watcher" }
      : {
          state: "exited",
          basis: this.ownership === "owned" ? "jobhost-root-exit" : "watcher-root-exit",
          exit:
            this.exit === null ? null : { ...this.exit, source: this.ownership === "owned" ? "jobhost" : "watcher" },
          tree: null,
        };
  }

  /** Test helper: the process exits (wakes waiters). */
  exitWith(exit: ExitInfo): void {
    this.exit = exit;
    this.state = "exited";
    this.notify();
  }

  notify(): void {
    for (const waiter of [...this.#waiters]) waiter();
  }

  async waitFor(cond: WaitCondition, op: OperationContext, timeoutMs: number): Promise<WaitOutcome> {
    const started = performance.now();
    const outcome = (satisfied: boolean, timedOut: boolean, cancelled: boolean): WaitOutcome => ({
      satisfied,
      timedOut,
      cancelled,
      state: this.state,
      waitedMs: Math.round(performance.now() - started),
    });
    if (this.#evaluate(cond)) return outcome(true, false, false);
    return new Promise((resolve) => {
      const done = (result: WaitOutcome): void => {
        clearTimeout(timer);
        this.#waiters.delete(check);
        op.signal.removeEventListener("abort", onAbort);
        resolve(result);
      };
      const check = (): void => {
        if (this.#evaluate(cond)) done(outcome(true, false, false));
      };
      const onAbort = (): void => done(outcome(false, false, true));
      const timer = setTimeout(() => done(outcome(false, true, false)), timeoutMs);
      op.signal.addEventListener("abort", onAbort, { once: true });
      this.#waiters.add(check);
    });
  }

  async crash(): Promise<Result<DerivedCrash | null, BeaError>> {
    return ok(this.derivedCrash);
  }

  #evaluate(cond: WaitCondition): boolean {
    switch (cond.kind) {
      case "process-exit":
        return this.state === "exited";
      case "detach":
        return this.state === "detached";
      case "stream-events":
        return (this.streams.counters(cond.agentStream)?.received ?? 0) >= cond.atLeast;
      case "stream-end":
        return this.streams.counters(cond.agentStream)?.ended ?? false;
      case "agent-job":
        return this.jobOutcomes.has(cond.jobId);
      case "output-contains":
        return this.output?.contains(cond.text) ?? false;
      case "any":
        return cond.of.some((inner) => this.#evaluate(inner));
      case "all":
        return cond.of.every((inner) => this.#evaluate(inner));
    }
  }
}

export class FakeSessions implements DynamicSessionPort {
  readonly sessions = new Map<SessionId, FakeLiveSession>();
  readonly externals = new Map<SessionId, ExternalSessionDriver>();
  readonly tombstones = new Map<SessionId, FakeLiveSession | null>();
  processList: ProcessListing[] = [];
  spawnResult: Result<SessionObservation, BeaError> | null = null;
  attachResult: Result<SessionObservation, BeaError> | null = null;
  closing = false;
  readonly #listeners = new Set<(event: SessionEndedEvent) => void>();
  readonly #queues = new Map<SessionId, Promise<unknown>>();
  #ops = 0;

  add(options: FakeLiveSessionOptions = {}): FakeLiveSession {
    const session = new FakeLiveSession(options);
    this.sessions.set(session.id, session);
    return session;
  }

  addExternal(id: SessionId, driver: ExternalSessionDriver): void {
    this.externals.set(id, driver);
  }

  /** Test helper: fire onSessionEnded. */
  fireEnded(event: SessionEndedEvent): void {
    for (const listener of [...this.#listeners]) listener(event);
  }

  async admit<T>(
    name: string,
    req: { readonly signal?: AbortSignal; readonly timeoutMs?: number },
    fn: (op: OperationContext) => Promise<Result<T, BeaError>>,
  ): Promise<Result<T, BeaError>> {
    if (this.closing)
      return err({
        _tag: "CapabilityUnavailable",
        operation: name,
        capability: "server",
        reason: "shutting-down",
        retryable: false,
      });
    const deadline = Deadline.after(req.timeoutMs ?? 120_000);
    const signal = req.signal ?? new AbortController().signal;
    try {
      return await fn({ opId: (this.#ops += 1), name, signal, deadline });
    } finally {
      deadline.dispose();
    }
  }

  async spawn(_input: SpawnInput, op: OperationContext): Promise<Result<SessionObservation, BeaError>> {
    return (
      this.spawnResult ??
      err({ _tag: "CapabilityUnavailable", operation: op.name, capability: "frida", reason: "fake", retryable: false })
    );
  }

  async attach(_input: AttachInput, op: OperationContext): Promise<Result<SessionObservation, BeaError>> {
    return (
      this.attachResult ??
      err({ _tag: "CapabilityUnavailable", operation: op.name, capability: "frida", reason: "fake", retryable: false })
    );
  }

  async processes(): Promise<Result<readonly ProcessListing[], BeaError>> {
    return ok(this.processList);
  }

  async resume(sessionId: SessionId, op: OperationContext) {
    const session = this.sessions.get(sessionId);
    if (session === undefined) return err(sessionNotFound(op.name, sessionId));
    if (session.state !== "paused")
      return err({ _tag: "InvalidState" as const, operation: op.name, state: session.state, expected: ["paused"] });
    session.state = "running";
    return ok({ state: "running" as const, resumedAt: { monoNs: "0", wall: new Date(0).toISOString() } });
  }

  async close(
    sessionId: SessionId,
    _options: { readonly force: boolean },
    op: OperationContext,
  ): Promise<Result<CloseReport, BeaError>> {
    const session = this.sessions.get(sessionId);
    if (session === undefined) return err(sessionNotFound(op.name, sessionId));
    session.state = "closed";
    this.sessions.delete(sessionId);
    this.tombstones.set(sessionId, session);
    this.fireEnded({ sessionId, kind: "live", reason: "closed" });
    return ok({
      sessionId,
      kind: "live",
      ownership: session.ownership,
      targetState: session.ownership === "owned" ? "killed" : "alive-detached",
      termination: null,
      exit: null,
      revert: null,
      agentUnloaded: null,
      fridaDetached: true,
      streamsFinalized: [],
      cleanup: { status: "complete" },
      limitations: [],
    });
  }

  async withSession<T>(
    sessionId: SessionId,
    op: OperationContext,
    mode: "exclusive" | "concurrent",
    fn: (s: LiveSession) => Promise<Result<T, BeaError>>,
  ): Promise<Result<T, BeaError>> {
    const session =
      this.sessions.get(sessionId) ??
      (mode === "concurrent" ? (this.tombstones.get(sessionId) ?? undefined) : undefined);
    if (session === undefined) return err(sessionNotFound(op.name, sessionId));
    if (mode === "concurrent") return fn(session);
    const previous = this.#queues.get(sessionId) ?? Promise.resolve();
    const run = previous.then(() => fn(session));
    this.#queues.set(
      sessionId,
      run.catch(() => undefined),
    );
    return run;
  }

  kindOf(sessionId: SessionId): "live" | "emulation" | "closed" | null {
    if (this.sessions.has(sessionId)) return "live";
    if (this.externals.has(sessionId)) return "emulation";
    if (this.tombstones.has(sessionId)) return "closed";
    return null;
  }

  external(sessionId: SessionId): ExternalSessionDriver | null {
    return this.externals.get(sessionId) ?? null;
  }

  list() {
    return [
      ...[...this.sessions.values()].map((s) => ({
        session_id: s.id,
        kind: "live" as const,
        state:
          s.state === "paused" || s.state === "running" || s.state === "exited" || s.state === "detached"
            ? s.state
            : ("closed" as const),
        pid: s.identity.pid,
        ownership: s.ownership,
        image: s.identity.image.path,
        instance_id: s.instanceId,
        active_instruments: 0,
        active_effects: 0,
      })),
      ...[...this.externals.values()].map((d) => d.summary()),
    ];
  }

  hostStatus(): HostStatus {
    return {
      limits: {
        liveSessions: { used: this.sessions.size, max: 4 },
        pipedTargets: { used: 0, max: 3 },
        pendingOpsPerSession: 16,
      },
      sessions: this.list(),
      counters: { orphanOutputBytes: 0, protocolViolations: 0, handlerErrors: 0, unboundStreamBatches: 0 },
      closing: this.closing,
    };
  }

  ownedTargets() {
    return [...this.sessions.values()]
      .filter((s) => s.ownership === "owned")
      .map((s) => ({
        sessionId: s.id,
        pid: s.identity.pid,
        creationTime100ns: s.identity.startTime.value,
        helperPid: null,
      }));
  }

  async registerExternal(
    _kind: "emulation",
    factory: ExternalSessionFactory,
    op: OperationContext,
  ): Promise<Result<SessionId, BeaError>> {
    const id = `00000000-0000-4000-8000-${(fakeIds += 1).toString(16).padStart(12, "0")}`;
    const created = await factory(id, op);
    if (!created.ok) return created;
    this.externals.set(id, created.value);
    return ok(id);
  }

  async closeAll(reason: CloseAllReport["reason"]): Promise<Result<CloseAllReport, BeaError>> {
    this.closing = true;
    for (const id of [...this.sessions.keys()]) this.fireEnded({ sessionId: id, kind: "live", reason: "shutdown" });
    this.sessions.clear();
    return ok({ reason, elapsedMs: 0, owned: [], attached: [], external: [], abandonedOps: [], failures: [] });
  }

  onSessionEnded(listener: (event: SessionEndedEvent) => void): () => void {
    this.#listeners.add(listener);
    return () => {
      this.#listeners.delete(listener);
    };
  }
}
