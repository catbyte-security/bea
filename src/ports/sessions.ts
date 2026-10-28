import type { Loc } from "../domain/address/addressRef.js";
import type { Deadline } from "../domain/deadline.js";
import type { BeaError } from "../domain/errors/beaError.js";
import type { BlobRef } from "../domain/evidence/record.js";
import type { EvId, MmId, PiId, StId } from "../domain/ids.js";
import type { JsonObject, JsonValue } from "../domain/json.js";
import type { ExitInfo } from "../domain/process/instance.js";
import type { Result } from "../domain/result.js";
import type { TimeMark } from "../domain/time.js";
import type {
  AgentError,
  AgentFeature,
  AgentLimits,
  CrashReport,
  DumpManifest,
  HelloResult,
  JobInfo,
  RowKind,
  ScanStatus,
  ShutdownResult,
} from "../shared/agentProtocol.js";
import type { AgentHealth, AgentRpc } from "./agentRpc.js";
import type { RecordedEvidence, StreamSpec, StreamWriter } from "./evidence.js";

/**
 * The session surface application services call (S3 §7.1, amended). Implemented by
 * src/providers/frida/SessionManager.ts (WP-SESS). Live and emulation sessions share ONE id space: emulation
 * sessions register through registerExternal (WP-EMU) with their own capacity.
 */
export type SessionId = string; // lowercase UUID v4

export interface OperationContext {
  readonly opId: number;
  /** tool or internal op name (logged; inputs never logged) */
  readonly name: string;
  /** composed: caller ∪ shutdown ∪ session-closing ∪ deadline */
  readonly signal: AbortSignal;
  /** absolute, ≤ 120 s from admission */
  readonly deadline: Deadline;
  /** BEA-authored text only; the server layer rate-limits */
  readonly progress?: (phase: string, message: string) => void;
}
export interface AdmitRequest {
  readonly signal?: AbortSignal;
  readonly timeoutMs?: number;
  readonly sessionId?: SessionId;
}

export type SessionState =
  | "spawning"
  | "adopted"
  | "inspecting"
  | "attached"
  | "agent_loading"
  | "agent_ready" // startup (never visible)
  | "paused"
  | "running"
  | "exited"
  | "detached"
  | "failed"
  | "closing"
  | "cleanup_pending"
  | "closed";
/** Tool-visible projection (S6 C10): startup states never appear; `ready`/`lost` are emulation states. */
export type VisibleSessionState =
  | "paused"
  | "running"
  | "exited"
  | "detached"
  | "closing"
  | "cleanup_pending"
  | "closed"
  | "ready"
  | "lost";

export type StartupStep =
  | "preflight"
  | "reserve"
  | "spawn"
  | "metadata"
  | "adopt"
  | "inspect"
  | "policy"
  | "watch"
  | "attach"
  | "subscribe"
  | "create-script"
  | "load"
  | "ready"
  | "hello"
  | "verify-identity"
  | "promote"
  | "resume";

export interface SpawnInput {
  /** drive-absolute path to a PE32+ x64 .exe (no .bat/.cmd) */
  readonly program: string;
  /** argv[1..]; Frida receives [program, ...argv] */
  readonly argv: readonly string[];
  /** default: dirname(program) (S3 A1) */
  readonly cwd?: string;
  /**
   * CT-I7: added to the target's base environment, which is an OS allowlist (SystemRoot, windir, SystemDrive, ComSpec,
   * PATHEXT, PATH, TEMP, TMP, USERPROFILE, USERNAME, USERDOMAIN, HOMEDRIVE, HOMEPATH, APPDATA, LOCALAPPDATA,
   * ProgramData, ProgramFiles, ProgramFiles(x86), ProgramW6432, CommonProgramFiles, CommonProgramFiles(x86),
   * CommonProgramW6432, PUBLIC, COMPUTERNAME, NUMBER_OF_PROCESSORS, PROCESSOR_*, OS, ALLUSERSPROFILE, DriverData;
   * Linux: PATH HOME USER LANG LC_* TMPDIR XDG_RUNTIME_DIR DISPLAY WAYLAND_DISPLAY), unless config spawn.env_mode is
   * "inherit". BEA_* keys are always stripped (also from caller env). Passed to Frida as `envp` (replace), never `env`.
   */
  readonly env?: Readonly<Record<string, string>>;
  /** true: stdio 'pipe' (≤ 3 concurrent); false: 'inherit' (win32 only) */
  readonly captureOutput: boolean;
  /** host-internal only (CLI one-shots); the tool keeps resume as a separate EX call */
  readonly resume: boolean;
  readonly memLimitBytes?: number;
  /** checked BEFORE spawning */
  readonly expectSha256?: string;
  readonly redactLiterals: readonly string[];
}
export interface AttachInput {
  readonly pid: number;
  readonly expectSha256?: string;
  readonly redactLiterals: readonly string[];
}
export interface ProcessIdentityFacts {
  readonly deviceId: "local";
  readonly pid: number;
  readonly startTime: {
    readonly source: "os-creation-time" | "frida-started" | "first-observed";
    readonly value: string;
  };
  readonly image: {
    readonly path: string;
    readonly sha256: string | null;
    readonly size: number | null;
    readonly machine: "x64";
    readonly peTimestamp: number | null;
    readonly preferredBase: string | null;
  };
  readonly parentPid: number | null;
  readonly osSessionId: number | null;
  readonly integrity: "low" | "medium" | "high" | "system" | "unknown";
  readonly launchedByBea: boolean;
}
export interface ContainmentFacts {
  readonly kind: "win32-job" | "posix-best-effort" | "none";
  readonly helperPid: number | null;
  readonly killOnClose: boolean;
  readonly dieOnUnhandledException: boolean;
  readonly breakawayAllowed: false;
  readonly memLimitBytes: number | null;
  readonly wasInJobBeforeAdopt: boolean | null;
  readonly assignedBeforeResume: boolean;
  /** dies with the BEA server even on a hard kill */
  readonly crashSafe: boolean;
}
export interface AgentReadyFacts {
  readonly protocol: "bea-agent/1";
  readonly protocolMinor: number;
  readonly agentVersion: string;
  readonly buildId: string;
  readonly bundleSha256: string;
  readonly fridaVersion: string;
  readonly runtime: "QJS";
  readonly jsThreadId: number;
  readonly features: readonly AgentFeature[];
  readonly limits: AgentLimits;
  readonly hello: HelloResult;
}
export interface SessionObservation {
  readonly sessionId: SessionId;
  readonly instanceId: PiId;
  readonly moduleMapId: MmId;
  readonly ownership: "owned" | "attached";
  readonly state: "paused" | "running";
  readonly identity: ProcessIdentityFacts;
  readonly containment: ContainmentFacts;
  readonly agent: AgentReadyFacts;
  readonly output: { readonly captured: boolean; readonly mode: "frida-pipe" | "not-captured" };
  /** built-in recordings registered at startup (exceptions, modules, output) */
  readonly builtinRecordings: readonly string[];
  readonly antiCheatSignals: readonly string[];
  /** CT-I7: how the target environment was built (spawn only; null for attach). Counts only, never key names. */
  readonly environment: {
    readonly mode: "allowlist" | "inherit";
    readonly allowlistVersion: 1;
    readonly droppedKeys: number;
    readonly callerKeys: number;
  } | null;
  readonly startup: { readonly steps: readonly { step: StartupStep; ms: number }[]; readonly totalMs: number };
  readonly limitations: readonly string[];
}

export interface ProcessExit extends ExitInfo {
  readonly source: "jobhost" | "watcher" | "frida-detach-only";
}
export type DetachReason =
  | "application-requested"
  | "process-replaced"
  | "process-terminated"
  | "connection-terminated"
  | "device-lost";
export interface DetachInfo {
  readonly reason: DetachReason | "unknown-before-subscribe";
  readonly requestedByBea: boolean;
  readonly at: TimeMark;
}
export type Liveness =
  | { readonly state: "alive"; readonly basis: "jobhost" | "watcher" | "frida-session" }
  | {
      readonly state: "exited";
      readonly basis:
        | "jobhost-root-exit"
        | "watcher-root-exit"
        | "frida-process-terminated"
        | "helper-lost-kernel-kill";
      readonly exit: ProcessExit | null;
      readonly tree: { readonly activeAfterRoot: number | null; readonly settled: boolean } | null;
    }
  | { readonly state: "unknown"; readonly reason: string };

export interface CloseOptions {
  /** attached: continue past unreverted effects (reported as revert-failed) */
  readonly force: boolean;
}
export interface CloseReport {
  readonly sessionId: SessionId;
  readonly kind: "live" | "emulation";
  readonly ownership: "owned" | "attached" | null;
  readonly targetState: "killed" | "already-exited" | "alive-detached" | "exited-during-close" | "unknown" | "none";
  readonly termination: {
    readonly method: "terminate-job" | "helper-terminated" | "frida-kill-suspended-root" | "posix-best-effort" | "none";
    readonly activeBefore: number | null;
    readonly settled:
      | "observed-zero-active"
      | "kernel-enforced-unobserved"
      | "timed-out-with-active"
      | "not-applicable"
      | "unknown";
    readonly elapsedMs: number;
  } | null;
  readonly exit: ProcessExit | null;
  readonly revert: ShutdownResult | null;
  readonly agentUnloaded: boolean | null;
  readonly fridaDetached: boolean;
  readonly streamsFinalized: readonly StId[];
  readonly cleanup:
    | { readonly status: "complete" }
    | { readonly status: "incomplete"; readonly resources: readonly string[]; readonly reason: string };
  readonly limitations: readonly string[];
}
export type ShutdownReason =
  | "stdin-closed"
  | "SIGINT"
  | "SIGTERM"
  | "connection-closed"
  | "http-shutdown"
  | "cli-exit"
  | "test";
export interface CloseAllReport {
  readonly reason: ShutdownReason;
  readonly elapsedMs: number;
  readonly owned: readonly {
    readonly sessionId: SessionId;
    readonly pid: number;
    readonly termination: CloseReport["termination"];
  }[];
  readonly attached: readonly {
    readonly sessionId: SessionId;
    readonly pid: number;
    readonly agentUnloaded: boolean | null;
    readonly fridaDetached: boolean;
    readonly targetAlive: boolean | null;
  }[];
  readonly external: readonly { readonly sessionId: SessionId; readonly ok: boolean }[];
  readonly abandonedOps: readonly string[];
  readonly failures: readonly BeaError[];
}

/** Wait conditions (S3 §6.6 re-expressed over S4 agent streams). Reading never consumes. */
export type WaitCondition =
  | { readonly kind: "process-exit" }
  | { readonly kind: "detach" }
  | { readonly kind: "stream-events"; readonly agentStream: string; readonly atLeast: number }
  | { readonly kind: "stream-end"; readonly agentStream: string }
  | { readonly kind: "agent-job"; readonly jobId: string }
  | { readonly kind: "output-contains"; readonly text: string }
  | { readonly kind: "any"; readonly of: readonly WaitCondition[] }
  | { readonly kind: "all"; readonly of: readonly WaitCondition[] };
export interface WaitOutcome {
  readonly satisfied: boolean;
  readonly timedOut: boolean;
  readonly cancelled: boolean;
  readonly state: SessionState;
  readonly waitedMs: number;
}

/** Binds agent stream ids (S4 "s<n>", "s:exceptions", …) to evidence StreamWriters (S2). */
export interface StreamBinder {
  /** Call right after the RPC that created the agent stream; replays parked batches (≤ 256 KiB, ≤ 2 s). */
  bind(agentStream: string, spec: StreamSpec): Promise<Result<StreamWriter, BeaError>>;
  writer(agentStream: string): StreamWriter | undefined;
  counters(agentStream: string): StreamCounters | null;
  /**
   * RPC failed or instrument ended: end the writer with the given reason. CI-I13: returns the
   * bea.stream.manifest evidence so stop_instrumentation / close_session can report `manifest_evidence_id`.
   */
  end(
    agentStream: string,
    reason: "stopped" | "expired" | "install-failed" | "agent-error",
  ): Promise<Result<RecordedEvidence<JsonObject>, BeaError>>;
}
export interface StreamCounters {
  readonly agentStream: string;
  readonly streamId: StId | null;
  readonly kind: RowKind | "bytes";
  readonly received: number;
  readonly batches: number;
  readonly agentDropped: number;
  readonly hostDropped: {
    readonly bseqGap: number;
    readonly hostQueueFull: number;
    readonly quota: number;
    readonly malformed: number;
    readonly unbound: number;
  };
  readonly ended: boolean;
}

/** Head (64 KiB) + tail (192 KiB) per fd, always draining (S3 §15). */
export interface OutputCapture {
  readonly observedBytes: { readonly stdout: number; readonly stderr: number };
  tail(fd: 1 | 2, maxBytes: number): string;
  contains(text: string): boolean;
  readonly truncated: boolean;
  readonly eof: { readonly stdout: boolean; readonly stderr: boolean };
}

export interface AgentFault {
  readonly kind: "error-message" | "fatal" | "notice";
  readonly description: string;
  readonly at: TimeMark;
}

/**
 * CI-B3: agent job outcomes. AgentChannel (WP-SESS) routes `job` messages and assembles `blob` parts
 * (sha256 recomputed) into EvidenceRuntime.blobs before resolving. Consumers: WP-DUMP (dumps, bundles), WP-SCAN.
 */
export interface AgentJobOutcome {
  readonly info: JobInfo;
  readonly result: ScanStatus | DumpManifest | null;
  readonly error: AgentError | null;
  /** agent BlobId ("b<n>") -> stored blob; `redacted` when a literal matched; `failed` when parts were lost */
  readonly blobs: ReadonlyMap<string, BlobRef | { readonly redacted: true } | { readonly failed: string }>;
}
export interface AgentJobsPort {
  /** Resolves after the job's JobMessage AND every blob of the job are stored; timeout -> provider_timeout. */
  await(jobId: string, op: OperationContext, timeoutMs: number): Promise<Result<AgentJobOutcome, BeaError>>;
}

/** CI-B4: a caller script in its own Frida Script (never the BEA agent; S4 §16). WP-SESS implements. */
export interface UserScriptRequest {
  readonly source: string;
  readonly runtime: "qjs" | "v8";
  readonly durationMs: number;
  readonly maxMessages: number;
  readonly rpcMethod?: string;
  readonly rpcArgs: readonly JsonValue[];
}
export interface UserScriptOutcome {
  readonly messages: readonly JsonValue[];
  readonly errors: readonly { readonly description: string; readonly line: number | null }[];
  readonly rpcResult?: JsonValue;
  readonly truncated: boolean;
  /** false -> the caller reports effect_unreverted */
  readonly unloaded: boolean;
}
export interface UserScriptPort {
  /** createScript (syntax error -> invalid_request) -> load -> optional rpc call -> duration cap -> unload */
  run(req: UserScriptRequest, op: OperationContext): Promise<Result<UserScriptOutcome, BeaError>>;
}

/** CI-I9: S6 §5.5 derived crash = contracts/schemas/shared.ts crashReportSchema (tool shape). */
export interface DerivedCrash {
  readonly type: string;
  readonly ntstatus: string | null;
  readonly thread_id: number | null;
  readonly pc: Loc | null;
  readonly insn: string | null;
  readonly memory: { readonly op: "read" | "write" | "execute"; readonly address: string } | null;
  readonly registers: Readonly<Record<string, string>>;
  readonly backtrace: readonly Loc[];
  readonly first_chance_count: number;
  readonly evidence_id: EvId | null;
}

/** What services get for an admitted session (never the internal record). */
export interface LiveSession {
  readonly id: SessionId;
  readonly kind: "live";
  readonly ownership: "owned" | "attached";
  readonly state: SessionState;
  readonly instanceId: PiId;
  readonly identity: ProcessIdentityFacts;
  readonly agent: AgentRpc;
  readonly streams: StreamBinder;
  readonly output: OutputCapture | null;
  /** last crash report received from the agent (S4 CrashMessage), if any */
  readonly lastCrash: CrashReport | null;
  /** true until resume_process (owned targets start paused) */
  readonly paused: boolean;
  /** CI-B3 */
  readonly jobs: AgentJobsPort;
  /** CI-B4 */
  readonly scripts: UserScriptPort;
  liveness(): Liveness;
  waitFor(cond: WaitCondition, op: OperationContext, timeoutMs: number): Promise<WaitOutcome>;
  /** CI-I9: crashDerivation (WP-SESS) result, recorded as bea.process.crash before it is returned; null = no crash */
  crash(op: OperationContext): Promise<Result<DerivedCrash | null, BeaError>>;
}

/** Same fields as contracts/schemas/status.ts sessionSummarySchema (bea_status rows). */
export interface SessionSummary {
  readonly session_id: SessionId;
  readonly kind: "live" | "emulation";
  readonly state: VisibleSessionState;
  readonly pid: number | null;
  readonly ownership: "owned" | "attached" | "none";
  readonly image: string | null;
  readonly instance_id: string | null;
  readonly active_instruments: number;
  readonly active_effects: number;
}
export interface ProcessListing {
  readonly pid: number;
  readonly name: string;
  readonly path: string | null;
  readonly ppid: number | null;
  readonly started: string | null;
  readonly user: string | null;
}
export interface OwnedTargetRecord {
  readonly sessionId: SessionId;
  readonly pid: number;
  readonly creationTime100ns: string;
  readonly helperPid: number | null;
}
export interface HostStatus {
  readonly limits: {
    readonly liveSessions: { readonly used: number; readonly max: number };
    readonly pipedTargets: { readonly used: number; readonly max: 3 };
    readonly pendingOpsPerSession: 16;
  };
  readonly sessions: readonly SessionSummary[];
  readonly counters: {
    readonly orphanOutputBytes: number;
    readonly protocolViolations: number;
    readonly handlerErrors: number;
    readonly unboundStreamBatches: number;
  };
  readonly closing: boolean;
}

export interface ExternalSessionDriver {
  readonly kind: "emulation";
  /** closeAll fast path (bridge.shutdown → EOF → kill) */
  shutdown(deadline: Deadline): Promise<Result<void, BeaError>>;
  close(deadline: Deadline): Promise<Result<CloseReport, BeaError>>;
  summary(): SessionSummary;
  /** CI-B5: session_status `emulation` block (S5 §8.3); "complete" may ping the bridge and call session.info */
  detail(level: "summary" | "complete", op: OperationContext): Promise<Result<JsonObject, BeaError>>;
}
export type ExternalSessionFactory = (
  id: SessionId,
  op: OperationContext,
) => Promise<Result<ExternalSessionDriver, BeaError>>;

/** CI-B6: lets WP-owned host stores (scan hit stores, emulation handles, call scratch) release per-session state. */
export interface SessionEndedEvent {
  readonly sessionId: SessionId;
  readonly kind: "live" | "emulation";
  readonly reason: "closed" | "exited" | "detached" | "shutdown";
}

export interface DynamicSessionPort {
  /** Admission + op registry + composed signal. Returns capability_unavailable(shutting-down) once closing. */
  admit<T>(
    name: string,
    req: AdmitRequest,
    fn: (op: OperationContext) => Promise<Result<T, BeaError>>,
  ): Promise<Result<T, BeaError>>;
  spawn(input: SpawnInput, op: OperationContext): Promise<Result<SessionObservation, BeaError>>;
  attach(input: AttachInput, op: OperationContext): Promise<Result<SessionObservation, BeaError>>;
  /** Host-side enumeration (Frida metadata scope); never a liveness check. */
  processes(op: OperationContext): Promise<Result<readonly ProcessListing[], BeaError>>;
  resume(
    sessionId: SessionId,
    op: OperationContext,
  ): Promise<Result<{ readonly state: "running"; readonly resumedAt: TimeMark }, BeaError>>;
  close(sessionId: SessionId, options: CloseOptions, op: OperationContext): Promise<Result<CloseReport, BeaError>>;
  /** exclusive: agent RPCs and state changes (per-session FIFO, 16 pending); concurrent: host-state reads. */
  withSession<T>(
    sessionId: SessionId,
    op: OperationContext,
    mode: "exclusive" | "concurrent",
    fn: (s: LiveSession) => Promise<Result<T, BeaError>>,
  ): Promise<Result<T, BeaError>>;
  /** kind lookup for tools that accept both kinds; tombstones answer "closed". */
  kindOf(sessionId: SessionId): "live" | "emulation" | "closed" | null;
  external(sessionId: SessionId): ExternalSessionDriver | null;
  list(): readonly SessionSummary[];
  hostStatus(): HostStatus;
  ownedTargets(): readonly OwnedTargetRecord[];
  registerExternal(
    kind: "emulation",
    factory: ExternalSessionFactory,
    op: OperationContext,
  ): Promise<Result<SessionId, BeaError>>;
  /** kill-first, memoized, retryable (S3 §7.6); registered as the teardown-targets lifecycle closer. */
  closeAll(reason: ShutdownReason, deadline: Deadline): Promise<Result<CloseAllReport, BeaError>>;
  readonly closing: boolean;
  /** CI-B6: fired once per session (sync listeners, must not throw); returns the unsubscribe function */
  onSessionEnded(listener: (event: SessionEndedEvent) => void): () => void;
}
