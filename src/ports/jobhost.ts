import type { Readable, Writable } from "node:stream";

import type { Deadline } from "../domain/deadline.js";
import type { BeaError } from "../domain/errors/beaError.js";
import type { JobHostEvent } from "../domain/jobhostProtocol.js";
import type { Result } from "../domain/result.js";

/**
 * bea-jobhost wrapper ports (S3 §5.7). Implemented by src/providers/process/** (WP-PROC); faked in tests.
 * An attached session holds a ProcessWatcherPort and NO JobHostPort: the type system has no kill path for it.
 */
export interface JobPolicy {
  readonly killOnClose: true;
  readonly dieOnUnhandledException: true;
  readonly breakawayAllowed: false;
  readonly memLimitBytes: number | null;
}
export interface AdoptRequest {
  readonly pid: number;
  /** From Frida metadata `started` (µs-truncated) converted to FILETIME. */
  readonly creationTime100ns: bigint;
  /** 10n: µs truncation (VERIFIED, S3 lab). */
  readonly tolerance100ns: bigint;
  readonly expectImage: string;
  /** process.pid: a Frida local spawn is a direct child (VERIFIED). */
  readonly expectParentPid: number;
  readonly memLimitBytes?: number;
  readonly deadline: Deadline;
  readonly signal?: AbortSignal;
}
export interface SpawnRequest {
  readonly exe: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly env: Readonly<Record<string, string>>;
  readonly suspended: boolean;
  readonly stdin: "nul" | "pipe";
  readonly killOnRootExit: boolean;
  readonly memLimitBytes?: number;
  readonly deadline: Deadline;
  readonly signal?: AbortSignal;
}
export interface WatchRequest {
  readonly pid: number;
  readonly creationTime100ns: bigint;
  readonly tolerance100ns: bigint;
  readonly deadline: Deadline;
}
export type JobHostState = "starting" | "contained" | "root-exited" | "killing" | "settled" | "helper-lost" | "failed";
export type KillReason =
  | "close-session"
  | "server-shutdown"
  | "startup-failed"
  | "startup-cancelled"
  | "protocol-violation";
export interface RootExit {
  readonly code: number;
  readonly codeHex: string;
  readonly byKill: boolean;
  readonly activeAfterRoot: number | null;
  readonly at: number;
}
export interface JobSettlement {
  readonly method: "control-kill" | "eof" | "helper-terminated" | "natural" | "root-exit-policy";
  readonly observation: "observed-zero-active" | "kernel-enforced-unobserved" | "timed-out-with-active";
  readonly activeBefore: number | null;
  readonly active: number | null;
  readonly peakJobMemoryBytes: number | null;
  readonly helperExitCode: number | null;
  /** spawn mode: stdout+stderr reached 'close' */
  readonly outputComplete: boolean;
  readonly elapsedMs: number;
}
export interface JobHostPort {
  readonly helperPid: number;
  readonly rootPid: number;
  readonly creationTime100ns: bigint;
  readonly imagePath: string | null;
  readonly policy: JobPolicy;
  readonly wasInJob: boolean | null;
  readonly state: JobHostState;
  readonly rootExit: RootExit | null;
  readonly lastActive: number | null;
  /** never rejects */
  readonly settled: Promise<JobSettlement>;
  on(listener: (e: JobHostEvent) => void): () => void;
  /** spawn --suspended only */
  resume(): Result<void, BeaError>;
  requestStatus(): void;
  /** idempotent, memoized; escalates to TerminateProcess(helper) after escalateAfterMs */
  kill(reason: KillReason, escalateAfterMs: number): Promise<JobSettlement>;
  readonly stdin: Writable | null;
  readonly stdout: Readable | null;
  readonly stderr: Readable | null;
}
export interface ProcessWatcherPort {
  readonly helperPid: number;
  readonly pid: number;
  readonly creationTime100ns: bigint;
  readonly imagePath: string | null;
  readonly rootExit: RootExit | null;
  /** null when stopped first */
  readonly exited: Promise<RootExit | null>;
  on(listener: (e: JobHostEvent) => void): () => void;
  /** EOF; the target is never touched (VERIFIED) */
  stop(): Promise<void>;
}
export interface ProcessInspection {
  readonly pid: number;
  readonly access: "limited" | "limited+synchronize";
  readonly exited: boolean | null;
  readonly exitCode: number | null;
  readonly creationTime100ns: bigint | null;
  readonly imagePath: string | null;
  readonly parentPid: number | null;
  readonly osSessionId: number | null;
  readonly critical: boolean | null;
  readonly protectionLevel: number | null;
  readonly protected: boolean | null;
  readonly wow64: boolean | null;
  readonly processMachine: number | null;
  readonly nativeMachine: number | null;
  readonly inJob: boolean | null;
  readonly elevated: boolean | null;
  readonly integrityRid: number | null;
  readonly sameUser: boolean | null;
}
export interface JobHostProbe {
  readonly ok: boolean;
  readonly jobPolicyVerified: boolean;
  readonly jobListAttribute: boolean;
  readonly assignedBeforeFirstInstruction: boolean;
  readonly adoptAssign: boolean;
  readonly terminateJob: boolean;
  readonly elapsedMs: number;
}
export interface JobHostAvailability {
  readonly state: "not-checked" | "available" | "unavailable";
  readonly sha256: string | null;
  readonly reason: string | null;
  readonly probe: JobHostProbe | null;
}
export interface JobHostFactory {
  availability(): JobHostAvailability;
  adopt(req: AdoptRequest): Promise<Result<JobHostPort, BeaError>>;
  spawn(req: SpawnRequest): Promise<Result<JobHostPort, BeaError>>;
  watch(req: WatchRequest): Promise<Result<ProcessWatcherPort, BeaError>>;
  inspect(pid: number, deadline: Deadline): Promise<Result<ProcessInspection, BeaError>>;
  /** memoized per server process after the first success */
  probe(deadline: Deadline): Promise<Result<JobHostProbe, BeaError>>;
}
