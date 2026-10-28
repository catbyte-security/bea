import type { Deadline } from "../../domain/deadline.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { inputError } from "../../domain/errors/constructors.js";
import type { JobHostEvent } from "../../domain/jobhostProtocol.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { HostPlatform } from "../../domain/paths.js";
import type { ProcessInspection } from "../../ports/jobhost.js";
import {
  nodeProcFs,
  parseBootTime,
  parseRealUid,
  readProcStat,
  startTicksToFiletime,
  type ProcFs,
} from "./posix/procfs.js";

/**
 * Process identity and refusal facts (S3 §5.7 ProcessInspector, §19). Windows: the `inspect` event of
 * `bea-jobhost inspect <pid>` (SYNCHRONIZE | QUERY_LIMITED only; modifies nothing). Linux: /proc. Unknown facts are
 * null and never refuse on their own (S3 §5.8).
 */
export type InspectEvent = Extract<JobHostEvent, { readonly event: "inspect" }>;

/** Wire (`sessionId`, decimal creation time) → port (`osSessionId`, bigint). */
const inspectionFromEvent = (e: InspectEvent): ProcessInspection => ({
  pid: e.pid,
  access: e.access,
  exited: e.exited,
  exitCode: e.exitCode,
  creationTime100ns: e.creationTime100ns === null ? null : BigInt(e.creationTime100ns),
  imagePath: e.imagePath,
  parentPid: e.parentPid,
  osSessionId: e.sessionId,
  critical: e.critical,
  protectionLevel: e.protectionLevel,
  protected: e.protected,
  wow64: e.wow64,
  processMachine: e.processMachine,
  nativeMachine: e.nativeMachine,
  inJob: e.inJob,
  elevated: e.elevated,
  integrityRid: e.integrityRid,
  sameUser: e.sameUser,
});

const isValidPid = (pid: number): boolean => Number.isInteger(pid) && pid >= 0 && pid <= 0xffff_ffff;

const invalidPidError = (operation: string): BeaError =>
  inputError(operation, [
    {
      path: "pid",
      reason: "out_of_range",
      message: "pid must be an integer in 0..4294967295.",
      minimum: 0,
      maximum: 0xffff_ffff,
    },
  ]);

/** Linux inspection from /proc (best effort; BELIEVED). Windows-only facts stay null. */
export const inspectLinux = async (
  pid: number,
  fs: ProcFs = nodeProcFs,
  selfUid: number | null = typeof process.getuid === "function" ? process.getuid() : null,
): Promise<Result<ProcessInspection, BeaError>> => {
  const operation = "jobhost.inspect";
  if (!isValidPid(pid)) return err(invalidPidError(operation));
  const stat = await readProcStat(fs, pid);
  if (stat === null)
    return err(
      inputError(operation, [{ path: "pid", reason: "invalid_value", message: "No process with this pid exists." }]),
    );
  const optional = async <T>(read: () => Promise<T>): Promise<T | null> => {
    try {
      return await read();
    } catch {
      return null;
    }
  };
  const boot = await optional(async () => parseBootTime(await fs.readText("/proc/stat")));
  const uid = await optional(async () => parseRealUid(await fs.readText(`/proc/${String(pid)}/status`)));
  const exe = await optional(() => fs.readLink(`/proc/${String(pid)}/exe`));
  const exited = stat.state === "Z" || stat.state === "X";
  return ok({
    pid,
    access: "limited",
    exited,
    exitCode: null,
    creationTime100ns: boot === null ? null : startTicksToFiletime(boot, stat.startTicks),
    imagePath: exe,
    parentPid: stat.ppid,
    osSessionId: null,
    critical: null,
    protectionLevel: null,
    protected: null,
    wow64: null,
    processMachine: null,
    nativeMachine: null,
    inJob: null,
    elevated: uid === null ? null : uid === 0,
    integrityRid: null,
    sameUser: uid === null || selfUid === null ? null : uid === selfUid,
  });
};

export interface ProcessInspectorDeps {
  readonly platform: HostPlatform;
  /** win32: run `bea-jobhost inspect <pid>` and return its `inspect` event */
  readonly runWindows: (pid: number, deadline: Deadline) => Promise<Result<InspectEvent, BeaError>>;
  readonly procFs?: ProcFs;
}

/** JobHostFactory.inspect (CI-M24): `inspect` on win32, /proc on Linux, capability_unavailable elsewhere. */
export class ProcessInspector {
  readonly #deps: ProcessInspectorDeps;

  constructor(deps: ProcessInspectorDeps) {
    this.#deps = deps;
  }

  async inspect(pid: number, deadline: Deadline): Promise<Result<ProcessInspection, BeaError>> {
    const operation = "jobhost.inspect";
    if (!isValidPid(pid)) return err(invalidPidError(operation));
    switch (this.#deps.platform) {
      case "win32": {
        const event = await this.#deps.runWindows(pid, deadline);
        return event.ok ? ok(inspectionFromEvent(event.value)) : event;
      }
      case "linux":
        return inspectLinux(pid, this.#deps.procFs ?? nodeProcFs);
      default:
        return err({
          _tag: "CapabilityUnavailable",
          operation,
          capability: "platform",
          reason: "unsupported-platform",
          retryable: false,
        });
    }
  }
}
