import type { BeaCore } from "../../application/BeaApplication.js";
import { resolveDistLayout } from "../../application/distLayout.js";
import type { DoctorCheckResult, DoctorClassification } from "../../application/doctor.js";
import type { BackendStatus } from "../../application/status.js";
import { Deadline } from "../../domain/deadline.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { serverShuttingDown } from "../../domain/errors/constructors.js";
import type { HostPlatform } from "../../domain/paths.js";
import { err, ok, type Result } from "../../domain/result.js";
import type {
  AdoptRequest,
  JobHostAvailability,
  JobHostFactory,
  JobHostPort,
  JobHostProbe,
  ProcessInspection,
  ProcessWatcherPort,
  SpawnRequest,
  WatchRequest,
} from "../../ports/jobhost.js";
import { HelperLocator, type JobHostBinary } from "./HelperLocator.js";
import { JobHostHandle, raceTimeout } from "./JobHost.js";
import {
  HelperSession,
  launchHelperProcess,
  type HelperMode,
  type JobHostEventOf,
  type LaunchHelper,
  type SpawnModeStdio,
} from "./JobHostSession.js";
import type { HelperRequestFacts } from "./jobhostErrors.js";
import type { ProcFs } from "./posix/procfs.js";
import { ProcessInspector, type InspectEvent } from "./ProcessInspector.js";
import { ProcessWatcher } from "./ProcessWatcher.js";
import { validateAdopt, validateSpawn, validateWatch } from "./requests.js";

/**
 * JobHostFactory implementation (S3 §5, DESIGN §5.2; WP-PROC). Construction is synchronous and cheap: no file
 * access, no helper spawn, no target contact (CI-M20); everything happens lazily on the first call. Registers the
 * `jobhost` status row, the doctor checks `jobhost:binary`, `jobhost:probe` and `host:elevation` (win32; CI-I7) and a
 * shutdown backstop closer that kills every helper still alive after its owner (sessions, emulator) had a short grace
 * at the start of the teardown phase.
 */
export interface JobHostFactoryDeps {
  /** Tests inject a helper; production uses the running build's dist (distLayout.ts). */
  readonly exePath?: string;
  readonly manifestPath?: string;
  readonly platform?: HostPlatform;
  readonly launch?: LaunchHelper;
  readonly systemRoot?: string;
  readonly procFs?: ProcFs;
}

/** Grace the shutdown backstop gives owners before it kills their helpers itself (teardown budget 1300 ms). */
const BACKSTOP_GRACE_MS = 250;
const BACKSTOP_ESCALATE_MS = 700;
/** Budget of the doctor probe and of the status row's lazy probe. */
const PROBE_BUDGET_MS = 5000;
/** After a failed start, how long the helper may take to exit by itself before it is terminated. */
const FAILED_START_EXIT_MS = 500;

const INTEGRITY_NAMES: ReadonlyMap<number, string> = new Map([
  [0x0000, "untrusted"],
  [0x1000, "low"],
  [0x2000, "medium"],
  [0x2100, "medium-plus"],
  [0x3000, "high"],
  [0x4000, "system"],
  [0x5000, "protected"],
]);

const BUILD_REMEDIATION =
  "Run `npm run build` (needs WinLibs MinGW-w64 gcc on PATH) to produce dist/native/win32-x64/bea-jobhost.exe and its manifest.";

export class JobHostService implements JobHostFactory {
  readonly #core: BeaCore;
  readonly #platform: HostPlatform;
  readonly #locator: HelperLocator;
  readonly #launch: LaunchHelper;
  readonly #systemRoot: string;
  readonly #inspector: ProcessInspector;
  readonly #handles = new Set<JobHostHandle>();
  readonly #watchers = new Set<ProcessWatcher>();
  #probe: JobHostProbe | null = null;
  #probeInflight: Promise<Result<JobHostProbe, BeaError>> | null = null;
  #lastFailure: { readonly reason: string; readonly probe: JobHostProbe | null } | null = null;
  #version: string | null = null;
  #sha256: string | null = null;

  constructor(core: BeaCore, deps: JobHostFactoryDeps = {}) {
    this.#core = core;
    this.#platform = deps.platform ?? core.config.platform;
    const layout = deps.exePath === undefined || deps.manifestPath === undefined ? resolveDistLayout() : null;
    this.#locator = new HelperLocator({
      exePath: deps.exePath ?? layout?.jobhostExe ?? "",
      manifestPath: deps.manifestPath ?? layout?.jobhostManifest ?? "",
      platform: this.#platform,
    });
    this.#launch = deps.launch ?? launchHelperProcess;
    this.#systemRoot = deps.systemRoot ?? process.env["SystemRoot"] ?? "C:\\Windows";
    this.#inspector = new ProcessInspector({
      platform: this.#platform,
      runWindows: (pid, deadline) => this.#oneShot("inspect", [String(pid)], { deadline }, { pid }),
      ...(deps.procFs === undefined ? {} : { procFs: deps.procFs }),
    });
  }

  /** Owned helpers and watchers still running (tests, status). */
  get live(): { readonly owned: number; readonly watchers: number } {
    return { owned: this.#handles.size, watchers: this.#watchers.size };
  }

  availability(): JobHostAvailability {
    if (this.#platform !== "win32")
      return { state: "unavailable", sha256: null, reason: "unsupported-platform", probe: null };
    if (this.#probe !== null) return { state: "available", sha256: this.#sha256, reason: null, probe: this.#probe };
    if (this.#lastFailure !== null)
      return {
        state: "unavailable",
        sha256: this.#sha256,
        reason: this.#lastFailure.reason,
        probe: this.#lastFailure.probe,
      };
    return { state: "not-checked", sha256: null, reason: null, probe: null };
  }

  async adopt(req: AdoptRequest): Promise<Result<JobHostPort, BeaError>> {
    const operation = "jobhost.adopt";
    const args = validateAdopt(operation, req);
    if (!args.ok) return args;
    const session = await this.#startSession(operation, "adopt", args.value, null);
    if (!session.ok) return session;
    const handle = new JobHostHandle(session.value, { now: this.#core.clock.monoMs, logger: this.#core.logger });
    const started = await session.value.waitDecisive(operation, req.deadline, req.signal, { pid: req.pid });
    if (!started.ok) return this.#failedStart(session.value, started.error);
    if (started.value.event !== "adopted") return this.#failedStart(session.value, unexpected(operation));
    handle.bindDecisive(started.value);
    this.#track(handle);
    return ok(handle);
  }

  async spawn(req: SpawnRequest): Promise<Result<JobHostPort, BeaError>> {
    const operation = "jobhost.spawn";
    const args = validateSpawn(operation, req);
    if (!args.ok) return args;
    const stdio: SpawnModeStdio = { cwd: req.cwd, env: req.env, stdinPipe: req.stdin === "pipe" };
    const session = await this.#startSession(operation, "spawn", args.value, stdio);
    if (!session.ok) return session;
    const handle = new JobHostHandle(session.value, { now: this.#core.clock.monoMs, logger: this.#core.logger });
    const started = await session.value.waitDecisive(operation, req.deadline, req.signal, { exe: req.exe });
    if (!started.ok) return this.#failedStart(session.value, started.error);
    if (started.value.event !== "started") return this.#failedStart(session.value, unexpected(operation));
    handle.bindDecisive(started.value);
    this.#track(handle);
    return ok(handle);
  }

  async watch(req: WatchRequest): Promise<Result<ProcessWatcherPort, BeaError>> {
    const operation = "jobhost.watch";
    const args = validateWatch(operation, req);
    if (!args.ok) return args;
    const session = await this.#startSession(operation, "watch", args.value, null);
    if (!session.ok) return session;
    const watcher = new ProcessWatcher(session.value, this.#core.clock.monoMs);
    const started = await session.value.waitDecisive(operation, req.deadline, undefined, { pid: req.pid });
    if (!started.ok) return this.#failedStart(session.value, started.error);
    if (started.value.event !== "watching") return this.#failedStart(session.value, unexpected(operation));
    watcher.bindWatching(started.value);
    this.#watchers.add(watcher);
    void session.value.finished.then(() => this.#watchers.delete(watcher));
    return ok(watcher);
  }

  inspect(pid: number, deadline: Deadline): Promise<Result<ProcessInspection, BeaError>> {
    return this.#inspector.inspect(pid, deadline);
  }

  probe(deadline: Deadline): Promise<Result<JobHostProbe, BeaError>> {
    return this.probeWithSignal(deadline, undefined);
  }

  /** probe() honouring an extra abort signal (doctor). Memoized after the first `ok:true`. */
  probeWithSignal(deadline: Deadline, signal: AbortSignal | undefined): Promise<Result<JobHostProbe, BeaError>> {
    if (this.#probe !== null) return Promise.resolve(ok(this.#probe));
    this.#probeInflight ??= this.#runProbe(deadline, signal).finally(() => {
      this.#probeInflight = null;
    });
    return this.#probeInflight;
  }

  /** Lifecycle backstop (phase teardown-targets): owners first, then kill what is left; honours the phase signal. */
  async closeAll(signal: AbortSignal): Promise<void> {
    const handles = [...this.#handles];
    const watchers = [...this.#watchers];
    if (handles.length === 0 && watchers.length === 0) return;
    const force = (): void => {
      for (const handle of handles) handle.forceTerminate();
      for (const watcher of watchers) watcher.forceStop();
    };
    signal.addEventListener("abort", force, { once: true });
    try {
      if (signal.aborted) force();
      await raceTimeout(
        Promise.all([...handles.map((h) => h.settled), ...watchers.map((w) => w.exited)]),
        BACKSTOP_GRACE_MS,
      );
      await Promise.all([
        ...handles.map((handle) => handle.kill("server-shutdown", BACKSTOP_ESCALATE_MS)),
        ...watchers.map((watcher) => watcher.stop()),
      ]);
    } finally {
      signal.removeEventListener("abort", force);
    }
  }

  // ------------------------------------------------------------------ status and doctor
  async statusRow(): Promise<BackendStatus> {
    if (this.#platform !== "win32")
      return {
        id: "jobhost",
        state: "unavailable",
        version: null,
        detail: `bea-jobhost is Windows-only; on ${this.#platform} owned targets use best-effort ownership.`,
      };
    if (this.availability().state === "not-checked") await this.probe(Deadline.after(PROBE_BUDGET_MS));
    const availability = this.availability();
    if (availability.state === "available")
      return { id: "jobhost", state: "available", version: this.#version, detail: "probe ok" };
    const reason = availability.reason ?? "unknown";
    return {
      id: "jobhost",
      state: reason === "probe-failed" ? "failed" : "unavailable",
      version: this.#version,
      detail: reason === "probe-failed" ? `probe failed: ${failedSteps(availability.probe)}` : reason,
    };
  }

  async checkBinary(signal: AbortSignal): Promise<DoctorCheckResult> {
    const name = "jobhost:binary";
    const located = await this.#locator.locate("doctor.jobhost:binary");
    if (!located.ok) return failedCheck(name, located.error);
    const version = await this.#oneShot("version", [], { deadline: Deadline.after(PROBE_BUDGET_MS), signal }, {});
    if (!version.ok) return failedCheck(name, version.error);
    return {
      name,
      ok: true,
      classification: "healthy",
      detail: `bea-jobhost ${this.#version ?? "?"} (protocol 1, ${String(located.value.bytes)} B, sha256 ${located.value.sha256.slice(0, 16)}…) matches its build manifest`,
    };
  }

  async checkProbe(signal: AbortSignal): Promise<DoctorCheckResult> {
    const name = "jobhost:probe";
    const probe = await this.probeWithSignal(Deadline.after(PROBE_BUDGET_MS), signal);
    if (!probe.ok) return failedCheck(name, probe.error);
    if (!probe.value.ok)
      return {
        name,
        ok: false,
        classification: "runtime_failure",
        detail: `job_object_containment: unavailable (failed: ${failedSteps(probe.value)})`,
        remediation:
          "BEA needs nested Job Objects (Windows 10+). Security software may block AssignProcessToJobObject; run `bea doctor` from a normal (non-sandboxed) shell.",
      };
    return {
      name,
      ok: true,
      classification: "healthy",
      detail: `job_object_containment: available (job policy read back, JOB_LIST assignment before the first instruction, adopt assignment, TerminateJobObject; ${String(probe.value.elapsedMs)} ms)`,
    };
  }

  async checkElevation(signal: AbortSignal): Promise<DoctorCheckResult> {
    const name = "host:elevation";
    const self = await this.#oneShot(
      "inspect",
      [String(process.pid)],
      { deadline: Deadline.after(PROBE_BUDGET_MS), signal },
      { pid: process.pid },
    );
    if (!self.ok)
      return {
        name,
        ok: false,
        classification: "unknown",
        detail: `could not inspect BEA's own process (${errorReason(self.error)})`,
        remediation: BUILD_REMEDIATION,
      };
    const rid = self.value.integrityRid;
    const integrity = rid === null ? "unknown" : (INTEGRITY_NAMES.get(rid) ?? `0x${rid.toString(16)}`);
    const elevated = self.value.elevated;
    return {
      name,
      ok: true,
      classification: "healthy",
      detail:
        `elevated: ${elevated === null ? "unknown" : String(elevated)}; integrity: ${integrity}. ` +
        (elevated === true
          ? "BEA runs elevated: it can reach elevated targets; it never elevates on its own."
          : "Elevated or other users' targets are refused (BEA never elevates); protected processes are unsupported."),
    };
  }

  // ------------------------------------------------------------------ internals
  #track(handle: JobHostHandle): void {
    this.#handles.add(handle);
    void handle.settled.then(() => this.#handles.delete(handle));
  }

  async #startSession(
    operation: string,
    mode: HelperMode,
    args: readonly string[],
    spawnMode: SpawnModeStdio | null,
  ): Promise<Result<HelperSession, BeaError>> {
    if (mode !== "inspect" && mode !== "probe" && mode !== "version" && this.#core.lifecycle.closing)
      return err(serverShuttingDown(operation));
    const binary = await this.#locate(operation);
    if (!binary.ok) return binary;
    const session = new HelperSession({
      binaryPath: binary.value.path,
      mode,
      args: [mode, ...args],
      spawnMode,
      launch: this.#launch,
      systemRoot: this.#systemRoot,
    });
    session.subscribe((event) => {
      if (event.event === "hello") this.#version = event.version;
    });
    return ok(session);
  }

  async #locate(operation: string): Promise<Result<JobHostBinary, BeaError>> {
    const located = await this.#locator.locate(operation);
    if (located.ok) this.#sha256 = located.value.sha256;
    else if (this.#probe === null) this.#lastFailure = { reason: errorReason(located.error), probe: null };
    return located;
  }

  /** A failed start: let the helper exit by itself (it always does after `error`), else terminate it. */
  async #failedStart(session: HelperSession, error: BeaError): Promise<Result<never, BeaError>> {
    session.endControl();
    if ((await raceTimeout(session.finished, FAILED_START_EXIT_MS)) === "timeout") {
      session.terminate();
      await raceTimeout(session.finished, FAILED_START_EXIT_MS);
    }
    return err(error);
  }

  /** inspect / probe / version: start, take the decisive event, wait for the helper's own exit. */
  async #oneShot<M extends "inspect" | "probe" | "version">(
    mode: M,
    args: readonly string[],
    wait: { readonly deadline: Deadline; readonly signal?: AbortSignal | undefined },
    facts: HelperRequestFacts,
  ): Promise<Result<OneShotEvent[M], BeaError>> {
    const operation = `jobhost.${mode}`;
    const { deadline, signal } = wait;
    const session = await this.#startSession(operation, mode, args, null);
    if (!session.ok) return session;
    const decisive = await session.value.waitDecisive(operation, deadline, signal, facts);
    if (!decisive.ok) return this.#failedStart(session.value, decisive.error);
    if ((await raceTimeout(session.value.finished, Math.max(FAILED_START_EXIT_MS, deadline.remaining()))) === "timeout")
      session.value.terminate();
    return ok(decisive.value as OneShotEvent[M]);
  }

  async #runProbe(deadline: Deadline, signal: AbortSignal | undefined): Promise<Result<JobHostProbe, BeaError>> {
    const started = this.#core.clock.monoMs();
    const event = await this.#oneShot("probe", [], { deadline, signal }, {});
    if (!event.ok) {
      this.#lastFailure = { reason: errorReason(event.error), probe: null };
      return event;
    }
    const e = event.value;
    const probe: JobHostProbe = {
      ok: e.ok,
      jobPolicyVerified: e.jobPolicyVerified,
      jobListAttribute: e.jobListAttribute,
      assignedBeforeFirstInstruction: e.assignedBeforeFirstInstruction,
      adoptAssign: e.adoptAssign,
      terminateJob: e.terminateJob,
      elapsedMs: Math.round(this.#core.clock.monoMs() - started),
    };
    if (probe.ok) {
      this.#probe = probe;
      this.#lastFailure = null;
    } else this.#lastFailure = { reason: "probe-failed", probe };
    return ok(probe);
  }
}

interface OneShotEvent {
  readonly inspect: InspectEvent;
  readonly probe: JobHostEventOf<"probe">;
  readonly version: JobHostEventOf<"hello">;
}

const unexpected = (operation: string): BeaError => ({
  _tag: "ProviderFailure",
  operation,
  provider: "jobhost",
  diagnostics: { reason: "unexpected-decisive-event" },
});

/** Short machine reason for status rows and doctor details (curated; never raw helper text). */
const errorReason = (error: BeaError): string => {
  switch (error._tag) {
    case "CapabilityUnavailable":
      return error.reason;
    case "ProviderTimeout":
      return `timeout-${error.phase}`;
    case "ProviderFailure": {
      const reason = error.diagnostics?.["reason"];
      return typeof reason === "string" ? reason : "helper-failure";
    }
    default:
      return error._tag;
  }
};

const failedSteps = (probe: JobHostProbe | null): string => {
  if (probe === null) return "unknown";
  const steps = (
    [
      ["job-policy", probe.jobPolicyVerified],
      ["job-list", probe.jobListAttribute],
      ["assigned-before-first-instruction", probe.assignedBeforeFirstInstruction],
      ["adopt-assign", probe.adoptAssign],
      ["terminate-job", probe.terminateJob],
    ] as const
  )
    .filter(([, passed]) => !passed)
    .map(([step]) => step);
  return steps.length === 0 ? "none" : steps.join(", ");
};

const classificationOf = (error: BeaError): DoctorClassification => {
  if (error._tag !== "CapabilityUnavailable") return "runtime_failure";
  switch (error.reason) {
    case "unsupported-platform":
      return "unsupported_host";
    case "binary-missing":
    case "manifest-missing":
      return "missing_dependency";
    case "binary-digest-mismatch":
    case "manifest-invalid":
    case "protocol-mismatch":
      return "config_drift";
    default:
      return "runtime_failure";
  }
};

const failedCheck = (name: string, error: BeaError): DoctorCheckResult => ({
  name,
  ok: false,
  classification: classificationOf(error),
  detail: `bea-jobhost unavailable (${errorReason(error)})`,
  remediation: BUILD_REMEDIATION,
});
