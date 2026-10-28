import type { BeaError } from "../../domain/errors/beaError.js";
import { LIMITATIONS } from "../../domain/evidence/limitations.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { SensitiveLiterals } from "../../ports/evidence.js";
import type { JobHostFactory, ProcessInspection, ProcessWatcherPort } from "../../ports/jobhost.js";
import type { AttachInput, OperationContext, ProcessIdentityFacts, SessionObservation } from "../../ports/sessions.js";
import { abortedError } from "./aborts.js";
import type { AgentBundle } from "./agentBundle.js";
import {
  ancestrySignals,
  antiCheatVerdict,
  directorySignals,
  importSignals,
  machineWideAntiCheat,
  moduleSignals,
} from "./antiCheatSignals.js";
import { evaluateAttachPolicy, type AttachPolicyConfig, type AttachSelfFacts } from "./attachPolicy.js";
import type { LiveDevice } from "./FridaHost.js";
import type { FridaDeviceLike, FridaSessionLike } from "./fridaPorts.js";
import { withTempDir } from "./fridaTemp.js";
import { createNativeCancel } from "./NativeCancel.js";
import type { PeHeaderFacts } from "./peHeader.js";
import type { SessionRecord } from "./SessionRecord.js";
import { cleanupStartup, type CleanupDeps } from "./startupCleanup.js";
import {
  agentIdentityOf,
  bindBuiltins,
  connectAgent,
  containmentJson,
  expectedInstanceId,
  fridaStep,
  listModulesOf,
  readyFacts,
  registerInstance,
  StepClock,
  type StartupContext,
} from "./startup.js";

/**
 * Attach path (S3 §9; DESIGN §5.1): bea-jobhost inspect → the refusal policy (rules 1–12, first hit wins, before any
 * injection; rule 12 = target-scoped anti-cheat signals: directory, on-disk imports, ancestry) → expect_sha256 →
 * bea-jobhost watch (pins the pid, reports the exit code, has no TERMINATE right) → attach → agent → hello → the live
 * module list is checked for anti-cheat modules before any instrumentation → instance → RUNNING. An attached target is
 * NEVER killed: every failure unloads and detaches.
 */
export interface AttachDeps extends StartupContext, CleanupDeps {
  readonly jobhost: JobHostFactory;
  readonly policy: AttachPolicyConfig;
  readonly self: () => Promise<AttachSelfFacts>;
  readonly hashFile: (
    path: string,
    signal?: AbortSignal,
  ) => Promise<{ readonly sha256: string; readonly size: number } | null>;
  readonly listNeighbourhood: (imagePath: string) => Promise<readonly string[]>;
  readonly readPe: (path: string, operation: string) => Promise<Result<PeHeaderFacts, BeaError>>;
  /** LIFE-3: the BEA-owned directory Frida extracts its agent into at the first attach (null: the user's TEMP) */
  readonly fridaTempDir?: () => string | null;
  readonly literals: (perCall: readonly string[]) => Result<SensitiveLiterals, BeaError>;
  readonly noteMachineWide: (labels: readonly string[]) => void;
  readonly machineWideLabels: () => readonly string[];
}

const integrityOf = (rid: number | null): ProcessIdentityFacts["integrity"] => {
  if (rid === null) return "unknown";
  if (rid >= 0x4000) return "system";
  if (rid >= 0x3000) return "high";
  if (rid >= 0x2000) return "medium";
  return "low";
};

const samePath = (a: string, b: string): boolean =>
  a.replaceAll("/", "\\").toLowerCase() === b.replaceAll("/", "\\").toLowerCase();

export const runAttach = async (
  deps: AttachDeps,
  record: SessionRecord,
  input: AttachInput,
  op: OperationContext,
  clock: StepClock,
  bundle: AgentBundle,
  live: LiveDevice,
): Promise<Result<SessionObservation, BeaError>> => {
  const operation = op.name;
  const pid = input.pid;
  record.pid = pid;
  const literals = deps.literals(input.redactLiterals);
  if (!literals.ok) return literals;
  record.literals = literals.value;

  // step 2: inspect
  const inspected = await deps.jobhost.inspect(pid, op.deadline.min(deps.limits.startup.inspectMs));
  if (!inspected.ok) return inspected;
  const inspection = inspected.value;
  record.imagePath = inspection.imagePath;
  clock.mark("inspect");

  // step 3: policy (target-scoped anti-cheat signals gathered before any injection)
  const listing = await processListing(deps, live.device, op);
  if (!listing.ok) return listing;
  deps.noteMachineWide(machineWideAntiCheat(listing.value.map((p) => p.name)));
  const pe = inspection.imagePath === null ? null : await deps.readPe(inspection.imagePath, operation);
  const signals = [
    ...(inspection.imagePath === null ? [] : directorySignals(await deps.listNeighbourhood(inspection.imagePath))),
    ...(pe?.ok === true ? importSignals(pe.value.imports) : []),
    ...ancestrySignals(pid, listing.value),
  ];
  const needsHash =
    input.expectSha256 !== undefined ||
    (signals.length > 0 && !deps.policy.allowAntiCheat && deps.policy.allowAntiCheatImages.length > 0);
  const hash =
    inspection.imagePath === null || !needsHash ? null : await deps.hashFile(inspection.imagePath, op.signal);
  const decision = evaluateAttachPolicy({
    pid,
    inspection,
    self: await deps.self(),
    config: deps.policy,
    antiCheatSignals: signals,
    imageSha256: hash?.sha256 ?? null,
  });
  if (decision.refusal !== null) return err({ ...decision.refusal, operation });
  if (decision.protectionUnknown) record.addLimitation(LIMITATIONS.PROTECTION_UNKNOWN);
  clock.mark("policy");

  // step 4: expect_sha256
  if (input.expectSha256 !== undefined) {
    const expected = input.expectSha256.toLowerCase();
    if (hash === null || hash.sha256 !== expected)
      return err({
        _tag: "InstanceMismatch",
        operation,
        expected_instance_id: `sha256:${expected}`,
        observed: { pid, start_time: inspection.creationTime100ns?.toString() ?? null },
        message: "The process image's sha256 differs from expect_sha256 (or could not be read); nothing was injected.",
        remediation: "Attach to the intended build, or omit expect_sha256.",
        diagnostics: { expected_sha256: expected, actual_sha256: hash?.sha256 ?? null },
      });
  }
  const aborted = abortedError(op.signal, operation, { deadline: op.deadline, phase: "policy" });
  if (aborted !== null) return err(aborted);

  // step 5: watch (pins the pid from here)
  const watcher = await startWatcher(deps, record, inspection, op);
  if (!watcher.ok) return watcher;
  clock.mark("watch");

  const fail = async (error: BeaError): Promise<Result<never, BeaError>> =>
    err(await cleanupStartup(deps, record, error, { device: null, reason: "startup-failed" }));

  // step 6: attach
  const cancel = createNativeCancel(deps.createCancellable(), {
    deadline: op.deadline.min(deps.limits.startup.attachMs),
    signal: op.signal,
  });
  let session: Result<FridaSessionLike, BeaError>;
  try {
    // LIFE-3: the injection that extracts Frida's agent runs with TEMP at BEA's own (swept) directory
    session = await withTempDir(deps.fridaTempDir?.() ?? null, () =>
      fridaStep(() => live.device.attach(pid, cancel.token), deps, op, "attach", {
        cancel,
        ms: deps.limits.startup.attachMs,
      }),
    );
  } finally {
    cancel.dispose();
  }
  if (!session.ok) return fail(session.error);
  clock.mark("attach");

  const startTime =
    inspection.creationTime100ns === null
      ? { source: "first-observed" as const, value: deps.wallIso() }
      : { source: "os-creation-time" as const, value: inspection.creationTime100ns.toString() };
  if (startTime.source !== "os-creation-time") record.addLimitation(LIMITATIONS.PID_REUSE_UNEXCLUDED);
  const mainPath = inspection.imagePath ?? "";
  const guess = expectedInstanceId({ pid, startTime, mainModulePath: mainPath, platform: "win32" });
  const connected = await connectAgent(deps, record, session.value, bundle, op, clock, guess);
  if (!connected.ok) return fail(connected.error);
  const { ready, hello } = connected.value;

  // step 12: identity
  if (record.watcher?.rootExit !== null && record.watcher?.rootExit !== undefined)
    return fail({
      _tag: "TargetExited",
      operation,
      instance_id: "",
      exit: { code: null, code_hex: null, kind: "unknown", name: null },
      detach_reason: null,
    });
  if (inspection.imagePath === null || !samePath(hello.process.main_module.path, inspection.imagePath))
    record.addLimitation(LIMITATIONS.MAIN_PATH_DIFFERS);
  const imagePath = inspection.imagePath ?? hello.process.main_module.path;
  const fullHash = hash ?? (await deps.hashFile(imagePath, op.signal));
  if (fullHash === null) record.addLimitation(LIMITATIONS.IMAGE_HASH_UNAVAILABLE);
  record.identity = {
    deviceId: "local",
    pid,
    startTime,
    image: {
      path: imagePath,
      sha256: fullHash?.sha256 ?? null,
      size: fullHash?.size ?? null,
      machine: "x64",
      peTimestamp: pe?.ok === true ? pe.value.timeDateStamp : null,
      preferredBase: pe?.ok === true ? pe.value.imageBase : null,
    },
    parentPid: inspection.parentPid,
    osSessionId: inspection.osSessionId,
    integrity: integrityOf(inspection.integrityRid),
    launchedByBea: false,
  };
  clock.mark("verify-identity");

  // (b) for attach: modules already loaded in the process, checked before any instrumentation
  const modules = await listModulesOf(record, op);
  if (!modules.ok) return fail(modules.error);
  const live_signals = moduleSignals(modules.value.modules.map((m) => m.name));
  if (live_signals.length > 0) {
    record.addLimitation(LIMITATIONS.ANTI_CHEAT_LIVE_CHECK);
    const verdict = antiCheatVerdict({
      signals: [...signals, ...live_signals],
      allowGlobal: deps.policy.allowAntiCheat,
      allowedImages: deps.policy.allowAntiCheatImages,
      imageSha256: fullHash?.sha256 ?? null,
    });
    if (verdict.kind === "refuse")
      return fail({
        _tag: "AccessDenied",
        operation,
        reason: "anti-cheat-detected",
        diagnostics: { signals: [...verdict.signals] },
      });
  }
  const allSignals = [...signals, ...live_signals];
  const allowed = allSignals.length > 0;
  const limitations: string[] = [LIMITATIONS.AGENT_FOOTPRINT];
  if (allowed) limitations.push(LIMITATIONS.ANTI_CHEAT_ALLOWED);
  else if (deps.machineWideLabels().length > 0) limitations.push(LIMITATIONS.ANTI_CHEAT_GLOBAL_PRESENT);
  for (const sentence of record.limitations) if (!limitations.includes(sentence)) limitations.push(sentence);

  const agentIdentity = agentIdentityOf(bundle, deps.beaVersion);
  const containment = containmentJson(record);
  const registered = await registerInstance(
    deps,
    record,
    op,
    {
      device_id: "local",
      pid,
      ownership: "attached",
      start_time: startTime,
      main_module_path: imagePath,
      agent: agentIdentity,
      environment: { platform: "win32", os_version: live.system.version, arch: "x64", pointer_size: 8 },
      ...(containment === undefined ? {} : { containment }),
      limitations,
      literals: literals.value,
    },
    modules.value,
  );
  if (!registered.ok) return fail(registered.error);
  record.instanceId = registered.value.instanceId;
  record.moduleMapId = registered.value.moduleMapId;
  const builtins = await bindBuiltins(deps, record, hello, registered.value.instanceId);
  if (!builtins.ok) return fail(builtins.error);

  // step 13: promote (running)
  deps.sink.bindSession({
    sessionId: record.id,
    instanceId: registered.value.instanceId,
    ownership: "attached",
    literals: literals.value,
    agent: agentIdentity,
  });
  record.agentFacts = readyFacts(ready, hello, bundle);
  record.visible = true;
  record.transition("running", "step:promote");
  const at = { monoNs: deps.monoNs().toString(), wall: deps.wallIso() };
  deps.sink.targetEffect({
    sessionId: record.id,
    kind: "agent-injected",
    facts: { operation, runtime: "qjs", build_id: bundle.buildId },
    at,
  });
  clock.mark("promote");
  record.observation = {
    sessionId: record.id,
    instanceId: registered.value.instanceId,
    moduleMapId: registered.value.moduleMapId,
    ownership: "attached",
    state: "running",
    identity: record.identity,
    containment: record.containment as NonNullable<typeof record.containment>,
    agent: record.agentFacts,
    output: { captured: false, mode: "not-captured" },
    builtinRecordings: builtins.value,
    antiCheatSignals: allowed ? allSignals : [],
    environment: null,
    startup: { steps: clock.steps, totalMs: clock.totalMs },
    limitations,
  };
  return ok(record.observation);
};

const processListing = async (
  deps: AttachDeps,
  device: FridaDeviceLike,
  op: OperationContext,
): Promise<
  Result<readonly { readonly pid: number; readonly name: string; readonly ppid: number | null }[], BeaError>
> => {
  const cancel = createNativeCancel(deps.createCancellable(), {
    deadline: op.deadline.min(deps.limits.startup.inspectMs),
    signal: op.signal,
  });
  try {
    const listed = await fridaStep(
      () => device.enumerateProcesses({ scope: "metadata" }, cancel.token),
      deps,
      op,
      "policy",
      { cancel, ms: deps.limits.startup.inspectMs },
    );
    if (!listed.ok) return listed;
    return ok(
      listed.value.map((p) => {
        const ppid = p.parameters["ppid"];
        return {
          pid: p.pid,
          name: p.name,
          ppid: typeof ppid === "bigint" ? Number(ppid) : typeof ppid === "number" ? ppid : null,
        };
      }),
    );
  } finally {
    cancel.dispose();
  }
};

const startWatcher = async (
  deps: AttachDeps,
  record: SessionRecord,
  inspection: ProcessInspection,
  op: OperationContext,
): Promise<Result<ProcessWatcherPort | null, BeaError>> => {
  if (inspection.creationTime100ns === null) {
    record.addLimitation(LIMITATIONS.WATCHER_UNAVAILABLE);
    setContainment(record, null, inspection);
    return ok(null);
  }
  const watched = await deps.jobhost.watch({
    pid: inspection.pid,
    creationTime100ns: inspection.creationTime100ns,
    tolerance100ns: 0n,
    deadline: op.deadline.min(deps.limits.startup.watchMs),
  });
  if (!watched.ok) return watched;
  const watcher = watched.value;
  record.watcher = watcher;
  const off = watcher.on((event) => {
    if (event.event === "root-exit")
      record.onRootExit(
        {
          code: event.code,
          codeHex: event.codeHex,
          byKill: event.byKill,
          activeAfterRoot: event.activeAfterRoot,
          at: deps.now(),
        },
        "watcher",
      );
  });
  record.onDisconnect(off);
  if (watcher.rootExit !== null) record.onRootExit(watcher.rootExit, "watcher");
  setContainment(record, watcher, inspection);
  return ok(watcher);
};

const setContainment = (
  record: SessionRecord,
  watcher: ProcessWatcherPort | null,
  inspection: ProcessInspection,
): void => {
  record.containment = {
    kind: "none",
    helperPid: watcher?.helperPid ?? null,
    killOnClose: false,
    dieOnUnhandledException: false,
    breakawayAllowed: false,
    memLimitBytes: null,
    wasInJobBeforeAdopt: inspection.inJob,
    assignedBeforeResume: false,
    crashSafe: false,
  };
};
