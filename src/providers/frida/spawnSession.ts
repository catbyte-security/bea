import { basename, win32 } from "node:path";

import { isNetworkPath } from "../../application/localPaths.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { LIMITATIONS } from "../../domain/evidence/limitations.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { SensitiveLiterals } from "../../ports/evidence.js";
import type { JobHostFactory, JobHostPort } from "../../ports/jobhost.js";
import type { OperationContext, SessionObservation, SpawnInput } from "../../ports/sessions.js";
import { abortedError } from "./aborts.js";
import {
  antiCheatVerdict,
  directorySignals,
  importSignals,
  machineWideAntiCheat,
  type AntiCheatVerdict,
} from "./antiCheatSignals.js";
import type { AgentBundle } from "./agentBundle.js";
import type { LiveDevice } from "./FridaHost.js";
import type { FridaDeviceLike, FridaSessionLike } from "./fridaPorts.js";
import { withTempDir } from "./fridaTemp.js";
import { createNativeCancel } from "./NativeCancel.js";
import { BoundedOutputCapture } from "./outputCapture.js";
import type { PeHeaderFacts } from "./peHeader.js";
import { withFridaMessage } from "./rpcErrors.js";
import { HOST_OUTPUT_STREAM, type SessionRecord } from "./SessionRecord.js";
import { buildTargetEnvironment, type EnvMode, type TargetEnvironment } from "./spawnEnv.js";
import {
  allowedProgram,
  crtCommandLineLength,
  isBatchScript,
  isDriveAbsoluteWin32,
  MAX_COMMAND_LINE,
  programRefusal,
  refusedLocations,
  versionInfoRefusal,
  type ProgramRefusal,
} from "./spawnPolicy.js";
import { cleanupStartup, killWhenSpawned, type CleanupDeps } from "./startupCleanup.js";
import {
  agentIdentityOf,
  bindBuiltins,
  connectAgent,
  containmentJson,
  envKeysDigest,
  expectedInstanceId,
  fridaStep,
  readyFacts,
  registerInstance,
  StepClock,
  type StartupContext,
} from "./startup.js";

/**
 * Spawn Path 1, owned (S3 §8; DESIGN §5.1): preflight (drive-absolute .exe, PE32+ x64, expect_sha256, the
 * interpreter/LOLBin refusal, target-scoped anti-cheat signals (a)+(b)) → reserve → the allowlisted environment as
 * `envp` → device.spawn (no cancellable, 10 s guard) → Frida metadata `started` → FILETIME → bea-jobhost adopt
 * (identity checked before assignment) → attach → agent → hello → instance registration → PAUSED. Cancellation or
 * failure at any step runs the startup cleanup (kill). BEA never runs an uncontained owned target on Windows.
 * device.kill is called only here and in startupCleanup.ts (verify-module-boundaries pins it).
 */
export interface SpawnDeps extends StartupContext, CleanupDeps {
  readonly jobhost: JobHostFactory;
  readonly policy: {
    readonly envMode: EnvMode;
    readonly allowInterpreters: boolean;
    /** SEC-1: config spawn.allowed_programs (drive-absolute paths or image sha256) */
    readonly allowedPrograms?: readonly string[];
    readonly allowAntiCheat: boolean;
    readonly allowAntiCheatImages: readonly string[];
  };
  /** SEC-1: the image's final path (junctions, symlinks and 8.3 names resolved), null when it cannot be resolved */
  readonly realPath?: (path: string) => Promise<string | null>;
  /** LIFE-3: the BEA-owned directory Frida extracts its agent into at the first attach (null: the user's TEMP) */
  readonly fridaTempDir?: () => string | null;
  /** SEC-2: what a spawn cwd is (resolved through junctions and mapped drives); tests may omit it */
  readonly inspectDirectory?: (path: string) => Promise<"directory" | "network" | "missing" | "not-directory">;
  readonly serverEnv: Readonly<Record<string, string | undefined>>;
  readonly selfPid: number;
  readonly hostPlatform: NodeJS.Platform;
  readonly hashFile: (
    path: string,
    signal?: AbortSignal,
  ) => Promise<{ readonly sha256: string; readonly size: number } | null>;
  readonly listNeighbourhood: (imagePath: string) => Promise<readonly string[]>;
  readonly readPe: (path: string, operation: string) => Promise<Result<PeHeaderFacts, BeaError>>;
  readonly literals: (perCall: readonly string[]) => Result<SensitiveLiterals, BeaError>;
  readonly noteMachineWide: (labels: readonly string[]) => void;
  readonly machineWideLabels: () => readonly string[];
}

export interface SpawnPreflight {
  readonly program: string;
  readonly cwd: string;
  readonly pe: PeHeaderFacts;
  readonly hash: Promise<{ readonly sha256: string; readonly size: number } | null>;
  readonly antiCheat: AntiCheatVerdict;
  readonly literals: SensitiveLiterals;
  readonly env: TargetEnvironment;
}

/** SEC-1: the refusal names the BEA-authored rule (and location label), never the caller's path. */
const programRefused = (operation: string, refusal: ProgramRefusal): BeaError => ({
  _tag: "AccessDenied",
  operation,
  reason: "policy",
  message:
    refusal.rule === "location"
      ? "spawn_process refuses programs from system, interpreter and toolchain directories: they can run arbitrary commands or act on other processes."
      : "spawn_process refuses script interpreters, shells and system tools that run arbitrary commands or act on other processes.",
  remediation:
    "Spawn the target program itself. Only the user can allow such a program: list its path or sha256 in spawn.allowed_programs (or set spawn.allow_interpreters=true) in BEA_HOME/config.json and restart BEA.",
  diagnostics: { rule: refusal.rule, ...(refusal.rule === "location" ? { location: refusal.location } : {}) },
});

const inputError = (operation: string, path: string, message: string): BeaError => ({
  _tag: "InputError",
  operation,
  issues: [{ path, reason: "invalid_value", message }],
});

/** S3 §8.2: Frida's `started` (µs ISO) → FILETIME 100 ns + its precision; null when absent or unparseable. */
export const isoToFiletime100ns = (
  iso: unknown,
): { readonly value: bigint; readonly precision100ns: bigint } | null => {
  if (typeof iso !== "string") return null;
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:?\d{2})$/u.exec(iso);
  if (m === null) return null;
  const [, y, mo, d, h, mi, s, frac = "", tz = "Z"] = m;
  let ms = Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s));
  if (tz !== "Z") {
    const sign = tz.startsWith("-") ? -1 : 1;
    ms -= sign * (Number(tz.slice(1, 3)) * 60 + Number(tz.slice(-2))) * 60_000;
  }
  const digits = Math.min(frac.length, 7);
  const units = digits === 0 ? 0n : BigInt(frac.slice(0, 7).padEnd(7, "0"));
  return { value: BigInt(ms) * 10_000n + units + 116_444_736_000_000_000n, precision100ns: 10n ** BigInt(7 - digits) };
};

const UNCHECKED_TOLERANCE = (1n << 63n) - 1n;

/** Frida's `started` (µs precision) and the OS creation time agree within the coarser precision. */
const sameCreationTime = (
  started: { readonly value: bigint; readonly precision100ns: bigint },
  creationTime100ns: bigint,
): boolean => {
  const delta = started.value - creationTime100ns;
  return (delta < 0n ? -delta : delta) <= started.precision100ns;
};

/** Preflight runs BEFORE capacity is reserved; nothing exists yet, so nothing needs cleanup. */
export const preflightSpawn = async (
  deps: SpawnDeps,
  input: SpawnInput,
  op: OperationContext,
  internal: boolean,
): Promise<Result<SpawnPreflight, BeaError>> => {
  const operation = op.name;
  if (deps.hostPlatform !== "win32")
    return err({
      _tag: "CapabilityUnavailable",
      operation,
      capability: "platform",
      reason: deps.hostPlatform === "darwin" ? "macos-unsupported" : "linux-spawn-unavailable",
      retryable: false,
      message:
        deps.hostPlatform === "darwin"
          ? "macOS targets are not supported in BEA v0.1."
          : "Owned (spawned) targets need bea-jobhost containment, which this BEA build provides on Windows only; attach to a running process instead.",
    });
  // One canonical spelling for every later use (jobhost --expect-image, the instance id, cwd, record.imagePath):
  // forward slashes and dot segments would otherwise fail the jobhost's ordinal image-path comparison.
  const program = win32.normalize(input.program);
  if (!isDriveAbsoluteWin32(program))
    return err(inputError(operation, "program", "program must be a drive-absolute path such as C:\\Games\\game.exe."));
  if (isBatchScript(program))
    return err(inputError(operation, "program", "Batch scripts (.bat/.cmd) are refused; give the .exe itself."));
  // SEC-2: the working directory is part of the target's DLL search path: a local, existing directory only
  const cwd = input.cwd === undefined ? null : win32.normalize(input.cwd);
  if (cwd !== null) {
    if (!isDriveAbsoluteWin32(cwd) || cwd.includes("\u0000"))
      return err(
        inputError(
          operation,
          "cwd",
          "cwd must be a drive-absolute local directory such as C:\\Games\\MyGame (no UNC, device or relative paths).",
        ),
      );
    const kind = (await deps.inspectDirectory?.(cwd)) ?? "directory";
    if (kind === "network")
      return err({
        _tag: "AccessDenied",
        operation,
        reason: "policy",
        message: "cwd resolves to a network location; the target would load DLLs from it.",
        remediation: "Use a local directory (or omit cwd: the program's own directory).",
        diagnostics: { field: "cwd" },
      });
    if (kind !== "directory") return err(inputError(operation, "cwd", "cwd must be an existing directory."));
  }
  const policed = !internal && !deps.policy.allowInterpreters;
  // review fix LIFE-5: the file the program spelling names (junctions, symlinks, subst and mapped drives resolved);
  // the policy checks both spellings, and the anti-cheat neighbourhood is read around both
  const finalPath = (await deps.realPath?.(program)) ?? program;
  if (isNetworkPath(finalPath))
    return err({
      _tag: "AccessDenied",
      operation,
      reason: "policy",
      message:
        "program resolves to a network location; network paths are not supported (the target would load its DLLs from the share).",
      remediation: "Copy the program to a local drive and spawn it from there.",
      diagnostics: { field: "program" },
    });
  // SEC-1 rules 1+2 (name, location) before anything reads the image; rule 3 (version info) after the PE read below
  const early = policed ? programRefusal(program, finalPath, refusedLocations(deps.serverEnv)) : null;
  if (crtCommandLineLength([program, ...input.argv]) > MAX_COMMAND_LINE)
    return err({
      _tag: "InputError",
      operation,
      issues: [
        {
          path: "args",
          reason: "out_of_range",
          message: "The quoted command line exceeds 32,767 characters.",
          maximum: MAX_COMMAND_LINE,
        },
      ],
    });
  const literals = deps.literals(input.redactLiterals);
  if (!literals.ok) return literals;
  if (early !== null && (deps.policy.allowedPrograms ?? []).length === 0) return err(programRefused(operation, early));
  const pe = await deps.readPe(program, operation);
  if (!pe.ok) return pe;
  const hash = deps.hashFile(program, op.signal);
  const refusal = policed ? (early ?? versionInfoRefusal(pe.value.versionNames)) : null;
  if (
    refusal !== null &&
    !allowedProgram(deps.policy.allowedPrograms ?? [], [program, finalPath], (await hash)?.sha256 ?? null)
  )
    return err(programRefused(operation, refusal));
  if (input.expectSha256 !== undefined) {
    const actual = await hash;
    const expected = input.expectSha256.toLowerCase();
    if (actual === null)
      return err({ _tag: "FileOperationFailed", operation, file_operation: "read", path: program, reason: "io" });
    if (actual.sha256 !== expected)
      return err({
        _tag: "InstanceMismatch",
        operation,
        expected_instance_id: `sha256:${expected}`,
        observed: { pid: 0, start_time: null },
        message: "The program file's sha256 differs from expect_sha256; nothing was spawned.",
        remediation:
          "Check that program is the intended build (for example the one REA or Ghidra analyzed), or omit expect_sha256.",
        diagnostics: { expected_sha256: expected, actual_sha256: actual.sha256 },
      });
  }
  const neighbourhood = [
    ...(await deps.listNeighbourhood(program)),
    ...(finalPath.toLowerCase() === program.toLowerCase() ? [] : await deps.listNeighbourhood(finalPath)),
  ];
  const signals = [...directorySignals(neighbourhood), ...importSignals(pe.value.imports)];
  const needsHash = signals.length > 0 && !deps.policy.allowAntiCheat && deps.policy.allowAntiCheatImages.length > 0;
  const verdict = antiCheatVerdict({
    signals,
    allowGlobal: deps.policy.allowAntiCheat,
    allowedImages: deps.policy.allowAntiCheatImages,
    imageSha256: needsHash ? ((await hash)?.sha256 ?? null) : null,
  });
  if (verdict.kind === "refuse")
    return err({
      _tag: "AccessDenied",
      operation,
      reason: "anti-cheat-detected",
      diagnostics: { signals: [...verdict.signals] },
    });
  const aborted = abortedError(op.signal, operation, { deadline: op.deadline, phase: "preflight" });
  if (aborted !== null) return err(aborted);
  const env = buildTargetEnvironment({
    server: deps.serverEnv,
    caller: input.env ?? {},
    mode: deps.policy.envMode,
    platform: "win32",
  });
  return ok({
    program,
    cwd: cwd ?? program.slice(0, Math.max(program.lastIndexOf("\\"), program.lastIndexOf("/"))),
    pe: pe.value,
    hash,
    antiCheat: verdict,
    literals: literals.value,
    env,
  });
};

const spawnFailure = (operation: string, cause: unknown, program: string): BeaError => {
  const text = cause instanceof Error ? cause.message : String(cause);
  if (/elevation/iu.test(text)) return { _tag: "AccessDenied", operation, reason: "elevation-required" };
  if (/unable to find|not found|cannot find/iu.test(text))
    return { _tag: "FileOperationFailed", operation, file_operation: "stat", path: program, reason: "missing" };
  if (/access is denied|access denied/iu.test(text)) return { _tag: "AccessDenied", operation, reason: "os-denied" };
  return { _tag: "ProviderFailure", operation, provider: "frida", diagnostics: { phase: "spawn" } };
};

/** Owned startup after preflight + reservation. The record starts in `spawning`; on failure it ends `failed`. */
export const runSpawn = async (
  deps: SpawnDeps,
  record: SessionRecord,
  input: SpawnInput,
  pre: SpawnPreflight,
  op: OperationContext,
  clock: StepClock,
  bundle: AgentBundle,
  live: LiveDevice,
): Promise<Result<SessionObservation, BeaError>> => {
  const operation = op.name;
  const device = live.device;
  record.literals = pre.literals;
  record.piped = input.captureOutput;
  record.imagePath = pre.program;
  const fail = async (error: BeaError): Promise<Result<never, BeaError>> => {
    const reason = op.signal.aborted ? "startup-cancelled" : "startup-failed";
    const final = await cleanupStartup(deps, record, error, { device, reason });
    return err(final);
  };

  // step 3: spawn — never cancelled; a guard expiry keeps the promise and kills the pid when it resolves
  const spawnPromise = device.spawn([pre.program, ...input.argv], {
    envp: pre.env.env,
    cwd: pre.cwd,
    stdio: input.captureOutput ? "pipe" : "inherit",
  });
  const spawned = await guard(spawnPromise, deps.limits.startup.spawnGuardMs);
  if (spawned.kind === "timeout") {
    killWhenSpawned(spawnPromise, device, (pid) => deps.logger.info("late spawn killed", { pid }));
    return err({ _tag: "ProviderTimeout", operation, timeout_ms: deps.limits.startup.spawnGuardMs, phase: "spawn" });
  }
  if (spawned.kind === "error")
    return err(withFridaMessage(spawnFailure(operation, spawned.cause, pre.program), spawned.cause, pre.literals));
  const pid = spawned.value;
  record.pid = pid;
  clock.mark("spawn");

  // step 4: output routing (piped)
  if (input.captureOutput) {
    const startedAt = deps.now();
    const output = new BoundedOutputCapture({
      headBytes: deps.limits.capture.stdioHeadBytes,
      tailBytes: deps.limits.capture.stdioTailBytes,
      onChunk: (fd, data) =>
        record.binder.appendHostRows(
          HOST_OUTPUT_STREAM,
          outputRows(fd, data, deps.now() - startedAt, deps.limits.capture.outputChunkBytes),
        ),
    });
    record.output = output;
    const unroute = deps.host.routeOutput(pid, (fd, data) => {
      output.push(fd, data);
      record.hub.notify();
    });
    record.onDisconnect(unroute);
  }
  const abortedAfterSpawn = abortedError(op.signal, operation, { deadline: op.deadline, phase: "spawn" });
  if (abortedAfterSpawn !== null) return fail(abortedAfterSpawn);

  // step 5: adopt — identity (image, parent = this server) refused before assignment. Review fix LIFE-4: adoption
  // comes BEFORE the machine-wide metadata listing (tens of ms): until assignment the suspended child is outside any
  // job, and a server killed in that window leaves it suspended forever with its .exe locked. The creation-time
  // check moved after assignment (step 6); a mismatch terminates the job.
  const adopted = await deps.jobhost.adopt({
    pid,
    creationTime100ns: 0n,
    tolerance100ns: UNCHECKED_TOLERANCE,
    expectImage: pre.program,
    expectParentPid: deps.selfPid,
    ...(input.memLimitBytes === undefined ? {} : { memLimitBytes: input.memLimitBytes }),
    deadline: op.deadline.min(deps.limits.startup.adoptMs),
    signal: op.signal,
  });
  if (!adopted.ok) return fail(adopted.error);
  attachJobHost(record, adopted.value, deps.now);
  record.containment = {
    kind: "win32-job",
    helperPid: adopted.value.helperPid,
    killOnClose: true,
    dieOnUnhandledException: true,
    breakawayAllowed: false,
    memLimitBytes: adopted.value.policy.memLimitBytes,
    wasInJobBeforeAdopt: adopted.value.wasInJob,
    assignedBeforeResume: true,
    crashSafe: true,
  };
  record.transition("adopted", "step:adopt");
  clock.mark("adopt");

  // step 6: Frida metadata `started` (full metadata listing: a pid-filtered query is never used, ext-frida §1.3),
  // cross-checked against the creation time the helper read from the adopted process
  const metadata = await withMetadata(deps, device, pid, op);
  if (!metadata.ok) return fail(metadata.error);
  deps.noteMachineWide(metadata.value.machineWide);
  const started = isoToFiletime100ns(metadata.value.started);
  if (started === null) record.addLimitation(LIMITATIONS.CREATION_TIME_UNCHECKED);
  else if (!sameCreationTime(started, adopted.value.creationTime100ns))
    return fail({
      _tag: "InstanceMismatch",
      operation,
      expected_instance_id: `pid:${String(pid)}`,
      observed: { pid, start_time: adopted.value.creationTime100ns.toString() },
      message: "The adopted process is not the one Frida spawned (creation times differ); it was terminated.",
      remediation: "Retry spawn_process.",
    });
  clock.mark("metadata");

  // step 7: attach
  const session = await attachDevice(deps, device, pid, op, pre.literals);
  if (!session.ok) return fail(session.error);
  clock.mark("attach");

  const startTime = { source: "os-creation-time" as const, value: adopted.value.creationTime100ns.toString() };
  const instanceGuess = expectedInstanceId({ pid, startTime, mainModulePath: pre.program, platform: "win32" });
  const connected = await connectAgent(deps, record, session.value, bundle, op, clock, instanceGuess);
  if (!connected.ok) return fail(connected.error);
  const { ready, hello } = connected.value;

  // step 13: identity (join the image hash started at preflight)
  if (!samePath(hello.process.main_module.path, pre.program)) record.addLimitation(LIMITATIONS.MAIN_PATH_DIFFERS);
  const hash = await pre.hash;
  if (hash === null) record.addLimitation(LIMITATIONS.IMAGE_HASH_UNAVAILABLE);
  record.identity = {
    deviceId: "local",
    pid,
    startTime,
    image: {
      path: pre.program,
      sha256: hash?.sha256 ?? null,
      size: hash?.size ?? pre.pe.fileSize,
      machine: "x64",
      peTimestamp: pre.pe.timeDateStamp,
      preferredBase: pre.pe.imageBase,
    },
    parentPid: deps.selfPid,
    osSessionId: null,
    integrity: "unknown",
    launchedByBea: true,
  };
  clock.mark("verify-identity");
  const abortedAfterAgent = abortedError(op.signal, operation, { deadline: op.deadline, phase: "verify-identity" });
  if (abortedAfterAgent !== null) return fail(abortedAfterAgent);

  const limitations = spawnLimitations(record, pre, input, deps.machineWideLabels());
  const agentIdentity = agentIdentityOf(bundle, deps.beaVersion);
  const containment = containmentJson(record);
  const registered = await registerInstance(deps, record, op, {
    device_id: "local",
    pid,
    ownership: "owned",
    start_time: startTime,
    main_module_path: pre.program,
    agent: agentIdentity,
    environment: { platform: "win32", os_version: live.system.version, arch: "x64", pointer_size: 8 },
    launch: {
      via: "frida-spawn+adopt",
      argv_count: input.argv.length,
      program_basename: basename(pre.program),
      env_keys_count: pre.env.callerKeys,
      env_keys_sha256: envKeysDigest(Object.keys(input.env ?? {})),
    },
    ...(containment === undefined ? {} : { containment }),
    limitations,
    literals: pre.literals,
  });
  if (!registered.ok) return fail(registered.error);
  record.instanceId = registered.value.instanceId;
  record.moduleMapId = registered.value.moduleMapId;
  const builtins = await bindBuiltins(deps, record, hello, registered.value.instanceId);
  if (!builtins.ok) return fail(builtins.error);

  // step 14: promote (paused until resume_process)
  deps.sink.bindSession({
    sessionId: record.id,
    instanceId: registered.value.instanceId,
    ownership: "owned",
    literals: pre.literals,
    agent: agentIdentity,
  });
  record.agentFacts = readyFacts(ready, hello, bundle);
  record.visible = true;
  record.transition("paused", "step:promote");
  const at = { monoNs: deps.monoNs().toString(), wall: deps.wallIso() };
  deps.sink.targetEffect({
    sessionId: record.id,
    kind: "process-spawned",
    facts: { operation, suspended: true, argv_count: input.argv.length },
    at,
  });
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
    ownership: "owned",
    state: "paused",
    identity: record.identity,
    containment: record.containment as NonNullable<typeof record.containment>,
    agent: record.agentFacts,
    output: { captured: input.captureOutput, mode: input.captureOutput ? "frida-pipe" : "not-captured" },
    builtinRecordings: builtins.value,
    antiCheatSignals: pre.antiCheat.kind === "allowed" ? pre.antiCheat.signals : [],
    environment: {
      mode: pre.env.mode,
      allowlistVersion: pre.env.allowlistVersion,
      droppedKeys: pre.env.droppedKeys + pre.env.callerDropped,
      callerKeys: pre.env.callerKeys,
    },
    startup: { steps: clock.steps, totalMs: clock.totalMs },
    limitations: [...limitations, ...record.limitations.filter((l) => !limitations.includes(l))],
  };
  return ok(record.observation);
};

/** Fixed spawn limitations (DESIGN §6.2 #3) plus the per-target ones. */
const spawnLimitations = (
  record: SessionRecord,
  pre: SpawnPreflight,
  input: SpawnInput,
  machineWide: readonly string[],
): string[] => {
  const out: string[] = [LIMITATIONS.AGENT_FOOTPRINT, LIMITATIONS.ARGV_ENV_COUNTS];
  out.push(input.captureOutput ? LIMITATIONS.STDIN_EMPTY_PIPE : LIMITATIONS.OUTPUT_NOT_CAPTURED);
  out.push(pre.env.mode === "inherit" ? LIMITATIONS.ENV_INHERITED : LIMITATIONS.ENV_ALLOWLIST(pre.env.droppedKeys));
  if (pre.antiCheat.kind === "allowed") out.push(LIMITATIONS.ANTI_CHEAT_ALLOWED);
  else if (machineWide.length > 0) out.push(LIMITATIONS.ANTI_CHEAT_GLOBAL_PRESENT);
  for (const sentence of record.limitations) if (!out.includes(sentence)) out.push(sentence);
  return out;
};

const samePath = (a: string, b: string): boolean =>
  a.replaceAll("/", "\\").toLowerCase() === b.replaceAll("/", "\\").toLowerCase();

/** Output rows of the `output` recording: [t_ms, fd, text, invalid_utf8], text ≤ chunk bytes each. */
const outputRows = (fd: 1 | 2, data: Buffer, tMs: number, chunkBytes: number): unknown[][] => {
  const rows: unknown[][] = [];
  for (let offset = 0; offset < data.length; offset += chunkBytes) {
    const chunk = data.subarray(offset, offset + chunkBytes);
    const text = chunk.toString("utf8");
    rows.push([Math.max(0, Math.round(tMs)), fd, text, Buffer.from(text, "utf8").equals(chunk) ? 0 : 1]);
  }
  return rows;
};

type Guarded<T> =
  | { readonly kind: "value"; readonly value: T }
  | { readonly kind: "error"; readonly cause: unknown }
  | { readonly kind: "timeout" };

/** Await an uncancellable native call under a guard timer (S3 §16 rule 3). */
export const guard = <T>(work: Promise<T>, ms: number): Promise<Guarded<T>> =>
  new Promise((resolve) => {
    const timer = setTimeout(() => resolve({ kind: "timeout" }), ms);
    timer.unref?.();
    work.then(
      (value) => {
        clearTimeout(timer);
        resolve({ kind: "value", value });
      },
      (cause: unknown) => {
        clearTimeout(timer);
        resolve({ kind: "error", cause });
      },
    );
  });

interface MetadataFacts {
  readonly started: unknown;
  readonly machineWide: readonly string[];
}

const withMetadata = async (
  deps: SpawnDeps,
  device: FridaDeviceLike,
  pid: number,
  op: OperationContext,
): Promise<Result<MetadataFacts, BeaError>> => {
  const cancel = createNativeCancel(deps.createCancellable(), {
    deadline: op.deadline.min(deps.limits.startup.metadataMs),
    signal: op.signal,
  });
  try {
    const listed = await fridaStep(
      () => device.enumerateProcesses({ scope: "metadata" }, cancel.token),
      deps,
      op,
      "metadata",
      { cancel, ms: deps.limits.startup.metadataMs },
    );
    if (!listed.ok) return listed;
    return ok({
      started: listed.value.find((p) => p.pid === pid)?.parameters["started"],
      machineWide: machineWideAntiCheat(listed.value.map((p) => p.name)),
    });
  } finally {
    cancel.dispose();
  }
};

const attachDevice = async (
  deps: SpawnDeps,
  device: FridaDeviceLike,
  pid: number,
  op: OperationContext,
  literals: SensitiveLiterals | null,
): Promise<Result<FridaSessionLike, BeaError>> => {
  const cancel = createNativeCancel(deps.createCancellable(), {
    deadline: op.deadline.min(deps.limits.startup.attachMs),
    signal: op.signal,
  });
  let cause: unknown;
  try {
    // LIFE-3: the injection that extracts Frida's agent runs with TEMP at BEA's own (swept) directory
    const result = await withTempDir(deps.fridaTempDir?.() ?? null, () =>
      fridaStep(
        () =>
          device.attach(pid, cancel.token).catch((rejection: unknown) => {
            cause = rejection;
            throw rejection;
          }),
        deps,
        op,
        "attach",
        { cancel, ms: deps.limits.startup.attachMs },
      ),
    );
    // BEA-FEEDBACK 1c: keep Frida's own rejection text (host-side step only; agent text never enters diagnostics)
    return result.ok || cause === undefined ? result : err(withFridaMessage(result.error, cause, literals));
  } finally {
    cancel.dispose();
  }
};

/** Subscribe the record to its jobhost (root exit, process tree, helper loss) and reconcile missed facts. */
const attachJobHost = (record: SessionRecord, jobHost: JobHostPort, now: () => number): void => {
  record.jobHost = jobHost;
  const off = jobHost.on((event) => {
    switch (event.event) {
      case "root-exit":
        record.onRootExit(
          {
            code: event.code,
            codeHex: event.codeHex,
            byKill: event.byKill,
            activeAfterRoot: event.activeAfterRoot,
            at: now(),
          },
          "jobhost",
        );
        return;
      case "proc-start":
        record.onTreeEvent({ kind: "proc-start", pid: event.pid, abnormal: null });
        return;
      case "proc-exit":
        record.onTreeEvent({ kind: "proc-exit", pid: event.pid, abnormal: event.abnormal });
        return;
      case "settled":
        record.tree.settled = true;
        record.tree.active = event.active;
        record.hub.notify();
        return;
      case "status":
        record.tree.active = event.active;
        return;
      default:
        return;
    }
  });
  record.onDisconnect(off);
  if (jobHost.rootExit !== null) record.onRootExit(jobHost.rootExit, "jobhost");
  void jobHost.settled.then(() => {
    if (jobHost.state === "helper-lost" && !record.killRequested) record.onHelperLost();
  });
};
