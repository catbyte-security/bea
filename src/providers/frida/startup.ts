import { createHash } from "node:crypto";

import { ATTACH_TIMEOUT_MS } from "../../domain/config.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import type { AgentIdentity } from "../../domain/evidence/record.js";
import type { MmId, PiId, StId } from "../../domain/ids.js";
import type { JsonObject } from "../../domain/json.js";
import type { Logger } from "../../domain/logger.js";
import { instanceIdOf, pathDigest } from "../../domain/process/instance.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { SessionEvidenceSink } from "../../application/sessions/SessionEvidenceSink.js";
import type { EvidenceRuntime, InstanceObservation, StreamSpec } from "../../ports/evidence.js";
import type { RecordingKind, RecordingRegistry } from "../../ports/recordings.js";
import type { DetachReason, OperationContext, StartupStep } from "../../ports/sessions.js";
import {
  AGENT_PROTOCOL,
  type CrashPolicy,
  type HelloParams,
  type HelloResult,
  type ListModulesResult,
  type ReadyMessage,
} from "../../shared/agentProtocol.js";
import { abortedError } from "./aborts.js";
import { AgentChannel } from "./AgentChannel.js";
import type { AgentBundle } from "./agentBundle.js";
import { AgentRpcClient } from "./AgentRpcClient.js";
import type { FridaHost } from "./FridaHost.js";
import type { FridaSessionLike } from "./fridaPorts.js";
import type { HostLimits } from "./hostLimits.js";
import type { NativeCancel } from "./NativeCancel.js";
import { HOST_OUTPUT_STREAM, type BuiltinKind, type SessionRecord } from "./SessionRecord.js";

/**
 * The startup steps spawn (Path 1) and attach share (S3 §8.1 steps 8–14, §9 steps 7–13; DESIGN §5.1): subscribe to
 * detach and reconcile, createScript with logHandler and message handler connected in the same tick, load, the ready
 * handshake, hello (host-computed gates, clamped limits with max_instruments 16, crash policy, flush 50 ms, flow
 * 32/8 MiB), listModules seeding the module map, instance registration, and the built-in recordings bound to the
 * agent's system streams. Every await is followed by an abort checkpoint; the caller owns cleanup.
 */
export interface StartupContext {
  readonly host: FridaHost;
  readonly evidence: EvidenceRuntime;
  readonly recordings: RecordingRegistry;
  readonly sink: SessionEvidenceSink;
  readonly limits: HostLimits;
  readonly logger: Logger;
  readonly now: () => number;
  readonly monoNs: () => bigint;
  readonly wallIso: () => string;
  readonly beaVersion: string;
  readonly platform: "win32" | "linux";
  readonly gates: { readonly writeMemory: boolean; readonly overrideFunction: boolean; readonly callAttached: boolean };
}

export class StepClock {
  readonly steps: { step: StartupStep; ms: number }[] = [];
  readonly #now: () => number;
  readonly #started: number;
  #last: number;

  constructor(now: () => number) {
    this.#now = now;
    this.#started = now();
    this.#last = this.#started;
  }

  mark(step: StartupStep): void {
    const now = this.#now();
    this.steps.push({ step, ms: Math.round(now - this.#last) });
    this.#last = now;
  }

  get totalMs(): number {
    return Math.round(this.#now() - this.#started);
  }
}

/**
 * "system" is not a crash class (review fix AGENT-11): Frida maps every code it does not know to "system", which
 * includes C++ throws, OutputDebugString and thread naming. Those stay first-chance rows; an unhandled one is still
 * reported at last chance with its NTSTATUS. The hello's policy replaces the agent's default
 * (src/agent/pure/coreCrash.ts), so it must match it. first_chance_blocking is opt-in (BEA-FEEDBACK #4): a blocking
 * report runs on the faulting thread, which may hold the target's own locks (ASan's allocator, JITs, drivers).
 */
const DEFAULT_CRASH_POLICY: CrashPolicy = {
  first_chance_rows: true,
  first_chance_blocking: false,
  crash_class: ["access-violation", "illegal-instruction", "stack-overflow", "arithmetic", "abort"],
  ack_timeout_ms: 1000,
  last_chance_ack_timeout_ms: 2000,
  max_blocking_per_10s: 8,
  rows_per_sec: 1000,
  stack_bytes: 256,
  backtrace_depth: 32,
  include_xmm: false,
  passthrough_modules: [],
};

/** The hello's crash policy: the defaults plus the configured part (config crash.*, BEA_CRASH_FIRST_CHANCE_BLOCKING). */
export const helloCrashPolicy = (crash: HostLimits["crash"]): CrashPolicy => ({
  ...DEFAULT_CRASH_POLICY,
  crash_class: [...DEFAULT_CRASH_POLICY.crash_class],
  first_chance_blocking: crash.firstChanceBlocking,
  passthrough_modules: [...crash.passthroughModules],
});

/**
 * A Frida attach (the injection) that ran out of its deadline names the setting that bounds it (BEA-FEEDBACK #3): a
 * large or busy target may need longer, while a wedged one (a deadlocked process) does not attach with any deadline.
 */
const attachTimeout = (operation: string, ms: number): BeaError => ({
  _tag: "ProviderTimeout",
  operation,
  timeout_ms: ms,
  phase: "attach",
  message: `${operation} did not finish within ${String(ms)} ms (phase attach; limits.attach_timeout_ms / BEA_ATTACH_TIMEOUT_MS).`,
  remediation: `Frida's attach (the agent injection) is bounded by limits.attach_timeout_ms in BEA_HOME/config.json or the BEA_ATTACH_TIMEOUT_MS environment variable (${String(ATTACH_TIMEOUT_MS.min)}-${String(ATTACH_TIMEOUT_MS.max)} ms; now ${String(ms)} ms); restart BEA with a larger value for a large or busy target. A target that is deadlocked or suspended does not attach with a longer deadline either: check that it still makes progress.`,
  diagnostics: { setting: "limits.attach_timeout_ms", env: "BEA_ATTACH_TIMEOUT_MS" },
});

/**
 * Bounded step: resolves the work, or a provider_timeout when `ms` passes first, or the op's abort. With
 * `abortable: false` (review fix LIFE-1) the step is a non-cancellable section like device.spawn: only `ms` bounds it
 * (not the op's deadline or abort), and the caller checks the abort once it settled.
 */
const withStepDeadline = async <T>(
  work: Promise<T>,
  ms: number,
  op: OperationContext,
  phase: string,
  options: { readonly abortable: boolean } = { abortable: true },
): Promise<Result<T, BeaError>> => {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let onAbort: (() => void) | undefined;
  try {
    return await Promise.race([
      work.then((value) => ok(value) as Result<T, BeaError>),
      new Promise<Result<T, BeaError>>((resolve) => {
        timer = setTimeout(
          () => resolve(err({ _tag: "ProviderTimeout", operation: op.name, timeout_ms: ms, phase })),
          Math.max(0, options.abortable ? Math.min(ms, op.deadline.remaining()) : ms),
        );
        timer.unref?.();
        if (!options.abortable) return;
        onAbort = () => resolve(err(abortedError(op.signal, op.name, { deadline: op.deadline, phase }) as BeaError));
        if (op.signal.aborted) onAbort();
        else op.signal.addEventListener("abort", onAbort, { once: true });
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    if (onAbort !== undefined) op.signal.removeEventListener("abort", onAbort);
  }
};

const fridaStepError = (operation: string, phase: string, cause: unknown): BeaError => {
  const text = cause instanceof Error ? cause.message : String(cause);
  if (/access.?denied|0x5\b|Access is denied/iu.test(text))
    return { _tag: "AccessDenied", operation, reason: "os-denied", diagnostics: { phase } };
  if (/unable to find process|process not found|no such process/iu.test(text))
    return {
      _tag: "TargetExited",
      operation,
      instance_id: "",
      exit: { code: null, code_hex: null, kind: "unknown", name: null },
      detach_reason: null,
    };
  return { _tag: "ProviderFailure", operation, provider: "frida", diagnostics: { phase } };
};

/**
 * Wraps a Frida promise: rejection → curated BeaError (Frida text is logged at debug level only). A rejection caused
 * by the step's own NativeCancel deadline is a provider_timeout of that step (review fix LIFE-1), not a failure.
 */
export const fridaStep = async <T>(
  work: () => Promise<T>,
  ctx: Pick<StartupContext, "logger">,
  op: OperationContext,
  phase: string,
  deadline?: { readonly cancel: NativeCancel; readonly ms: number },
): Promise<Result<T, BeaError>> => {
  try {
    return ok(await work());
  } catch (cause) {
    ctx.logger.debug("frida step failed", {
      phase,
      text: (cause instanceof Error ? cause.message : String(cause)).slice(0, 512),
    });
    const aborted = abortedError(op.signal, op.name, { deadline: op.deadline, phase });
    if (aborted !== null) return err(aborted);
    if (deadline?.cancel.outcome() === "deadline")
      return err(
        phase === "attach"
          ? attachTimeout(op.name, deadline.ms)
          : { _tag: "ProviderTimeout", operation: op.name, timeout_ms: deadline.ms, phase },
      );
    return err(fridaStepError(op.name, phase, cause));
  }
};

export interface AgentConnection {
  readonly ready: ReadyMessage;
  readonly hello: HelloResult;
}

/**
 * Subscribe → createScript → handlers (same tick) → load → ready → hello. On failure the caller cleans up
 * (owned: kill; attached: unload/detach, never kill).
 */
export const connectAgent = async (
  ctx: StartupContext,
  record: SessionRecord,
  session: FridaSessionLike,
  bundle: AgentBundle,
  op: OperationContext,
  clock: StepClock,
  expectedInstanceId: PiId,
): Promise<Result<AgentConnection, BeaError>> => {
  const pid = record.pid ?? 0;
  record.fridaSession = session;
  const onDetached = (reason: DetachReason): void =>
    record.onDetached(reason, record.closing !== null || record.killRequested);
  session.detached.connect(onDetached);
  record.onDisconnect(() => session.detached.disconnect(onDetached));
  if (session.isDetached()) record.onDetached("unknown-before-subscribe", false);
  record.transition("attached", "step:subscribe");
  clock.mark("subscribe");

  // Review fix LIFE-1: create-script → load is a non-cancellable section. Frida 17.23.2 strands frida-agent.dll in the
  // target when the session is detached while createScript is in flight, so an abort is checked only once the step
  // settled (the cleanup then unloads the script before it detaches). A step past its own timeout keeps its promise
  // on the record: the cleanup waits for it before detaching.
  const pendingScript = session.createScript(bundle.source, { name: "bea-agent", runtime: "qjs" });
  record.pendingStartup = pendingScript;
  const created = await withStepDeadline(
    fridaStep(() => pendingScript, ctx, op, "create-script"),
    ctx.limits.startup.createScriptMs,
    op,
    "create-script",
    { abortable: false },
  );
  if (!created.ok) {
    record.pendingScript = pendingScript;
    return created;
  }
  record.pendingStartup = null;
  if (!created.value.ok) return created.value;
  const script = created.value.value;
  // Same synchronous block as the resolution (S3 §8.1 step 9): the default logHandler prints to stdout.
  const channel = new AgentChannel({
    operation: op.name,
    expected: { pid, buildId: bundle.buildId },
    binder: record.binder,
    jobs: record.jobs,
    crash: record.crash,
    onInstrument: (message) => record.onInstrument(message),
    onFault: (fault) => ctx.sink.agentFault({ sessionId: record.id, fault }),
    onNotice: (notice) => ctx.logger.debug("agent notice", { session: record.id, code: notice.code }),
    logger: ctx.logger,
    now: ctx.now,
    wallIso: ctx.wallIso,
    monoNs: ctx.monoNs,
    limits: ctx.limits.capture,
  });
  script.logHandler = channel.onLog;
  script.message.connect(channel.onMessage);
  script.destroyed.connect(channel.onDestroyed);
  record.script = script;
  record.channel = channel;
  record.onDisconnect(() => {
    script.message.disconnect(channel.onMessage);
    script.destroyed.disconnect(channel.onDestroyed);
    script.logHandler = () => undefined;
  });
  record.rpc = new AgentRpcClient({
    script,
    createCancellable: () => {
      const mod = ctx.host.module;
      if (mod === null) throw new Error("frida binding not loaded");
      return mod.createCancellable();
    },
    defaultTimeoutMs: ctx.limits.rpcDefaultTimeoutMs,
    pingTimeoutMs: ctx.limits.health.pingTimeoutMs,
    pingIntervalMs: ctx.limits.health.pingIntervalMs,
    instanceId: () => record.instanceId ?? "",
    terminal: () => record.terminalView(),
    logger: ctx.logger,
    now: ctx.now,
  });
  record.transition("agent_loading", "step:create-script");
  clock.mark("create-script");
  const abortedAfterCreate = abortedError(op.signal, op.name, { deadline: op.deadline, phase: "create-script" });
  if (abortedAfterCreate !== null) return err(abortedAfterCreate);

  const pendingLoad = script.load();
  record.pendingStartup = pendingLoad;
  const loaded = await withStepDeadline(
    fridaStep(() => pendingLoad, ctx, op, "load"),
    ctx.limits.startup.loadMs,
    op,
    "load",
    { abortable: false },
  );
  if (loaded.ok) record.pendingStartup = null;
  if (!loaded.ok) return loaded;
  if (!loaded.value.ok) return loaded.value;
  clock.mark("load");
  const abortedAfterLoad = abortedError(op.signal, op.name, { deadline: op.deadline, phase: "load" });
  if (abortedAfterLoad !== null) return err(abortedAfterLoad);

  const readyTimer = setTimeout(
    () =>
      channel.failReady({
        _tag: "ProviderTimeout",
        operation: op.name,
        timeout_ms: ctx.limits.startup.readyMs,
        phase: "agent-ready",
      }),
    ctx.limits.startup.readyMs,
  );
  readyTimer.unref?.();
  const onAbort = (): void =>
    channel.failReady(abortedError(op.signal, op.name, { deadline: op.deadline, phase: "agent-ready" }) as BeaError);
  op.signal.addEventListener("abort", onAbort, { once: true });
  if (op.signal.aborted) onAbort();
  const ready = await channel.ready;
  clearTimeout(readyTimer);
  op.signal.removeEventListener("abort", onAbort);
  if (!ready.ok) return ready;
  record.transition("agent_ready", "step:ready");
  clock.mark("ready");

  const hello = await record.rpc.call("hello", helloParams(ctx, record, expectedInstanceId), {
    op,
    timeoutMs: ctx.limits.startup.helloMs,
  });
  if (!hello.ok) return hello;
  if (hello.value.protocol !== AGENT_PROTOCOL)
    return err({
      _tag: "CapabilityUnavailable",
      operation: op.name,
      capability: "agent",
      reason: "protocol-mismatch",
      retryable: false,
    });
  clock.mark("hello");
  return ok({ ready: ready.value, hello: hello.value });
};

const helloParams = (ctx: StartupContext, record: SessionRecord, instanceId: PiId): HelloParams => ({
  protocol: AGENT_PROTOCOL,
  min_minor: 0,
  host: { name: "bea", version: ctx.beaVersion },
  session: { session_id: record.id, instance_id: instanceId, owned: record.ownership === "owned" },
  gates: {
    write_memory: ctx.gates.writeMemory,
    override_function: ctx.gates.overrideFunction,
    call_function: record.ownership === "owned" || ctx.gates.callAttached,
  },
  limits: {
    max_instruments: ctx.limits.maxInstrumentsPerSession,
    flush_ms: ctx.limits.hello.flushMs,
    flow_high_water_bytes: ctx.limits.hello.highWaterBytes,
    flow_low_water_bytes: ctx.limits.hello.lowWaterBytes,
  },
  crash: helloCrashPolicy(ctx.limits.crash),
  streams: { flush_ms: ctx.limits.hello.flushMs, exceptions: true, threads: true },
  flow: { high_water_bytes: ctx.limits.hello.highWaterBytes, low_water_bytes: ctx.limits.hello.lowWaterBytes },
});

/** The instance id register() will compute (S2 §4.1), known before registration so hello can carry it. */
export const expectedInstanceId = (input: {
  readonly pid: number;
  readonly startTime: {
    readonly source: "os-creation-time" | "frida-started" | "first-observed";
    readonly value: string;
  };
  readonly mainModulePath: string;
  readonly platform: "win32" | "linux";
}): PiId =>
  instanceIdOf({
    t: "bea.pi/1",
    device_id: "local",
    pid: input.pid,
    start_time: { source: input.startTime.source, value: input.startTime.value },
    image_path_sha256: pathDigest(input.mainModulePath, input.platform),
  });

export interface RegisteredInstance {
  readonly instanceId: PiId;
  readonly moduleMapId: MmId;
  readonly epoch: number;
  readonly modules: ListModulesResult;
}

/** listModules → InstanceRegistry.register (bea.process.instance) → module map recorded. */
export const listModulesOf = async (
  record: SessionRecord,
  op: OperationContext,
): Promise<Result<ListModulesResult, BeaError>> => {
  const rpc = record.rpc;
  if (rpc === null) return err({ _tag: "Internal", operation: op.name });
  return rpc.call("listModules", { with_pe: false }, { op });
};

export const registerInstance = async (
  ctx: StartupContext,
  record: SessionRecord,
  op: OperationContext,
  observation: Omit<InstanceObservation, "initial_modules">,
  prefetched?: ListModulesResult,
): Promise<Result<RegisteredInstance, BeaError>> => {
  let modules = prefetched;
  if (modules === undefined) {
    const listed = await listModulesOf(record, op);
    if (!listed.ok) return listed;
    modules = listed.value;
  }
  const registered = await ctx.evidence.instances.register({
    ...observation,
    initial_modules: {
      epoch: modules.module_map_epoch,
      modules: modules.modules.map((m) => ({ name: m.name, base: m.base, size: m.size, path: m.path })),
    },
  });
  if (!registered.ok) return registered;
  const instanceId = registered.value.instance.instance_id;
  const current = ctx.evidence.modules.current(instanceId);
  if (current === undefined || current.epoch !== modules.module_map_epoch)
    ctx.evidence.modules.apply(instanceId, {
      op: "snapshot",
      epoch: modules.module_map_epoch,
      modules: modules.modules.map((m) => ({ name: m.name, base: m.base, size: m.size, path: m.path })),
    });
  const map = await ctx.evidence.modules.ensureRecorded(instanceId, modules.module_map_epoch, op.name);
  if (!map.ok) return map;
  return ok({ instanceId, moduleMapId: map.value.module_map_id, epoch: modules.module_map_epoch, modules });
};

const recordingFor = (
  ctx: StartupContext,
  record: SessionRecord,
  kind: RecordingKind,
  agentStream: string,
  streamId: StId,
): string =>
  ctx.recordings.create({
    sessionId: record.id,
    kind,
    agentInstrumentId: null,
    agentStream,
    streamId,
    effectId: null,
    durationMs: null,
    maxEvents: null,
    startsAtResume: false,
    decoders: null,
  }).id;

/** Bind s:exceptions, s:modules, s:threads (+ the host output stream) and create the built-in recordings. */
export const bindBuiltins = async (
  ctx: StartupContext,
  record: SessionRecord,
  hello: HelloResult,
  instanceId: PiId,
): Promise<Result<readonly string[], BeaError>> => {
  const literals = record.literals ?? { count: 0, texts: [], spellings: [] };
  const spec = (kind: StreamSpec["source"]["kind"], channel: string, encoding: StreamSpec["encoding"]): StreamSpec => ({
    source: { kind, instance_id: instanceId, effect_id: null, channel },
    encoding,
    decoders: null,
    literals,
  });
  record.systemStreams = hello.system_streams;
  const created: string[] = [];
  const plan: { readonly stream: string | null; readonly builtin: BuiltinKind | null; readonly spec: StreamSpec }[] = [
    {
      stream: hello.system_streams.exceptions,
      builtin: "exceptions",
      spec: spec("exceptions", hello.system_streams.exceptions ?? "", { kind: "json-rows", row_kind: "exception/1" }),
    },
    {
      stream: hello.system_streams.modules,
      builtin: "modules",
      spec: spec("modules", hello.system_streams.modules, { kind: "json-rows", row_kind: "module/1" }),
    },
    {
      stream: hello.system_streams.threads,
      builtin: null,
      spec: spec("threads", hello.system_streams.threads ?? "", { kind: "json-rows", row_kind: "thread/1" }),
    },
    {
      stream: record.piped ? HOST_OUTPUT_STREAM : null,
      builtin: "output",
      spec: spec("stdout", "output", { kind: "ndjson" }),
    },
  ];
  for (const item of plan) {
    if (item.stream === null) continue;
    const bound = await record.binder.bind(item.stream, item.spec);
    if (!bound.ok) return bound;
    if (item.builtin === null) continue;
    const id = recordingFor(ctx, record, item.builtin, item.stream, bound.value.stream_id);
    record.builtins.set(item.builtin, id);
    created.push(id);
  }
  return ok(created);
};

export const agentIdentityOf = (bundle: AgentBundle, beaVersion: string): AgentIdentity => ({
  bundle_sha256: bundle.sha256,
  bea_version: beaVersion,
  runtime: "qjs",
});

/** sha256 of the sorted caller env KEY names (never values), or null without caller keys. */
export const envKeysDigest = (keys: readonly string[]): string | null =>
  keys.length === 0
    ? null
    : createHash("sha256")
        .update([...keys].sort().join("\n"))
        .digest("hex");

export const containmentJson = (record: SessionRecord): JsonObject | undefined => {
  const c = record.containment;
  if (c === null) return undefined;
  return {
    kind: c.kind,
    helper_pid: c.helperPid,
    kill_on_close: c.killOnClose,
    die_on_unhandled_exception: c.dieOnUnhandledException,
    breakaway_allowed: false,
    mem_limit_bytes: c.memLimitBytes,
    was_in_job_before_adopt: c.wasInJobBeforeAdopt,
    assigned_before_resume: c.assignedBeforeResume,
    crash_safe: c.crashSafe,
  };
};

export const readyFacts = (ready: ReadyMessage, hello: HelloResult, bundle: AgentBundle) => ({
  protocol: AGENT_PROTOCOL,
  protocolMinor: hello.protocol_minor,
  agentVersion: hello.agent_version,
  buildId: hello.build_id,
  bundleSha256: bundle.sha256,
  fridaVersion: hello.frida_version,
  runtime: "QJS" as const,
  jsThreadId: ready.js_thread_id,
  features: hello.features,
  limits: hello.limits,
  hello,
});
