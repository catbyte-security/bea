// =================================================================================================
// src/agent/coreRpc.ts — WP3-AGENT boot sequence and the core RPCs (S4 §3.2, §4.3, §18; DESIGN §5.3).
// The frozen index.ts calls `init(core)` first: it runs the boot order — platform check → core CModule (fatal on
// failure) → THE exception dispatcher (first, once) → last-chance/exit hooks → events (system streams, receivers,
// flush timer) → module observer — then feature inits follow in index.ts. RPCs: hello (config clamped to the hard caps,
// gates, crash policy, system streams, deny/caution lists), ping, status, flush, shutdown (attached targets: stop every
// instrument newest first with full revert, bounded by timeout_ms) and fingerprint.
// =================================================================================================
import {
  AGENT_PROTOCOL,
  AGENT_PROTOCOL_MINOR,
  type AgentResult,
  type AgentRpcImpl,
  type AgentStatus,
  type CrashPolicy,
  type ExceptionType,
  type FlushParams,
  type HelloParams,
  type HelloResult,
  type Hex,
  type InstrumentSummary,
  type ShutdownParams,
  type ShutdownResult,
  type StatusParams,
} from "../shared/agentProtocol.js";
import { AGENT_LIMIT_HARD, clampAgentLimits } from "../shared/agentLimits.js";
import { HOOK_CAUTION_LIST, HOOK_DENY_LIST } from "../shared/apiProfiles.js";
import { AGENT_BUILD_ID, AGENT_VERSION } from "./buildInfo.js";
import { hex } from "./encode.js";
import { env } from "./env.js";
import { badParam, fail, ok, raise } from "./errors.js";
import { fingerprint } from "./fingerprint.js";
import { processInfo } from "./inspect.js";
import { DEFAULT_CRASH_POLICY, type AgentCore } from "./state.js";

const EXCEPTION_TYPES: readonly ExceptionType[] = [
  "abort",
  "access-violation",
  "guard-page",
  "illegal-instruction",
  "stack-overflow",
  "arithmetic",
  "breakpoint",
  "single-step",
  "system",
];

/** Boot (index.ts step "core.init"): every step records its stage so a failure reports it in {bea:"fatal"}. */
export function init(c: AgentCore): void {
  c.bootStage = "platform";
  if (!env.isWindowsX64())
    raise({
      _tag: "Unsupported",
      message: "unsupported target",
      feature: "target",
      reason: "x64 Windows only in v0.1",
    });
  c.bootStage = "cmodule";
  c.native.init();
  c.bootStage = "exception-handler";
  c.exceptions.install();
  c.bootStage = "core-hooks";
  c.exceptions.installCoreHooks();
  c.bootStage = "events";
  c.events.init();
  c.bootStage = "modules";
  c.modules.start();
  c.bootStage = "features";
  c.bootT = c.native.nowUs();
  bound = c;
}

let bound: AgentCore | null = null;
const core = (): AgentCore => {
  if (bound === null) throw new Error("core.init() has not run");
  return bound;
};

const clampInt = (v: unknown, lo: number, hi: number, fallback: number): number =>
  typeof v === "number" && Number.isFinite(v) ? Math.max(lo, Math.min(Math.floor(v), hi)) : fallback;

/** Host crash policy clamped to the documented maxima (CrashPolicy comments). */
export const clampCrashPolicy = (p: Partial<CrashPolicy> | undefined): CrashPolicy => {
  const d = DEFAULT_CRASH_POLICY;
  const classes = Array.isArray(p?.crash_class)
    ? p.crash_class.filter((t) => EXCEPTION_TYPES.includes(t))
    : d.crash_class;
  return {
    first_chance_rows: typeof p?.first_chance_rows === "boolean" ? p.first_chance_rows : d.first_chance_rows,
    first_chance_blocking:
      typeof p?.first_chance_blocking === "boolean" ? p.first_chance_blocking : d.first_chance_blocking,
    crash_class: [...classes],
    ack_timeout_ms: clampInt(p?.ack_timeout_ms, 0, 5000, d.ack_timeout_ms),
    last_chance_ack_timeout_ms: clampInt(p?.last_chance_ack_timeout_ms, 0, 5000, d.last_chance_ack_timeout_ms),
    max_blocking_per_10s: clampInt(p?.max_blocking_per_10s, 0, 64, d.max_blocking_per_10s),
    rows_per_sec: clampInt(p?.rows_per_sec, 1, 100_000, d.rows_per_sec),
    stack_bytes: clampInt(p?.stack_bytes, 0, 4096, d.stack_bytes),
    backtrace_depth: clampInt(p?.backtrace_depth, 0, 64, d.backtrace_depth),
    include_xmm: typeof p?.include_xmm === "boolean" ? p.include_xmm : d.include_xmm,
  };
};

/** "module!export" lists resolved to VAs (modules not loaded are skipped). */
const resolveApiList = (names: readonly string[]): { api: string; va: Hex }[] => {
  const out: { api: string; va: Hex }[] = [];
  for (const api of names) {
    const [module, name] = api.split("!");
    if (module === undefined || name === undefined) continue;
    const va = Process.findModuleByName(module)?.findExportByName(name) ?? null;
    if (va !== null) out.push({ api, va: hex(va) });
  }
  return out;
};

/** Apply the session configuration of hello (limits, gates, crash policy, streams, flow) to the core. */
const applyHelloConfig = (c: AgentCore, p: HelloParams): void => {
  c.limits = clampAgentLimits(p.limits);
  c.gates = {
    write_memory: p.gates?.write_memory === true,
    override_function: p.gates?.override_function === true,
    call_function: p.gates?.call_function === true,
  };
  c.config.session = p.session ?? null;
  c.config.crash = clampCrashPolicy(p.crash);
  c.config.streams = {
    flush_ms: clampInt(p.streams?.flush_ms, 1, AGENT_LIMIT_HARD.flush_ms, c.limits.flush_ms),
    exceptions: p.streams?.exceptions !== false,
    threads: p.streams?.threads === true,
  };
  const high = clampInt(
    p.flow?.high_water_bytes,
    1,
    AGENT_LIMIT_HARD.flow_high_water_bytes,
    c.limits.flow_high_water_bytes,
  );
  c.config.flow = {
    high_water_bytes: high,
    low_water_bytes: Math.min(
      clampInt(p.flow?.low_water_bytes, 1, Math.floor(high / 2), c.limits.flow_low_water_bytes),
      Math.floor(high / 2),
    ),
  };
  c.streams.configureFlow(c.config.flow.high_water_bytes, c.config.flow.low_water_bytes);
  c.events.setFlushInterval(c.config.streams.flush_ms);
  c.exceptions.configure();
  if (!c.config.streams.exceptions || !c.config.crash.first_chance_rows) c.events.disableExceptions();
  if (c.config.streams.threads) {
    c.events.enableThreads();
    c.threads.enableRows();
  }
};

const hello = (p: HelloParams) => {
  const c = core();
  if (p === null || typeof p !== "object") return fail(badParam("params", "hello parameters required"));
  if (p.protocol !== AGENT_PROTOCOL || typeof p.min_minor !== "number" || p.min_minor > AGENT_PROTOCOL_MINOR)
    return fail({
      _tag: "ProtocolMismatch",
      message: "agent/host protocol mismatch",
      expected: `${AGENT_PROTOCOL}.${String(p.min_minor)}`,
      got: `${AGENT_PROTOCOL}.${AGENT_PROTOCOL_MINOR}`,
      agent_minor: AGENT_PROTOCOL_MINOR,
    });
  applyHelloConfig(c, p);
  const early = (c.systemStreams.modules?.recorded ?? 0) + (c.systemStreams.exceptions?.recorded ?? 0);
  c.phase = "ready";
  c.helloDone = true;
  const result: HelloResult = {
    protocol: AGENT_PROTOCOL,
    protocol_minor: AGENT_PROTOCOL_MINOR,
    agent_version: AGENT_VERSION,
    build_id: AGENT_BUILD_ID,
    frida_version: Frida.version,
    runtime: Script.runtime === "V8" ? "V8" : "QJS",
    process: processInfo(c),
    limits: { ...c.limits },
    features: [...c.features],
    deny_list: resolveApiList(HOOK_DENY_LIST.map((d) => d.api)).map((r) => ({
      ...r,
      reason: HOOK_DENY_LIST.find((d) => d.api === r.api)?.reason ?? "deadlock-risk",
    })),
    caution_list: resolveApiList(HOOK_CAUTION_LIST),
    system_streams: {
      exceptions: c.systemStreams.exceptions?.id ?? null,
      modules: c.systemStreams.modules?.id ?? "s:modules",
      threads: c.systemStreams.threads?.id ?? null,
    },
    module_map_epoch: c.modules.epoch,
    boot: { t_us: c.bootT, early_rows: early },
  };
  return ok(result);
};

const status = (p: StatusParams) => {
  const c = core();
  const full = p?.detail === "full";
  const streams = c.streams.list().filter((s) => full || s.state !== "closed");
  const memory: AgentStatus["memory"] = {
    frida_heap_bytes: env.heapBytes(),
    native_bytes: 0,
    scan_bytes: c.scanRegistry?.memoryBytes() ?? 0,
    ring_bytes: 0,
  };
  for (const contribute of c.hooks.memory) {
    const m = contribute();
    memory.native_bytes += m.native_bytes ?? 0;
    memory.scan_bytes += m.scan_bytes ?? 0;
    memory.ring_bytes += m.ring_bytes ?? 0;
  }
  const result: AgentStatus = {
    phase: c.phase,
    t: c.native.nowUs(),
    g: c.native.peekG(),
    module_map_epoch: c.modules.epoch,
    instruments: c.instruments.infos(full),
    streams: streams.map((s) => c.streams.info(s)),
    jobs: c.jobs.list().filter((j) => full || j.state === "queued" || j.state === "running"),
    scans: c.hooks.scans?.() ?? c.scanRegistry?.list() ?? [],
    flow: {
      sent_bytes: c.streams.flow.sentBytes,
      received_bytes: c.streams.flow.receivedBytes,
      inflight: c.streams.flow.inflight,
      shedding: c.streams.flow.shedding,
      shed_rows: c.streams.flow.shedRows,
    },
    exceptions: {
      by_type: { ...c.exceptions.byType },
      blocking_reports: c.exceptions.blockingReports,
      last_chance: c.exceptions.lastChance,
      bea_traps: c.exceptions.beaTraps,
      in_call: c.calls.inCallExceptions,
      safety_net: c.hooks.safetyNet?.() ?? "none",
    },
    calls: c.calls.status(),
    memory,
    rpc: { calls: c.counters.rpcCalls, slow: [...c.counters.slow] },
    faults: c.counters.faults,
    debug_registers: c.hooks.debugRegisters?.() ?? [0, 1, 2, 3].map((slot) => ({ slot, owner: null })),
  };
  return ok(result);
};

const flush = (p: FlushParams) => {
  const r = core().streams.flushAll(p?.streams === undefined ? {} : { streams: p.streams });
  return ok({ batches: r.batches, rows: r.rows });
};

const endWithoutRevert = (c: AgentCore): InstrumentSummary[] =>
  c.instruments
    .list()
    .filter((i) => i.state !== "ended")
    .map((i) => {
      i.state = "ended";
      i.endReason ??= "shutdown";
      i.endedT = c.native.nowUs();
      i.unrevertedDetail = "revert not requested";
      if (i.stream !== null) c.streams.close(i.stream);
      return c.instruments.summary(i);
    });

/** shutdown (S4 §18): only status/ping are admitted from here on (rpc.ts). */
const shutdown = async (p: ShutdownParams): Promise<AgentResult<ShutdownResult>> => {
  const c = core();
  c.phase = "shutting-down";
  const timeoutMs = clampInt(p?.timeout_ms, 0, 30_000, 5000);
  const jobsCancelled = c.jobs.cancelAll();
  let stopped: InstrumentSummary[];
  if (p?.revert === false) stopped = endWithoutRevert(c);
  else {
    let timer: number | null = null;
    const timedOut = new Promise<null>((resolve) => {
      timer = env.after(timeoutMs, () => resolve(null));
    });
    const done = await Promise.race([c.instruments.stopAll("shutdown"), timedOut]);
    if (timer !== null) env.cancelAfter(timer);
    stopped =
      done ??
      c.instruments
        .list()
        .filter((i) => i.state === "ended")
        .map((i) => c.instruments.summary(i));
  }
  let scansFreed = 0;
  try {
    scansFreed += c.scanRegistry?.closeAll() ?? 0;
  } catch (e) {
    c.fault("shutdown-scans", e);
  }
  for (const hook of c.hooks.onShutdown) {
    try {
      scansFreed += hook()?.scans_freed ?? 0;
    } catch (e) {
      c.fault("shutdown-hook", e);
    }
  }
  const final = c.streams.flushAll({ final: true });
  return ok({
    stopped,
    unreverted: c.instruments.unreverted(),
    scans_freed: scansFreed,
    jobs_cancelled: jobsCancelled,
    final_batches: final.batches,
  });
};

export const rpc = {
  hello,
  ping: () => ok({ t: core().native.nowUs(), g: core().native.peekG(), phase: core().phase }),
  status,
  flush,
  shutdown,
  fingerprint: () => ok(fingerprint(core())),
} satisfies Partial<AgentRpcImpl>;
