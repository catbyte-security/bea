// =================================================================================================
// src/agent/state.ts — WP3-AGENT the AgentCore singleton (S4 §5.1; DESIGN §5.3). Internal, never on the wire.
// createCore() (called by the frozen index.ts outside its try block, so it never throws) builds every core service as
// a plain object; native resources are created later by coreRpc.init (the boot sequence). Features receive this
// object in init(core) and reach services through it: streams, instruments, jobs, modules, threads, originals,
// guards (withBeaGuardsSuspended), calls (in-call registry), stalkerCo, exceptions (registerTrapRouter), keep, hooks.
// Feature-seam conventions the parallel feature WPs probe structurally are served too (thin aliases, documented at
// each member): core.nextG/nowUs/onDispose, core.watchSeam (WP9), instruments.registerExternal (WP7/WP8) and
// register(id, handle)/allocate/ended (WP12), streams.open(kind, id)/push/close(id) (WP12), originals.save(owner,
// address, size)/release(owner) (WP12), guards.isGuarded (WP12), jobs.submit(spec, announced)/announce (WP10),
// core.scanRegistry (published by WP10, read by status/shutdown), calls.exit(...) summary fields (WP11).
// =================================================================================================
import type {
  AgentFeature,
  AgentLimits,
  AgentStatus,
  CrashPolicy,
  FatalMessage,
  GateName,
  HelloParams,
  ReadMemoryMeta,
  ReadyMessage,
  ScanStatus,
  ThreadId,
  TimeUs,
} from "../shared/agentProtocol.js";
import { AGENT_LIMIT_DEFAULTS } from "../shared/agentLimits.js";
import { AckService } from "./ack.js";
import { CallRegistry, type ActiveCall } from "./calls.js";
import { env } from "./env.js";
import { mapThrown } from "./errors.js";
import { createStreamRegistry, EventLoop, type AgentStreams, type Stream } from "./events.js";
import { ExceptionDispatcher } from "./exceptions.js";
import { GuardTable } from "./guards.js";
import { createWatchSeam, InstrumentRegistry, type WatchSeam } from "./instruments.js";
import { createJobRunner } from "./jobs.js";
import { safeReadBytes } from "./memory.js";
import { ModuleIndex } from "./modules.js";
import { NativeCore } from "./native/core.js";
import { OriginalBytes } from "./originals.js";
import type { JobRunner } from "./pure/coreJobs.js";
import { FaultCoalescer } from "./pure/coreRate.js";
import { StalkerCoordinator } from "./stalkerCo.js";
import { ThreadService } from "./threads.js";
import { Win32 } from "./win32.js";

export type Phase = "loaded" | "ready" | "shutting-down";

/** Session configuration from hello (defaults until then). */
export interface EffectiveConfig {
  session: HelloParams["session"] | null;
  crash: CrashPolicy;
  streams: HelloParams["streams"];
  flow: HelloParams["flow"];
}

/**
 * "system" is not a crash class by default (review fix AGENT-11): Frida reports every code it does not map as
 * "system", which includes C++ throws (0xE06D7363, 0x20474343), OutputDebugString (0x40010006/0x4001000A), thread
 * naming (0x406D1388) and RPC errors, all normally handled. They were blocking crash reports with no code, used up the
 * 8-per-10 s budget and could be joined to a later fail-fast exit. An unhandled one is reported at last chance.
 */
export const DEFAULT_CRASH_POLICY: CrashPolicy = {
  first_chance_rows: true,
  first_chance_blocking: true,
  crash_class: ["access-violation", "illegal-instruction", "stack-overflow", "arithmetic", "abort"],
  ack_timeout_ms: 1000,
  last_chance_ack_timeout_ms: 2000,
  max_blocking_per_10s: 8,
  rows_per_sec: 1000,
  stack_bytes: 256,
  backtrace_depth: 32,
  include_xmm: false,
};

/** Registration points so feature files plug into core RPCs without core importing features (S4 §3.1). */
export interface CoreHooks {
  /** WP10: status().scans */
  scans: (() => ScanStatus[]) | null;
  /** WP9: status().debug_registers */
  debugRegisters: (() => AgentStatus["debug_registers"]) | null;
  /** WP9: status().exceptions.safety_net */
  safetyNet: (() => "none" | "installed") | null;
  /** WP9: DR7 bits BEA expects on every armed thread (fingerprint); null = no expectation */
  expectedDr7: (() => bigint | null) | null;
  /** feature memory accounting for status().memory */
  readonly memory: (() => Partial<AgentStatus["memory"]>)[];
  /** shutdown step 4 (close scans, free native arrays): return how many scans were freed */
  readonly onShutdown: (() => { scans_freed?: number } | void)[];
  /** rpc.exports.dispose (script unload, also on host kill): SYNCHRONOUS disarm of DRs, code writes, function tables */
  readonly onDispose: (() => void)[];
}

/** Pins CModules / NativeCallbacks / native buffers until their last user is gone (QJS frees eagerly). */
export class KeepAlive {
  readonly #pinned = new Set<unknown>();

  pin<T>(value: T): T {
    this.#pinned.add(value);
    return value;
  }

  /** Release after `afterMs` (Stalker rule: only after unfollow + flush + settle, S4 §12.4). */
  release(value: unknown, afterMs = 0): void {
    if (afterMs <= 0) this.#pinned.delete(value);
    else env.after(afterMs, () => this.#pinned.delete(value));
  }

  get size(): number {
    return this.#pinned.size;
  }
}

/**
 * The announcement-rule scope of the RPCs in progress: callbacks run once every open RPC has produced its reply.
 * An async RPC that never settles must not hold announcements back forever: after STALE_SCOPE_MS of continuously
 * open scope the flush loop releases the pending callbacks (the host parks early batches ≤ 2 s anyway, D-INT-7).
 */
export const STALE_SCOPE_MS = 10_000;

export class RpcScope {
  #depth = 0;
  #openedAt = 0;
  readonly #pending: (() => void)[] = [];

  begin(): void {
    if (this.#depth === 0) this.#openedAt = Date.now();
    this.#depth++;
  }

  end(): void {
    this.#depth = Math.max(0, this.#depth - 1);
    if (this.#depth > 0) return;
    this.releasePending();
  }

  /** Some RPC scope has stayed open for longer than `maxMs`. */
  isStale(nowMs: number, maxMs = STALE_SCOPE_MS): boolean {
    return this.#depth > 0 && nowMs - this.#openedAt > maxMs;
  }

  /** Run the deferred callbacks now (scope end, or a stale scope). */
  releasePending(): void {
    for (const fn of this.#pending.splice(0)) fn();
  }

  /** Inside an RPC: defer `fn` to the reply and return true; outside: return false (caller acts now). */
  afterReply(fn: () => void): boolean {
    if (this.#depth === 0) return false;
    this.#pending.push(fn);
    return true;
  }
}

export interface AgentCore {
  readonly t0Wall: number;
  /** the agent JS thread (cloaked, F2) */
  readonly jsTid: ThreadId;
  phase: Phase;
  bootStage: FatalMessage["stage"];
  features: AgentFeature[];
  early: ReadyMessage["early"];
  /** effective gates from hello (defense in depth; the host enforces first) */
  gates: Record<GateName, boolean>;
  /** effective limits: defaults until hello, then hello.limits clamped to AGENT_LIMIT_HARD */
  limits: AgentLimits;
  config: EffectiveConfig;
  /** the host posted {type:"resumed"} (clock:"resume" timers armed) */
  resumed: boolean;
  bootT: TimeUs;
  helloDone: boolean;
  native: NativeCore;
  win: Win32;
  streams: AgentStreams;
  events: EventLoop;
  acks: AckService;
  instruments: InstrumentRegistry;
  jobs: JobRunner;
  modules: ModuleIndex;
  threads: ThreadService;
  originals: OriginalBytes;
  guards: GuardTable;
  calls: CallRegistry;
  stalkerCo: StalkerCoordinator;
  exceptions: ExceptionDispatcher;
  systemStreams: { exceptions: Stream | null; modules: Stream | null; threads: Stream | null; memmap: Stream | null };
  keep: KeepAlive;
  scope: RpcScope;
  hooks: CoreHooks;
  counters: { faults: number; rpcCalls: number; slow: { method: string; us: number }[] };
  /** threads currently running a BEA-initiated call (S4 §13.4); listeners check `calls.suppresses(tid)` */
  agentCallTids: Map<ThreadId, ActiveCall>;
  /** rate-limited FaultMessage (≤ 10/s, coalesced counts); never throws */
  fault(where: string, e: unknown): void;
  // ---- feature seams (structural conventions the feature WPs probe; thin aliases of the services above)
  /** agent-global row sequence / µs clock (core.native) */
  nextG(): number;
  nowUs(): number;
  /** register a synchronous disarm for rpc.exports.dispose (= hooks.onDispose) */
  onDispose(fn: () => void): void;
  /** WP9 watch/trace seam (instruments.ts createWatchSeam) */
  watchSeam: WatchSeam;
  /** WP10 publishes its scan registry here (status().scans, memory.scan_bytes, shutdown scans_freed) */
  scanRegistry?: { list(): ScanStatus[]; closeAll(): number; memoryBytes(): number };
  /**
   * A-18 guard-aware read for feature hot paths (memory.ts safeReadBytes with the cached VirtualQuery planner): the
   * readable prefix, stopping before unmapped/unreadable memory and target guard pages; BEA guard pages suspended.
   * Hook captures read through it (review fix AGENT-10).
   */
  safeRead(p: NativePointer, n: number): { readonly bytes: Uint8Array; readonly stop: ReadMemoryMeta["stop"] };
}

let current: AgentCore | null = null;

/** The singleton index.ts created (null before createCore); test agent builds reach the core through it. @public */
export const currentCore = (): AgentCore | null => current;

export function createCore(): AgentCore {
  const faults = new FaultCoalescer(10);
  const c = {
    t0Wall: Date.now(),
    jsTid: Process.getCurrentThreadId(),
    phase: "loaded",
    bootStage: "platform",
    features: [],
    early: { exception_handler: true, exit_hook: false, last_chance_hook: false, module_observer: false },
    gates: { write_memory: false, override_function: false, call_function: false },
    limits: { ...AGENT_LIMIT_DEFAULTS },
    config: {
      session: null,
      crash: { ...DEFAULT_CRASH_POLICY, crash_class: [...DEFAULT_CRASH_POLICY.crash_class] },
      streams: { flush_ms: AGENT_LIMIT_DEFAULTS.flush_ms, exceptions: true, threads: false },
      flow: {
        high_water_bytes: AGENT_LIMIT_DEFAULTS.flow_high_water_bytes,
        low_water_bytes: AGENT_LIMIT_DEFAULTS.flow_low_water_bytes,
      },
    },
    resumed: false,
    bootT: 0,
    helloDone: false,
    systemStreams: { exceptions: null, modules: null, threads: null, memmap: null },
    keep: new KeepAlive(),
    scope: new RpcScope(),
    hooks: {
      scans: null,
      debugRegisters: null,
      safetyNet: null,
      expectedDr7: null,
      memory: [],
      onShutdown: [],
      onDispose: [],
    },
    counters: { faults: 0, rpcCalls: 0, slow: [] },
    agentCallTids: new Map(),
    fault(where: string, e: unknown): void {
      try {
        c.counters.faults++;
        const count = faults.note(Date.now());
        if (count !== null) env.send({ bea: "fault", where, error: mapThrown(e, where), count });
      } catch {
        // never throw from the fault path
      }
    },
    nextG: (): number => c.native.nextG(),
    nowUs: (): number => c.native.nowUs(),
    onDispose(fn: () => void): void {
      c.hooks.onDispose.push(fn);
    },
    safeRead: (p: NativePointer, n: number) => {
      const r = safeReadBytes(c, p, n, true);
      return { bytes: r.bytes, stop: r.stop };
    },
  } as unknown as AgentCore;
  c.native = new NativeCore();
  c.win = new Win32();
  c.streams = createStreamRegistry(c);
  c.events = new EventLoop(c);
  c.acks = new AckService(c);
  c.instruments = new InstrumentRegistry(c);
  c.jobs = createJobRunner(c);
  c.modules = new ModuleIndex(c);
  c.threads = new ThreadService(c);
  c.originals = new OriginalBytes();
  c.guards = new GuardTable(c);
  c.calls = new CallRegistry(c);
  c.stalkerCo = new StalkerCoordinator(c);
  c.exceptions = new ExceptionDispatcher(c);
  c.watchSeam = createWatchSeam(c);
  current = c;
  return c;
}
