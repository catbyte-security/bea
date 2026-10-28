import type {
  AgentResult,
  AgentRpcImpl,
  ApiRow,
  DropCounters,
  EffectHint,
  EndReason,
  InstrumentCounters,
  InstrumentInfo,
  InstrumentSummary,
  ProfileInstallParams,
  ProfileInstallResult,
} from "../shared/agentProtocol.js";
import { API_CATALOG_MINOR, PSEUDO_API, apiName, type ApiSpec } from "../shared/apiProfiles.js";
import type { Hex } from "../shared/hex.js";
import { fail, ok } from "./errors.js";
import { MemmapWatcher } from "./memmap.js";
import { CallerResolver, gumMem, initLookups, keyNameOf, localEndpointOf, moduleNameIn } from "./profileDecoders.js";
import type { DecodeEnv } from "./pure/profileDecode.js";
import { ProfileEngine, type CallState } from "./pure/profileEngine.js";
import { HandleCache } from "./pure/profileHandles.js";
import { ModuleTable } from "./pure/profileModules.js";
import { selectApis } from "./pure/profileSelect.js";
import type { Cells } from "./pure/profileTypes.js";
import type { AgentCore } from "./state.js";

/**
 * API behavior profiles (S4 §10.5–10.7, S6 §6; WP-BEHAVIOR). Feature file: `init(core)` + `rpc.profileInstall`.
 *
 * One profileInstall = one instrument "p<n>" and one `api/1` stream. Every selected catalog entry gets one
 * Interceptor listener whose callbacks run the pure engine (./pure/profileEngine.ts). Observer rows (memmap watcher,
 * module observer) are multiplexed on the same stream as pseudo APIs (PSEUDO_API), so `memmap_stream` is null.
 *
 * CORE BINDING (parallel development, see the WP8 report): the S4 core services this file needs — a global g/clock,
 * the stream registry, the instrument registry (instrumentStop/instrumentList, unload stops) and the exit flush —
 * belong to WP-AGENT and were not available when this was written. `bindCore` uses the S4 names when the core
 * provides them (`nextG`, `nowUs`, `agentCallTids`, `instruments.registerExternal`) and otherwise runs the
 * self-contained fallback below (own counter, own 50 ms JSON batching with the announcement rule, own lifetime
 * timers, best-effort exit flush).
 *
 * Stalker rule (S4 §12.1, review fix AGENT-7): every Interceptor attach/detach here (install, lazy install, stop, the
 * exit hook) is followed by Interceptor.flush() and core.stalkerCo.invalidateAll(sites); a thread trace_execution
 * follows otherwise keeps running its old translation of the API (no rows from exactly the traced thread) or a stale
 * trampoline after the detach (the lab crash).
 */

// ---------------------------------------------------------------------------------------------- core binding
/** What profiles needs from the core. Matches S4 §5.1/§10.3 names where S4 names them. */
interface ExternalInstrument {
  readonly id: string;
  readonly kind: "profile";
  info(): InstrumentInfo;
  stop(reason: EndReason): InstrumentSummary;
}
interface CoreExtras {
  nextG?: () => number;
  nowUs?: () => number;
  agentCallTids?: { has(tid: number): boolean };
  instruments?: {
    registerExternal?: (entry: ExternalInstrument) => void;
    whenResumed?: (fn: () => void) => void;
  };
  stalkerCo?: { invalidateAll?: (sites: readonly NativePointer[]) => unknown };
}
interface Bound {
  nextG(): number;
  nowUs(): number;
  isAgentCall(tid: number): boolean;
  register(entry: ExternalInstrument): void;
  /** run `fn` after the host's `resumed` post (the core's seam; recv only without a core receiver) */
  whenResumed(fn: () => void): void;
  /** after an attach/detach + Interceptor.flush(): re-compile followed threads' blocks at `sites` (S4 §12.1) */
  invalidate(sites: readonly NativePointer[]): void;
}

let core: AgentCore | null = null;
let gCounter = 0;
let nextInstrument = 0;
let nextStream = 0;

const bindCore = (c: AgentCore): Bound => {
  const x = c as AgentCore & CoreExtras;
  return {
    nextG: typeof x.nextG === "function" ? () => (x.nextG as () => number)() : () => ++gCounter,
    nowUs: typeof x.nowUs === "function" ? () => (x.nowUs as () => number)() : () => (Date.now() - c.t0Wall) * 1000,
    isAgentCall: (tid) => x.agentCallTids?.has(tid) ?? false,
    register: (entry) => x.instruments?.registerExternal?.(entry),
    // integrator fix (WP8 change request): the core owns the persistent `resumed` receiver; a one-shot recv here
    // would queue behind it and never fire
    whenResumed: (fn) => {
      const instruments = x.instruments;
      if (typeof instruments?.whenResumed === "function") instruments.whenResumed(fn);
      else recv("resumed", () => fn());
    },
    invalidate: (sites) => {
      if (sites.length === 0) return;
      try {
        x.stalkerCo?.invalidateAll?.(sites);
      } catch {
        // best effort: no thread is followed, or it exited
      }
    },
  };
};

// ---------------------------------------------------------------------------------------------- stream (fallback)
const FLUSH_MS = 50;

/** JSON row stream with per-batch drop deltas. Flushes only after `announce()` (S4 announcement rule). */
class RowStream {
  private rows: ApiRow[] = [];
  private bseq = 0;
  private announced = false;
  private closed = false;
  private delta: DropCounters = {};
  readonly total: DropCounters = {};
  sentRows = 0;

  constructor(
    readonly id: string,
    readonly instrument: string,
    private readonly maxPending: number,
    private readonly batchRows: number,
  ) {}

  drop(reason: keyof DropCounters, n = 1): void {
    this.delta[reason] = (this.delta[reason] ?? 0) + n;
    this.total[reason] = (this.total[reason] ?? 0) + n;
  }

  push(row: ApiRow): void {
    if (this.closed) return this.drop("stopped");
    if (this.rows.length >= this.maxPending) return this.drop("buffer_full");
    this.rows.push(row);
    if (this.rows.length >= this.batchRows) this.flush(false);
  }

  announce(): void {
    this.announced = true;
  }

  flush(final: boolean): void {
    if (!this.announced || (this.closed && !final)) return;
    const hasDrops = Object.keys(this.delta).length > 0;
    if (this.rows.length === 0 && !final && !hasDrops) return;
    const batch = this.rows;
    this.rows = [];
    const first = batch[0];
    const last = batch[batch.length - 1];
    this.bseq++;
    send({
      bea: "batch",
      stream: this.id,
      instrument: this.instrument,
      bseq: this.bseq,
      kind: "api/1",
      n: batch.length,
      g0: first?.[0] ?? 0,
      g1: last?.[0] ?? 0,
      t0: first?.[1] ?? 0,
      t1: last?.[1] ?? 0,
      dropped: this.delta,
      final,
      enc: "json",
      rows: batch,
    });
    this.sentRows += batch.length;
    this.delta = {};
    if (final) this.closed = true;
  }
}

// ---------------------------------------------------------------------------------------------- instruments
interface Installed {
  readonly spec: ApiSpec;
  readonly va: Hex;
  readonly listener: InvocationListener;
}

interface ProfileInstrument {
  readonly id: string;
  readonly label: string | null;
  readonly stream: RowStream;
  readonly engine: ProfileEngine<NativePointer>;
  readonly installed: Installed[];
  readonly pending: ApiSpec[];
  readonly createdT: number;
  deadlineT: number | null;
  readonly maxHits: number;
  state: "active" | "stopping" | "ended";
  timer: ReturnType<typeof setTimeout> | null;
  memmap: MemmapWatcher | null;
  endReason: EndReason | null;
  endedT: number | null;
  suppressed: number;
  readonly moduleRows: boolean;
}

const active = new Map<string, ProfileInstrument>();
let flushTimer: ReturnType<typeof setInterval> | null = null;
let exitHook: InvocationListener | null = null;
let exitHookAt: NativePointer | null = null;

const sitesOf = (installed: readonly Installed[]): NativePointer[] => installed.map((i) => ptr(i.va));
let bound: Bound | null = null;
let callers: CallerResolver | null = null;

const flushAll = (final: boolean): void => {
  for (const inst of active.values()) inst.stream.flush(final);
};

const ensureTimers = (): void => {
  if (flushTimer === null) flushTimer = setInterval(() => flushAll(false), FLUSH_MS);
  if (exitHook === null) {
    // Best-effort exit flush for the fallback binding (the core's acked exit flush is the real one, S4 §7, F11).
    const exit = moduleObjects.get("ntdll.dll")?.findExportByName("RtlExitUserProcess") ?? null;
    if (exit !== null) {
      exitHook = Interceptor.attach(exit, {
        onEnter() {
          if (Cloak.hasCurrentThread() || active.size === 0) return;
          for (const inst of active.values()) inst.stream.flush(true);
          Thread.sleep(0.1);
        },
      });
      exitHookAt = exit;
      Interceptor.flush();
      bound?.invalidate([exit]);
    }
  }
};

const releaseTimers = (): void => {
  if (active.size > 0) return;
  if (flushTimer !== null) clearInterval(flushTimer);
  flushTimer = null;
  exitHook?.detach();
  exitHook = null;
  Interceptor.flush();
  if (exitHookAt !== null) bound?.invalidate([exitHookAt]);
  exitHookAt = null;
};

const counters = (inst: ProfileInstrument): InstrumentCounters => {
  const c = inst.engine.counters;
  const dropped: DropCounters = { ...c.dropped };
  for (const [k, v] of Object.entries(inst.stream.total) as [keyof DropCounters, number][])
    dropped[k] = (dropped[k] ?? 0) + v;
  return {
    hits: c.hits,
    recorded: c.recorded,
    sampled_out: 0,
    filtered: c.filtered,
    agent_calls_suppressed: inst.suppressed,
    unreturned: c.unreturned,
    errors: c.errors,
    dropped,
    bea_guard_suspended: 0,
  };
};

const infoOf = (inst: ProfileInstrument): InstrumentInfo => ({
  id: inst.id,
  kind: "profile",
  label: inst.label,
  state: inst.state,
  stream: inst.stream.id,
  created_t: inst.createdT,
  deadline_t: inst.deadlineT,
  max_hits: inst.maxHits,
  counters: counters(inst),
  targets: inst.installed.map((i) => i.va),
});

/** Stop protocol (S4 §5.7): stopping → detach → flush → final batch + "ended" on the next tick. Idempotent. */
const stopInstrument = (inst: ProfileInstrument, reason: EndReason): InstrumentSummary => {
  if (inst.state === "active") {
    inst.state = "stopping";
    inst.engine.active = false;
    if (inst.timer !== null) clearTimeout(inst.timer);
    inst.timer = null;
    let reverted = true;
    for (const i of inst.installed) {
      try {
        i.listener.detach();
      } catch {
        reverted = false;
      }
    }
    Interceptor.flush();
    bound?.invalidate(sitesOf(inst.installed));
    inst.memmap?.stop();
    inst.endReason = reason;
    inst.endedT = bound?.nowUs() ?? 0;
    inst.state = "ended";
    const summary = summaryOf(inst, reverted);
    setImmediate(() => {
      inst.stream.flush(true);
      send({ bea: "instrument", id: inst.id, event: "ended", detail: summary });
      active.delete(inst.id);
      releaseTimers();
    });
    return summary;
  }
  return summaryOf(inst, true);
};

const summaryOf = (inst: ProfileInstrument, reverted: boolean): InstrumentSummary => ({
  ...infoOf(inst),
  end_reason: inst.endReason,
  ended_t: inst.endedT,
  reverted,
  verification: null,
});

// ---------------------------------------------------------------------------------------------- listeners
type ProfileCtx = InvocationContext & { bea?: CallState<NativePointer> | null };

const attachSpec = (inst: ProfileInstrument, spec: ApiSpec, address: NativePointer): Installed => {
  const engine = inst.engine;
  const resolver = callers;
  const callbacks: InvocationListenerCallbacks = {
    onEnter(args) {
      const self = this as ProfileCtx;
      self.bea = null;
      if (!engine.active) return; // detached guard
      if (Cloak.hasCurrentThread()) return; // BEA/Frida threads (F2)
      if (bound?.isAgentCall(self.threadId) === true) {
        inst.suppressed++;
        return;
      }
      self.bea = engine.enter(spec, {
        tid: self.threadId,
        depth: self.depth,
        args: (i) => args[i] as NativePointer,
        caller: () => (resolver === null ? (self.returnAddress.toString() as Hex) : resolver.resolve(self)),
      });
      if (spec.id === 54 && inst.memmap !== null) probeFree(inst, args);
    },
    onLeave(retval) {
      const self = this as ProfileCtx;
      const state = self.bea;
      if (state === null || state === undefined) return;
      engine.leave(state, retval, self.lastError);
    },
  };
  let listener: InvocationListener;
  try {
    listener = Interceptor.attach(address, callbacks);
  } catch (e) {
    if (!/unable to intercept/iu.test(String(e))) throw e;
    // S4 §10.2 step 6: retry with forced relocation (VERIFIED for 4-byte functions)
    listener = Interceptor.attach({ target: address, relocation: "forced" }, callbacks);
  }
  return { spec, va: address.toString() as Hex, listener };
};

/** NtFreeVirtualMemory(self, &base, &size, MEM_RELEASE): executable region about to vanish (see memmap.ts). */
const probeFree = (inst: ProfileInstrument, args: InvocationArguments): void => {
  try {
    const process = args[0] as NativePointer;
    if (!process.equals(ptr(-1)) && !process.isNull()) return;
    if (((args[3] as NativePointer).toUInt32() & 0x8000) === 0) return;
    const pBase = args[1] as NativePointer;
    if (!pBase.isNull()) inst.memmap?.probeFree(pBase.readPointer());
  } catch {
    inst.engine.counters.errors++;
  }
};

const resolveExport = (spec: ApiSpec): NativePointer | "module-missing" | "export-missing" => {
  const m = moduleObjects.get(spec.module) ?? null;
  if (m === null) return "module-missing";
  return m.findExportByName(spec.export) ?? "export-missing";
};

// ---------------------------------------------------------------------------------------------- module observer
/**
 * ONE feature-level observer (attached at the first install, before any listener): its initial synchronous onAdded
 * calls fill the module table; later loads/unloads update it right in the loader callback (plain data, cheap) and
 * queue pseudo rows and lazy installs for the JS thread (never inside the loader callback, S4 §8.1). Nothing here
 * enumerates modules while hooks are active (./pure/profileModules.ts).
 */
const modules = new ModuleTable();
/** Module objects by lowercase name, for export resolution without enumerating modules */
const moduleObjects = new Map<string, Module>();
let observer: ModuleObserver | null = null;

const entryOf = (m: Module) => ({ name: m.name, path: m.path, base: BigInt(m.base.toString()), size: m.size });

const ensureObserver = (): void => {
  if (observer !== null) return;
  let initial = true;
  observer = Process.attachModuleObserver({
    onAdded(m) {
      modules.add(entryOf(m));
      moduleObjects.set(m.name.toLowerCase(), m);
      if (initial || Cloak.hasCurrentThread()) return;
      const tid = Process.getCurrentThreadId();
      setImmediate(() => onModule("L", m, tid));
    },
    onRemoved(m) {
      modules.remove(BigInt(m.base.toString()));
      if (moduleObjects.get(m.name.toLowerCase())?.base.equals(m.base) === true)
        moduleObjects.delete(m.name.toLowerCase());
      if (Cloak.hasCurrentThread()) return;
      const tid = Process.getCurrentThreadId();
      setImmediate(() => onModule("U", m, tid));
    },
  });
  initial = false;
};

const onModule = (ev: "L" | "U", m: Module, tid: number): void => {
  for (const inst of active.values()) {
    if (inst.state !== "active") continue;
    if (inst.moduleRows) {
      const cells: Cells = {
        ev: { s: ev },
        name: { s: m.name },
        path: { s: m.path },
        base: m.base.toString() as Hex,
        size: m.size,
      };
      inst.engine.emitPseudo(PSEUDO_API.MODULES.id, tid, cells);
    }
    if (ev === "L") lazyInstall(inst, m);
  }
};

/** S4 §10.6 "Lazy modules": install the pending entries of a module that just loaded, then announce them. */
const lazyInstall = (inst: ProfileInstrument, m: Module): void => {
  if (inst.pending.length === 0) return;
  const lower = m.name.toLowerCase();
  const apis: string[] = [];
  const added: Installed[] = [];
  for (let i = inst.pending.length - 1; i >= 0; i--) {
    const spec = inst.pending[i];
    if (spec === undefined || spec.module !== lower) continue;
    inst.pending.splice(i, 1);
    const addr = m.findExportByName(spec.export);
    if (addr === null) continue;
    try {
      const installed = attachSpec(inst, spec, addr);
      inst.installed.push(installed);
      added.push(installed);
      apis.push(apiName(spec));
    } catch {
      inst.engine.counters.errors++;
    }
  }
  if (apis.length === 0) return;
  Interceptor.flush();
  bound?.invalidate(sitesOf(added));
  send({ bea: "instrument", id: inst.id, event: "lazy-installed", detail: { apis } });
};

// ---------------------------------------------------------------------------------------------- install
const PROFILE_NAMES = new Set(["file", "registry", "network", "process", "module_load", "memory_protection"]);
const DEFAULT_DURATION_MS = 30_000;
const DEFAULT_MAX_HITS = 10_000;

const badParams = (path: string, problem: string): AgentResult<never> =>
  fail({ _tag: "BadParams", message: "invalid profileInstall parameters", issues: [{ path, problem }] });

const profileInstall = (params: ProfileInstallParams): AgentResult<ProfileInstallResult> => {
  if (core === null || bound === null) return fail({ _tag: "NotReady", message: "profiles not initialized" });
  const c = core;
  const b = bound;
  if (!Array.isArray(params.profiles) || params.profiles.length === 0)
    return badParams("profiles", "at least one profile is required");
  for (const p of params.profiles) if (!PROFILE_NAMES.has(p)) return badParams("profiles", `unknown profile ${p}`);
  const options = params.options ?? {};
  const limits = c.limits;
  const { specs, denied } = selectApis(params.profiles, options);
  if (specs.length > limits.max_profile_api_hooks)
    return fail({
      _tag: "ResourceLimit",
      message: "too many profile hooks",
      resource: "instruments",
      limit: limits.max_profile_api_hooks,
      observed: specs.length,
    });
  ensureObserver();
  if (callers === null) {
    initLookups(moduleObjects);
    callers = new CallerResolver(modules);
  }
  const lifetime = params.lifetime;
  const durationMs = Math.min(
    lifetime.duration_ms > 0 ? lifetime.duration_ms : DEFAULT_DURATION_MS,
    limits.max_duration_ms,
  );
  const maxHits = Math.min(lifetime.max_hits > 0 ? lifetime.max_hits : DEFAULT_MAX_HITS, limits.max_hits_cap);
  const id = `p${String(++nextInstrument)}`;
  const stream = new RowStream(`sp${String(++nextStream)}`, id, limits.stream_max_pending_rows, limits.batch_max_rows);
  const cache = new HandleCache(limits.handle_cache_entries);
  const env: DecodeEnv<NativePointer> = {
    mem: gumMem,
    cache,
    caps: {
      fileBytes: Math.min(options.file?.capture_bytes ?? 0, limits.max_capture_bytes),
      netBytes: Math.min(options.network?.capture_payload_bytes ?? 0, limits.max_capture_bytes),
      valueBytes: Math.min(options.registry?.capture_value_bytes ?? 0, limits.max_capture_bytes),
    },
    keyName: keyNameOf,
    moduleName: moduleNameIn(modules),
  };
  let inst: ProfileInstrument | null = null;
  const engine = new ProfileEngine<NativePointer>(
    env,
    {
      nextG: b.nextG,
      nowUs: b.nowUs,
      emit: (row) => stream.push(row),
      onMaxHits: () =>
        setImmediate(() => {
          if (inst !== null) stopInstrument(inst, "max_hits");
        }),
      localEndpoint: localEndpointOf,
    },
    {
      perApiMax: Math.min(options.per_api_max_events ?? limits.profile_events_per_api, limits.profile_events_per_api),
      maxHits,
      threadIds: options.thread_ids !== undefined && options.thread_ids.length > 0 ? new Set(options.thread_ids) : null,
    },
  );
  const created: ProfileInstrument = {
    id,
    label: params.label ?? null,
    stream,
    engine,
    installed: [],
    pending: [],
    createdT: b.nowUs(),
    deadlineT: null,
    maxHits,
    state: "active",
    timer: null,
    memmap: null,
    endReason: null,
    endedT: null,
    suppressed: 0,
    moduleRows: params.profiles.includes("module_load"),
  };
  inst = created;
  const failed: ProfileInstallResult["failed"] = [];
  const pending: ProfileInstallResult["pending"] = [];
  const scanMs = options.memory_protection?.exec_region_scan_ms ?? 1000;
  if (params.profiles.includes("memory_protection") && scanMs > 0)
    created.memmap = new MemmapWatcher(Math.max(50, scanMs), modules, (ev, seen) =>
      engine.emitPseudo(PSEUDO_API.MEMMAP.id, Process.getCurrentThreadId(), {
        ev: { s: ev.ev },
        base: ev.base,
        size: ev.size,
        protection: { s: ev.protection },
        module: ev.module === null ? null : { s: ev.module },
        seen: { s: seen },
      }),
    );
  for (const spec of specs) {
    const target = resolveExport(spec);
    if (target === "module-missing") {
      if (spec.lazy_module) {
        created.pending.push(spec);
        pending.push({ api: apiName(spec), module: spec.module });
      } else
        failed.push({
          api: apiName(spec),
          error: { _tag: "ModuleNotFound", message: "module not loaded", module: spec.module },
        });
      continue;
    }
    if (target === "export-missing") {
      failed.push({
        api: apiName(spec),
        error: { _tag: "ExportNotFound", message: "export not found", module: spec.module, export: spec.export },
      });
      continue;
    }
    try {
      created.installed.push(attachSpec(created, spec, target));
    } catch (e) {
      failed.push({
        api: apiName(spec),
        error: {
          _tag: "HookInstallFailed",
          message: "Interceptor.attach failed",
          address: target.toString() as Hex,
          attempts: ["default", "forced"],
          frida_message: String(e).slice(0, 256),
          alternatives: ["hook_function on a caller", "trace_execution coverage"],
        },
      });
    }
  }
  if (created.installed.length === 0 && created.pending.length === 0) {
    return fail({
      _tag: "HookInstallFailed",
      message: "no profile API could be hooked",
      address: "0x0",
      attempts: ["default"],
      frida_message: failed
        .map((f) => f.api)
        .join(", ")
        .slice(0, 256),
      alternatives: ["hook_function on the specific API", "trace_execution coverage"],
    });
  }
  Interceptor.flush();
  b.invalidate(sitesOf(created.installed));
  created.memmap?.start();
  active.set(id, created);
  ensureTimers();
  const armDeadline = (): void => {
    if (created.state !== "active") return; // stopped before the target was resumed
    created.deadlineT = b.nowUs() + durationMs * 1000;
    created.timer = setTimeout(() => stopInstrument(created, "duration"), durationMs);
  };
  if (lifetime.clock === "resume") b.whenResumed(armDeadline);
  else armDeadline();
  b.register({ id, kind: "profile", info: () => infoOf(created), stop: (reason) => stopInstrument(created, reason) });
  // announcement rule: the stream becomes flushable after this RPC's reply has been produced
  setImmediate(() => stream.announce());
  const effect: EffectHint = {
    kind: "profile-installed",
    reversible: true,
    targets: created.installed.map((i) => ({ address: i.va, size: null })),
    thread_ids: options.thread_ids ?? null,
    before: [],
  };
  return ok({
    instrument_id: id,
    stream_id: stream.id,
    row_kind: "api/1",
    catalog_minor: API_CATALOG_MINOR,
    installed: created.installed.map((i) => ({ api_id: i.spec.id, api: apiName(i.spec), va: i.va })),
    pending,
    denied: [...denied],
    failed,
    memmap_stream: null,
    effect,
  });
};

/** Agent feature file (WP-BEHAVIOR). Methods: profileInstall. */
export function init(c: AgentCore): void {
  core = c;
  bound = bindCore(c);
  c.features.push("profiles");
}

export const rpc = {
  profileInstall,
} satisfies Partial<AgentRpcImpl>;

/** Fallback-binding hooks for the core and the raw-Frida acceptance harness (never called by the host). @public */
export const profileRuntime = {
  list: (): InstrumentInfo[] => [...active.values()].map(infoOf),
  stop: (id: string, reason: EndReason): InstrumentSummary | null => {
    const inst = active.get(id);
    return inst === undefined ? null : stopInstrument(inst, reason);
  },
  flush: (): void => flushAll(false),
};
