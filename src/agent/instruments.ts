// =================================================================================================
// src/agent/instruments.ts — WP3-AGENT InstrumentRegistry and the generic stop/list RPCs (S4 §5.7, CI-I3).
// Ids are h|p|w|t|o + a counter never reused. Every instrument is bounded: duration (timer armed at install, or at
// the host's `resumed` post for clock:"resume") and max_hits (the hit reaching it is recorded and the stop scheduled;
// listeners never detach themselves). The stop protocol, in order: state=stopping (every callback returns at its first
// line) → kind-specific revert (feature-supplied) → Interceptor.flush → Stalker invalidate of the patch sites →
// verification → one setImmediate tick → final batch + {bea:"instrument", event:"ended", detail: summary}. A failed
// verification keeps reverted=false (host: effect_unreverted) and the instrument stays listed. Module unload stops
// every instrument with a patch site inside the module (reason module-unloaded; A-12).
// =================================================================================================
import type {
  AgentError,
  AgentLimits,
  AgentRpcImpl,
  BinaryLayout,
  EndReason,
  Hex,
  InstrumentCounters,
  InstrumentId,
  InstrumentInfo,
  InstrumentStopParams,
  InstrumentStopResult,
  InstrumentSummary,
  Lifetime,
  NoticeMessage,
  RowKind,
  StreamId,
  ThreadId,
} from "../shared/agentProtocol.js";
import { findAccessInsn } from "./disasm.js";
import { env } from "./env.js";
import { badParam, fail, ok } from "./errors.js";
import { Stream } from "./events.js";
import type { ExternalGuardEntry } from "./guards.js";
import type { ModuleChange } from "./modules.js";
import {
  hitOutcome,
  INSTRUMENT_PREFIX,
  normalizeLifetime,
  type HitOutcome,
  type InstrumentKind,
  type NormalizedLifetime,
} from "./pure/coreInstruments.js";
import type { AgentCore } from "./state.js";

export interface RevertOutcome {
  readonly reverted: boolean;
  readonly verification: InstrumentSummary["verification"];
  /** why it could not be reverted (InstrumentStopResult.unreverted[].detail) */
  readonly detail?: string;
}

export interface InstrumentSpec {
  /** an id reserved with `nextId(kind)` (when the stream had to be opened first); allocated otherwise */
  readonly id?: InstrumentId;
  readonly kind: InstrumentKind;
  readonly label?: string | null;
  readonly lifetime: Partial<Lifetime> | undefined;
  readonly targets: readonly Hex[];
  readonly stream: Stream | null;
  /** code addresses BEA patched for this instrument (Stalker invalidate, module-unload stops) */
  readonly sites?: readonly NativePointer[];
  /** kind-specific revert (detach listeners, disarm DRs/guards, unfollow …); runs once */
  readonly revert: (inst: Instrument, reason: EndReason) => RevertOutcome | Promise<RevertOutcome>;
  /** after the final batch (release native memory once core.keep settles) */
  readonly onEnded?: (inst: Instrument) => void;
}

const emptyCounters = (): InstrumentCounters => ({
  hits: 0,
  recorded: 0,
  sampled_out: 0,
  filtered: 0,
  agent_calls_suppressed: 0,
  unreturned: 0,
  errors: 0,
  dropped: {},
  bea_guard_suspended: 0,
});

export class Instrument {
  readonly id: InstrumentId;
  readonly kind: InstrumentKind;
  readonly label: string | null;
  readonly seq: number;
  state: InstrumentInfo["state"] = "active";
  readonly stream: Stream | null;
  readonly createdT: number;
  deadlineT: number | null = null;
  readonly lifetime: NormalizedLifetime;
  readonly counters: InstrumentCounters = emptyCounters();
  readonly targets: readonly Hex[];
  readonly sites: readonly NativePointer[];
  endReason: EndReason | null = null;
  endedT: number | null = null;
  reverted = false;
  verification: InstrumentSummary["verification"] = null;
  unrevertedDetail: string | null = null;
  readonly spec: InstrumentSpec;
  timer: number | null = null;
  stopping: Promise<InstrumentSummary> | null = null;
  readonly #registry: InstrumentRegistry;

  constructor(
    registry: InstrumentRegistry,
    id: InstrumentId,
    seq: number,
    spec: InstrumentSpec,
    lifetime: NormalizedLifetime,
    now: number,
  ) {
    this.#registry = registry;
    this.id = id;
    this.kind = spec.kind;
    this.label = spec.label ?? null;
    this.seq = seq;
    this.stream = spec.stream;
    this.createdT = now;
    this.lifetime = lifetime;
    this.targets = [...spec.targets];
    this.sites = [...(spec.sites ?? [])];
    this.spec = spec;
  }

  /** Detached guard: every callback's first line (late callbacks happen after detach [ext-frida §3.6]). */
  get active(): boolean {
    return this.state === "active";
  }

  /**
   * Count one hit against max_hits: "record" / "record-and-stop" (the stop is scheduled with setImmediate, never from
   * inside the listener) / "ignore" (not active, or past the limit).
   */
  hit(): HitOutcome {
    const outcome = hitOutcome(this.active, this.counters.hits, this.lifetime.maxHits);
    if (outcome === "ignore") return outcome;
    this.counters.hits++;
    if (outcome === "record-and-stop") {
      this.state = "stopping";
      this.#registry.scheduleStop(this, "max_hits");
    }
    return outcome;
  }
}

/**
 * An instrument whose lifecycle a feature manages itself: the registry lists it and stops it on instrumentStop and
 * shutdown. WP7/WP8 entries (`registerExternal`) send their own ended message; WP12 entries (`register(id, handle)`)
 * let the registry send it (after a registry-initiated stop, or when the feature reports `ended(id, summary)`).
 */
export interface ExternalInstrument {
  readonly id: InstrumentId;
  readonly kind: InstrumentKind;
  info(): InstrumentInfo;
  stop(reason: EndReason): InstrumentSummary | Promise<InstrumentSummary>;
}

interface ExternalEntry {
  readonly entry: ExternalInstrument;
  readonly seq: number;
  /** the registry sends the ended message for this entry */
  readonly registrySendsEnded: boolean;
  ended: InstrumentSummary | null;
}

type ExternalHandle = { info(): InstrumentInfo; stop(reason: EndReason): Promise<InstrumentSummary> };

export class InstrumentRegistry {
  readonly #core: AgentCore;
  readonly #items = new Map<InstrumentId, Instrument>();
  readonly #externals = new Map<InstrumentId, ExternalEntry>();
  readonly #pendingResume = new Set<Instrument>();
  /** feature callbacks waiting for the host's `resumed` post (whenResumed) */
  readonly #resumeWaiters: (() => void)[] = [];
  #next = 1;
  #heapNoticeSent = false;

  constructor(core: AgentCore) {
    this.#core = core;
  }

  /** Reserve an id (h|p|w|t|o + a counter never reused). */
  nextId(kind: InstrumentKind): InstrumentId {
    return `${INSTRUMENT_PREFIX[kind]}${this.#next++}`;
  }

  /** WP12 seam name for nextId. */
  allocate(kind: InstrumentKind): InstrumentId {
    return this.nextId(kind);
  }

  /** Register an instrument; ResourceLimit{instruments | agent_memory} when the agent is at its bounds. */
  register(spec: InstrumentSpec): Instrument | AgentError;
  /** WP12 seam: an externally managed instrument under a reserved id. */
  register(id: InstrumentId, handle: ExternalHandle): void;
  register(a: InstrumentSpec | InstrumentId, handle?: ExternalHandle): Instrument | AgentError | void {
    if (typeof a !== "string") return this.#register(a);
    if (handle !== undefined)
      this.#addExternal({ id: a, kind: kindOfId(a), info: () => handle.info(), stop: (r) => handle.stop(r) }, true);
  }

  /** WP7/WP8 seam: a feature-managed instrument joins instrumentList / instrumentStop / shutdown. */
  registerExternal(entry: ExternalInstrument): void {
    this.#addExternal(entry, false);
  }

  /** WP12 seam: an external instrument ended on its own (duration, max_hits): send the ended message once. */
  ended(id: InstrumentId, summary: InstrumentSummary): void {
    const ext = this.#externals.get(id);
    if (ext === undefined || ext.ended !== null) return;
    ext.ended = summary;
    if (ext.registrySendsEnded) env.send({ bea: "instrument", id, event: "ended", detail: summary });
  }

  #addExternal(entry: ExternalInstrument, registrySendsEnded: boolean): void {
    const seq = Number.parseInt(entry.id.slice(1), 10);
    this.#externals.set(entry.id, {
      entry,
      seq: Number.isFinite(seq) ? seq : this.#next++,
      registrySendsEnded,
      ended: null,
    });
  }

  /** An external entry is still live (not ended, and the feature does not report it ended). */
  #externalLive(e: ExternalEntry): boolean {
    if (e.ended !== null) return false;
    try {
      return e.entry.info().state !== "ended";
    } catch {
      return false;
    }
  }

  /** InstrumentInfo of every registry and external instrument (status / instrumentList). */
  infos(includeEnded: boolean): InstrumentInfo[] {
    const own = this.list()
      .filter((i) => includeEnded || i.state !== "ended")
      .map((i) => this.info(i));
    const ext: InstrumentInfo[] = [];
    for (const e of this.#externals.values()) {
      try {
        const info = e.ended ?? e.entry.info();
        if (includeEnded || info.state !== "ended") ext.push(info);
      } catch (err) {
        this.#core.fault("external-instrument-info", err);
      }
    }
    return [...own, ...ext];
  }

  /** Stop one instrument by id (registry or external); null when unknown. */
  async stopById(id: InstrumentId, reason: EndReason): Promise<InstrumentSummary | null> {
    const inst = this.#items.get(id);
    if (inst !== undefined) return this.stop(inst, reason);
    const ext = this.#externals.get(id);
    if (ext === undefined) return null;
    if (ext.ended !== null) return ext.ended;
    const summary = await ext.entry.stop(reason);
    this.ended(id, summary);
    return summary;
  }

  /** Ids of live instruments, newest first (instrumentStop "all", shutdown). */
  liveIds(): InstrumentId[] {
    const live: { id: InstrumentId; seq: number }[] = [];
    for (const i of this.#items.values()) if (i.state !== "ended") live.push({ id: i.id, seq: i.seq });
    for (const e of this.#externals.values()) if (this.#externalLive(e)) live.push({ id: e.entry.id, seq: e.seq });
    return live.sort((x, y) => y.seq - x.seq).map((x) => x.id);
  }

  /** Unreverted instruments (shutdown reporting); live ones are reported as "timeout". */
  unreverted(): { id: InstrumentId; detail: string }[] {
    const out: { id: InstrumentId; detail: string }[] = [];
    for (const i of this.#items.values())
      if (i.state !== "ended") out.push({ id: i.id, detail: "timeout" });
      else if (!i.reverted) out.push({ id: i.id, detail: i.unrevertedDetail ?? "not reverted" });
    for (const e of this.#externals.values())
      if (this.#externalLive(e)) out.push({ id: e.entry.id, detail: "timeout" });
      else if (e.ended !== null && !e.ended.reverted)
        out.push({ id: e.entry.id, detail: e.ended.verification?.detail ?? "not reverted" });
    return out;
  }

  #register(spec: InstrumentSpec): Instrument | AgentError {
    const c = this.#core;
    const refusal = this.admissionError();
    if (refusal !== null) return refusal;
    const lifetime = normalizeLifetime(spec.kind, spec.lifetime, c.limits);
    const id = spec.id ?? this.nextId(spec.kind);
    const parsed = Number.parseInt(id.slice(1), 10);
    const inst = new Instrument(
      this,
      id,
      Number.isFinite(parsed) ? parsed : this.#next++,
      spec,
      lifetime,
      c.native.nowUs(),
    );
    this.#items.set(inst.id, inst);
    if (lifetime.clock === "resume" && !c.resumed) this.#pendingResume.add(inst);
    else this.#armDeadline(inst);
    return inst;
  }

  /** null when a new instrument may be created now (max_instruments, agent heap soft limit). */
  admissionError(): AgentError | null {
    const c = this.#core;
    const live = this.liveIds().length;
    if (live >= c.limits.max_instruments)
      return {
        _tag: "ResourceLimit",
        message: "too many active instruments",
        resource: "instruments",
        limit: c.limits.max_instruments,
        observed: live,
      };
    const heap = env.heapBytes();
    if (heap > c.limits.agent_heap_soft_bytes) {
      if (!this.#heapNoticeSent) {
        this.#heapNoticeSent = true;
        env.send({
          bea: "notice",
          code: "heap-soft-limit",
          detail: { heap_bytes: heap, limit: c.limits.agent_heap_soft_bytes },
        });
      }
      return {
        _tag: "ResourceLimit",
        message: "agent heap above its soft limit",
        resource: "agent_memory",
        limit: c.limits.agent_heap_soft_bytes,
        observed: heap,
      };
    }
    this.#heapNoticeSent = false;
    return null;
  }

  get(id: InstrumentId): Instrument | null {
    return this.#items.get(id) ?? null;
  }

  list(): Instrument[] {
    return [...this.#items.values()];
  }

  info(inst: Instrument): InstrumentInfo {
    return {
      id: inst.id,
      kind: inst.kind,
      label: inst.label,
      state: inst.state,
      stream: inst.stream?.id ?? null,
      created_t: inst.createdT,
      deadline_t: inst.deadlineT,
      max_hits: inst.lifetime.maxHits,
      counters: {
        ...inst.counters,
        dropped: inst.stream === null ? inst.counters.dropped : inst.stream.drops.snapshot(),
      },
      targets: [...inst.targets],
    };
  }

  summary(inst: Instrument): InstrumentSummary {
    return {
      ...this.info(inst),
      end_reason: inst.endReason,
      ended_t: inst.endedT,
      reverted: inst.reverted,
      verification: inst.verification,
    };
  }

  /** max_hits reached inside a listener: stop on a later turn. */
  scheduleStop(inst: Instrument, reason: EndReason): void {
    env.defer(() => {
      void this.stop(inst, reason);
    });
  }

  /** The stop protocol (S4 §5.7); idempotent (concurrent callers share one promise). */
  stop(inst: Instrument, reason: EndReason): Promise<InstrumentSummary> {
    if (inst.stopping !== null) return inst.stopping;
    if (inst.state === "ended") return Promise.resolve(this.summary(inst));
    inst.stopping = this.#runStop(inst, reason);
    return inst.stopping;
  }

  /** Stop every live instrument (registry and external), newest first (shutdown; S4 §18). */
  async stopAll(reason: EndReason): Promise<InstrumentSummary[]> {
    const out: InstrumentSummary[] = [];
    for (const id of this.liveIds()) {
      try {
        const summary = await this.stopById(id, reason);
        if (summary !== null) out.push(summary);
      } catch (e) {
        this.#core.fault("instrument-stop", e);
      }
    }
    return out;
  }

  /** The exit hook: every instrument ends with process-exit, no reverts (the process is going away). */
  markProcessExit(): void {
    const now = this.#core.native.nowUs();
    for (const inst of this.#items.values()) {
      if (inst.state === "ended") continue;
      inst.state = "stopping";
      inst.endReason ??= "process-exit";
      inst.endedT = now;
      this.#clearTimer(inst);
    }
  }

  /** The host resumed the target: arm the clock:"resume" deadlines (CI-I3). */
  onResumed(): void {
    this.#core.resumed = true;
    for (const inst of this.#pendingResume) if (inst.state === "active") this.#armDeadline(inst);
    this.#pendingResume.clear();
    for (const fn of this.#resumeWaiters.splice(0)) {
      try {
        fn();
      } catch (e) {
        this.#core.fault("resumed-waiter", e);
      }
    }
  }

  /**
   * Seam for feature-managed (registerExternal) instruments with clock:"resume" (integrator fix, implement stage, WP8
   * change request): run `fn` once the host has posted `resumed`, at once when it already has. Features must not
   * call recv("resumed") themselves: recv is one-shot and FIFO per type, so a feature receiver queued behind the
   * core's persistent one never sees the post (and would steal the next one from the core).
   */
  whenResumed(fn: () => void): void {
    if (this.#core.resumed) fn();
    else this.#resumeWaiters.push(fn);
  }

  /** Module listener: stop instruments whose patch sites lie inside an unloaded module. */
  onModulesChanged(changes: readonly ModuleChange[]): void {
    for (const ch of changes) {
      if (ch.ev !== "U") continue;
      const lo = ch.module.base;
      const hi = ch.module.base.add(ch.module.size);
      for (const inst of this.list()) {
        if (inst.state === "ended") continue;
        if (inst.sites.some((s) => s.compare(lo) >= 0 && s.compare(hi) < 0)) void this.stop(inst, "module-unloaded");
      }
    }
  }

  #armDeadline(inst: Instrument): void {
    const c = this.#core;
    inst.deadlineT = c.native.nowUs() + inst.lifetime.durationMs * 1000;
    inst.timer = env.after(inst.lifetime.durationMs, () => {
      inst.timer = null;
      void this.stop(inst, "duration");
    });
  }

  #clearTimer(inst: Instrument): void {
    if (inst.timer !== null) env.cancelAfter(inst.timer);
    inst.timer = null;
    this.#pendingResume.delete(inst);
  }

  async #runStop(inst: Instrument, reason: EndReason): Promise<InstrumentSummary> {
    const c = this.#core;
    inst.state = "stopping";
    inst.endReason ??= reason;
    this.#clearTimer(inst);
    let outcome: RevertOutcome;
    try {
      outcome = await inst.spec.revert(inst, reason);
    } catch (e) {
      c.fault("instrument-revert", e);
      outcome = {
        reverted: false,
        verification: null,
        detail: reason === "module-unloaded" ? "code unmapped" : "revert failed",
      };
    }
    try {
      Interceptor.flush();
    } catch (e) {
      c.fault("interceptor-flush", e);
    }
    c.stalkerCo.invalidateAll(inst.sites);
    inst.reverted = outcome.reverted;
    inst.verification = outcome.verification;
    inst.unrevertedDetail = outcome.reverted ? null : (outcome.detail ?? "not reverted");
    await new Promise<void>((resolve) => env.defer(resolve));
    if (inst.stream !== null) c.streams.close(inst.stream);
    inst.state = "ended";
    inst.endedT = c.native.nowUs();
    const summary = this.summary(inst);
    env.send({ bea: "instrument", id: inst.id, event: "ended", detail: summary });
    try {
      inst.spec.onEnded?.(inst);
    } catch (e) {
      c.fault("instrument-ended", e);
    }
    if (inst.reverted) this.#prune();
    return summary;
  }

  /** Keep ended instruments listed (bounded); unreverted ones stay until shutdown. */
  #prune(): void {
    const ended = this.list().filter((i) => i.state === "ended" && i.reverted);
    for (const inst of ended.slice(0, Math.max(0, ended.length - 64))) this.#items.delete(inst.id);
  }
}

const kindOfId = (id: InstrumentId): InstrumentKind => {
  const kinds = Object.keys(INSTRUMENT_PREFIX) as InstrumentKind[];
  return kinds.find((k) => INSTRUMENT_PREFIX[k] === id.charAt(0)) ?? "override";
};

let bound: AgentCore | null = null;
const core = (): AgentCore => {
  if (bound === null) throw new Error("instruments.init() has not run");
  return bound;
};

/** Feature contract: index.ts calls init(core) before spreading `rpc`. */
export function init(c: AgentCore): void {
  bound = c;
  c.modules.onChange((changes) => c.instruments.onModulesChanged(changes));
}

const instrumentStop = async (p: InstrumentStopParams) => {
  const c = core();
  if (p === null || typeof p !== "object" || (typeof p.id !== "string" && p.id !== "all"))
    return fail(badParam("id", 'an instrument id or "all"'));
  const reg = c.instruments;
  const ids = p.id === "all" ? reg.liveIds() : [p.id];
  const stopped: InstrumentSummary[] = [];
  const notFound: string[] = [];
  for (const id of ids) {
    const summary = await reg.stopById(id, "requested");
    if (summary === null) notFound.push(id);
    else stopped.push(summary);
  }
  if (p.final_flush) c.streams.flushAll();
  const result: InstrumentStopResult = {
    stopped,
    not_found: notFound,
    unreverted: stopped
      .filter((sm) => !sm.reverted)
      .map((sm) => ({ id: sm.id, detail: sm.verification?.detail ?? "not reverted" })),
  };
  return ok(result);
};

export const rpc = {
  instrumentStop,
  instrumentList: () => ok({ instruments: core().instruments.infos(true) }),
} satisfies Partial<AgentRpcImpl>;

// ---------------------------------------------------------------- WP9 seam (`core.watchSeam`, see watch.ts/trace.ts)

/** What WP9's watch/trace engines receive from the core (their WatchCoreSeam / TraceCoreSeam, structurally). */
export interface WatchSeam {
  attached(): boolean;
  limits(): AgentLimits;
  nowUs(): number;
  nextG(): number;
  registerTrapRouter(router: {
    onSingleStep(d: ExceptionDetails, tid: ThreadId): boolean;
    onGuardPage(d: ExceptionDetails, tid: ThreadId): boolean;
  }): void;
  registerDisposer(dispose: () => void): void;
  openInstrument(spec: SeamInstrumentSpec): SeamInstrumentHandle | AgentError;
  readonly guards: { add(page: NativePointer, entry: ExternalGuardEntry): void; remove(page: NativePointer): void };
  findAccessInsn(pcAfter: NativePointer): {
    insn: NativePointer | null;
    conf: "exact" | "swept" | "heuristic" | "unknown";
    text: string | null;
  };
  fault(where: string, e: unknown): void;
  readonly stalkerCo: AgentCore["stalkerCo"];
}

export interface SeamInstrumentSpec {
  readonly kind: "watch" | "trace";
  readonly rowKind: RowKind;
  readonly layout: BinaryLayout | null;
  readonly lifetime: Lifetime;
  readonly targets: Hex[];
  readonly label?: string;
  revert(reason: EndReason): RevertOutcome | Promise<RevertOutcome>;
}

export interface SeamInstrumentHandle {
  readonly id: InstrumentId;
  readonly streamId: StreamId;
  isActive(): boolean;
  emitJson(row: unknown[], estBytes: number): void;
  emitBinary(records: ArrayBuffer, count: number): void;
  hit(): boolean;
  count(counter: "filtered" | "errors" | "bea_guard_suspended", n?: number): void;
  end(reason: EndReason): void;
  notice(code: NoticeMessage["code"], detail: Record<string, unknown>): void;
}

const openSeamInstrument = (c: AgentCore, spec: SeamInstrumentSpec): SeamInstrumentHandle | AgentError => {
  const refusal = c.instruments.admissionError();
  if (refusal !== null) return refusal;
  const id = c.instruments.nextId(spec.kind);
  const stream = c.streams.open({
    instrument: id,
    kind: spec.rowKind,
    enc: spec.layout === null ? "json" : "bin",
    ...(spec.layout === null ? {} : { layout: spec.layout.id, recBytes: spec.layout.rec_bytes }),
  });
  if (!(stream instanceof Stream)) return stream;
  const inst = c.instruments.register({
    id,
    kind: spec.kind,
    label: spec.label ?? null,
    lifetime: spec.lifetime,
    targets: spec.targets,
    stream,
    revert: (_i, reason) => spec.revert(reason),
  });
  if (!(inst instanceof Instrument)) {
    c.streams.close(stream);
    return inst;
  }
  return {
    id,
    streamId: stream.id,
    isActive: () => inst.active,
    emitJson: (row, estBytes) => {
      if (c.streams.emit(stream, row, estBytes)) inst.counters.recorded++;
    },
    emitBinary: (records, count) => {
      const t = c.native.nowUs();
      if (c.streams.emitBin(stream, { bytes: new Uint8Array(records), n: count, g0: 0, g1: 0, t0: t, t1: t }))
        inst.counters.recorded += count;
    },
    hit: () => inst.hit() !== "ignore",
    count: (counter, n = 1) => {
      inst.counters[counter] += n;
    },
    end: (reason) => {
      void c.instruments.stop(inst, reason);
    },
    notice: (code, detail) => env.send({ bea: "notice", code, detail }),
  };
};

export const createWatchSeam = (c: AgentCore): WatchSeam => ({
  attached: () => c.config.session?.owned === false,
  limits: () => c.limits,
  nowUs: () => c.native.nowUs(),
  nextG: () => c.native.nextG(),
  registerTrapRouter: (router) => {
    c.exceptions.registerTrapRouter({
      name: "watch",
      order: 10,
      onSingleStep: (d, tid) => router.onSingleStep(d, tid),
      onGuardPage: (d, tid) => router.onGuardPage(d, tid),
    });
  },
  registerDisposer: (dispose) => {
    c.hooks.onDispose.push(dispose);
  },
  openInstrument: (spec) => openSeamInstrument(c, spec),
  guards: {
    add: (page, entry) => c.guards.addExternal(page, entry),
    remove: (page) => c.guards.removeExternal(page),
  },
  findAccessInsn: (pcAfter) => {
    const r = findAccessInsn(c, pcAfter);
    return { insn: r.address === null ? null : ptr(r.address), conf: r.conf, text: r.text };
  },
  fault: (where, e) => c.fault(where, e),
  stalkerCo: c.stalkerCo,
});
