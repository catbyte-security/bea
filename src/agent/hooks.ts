// =================================================================================================
// src/agent/hooks.ts — WP7-HOOK agent hook engine: `hookInstall` (S4 §10.2–10.4, §10.8, §13.4; S6 §2.5, §4.20).
// JS tier: ONE Interceptor listener per address (and per kind: function entry vs instruction probe) multiplexing
// every hook instrument on it; Win64 captures (slots by position, float bits straight from xmm, stack slots, any
// register, deref chains, strings, bytes), return value (xmm0 or rax), caller, ACCURATE backtrace. Native tier:
// hookNative.ts (CModule ring, binary hook-native/1 batches). Install: resolve → executable check → thunk
// resolution → deny/caution list → replace-conflict → originals → attach (retry relocation:"forced") → flush →
// Stalker invalidate → patch check. Every callback starts with the detached guard and skips BEA's own oracle-call
// threads (`agentCallTids`, CT-M2) and cloaked agent threads unless the instrument observes agent calls.
//
// Core coupling: the engine reaches the WP3 core runtime ONLY through `HookCoreLink` (below), resolved once by
// `linkFromCore`; without core hook services it runs standalone (own clock, streams and lifetimes).
// =================================================================================================
import type {
  AgentError,
  AgentFeature,
  AgentLimits,
  AgentResult,
  AgentRpcImpl,
  BinaryLayout,
  DropCounters,
  DropReason,
  EffectHint,
  EndReason,
  Hex,
  HookInstallParams,
  HookInstallResult,
  HookRow,
  InstrumentCounters,
  InstrumentId,
  InstrumentInfo,
  InstrumentSummary,
  Lifetime,
  ResolvedTarget,
  StreamId,
  ThreadId,
  ValueCell,
} from "../shared/agentProtocol.js";
import { HOOK_CAUTION_LIST, HOOK_DENY_LIST } from "../shared/apiProfiles.js";
import { BINARY_LAYOUTS } from "../shared/binaryLayouts.js";
import { fail, ok } from "./errors.js";
import { NativeHook, NativeHookTier, StandaloneClock, nativeFieldOffset, type NativeSymbols } from "./hookNative.js";
import {
  arrayCell,
  bytesOfHex64,
  cellOfWord,
  decodeText,
  hexBytes,
  scalarCell,
  textReadBytes,
} from "./pure/hookCells.js";
import {
  DENY_ALTERNATIVES,
  INSTALL_ALTERNATIVES,
  TYPE_BYTES,
  TokenBucket,
  decodeThunk,
  describeSource,
  isTextType,
  looksPatched,
  planHook,
  siteRuleHit,
  type CapturePlan,
  type CaptureSource,
  type HookPlan,
  type ResolvedSiteRule,
  type RetPlan,
} from "./pure/hookPlan.js";
import type { AgentCore } from "./state.js";

// ------------------------------------------------------------------------------------------------ core link
/** One hook instrument as handed to the core instrument registry + event pipeline (S4 §5.7, §6). */
export interface HookRegistration {
  readonly label: string | null;
  readonly targets: readonly Hex[];
  /** code addresses this hook patches (Stalker invalidate, module-unload stops) */
  readonly sites: readonly NativePointer[];
  readonly lifetime: Lifetime;
  readonly stream:
    | { readonly enc: "json"; readonly kind: "hook/1" }
    | { readonly enc: "bin"; readonly kind: "hook-native/1"; readonly layout: BinaryLayout };
  /** before every (final) flush of the stream: native rings drain here and native counters refresh */
  beforeFlush(): void;
  /** stop protocol step 2 (detach + verify; the registry flushes Interceptor and invalidates Stalker too) */
  revert(): RevertResult;
}
export interface RevertResult {
  readonly reverted: boolean;
  readonly verification: InstrumentSummary["verification"];
  readonly detail?: string;
}
/** What the registry hands back: the registry owns id, lifetime, counters, max_hits and the stop protocol. */
export interface HookRegistered {
  readonly id: InstrumentId;
  readonly stream: StreamId;
  /** registry-owned counters the engine increments (status / summaries read them) */
  readonly counters: InstrumentCounters;
  /** detached guard: false from the moment the instrument starts stopping */
  readonly active: boolean;
  /** one hit against max_hits; false = ignore (past the limit or not active). Reaching the limit schedules the stop. */
  hit(): boolean;
  /** JSON row admission into the instrument stream (S4 §6.2) */
  emit(row: HookRow, estBytes: number): void;
  /** whole hook-native/1 records (g/t of the first and last record for the batch header) */
  emitBin(data: ArrayBuffer, records: number): void;
  /** drops counted by the engine (rate limits, ring overruns, torn records) */
  noteDropped(reason: DropReason, n: number): void;
  /** schedule the registry stop on a later turn (native max_hits; never synchronously inside a listener) */
  requestStop(reason: "max_hits" | "error"): void;
  /** install failed after registration: end it without a revert of anything */
  abandon(): void;
}
/** Everything the hook engine needs from the agent core (WP3). */
export interface HookCoreLink {
  /** effective limits (defaults until hello, then the clamped hello limits) */
  limits(): AgentLimits;
  /** agent-global row sequence and µs clock (core CModule bea_next_g / bea_now_us) */
  nextG(): number;
  nowUs(): number;
  /** core CModule symbols for feature CModules (native tier) */
  readonly nativeSymbols: NativeSymbols | null;
  /** S4 §13.4: true while a BEA oracle call that does not observe hooks runs on `tid` (CT-M2) */
  suppresses(tid: ThreadId): boolean;
  register(reg: HookRegistration): HookRegistered | AgentError;
  /** originals registry (S4 §8.4), refcounted per site and owner */
  saveOriginals?(site: NativePointer, len: number, owner: string): void;
  releaseOriginals?(site: NativePointer, owner: string): void;
  /** true while another BEA patch keeps `site` patched (verification after our detach) */
  patchedByOthers?(site: NativePointer): boolean;
  /** after Interceptor.flush: remember the patched head (fingerprint) */
  markPatched?(site: NativePointer): void;
  /** StalkerCoordinator.invalidateAll (S4 §12.1); returns the threads invalidated */
  invalidate?(sites: readonly NativePointer[]): ThreadId[];
  /** a replace-mode override instrument at `site` (HookConflict), else null */
  replaceOwner?(site: NativePointer): InstrumentId | null;
  /** the .pdata function containing `va` (core inspect findFunction) */
  findFunction?(va: NativePointer): { readonly base: NativePointer; readonly size: number } | null;
  /** keep native memory alive until the core's keep-alive settles (S4 §5.4 lifetime rule) */
  pin?<T>(value: T): T;
  /** D-INT-44 / CT-I5: run a capture read with BEA guard pages over [base, base+size) suspended */
  guardedRead?<T>(base: NativePointer, size: number, read: () => T): T;
  /**
   * A-18 guard-aware read (the core's memory.ts safeReadBytes over its cached VirtualQuery planner): the readable
   * prefix of [base, base+size), stopping before unmapped/unreadable memory and before a page carrying the TARGET's
   * PAGE_GUARD (touching it would consume the guard); BEA guard pages are suspended. Review fix AGENT-10.
   */
  safeRead?(base: NativePointer, size: number): CaptureRead;
}

/** A guard-aware read's readable prefix and why it stopped (null: complete). */
interface CaptureRead {
  readonly bytes: Uint8Array;
  readonly stop: { readonly reason: string } | null;
}

/**
 * The WP3 core services the adapter uses (src/agent/state.ts AgentCore; mirrored structurally so the hook engine also
 * compiles and runs against the day-0 core of the raw-agent harness). Names and shapes as of WP3's implementation.
 */
interface Wp3Stream {
  readonly id: StreamId;
  drain: (() => void) | null;
}
interface Wp3Instrument {
  readonly id: InstrumentId;
  readonly active: boolean;
  readonly counters: InstrumentCounters;
  hit(): "record" | "record-and-stop" | "ignore";
}
interface Wp3Core {
  readonly native: {
    nextG(): number;
    nowUs(): number;
    readonly symbols: Readonly<Record<string, NativePointer>>;
  };
  readonly calls: { suppresses(tid: ThreadId): boolean };
  readonly streams: {
    open(spec: {
      readonly instrument: InstrumentId | null;
      readonly kind: "hook/1" | "hook-native/1";
      readonly enc: "json" | "bin";
      readonly layout?: "hook-native/1";
      readonly recBytes?: number;
    }): Wp3Stream | AgentError;
    emit(s: Wp3Stream, row: unknown[], estBytes?: number): boolean;
    emitBin(
      s: Wp3Stream,
      chunk: { bytes: Uint8Array; n: number; g0: number; g1: number; t0: number; t1: number },
    ): boolean;
    drop(s: Wp3Stream, reason: DropReason, n?: number): void;
    close(s: Wp3Stream): unknown;
  };
  readonly instruments: {
    register(spec: {
      readonly kind: "hook";
      readonly label: string | null;
      readonly lifetime: Partial<Lifetime>;
      readonly targets: readonly Hex[];
      readonly stream: Wp3Stream | null;
      readonly sites: readonly NativePointer[];
      readonly revert: (inst: Wp3Instrument, reason: EndReason) => RevertResult;
    }): Wp3Instrument | AgentError;
    scheduleStop(inst: Wp3Instrument, reason: EndReason): void;
    stop(inst: Wp3Instrument, reason: EndReason): Promise<unknown>;
  };
  readonly originals: {
    save(site: NativePointer, n?: number, owner?: string): unknown;
    release(site: NativePointer, owner?: string): unknown;
    markPatched(site: NativePointer): void;
    patchedByOthers(site: NativePointer): boolean;
  };
  readonly stalkerCo: { invalidateAll(sites: readonly NativePointer[]): ThreadId[] };
  readonly keep: { pin<T>(value: T): T };
  readonly guards?: {
    readonly size: number;
    withBeaGuardsSuspended<T>(ranges: readonly { base: NativePointer; size: number }[], fn: () => T): T;
  };
}

const u64At = (v: DataView, o: number): number => v.getUint32(o, true) + v.getUint32(o + 4, true) * 2 ** 32;
/** g/t of the first and last record of a hook-native/1 chunk (batch header). */
const binBounds = (data: ArrayBuffer, records: number): { g0: number; g1: number; t0: number; t1: number } => {
  const first = new DataView(data, 0, 16);
  const last = new DataView(data, (records - 1) * 160, 16);
  return { g0: u64At(first, 0), g1: u64At(last, 0), t0: u64At(first, 8), t1: u64At(last, 8) };
};

/** Adapter over WP3's InstrumentRegistry + StreamRegistry (the production path). */
function wp3Link(core: AgentCore, c: Wp3Core): HookCoreLink {
  const sym = c.native.symbols;
  const next = sym["bea_next_g"];
  const now = sym["bea_now_us"];
  const inCall = sym["bea_in_agent_call"];
  return {
    limits: () => core.limits,
    nextG: () => c.native.nextG(),
    nowUs: () => c.native.nowUs(),
    nativeSymbols:
      next !== undefined && now !== undefined && inCall !== undefined
        ? { bea_next_g: next, bea_now_us: now, bea_in_agent_call: inCall }
        : null,
    suppresses: (tid) => c.calls.suppresses(tid),
    register: (reg) => {
      const opened = c.streams.open(
        reg.stream.enc === "json"
          ? { instrument: null, kind: "hook/1", enc: "json" }
          : {
              instrument: null,
              kind: "hook-native/1",
              enc: "bin",
              layout: "hook-native/1",
              recBytes: reg.stream.layout.rec_bytes,
            },
      );
      if (isAgentError(opened)) return opened;
      const stream = opened;
      let abandoned = false;
      const inst = c.instruments.register({
        kind: "hook",
        label: reg.label,
        lifetime: reg.lifetime,
        targets: reg.targets,
        stream,
        sites: reg.sites,
        revert: () => (abandoned ? { reverted: true, verification: null } : reg.revert()),
      });
      if (isAgentError(inst)) {
        c.streams.close(stream);
        return inst;
      }
      // the stream was opened before its instrument id existed (WP3 allocates it in register)
      (stream as unknown as { instrument: InstrumentId }).instrument = inst.id;
      stream.drain = () => reg.beforeFlush();
      return {
        id: inst.id,
        stream: stream.id,
        counters: inst.counters,
        get active() {
          return inst.active;
        },
        hit: () => inst.hit() !== "ignore",
        emit: (row, est) => void c.streams.emit(stream, row as unknown as unknown[], est),
        emitBin: (data, records) =>
          void c.streams.emitBin(stream, { bytes: new Uint8Array(data), n: records, ...binBounds(data, records) }),
        noteDropped: (reason, n) => c.streams.drop(stream, reason, n),
        requestStop: (reason) => c.instruments.scheduleStop(inst, reason === "max_hits" ? "max_hits" : "error"),
        abandon: () => {
          abandoned = true;
          void c.instruments.stop(inst, "error");
        },
      };
    },
    saveOriginals: (site, len, owner) => void c.originals.save(site, len, owner),
    releaseOriginals: (site, owner) => void c.originals.release(site, owner),
    patchedByOthers: (site) => c.originals.patchedByOthers(site),
    markPatched: (site) => c.originals.markPatched(site),
    invalidate: (sites) => c.stalkerCo.invalidateAll(sites),
    pin: (value) => c.keep.pin(value),
    guardedRead: (base, size, read) =>
      c.guards === undefined || c.guards.size === 0 ? read() : c.guards.withBeaGuardsSuspended([{ base, size }], read),
    ...(typeof (core as { safeRead?: unknown }).safeRead === "function"
      ? { safeRead: (base: NativePointer, size: number) => (core as unknown as SafeReadCore).safeRead(base, size) }
      : {}),
  };
}
/** The core's guard-aware read seam (state.ts AgentCore.safeRead), bound structurally. */
interface SafeReadCore {
  safeRead(base: NativePointer, size: number): CaptureRead;
}

/**
 * Resolve the link. An explicit `core.hookLink` wins (tests); WP3's core services (InstrumentRegistry, StreamRegistry,
 * NativeCore, CallRegistry, OriginalBytes, StalkerCoordinator) are the production path; without them the engine runs
 * STANDALONE (own clock CModule, own streams sending batches, own lifetimes) and registers each hook with
 * `core.instruments.registerExternal` when that exists (the convention WP8 profiles uses), so it stays usable against
 * the day-0 core and in the raw-agent acceptance harness.
 */
export function linkFromCore(core: AgentCore): HookCoreLink {
  const c = core as AgentCore & {
    readonly hookLink?: HookCoreLink;
    readonly instruments?: { readonly registerExternal?: (entry: ExternalInstrument) => void };
  } & Partial<Wp3Core>;
  if (c.hookLink !== undefined) return c.hookLink;
  if (
    typeof c.native?.nextG === "function" &&
    typeof c.streams?.open === "function" &&
    typeof (c.instruments as Partial<Wp3Core["instruments"]> | undefined)?.register === "function" &&
    typeof c.calls?.suppresses === "function"
  )
    return wp3Link(core, c as unknown as Wp3Core);
  let local: StandaloneClock | null = null;
  const clock = (): StandaloneClock => (local ??= new StandaloneClock());
  const registry = new LocalHookRegistry(core, () => clock(), c.instruments?.registerExternal?.bind(c.instruments));
  return {
    limits: () => core.limits,
    nextG: () => clock().nextG(),
    nowUs: () => clock().nowUs(),
    get nativeSymbols(): NativeSymbols {
      return clock().symbols;
    },
    suppresses: () => false,
    register: (reg) => registry.register(reg),
  };
}
/** Registry entry for instruments that own their stream (the shape WP8 profiles registers too). */
export interface ExternalInstrument {
  readonly id: InstrumentId;
  readonly kind: "hook";
  info(): InstrumentInfo;
  stop(reason: EndReason): InstrumentSummary;
}

// ------------------------------------------------------------------------------------------------ standalone registry
const FLUSH_MS = 50;

/** One hook stream sending its own batches (S4 §6.1–6.3): JSON rows every 50 ms / batch_max_rows; binary at once. */
class LocalStream {
  #rows: HookRow[] = [];
  #bseq = 0;
  #announced = false;
  #closed = false;
  #delta: DropCounters = {};
  #g1 = 0;
  #t1 = 0;
  readonly total: DropCounters = {};

  constructor(
    readonly id: StreamId,
    readonly instrument: InstrumentId,
    readonly enc: "json" | "bin",
    private readonly limits: () => AgentLimits,
  ) {}

  /** S4 announcement rule: no batch before the RPC that created the stream has replied. */
  announce(): void {
    this.#announced = true;
  }

  drop(reason: DropReason, n: number): void {
    this.#delta[reason] = (this.#delta[reason] ?? 0) + n;
    this.total[reason] = (this.total[reason] ?? 0) + n;
  }

  push(row: HookRow): void {
    if (this.#closed) return this.drop("stopped", 1);
    if (this.#rows.length >= this.limits().stream_max_pending_rows) return this.drop("buffer_full", 1);
    this.#rows.push(row);
    if (this.#announced && this.#rows.length >= this.limits().batch_max_rows) this.flush(false);
  }

  /** Binary records go out at once (the native drain already batches them, ≤ batch_max_bin_bytes). */
  pushBin(data: ArrayBuffer, records: number): void {
    if (this.#closed) return this.drop("stopped", records);
    if (records === 0) return;
    const b = binBounds(data, records);
    this.#g1 = b.g1;
    this.#t1 = b.t1;
    this.#sendBin(data, records, b.g0, b.t0, false);
  }

  #sendBin(data: ArrayBuffer, n: number, g0: number, t0: number, final: boolean): void {
    send(
      {
        bea: "batch",
        stream: this.id,
        instrument: this.instrument,
        bseq: ++this.#bseq,
        kind: "hook-native/1",
        n,
        g0,
        g1: this.#g1,
        t0,
        t1: this.#t1,
        dropped: this.#takeDelta(),
        final,
        enc: "bin",
        layout: "hook-native/1",
        rec_bytes: 160,
      },
      data,
    );
  }

  #takeDelta(): DropCounters {
    const d = this.#delta;
    this.#delta = {};
    return d;
  }

  flush(final: boolean): void {
    if (!this.#announced && !final) return;
    if (this.enc === "bin") {
      if (final || Object.keys(this.#delta).length > 0) this.#sendBin(new ArrayBuffer(0), 0, this.#g1, this.#t1, final); // drops / final marker
      return;
    }
    if (this.#rows.length === 0 && !final && Object.keys(this.#delta).length === 0) return;
    const max = Math.max(1, this.limits().batch_max_rows);
    do {
      const rows = this.#rows.splice(0, max);
      const head = rows[0];
      const tail = rows[rows.length - 1];
      if (tail !== undefined) {
        this.#g1 = tail[0];
        this.#t1 = tail[1];
      }
      send({
        bea: "batch",
        stream: this.id,
        instrument: this.instrument,
        bseq: ++this.#bseq,
        kind: "hook/1",
        n: rows.length,
        g0: head?.[0] ?? this.#g1,
        g1: this.#g1,
        t0: head?.[1] ?? this.#t1,
        t1: this.#t1,
        dropped: this.#takeDelta(),
        final: final && this.#rows.length === 0,
        enc: "json",
        rows,
      });
    } while (this.#rows.length > 0);
  }

  close(): void {
    this.#announced = true;
    this.flush(true);
    this.#closed = true;
  }
}

interface LocalEntry {
  readonly id: InstrumentId;
  readonly reg: HookRegistration;
  readonly stream: LocalStream;
  readonly counters: InstrumentCounters;
  readonly createdT: number;
  readonly deadlineT: number | null;
  state: "active" | "stopping" | "ended";
  timer: ReturnType<typeof setTimeout> | null;
  summary: InstrumentSummary | null;
  abandoned: boolean;
}

/** Ids, lifetimes, max_hits and the stop protocol (S4 §5.7) for hooks when the core has no registry of its own. */
class LocalHookRegistry {
  #next = 0;
  readonly #entries = new Map<InstrumentId, LocalEntry>();
  #flushTimer: ReturnType<typeof setInterval> | null = null;

  constructor(
    private readonly core: AgentCore,
    private readonly clock: () => { readonly nextG: () => number; readonly nowUs: () => number },
    private readonly registerExternal: ((entry: ExternalInstrument) => void) | undefined,
  ) {}

  register(reg: HookRegistration): HookRegistered | AgentError {
    const limits = this.core.limits;
    const live = [...this.#entries.values()].filter((e) => e.state !== "ended").length;
    if (live >= limits.max_instruments)
      return {
        _tag: "ResourceLimit",
        message: "too many instruments",
        resource: "instruments",
        limit: limits.max_instruments,
      };
    const n = ++this.#next;
    const id = `h${n}`;
    const stream = new LocalStream(`sh${n}`, id, reg.stream.enc, () => this.core.limits);
    const now = this.clock().nowUs();
    const duration = reg.lifetime.duration_ms;
    const maxHits = reg.lifetime.max_hits;
    const entry: LocalEntry = {
      id,
      reg,
      stream,
      counters: freshCounters(),
      createdT: now,
      deadlineT: duration > 0 ? now + duration * 1000 : null,
      state: "active",
      timer: null,
      summary: null,
      abandoned: false,
    };
    this.#entries.set(id, entry);
    // The RPC reply goes out when the export returns; batches may follow from the next turn on.
    setTimeout(() => stream.announce(), 0);
    // clock:"resume" needs the host's `resumed` post, which only the core receives: standalone arms at install.
    if (duration > 0) entry.timer = setTimeout(() => this.stop(id, "duration"), duration);
    this.#flushTimer ??= setInterval(() => this.flushAll(), FLUSH_MS);
    this.registerExternal?.({
      id,
      kind: "hook",
      info: () => this.info(entry),
      stop: (reason) => this.stop(id, reason),
    });
    const schedule = (reason: EndReason): void => {
      setTimeout(() => this.stop(id, reason), 0);
    };
    return {
      id,
      stream: stream.id,
      counters: entry.counters,
      get active() {
        return entry.state === "active";
      },
      hit: () => {
        if (entry.state !== "active") return false;
        entry.counters.hits++;
        if (maxHits > 0 && entry.counters.hits >= maxHits) {
          entry.state = "stopping"; // the hit reaching the limit is recorded; later callbacks return at once
          schedule("max_hits");
        }
        return true;
      },
      emit: (row) => stream.push(row),
      emitBin: (data, records) => stream.pushBin(data, records),
      noteDropped: (reason, k) => stream.drop(reason, k),
      requestStop: (reason) => schedule(reason === "max_hits" ? "max_hits" : "error"),
      abandon: () => {
        entry.abandoned = true;
        if (entry.timer !== null) clearTimeout(entry.timer);
        entry.state = "ended";
        this.#entries.delete(id);
      },
    };
  }

  private flushAll(): void {
    for (const e of this.#entries.values()) {
      if (e.state === "ended") continue;
      e.reg.beforeFlush();
      e.stream.flush(false);
    }
  }

  private info(e: LocalEntry): InstrumentInfo {
    return {
      id: e.id,
      kind: "hook",
      label: e.reg.label,
      state: e.state,
      stream: e.stream.id,
      created_t: e.createdT,
      deadline_t: e.deadlineT,
      max_hits: e.reg.lifetime.max_hits,
      counters: { ...e.counters, dropped: { ...e.counters.dropped, ...e.stream.total } },
      targets: [...e.reg.targets],
    };
  }

  /** S4 §5.7 stop protocol: detached guard, revert, drain, final batch, `ended` message. Idempotent. */
  stop(id: InstrumentId, reason: EndReason): InstrumentSummary {
    const e = this.#entries.get(id);
    if (e === undefined) throw new Error(`unknown hook instrument ${id}`);
    if (e.summary !== null) return e.summary;
    e.state = "stopping";
    if (e.timer !== null) clearTimeout(e.timer);
    let outcome: RevertResult;
    try {
      outcome = e.reg.revert();
    } catch (err) {
      outcome = { reverted: false, verification: { kind: "bytes", ok: false, detail: errorText(err).slice(0, 200) } };
    }
    e.reg.beforeFlush();
    e.stream.close();
    e.state = "ended";
    const summary: InstrumentSummary = {
      ...this.info(e),
      end_reason: reason,
      ended_t: this.clock().nowUs(),
      reverted: outcome.reverted,
      verification: outcome.verification,
    };
    e.summary = summary;
    send({ bea: "instrument", id, event: "ended", detail: summary });
    if ([...this.#entries.values()].every((x) => x.state === "ended") && this.#flushTimer !== null) {
      clearInterval(this.#flushTimer);
      this.#flushTimer = null;
    }
    return summary;
  }
}

// ------------------------------------------------------------------------------------------------ engine state
interface JsSite {
  readonly key: string;
  readonly address: NativePointer;
  readonly probe: boolean;
  readonly patchedAt: readonly NativePointer[];
  readonly before: readonly { readonly address: Hex; readonly hex: string }[];
  relocation: "default" | "forced";
  listener: InvocationListener | null;
  hooks: JsHook[];
  /** instrument id that saved the originals of this site (released by the last hook to leave) */
  owner: string;
}
interface Pending {
  readonly g: number;
  readonly t: number;
  readonly cells: ValueCell[];
  /** per leave-capture: the slot value saved at enter (argument registers are volatile) */
  readonly saved: (Uint8Array | null)[];
  readonly bt: string[] | null;
}
interface JsHook {
  readonly plan: HookPlan;
  readonly site: JsSite;
  readonly threads: ReadonlySet<number> | null;
  readonly callers: ReadonlySet<string> | null;
  readonly rate: TokenBucket | null;
  readonly btRate: TokenBucket | null;
  readonly gpr: boolean;
  readonly reg: HookRegistered;
  state: "active" | "ended";
  enters: number;
  leaves: number;
}

const GPRS = [
  "rax",
  "rbx",
  "rcx",
  "rdx",
  "rsi",
  "rdi",
  "rbp",
  "rsp",
  "r8",
  "r9",
  "r10",
  "r11",
  "r12",
  "r13",
  "r14",
  "r15",
  "rip",
] as const;

const freshCounters = (): InstrumentCounters => ({
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
const hexOf = (p: NativePointer): Hex => p.toString() as Hex;
const errorText = (e: unknown): string => (e instanceof Error ? e.message : String(e)).slice(0, 512);
const badParams = (issues: readonly { path: string; problem: string }[]): AgentResult<never> =>
  fail({ _tag: "BadParams", message: "invalid hookInstall parameters", issues: [...issues] });
const isAgentError = (v: unknown): v is AgentError =>
  typeof v === "object" && v !== null && typeof (v as { _tag?: unknown })._tag === "string";
/** A stopped native hook's ring is dropped this long (at least) after the detach (AGENT-5). */
const NATIVE_SETTLE_MS = 250;

// ------------------------------------------------------------------------------------------------ value capture
/** The 64-bit word a source holds (pointer bases, integer slots). Float-class sources yield their low 8 bytes. */
function sourceBytes(ic: InvocationContext, args: InvocationArguments, src: CaptureSource): Uint8Array {
  const ctx = ic.context as X64CpuContext;
  switch (src.kind) {
    case "slot-int": {
      const v = args[src.p];
      return bytesOfHex64(v === undefined ? "0x0" : v.toString());
    }
    case "slot-xmm":
      return new Uint8Array(ctx[`xmm${src.p}` as "xmm0"]);
    case "slot-stack": {
      const ab = ctx.rsp.add(src.offset).readByteArray(8);
      return ab === null ? new Uint8Array(8) : new Uint8Array(ab);
    }
    case "reg": {
      if (src.reg.startsWith("xmm")) return new Uint8Array(ctx[src.reg as "xmm0"]);
      return bytesOfHex64((ctx[src.reg as "rax"] as NativePointer).toString());
    }
  }
}

/** Capture reads into target memory; the engine routes them through the core guard table when it has one. */
let guarded: <T>(base: NativePointer, size: number, read: () => T) => T = (_b, _s, read) => read();
/** The core's guard-aware reader (AGENT-10); null on a link without one (standalone: raw reads as before). */
let safeRead: ((base: NativePointer, size: number) => CaptureRead) | null = null;

/** A capture read stopped before memory it must not touch: {e:"guard"} (a target PAGE_GUARD page) or {e:"av"}. */
class CaptureStop extends Error {
  constructor(readonly cell: "guard" | "av") {
    super(cell);
  }
}
const stopOf = (r: CaptureRead): CaptureStop => new CaptureStop(r.stop?.reason === "guard-page" ? "guard" : "av");

const pointerOf = (bytes: Uint8Array): NativePointer => ptr(hexBytesLE(bytes));
const hexBytesLE = (b: Uint8Array): string => {
  let s = "";
  for (let i = Math.min(8, b.length) - 1; i >= 0; i--) s += ((b[i] ?? 0) + 0x100).toString(16).slice(1);
  return `0x${s}`;
};

/**
 * Read `size` bytes; text reads decode the readable prefix when the full window is not readable. With the core's
 * guard-aware reader, a window that would touch a target guard page stops before it (CaptureStop "guard"): the raw
 * read would have consumed the guard, which the OS clears before Frida reports the fault (AGENT-10).
 */
function readWindow(p: NativePointer, size: number, text: boolean): Uint8Array {
  if (safeRead !== null) {
    const r = safeRead(p, size);
    if (r.bytes.length === size || (text && r.bytes.length > 0)) return r.bytes;
    throw stopOf(r);
  }
  try {
    const ab = guarded(p, size, () => p.readByteArray(size));
    if (ab !== null) return new Uint8Array(ab);
  } catch (e) {
    if (!text) throw e;
  }
  const page = Process.pageSize;
  const rest = Math.min(size, page - Number(BigInt(p.toString()) % BigInt(page)));
  const ab = guarded(p, rest, () => p.readByteArray(rest));
  return ab === null ? new Uint8Array(0) : new Uint8Array(ab);
}

/** Final read at `p` with the capture's type, count and text/bytes cap. */
function readValue(p: NativePointer, type: CapturePlan["type"], count: number, maxLen: number): ValueCell {
  if (p.isNull()) return { e: "null", a: "0x0" };
  try {
    if (isTextType(type)) {
      const enc = type as "utf8" | "utf16" | "ansi";
      const text = decodeText(readWindow(p, textReadBytes(enc, maxLen), true), enc, maxLen);
      return text.trunc ? { s: text.s, trunc: true } : { s: text.s };
    }
    if (type === "bytes") return { x: hexBytes(readWindow(p, maxLen, false)) };
    const size = (TYPE_BYTES[type] ?? 8) * Math.max(1, count);
    return arrayCell(type, readWindow(p, size, false), count);
  } catch (e) {
    return { e: e instanceof CaptureStop ? e.cell : "av", a: hexOf(p) };
  }
}

/** One pointer of a deref chain, guard-aware when the core offers it. */
function readPointerAt(at: NativePointer): NativePointer {
  if (safeRead === null) return guarded(at, 8, () => at.readPointer());
  const r = safeRead(at, 8);
  if (r.bytes.length < 8) throw stopOf(r);
  return pointerOf(r.bytes);
}

/** S6 §5.1 deref: p = src + d0; each further offset p = readPointer(p) + d; then read at p. */
function derefRead(
  base: NativePointer,
  deref: readonly number[],
  type: CapturePlan["type"],
  count: number,
  maxLen: number,
): ValueCell {
  if (deref.length === 0) return readValue(base, type, count, maxLen);
  if (base.isNull()) return { e: "null", a: "0x0" };
  let p = base.add(deref[0] ?? 0);
  for (let i = 1; i < deref.length; i++) {
    let next: NativePointer;
    try {
      next = readPointerAt(p);
    } catch (e) {
      return { e: e instanceof CaptureStop ? e.cell : "av", a: hexOf(p) };
    }
    if (next.isNull()) return { e: "null", a: hexOf(p) };
    p = next.add(deref[i] ?? 0);
  }
  return readValue(p, type, count, maxLen);
}

/** One capture cell from a source word/bytes (no deref: scalars are the value itself, text/bytes read at it). */
function cellFrom(bytes: Uint8Array, c: CapturePlan | RetPlan): ValueCell {
  if (c.deref.length > 0) return derefRead(pointerOf(bytes), c.deref, c.type, c.count, c.maxLen);
  if (isTextType(c.type) || c.type === "bytes") return readValue(pointerOf(bytes), c.type, c.count, c.maxLen);
  return scalarCell(c.type, bytes, 0);
}

// ------------------------------------------------------------------------------------------------ engine
class HookEngine {
  readonly #core: AgentCore;
  #link: HookCoreLink | null = null;
  #native: NativeHookTier | null = null;
  #nativeError: string | null = null;
  #nativeCount = 0;
  #nativeIndex = 0;
  /** native hooks whose ring/staging buffers are still held (installed, or stopped and settling) */
  readonly #nativeHeld = new Set<NativeHook>();
  #nativeBytes(): number {
    let n = 0;
    for (const h of this.#nativeHeld) n += h.bytes;
    return n;
  }
  #rules: ResolvedSiteRule[] | null = null;
  readonly #sites = new Map<string, JsSite>();
  readonly #modules: ModuleMap;
  #modulesAt = 0;

  constructor(core: AgentCore) {
    this.#core = core;
    this.#modules = new ModuleMap();
    this.#modulesAt = Date.now();
  }

  /** boot: resolve the core link, compile the native tier, publish features */
  boot(): void {
    const link = this.link();
    if (link.guardedRead !== undefined) {
      const read = link.guardedRead.bind(link);
      guarded = (base, size, fn) => read(base, size, fn);
    }
    if (link.safeRead !== undefined) safeRead = link.safeRead.bind(link);
    // status().memory.ring_bytes: the native rings and staging buffers held right now (AGENT-5)
    const hooks = (this.#core as { readonly hooks?: { readonly memory?: (() => { ring_bytes?: number })[] } }).hooks;
    hooks?.memory?.push(() => ({ ring_bytes: this.#nativeBytes() }));
    const add = (f: AgentFeature): void => {
      if (!this.#core.features.includes(f)) this.#core.features.push(f);
    };
    add("hooks.js");
    try {
      const symbols = link.nativeSymbols;
      if (symbols === null) return;
      this.#native = NativeHookTier.compile(symbols);
      add("hooks.native");
      if (this.#native.withXmm) add("hooks.native.xmm");
    } catch (e) {
      this.#nativeError = errorText(e);
    }
  }

  link(): HookCoreLink {
    return (this.#link ??= linkFromCore(this.#core));
  }

  /** "module+0xrva" inside a module (ModuleMap refreshed at most once a second on a miss), else the VA. */
  frameRef(va: NativePointer): string {
    let m = this.#modules.find(va);
    if (m === null && Date.now() - this.#modulesAt > 1000) {
      this.#modules.update();
      this.#modulesAt = Date.now();
      m = this.#modules.find(va);
    }
    return m === null ? hexOf(va) : `${m.name}+${hexOf(va.sub(m.base))}`;
  }

  /** Deny + caution rules resolved once (module!export → VA), S4 §10.8. */
  rules(): readonly ResolvedSiteRule[] {
    if (this.#rules !== null) return this.#rules;
    const out: ResolvedSiteRule[] = [];
    const resolve = (api: string): NativePointer | null => {
      const [mod, name] = api.split("!");
      if (mod === undefined || name === undefined) return null;
      try {
        return Process.findModuleByName(mod)?.findExportByName(name) ?? null;
      } catch {
        return null;
      }
    };
    for (const d of HOOK_DENY_LIST) {
      const va = resolve(d.api);
      if (va !== null) out.push({ api: d.api, va: hexOf(va), reason: d.reason });
    }
    for (const api of HOOK_CAUTION_LIST) {
      const va = resolve(api);
      if (va !== null) out.push({ api, va: hexOf(va), reason: "caution" });
    }
    this.#rules = out;
    return out;
  }

  install(p: HookInstallParams): AgentResult<HookInstallResult> {
    const link = this.link();
    const planned = planHook(p, link.limits(), this.#core.features);
    if (!planned.ok) return badParams(planned.issues);
    const plan = planned.plan;

    const target = this.resolveTarget(p);
    if (!target.ok) return target;
    const at = target.value;
    const range = Process.findRangeByAddress(at);
    if (range === null || !range.protection.includes("x"))
      return fail({
        _tag: "NotExecutable",
        message: "the hook target is not executable",
        address: hexOf(at),
        protection: range?.protection ?? null,
      });
    const fn = link.findFunction?.(at) ?? null;
    const mod = Process.findModuleByAddress(at);
    const resolved: ResolvedTarget = {
      va: hexOf(at),
      module: mod?.name ?? null,
      module_base: mod === null ? null : hexOf(mod.base),
      rva: mod === null ? null : hexOf(at.sub(mod.base)),
      export: "export" in p.target ? p.target.export : null,
      function: fn === null ? null : { base: hexOf(fn.base), size: fn.size, source: "pdata" },
      protection: range.protection,
    };

    // thunk resolution (function entries only): Interceptor patches the thunk TARGET (S4 F5)
    let thunk: HookInstallResult["thunk"] = null;
    let sites: NativePointer[] = [at];
    if (!plan.probe) {
      const head = this.headBytes(at);
      const insn = head === null ? null : decodeThunk(head);
      if (insn !== null) {
        try {
          const to =
            insn.kind === "jmp-rip" ? at.add(insn.length + insn.disp).readPointer() : at.add(insn.length + insn.rel);
          // Interceptor follows a leading jmp and patches its target (S4 F5); a jmp inside a known function is not a thunk
          const inside = fn !== null && to.compare(fn.base) >= 0 && to.compare(fn.base.add(fn.size)) < 0;
          if (!inside) {
            thunk = { kind: insn.kind, to: hexOf(to) };
            sites = [to];
          }
        } catch {
          // unreadable thunk slot: hook the address itself
        }
      }
    }

    const rule = siteRuleHit([hexOf(at), ...sites.map(hexOf)], this.rules());
    if (rule !== null && (rule.reason !== "caution" || p.force_caution !== true))
      return fail({
        _tag: "HookDenied",
        message: "hooking this function is refused by the hook safety policy",
        address: hexOf(at),
        api: rule.api,
        reason: rule.reason === "caution" ? "caution-requires-force" : rule.reason,
        alternatives: [...DENY_ALTERNATIVES],
      });
    for (const s of sites) {
      const owner = link.replaceOwner?.(s) ?? null;
      if (owner !== null)
        return fail({
          _tag: "HookConflict",
          message: "a replace-mode override owns this function",
          address: hexOf(s),
          existing: owner,
          kind: "replace",
        });
    }
    return plan.engine === "native"
      ? this.installNative(p, plan, link, at, resolved, thunk, sites)
      : this.installJs(p, plan, link, at, resolved, thunk, sites);
  }

  private resolveTarget(p: HookInstallParams): AgentResult<NativePointer> {
    const t = p.target;
    if ("va" in t) return ok(ptr(t.va));
    const mod = Process.findModuleByName(t.module);
    if (mod === null) return fail({ _tag: "ModuleNotFound", message: "module not loaded", module: t.module });
    if ("rva" in t) return ok(mod.base.add(ptr(t.rva)));
    const va = mod.findExportByName(t.export);
    return va === null
      ? fail({ _tag: "ExportNotFound", message: "export not found", module: t.module, export: t.export })
      : ok(va);
  }

  private headBytes(at: NativePointer): Uint8Array | null {
    try {
      const ab = at.readByteArray(16);
      return ab === null ? null : new Uint8Array(ab);
    } catch {
      return null;
    }
  }

  private beforeOf(sites: readonly NativePointer[]): { address: Hex; hex: string }[] {
    return sites.map((s) => {
      const head = (() => {
        try {
          const ab = s.readByteArray(32);
          return ab === null ? new Uint8Array(0) : new Uint8Array(ab);
        } catch {
          return new Uint8Array(0);
        }
      })();
      return { address: hexOf(s), hex: hexBytes(head) };
    });
  }

  /** Interceptor.attach with the forced-relocation retry (S4 §10.2 step 6). */
  private attach(
    at: NativePointer,
    callbacks: InvocationListenerCallbacks | InstructionProbeCallback,
    relocation: HookInstallParams["relocation"],
    data?: NativePointer,
  ):
    | { readonly ok: true; readonly listener: InvocationListener; readonly relocation: "default" | "forced" }
    | { readonly ok: false; readonly error: AgentError } {
    const attempts: ("default" | "forced")[] = [];
    let message = "";
    const order: ("default" | "forced")[] = relocation === "forced" ? ["forced"] : ["default", "forced"];
    for (const mode of order) {
      attempts.push(mode);
      try {
        const listener =
          mode === "default"
            ? Interceptor.attach(at, callbacks, data)
            : Interceptor.attach({ target: at, relocation: "forced" }, callbacks, data);
        return { ok: true, listener, relocation: mode };
      } catch (e) {
        message = errorText(e);
        if (!/unable to intercept/iu.test(message)) break;
      }
    }
    return {
      ok: false,
      error: {
        _tag: "HookInstallFailed",
        message: "Interceptor could not hook this address",
        address: hexOf(at),
        attempts,
        frida_message: message,
        alternatives: [...INSTALL_ALTERNATIVES],
      },
    };
  }

  private effect(at: NativePointer, plan: HookPlan, before: JsSite["before"]): EffectHint {
    return {
      kind: "hook-installed",
      reversible: true,
      targets: [{ address: hexOf(at), size: null }],
      thread_ids: plan.threadIds.length > 0 ? [...plan.threadIds] : null,
      before: before.map((b) => ({ address: b.address, hex: b.hex.slice(0, 128) })),
    };
  }

  private lifetimeOf(p: HookInstallParams, plan: HookPlan): Lifetime {
    return {
      duration_ms: plan.durationMs,
      max_hits: plan.maxHits,
      ...(p.lifetime.clock === undefined ? {} : { clock: p.lifetime.clock }),
    };
  }

  // -------------------------------------------------------------------------------------------- JS tier
  private installJs(
    p: HookInstallParams,
    plan: HookPlan,
    link: HookCoreLink,
    at: NativePointer,
    resolved: ResolvedTarget,
    thunk: HookInstallResult["thunk"],
    sites: readonly NativePointer[],
  ): AgentResult<HookInstallResult> {
    const key = `${hexOf(at)}|${plan.probe ? "probe" : "fn"}`;
    const existing = this.#sites.get(key);
    const now = link.nowUs();
    let hook: JsHook | null = null;
    const registered = link.register({
      label: p.label ?? null,
      targets: [hexOf(at)],
      sites,
      lifetime: this.lifetimeOf(p, plan),
      stream: { enc: "json", kind: "hook/1" },
      beforeFlush: () => {
        if (hook !== null && plan.emit === "leave")
          hook.reg.counters.unreturned = Math.max(0, hook.enters - hook.leaves);
      },
      revert: () => (hook === null ? { reverted: true, verification: null } : this.revertJs(hook, link)),
    });
    if (isAgentError(registered)) return fail(registered);
    const site: JsSite = existing ?? {
      key,
      address: at,
      probe: plan.probe,
      patchedAt: sites,
      before: this.beforeOf(sites),
      relocation: "default",
      listener: null,
      hooks: [],
      owner: registered.id,
    };
    hook = {
      plan,
      site,
      threads: plan.threadIds.length > 0 ? new Set(plan.threadIds) : null,
      callers: plan.callerModules.length > 0 ? new Set(plan.callerModules) : null,
      rate: plan.maxPerSec > 0 ? new TokenBucket(plan.maxPerSec, now) : null,
      btRate: plan.backtrace === null ? null : new TokenBucket(plan.backtrace.perSec, now),
      gpr: p.capture.registers === "gpr",
      reg: registered,
      state: "active",
      enters: 0,
      leaves: 0,
    };

    if (existing === undefined) {
      for (const s of sites) link.saveOriginals?.(s, 32, site.owner);
      const attached = this.attach(at, this.callbacksFor(site, link), p.relocation);
      if (!attached.ok) {
        for (const s of sites) link.releaseOriginals?.(s, site.owner);
        registered.abandon();
        return fail(attached.error);
      }
      site.relocation = attached.relocation;
      site.listener = attached.listener;
      this.#sites.set(key, site);
    }
    // JS listeners need the JS lock this RPC holds, so no callback runs before the hook is in the list.
    site.hooks.push(hook);
    const relocation = site.relocation;
    Interceptor.flush();
    for (const s of sites) link.markPatched?.(s);
    const invalidated = link.invalidate?.(sites) ?? [];
    return ok({
      instrument_id: registered.id,
      stream_id: registered.stream,
      row_kind: "hook/1",
      layout: null,
      resolved,
      thunk,
      patched_at: sites.map(hexOf),
      relocation,
      stalker_invalidated: invalidated,
      arg_map: plan.captures.map((c) => ({ slot: c.index, source: describeSource(c.source) })),
      effect: this.effect(at, plan, site.before),
    });
  }

  /** The multiplexing callbacks of one site. Exceptions never reach the target (counted as errors). */
  private callbacksFor(site: JsSite, link: HookCoreLink): InvocationListenerCallbacks | InstructionProbeCallback {
    const engine = this;
    const current = (): JsSite => site;
    if (site.probe)
      return function (this: InvocationContext, args: InvocationArguments): void {
        for (const h of current().hooks) {
          if (h.state !== "active" || !h.reg.active) continue;
          try {
            engine.enter(h, this, args, link);
          } catch {
            h.reg.counters.errors++;
          }
        }
      };
    return {
      onEnter(this: InvocationContext, args: InvocationArguments): void {
        let pending: [JsHook, Pending][] | null = null;
        for (const h of current().hooks) {
          if (h.state !== "active" || !h.reg.active) continue;
          try {
            const st = engine.enter(h, this, args, link);
            if (st !== null) (pending ??= []).push([h, st]);
          } catch {
            h.reg.counters.errors++;
          }
        }
        this["bea"] = pending;
      },
      onLeave(this: InvocationContext, retval: InvocationReturnValue): void {
        const pending = this["bea"] as [JsHook, Pending][] | null | undefined;
        if (pending === null || pending === undefined) return;
        for (const [h, st] of pending) {
          if (h.state !== "active") continue;
          try {
            engine.leave(h, this, retval, st, link);
          } catch {
            h.reg.counters.errors++;
          }
        }
      },
    };
  }

  /** onEnter of one instrument: filters (S4 §10.3 order), stamping, enter captures. */
  enter(h: JsHook, ic: InvocationContext, args: InvocationArguments, link: HookCoreLink): Pending | null {
    const plan = h.plan;
    if (!plan.observeAgentCalls && Cloak.hasCurrentThread()) return null;
    const tid = ic.threadId;
    const counters = h.reg.counters;
    if (!plan.observeAgentCalls && link.suppresses(tid)) {
      counters.agent_calls_suppressed++;
      return null;
    }
    if (h.threads !== null && !h.threads.has(tid)) {
      counters.filtered++;
      return null;
    }
    if (h.callers !== null) {
      const m = Process.findModuleByAddress(ic.returnAddress);
      if (m === null || !h.callers.has(m.name.toLowerCase())) {
        counters.filtered++;
        return null;
      }
    }
    if (!h.reg.hit()) return null; // max_hits: the registry schedules the stop (never from inside the listener)
    if (plan.everyN > 1 && (counters.hits - 1) % plan.everyN !== 0) {
      counters.sampled_out++;
      return null;
    }
    const t = link.nowUs();
    if (h.rate !== null && !h.rate.take(t)) {
      h.reg.noteDropped("rate_limit", 1);
      return null;
    }
    const g = link.nextG();
    const cells: ValueCell[] = [];
    const saved: (Uint8Array | null)[] = [];
    for (const c of plan.captures) {
      if (c.at === "enter") {
        cells[c.index] = cellFrom(sourceBytes(ic, args, c.source), c);
        saved[c.index] = null;
      } else {
        cells[c.index] = null;
        saved[c.index] = c.source.kind === "reg" ? null : sourceBytes(ic, args, c.source);
      }
    }
    const bt =
      plan.backtrace !== null && h.btRate !== null && h.btRate.take(t)
        ? Thread.backtrace(ic.context, Backtracer.ACCURATE)
            .slice(0, plan.backtrace.depth)
            .map((va) => this.frameRef(va))
        : null;
    if (plan.emit === "enter") {
      this.emitRow(h, [g, t, tid, 1, ic.depth, hexOf(ic.returnAddress), cells, null, bt, this.regsOf(h, ic, null)]);
      return null;
    }
    h.enters++;
    return { g, t, cells, saved, bt };
  }

  /** onLeave of one instrument: leave captures from the saved slot values, return value, one phase-2 row. */
  leave(h: JsHook, ic: InvocationContext, retval: InvocationReturnValue, st: Pending, link: HookCoreLink): void {
    h.leaves++;
    const plan = h.plan;
    const cells = st.cells.slice();
    for (const c of plan.captures) {
      if (c.at !== "leave") continue;
      const bytes = st.saved[c.index] ?? sourceBytes(ic, [] as unknown as InvocationArguments, c.source);
      cells[c.index] = cellFrom(bytes, c);
    }
    let ret: ValueCell | null = null;
    const r = plan.ret;
    if (r !== null) {
      ret = r.fromXmm0
        ? scalarCell(r.type, new Uint8Array((ic.context as X64CpuContext).xmm0), 0)
        : r.deref.length === 0 && !isTextType(r.type) && r.type !== "bytes"
          ? cellOfWord(r.type, retval.toString())
          : cellFrom(bytesOfHex64(retval.toString()), r);
    }
    const tLeave = link.nowUs();
    this.emitRow(h, [
      st.g,
      st.t,
      ic.threadId,
      2,
      ic.depth,
      hexOf(ic.returnAddress),
      cells,
      ret,
      st.bt,
      this.regsOf(h, ic, tLeave),
    ]);
  }

  /** registers:"gpr" dump plus the phase-2 leave timestamp `t_leave` (µs, Hex) for dur_us. */
  private regsOf(h: JsHook, ic: InvocationContext, tLeave: number | null): Record<string, Hex> | null {
    if (!h.gpr && tLeave === null) return null;
    const out: Record<string, Hex> = {};
    if (h.gpr) {
      const ctx = ic.context as X64CpuContext;
      for (const r of GPRS) out[r] = hexOf(ctx[r]);
    }
    if (tLeave !== null) out["t_leave"] = `0x${Math.max(0, Math.floor(tLeave)).toString(16)}` as Hex;
    return out;
  }

  private emitRow(h: JsHook, row: HookRow): void {
    h.reg.counters.recorded++;
    h.reg.emit(row, 96 + 24 * row[6].length + (row[8]?.length ?? 0) * 32);
  }

  /** Registry stop step 2–5 for a JS hook (S4 §5.7). */
  private revertJs(h: JsHook, link: HookCoreLink): RevertResult {
    h.state = "ended";
    if (h.plan.emit === "leave") h.reg.counters.unreturned = Math.max(0, h.enters - h.leaves);
    const site = h.site;
    site.hooks = site.hooks.filter((x) => x !== h);
    if (site.hooks.length > 0)
      return {
        reverted: true,
        verification: { kind: "bytes", ok: true, detail: "listener kept for other instruments at this address" },
      };
    try {
      site.listener?.detach();
    } catch {
      // code unmapped (module unloaded): verified below
    }
    site.listener = null;
    this.#sites.delete(site.key);
    Interceptor.flush();
    link.invalidate?.(site.patchedAt);
    for (const s of site.patchedAt) link.releaseOriginals?.(s, site.owner);
    const verification = this.verifySites(site.patchedAt, site.before, link);
    return verification.ok
      ? { reverted: true, verification }
      : { reverted: false, verification, detail: "patch bytes not restored" };
  }

  /** Restored bytes equal the bytes saved before patching (another BEA listener may legitimately keep a patch). */
  private verifySites(
    sites: readonly NativePointer[],
    before: JsSite["before"],
    link: HookCoreLink,
  ): { kind: "bytes"; ok: boolean; detail: string } {
    let bad = 0;
    let shared = 0;
    const check = (): void => {
      bad = 0;
      shared = 0;
      sites.forEach((s, i) => {
        const want = before[i]?.hex.slice(0, 32) ?? "";
        const head = this.headBytes(s);
        const now = head === null ? "" : hexBytes(head).slice(0, 32);
        if (want === "" || now === want) return;
        if (head !== null && looksPatched(head) && link.patchedByOthers?.(s) === true) shared++;
        else bad++;
      });
    };
    check();
    // Interceptor may defer removing a patch while a thread runs through the trampoline: settle briefly (≤ 50 ms)
    for (let i = 0; i < 25 && bad > 0; i++) {
      Thread.sleep(0.002);
      Interceptor.flush();
      check();
    }
    return bad > 0
      ? { kind: "bytes", ok: false, detail: `${bad} patch site(s) do not match their original bytes` }
      : {
          kind: "bytes",
          ok: true,
          detail: shared > 0 ? "original bytes restored; another BEA patch remains" : "original bytes restored",
        };
  }

  // -------------------------------------------------------------------------------------------- native tier
  private installNative(
    p: HookInstallParams,
    plan: HookPlan,
    link: HookCoreLink,
    at: NativePointer,
    resolved: ResolvedTarget,
    thunk: HookInstallResult["thunk"],
    sites: readonly NativePointer[],
  ): AgentResult<HookInstallResult> {
    const tier = this.#native;
    const nplan = plan.native;
    if (tier === null || nplan === null)
      return fail({
        _tag: "Unsupported",
        message: "the native hook tier is not available in this agent",
        feature: "hooks.native",
        reason: this.#nativeError === null ? "core-symbols-unavailable" : "cmodule-compile-failed",
      });
    const limits = link.limits();
    if (this.#nativeCount >= limits.max_native_hooks)
      return fail({
        _tag: "ResourceLimit",
        message: "too many native hooks",
        resource: "native_hooks",
        limit: limits.max_native_hooks,
      });
    const layout = BINARY_LAYOUTS["hook-native/1"];
    const nh = new NativeHook(tier, {
      hookIndex: ++this.#nativeIndex,
      ringRecords: limits.native_ring_records,
      stagingRecords: Math.floor(limits.batch_max_bin_bytes / layout.rec_bytes),
      maxHits: plan.maxHits,
      everyN: plan.everyN,
      emitAtEnter: plan.emit === "enter",
      observeAgentCalls: plan.observeAgentCalls,
      plan: nplan,
    });
    const before = this.beforeOf(sites);
    let state: "pending" | "active" | "ended" = "pending";
    let listener: InvocationListener | null = null;
    let timer: ReturnType<typeof setInterval> | null = null;
    let reported = { overrun: 0, torn: 0 };
    let stopRequested = false;
    let reg: HookRegistered | null = null;
    /** ring → stream, drop deltas, counters from the C struct, native max_hits → registry stop */
    const drain = (): void => {
      if (reg === null) return;
      for (let i = 0; i < 64; i++) {
        const batch = nh.collect();
        if (batch === null) break;
        reg.emitBin(batch.data, batch.records);
      }
      const s = nh.stats();
      if (s.overrun > reported.overrun) reg.noteDropped("ring_overrun", s.overrun - reported.overrun);
      if (s.torn > reported.torn) reg.noteDropped("torn_record", s.torn - reported.torn);
      reported = { overrun: s.overrun, torn: s.torn };
      const c = reg.counters;
      c.hits = s.hits;
      c.recorded = s.recorded;
      c.sampled_out = s.sampledOut;
      c.agent_calls_suppressed = s.suppressed;
      const entered = (plan.maxHits > 0 ? Math.min(s.hits, plan.maxHits) : s.hits) - s.sampledOut;
      c.unreturned = plan.emit === "leave" ? Math.max(0, entered - s.leaves) : 0;
      if (!s.active && state === "active" && !stopRequested && plan.maxHits > 0 && s.hits > plan.maxHits) {
        stopRequested = true;
        reg.requestStop("max_hits");
      }
    };
    const registered = link.register({
      label: p.label ?? null,
      targets: [hexOf(at)],
      sites,
      lifetime: this.lifetimeOf(p, plan),
      stream: { enc: "bin", kind: "hook-native/1", layout },
      beforeFlush: drain,
      revert: () => {
        if (state !== "active") return { reverted: true, verification: null };
        state = "ended";
        nh.deactivate();
        try {
          listener?.detach();
        } catch {
          // module unloaded
        }
        Interceptor.flush();
        link.invalidate?.(sites);
        drain();
        this.#nativeCount--;
        if (timer !== null) clearInterval(timer);
        // AGENT-5: the ring and staging buffers go once a callback racing the deactivate has finished; the registry
        // keeps this closure (and so `nh`) for its 64 newest ended instruments, the pin keeps it for the session
        setTimeout(
          () => {
            nh.dispose();
            this.#nativeHeld.delete(nh);
          },
          Math.max(NATIVE_SETTLE_MS, link.limits().stalker_settle_ms),
        );
        for (const s of sites) link.releaseOriginals?.(s, owner);
        const verification = this.verifySites(sites, before, link);
        return verification.ok
          ? { reverted: true, verification }
          : { reverted: false, verification, detail: "patch bytes not restored" };
      },
    });
    if (isAgentError(registered)) {
      nh.dispose();
      return fail(registered);
    }
    reg = registered;
    const owner = registered.id;
    link.pin?.(nh);
    this.#nativeHeld.add(nh);
    for (const s of sites) link.saveOriginals?.(s, 32, owner);
    const attached = this.attach(at, nh.callbacks, p.relocation, nh.struct);
    if (!attached.ok) {
      for (const s of sites) link.releaseOriginals?.(s, owner);
      registered.abandon();
      nh.dispose(); // never attached: no callback can be writing
      this.#nativeHeld.delete(nh);
      return fail(attached.error);
    }
    listener = attached.listener;
    state = "active";
    this.#nativeCount++;
    for (const s of sites) link.markPatched?.(s);
    // A ring holds native_ring_records × 160 B; at 1M+ events/s the 50 ms core flush is too slow, so native hooks
    // drain on their own 10 ms timer (records go out through the instrument stream as binary batches).
    timer = setInterval(() => {
      if (state === "active") drain();
    }, 10);
    Interceptor.flush();
    const invalidated = link.invalidate?.(sites) ?? [];
    return ok({
      instrument_id: registered.id,
      stream_id: registered.stream,
      row_kind: "hook-native/1",
      layout,
      resolved,
      thunk,
      patched_at: sites.map(hexOf),
      relocation: attached.relocation,
      stalker_invalidated: invalidated,
      arg_map: nplan.fields.map((f) => ({ slot: f.index, source: `${f.field}@+${nativeFieldOffset(f.field)}` })),
      effect: this.effect(at, plan, before),
    });
  }
}

// ------------------------------------------------------------------------------------------------ feature exports
let engine: HookEngine | null = null;

/** Agent feature file (S4 §3.1). init runs after the core services, so the core link can be resolved here. */
export function init(core: AgentCore): void {
  engine = new HookEngine(core);
  engine.boot();
}

export const rpc = {
  hookInstall: (p: HookInstallParams): AgentResult<HookInstallResult> =>
    engine === null ? fail({ _tag: "NotReady", message: "the hook engine is not initialized" }) : engine.install(p),
} satisfies Partial<AgentRpcImpl>;
