// =================================================================================================
// src/agent/watch.ts — watchInstall façade over hwbp.ts / pageguard.ts / poll.ts (S4 §11, DESIGN §5.3 + D-INT-20;
// WP9-WATCH) and debugRegisterState. The engines depend only on the narrow hooks they declare; this file binds them
// to the agent core through WatchCoreSeam. The seam is built from the WP3 core services (instruments, streams,
// exceptions.registerTrapRouter, guards, native clock, hooks) by structural access checked at run time, so a change
// of WP3's types can never break the agent build: a missing member makes the watch RPCs answer
// Unsupported{reason:"core-seam-missing: …"} naming it. `core.watchSeam`, when present, overrides the adapter.
// =================================================================================================
import type {
  AgentError,
  AgentLimits,
  AgentResult,
  AgentRpcImpl,
  AgentStatus,
  BinaryLayout,
  DebugRegisterStateParams,
  DebugRegisterStateResult,
  EffectHint,
  EndReason,
  Hex,
  InstrumentId,
  InstrumentSummary,
  Lifetime,
  NoticeMessage,
  PollRow,
  RowKind,
  StreamId,
  WatchInstallParams,
  WatchInstallResult,
  WatchRow,
} from "../shared/agentProtocol.js";
import * as wp3disasm from "./disasm.js";
import {
  bytesHex,
  DebugRegisters4,
  findAccessInsnLocal,
  hexOf,
  readBytes,
  readBytesKernel,
  readDebugRegisters,
  type AccessInsn,
  type HitSink,
  type HitVerdict,
  type WatchHit,
} from "./hwbp.js";
import {
  LocalGuardPages,
  PageGuardEngine,
  type ExternalGuards,
  type GuardPageLike,
  type GuardPages,
  type GuardSink,
} from "./pageguard.js";
import { PollEngine } from "./poll.js";
import { ctrlBitsFor, validateDebugRegister, type DrRw } from "./pure/dr7.js";
import { DEFAULT_RATE_VALVE, PAGE_GUARD_MAX_PAGES_TOOL, pagesOf, type ChangedCell } from "./pure/watchPlan.js";
import type { AgentCore } from "./state.js";
import { SafetyNet } from "./watchSafetyNet.js";

// ---------------------------------------------------------------- the seam (DESIGN §5.3 core services WP9 consumes)

/**
 * WP3 exceptions.ts TrapRouter (same shape). WP9 registers ONE router with both hooks: WP3's core.watchSeam wrapper
 * calls both unconditionally and passes no page (each engine finds its own entry).
 */
export interface TrapRouter {
  readonly name: string;
  /** lower runs first (watch 10, core fallback 1000) */
  readonly order: number;
  readonly onSingleStep?: (d: ExceptionDetails, tid: number) => boolean;
  readonly onGuardPage?: (d: ExceptionDetails, tid: number, page?: GuardPageLike) => boolean;
}
export interface RevertOutcome {
  readonly reverted: boolean;
  readonly verification: InstrumentSummary["verification"];
  readonly detail?: string;
}
export interface InstrumentSpec {
  readonly kind: "watch" | "trace";
  readonly rowKind: RowKind;
  readonly layout: BinaryLayout | null;
  readonly lifetime: Lifetime;
  readonly targets: Hex[];
  readonly label?: string;
  /** step 2 of the S4 §5.7 stop protocol (kind-specific revert); awaited by the registry */
  revert(reason: EndReason): RevertOutcome | Promise<RevertOutcome>;
}
export interface InstrumentHandle {
  readonly id: InstrumentId;
  readonly streamId: StreamId;
  /** false from the moment the stop protocol starts: late callbacks return at their first line */
  isActive(): boolean;
  emitJson(row: unknown[], estBytes: number): void;
  emitBinary(records: ArrayBuffer, count: number): void;
  /** counts one hit; false when it exceeds max_hits (the registry then stops the instrument with "max_hits") */
  hit(): boolean;
  count(counter: "filtered" | "errors", n?: number): void;
  /** bea_guard_suspended windows counted on this instrument by the core (absent: the local table counts them) */
  suspendedWindows?(): number;
  /** ends the instrument from inside the feature (rate valve, invocations); scheduled, never synchronous */
  end(reason: EndReason): void;
  notice(code: NoticeMessage["code"], detail: Record<string, unknown>): void;
}
export interface WatchCoreSeam {
  /** hello.session.owned === false (the safety net installs only for attached sessions) */
  attached(): boolean;
  limits(): AgentLimits;
  nowUs(): number;
  nextG(): number;
  registerTrapRouter(router: TrapRouter): void;
  /** rpc.exports.dispose runs these synchronously before unload (A-36 VERIFIED) */
  registerDisposer(dispose: () => void): void;
  /** status/fingerprint hooks (WP3 CoreHooks.debugRegisters / safetyNet / expectedDr7); optional */
  setStatusHooks?(hooks: WatchStatusHooks): void;
  openInstrument(spec: InstrumentSpec): InstrumentHandle | AgentError;
  /** THE BEA guard table (WP3 GuardTable) */
  guardPages(): GuardPages;
  /** overlay-aware access-instruction recovery (WP3 disasm.findAccessInsn); optional */
  findAccessInsn?(pcAfter: NativePointer): AccessInsn;
  fault(where: string, e: unknown): void;
}
export interface WatchStatusHooks {
  readonly debugRegisters: () => AgentStatus["debug_registers"];
  readonly safetyNet: () => "none" | "installed";
  readonly expectedDr7: () => bigint | null;
}

// ---------------------------------------------------------------- the WP3 adapter (structural, run-time checked)

const isAgentError = (v: unknown): v is AgentError =>
  typeof v === "object" && v !== null && "_tag" in v && "message" in v;
type Fn = (...args: never[]) => unknown;
const fnAt = (root: unknown, path: string): Fn | null => {
  let v: unknown = root;
  for (const k of path.split("."))
    v = typeof v === "object" && v !== null ? (v as Record<string, unknown>)[k] : undefined;
  return typeof v === "function" ? (v as Fn) : null;
};
const WP3_REQUIRED = [
  "native.nowUs",
  "native.nextG",
  "streams.open",
  "streams.emit",
  "streams.emitBin",
  "instruments.register",
  "instruments.scheduleStop",
  "exceptions.registerTrapRouter",
  "guards.add",
  "guards.arm",
  "guards.disarm",
  "guards.removeOwner",
  "guards.find",
  "guards.noteConsumed",
  "guards.isGuardedNow",
  "guards.withBeaGuardsSuspended",
  "fault",
] as const;

interface Wp3Stream {
  readonly id: StreamId;
}
interface Wp3Instrument {
  readonly id: InstrumentId;
  readonly active: boolean;
  readonly counters: { filtered: number; errors: number; bea_guard_suspended: number };
  hit(): "record" | "record-and-stop" | "ignore";
}
interface Wp3Core {
  readonly limits: AgentLimits;
  readonly config?: { readonly session: { readonly owned: boolean } | null };
  readonly native: { nowUs(): number; nextG(): number };
  readonly streams: {
    open(spec: {
      instrument: InstrumentId | null;
      kind: RowKind;
      enc: "json" | "bin";
      layout?: string;
      recBytes?: number;
    }): Wp3Stream | AgentError;
    emit(s: Wp3Stream, row: unknown[], estBytes?: number): boolean;
    emitBin(
      s: Wp3Stream,
      chunk: { bytes: Uint8Array; n: number; g0: number; g1: number; t0: number; t1: number },
    ): boolean;
    close?(s: Wp3Stream): unknown;
  };
  readonly instruments: {
    register(spec: {
      kind: "watch" | "trace";
      label: string | null;
      lifetime: Lifetime;
      targets: readonly Hex[];
      stream: Wp3Stream | null;
      revert: (inst: Wp3Instrument, reason: EndReason) => RevertOutcome | Promise<RevertOutcome>;
    }): Wp3Instrument | AgentError;
    scheduleStop(inst: Wp3Instrument, reason: EndReason): void;
  };
  readonly exceptions: { registerTrapRouter(router: TrapRouter): unknown };
  readonly guards: GuardPages;
  readonly hooks?: {
    onDispose?: (() => void)[];
    debugRegisters?: unknown;
    safetyNet?: unknown;
    expectedDr7?: unknown;
  };
  fault(where: string, e: unknown): void;
}

const handleOf = (c: Wp3Core, inst: Wp3Instrument, stream: Wp3Stream): InstrumentHandle => ({
  id: inst.id,
  streamId: stream.id,
  isActive: () => inst.active,
  emitJson: (row, estBytes) => {
    c.streams.emit(stream, row, estBytes);
  },
  emitBinary: (records, count) => {
    const g0 = c.native.nextG();
    const t = c.native.nowUs();
    c.streams.emitBin(stream, { bytes: new Uint8Array(records), n: count, g0, g1: g0, t0: t, t1: t });
  },
  hit: () => inst.hit() !== "ignore",
  count: (counter, n = 1) => {
    inst.counters[counter] += n;
  },
  suspendedWindows: () => inst.counters.bea_guard_suspended,
  end: (reason) => c.instruments.scheduleStop(inst, reason),
  notice: (code, detail) => send({ bea: "notice", code, detail }),
});

/** Open the instrument's stream, then the instrument (the WP3 stream carries no instrument id: WP3 opens it first). */
const openWp3Instrument = (c: Wp3Core, spec: InstrumentSpec): InstrumentHandle | AgentError => {
  const stream = c.streams.open({
    instrument: null,
    kind: spec.rowKind,
    enc: spec.layout === null ? "json" : "bin",
    ...(spec.layout === null ? {} : { layout: spec.layout.id, recBytes: spec.layout.rec_bytes }),
  });
  if (isAgentError(stream)) return stream;
  const inst = c.instruments.register({
    kind: spec.kind,
    label: spec.label ?? null,
    lifetime: spec.lifetime,
    targets: spec.targets,
    stream,
    revert: (_inst, reason) => spec.revert(reason),
  });
  if (isAgentError(inst)) {
    c.streams.close?.(stream);
    return inst;
  }
  return handleOf(c, inst, stream);
};

/** WatchCoreSeam from the WP3 core, or the missing members. */
const seamFromCore = (core: AgentCore): WatchCoreSeam | string[] => {
  const missing = WP3_REQUIRED.filter((p) => fnAt(core, p) === null);
  if (missing.length > 0) return missing.map((p) => `core.${p}`);
  const c = core as unknown as Wp3Core;
  const findAccess = (wp3disasm as unknown as Record<string, unknown>)["findAccessInsn"];
  return {
    attached: () => c.config?.session?.owned === false,
    limits: () => c.limits,
    nowUs: () => c.native.nowUs(),
    nextG: () => c.native.nextG(),
    registerTrapRouter: (router) => {
      c.exceptions.registerTrapRouter(router);
    },
    registerDisposer: (dispose) => {
      c.hooks?.onDispose?.push(dispose);
    },
    setStatusHooks: (hooks) => {
      if (c.hooks === undefined) return;
      c.hooks.debugRegisters = hooks.debugRegisters;
      c.hooks.safetyNet = hooks.safetyNet;
      c.hooks.expectedDr7 = hooks.expectedDr7;
    },
    openInstrument: (spec) => openWp3Instrument(c, spec),
    guardPages: () => c.guards,
    ...(typeof findAccess === "function"
      ? {
          findAccessInsn: (pcAfter: NativePointer): AccessInsn => {
            const r = (findAccess as (core: AgentCore, pc: NativePointer) => unknown)(core, pcAfter) as {
              address?: unknown;
              text?: unknown;
              conf?: unknown;
            };
            const conf = r.conf === "swept" || r.conf === "heuristic" || r.conf === "exact" ? r.conf : "unknown";
            return typeof r.address === "string"
              ? { insn: ptr(r.address), conf, text: typeof r.text === "string" ? r.text : null }
              : findAccessInsnLocal(pcAfter);
          },
        }
      : {}),
    fault: (where, e) => c.fault(where, e),
  };
};

const SEAM_REQUIRED = [
  "attached",
  "limits",
  "nowUs",
  "nextG",
  "registerTrapRouter",
  "registerDisposer",
  "openInstrument",
  "fault",
] as const;

/**
 * WP3's core.watchSeam (instruments.ts createWatchSeam) is WP9's integration point; it differs from WatchCoreSeam in
 * three places, bridged here: guard pages are external (guards.add/remove: the engine keeps a LocalGuardPages and
 * mirrors each page into BEA's table), there is no setStatusHooks (core.hooks is set directly), and handles have no
 * suspendedWindows (the local table counts the windows). A seam that already has guardPages is used as it is.
 */
const adaptSeam = (core: AgentCore, raw: object): WatchCoreSeam | string[] => {
  const s = raw as Partial<WatchCoreSeam> & { readonly guards?: Partial<ExternalGuards> };
  const missing = SEAM_REQUIRED.filter((k) => typeof s[k] !== "function").map((k) => `core.watchSeam.${k}`);
  if (missing.length > 0) return missing;
  const full = s as WatchCoreSeam;
  let guardPages = s.guardPages;
  if (guardPages === undefined) {
    const ext = s.guards;
    if (typeof ext?.add !== "function" || typeof ext.remove !== "function")
      return ["core.watchSeam.guardPages or core.watchSeam.guards.add/remove"];
    const table = new LocalGuardPages(() => full.limits().page_guard_max_pages, ext as ExternalGuards);
    guardPages = () => table;
  }
  const hooks = (core as unknown as { hooks?: Partial<Record<keyof WatchStatusHooks, unknown>> }).hooks;
  return {
    ...full,
    guardPages,
    setStatusHooks:
      s.setStatusHooks ??
      ((h: WatchStatusHooks) => {
        if (hooks === undefined) return;
        hooks.debugRegisters = h.debugRegisters;
        hooks.safetyNet = h.safetyNet;
        hooks.expectedDr7 = h.expectedDr7;
      }),
  };
};

const bindWatchSeam = (core: AgentCore): WatchCoreSeam | string[] => {
  const injected = (core as unknown as { readonly watchSeam?: unknown }).watchSeam;
  return typeof injected === "object" && injected !== null ? adaptSeam(core, injected) : seamFromCore(core);
};

// ---------------------------------------------------------------- marker rows (page-guard counters for the host)

/**
 * The frozen watch/1 row has no field for page-guard counters or the rate-valve trip, and the agent EndReason
 * "rate-limit" has no recording end reason on the host. Both reach the host as marker rows: insn null,
 * insn_conf "unknown", text "bea:<marker>", counters as hex values in the regs slot. Capstone never produces text
 * starting with "bea:", so a marker cannot be confused with a hit (src/application/watch/markers.ts decodes them).
 */
const WATCH_MARKER_RATE_LIMIT = "bea:rate-limit";
const WATCH_MARKER_FINAL = "bea:watch-final";

// ---------------------------------------------------------------- state

const ok = <T>(value: T): AgentResult<T> => ({ ok: true, value });
const fail = (error: AgentError): AgentResult<never> => ({ ok: false, error });
const badParams = (path: string, problem: string): AgentResult<never> =>
  fail({ _tag: "BadParams", message: "invalid watchInstall parameters", issues: [{ path, problem }] });

export interface Bound {
  readonly seam: WatchCoreSeam;
  readonly hw: DebugRegisters4;
  readonly pg: PageGuardEngine;
  readonly poll: PollEngine;
  readonly net: SafetyNet;
  /** suspension windows the guard table counted on `owner` (0 when the core counts them on the instrument) */
  windowsOf(owner: InstrumentId): number;
}
const state: { core: AgentCore | null; bound: Bound | null } = { core: null, bound: null };

const threadsOf = (): ThreadDetails[] => Process.enumerateThreads();

/** DR7 bits every thread armed by an "all"-threads slot must carry (fingerprint). */
const expectedDr7Of = (hw: DebugRegisters4): bigint | null => {
  let bits = 0n;
  for (const s of hw.armedAllThreads()) bits |= (1n << BigInt(2 * s.slot)) | ctrlBitsFor(s.slot, s.rw, s.size); // L_s + RW/LEN
  return bits === 0n ? null : bits;
};

/** Build the engines on a seam (exported for the raw-Frida harness, which supplies its own seam). */
export const bindEngines = (seam: WatchCoreSeam): Bound => {
  const net = new SafetyNet();
  const guards = seam.guardPages();
  const hw = new DebugRegisters4({
    threads: threadsOf,
    readDebugRegisters,
    findAccessInsn: (pc) => seam.findAccessInsn?.(pc) ?? findAccessInsnLocal(pc),
    readWatched: (address, size, kernel) =>
      guards.withBeaGuardsSuspended([{ base: address, size }], () =>
        kernel ? readBytesKernel(address, size) : readBytes(address, size),
      ),
    verifyThreads: () => seam.limits().hwbp_verify_threads,
    onSlotsChanged: (mask) => net.setSlots(mask),
    fault: (where, e) => seam.fault(where, e),
  });
  const pg = new PageGuardEngine(guards, {
    nowUs: () => seam.nowUs(),
    onPagesChanged: (pages) => net.setPages(pages),
    onTrapFlag: (tid, set) => {
      if (net.installed) net.setTrapFlag(tid, set);
    },
    readOnFaultingThread: (address, size) =>
      hw.readTrips(address, size) ? readBytesKernel(address, size) : readBytes(address, size),
    fault: (where, e) => seam.fault(where, e),
  });
  const poll = new PollEngine({ read: (address, _lo, size) => pg.read(address, size) });
  seam.registerTrapRouter({
    name: "wp9-watch",
    order: 10,
    onSingleStep: (d, tid) => {
      // one step can be both a DR hit (DR6 B0-3) and a pending page-guard step (BS): both engines must see it
      const byDr = hw.onTrap(d, tid);
      const byStep = pg.hasPendingStep(tid) ? pg.onStep(d, tid) : false;
      return byDr || byStep;
    },
    onGuardPage: (d, tid) => pg.onGuard(d, tid),
  });
  seam.registerDisposer(() => {
    hw.disarmAllSync();
    pg.disarmAllSync();
    poll.stopAll();
  });
  seam.setStatusHooks?.({
    debugRegisters: () => hw.slotInfo().map((s) => ({ slot: s.slot, owner: s.owner })),
    safetyNet: () => (net.installed ? "installed" : "none"),
    expectedDr7: () => expectedDr7Of(hw),
  });
  const table = seam.guardPages() as GuardPages & { windowsOf?: (owner: string) => number };
  const windowsOf = (owner: InstrumentId): number =>
    typeof table.windowsOf === "function" ? table.windowsOf(owner) : 0;
  return { seam, hw, pg, poll, net, windowsOf };
};

const bound = (): Bound | string[] => {
  if (state.bound !== null) return state.bound;
  if (state.core === null) return ["core"];
  const seam = bindWatchSeam(state.core);
  if (Array.isArray(seam)) return seam;
  state.bound = bindEngines(seam);
  return state.bound;
};

export function init(core: AgentCore): void {
  state.core = core;
}

// ---------------------------------------------------------------- rows

const estimate = (row: readonly unknown[]): number => {
  let n = 0;
  for (const cell of row) n += typeof cell === "string" ? 2 + cell.length : cell === null ? 4 : 24;
  return n;
};

const hitRow = (seam: WatchCoreSeam, handle: InstrumentHandle, h: WatchHit): WatchRow => [
  seam.nextG(),
  seam.nowUs(),
  h.tid,
  handle.id,
  h.access,
  h.insn === null ? null : hexOf(h.insn),
  h.conf,
  h.pcAfter === null ? null : hexOf(h.pcAfter),
  h.text,
  hexOf(h.addr),
  bytesHex(h.before),
  bytesHex(h.after),
  h.regs,
  h.bt,
  h.mem,
];

/** A marker row: insn null, the marker in the text slot, the first watched page, counters (hex) in the regs slot. */
interface Marker {
  readonly text: string;
  readonly at: Hex;
  readonly counters: Record<string, number>;
}
const markerRow = (seam: WatchCoreSeam, handle: InstrumentHandle, { text, at, counters }: Marker): WatchRow => [
  seam.nextG(),
  seam.nowUs(),
  Process.getCurrentThreadId(),
  handle.id,
  "r",
  null,
  "unknown",
  null,
  text,
  at,
  null,
  null,
  Object.fromEntries(Object.entries(counters).map(([k, v]) => [k, hexOf(Math.max(0, Math.floor(v)))])),
  null,
  null,
];

const hitSink = (seam: WatchCoreSeam, handle: () => InstrumentHandle | null): HitSink => ({
  hit: (h): HitVerdict => {
    const ih = handle();
    if (ih === null || !ih.isActive()) return "stop";
    if (!ih.hit()) return "stop";
    const row = hitRow(seam, ih, h);
    ih.emitJson(row, estimate(row));
    return "continue";
  },
});

// ---------------------------------------------------------------- watchInstall

const effectOf = (
  kind: EffectHint["kind"],
  address: Hex | null,
  size: number | null,
  threads: number[] | null,
): EffectHint => ({
  kind,
  reversible: true,
  targets: address === null ? [] : [{ address, size }],
  thread_ids: threads,
  before: [],
});

const validate = (p: WatchInstallParams): AgentResult<never> | null => {
  if (p.method !== "debug-register" && p.method !== "page-guard" && p.method !== "poll")
    return badParams("method", "debug-register | page-guard | poll");
  if (typeof p.address !== "string" || !/^0x[0-9a-f]{1,16}$/u.test(p.address)) return badParams("address", "hex");
  if (!Number.isInteger(p.size) || p.size < 1 || p.size > 65_536) return badParams("size", "1..65536");
  if (p.access !== "write" && p.access !== "read-write" && p.access !== "execute")
    return badParams("access", "write | read-write | execute");
  if (p.threads !== "all" && (!Array.isArray(p.threads) || p.threads.length === 0 || p.threads.length > 1024))
    return badParams("threads", '"all" or 1..1024 thread ids');
  if (p.interval_ms !== undefined && (!Number.isInteger(p.interval_ms) || p.interval_ms < 1 || p.interval_ms > 10_000))
    return badParams("interval_ms", "1..10000");
  return null;
};

/** A handle reference the revert/sink closures read once the registry has opened the instrument. */
interface HandleRef {
  handle: InstrumentHandle | null;
}

/** Polls emit poll/1 rows, debug-register and page-guard watches watch/1 rows. */
const openWatch = (
  b: Bound,
  p: WatchInstallParams,
  ref: HandleRef,
  revert: (handle: InstrumentHandle) => RevertOutcome | Promise<RevertOutcome>,
): InstrumentHandle | AgentError => {
  const opened = b.seam.openInstrument({
    kind: "watch",
    rowKind: p.method === "poll" ? "poll/1" : "watch/1",
    layout: null,
    lifetime: p.lifetime,
    targets: [p.address],
    ...(p.label === undefined ? {} : { label: p.label }),
    revert: () => (ref.handle === null ? { reverted: true, verification: null } : revert(ref.handle)),
  });
  if (!isAgentError(opened)) ref.handle = opened;
  return opened;
};

const installDebugRegister = (b: Bound, p: WatchInstallParams): AgentResult<WatchInstallResult> => {
  const rw: DrRw = p.access === "execute" ? "x" : p.access === "write" ? "w" : "rw";
  const address = ptr(p.address);
  const check = validateDebugRegister(BigInt(p.address), p.size, rw);
  if (!check.ok)
    return fail({ _tag: "WatchInvalid", message: "debug-register watch is invalid", reason: check.reason });
  if (Cloak.hasRangeContaining(address))
    return fail({ _tag: "WatchInvalid", message: "the address is inside the agent", reason: "agent-page" });
  const busy = b.hw.busy();
  if ((p.slot !== undefined && busy[p.slot] === true) || !busy.includes(false))
    return fail({ _tag: "NoFreeDebugRegister", message: "no free debug register", in_use: b.hw.inUse() });
  const ref: HandleRef = { handle: null };
  const opened = openWatch(b, p, ref, async (handle) => {
    const r = await b.hw.disarm(handle.id);
    if (!r.ok) handle.notice("hwbp-unreverted", { slot: r.slot, detail: r.detail });
    return { reverted: r.ok, verification: { kind: "dr7", ok: r.ok, detail: r.detail }, detail: r.detail };
  });
  if (isAgentError(opened)) return fail(opened);
  if (b.seam.attached()) b.net.install(); // before the first thread is armed (arm() publishes the slot mask first)
  const armed = b.hw.arm({
    owner: opened.id,
    address,
    size: check.size,
    rw,
    ...(p.slot === undefined ? {} : { slot: p.slot }),
    threads: p.threads,
    capture: { registers: p.capture.registers, backtrace: Math.min(16, Math.max(0, p.capture.backtrace)) },
    sink: hitSink(b.seam, () => ref.handle),
  });
  if (armed === null) {
    opened.end("error");
    return fail({ _tag: "NoFreeDebugRegister", message: "no free debug register", in_use: b.hw.inUse() });
  }
  return ok({
    instrument_id: opened.id,
    stream_id: opened.streamId,
    method: "debug-register",
    slot: armed.slot,
    pages: null,
    armed_threads: armed.armedThreads,
    arm_errors: armed.armErrors.slice(0, 64),
    verified: armed.verified,
    initial_value: bytesHex(armed.initial),
    effect: effectOf(
      rw === "x" ? "breakpoint-set" : "watchpoint-set",
      p.address,
      check.size,
      p.threads === "all" ? null : [...p.threads],
    ),
  });
};

const guardSink = (b: Bound, handle: () => InstrumentHandle | null, page: Hex): GuardSink => ({
  ...hitSink(b.seam, handle),
  filtered: () => handle()?.count("filtered"),
  rateLimited: (trip) => {
    const ih = handle();
    if (ih === null) return;
    const row = markerRow(b.seam, ih, {
      text: WATCH_MARKER_RATE_LIMIT,
      at: page,
      counters: {
        limit_per_sec: trip.limitPerSec,
        peak_per_sec: trip.peakPerSec,
        busy_pct: trip.busyPct,
        busy_limit_pct: trip.busyLimitPct,
        busy_trip: trip.cause === "busy" ? 1 : 0,
      },
    });
    ih.emitJson(row, estimate(row));
    ih.end("rate-limit");
  },
});

const installPageGuard = (b: Bound, p: WatchInstallParams): AgentResult<WatchInstallResult> => {
  const pages = pagesOf(BigInt(p.address), p.size);
  if (pages.length > PAGE_GUARD_MAX_PAGES_TOOL)
    return fail({ _tag: "WatchInvalid", message: "a page-guard watch covers at most 16 pages", reason: "range" });
  const firstPage = hexOf(pages[0] ?? 0n);
  const ref: HandleRef = { handle: null };
  const opened = openWatch(b, p, ref, (handle) => {
    const counters = b.pg.counters(handle.id);
    const row = markerRow(b.seam, handle, {
      text: WATCH_MARKER_FINAL,
      at: firstPage,
      counters: {
        bea_guard_suspended: handle.suspendedWindows?.() ?? b.windowsOf(handle.id),
        kernel_rearms: counters?.kernelRearms ?? 0,
        rearm_fails: counters?.rearmFails ?? 0,
      },
    });
    handle.emitJson(row, estimate(row));
    const r = b.pg.disarm(handle.id);
    return { reverted: r.ok, verification: { kind: "protection", ok: r.ok, detail: r.detail }, detail: r.detail };
  });
  if (isAgentError(opened)) return fail(opened);
  const rate = p.rate_limit ?? { max_per_sec: DEFAULT_RATE_VALVE.maxPerSec, window_ms: DEFAULT_RATE_VALVE.windowMs };
  if (b.seam.attached()) b.net.install(); // before the first page is guarded (arm() publishes the page list first)
  const armed = b.pg.arm({
    owner: opened.id,
    address: ptr(p.address),
    size: p.size,
    access: p.access,
    capture: { registers: p.capture.registers, backtrace: Math.min(16, Math.max(0, p.capture.backtrace)) },
    rate: { maxPerSec: Math.max(1, rate.max_per_sec), windowMs: Math.max(1, rate.window_ms) },
    sink: guardSink(b, () => ref.handle, firstPage),
  });
  if (typeof armed === "string" || isAgentError(armed)) {
    opened.end("error");
    return fail(
      typeof armed === "string"
        ? { _tag: "WatchInvalid", message: "the range cannot carry a page-guard watch", reason: armed }
        : armed,
    );
  }
  return ok({
    instrument_id: opened.id,
    stream_id: opened.streamId,
    method: "page-guard",
    slot: null,
    pages: armed.pages,
    armed_threads: 0,
    arm_errors: [],
    verified: null,
    initial_value: bytesHex(armed.before),
    effect: effectOf("guard-page-set", p.address, p.size, null),
  });
};

const u8Hex = (u: Uint8Array): string => {
  let out = "";
  for (const v of u) out += v.toString(16).padStart(2, "0");
  return out;
};
const pollRow = (seam: WatchCoreSeam, cell: ChangedCell): PollRow => [
  seam.nextG(),
  seam.nowUs(),
  cell.offset,
  u8Hex(cell.old),
  u8Hex(cell.now),
];

const installPoll = (b: Bound, p: WatchInstallParams): AgentResult<WatchInstallResult> => {
  const ref: HandleRef = { handle: null };
  const opened = openWatch(b, p, ref, (handle) => {
    b.poll.stop(handle.id);
    return { reverted: true, verification: null };
  });
  if (isAgentError(opened)) return fail(opened);
  const first = b.poll.start({
    owner: opened.id,
    address: ptr(p.address),
    size: p.size,
    intervalMs: p.interval_ms ?? 16,
    sink: {
      changes: (cells) => {
        const ih = ref.handle;
        if (ih === null || !ih.isActive()) return "stop";
        for (const cell of cells) {
          if (!ih.hit()) return "stop";
          const row = pollRow(b.seam, cell);
          ih.emitJson(row, estimate(row));
        }
        return "continue";
      },
      unreadable: () => ref.handle?.count("errors"),
    },
  });
  if (first === null) {
    opened.end("error");
    return fail({
      _tag: "AccessViolation",
      message: "the range is not readable",
      address: p.address,
      operation: "read",
    });
  }
  return ok({
    instrument_id: opened.id,
    stream_id: opened.streamId,
    method: "poll",
    slot: null,
    pages: null,
    armed_threads: 0,
    arm_errors: [],
    verified: null,
    initial_value: bytesHex(first),
    effect: effectOf("watchpoint-set", null, null, null),
  });
};

/** The RPC body on an explicit binding (exported for the raw-Frida harness). */
export const watchInstallOn = (b: Bound, p: WatchInstallParams): AgentResult<WatchInstallResult> => {
  const invalid = validate(p);
  if (invalid !== null) return invalid;
  if (p.method === "debug-register") return installDebugRegister(b, p);
  if (p.method === "page-guard") return installPageGuard(b, p);
  return installPoll(b, p);
};

const watchInstall = (p: WatchInstallParams): AgentResult<WatchInstallResult> => {
  const b = bound();
  if (Array.isArray(b))
    return fail({
      _tag: "Unsupported",
      message: "the watch engine is not bound to the agent core",
      feature: p.method === "page-guard" ? "watch.page-guard" : "watch.debug-register",
      reason: `core-seam-missing: ${b.join(", ").slice(0, 200)}`,
    });
  return watchInstallOn(b, p);
};

// ---------------------------------------------------------------- debugRegisterState (works without the seam)

/** The RPC body; `hw` null reports every slot free (exported for the raw-Frida harness). */
export const debugRegisterStateOn = (
  hw: DebugRegisters4 | null,
  p: DebugRegisterStateParams,
  limit: number,
): AgentResult<DebugRegisterStateResult> => {
  const wanted = p.thread_ids === undefined ? null : new Set(p.thread_ids);
  const threads: DebugRegisterStateResult["threads"] = [];
  for (const t of threadsOf()) {
    if (wanted !== null && !wanted.has(t.id)) continue;
    if (threads.length >= limit) break;
    const regs = readDebugRegisters(t.id);
    threads.push(
      "error" in regs
        ? { tid: t.id, dr: ["0x0", "0x0", "0x0", "0x0"], dr7: "0x0", error: regs.error }
        : {
            tid: t.id,
            dr: [hexOf(regs.dr[0]), hexOf(regs.dr[1]), hexOf(regs.dr[2]), hexOf(regs.dr[3])],
            dr7: hexOf(regs.dr7),
            error: null,
          },
    );
  }
  const slots = hw?.slotInfo() ?? [0, 1, 2, 3].map((slot) => ({ slot, owner: null, kind: null, address: null }));
  return ok({ threads, slots });
};

const debugRegisterState = (p: DebugRegisterStateParams): AgentResult<DebugRegisterStateResult> => {
  const b = bound();
  return Array.isArray(b)
    ? debugRegisterStateOn(null, p, 64)
    : debugRegisterStateOn(b.hw, p, b.seam.limits().hwbp_verify_threads);
};

export const rpc = {
  watchInstall,
  debugRegisterState,
} satisfies Partial<AgentRpcImpl>;
