// =================================================================================================
// src/agent/trace.ts — traceStart: Stalker modes and on_call (S4 §12, DESIGN §5.3 + D-INT-22, CT-M1; WP9-WATCH).
//   coverage    threads: compile events → unique blocks (block-span/1); cheap [ext-frida §3.8]
//   block_counts         CModule transform counting every block execution (block-count/1, deltas every 1 s)
//   call_summary         CModule transform counting every call site (call-site-count/1, deltas every 1 s)
//   call_events          raw GumEvent passthrough (gum-event-x64/1; internal)
//   on_call     Interceptor onEnter follows the calling thread, onLeave unfollows, N invocations. Coverage and
//               block counts use the gated block-count kernel, so blocks run after the return (in the caller,
//               before Stalker lets go) are not counted; the entry block Interceptor relocates into its trampoline
//               is synthesized as [entry, first block) with count = invocations (CT-M1). Rows: block-count/1.
//               Ends with "invocations" once the requested invocations completed (review fix UX-11).
// Reads the WP3 seam published as `core.watchSeam` (its trace members); see watch.ts for the full contract.
// Review fix AGENT-8: Stalker.unfollow(tid) of another thread only marks it pending; the thread leaves at its next pass
// through Stalker's gate, and a loop running in backpatched translated blocks (every other module excluded) may never
// pass it: it stayed under the stopped trace (slowed, running its callouts) and the next trace of that thread recorded
// nothing. unfollowAll therefore invalidates the blocks the trace compiled for each unfollowed thread (the hottest
// first), so the thread reaches the gate at its next block; and a deferred follow refuses an entry made from translated
// code (an old exec context still running). Review fix AGENT-6: a stopped trace drops its kernels, blocks and counters
// (the registry keeps the 64 newest ended instruments, and their revert closures kept the whole trace alive).
// =================================================================================================
import { BINARY_LAYOUTS } from "../shared/binaryLayouts.js";
import type {
  AgentError,
  AgentLimits,
  AgentResult,
  AgentRpcImpl,
  BinaryLayout,
  EndReason,
  Hex,
  InstrumentId,
  Lifetime,
  RowKind,
  StreamId,
  ThreadId,
  TraceStartParams,
  TraceStartResult,
} from "../shared/agentProtocol.js";
import {
  BlockSet,
  encodeBlockSpans,
  encodeTriples,
  inRanges,
  sumTriples,
  synthesizeEntryBlock,
  type CodeRange,
} from "./pure/traceBlocks.js";
import type { AgentCore } from "./state.js";
import { createKernels, type KernelSet } from "./traceKernels.js";

// ---------------------------------------------------------------- the trace view of the WP3 core

interface TraceRevert {
  readonly reverted: boolean;
  readonly verification: null;
}
interface TraceInstrumentSpec {
  readonly kind: "trace";
  readonly rowKind: RowKind;
  readonly layout: BinaryLayout | null;
  readonly lifetime: Lifetime;
  readonly targets: Hex[];
  readonly label?: string;
  revert(reason: EndReason): TraceRevert | Promise<TraceRevert>;
}
interface TraceHandle {
  readonly id: InstrumentId;
  readonly streamId: StreamId;
  isActive(): boolean;
  emitBinary(records: ArrayBuffer, count: number): void;
  hit(): boolean;
  /** scheduled, never synchronous (listeners never stop themselves) */
  end(reason: EndReason): void;
}
/** The WP3 StalkerCoordinator surface (stalkerCo.ts; S4 §12.1). */
interface StalkerCo {
  ensureQueue(capacity?: number, drainMs?: number): { capacity: number; drain_ms: number };
  /** StalkerBusy when the thread is followed (another trace or a call) or still settling */
  claim(tid: ThreadId, owner: InstrumentId): AgentError | null;
  release(tid: ThreadId): void;
  forget(tid: ThreadId): void;
  invalidateAll(addresses: readonly NativePointer[]): unknown;
}
/** What trace.ts needs from the core (the trace members of watch.ts's WatchCoreSeam + the StalkerCoordinator). */
interface TraceCoreSeam {
  limits(): AgentLimits;
  registerDisposer(dispose: () => void): void;
  openInstrument(spec: TraceInstrumentSpec): TraceHandle | AgentError;
  stalkerCo(): StalkerCo;
  fault(where: string, e: unknown): void;
}

const isAgentError = (v: unknown): v is AgentError =>
  typeof v === "object" && v !== null && "_tag" in v && "message" in v;
const fnAt = (root: unknown, path: string): boolean => {
  let v: unknown = root;
  for (const k of path.split("."))
    v = typeof v === "object" && v !== null ? (v as Record<string, unknown>)[k] : undefined;
  return typeof v === "function";
};
const WP3_REQUIRED = [
  "native.nowUs",
  "native.nextG",
  "streams.open",
  "streams.emitBin",
  "instruments.register",
  "instruments.scheduleStop",
  "stalkerCo.ensureQueue",
  "stalkerCo.claim",
  "stalkerCo.release",
  "stalkerCo.forget",
  "stalkerCo.invalidateAll",
  "fault",
] as const;
interface Wp3Stream {
  readonly id: StreamId;
}
interface Wp3Instrument {
  readonly id: InstrumentId;
  readonly active: boolean;
  hit(): "record" | "record-and-stop" | "ignore";
}
interface Wp3Core {
  readonly limits: AgentLimits;
  readonly native: { nowUs(): number; nextG(): number };
  readonly streams: {
    open(spec: {
      instrument: null;
      kind: RowKind;
      enc: "bin";
      layout: string;
      recBytes: number;
    }): Wp3Stream | AgentError;
    emitBin(
      s: Wp3Stream,
      chunk: { bytes: Uint8Array; n: number; g0: number; g1: number; t0: number; t1: number },
    ): boolean;
    close?(s: Wp3Stream): unknown;
  };
  readonly instruments: {
    register(spec: {
      kind: "trace";
      label: string | null;
      lifetime: Lifetime;
      targets: readonly Hex[];
      stream: Wp3Stream | null;
      revert: (inst: Wp3Instrument, reason: EndReason) => TraceRevert | Promise<TraceRevert>;
    }): Wp3Instrument | AgentError;
    scheduleStop(inst: Wp3Instrument, reason: EndReason): void;
  };
  readonly stalkerCo: StalkerCo;
  readonly hooks?: { onDispose?: (() => void)[] };
  fault(where: string, e: unknown): void;
}

/**
 * TraceCoreSeam from `core.watchSeam` (WP3 createWatchSeam: its stalkerCo is the coordinator object; the harness
 * passes a function) or the WP3 core services, or the missing members.
 */
const bindTraceSeam = (core: AgentCore): TraceCoreSeam | string[] => {
  const injected = (core as unknown as { readonly watchSeam?: Record<string, unknown> }).watchSeam;
  if (typeof injected === "object" && injected !== null) {
    const co = injected["stalkerCo"];
    const stalkerCo =
      typeof co === "function"
        ? (co as () => StalkerCo)
        : typeof co === "object" && co !== null
          ? () => co as StalkerCo
          : null;
    const usable = (["limits", "registerDisposer", "openInstrument", "fault"] as const).every(
      (k) => typeof injected[k] === "function",
    );
    if (stalkerCo !== null && usable) return { ...(injected as unknown as TraceCoreSeam), stalkerCo };
  }
  const missing = WP3_REQUIRED.filter((p) => !fnAt(core, p)).map((p) => `core.${p}`);
  if (missing.length > 0) return missing;
  const c = core as unknown as Wp3Core;
  return {
    limits: () => c.limits,
    registerDisposer: (dispose) => {
      c.hooks?.onDispose?.push(dispose);
    },
    stalkerCo: () => c.stalkerCo,
    fault: (where, e) => c.fault(where, e),
    openInstrument: (spec) => {
      const layout = spec.layout ?? BINARY_LAYOUTS["block-span/1"];
      const stream = c.streams.open({
        instrument: null,
        kind: spec.rowKind,
        enc: "bin",
        layout: layout.id,
        recBytes: layout.rec_bytes,
      });
      if (isAgentError(stream)) return stream;
      const inst = c.instruments.register({
        kind: "trace",
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
      return {
        id: inst.id,
        streamId: stream.id,
        isActive: () => inst.active,
        emitBinary: (records, count) => {
          const g0 = c.native.nextG();
          const t = c.native.nowUs();
          c.streams.emitBin(stream, { bytes: new Uint8Array(records), n: count, g0, g1: g0, t0: t, t1: t });
        },
        hit: () => inst.hit() !== "ignore",
        end: (reason) => c.instruments.scheduleStop(inst, reason),
      };
    },
  };
};

// ---------------------------------------------------------------- state

const ok = <T>(value: T): AgentResult<T> => ({ ok: true, value });
const fail = (error: AgentError): AgentResult<never> => ({ ok: false, error });
const bad = (path: string, problem: string): AgentResult<never> =>
  fail({ _tag: "BadParams", message: "invalid traceStart parameters", issues: [{ path, problem }] });

interface Trace {
  readonly id: InstrumentId;
  readonly handle: TraceHandle;
  readonly mode: TraceStartParams["mode"];
  readonly ranges: CodeRange[];
  readonly tids: Set<ThreadId>;
  blocks: BlockSet | null;
  kernels: KernelSet | null;
  last: Map<number, bigint>;
  snapshot: ReturnType<typeof setInterval> | null;
  listener: InvocationListener | null;
  entry: NativePointer | null;
  invocations: number;
  maxInvocations: number;
  inFlight: ThreadId | null;
  observer: ThreadObserver | null;
  /** threads-mode follows deferred to the thread's next entry into the system-call stub it was blocked in */
  deferred: InvocationListener[];
  /** the stubs of `deferred` (invalidated for other traces' threads when the listeners detach) */
  deferredSites: NativePointer[];
  /** the stop protocol started: no new invocation is followed */
  ending: boolean;
  /** the final rows were emitted: late Stalker batches are ignored */
  closed: boolean;
}

const state = {
  core: null as AgentCore | null,
  seam: null as TraceCoreSeam | null,
  /** A-30: Stalker.exclude is process-global and cannot be undone; tracked for the session */
  excluded: new Map<string, { base: NativePointer; size: number }>(),
  traces: new Map<InstrumentId, Trace>(),
  /** threads some trace unfollowed in this session (an old exec context may still hold them; AGENT-8) */
  released: new Set<ThreadId>(),
};

export function init(core: AgentCore): void {
  state.core = core;
}

const seam = (): TraceCoreSeam | string[] => {
  if (state.seam !== null) return state.seam;
  if (state.core === null) return ["core"];
  const bound = bindTraceSeam(state.core);
  if (Array.isArray(bound)) return bound;
  state.seam = bound;
  bound.registerDisposer(() => {
    for (const t of state.traces.values()) unfollowAll(t, null);
  });
  return bound;
};

// ---------------------------------------------------------------- helpers

const toBig = (p: NativePointer): bigint => BigInt(p.toString());
const rangeOf = (m: Module): CodeRange => ({ base: toBig(m.base), end: toBig(m.base) + BigInt(m.size) });
const findModule = (name: string): Module | null =>
  name === "$main" ? Process.mainModule : Process.findModuleByName(name);

const layoutFor = (p: TraceStartParams): BinaryLayout => {
  if (p.mode === "call_summary") return BINARY_LAYOUTS["call-site-count/1"];
  if (p.mode === "call_events") return BINARY_LAYOUTS["gum-event-x64/1"];
  if (p.mode === "block_counts" || p.on_call !== undefined) return BINARY_LAYOUTS["block-count/1"];
  return BINARY_LAYOUTS["block-span/1"];
};

const releaseThread = (s: TraceCoreSeam, tid: ThreadId): void => {
  s.stalkerCo().release(tid);
};

/**
 * Records count against max_hits while the instrument is active. The final rows of the stop protocol (the last
 * compile batches and the closing snapshot) are emitted after the registry marked the instrument stopping, so they
 * bypass the hit count: the slab already bounds them.
 */
const admitted = (t: Trace, n: number, final: boolean): number => {
  if (final) return n;
  let k = 0;
  while (k < n && t.handle.hit()) k += 1;
  return k;
};
const emitSpans = (t: Trace, spans: [bigint, bigint][], final = false): void => {
  for (let i = 0; i < spans.length; i += 4096) {
    const chunk = spans.slice(i, i + 4096);
    const n = admitted(t, chunk.length, final);
    if (n > 0) t.handle.emitBinary(encodeBlockSpans(chunk.slice(0, n)), n);
    if (n < chunk.length) return;
  }
};
const emitTriples = (t: Trace, rows: [bigint, bigint, bigint][], final = false): void => {
  for (let i = 0; i < rows.length; i += 4096) {
    const chunk = rows.slice(i, i + 4096);
    const n = admitted(t, chunk.length, final);
    if (n > 0) t.handle.emitBinary(encodeTriples(chunk.slice(0, n)), n);
    if (n < chunk.length) return;
  }
};

/** Counts gained since the last snapshot (the host sums block-count/call-site-count rows by key). */
const takeDeltas = (t: Trace): [bigint, bigint, bigint][] => {
  const k = t.kernels;
  if (k === null) return [];
  const out: [bigint, bigint, bigint][] = [];
  for (const e of k.entries(0)) {
    const before = t.last.get(e.index) ?? 0n;
    if (e.count > before) {
      out.push([e.a, e.b, e.count - before]);
      t.last.set(e.index, e.count);
    }
  }
  return sumTriples(out, t.mode === "call_summary" ? "ab" : "a");
};

// ---------------------------------------------------------------- follow options

const coverageOptions = (t: Trace): StalkerOptions => ({
  events: { compile: true },
  onReceive: (raw: ArrayBuffer) => {
    const blocks = t.blocks;
    if (blocks === null || t.closed) return;
    const fresh: [bigint, bigint][] = [];
    for (const ev of Stalker.parse(raw, { annotate: false, stringify: false }) as [NativePointer, NativePointer][]) {
      const start = toBig(ev[0]);
      if (!inRanges(start, t.ranges)) continue;
      if (blocks.add(start, toBig(ev[1])) === "added") fresh.push([start, toBig(ev[1])]);
    }
    if (fresh.length > 0) emitSpans(t, fresh, t.ending);
  },
});

const followOptions = (t: Trace): StalkerOptions => {
  if (t.mode === "call_events")
    return {
      events: { call: true },
      onReceive: (raw: ArrayBuffer) => {
        const n = Math.floor(raw.byteLength / 32);
        if (n > 0 && !t.closed && t.handle.hit()) t.handle.emitBinary(raw.slice(0, n * 32), n);
      },
    };
  if (t.kernels !== null) return { transform: t.kernels.transform, data: t.kernels.bc };
  return coverageOptions(t);
};

// ---------------------------------------------------------------- start / stop

/**
 * At most this many translated blocks are invalidated per unfollowed thread (AGENT-8): about 40 µs each on this host
 * (review lab), so ≤ 0.2 s per thread at stop; the hottest blocks come first, where the thread is next.
 */
const MAX_REENTRY_POINTS = 4096;

const ptrOf = (a: bigint): NativePointer => ptr(`0x${a.toString(16)}`);

/** The block that starts right after the call instruction at `site` (where its callee returns), else null. */
const returnSite = (site: bigint): bigint | null => {
  try {
    return site + BigInt(Instruction.parse(ptrOf(site)).size);
  } catch {
    return null;
  }
};

/**
 * Block starts this trace's thread may still run translated code at after Stalker.unfollow (AGENT-8): the counted
 * blocks, hottest first (block_counts, on_call coverage); for call_summary the call targets and return sites (a
 * recorded site is a call instruction inside a block); the coverage set; the on_call entry. call_events records no
 * blocks (an internal mode; its threads leave at their next unbackpatched transition).
 */
const reentryPoints = (t: Trace): NativePointer[] => {
  const out = new Set<bigint>();
  const full = (): boolean => out.size >= MAX_REENTRY_POINTS;
  const add = (a: bigint | null): void => {
    if (a !== null && a !== 0n && !full()) out.add(a);
  };
  if (t.entry !== null) add(toBig(t.entry));
  const entries = t.kernels?.entries(0) ?? [];
  if (t.mode === "call_summary")
    for (const e of entries) {
      if (full()) break;
      add(e.b);
      add(returnSite(e.a));
    }
  else
    for (const e of entries.sort((x, y) => (x.count > y.count ? -1 : x.count < y.count ? 1 : 0))) {
      if (full()) break;
      add(e.a);
    }
  for (const [start] of t.blocks?.entries() ?? []) {
    if (full()) break;
    add(start);
  }
  return [...out].map(ptrOf);
};

const unfollowAll = (t: Trace, co: StalkerCo | null): void => {
  const detached: NativePointer[] = [];
  if (t.listener !== null || t.deferred.length > 0) {
    if (t.listener !== null && t.entry !== null) detached.push(t.entry);
    detached.push(...t.deferredSites.splice(0));
    t.listener?.detach();
    t.listener = null;
    for (const listener of t.deferred.splice(0)) listener.detach();
    Interceptor.flush();
  }
  // on_call: only the thread inside an invocation is still followed (onLeave unfollowed the others)
  const tids = t.entry === null ? [...t.tids] : t.inFlight === null ? [] : [t.inFlight];
  const points = tids.length > 0 ? reentryPoints(t) : [];
  for (const tid of tids) {
    try {
      Stalker.unfollow(tid);
    } catch {
      continue; // the thread exited
    }
    state.released.add(tid);
    // the pending unfollow is processed at the thread's next block entry instead of whenever (if ever) it next
    // passes the gate: every block it compiled is re-entered through the gate (VERIFIED in the review lab)
    for (const at of points) {
      try {
        Stalker.invalidate(tid, at);
      } catch {
        // not compiled for this thread
      }
    }
  }
  t.kernels?.setGate(false);
  // other traces' followed threads must not keep running the detached listeners' trampolines (S4 §12.1, AGENT-7)
  if (detached.length > 0) co?.invalidateAll(detached);
};

const stopTrace = async (s: TraceCoreSeam, t: Trace): Promise<TraceRevert> => {
  if (t.ending) return { reverted: true, verification: null };
  t.ending = true;
  if (t.snapshot !== null) clearInterval(t.snapshot);
  if (t.observer !== null) t.observer.detach();
  unfollowAll(t, s.stalkerCo());
  Stalker.flush();
  const drain = Math.max(Stalker.queueDrainInterval, s.limits().stalker_drain_ms);
  await new Promise<void>((resolve) => setTimeout(resolve, 2 * drain)); // the last onReceive batches land here
  if (t.kernels !== null) {
    const rows = takeDeltas(t);
    if (t.entry !== null && t.mode !== "call_summary") {
      const entry = toBig(t.entry);
      const first = rows.filter((r) => r[0] > entry && r[0] <= entry + 64n).sort((a, b) => (a[0] < b[0] ? -1 : 1))[0];
      const synthesized = synthesizeEntryBlock(entry, first?.[0] ?? null);
      if (synthesized !== null && t.invocations > 0)
        rows.unshift([synthesized.base, synthesized.end, BigInt(t.invocations)]);
    }
    if (t.entry !== null && t.mode === "call_summary" && t.invocations > 0) {
      const entry = toBig(t.entry);
      rows.unshift([entry, entry, BigInt(t.invocations)]); // invocation count: a self edge at the entry
    }
    emitTriples(t, rows, true);
  }
  t.closed = true;
  Stalker.garbageCollect();
  if (t.entry === null) for (const tid of t.tids) releaseThread(s, tid);
  else if (t.inFlight !== null) releaseThread(s, t.inFlight);
  t.kernels?.release(s.limits().stalker_settle_ms);
  // AGENT-6: nothing reads them after the final rows; the registry keeps ended instruments (and so this Trace)
  t.kernels = null;
  t.blocks = null;
  t.last.clear();
  state.traces.delete(t.id);
  return { reverted: true, verification: null };
};

const startOnCall = (s: TraceCoreSeam, t: Trace, target: NativePointer): void => {
  t.entry = target;
  const following = new Set<ThreadId>();
  t.listener = Interceptor.attach(target, {
    onEnter() {
      if (t.ending || t.inFlight !== null || t.invocations >= t.maxInvocations || Cloak.hasCurrentThread()) return;
      if (s.stalkerCo().claim(this.threadId, t.id) !== null) return;
      t.inFlight = this.threadId;
      t.tids.add(this.threadId);
      following.add(this.threadId);
      t.kernels?.setGate(true);
      Stalker.follow(this.threadId, followOptions(t));
    },
    onLeave() {
      if (!following.has(this.threadId)) return;
      following.delete(this.threadId);
      t.kernels?.setGate(false);
      Stalker.unfollow(this.threadId);
      state.released.add(this.threadId);
      t.inFlight = null;
      t.invocations += 1;
      releaseThread(s, this.threadId);
      if (t.invocations >= t.maxInvocations) t.handle.end("invocations"); // UX-11: not the event cap
    },
  });
  Interceptor.flush();
  s.stalkerCo().invalidateAll([target]);
};

/** The canonical Win64 system-call stub: `mov r10, rcx; mov eax, imm32; …; syscall (stub+0x12); ret (stub+0x14)`. */
const SYSCALL_STUB_HEAD = 0xb8d18b4c; // 4c 8b d1 b8, little endian
const SYSCALL_RETURN_OFFSET = 0x14;

/** The stub a thread is blocked in (its pc is right after a stub's `syscall`), else null. */
const blockedInStub = (tid: ThreadId): NativePointer | null => {
  const thread = Process.enumerateThreads().find((th) => th.id === tid);
  if (thread === undefined) return null;
  try {
    const pc = thread.context.pc;
    if (pc.sub(2).readU16() !== 0x050f) return null;
    const stub = pc.sub(SYSCALL_RETURN_OFFSET);
    return stub.readU32() === SYSCALL_STUB_HEAD ? stub : null;
  } catch {
    return null;
  }
};

/**
 * Frida 17.23.2 mitigation (WP18; docs/limitations.md, "trace_execution threads"): Stalker.follow(tid) of a thread
 * blocked in a system call arms a debug register at the stub's return, and gum's exceptor can re-trap on it inside its
 * own critical section (its allocator yields through SleepEx(0), which returns through the same address), which
 * deadlocks the thread and then the agent. Such a thread is followed from its own next entry into that stub instead:
 * an Interceptor listener on the stub follows the current thread (the on_call path, VERIFIED CT-lab E10), so no debug
 * register is armed. The thread's first wake-up up to that entry is not traced (a game loop loses at most one frame).
 */
const followAtNextEntry = (t: Trace, stub: NativePointer, tids: Set<ThreadId>): void => {
  const listener = Interceptor.attach(stub, {
    onEnter() {
      if (!tids.has(this.threadId) || t.ending) return;
      // AGENT-8: for a thread an earlier trace unfollowed, an entry made from code outside every module comes from that
      // trace's exec context, which has not let go of the thread yet; following from there creates a context that the
      // old one's pending unfollow then ends. Stay armed for the thread's next entry from module code.
      if (state.released.has(this.threadId) && Process.findModuleByAddress(this.returnAddress) === null) return;
      tids.delete(this.threadId);
      Stalker.follow(this.threadId, followOptions(t));
    },
  });
  Interceptor.flush();
  t.deferred.push(listener);
  t.deferredSites.push(stub);
};

const startThreads = (s: TraceCoreSeam, t: Trace, tids: readonly ThreadId[]): AgentError | null => {
  for (const tid of tids) {
    const busy = s.stalkerCo().claim(tid, t.id);
    if (busy !== null) {
      for (const done of t.tids) s.stalkerCo().forget(done); // claimed, never followed: no settle period
      t.tids.clear();
      return busy;
    }
    t.tids.add(tid);
  }
  const atNextEntry = new Map<string, { stub: NativePointer; tids: Set<ThreadId> }>();
  for (const tid of t.tids) {
    const stub = blockedInStub(tid);
    if (stub === null) {
      Stalker.follow(tid, followOptions(t));
      continue;
    }
    const key = stub.toString();
    const group = atNextEntry.get(key) ?? { stub, tids: new Set<ThreadId>() };
    group.tids.add(tid);
    atNextEntry.set(key, group);
  }
  for (const group of atNextEntry.values()) followAtNextEntry(t, group.stub, group.tids);
  t.observer = Process.attachThreadObserver({
    onRemoved: (th) => {
      if (!t.tids.has(th.id)) return;
      t.tids.delete(th.id);
      s.stalkerCo().forget(th.id);
      if (t.tids.size === 0) t.handle.end("thread-exit");
    },
  });
  return null;
};

const validate = (p: TraceStartParams, limits: AgentLimits, jsTid: ThreadId): AgentResult<never> | null => {
  const modes = ["coverage", "block_counts", "call_summary", "call_events"];
  if (!modes.includes(p.mode)) return bad("mode", modes.join(" | "));
  if ((p.threads === undefined) === (p.on_call === undefined))
    return bad("threads", "exactly one of threads / on_call");
  if (p.threads !== undefined) {
    if (p.threads.length < 1 || p.threads.length > limits.stalker_max_threads)
      return bad("threads", `1..${String(limits.stalker_max_threads)} thread ids`);
    if (p.threads.includes(jsTid)) return bad("threads", "the agent thread cannot be followed");
  }
  if (p.on_call !== undefined && (!Number.isInteger(p.on_call.invocations) || p.on_call.invocations < 1))
    return bad("on_call.invocations", "≥ 1");
  if (!Array.isArray(p.modules) || p.modules.length < 1 || p.modules.length > 16) return bad("modules", "1..16 names");
  return null;
};

const resolveOnCall = (p: TraceStartParams): NativePointer | AgentError => {
  const target = p.on_call?.target;
  if (target === undefined) return { _tag: "BadParams", message: "on_call needs a target", issues: [] };
  if ("va" in target) return ptr(target.va);
  const m = Process.findModuleByName(target.module);
  if (m === null) return { _tag: "ModuleNotFound", message: "module not loaded", module: target.module };
  if ("rva" in target) return m.base.add(ptr(target.rva));
  const e = m.findExportByName(target.export);
  return e ?? { _tag: "ExportNotFound", message: "export not found", module: target.module, export: target.export };
};

const unbound = (missing: readonly string[]): AgentResult<never> =>
  fail({
    _tag: "Unsupported",
    message: "Stalker tracing is not bound to the agent core",
    feature: "stalker",
    reason: `core-seam-missing: ${missing.join(", ").slice(0, 200)}`,
  });

/** The followed modules in request order; one an earlier trace excluded is refused (A-30). */
const traceModules = (p: TraceStartParams): Module[] | AgentResult<never> => {
  const modules: Module[] = [];
  for (const [i, name] of p.modules.entries()) {
    const m = findModule(name);
    if (m === null) return fail({ _tag: "ModuleNotFound", message: "module not loaded", module: name });
    if (state.excluded.has(m.name.toLowerCase()))
      return bad(`modules[${String(i)}]`, "excluded from Stalker by an earlier trace; exclusions last for the session");
    modules.push(m);
  }
  return modules;
};

/** Stalker.exclude for the other modules: process-global and never undone, so tracked for the session. */
const excludeModules = (p: TraceStartParams, modules: readonly Module[]): void => {
  const wanted = new Set(modules.map((m) => m.name.toLowerCase()));
  for (const name of p.exclude_modules) {
    const m = Process.findModuleByName(name);
    const key = m?.name.toLowerCase();
    if (m === null || key === undefined || wanted.has(key) || state.excluded.has(key)) continue;
    Stalker.exclude({ base: m.base, size: m.size });
    state.excluded.set(key, { base: m.base, size: m.size });
  }
};

/** block_counts, call_summary and on_call coverage count in the CModule kernels; the other modes need none. */
const kernelsFor = (p: TraceStartParams, modules: readonly Module[], cap: number): KernelSet | AgentError | null => {
  const counted =
    p.mode === "block_counts" || p.mode === "call_summary" || (p.on_call !== undefined && p.mode === "coverage");
  if (!counted) return null;
  try {
    return createKernels(
      p.mode === "call_summary" ? "calls" : "blocks",
      modules.map((m) => ({ base: m.base, size: m.size })),
      cap,
      p.on_call === undefined,
    );
  } catch (e) {
    return {
      _tag: "Internal",
      message: "trace kernel failed",
      where: "traceKernels",
      frida_message: String(e).slice(0, 200),
    };
  }
};

interface TracePlan {
  readonly modules: readonly Module[];
  readonly target: NativePointer | null;
  readonly cap: number;
  readonly layout: BinaryLayout;
  readonly kernels: KernelSet | null;
}

const newTrace = (handle: TraceHandle, p: TraceStartParams, plan: TracePlan): Trace => ({
  id: handle.id,
  handle,
  mode: p.mode,
  ranges: plan.modules.map(rangeOf),
  tids: new Set(),
  blocks: p.mode === "coverage" && p.on_call === undefined ? new BlockSet(plan.cap) : null,
  kernels: plan.kernels,
  last: new Map(),
  snapshot: null,
  listener: null,
  entry: null,
  invocations: 0,
  maxInvocations: p.on_call?.invocations ?? 0,
  inFlight: null,
  observer: null,
  deferred: [],
  deferredSites: [],
  ending: false,
  closed: false,
});

/** Thread-following counting modes emit their deltas once a second (on_call emits at each invocation's end). */
const snapshotEverySecond = (s: TraceCoreSeam, t: Trace): void => {
  t.snapshot = setInterval(() => {
    try {
      emitTriples(t, takeDeltas(t));
    } catch (e) {
      s.fault("trace.snapshot", e);
    }
  }, 1000);
};

const hexOfPtr = (p: NativePointer): Hex => `0x${toBig(p).toString(16)}` as Hex;

const startResult = (
  p: TraceStartParams,
  plan: TracePlan,
  t: Trace,
  queue: TraceStartResult["queue"],
): TraceStartResult => ({
  instrument_id: t.handle.id,
  stream_id: t.handle.streamId,
  row_kind: plan.layout.id as TraceStartResult["row_kind"],
  layout: plan.layout,
  threads: [...t.tids],
  queue,
  excluded: [...state.excluded.entries()].map(([module, r]) => ({ module, base: hexOfPtr(r.base), size: r.size })),
  effect: {
    kind: "stalker-followed",
    reversible: true,
    targets: plan.target === null ? [] : [{ address: hexOfPtr(plan.target), size: null }],
    thread_ids: p.threads === undefined ? null : [...p.threads],
    before: [],
  },
});

/** The owner a probe claim is made under (forgotten in the same synchronous turn, so never observable). */
const PROBE_OWNER = "t0" as InstrumentId;
/**
 * Every requested thread must be free (not followed, not settling, not the agent thread) BEFORE the instrument, the
 * stream and the counting kernels (a slab of up to stalker_max_blocks × 24 bytes) are created: a refused trace
 * allocates nothing. Each probe claim is forgotten at once, without a settle period.
 */
const busyThread = (s: TraceCoreSeam, tids: readonly ThreadId[]): AgentError | null => {
  const co = s.stalkerCo();
  for (const tid of tids) {
    const busy = co.claim(tid, PROBE_OWNER);
    if (busy !== null) return busy;
    co.forget(tid);
  }
  return null;
};

interface Admitted {
  readonly modules: Module[];
  readonly target: NativePointer | null;
}
/** Validation, the followed modules, the on_call target and free threads: nothing is allocated before this passes. */
const admit = (s: TraceCoreSeam, p: TraceStartParams, limits: AgentLimits): Admitted | AgentResult<never> => {
  const invalid = validate(p, limits, (state.core as AgentCore).jsTid);
  if (invalid !== null) return invalid;
  const modules = traceModules(p);
  if (!Array.isArray(modules)) return modules;
  const target = p.on_call === undefined ? null : resolveOnCall(p);
  if (target !== null && !(target instanceof NativePointer)) return fail(target);
  const busy = target === null ? busyThread(s, p.threads ?? []) : null;
  return busy === null ? { modules, target } : fail(busy);
};

const traceStart = (p: TraceStartParams): AgentResult<TraceStartResult> => {
  const s = seam();
  if (Array.isArray(s)) return unbound(s);
  const limits = s.limits();
  const admitted = admit(s, p, limits);
  if ("ok" in admitted) return admitted;
  const { modules, target } = admitted;
  excludeModules(p, modules);
  const queue = s.stalkerCo().ensureQueue(p.queue?.capacity, p.queue?.drain_ms);
  const cap = Math.min(limits.stalker_max_blocks, Math.max(4096, p.lifetime.max_hits));
  const kernels = kernelsFor(p, modules, cap);
  if (kernels !== null && isAgentError(kernels)) return fail(kernels);
  const plan: TracePlan = { modules, target, cap, layout: layoutFor(p), kernels };
  let trace: Trace | null = null;
  const opened = s.openInstrument({
    kind: "trace",
    rowKind: plan.layout.id,
    layout: plan.layout,
    lifetime: p.lifetime,
    targets: target === null ? [] : [hexOfPtr(target)],
    ...(p.label === undefined ? {} : { label: p.label }),
    // AGENT-6: the registry keeps this closure after the end; it must not keep the trace (slab, blocks) alive
    revert: () => {
      const t = trace;
      trace = null;
      return t === null ? { reverted: true, verification: null } : stopTrace(s, t);
    },
  });
  if (!("emitBinary" in opened)) {
    kernels?.release(limits.stalker_settle_ms);
    return fail(opened);
  }
  trace = newTrace(opened, p, plan);
  state.traces.set(trace.id, trace);
  if (target !== null) startOnCall(s, trace, target);
  else {
    const busy = startThreads(s, trace, p.threads ?? []);
    if (busy !== null) {
      opened.end("error");
      return fail(busy);
    }
  }
  if (kernels !== null && p.on_call === undefined) snapshotEverySecond(s, trace);
  return ok(startResult(p, plan, trace, queue));
};

export const rpc = {
  traceStart,
} satisfies Partial<AgentRpcImpl>;
