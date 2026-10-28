// =================================================================================================
// src/agent/pageguard.ts — PAGE_GUARD + trap-flag watches (S4 §11.3 F19, DESIGN §5.3; WP9-WATCH).
// A guarded page faults on any access; the dispatcher's guard-page hook records the faulting instruction and the
// value before, sets TF and returns; the single step that follows records the value after and re-arms the guard
// (VERIFIED lossless on a cold page; ≈ 9 µs per access [CT-lab E18], ≈ 55 µs through the JS dispatcher on this host
// in the WP9 acceptance). CT-I4 rate valve: above rate_limit traps/s over the window, or when handling the traps held
// the target for more than half of a window, the handler stops re-arming and the instrument ends with "rate-limit".
// CT-I5: page protection lives in THE BEA guard table (WP3 guards.ts GuardTable, which every agent reader suspends
// through withBeaGuardsSuspended and whose pages the dispatcher routes to this engine). The engine only needs the
// GuardPages surface below; LocalGuardPages implements it for a core without a table (and the raw-Frida harness).
// Review fix AGENT-2: every arm, re-arm, suspension window and disarm toggles PAGE_GUARD relative to the page's CURRENT
// protection (pure/watchPlan.ts guardToggle); the protection seen at arm time is never written back. A target that
// re-protects a watched page keeps its protection (the verifier re-arms over it and does not count it as a kernel
// access), and stopping the watch leaves the target's protection in place instead of restoring the old one.
// =================================================================================================
import type { AgentError, Hex, InstrumentId } from "../shared/agentProtocol.js";
import {
  backtraceOf,
  bigOf,
  captureRegisters,
  CONTEXT,
  decodeInsn,
  GPR_NAMES,
  hexOf,
  memOperandOf,
  protect,
  queryRegion,
  readBytes,
  threadStack,
  type DrCapture,
  type HitVerdict,
  type WatchHit,
} from "./hwbp.js";
import {
  createRateValve,
  guardToggle,
  overlaps,
  pagesOf,
  PAGE_SIZE,
  rateValveBusy,
  rateValveTrap,
  reprotectedSince,
  VALVE_MAX_BUSY,
  type RateValve,
  type RateValveConfig,
} from "./pure/watchPlan.js";

const PAGE_GUARD = 0x100;
const MEM_COMMIT = 0x1000;
const EXECUTABLE = 0x10 | 0x20 | 0x40 | 0x80;
const VERIFY_EVERY_MS = 250;
/**
 * A page leaves the guard table only this long after its last watch disarmed: a fault another thread raised just
 * before the disarm is still in flight, and a table that no longer knows the page would pass it on unhandled
 * (STATUS_GUARD_PAGE_VIOLATION kills the target; seen in the WP9 lab on a hot page).
 */
const RELEASE_GRACE_MS = 2000;

// ---------------------------------------------------------------- the guard table surface (WP3 GuardTable)

/** The fields of WP3's GuardPageEntry this engine reads. */
export interface GuardPageLike {
  readonly base: NativePointer;
  readonly key: string;
  /** the page's protection without PAGE_GUARD as BEA last saw it (updated at every toggle: the target may change it) */
  origProtect: number;
  /** times a toggle found a protection the target had set (it was kept and adopted as origProtect) */
  reprotects?: number;
  /** the owners want PAGE_GUARD present */
  desired: boolean;
  /** PAGE_GUARD applied as far as BEA knows (the OS clears it on a trap) */
  applied: boolean;
}
interface GuardRangeLike {
  readonly base: NativePointer;
  readonly size: number;
}
/** WP3 guards.ts GuardTable implements this surface (same names and shapes). */
export interface GuardPages {
  /** register `owner` on the page of `address`: WatchInvalid{range} (uncommitted / target guard), ResourceLimit */
  add(address: NativePointer, owner: string): GuardPageLike | AgentError;
  /** PAGE_GUARD on, over the page's current protection */
  arm(entry: GuardPageLike): boolean;
  /** PAGE_GUARD off, keeping the page's current protection */
  disarm(entry: GuardPageLike): boolean;
  /** the last owner removes the guard and drops the page */
  removeOwner(entry: GuardPageLike, owner: string): boolean;
  find(address: NativePointer | bigint): GuardPageLike | null;
  noteConsumed(entry: GuardPageLike): void;
  isGuardedNow(entry: GuardPageLike): boolean;
  /** the target changed the page's protection since BEA last toggled the guard (VirtualQuery now) */
  reprotected(entry: GuardPageLike): boolean;
  withBeaGuardsSuspended<T>(ranges: readonly GuardRangeLike[], fn: (pages: readonly GuardPageLike[]) => T): T;
}

interface LocalPage extends GuardPageLike {
  readonly owners: Set<string>;
  suspended: number;
}
/** What BEA's guard table must know of a page this engine arms (WP3 guards.ts ExternalGuardEntry). */
export interface ExternalGuardEntry {
  readonly origProtect: number;
  readonly owner: string;
  isArmed(): boolean;
  /** a BEA access suspended the guard: count one window */
  onSuspended(): void;
  /** a BEA access consumed the guard outside a window: re-arm now and count one window */
  onStolen(): void;
}
/** WP3's core.watchSeam.guards: BEA's table learns about (and later forgets) a page this engine arms. */
export interface ExternalGuards {
  add(page: NativePointer, entry: ExternalGuardEntry): void;
  remove(page: NativePointer): void;
}
/**
 * Self-contained GuardPages: VirtualQuery/VirtualProtect, suspension windows counted per owner. With `external`
 * (WP3's core.watchSeam.guards) every page is also registered in BEA's guard table, so the core dispatcher routes its
 * guard faults to this engine and other BEA readers suspend it (CT-I5), counted back here as windows.
 */
export class LocalGuardPages implements GuardPages {
  readonly #pages = new Map<string, LocalPage>();
  readonly #windows = new Map<string, number>();
  constructor(
    private readonly maxPages: () => number,
    private readonly external: ExternalGuards | null = null,
  ) {}

  add(address: NativePointer, owner: string): GuardPageLike | AgentError {
    const base = ptr(hexOf(bigOf(address) & ~BigInt(PAGE_SIZE - 1)));
    const key = base.toString();
    const known = this.#pages.get(key);
    if (known !== undefined) {
      known.owners.add(owner);
      return known;
    }
    if (this.#pages.size >= this.maxPages())
      return {
        _tag: "ResourceLimit",
        message: "too many BEA guard pages",
        resource: "page_guard_pages",
        limit: this.maxPages(),
      };
    const region = queryRegion(base);
    if (region === null || region.state !== MEM_COMMIT)
      return { _tag: "WatchInvalid", message: "the page is not committed", reason: "range" };
    if ((region.protect & PAGE_GUARD) !== 0)
      return { _tag: "WatchInvalid", message: "the page already has the target's PAGE_GUARD", reason: "range" };
    const page: LocalPage = {
      base,
      key,
      origProtect: region.protect & ~PAGE_GUARD,
      desired: false,
      applied: false,
      owners: new Set([owner]),
      suspended: 0,
    };
    this.#pages.set(key, page);
    this.#mirror(page);
    return page;
  }

  #mirror(page: LocalPage): void {
    if (this.external === null) return;
    try {
      this.external.add(page.base, {
        get origProtect() {
          return page.origProtect;
        },
        owner: "wp9-pageguard",
        isArmed: () => page.desired && this.#pages.has(page.key),
        onSuspended: () => this.#countWindow(page),
        onStolen: () => {
          this.#countWindow(page);
          page.applied = false;
          if (page.desired && page.suspended === 0) this.arm(page);
        },
      });
    } catch {
      // BEA's table refused the page: this engine still guards it, only other readers will not suspend it
    }
  }

  #countWindow(page: LocalPage): void {
    for (const o of page.owners) this.#windows.set(o, (this.#windows.get(o) ?? 0) + 1);
  }
  arm(entry: GuardPageLike): boolean {
    entry.desired = true;
    const page = this.#pages.get(entry.key);
    if (entry.applied || (page !== undefined && page.suspended > 0)) return true;
    entry.applied = this.#toggle(entry, true);
    return entry.applied;
  }
  disarm(entry: GuardPageLike): boolean {
    entry.desired = false;
    if (!entry.applied) return true;
    const ok = this.#toggle(entry, false);
    if (ok) entry.applied = false;
    return ok;
  }
  reprotected(entry: GuardPageLike): boolean {
    const region = queryRegion(entry.base);
    return region !== null && region.state === MEM_COMMIT && reprotectedSince(entry.origProtect, region.protect);
  }
  /**
   * PAGE_GUARD on (`want`) or off relative to the page's CURRENT protection, which becomes origProtect; a page that is
   * no longer committed is left alone. True when the page ends in the wanted state.
   */
  #toggle(entry: GuardPageLike, want: boolean): boolean {
    const region = queryRegion(entry.base);
    if (region === null || region.state !== MEM_COMMIT) return !want;
    if (reprotectedSince(entry.origProtect, region.protect)) {
      entry.origProtect = region.protect & ~PAGE_GUARD;
      entry.reprotects = (entry.reprotects ?? 0) + 1;
    }
    const next = guardToggle(region.protect, want);
    if (next === "unchanged") return true;
    if (next === "refused") return false;
    return protect(entry.base, PAGE_SIZE, next);
  }
  removeOwner(entry: GuardPageLike, owner: string): boolean {
    const page = this.#pages.get(entry.key);
    if (page === undefined) return true;
    page.owners.delete(owner);
    if (page.owners.size > 0) return false;
    this.disarm(page);
    this.#pages.delete(page.key);
    try {
      this.external?.remove(page.base);
    } catch {
      // already gone from BEA's table
    }
    return true;
  }
  find(address: NativePointer | bigint): GuardPageLike | null {
    const a = typeof address === "bigint" ? address : bigOf(address);
    return this.#pages.get(ptr(hexOf(a & ~BigInt(PAGE_SIZE - 1))).toString()) ?? null;
  }
  noteConsumed(entry: GuardPageLike): void {
    entry.applied = false;
  }
  isGuardedNow(entry: GuardPageLike): boolean {
    const region = queryRegion(entry.base);
    return region !== null && (region.protect & PAGE_GUARD) !== 0;
  }
  withBeaGuardsSuspended<T>(ranges: readonly GuardRangeLike[], fn: (pages: readonly GuardPageLike[]) => T): T {
    const lifted: LocalPage[] = [];
    for (const r of ranges)
      for (const page of this.#pages.values())
        if (page.desired && !lifted.includes(page) && overlaps(bigOf(page.base), PAGE_SIZE, bigOf(r.base), r.size)) {
          page.suspended += 1;
          if (page.applied && this.#toggle(page, false)) page.applied = false;
          this.#countWindow(page);
          lifted.push(page);
        }
    try {
      return fn(lifted);
    } finally {
      for (const page of lifted) {
        page.suspended -= 1;
        if (page.suspended === 0 && page.desired && this.#pages.has(page.key)) this.arm(page);
      }
    }
  }
  /** suspension windows counted on `owner` (the WP3 table counts them on the instrument instead) */
  windowsOf(owner: string): number {
    return this.#windows.get(owner) ?? 0;
  }
  disarmAll(): void {
    for (const page of this.#pages.values()) this.disarm(page);
  }
}

// ---------------------------------------------------------------- the engine

export type GuardAccess = "write" | "read-write" | "execute";
export type GuardRefusal = "stack-page" | "module-code" | "agent-page";

export interface GuardSink {
  hit(h: WatchHit): HitVerdict;
  /** a trap on a watched page outside the watched bytes or of a filtered access kind */
  filtered(): void;
  /** the CT-I4 valve tripped in the handler; the watch no longer re-arms */
  rateLimited(trip: RateTrip): void;
}
/** Why and how hard the valve tripped (the rate-limit marker's counters). */
export interface RateTrip {
  readonly cause: "rate" | "busy";
  readonly limitPerSec: number;
  readonly peakPerSec: number;
  /** the share of a window the target spent in this engine's handlers, in percent */
  readonly busyPct: number;
  readonly busyLimitPct: number;
}
export interface GuardWatchSpec {
  readonly owner: InstrumentId;
  readonly address: NativePointer;
  readonly size: number;
  readonly access: GuardAccess;
  readonly capture: DrCapture;
  readonly rate: RateValveConfig;
  readonly sink: GuardSink;
}
export interface GuardHostHooks {
  nowUs(): number;
  /** safety-net tables (attached sessions) */
  onPagesChanged(pages: readonly NativePointer[]): void;
  onTrapFlag(tid: number, set: boolean): void;
  /**
   * The watched bytes from inside a guard handler (on the faulting thread): a kernel-side copy when a read/write debug
   * register covers them, since a user-mode read would trip it there (hwbp readBytesKernel).
   */
  readOnFaultingThread(address: NativePointer, size: number): ArrayBuffer | null;
  fault(where: string, e: unknown): void;
}

interface GuardWatch {
  readonly spec: GuardWatchSpec;
  readonly lo: bigint;
  readonly hi: bigint;
  readonly pages: GuardPageLike[];
  readonly valve: RateValve;
  active: boolean;
  tripped: boolean;
  kernelRearms: number;
  rearmFails: number;
}
interface PendingHit {
  readonly watch: GuardWatch;
  readonly insn: NativePointer;
  readonly op: "r" | "w" | "x";
  readonly addr: NativePointer;
  readonly before: ArrayBuffer | null;
  readonly regs: Record<string, Hex> | null;
  readonly bt: string[] | null;
  readonly mem: WatchHit["mem"];
  readonly text: string | null;
}
export interface GuardCounters {
  readonly kernelRearms: number;
  readonly rearmFails: number;
  readonly tripped: boolean;
}

export class PageGuardEngine {
  /** page key → watches on it */
  readonly #byPage = new Map<string, Set<GuardWatch>>();
  readonly #watches = new Map<InstrumentId, GuardWatch>();
  /** per thread: the pages and hits of the guard faults waiting for their step, since `t0Us` (the first fault) */
  readonly #pending = new Map<number, { pages: GuardPageLike[]; hits: PendingHit[]; t0Us: number }>();
  #verifier: ReturnType<typeof setInterval> | null = null;
  constructor(
    private readonly pages: GuardPages,
    private readonly host: GuardHostHooks,
  ) {}

  ownsPage(address: NativePointer): boolean {
    const entry = this.pages.find(address);
    return entry !== null && this.#byPage.has(entry.key);
  }
  hasPendingStep(tid: number): boolean {
    return this.#pending.has(tid);
  }
  pageBases(): NativePointer[] {
    const out: NativePointer[] = [];
    for (const w of this.#watches.values())
      for (const p of w.pages) if (!out.some((b) => b.equals(p.base))) out.push(p.base);
    return out;
  }
  get pageCount(): number {
    return this.#byPage.size;
  }

  /** S4 §11.3 arm: refuse what must not be guarded, then register and guard every page of the range. */
  arm(
    spec: GuardWatchSpec,
  ): { readonly pages: Hex[]; readonly before: ArrayBuffer | null } | GuardRefusal | AgentError {
    const lo = bigOf(spec.address);
    const bases = pagesOf(lo, spec.size);
    for (const b of bases) {
      const refusal = this.#refusal(b, spec.access);
      if (refusal !== null) return refusal;
    }
    const entries: GuardPageLike[] = [];
    for (const b of bases) {
      const entry = this.pages.add(ptr(hexOf(b)), spec.owner);
      if ("_tag" in entry) {
        for (const done of entries) this.pages.removeOwner(done, spec.owner);
        return entry;
      }
      entries.push(entry);
    }
    const watch: GuardWatch = {
      spec,
      lo,
      hi: lo + BigInt(spec.size),
      pages: entries,
      valve: createRateValve(spec.rate, this.host.nowUs()),
      active: true,
      tripped: false,
      kernelRearms: 0,
      rearmFails: 0,
    };
    const before = readBytes(spec.address, spec.size);
    this.#watches.set(spec.owner, watch);
    for (const e of entries) {
      const set = this.#byPage.get(e.key) ?? new Set<GuardWatch>();
      set.add(watch);
      this.#byPage.set(e.key, set);
    }
    this.host.onPagesChanged(this.pageBases()); // published before the first page is guarded (safety net)
    for (const e of entries) if (!this.pages.arm(e)) watch.rearmFails += 1;
    this.#ensureVerifier();
    return { pages: bases.map((b) => hexOf(b)), before };
  }

  #refusal(base: bigint, access: GuardAccess): GuardRefusal | null {
    const page = ptr(hexOf(base));
    if (Cloak.hasRangeContaining(page)) return "agent-page";
    const region = queryRegion(page);
    if (
      region !== null &&
      access !== "execute" &&
      (region.protect & EXECUTABLE) !== 0 &&
      Process.findModuleByAddress(page) !== null
    )
      return "module-code";
    for (const t of Process.enumerateThreads()) {
      const stack = threadStack(t.id);
      if (stack !== null && overlaps(base, PAGE_SIZE, stack.limit, Number(stack.base - stack.limit)))
        return "stack-page";
    }
    return null;
  }

  #wanted(key: string): boolean {
    for (const w of this.#byPage.get(key) ?? []) if (w.active) return true;
    return false;
  }

  /**
   * Router hook for "guard-page" on a BEA page (S4 §11.3 onGuard); false when no watch of this engine owns it. A
   * failure while recording the hit loses that hit only: the fault is ours, so it is still claimed and the page is
   * re-armed after the step (never a dead target over a row).
   */
  onGuard(d: ExceptionDetails, tid: number): boolean {
    const memory = d.memory;
    if (memory === undefined || memory === null) return false;
    // this engine's own entry: the dispatcher's may come from BEA's table (pages mirrored as external entries)
    const page = this.pages.find(memory.address);
    if (page === null) return false;
    const watches = this.#byPage.get(page.key);
    if (watches === undefined) return false;
    this.pages.noteConsumed(page); // the OS cleared PAGE_GUARD for this access (F19)
    const now = this.host.nowUs();
    let hits: PendingHit[] = [];
    try {
      hits = this.#collect(d, memory, watches, now);
    } catch (e) {
      this.host.fault("pageguard.onGuard", e);
    }
    const nc = d.nativeContext;
    nc.add(CONTEXT.eflags).writeU32(nc.add(CONTEXT.eflags).readU32() | 0x100); // TF: re-execute, then step
    const pending = this.#pending.get(tid) ?? { pages: [], hits: [], t0Us: now };
    if (!pending.pages.includes(page)) pending.pages.push(page);
    pending.hits.push(...hits);
    this.#pending.set(tid, pending);
    this.host.onTrapFlag(tid, true);
    return true;
  }

  /** The hits of one guard fault: the rate valve, the access filter and the pre-access capture per watch. */
  #collect(
    d: ExceptionDetails,
    memory: ExceptionMemoryDetails,
    watches: ReadonlySet<GuardWatch>,
    now: number,
  ): PendingHit[] {
    const op = memory.operation === "write" ? "w" : memory.operation === "execute" ? "x" : "r";
    const a = bigOf(memory.address);
    const hits: PendingHit[] = [];
    for (const w of watches) {
      if (!w.active) continue;
      if (rateValveTrap(w.valve, now)) {
        this.#trip(w);
        continue;
      }
      const wanted = w.spec.access === "read-write" ? op !== "x" : w.spec.access === "write" ? op === "w" : op === "x";
      if (!wanted || a < w.lo || a >= w.hi) {
        w.spec.sink.filtered();
        continue;
      }
      const mem = memOperandOf(d.address, d.context);
      hits.push({
        watch: w,
        insn: d.address,
        op,
        addr: memory.address,
        before: this.#readWatched(w),
        regs: w.spec.capture.registers === "gpr" ? captureRegisters(d.context, GPR_NAMES) : null,
        bt: backtraceOf(d.context, w.spec.capture.backtrace),
        // the context is from BEFORE the faulting instruction: the base value is exact even when it is overwritten
        mem: mem === null ? null : { ...mem, base_written: false },
        text: this.#text(d.address),
      });
    }
    return hits;
  }

  #trip(w: GuardWatch): void {
    w.active = false;
    w.tripped = true;
    for (const p of w.pages) if (!this.#wanted(p.key)) this.pages.disarm(p);
    w.spec.sink.rateLimited({
      cause: w.valve.cause ?? "rate",
      limitPerSec: w.spec.rate.maxPerSec,
      peakPerSec: w.valve.peakPerSec,
      busyPct: w.valve.peakBusyPct,
      busyLimitPct: Math.round(VALVE_MAX_BUSY * 100),
    });
  }

  /**
   * The busy half of the valve: the time from a thread's first guard fault to its completed step (both exceptions,
   * the hits and the re-arm) is charged to every active watch on the faulted pages, as the rate is.
   */
  #chargeBusy(pages: readonly GuardPageLike[], t0Us: number): void {
    const now = this.host.nowUs();
    const charged = new Set<GuardWatch>();
    for (const page of pages)
      for (const w of this.#byPage.get(page.key) ?? []) {
        if (!w.active || charged.has(w)) continue;
        charged.add(w);
        if (rateValveBusy(w.valve, now, now - t0Us)) this.#trip(w);
      }
  }

  #text(at: NativePointer): string | null {
    return decodeInsn(at)?.text ?? null;
  }

  /**
   * Router hook for the single step owed to a guard hit (S4 §11.3 onStep). The trap flag is cleared first, so a
   * failure while delivering the hits never leaves the thread stepping; pages are re-armed after the hits were read.
   */
  onStep(d: ExceptionDetails, tid: number): boolean {
    const pending = this.#pending.get(tid);
    if (pending === undefined) return false;
    this.#pending.delete(tid);
    const nc = d.nativeContext;
    nc.add(CONTEXT.eflags).writeU32(nc.add(CONTEXT.eflags).readU32() & ~0x100);
    const dr6 = bigOf(nc.add(CONTEXT.dr6).readU64());
    nc.add(CONTEXT.dr6).writeU64(uint64((dr6 & ~0x4000n).toString())); // BS only: DR hits stay for hwbp
    this.host.onTrapFlag(tid, false);
    try {
      this.#deliver(tid, pending.hits);
    } catch (e) {
      this.host.fault("pageguard.onStep", e);
    }
    try {
      this.#rearm(pending.pages);
    } catch (e) {
      this.host.fault("pageguard.rearm", e);
    }
    try {
      this.#chargeBusy(pending.pages, pending.t0Us); // a trip here disarms the pages just re-armed
    } catch (e) {
      this.host.fault("pageguard.valve", e);
    }
    return true;
  }

  #deliver(tid: number, hits: readonly PendingHit[]): void {
    for (const h of hits) {
      if (!h.watch.active) continue;
      const verdict = h.watch.spec.sink.hit({
        tid,
        access: h.op,
        insn: h.insn,
        conf: "exact",
        pcAfter: null,
        text: h.text,
        addr: h.addr,
        before: h.before,
        after: this.#readWatched(h.watch),
        regs: h.regs,
        bt: h.bt,
        mem: h.mem,
      });
      if (verdict === "stop") h.watch.active = false;
    }
  }

  #rearm(pages: readonly GuardPageLike[]): void {
    for (const page of pages) {
      if (page.applied) continue;
      if (this.#wanted(page.key)) {
        if (!this.pages.arm(page)) for (const w of this.#byPage.get(page.key) ?? []) w.rearmFails += 1;
      } else if (page.desired) this.pages.disarm(page);
    }
  }

  /**
   * The watched bytes. Pages of the range that still carry PAGE_GUARD (multi-page watches) are read inside a
   * suspension window; the faulting page itself is already unguarded, so a single-page watch reads directly.
   */
  #readWatched(w: GuardWatch): ArrayBuffer | null {
    const armed = w.pages.filter((p) => p.applied).map((p) => ({ base: p.base, size: PAGE_SIZE }));
    const read = (): ArrayBuffer | null => this.host.readOnFaultingThread(w.spec.address, w.spec.size);
    return armed.length === 0 ? read() : this.pages.withBeaGuardsSuspended(armed, read);
  }

  /** Reads for other WP9 engines (poll) of a range that may lie on BEA pages. */
  read(address: NativePointer, size: number): ArrayBuffer | null {
    return this.pages.withBeaGuardsSuspended([{ base: address, size }], () => readBytes(address, size));
  }

  /**
   * S4 §11.3 verifier: a guard lost with no pending step for its page was consumed outside BEA (A-29): re-arm it. A
   * target VirtualProtect drops the guard too: then the protection changed, it is not counted as a kernel access, and
   * the guard goes back on over the target's new protection (AGENT-2).
   */
  #ensureVerifier(): void {
    if (this.#verifier !== null) return;
    this.#verifier = setInterval(() => {
      try {
        this.#verifyOnce();
      } catch (e) {
        this.host.fault("pageguard.verify", e);
      }
    }, VERIFY_EVERY_MS);
  }
  #verifyOnce(): void {
    const stepping = new Set<string>();
    for (const p of this.#pending.values()) for (const page of p.pages) stepping.add(page.key);
    const seen = new Set<string>();
    for (const w of this.#watches.values())
      for (const page of w.pages) {
        if (seen.has(page.key) || stepping.has(page.key)) continue;
        seen.add(page.key);
        if (!page.applied || this.pages.isGuardedNow(page)) continue;
        if (!this.pages.reprotected(page))
          for (const owner of this.#byPage.get(page.key) ?? []) owner.kernelRearms += 1;
        page.applied = false;
        this.pages.arm(page);
      }
  }

  counters(owner: InstrumentId): GuardCounters | null {
    const w = this.#watches.get(owner);
    return w === undefined ? null : { kernelRearms: w.kernelRearms, rearmFails: w.rearmFails, tripped: w.tripped };
  }

  /**
   * Disarm: drop the watch from its pages; the guard table removes the guard from pages left without owners, keeping
   * their current protection (the target's, when it re-protected one). Verified with VirtualQuery. A step still
   * pending for such a page sees the watch inactive and does not re-arm.
   */
  disarm(owner: InstrumentId): { ok: boolean; detail: string } {
    const w = this.#watches.get(owner);
    if (w === undefined) return { ok: true, detail: "not armed" };
    w.active = false;
    this.#watches.delete(owner);
    let failures = 0;
    let reprotected = 0;
    const leaving: GuardPageLike[] = [];
    for (const page of w.pages) {
      const set = this.#byPage.get(page.key);
      set?.delete(w);
      if (set !== undefined && set.size > 0) {
        this.pages.removeOwner(page, owner);
        continue;
      }
      this.#byPage.delete(page.key);
      this.pages.disarm(page); // guard removed now; the table keeps the page for in-flight faults
      if ((page.reprotects ?? 0) > 0) reprotected += 1;
      if (this.pages.isGuardedNow(page)) failures += 1;
      leaving.push(page);
    }
    if (leaving.length > 0)
      setTimeout(() => {
        for (const page of leaving) if (!this.#byPage.has(page.key)) this.pages.removeOwner(page, owner);
      }, RELEASE_GRACE_MS);
    this.host.onPagesChanged(this.pageBases());
    if (this.#watches.size === 0 && this.#verifier !== null) {
      clearInterval(this.#verifier);
      this.#verifier = null;
    }
    const kept = reprotected === 0 ? "" : `; ${String(reprotected)} page(s) keep the protection the target set`;
    return failures === 0
      ? { ok: true, detail: `no PAGE_GUARD left on the watch's pages${kept}` }
      : { ok: false, detail: `${String(failures)} page(s) still guarded${kept}` };
  }

  /** dispose (unload): restore every page synchronously (the WP3 table restores its own pages too). */
  disarmAllSync(): void {
    for (const w of this.#watches.values()) {
      w.active = false;
      for (const page of w.pages) this.pages.disarm(page);
    }
    if (this.#verifier !== null) {
      clearInterval(this.#verifier);
      this.#verifier = null;
    }
  }
}
