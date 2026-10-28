// =================================================================================================
// src/agent/guards.ts — WP3-AGENT BEA guard-page table and withBeaGuardsSuspended (DESIGN §5.3 `guards`, CT-I5,
// D-INT-44). The table is shared by the page-guard watch engine (WP9 pageguard.ts) and every agent reader:
//  - withBeaGuardsSuspended(ranges, fn) removes PAGE_GUARD from intersecting BEA pages (restoring origProtect), runs
//    fn, re-arms, and counts one `bea_guard_suspended` window per page on each owning instrument. Frida's try-scope
//    APIs (read*, scanSync, Memory.copy, findPointers, NativeFunction steal) consume a guard before BEA's dispatcher
//    sees it [CT-lab E6–E9, E16b], so every agent access path to target memory goes through this primitive.
//  - listRanges/describeAddresses re-insert BEA-guarded pages with their origProtect (Frida omits guarded pages from
//    enumerateRanges, [CT-lab E16b]).
//  - A stolen guard-page on a BEA page (a guard consumed outside a suspension window) marks it disarmed, re-arms at
//    once and counts one window — never `kernel_access_suspected` (that is the WP9 verifier's own signal).
//  - A fallback trap engine keeps a BEA page armed when no engine claimed its trap: TF step, then re-apply the guard
//    (the lossless F19 mechanism). WP9's page-guard router claims its own pages first.
//  - Every protection write toggles PAGE_GUARD relative to the page's CURRENT protection (VirtualQuery right before the
//    VirtualProtect; review fix AGENT-2). The protection seen at add() is never written back: a target that re-protects
//    a watched page (RO → RW, RW → RX) keeps its protection, which becomes the entry's origProtect.
// =================================================================================================
import type { AgentError, Hex, InstrumentId, ThreadId } from "../shared/agentProtocol.js";
import { big, hex } from "./encode.js";
import { guardPageAddressOf } from "./pure/coreErrors.js";
import { overlaps, pageBaseOf, type RangeRec } from "./pure/coreRanges.js";
import {
  CTX,
  guardToggle,
  isGuardProtect,
  MEM_COMMIT,
  parseMbi,
  protectionText,
  reprotectedSince,
  withoutGuard,
} from "./pure/coreWin64.js";
import type { AgentCore } from "./state.js";

/**
 * A page whose PAGE_GUARD another engine applies and re-arms itself (WP9 pageguard.ts seam `guards.add(page, entry)`):
 * the table still suspends it for BEA reads, re-inserts it in listings and reports stolen guards to it.
 */
export interface ExternalGuardEntry {
  readonly origProtect: number;
  readonly owner: string;
  isArmed(): boolean;
  /** a BEA access suspended the guard: count one window */
  onSuspended(): void;
  /** a BEA access consumed the guard outside a window: re-arm now and count one window */
  onStolen(): void;
}

export interface GuardPageEntry {
  readonly base: NativePointer;
  readonly key: string;
  /** the page's protection without PAGE_GUARD as BEA last saw it (updated at every toggle: the target may change it) */
  origProtect: number;
  /** times a toggle found a protection the target had set (it was kept and adopted as origProtect) */
  reprotects?: number;
  readonly owners: Set<string>;
  /** set when another engine owns the arm state (WP9); the table never re-arms such a page on its own */
  external: ExternalGuardEntry | null;
  /** what the owners want: PAGE_GUARD present */
  desired: boolean;
  /** PAGE_GUARD is applied as far as BEA knows (the OS clears it on a trap) */
  applied: boolean;
  /** open suspension windows */
  suspended: number;
  windows: number;
  stolen: number;
  rearmFails: number;
  fallbackTraps: number;
}

export interface GuardRange {
  readonly base: NativePointer;
  readonly size: number;
}

const TF = 0x100;

export class GuardTable {
  readonly #core: AgentCore;
  readonly #pages = new Map<string, GuardPageEntry>();
  /** fallback engine: threads with a pending TF re-arm, and the pages to re-arm */
  readonly #pendingSteps = new Map<ThreadId, GuardPageEntry[]>();
  #oldProt: NativePointer | null = null;
  #mbi: NativePointer | null = null;

  constructor(core: AgentCore) {
    this.#core = core;
  }

  get #ps(): number {
    return Process.pageSize;
  }

  /**
   * Register `owner` on the page containing `address` (not armed yet). The original protection is read with
   * VirtualQuery; a page that is not committed or already carries the target's own PAGE_GUARD is refused.
   */
  add(address: NativePointer, owner: string): GuardPageEntry | AgentError {
    const base = ptr(hex(pageBaseOf(big(address), this.#ps)));
    const key = base.toString();
    const existing = this.#pages.get(key);
    if (existing !== undefined) {
      existing.owners.add(owner);
      return existing;
    }
    const max = this.#core.limits.page_guard_max_pages;
    if (this.#pages.size >= max)
      return { _tag: "ResourceLimit", message: "too many BEA guard pages", resource: "page_guard_pages", limit: max };
    const mbi = this.query(base);
    if (mbi === null || mbi.state !== MEM_COMMIT)
      return { _tag: "WatchInvalid", message: "the page is not committed", reason: "range" };
    if (isGuardProtect(mbi.protect))
      return { _tag: "WatchInvalid", message: "the page already has the target's PAGE_GUARD", reason: "range" };
    const entry: GuardPageEntry = {
      base,
      key,
      origProtect: withoutGuard(mbi.protect),
      owners: new Set([owner]),
      desired: false,
      applied: false,
      suspended: 0,
      windows: 0,
      stolen: 0,
      rearmFails: 0,
      fallbackTraps: 0,
      external: null,
    };
    this.#pages.set(key, entry);
    return entry;
  }

  /** WP9 seam: register a page another engine arms (`watchSeam.guards.add`). */
  addExternal(page: NativePointer, external: ExternalGuardEntry): void {
    const base = ptr(hex(pageBaseOf(big(page), this.#ps)));
    const key = base.toString();
    const existing = this.#pages.get(key);
    if (existing !== undefined) {
      existing.external = external;
      existing.owners.add(external.owner);
      return;
    }
    this.#pages.set(key, {
      base,
      key,
      origProtect: withoutGuard(external.origProtect),
      owners: new Set([external.owner]),
      desired: false,
      applied: false,
      suspended: 0,
      windows: 0,
      stolen: 0,
      rearmFails: 0,
      fallbackTraps: 0,
      external,
    });
  }

  /** WP9 seam: the engine dropped the page (`watchSeam.guards.remove`). */
  removeExternal(page: NativePointer): void {
    const entry = this.find(page);
    if (entry === null || entry.external === null) return;
    entry.owners.delete(entry.external.owner);
    entry.external = null;
    if (entry.owners.size === 0) this.#pages.delete(entry.key);
  }

  /** WP12 seam: [address, address+size) intersects a BEA guard page. */
  isGuarded(address: NativePointer, size: number): boolean {
    return this.intersecting(address, Math.max(1, size)).length > 0;
  }

  /** Remove `owner`; the last owner removes BEA's guard and drops the page. Returns true when the page is gone. */
  removeOwner(entry: GuardPageEntry, owner: string): boolean {
    entry.owners.delete(owner);
    if (entry.owners.size > 0) return false;
    this.disarm(entry);
    this.#pages.delete(entry.key);
    return true;
  }

  /** Apply PAGE_GUARD over the current protection (deferred to the end of an open suspension window). */
  arm(entry: GuardPageEntry): boolean {
    entry.desired = true;
    if (entry.suspended > 0 || entry.applied) return true;
    const ok = this.#toggle(entry, true);
    if (ok) entry.applied = true;
    else entry.rearmFails++;
    return ok;
  }

  /** Remove PAGE_GUARD, keeping the current protection (a no-op when the guard is already gone). */
  disarm(entry: GuardPageEntry): boolean {
    entry.desired = false;
    if (!entry.applied) return true;
    const ok = this.#toggle(entry, false);
    if (ok) entry.applied = false;
    return ok;
  }

  /** The target changed the page's protection since BEA last toggled it (guard bits ignored; VirtualQuery now). */
  reprotected(entry: GuardPageEntry): boolean {
    const mbi = this.query(entry.base);
    return mbi !== null && mbi.state === MEM_COMMIT && reprotectedSince(entry.origProtect, mbi.protect);
  }

  /** The OS cleared the guard of this page (a trap was raised on it). */
  noteConsumed(entry: GuardPageEntry): void {
    entry.applied = false;
  }

  /** The BEA page containing `address`, or null. */
  find(address: NativePointer | bigint): GuardPageEntry | null {
    const a = typeof address === "bigint" ? address : big(address);
    return this.#pages.get(hex(pageBaseOf(a, this.#ps))) ?? null;
  }

  ownsPage(address: NativePointer | bigint): boolean {
    return this.find(address) !== null;
  }

  entries(): GuardPageEntry[] {
    return [...this.#pages.values()];
  }

  get size(): number {
    return this.#pages.size;
  }

  /** BEA pages intersecting [base, base+size). */
  intersecting(base: NativePointer, size: number): GuardPageEntry[] {
    const b = big(base);
    return this.entries().filter((e) => overlaps(big(e.base), this.#ps, b, size));
  }

  /** Pages to re-insert into range listings, with their protection now (without BEA's guard). */
  listingPages(): RangeRec[] {
    return this.entries().map((e) => {
      const mbi = this.query(e.base);
      return {
        base: big(e.base),
        size: this.#ps,
        protection: protectionText(
          mbi !== null && mbi.state === MEM_COMMIT ? withoutGuard(mbi.protect) : e.origProtect,
        ),
      };
    });
  }

  /** PAGE_GUARD currently present (VirtualQuery; fingerprint and tests). */
  isGuardedNow(entry: GuardPageEntry): boolean {
    const mbi = this.query(entry.base);
    return mbi !== null && isGuardProtect(mbi.protect);
  }

  /**
   * Run `fn` with the BEA guards of every page intersecting `ranges` removed, then re-arm them. Counts one
   * bea_guard_suspended window per page on each owning instrument. `fn` should be synchronous; a returned promise
   * keeps the pages unguarded until it settles.
   */
  withBeaGuardsSuspended<T>(ranges: readonly GuardRange[], fn: (pages: readonly GuardPageEntry[]) => T): T {
    const pages = new Set<GuardPageEntry>();
    for (const r of ranges)
      for (const e of this.intersecting(r.base, r.size)) if (e.desired || e.external?.isArmed() === true) pages.add(e);
    if (pages.size === 0) return fn([]);
    const list = [...pages];
    for (const e of list) this.#openWindow(e);
    let result: T;
    try {
      result = fn(list);
    } catch (e) {
      for (const p of list) this.#closeWindow(p);
      this.noteThrown(e);
      throw e;
    }
    if (result instanceof Promise) {
      return result.finally(() => {
        for (const p of list) this.#closeWindow(p);
      }) as T;
    }
    for (const p of list) this.#closeWindow(p);
    return result;
  }

  /** A guard consumed outside a window on a BEA page: re-arm at once and count one window. */
  noteStolen(address: bigint): boolean {
    const entry = this.find(address);
    if (entry === null) return false;
    entry.stolen++;
    if (entry.external !== null) {
      entry.external.onStolen();
      return true;
    }
    entry.applied = false;
    this.#countWindow(entry);
    if (entry.desired && entry.suspended === 0) this.arm(entry);
    return true;
  }

  /** Stolen-guard detection from a thrown Frida error ("guard page was hit accessing 0x…"). */
  noteThrown(e: unknown): boolean {
    const text = e instanceof Error ? e.message : typeof e === "string" ? e : "";
    const address = guardPageAddressOf(text);
    return address !== null && this.noteStolen(address);
  }

  /**
   * Fallback engine, guard-page trap on a BEA page nobody claimed: the OS already cleared the guard; set TF so the
   * instruction re-executes once, then re-arm on the step (F19). Returns true (handled).
   */
  fallbackOnGuard(entry: GuardPageEntry, nativeContext: NativePointer, tid: ThreadId): boolean {
    entry.fallbackTraps++;
    if (entry.external !== null && !entry.external.isArmed()) return true;
    const eflags = nativeContext.add(CTX.EFlags);
    eflags.writeU32(eflags.readU32() | TF);
    const pending = this.#pendingSteps.get(tid) ?? [];
    pending.push(entry);
    this.#pendingSteps.set(tid, pending);
    return true;
  }

  hasPendingStep(tid: ThreadId): boolean {
    return this.#pendingSteps.has(tid);
  }

  /** Fallback engine, the single-step after a guard trap: re-arm, clear TF and DR6. */
  fallbackOnStep(nativeContext: NativePointer, tid: ThreadId): boolean {
    const pending = this.#pendingSteps.get(tid);
    if (pending === undefined) return false;
    this.#pendingSteps.delete(tid);
    for (const entry of pending) {
      if (!this.#pages.has(entry.key)) continue;
      if (entry.external !== null) {
        if (entry.external.isArmed() && entry.suspended === 0) this.#toggle(entry, true);
      } else if (entry.desired) this.arm(entry);
    }
    const eflags = nativeContext.add(CTX.EFlags);
    eflags.writeU32(eflags.readU32() & ~TF);
    nativeContext.add(CTX.Dr6).writeU64(0);
    return true;
  }

  /**
   * dispose / shutdown: remove BEA's guard from every page synchronously, keeping each page's current protection;
   * returns the number of pages left without a guard.
   */
  disarmAll(): number {
    let n = 0;
    for (const entry of this.#pages.values()) {
      if (entry.external !== null) n += this.#toggle(entry, false) ? 1 : 0;
      else if (entry.applied || entry.desired) n += this.disarm(entry) ? 1 : 0;
    }
    return n;
  }

  /** Suspended page addresses as Hex (ReadMemoryMeta.bea_guard_suspended). */
  static pagesHex(pages: readonly GuardPageEntry[]): Hex[] {
    return pages.map((p) => hex(p.base));
  }

  /** VirtualQuery one address (exclusive binding); null on failure. */
  query(address: NativePointer): ReturnType<typeof parseMbi> | null {
    this.#mbi ??= Memory.alloc(48);
    const n = this.#core.win.VirtualQuery(address, this.#mbi, 48);
    if (n.toNumber() === 0) return null;
    const ab = this.#mbi.readByteArray(48);
    return ab === null ? null : parseMbi(new Uint8Array(ab));
  }

  #openWindow(entry: GuardPageEntry): void {
    entry.suspended++;
    if (entry.suspended !== 1) return;
    entry.windows++;
    if (entry.external !== null) {
      entry.external.onSuspended();
      this.#toggle(entry, false);
      return;
    }
    this.#countWindow(entry);
    if (entry.applied && this.#toggle(entry, false)) entry.applied = false;
  }

  #closeWindow(entry: GuardPageEntry): void {
    entry.suspended = Math.max(0, entry.suspended - 1);
    if (entry.suspended !== 0 || !this.#pages.has(entry.key)) return;
    if (entry.external !== null) {
      if (entry.external.isArmed()) this.#toggle(entry, true);
    } else if (entry.desired) this.arm(entry);
  }

  /**
   * Set (`want`) or clear PAGE_GUARD relative to the page's CURRENT protection (AGENT-2): a remembered protection is
   * never written back. The current protection becomes the entry's origProtect (the target may have re-protected the
   * page). A page that is no longer committed is left alone. True when the page ends in the wanted state.
   */
  #toggle(entry: GuardPageEntry, want: boolean): boolean {
    const mbi = this.query(entry.base);
    if (mbi === null || mbi.state !== MEM_COMMIT) return !want;
    if (reprotectedSince(entry.origProtect, mbi.protect)) {
      entry.origProtect = withoutGuard(mbi.protect);
      entry.reprotects = (entry.reprotects ?? 0) + 1;
    }
    const next = guardToggle(mbi.protect, want);
    if (next === "unchanged") return true;
    if (next === "refused") return false;
    return this.#protect(entry.base, next);
  }

  #countWindow(entry: GuardPageEntry): void {
    for (const owner of entry.owners) {
      const inst = this.#core.instruments.get(owner as InstrumentId);
      if (inst !== null) inst.counters.bea_guard_suspended++;
    }
  }

  #protect(base: NativePointer, protect: number): boolean {
    this.#oldProt ??= Memory.alloc(8);
    return this.#core.win.VirtualProtect(base, this.#ps, protect, this.#oldProt) !== 0;
  }
}

/** The design's primitive: `withBeaGuardsSuspended(ranges, fn)` on the agent core's guard table. @public */
export const withBeaGuardsSuspended = <T>(
  core: AgentCore,
  ranges: readonly GuardRange[],
  fn: (pages: readonly GuardPageEntry[]) => T,
): T => core.guards.withBeaGuardsSuspended(ranges, fn);
