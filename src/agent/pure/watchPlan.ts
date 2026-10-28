// =================================================================================================
// src/agent/pure/watchPlan.ts — page-guard planning, the CT-I4 rate valve, poll change cells and the safety-net
// bookkeeping (S4 §11.3, DESIGN §5.3; WP9-WATCH). Pure: no GumJS globals or types.
// =================================================================================================

export const PAGE_SIZE = 4096;
/** DESIGN §6.2 #23: a page_guard watch covers at most 16 pages. */
export const PAGE_GUARD_MAX_PAGES_TOOL = 16;
/** DESIGN §5.3: the leaked safety net tracks at most 64 guard pages and 64 trap-flag threads. */
export const SAFETY_NET_MAX_PAGES = 64;
export const SAFETY_NET_MAX_TIDS = 64;
/** Poll rows report changes per 8-byte cell (relative to the watched address); the host splits cells by view. */
const POLL_CELL_BYTES = 8;

/** Page bases (4 KiB) covering [address, address+size). */
export const pagesOf = (address: bigint, size: number, pageSize = PAGE_SIZE): bigint[] => {
  if (size <= 0) return [];
  const mask = ~BigInt(pageSize - 1);
  const first = address & mask;
  const last = (address + BigInt(size) - 1n) & mask;
  const out: bigint[] = [];
  for (let p = first; p <= last; p += BigInt(pageSize)) out.push(p);
  return out;
};

/** True when [a, a+n) and [b, b+m) intersect. */
export const overlaps = (a: bigint, n: number, b: bigint, m: number): boolean => a < b + BigInt(m) && b < a + BigInt(n);

// ---------------------------------------------------------------- guard toggles (review fix AGENT-2)

const PAGE_GUARD = 0x100;
const PAGE_NOACCESS = 0x01;

/**
 * What a page-guard toggle writes, given the page's CURRENT protection `cur` (VirtualQuery right before the write):
 * "unchanged" when PAGE_GUARD already is in the wanted state, "refused" for a guard on PAGE_NOACCESS (VirtualProtect
 * rejects the combination), else `cur` with the guard added or removed. A protection remembered at arm time is never
 * written back: the target may have re-protected the page since. The same rule as pure/coreWin64.ts guardToggle (the
 * WP3 guard table); each side keeps its own copy because the WP9 and WP3 test builds stage only their own pure files.
 */
export const guardToggle = (cur: number, want: boolean): number | "unchanged" | "refused" => {
  if (((cur & PAGE_GUARD) !== 0) === want) return "unchanged";
  if (want && (cur & 0xff) === PAGE_NOACCESS) return "refused";
  return want ? cur | PAGE_GUARD : cur & ~PAGE_GUARD;
};

/** The target changed the page's protection since BEA recorded `orig` (guard bits ignored on both sides). */
export const reprotectedSince = (orig: number, cur: number): boolean => (cur & ~PAGE_GUARD) !== (orig & ~PAGE_GUARD);

// ---------------------------------------------------------------- rate valve (CT-I4)

export interface RateValveConfig {
  /** traps (hits + filtered) per second above which the watch disarms; default 20,000 */
  readonly maxPerSec: number;
  /** measurement window; default 100 ms */
  readonly windowMs: number;
}
export const DEFAULT_RATE_VALVE: RateValveConfig = { maxPerSec: 20_000, windowMs: 100 };
/**
 * The valve also trips when handling the traps (guard fault to completed step) held the target for more than this
 * share of a window. WP9 acceptance: the production handler costs ≈ 55 µs per access on this host (two exceptions
 * through the JS dispatcher; the CT-lab engine measured ≈ 9 µs), so a hot page tops out near 18,000 traps/s and the
 * rate criterion alone never tripped while the trapping thread did almost nothing but take traps.
 */
export const VALVE_MAX_BUSY = 0.5;

export interface RateValve {
  readonly limit: number;
  readonly windowUs: number;
  windowStartUs: number;
  count: number;
  /** handling time accounted in the current window (µs; several threads add up) */
  busyUs: number;
  tripped: boolean;
  /** what tripped it: the trap rate, or the time the target spent in BEA's handlers */
  cause: "rate" | "busy" | null;
  /** the highest per-second rate seen at a window end (diagnostics) */
  peakPerSec: number;
  /** the highest share of a window spent handling traps, in percent (diagnostics) */
  peakBusyPct: number;
}

/** Traps allowed per window: maxPerSec × windowMs / 1000 (20,000/s over 100 ms = 2,000), at least 1. */
export const createRateValve = (config: RateValveConfig, nowUs: number): RateValve => ({
  limit: Math.max(1, Math.floor((config.maxPerSec * config.windowMs) / 1000)),
  windowUs: Math.max(1, config.windowMs) * 1000,
  windowStartUs: nowUs,
  count: 0,
  busyUs: 0,
  tripped: false,
  cause: null,
  peakPerSec: 0,
  peakBusyPct: 0,
});

/** Tumbling windows: at a window end, record its peaks and start counting again. */
const rollWindow = (valve: RateValve, nowUs: number): void => {
  if (nowUs - valve.windowStartUs < valve.windowUs) return;
  const elapsed = Math.max(1, nowUs - valve.windowStartUs);
  valve.peakPerSec = Math.max(valve.peakPerSec, Math.round((valve.count * 1_000_000) / elapsed));
  valve.peakBusyPct = Math.max(valve.peakBusyPct, Math.round((valve.busyUs * 100) / elapsed));
  valve.windowStartUs = nowUs;
  valve.count = 0;
  valve.busyUs = 0;
};

/**
 * Count one trap (a hit or a filtered same-page access). Returns true exactly once over both criteria: on the trap
 * that pushes the current window above its limit. A trip is permanent (the engine disarms without re-arming).
 */
export const rateValveTrap = (valve: RateValve, nowUs: number): boolean => {
  if (valve.tripped) return false;
  rollWindow(valve, nowUs);
  valve.count += 1;
  if (valve.count > valve.limit) {
    valve.tripped = true;
    valve.cause = "rate";
    valve.peakPerSec = Math.max(valve.peakPerSec, Math.round((valve.count * 1_000_000) / valve.windowUs));
    return true;
  }
  return false;
};

/**
 * Account the handling time of one trap (from its guard fault to its completed step, waits for the JS lock
 * included: the target thread is held either way). Returns true exactly once over both criteria: when the current
 * window's handling time passes VALVE_MAX_BUSY of the window.
 */
export const rateValveBusy = (valve: RateValve, nowUs: number, busyUs: number): boolean => {
  if (valve.tripped) return false;
  rollWindow(valve, nowUs);
  valve.busyUs += Math.max(0, busyUs);
  if (valve.busyUs > valve.windowUs * VALVE_MAX_BUSY) {
    valve.tripped = true;
    valve.cause = "busy";
    const elapsed = Math.max(1, nowUs - valve.windowStartUs); // the part of the window seen so far
    valve.peakBusyPct = Math.max(valve.peakBusyPct, Math.round((valve.busyUs * 100) / elapsed));
    valve.peakPerSec = Math.max(valve.peakPerSec, Math.round((valve.count * 1_000_000) / elapsed));
    return true;
  }
  return false;
};

// ---------------------------------------------------------------- poll cells

export interface ChangedCell {
  /** offset from the watched address (multiple of POLL_CELL_BYTES) */
  readonly offset: number;
  readonly old: Uint8Array;
  readonly now: Uint8Array;
}

/** The 8-byte cells whose bytes differ between two samples of equal length (the last cell may be shorter). */
export const changedCells = (prev: Uint8Array, next: Uint8Array): ChangedCell[] => {
  const out: ChangedCell[] = [];
  const n = Math.min(prev.length, next.length);
  for (let off = 0; off < n; off += POLL_CELL_BYTES) {
    const end = Math.min(n, off + POLL_CELL_BYTES);
    let differs = false;
    for (let i = off; i < end; i++)
      if (prev[i] !== next[i]) {
        differs = true;
        break;
      }
    if (differs) out.push({ offset: off, old: prev.slice(off, end), now: next.slice(off, end) });
  }
  return out;
};

// ---------------------------------------------------------------- safety-net tables

/** Insert into a bounded set kept as a dense array; returns false when full. */
export const addBounded = <T>(list: T[], value: T, max: number): boolean => {
  if (list.includes(value)) return true;
  if (list.length >= max) return false;
  list.push(value);
  return true;
};

/** Remove one occurrence (swap with the last element, like the native table). */
export const removeSwap = <T>(list: T[], value: T): boolean => {
  const at = list.indexOf(value);
  if (at < 0) return false;
  const last = list.pop() as T;
  if (at < list.length) list[at] = last;
  return true;
};
