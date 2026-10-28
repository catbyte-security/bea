// Memory-map watcher of the memory_protection profile (S4 §10.7). NtAllocateVirtualMemory/VirtualAlloc cannot be
// hooked (F8), so new executable regions are found by sampling: a JS-thread timer enumerates '--x' ranges and diffs
// them (pure diff in ./pure/profileSelect.ts). Sampled state, not an event log: short-lived regions can be missed,
// which is why profiles.ts also probes a region's protection when it is freed (NtFreeVirtualMemory, `seen:"free"`).
import type { Hex } from "../shared/hex.js";
import type { ModuleTable } from "./pure/profileModules.js";
import { diffExecRanges, type MemmapEvent, type RangeView } from "./pure/profileSelect.js";

const COST_LIMIT_MS = 20;
const MAX_INTERVAL_MS = 10_000;

const viewOf = (r: RangeDetails, modules: ModuleTable): RangeView => ({
  base: r.base.toString() as Hex,
  size: r.size,
  protection: r.protection,
  module: modules.find(BigInt(r.base.toString()))?.name ?? null,
});

export class MemmapWatcher {
  private readonly tracked = new Map<Hex, RangeView>();
  private timer: ReturnType<typeof setTimeout> | null = null;
  private interval: number;
  private stopped = false;
  /** ticks that exceeded the cost guard (diagnostic) */
  slowTicks = 0;

  constructor(
    intervalMs: number,
    /** the profiles' observer-fed module table (never enumerated here: see ./pure/profileModules.ts) */
    private readonly modules: ModuleTable,
    private readonly emit: (ev: MemmapEvent, seen: "scan" | "free") => void,
  ) {
    this.interval = intervalMs;
  }

  /** Baseline (no events for regions that already exist), then periodic ticks. */
  start(): void {
    this.scan(false);
    this.schedule();
  }

  stop(): void {
    this.stopped = true;
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
  }

  /**
   * NtFreeVirtualMemory probe (target thread, inside the hook): an executable non-module region about to be released
   * that the sampler never saw is reported once as new-exec/new-rwx with seen:"free".
   */
  probeFree(base: NativePointer): void {
    if (this.stopped || base.isNull()) return;
    const range = Process.findRangeByAddress(base);
    if (range === null || !range.protection.includes("x") || Cloak.hasRangeContaining(range.base)) return;
    if (this.modules.find(BigInt(range.base.toString())) !== null) return;
    const key = range.base.toString() as Hex;
    if (this.tracked.delete(key)) return; // the sampler reported it; its "gone" is implied by the free row
    this.emit(
      {
        ev: range.protection.includes("w") ? "new-rwx" : "new-exec",
        base: key,
        size: range.size,
        protection: range.protection,
        module: null,
      },
      "free",
    );
  }

  private schedule(): void {
    if (this.stopped) return;
    this.timer = setTimeout(() => {
      this.timer = null;
      const t0 = Date.now();
      this.scan(true);
      if (Date.now() - t0 > COST_LIMIT_MS) {
        this.slowTicks++;
        this.interval = Math.min(this.interval * 2, MAX_INTERVAL_MS);
      }
      this.schedule();
    }, this.interval);
  }

  private scan(report: boolean): void {
    let current: RangeView[];
    try {
      current = Process.enumerateRanges({ protection: "--x", coalesce: false }).map((r) => viewOf(r, this.modules));
    } catch {
      return;
    }
    const lookup = (base: Hex): RangeView | null => {
      const r = Process.findRangeByAddress(ptr(base));
      return r === null ? null : viewOf(r, this.modules);
    };
    const events = diffExecRanges(this.tracked, current, lookup);
    if (report) for (const ev of events) this.emit(ev, "scan");
  }
}
