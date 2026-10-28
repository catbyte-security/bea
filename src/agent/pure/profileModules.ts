// Module table of the profile engine (WP-BEHAVIOR). Fed ONLY from module-observer callbacks (the initial synchronous
// onAdded calls and later loads/unloads), so no code path that runs while hooks are active ever enumerates modules:
// module enumeration takes the loader lock, and a JS callback holding the script lock that waits for the loader lock
// deadlocks against a loader thread that enters a hooked function (observed as an intermittent hang of behavior.exe).
// Pure: addresses are bigint.

export interface ModuleEntry {
  readonly name: string;
  readonly path: string;
  readonly base: bigint;
  readonly size: number;
}

export class ModuleTable {
  /** sorted by base */
  private entries: ModuleEntry[] = [];

  get size(): number {
    return this.entries.length;
  }

  add(entry: ModuleEntry): void {
    this.remove(entry.base);
    let lo = 0;
    let hi = this.entries.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if ((this.entries[mid]?.base ?? 0n) < entry.base) lo = mid + 1;
      else hi = mid;
    }
    this.entries.splice(lo, 0, entry);
  }

  remove(base: bigint): void {
    const i = this.entries.findIndex((e) => e.base === base);
    if (i >= 0) this.entries.splice(i, 1);
  }

  /** The module containing `address`, or null. */
  find(address: bigint): ModuleEntry | null {
    let lo = 0;
    let hi = this.entries.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      const e = this.entries[mid];
      if (e === undefined) return null;
      if (address < e.base) hi = mid - 1;
      else if (address >= e.base + BigInt(e.size)) lo = mid + 1;
      else return e;
    }
    return null;
  }

  findByName(name: string): ModuleEntry | null {
    const lower = name.toLowerCase();
    return this.entries.find((e) => e.name.toLowerCase() === lower) ?? null;
  }

  /** Name of the module whose base is exactly `base` (a module handle), or null. */
  nameAt(base: bigint): string | null {
    const e = this.find(base);
    return e !== null && e.base === base ? e.name : null;
  }
}

/** "c:\windows\" prefix test for ApiRow.caller's "outside system modules" rule (case-insensitive). */
export const isUnder = (path: string, rootLower: string): boolean => path.toLowerCase().startsWith(rootLower);
