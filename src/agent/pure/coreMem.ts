// =================================================================================================
// src/agent/pure/coreMem.ts — WP3-AGENT pure helpers: the guard-aware read plan of readMemory / readTyped / capture
// derefs (S4 §8.2, CT-I5). The agent walks VirtualQuery regions from the start address; this module decides where a
// read must stop and which BEA guard pages it must suspend. A target PAGE_GUARD page is never touched (reading it
// would consume the application's guard, A-18); a BEA page is read inside withBeaGuardsSuspended.
// =================================================================================================
import { isGuardProtect, isReadableProtect, MEM_COMMIT, MEM_FREE, MEM_RESERVE, type Mbi } from "./coreWin64.js";

export type ReadStopReason = "unmapped" | "protection" | "guard-page" | "access-violation";

/** How one VirtualQuery region may be read. */
export type RegionClass = "readable" | "guard" | Exclude<ReadStopReason, "guard-page" | "access-violation">;

export const classifyRegion = (mbi: Pick<Mbi, "state" | "protect">): RegionClass => {
  if (mbi.state === MEM_FREE || mbi.state === MEM_RESERVE || mbi.state !== MEM_COMMIT) return "unmapped";
  if (isGuardProtect(mbi.protect)) return isReadableProtect(mbi.protect) ? "guard" : "protection";
  return isReadableProtect(mbi.protect) ? "readable" : "protection";
};

export interface ReadPlan {
  /** readable prefix length from the start */
  readonly readable: number;
  readonly stop: { readonly reason: ReadStopReason; readonly at: bigint } | null;
  /** BEA guard pages inside the readable prefix (to suspend during the read) */
  readonly beaPages: readonly bigint[];
}

export interface PlanInput {
  readonly start: bigint;
  readonly size: number;
  readonly pageSize: number;
  /** VirtualQuery at an address (null when the call fails: treated as unmapped) */
  readonly query: (addr: bigint) => Mbi | null;
  /** the page base is a BEA guard page (its PAGE_GUARD is BEA's own) */
  readonly isBeaPage: (pageBase: bigint) => boolean;
  /** bound on regions visited (defensive; 4096 by default) */
  readonly maxRegions?: number;
}

/** Walk regions from `start` until `size` bytes are covered or a region stops the read. */
export const planRead = (input: PlanInput): ReadPlan => {
  const { start, size, pageSize } = input;
  const end = start + BigInt(size);
  const ps = BigInt(pageSize);
  const beaPages: bigint[] = [];
  let cursor = start;
  for (let visited = 0; cursor < end && visited < (input.maxRegions ?? 4096); visited++) {
    const mbi = input.query(cursor);
    if (mbi === null) return stopAt(start, cursor, "unmapped", beaPages);
    const regionEnd = mbi.base + mbi.regionSize;
    if (regionEnd <= cursor) return stopAt(start, cursor, "unmapped", beaPages);
    const cls = classifyRegion(mbi);
    const upto = regionEnd < end ? regionEnd : end;
    if (cls === "readable") {
      cursor = upto;
      continue;
    }
    if (cls !== "guard") return stopAt(start, cursor, cls, beaPages);
    // Guarded region: every page must be BEA's own; stop at the first target guard page.
    for (let page = cursor - (cursor % ps); page < upto; page += ps) {
      if (!input.isBeaPage(page)) return stopAt(start, page > cursor ? page : cursor, "guard-page", beaPages);
      beaPages.push(page);
    }
    cursor = upto;
  }
  return cursor >= end ? { readable: size, stop: null, beaPages } : stopAt(start, cursor, "unmapped", beaPages);
};

const stopAt = (start: bigint, at: bigint, reason: ReadStopReason, beaPages: readonly bigint[]): ReadPlan => ({
  readable: Number(at - start),
  stop: { reason, at },
  beaPages: beaPages.filter((p) => p < at),
});

/** Readable prefix of a page-wise fallback read: index of the first failing page. */
export const firstFailingPage = (pageOk: readonly boolean[]): number => {
  const i = pageOk.indexOf(false);
  return i === -1 ? pageOk.length : i;
};
