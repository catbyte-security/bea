// WP3-AGENT unit tests: the guard-aware read plan (S4 §8.2, CT-I5, A-18) and range/listing helpers (S4 §8.5): BEA
// guard-page re-insertion into enumerateRanges listings [CT-lab E16b], protection filters, binary searches, globs,
// paging and the TTL/LRU snapshot store.
import { describe, expect, it } from "vitest";

import { classifyRegion, firstFailingPage, planRead } from "../../../../src/agent/pure/coreMem.js";
import {
  coalesceRanges,
  findPdataIndex,
  globToRegExp,
  lastIndexAtOrBelow,
  overlaps,
  pageBaseOf,
  pagesCovering,
  paginate,
  protectionMatches,
  reinsertGuardPages,
  TtlLru,
} from "../../../../src/agent/pure/coreRanges.js";
import type { Mbi } from "../../../../src/agent/pure/coreWin64.js";

const PS = 0x1000;
const region = (base: number, pages: number, protect: number, state = 0x1000): Mbi => ({
  base: BigInt(base),
  allocationBase: BigInt(base),
  regionSize: BigInt(pages * PS),
  state,
  protect,
  type: 0x20000,
});

/** A fake VirtualQuery over a list of regions. */
const queryOf =
  (regions: readonly Mbi[]) =>
  (a: bigint): Mbi | null =>
    regions.find((r) => a >= r.base && a < r.base + r.regionSize) ?? null;

describe("read plan", () => {
  it("classifies regions", () => {
    expect(classifyRegion({ state: 0x10000, protect: 0 })).toBe("unmapped");
    expect(classifyRegion({ state: 0x2000, protect: 0 })).toBe("unmapped");
    expect(classifyRegion({ state: 0x1000, protect: 0x01 })).toBe("protection");
    expect(classifyRegion({ state: 0x1000, protect: 0x10 })).toBe("protection");
    expect(classifyRegion({ state: 0x1000, protect: 0x104 })).toBe("guard");
    expect(classifyRegion({ state: 0x1000, protect: 0x20 })).toBe("readable");
  });

  it("reads across readable regions and stops at the first unreadable one", () => {
    const query = queryOf([region(0x10000, 1, 0x04), region(0x11000, 2, 0x20), region(0x13000, 1, 0x01)]);
    expect(planRead({ start: 0x10800n, size: 0x1000, pageSize: PS, query, isBeaPage: () => false })).toEqual({
      readable: 0x1000,
      stop: null,
      beaPages: [],
    });
    expect(planRead({ start: 0x12ff0n, size: 0x20, pageSize: PS, query, isBeaPage: () => false })).toEqual({
      readable: 0x10,
      stop: { reason: "protection", at: 0x13000n },
      beaPages: [],
    });
    expect(planRead({ start: 0x9000n, size: 4, pageSize: PS, query, isBeaPage: () => false })).toMatchObject({
      readable: 0,
      stop: { reason: "unmapped", at: 0x9000n },
    });
  });

  it("suspends BEA guard pages but never touches a target guard page", () => {
    const query = queryOf([region(0x20000, 1, 0x04), region(0x21000, 2, 0x104), region(0x23000, 1, 0x04)]);
    const bea = new Set([0x21000n, 0x22000n]);
    expect(planRead({ start: 0x20000n, size: 0x4000, pageSize: PS, query, isBeaPage: (p) => bea.has(p) })).toEqual({
      readable: 0x4000,
      stop: null,
      beaPages: [0x21000n, 0x22000n],
    });
    const onlyFirst = new Set([0x21000n]);
    expect(
      planRead({ start: 0x20f00n, size: 0x3000, pageSize: PS, query, isBeaPage: (p) => onlyFirst.has(p) }),
    ).toEqual({
      readable: 0x1100,
      stop: { reason: "guard-page", at: 0x22000n },
      beaPages: [0x21000n],
    });
    expect(planRead({ start: 0x21010n, size: 8, pageSize: PS, query, isBeaPage: () => false })).toEqual({
      readable: 0,
      stop: { reason: "guard-page", at: 0x21010n },
      beaPages: [],
    });
  });

  it("finds the first failing page of a page-wise fallback", () => {
    expect(firstFailingPage([true, true, false, true])).toBe(2);
    expect(firstFailingPage([true, true])).toBe(2);
  });
});

describe("ranges", () => {
  it("does page arithmetic", () => {
    expect(pageBaseOf(0x12345n, PS)).toBe(0x12000n);
    expect(pagesCovering(0x12ff0n, 0x20, PS)).toEqual([0x12000n, 0x13000n]);
    expect(pagesCovering(0x1000n, 0, PS)).toEqual([]);
    expect(overlaps(0x1000n, 0x1000, 0x1fffn, 1)).toBe(true);
    expect(overlaps(0x1000n, 0x1000, 0x2000n, 1)).toBe(false);
  });

  it("applies Frida's minimum-protection filters", () => {
    expect(protectionMatches("rw-", "rw-")).toBe(true);
    expect(protectionMatches("rwx", "rw-")).toBe(true);
    expect(protectionMatches("r-x", "rw-")).toBe(false);
    expect(protectionMatches("---", "---")).toBe(true);
    expect(protectionMatches("r--", "r--")).toBe(true);
  });

  it("re-inserts BEA guard pages with their original protection and coalesces", () => {
    // Frida split a 3-page rw- region around the guarded middle page (it omits PAGE_GUARD pages)
    const live = [
      { base: 0x30000n, size: PS, protection: "rw-" },
      { base: 0x32000n, size: PS, protection: "rw-" },
    ];
    const pages = [
      { base: 0x31000n, size: PS, protection: "rw-" },
      { base: 0x50000n, size: PS, protection: "r--" },
    ];
    expect(reinsertGuardPages(live, pages, "rw-", true)).toEqual([{ base: 0x30000n, size: 3 * PS, protection: "rw-" }]);
    expect(reinsertGuardPages(live, pages, "r--", false)).toEqual([
      { base: 0x30000n, size: PS, protection: "rw-" },
      { base: 0x31000n, size: PS, protection: "rw-" },
      { base: 0x32000n, size: PS, protection: "rw-" },
      { base: 0x50000n, size: PS, protection: "r--" },
    ]);
    // a page some listed range already covers is not duplicated
    expect(reinsertGuardPages([{ base: 0x31000n, size: PS, protection: "rw-" }], pages, "rw-", false)).toHaveLength(1);
    expect(
      coalesceRanges([
        { base: 0n, size: 1, protection: "r--" },
        { base: 1n, size: 1, protection: "rw-" },
      ]),
    ).toHaveLength(2);
  });

  it("binary-searches exports and .pdata", () => {
    const vas = [0x1000n, 0x1800n, 0x2000n];
    expect(lastIndexAtOrBelow(vas, 0x17ffn)).toBe(0);
    expect(lastIndexAtOrBelow(vas, 0x2000n)).toBe(2);
    expect(lastIndexAtOrBelow(vas, 0xfffn)).toBe(-1);
    const begins = [0x1000, 0x1017, 0x17a0];
    const ends = [0x1017, 0x1030, 0x18bd];
    expect(findPdataIndex(begins, ends, 0x17a0)).toBe(2);
    expect(findPdataIndex(begins, ends, 0x18bc)).toBe(2);
    expect(findPdataIndex(begins, ends, 0x18bd)).toBe(-1);
    expect(findPdataIndex(begins, ends, 0x1030)).toBe(-1);
    expect(findPdataIndex(begins, ends, 0x1016)).toBe(0);
  });

  it("matches names with case-insensitive globs", () => {
    expect(globToRegExp("game_sim*").test("GAME_SIM.EXE")).toBe(true);
    expect(globToRegExp("math?ib.dll").test("mathlib.dll")).toBe(true);
    expect(globToRegExp("a.b").test("axb")).toBe(false);
    expect(globToRegExp("(x)*").test("(x)y")).toBe(true);
  });

  it("pages lists with clamped limits", () => {
    const items = [1, 2, 3, 4, 5];
    expect(paginate(items, 0, 2, 5000)).toEqual({ total: 5, offset: 0, items: [1, 2], next_offset: 2 });
    expect(paginate(items, 4, 2, 5000)).toEqual({ total: 5, offset: 4, items: [5], next_offset: null });
    expect(paginate(items, 0, 999, 3).items).toEqual([1, 2, 3]);
    expect(paginate(items, -5, 0, 3)).toMatchObject({ offset: 0, items: [1] });
  });

  it("keeps snapshots for their TTL, refreshed on use, at most max (LRU)", () => {
    const s = new TtlLru<string>(1000, 2);
    s.put("ss1", "a", 0);
    s.put("ss2", "b", 10);
    expect(s.get("ss1", 500)).toBe("a"); // refreshed: now the most recent
    s.put("ss3", "c", 600); // evicts the least recently used (ss2)
    expect(s.get("ss2", 600)).toBeNull();
    expect(s.get("ss1", 1400)).toBe("a");
    expect(s.get("ss3", 1700)).toBeNull(); // expired
    expect(s.size).toBe(1);
  });
});
