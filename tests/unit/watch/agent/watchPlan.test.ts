import { describe, expect, it } from "vitest";

import * as core from "../../../../src/agent/pure/coreWin64.js";
import {
  addBounded,
  changedCells,
  createRateValve,
  guardToggle,
  overlaps,
  pagesOf,
  rateValveBusy,
  rateValveTrap,
  removeSwap,
  reprotectedSince,
  VALVE_MAX_BUSY,
} from "../../../../src/agent/pure/watchPlan.js";

describe("page planning", () => {
  it("lists the 4 KiB pages a range touches", () => {
    expect(pagesOf(0x1000n, 4)).toEqual([0x1000n]);
    expect(pagesOf(0x1ffen, 4)).toEqual([0x1000n, 0x2000n]);
    expect(pagesOf(0x1000n, 65_536)).toHaveLength(16);
    expect(pagesOf(0x1001n, 65_536)).toHaveLength(17);
    expect(pagesOf(0x1000n, 0)).toEqual([]);
  });

  it("intersects half-open ranges", () => {
    expect(overlaps(0x1000n, 0x1000, 0x1fffn, 1)).toBe(true);
    expect(overlaps(0x1000n, 0x1000, 0x2000n, 1)).toBe(false);
    expect(overlaps(0x2000n, 8, 0x1000n, 0x1000)).toBe(false);
  });
});

describe("guard toggles relative to the current protection (review fix AGENT-2)", () => {
  // [current protection, want guard, expected write]: RO armed, the target made it RW (dropping the guard): re-arm over
  // RW, and a stop writes nothing; a stop under BEA's guard keeps the current base (RX); NOACCESS takes no guard
  const cases: [number, boolean, number | "unchanged" | "refused"][] = [
    [0x04, true, 0x104],
    [0x04, false, "unchanged"],
    [0x120, false, 0x20],
    [0x104, true, "unchanged"],
    [0x01, true, "refused"],
    [0x01, false, "unchanged"],
    [0x102, false, 0x02],
  ];
  it.each(cases)("current 0x%s, guard %s: %s (WP9 copy and WP3 copy agree)", (cur, want, expected) => {
    expect(guardToggle(cur, want)).toBe(expected);
    expect(core.guardToggle(cur, want)).toBe(expected);
  });

  it("detects a re-protection on the base protection only", () => {
    for (const f of [reprotectedSince, core.reprotectedSince]) {
      expect(f(0x02, 0x04)).toBe(true);
      expect(f(0x02, 0x102)).toBe(false);
      expect(f(0x104, 0x04)).toBe(false);
      expect(f(0x04, 0x20)).toBe(true);
    }
  });
});

describe("rate valve (CT-I4)", () => {
  it("allows maxPerSec × window and trips exactly once above it", () => {
    const valve = createRateValve({ maxPerSec: 20_000, windowMs: 100 }, 0);
    expect(valve.limit).toBe(2000);
    let trips = 0;
    for (let i = 0; i < 2000; i++) if (rateValveTrap(valve, 10)) trips++;
    expect(trips).toBe(0);
    expect(rateValveTrap(valve, 11)).toBe(true);
    expect(rateValveTrap(valve, 12)).toBe(false);
    expect(valve.tripped).toBe(true);
    expect(valve.peakPerSec).toBeGreaterThanOrEqual(20_000);
  });

  it("restarts the count in every new window (a steady rate under the limit never trips)", () => {
    const valve = createRateValve({ maxPerSec: 1000, windowMs: 100 }, 0);
    let now = 0;
    for (let i = 0; i < 10_000; i++) {
      now += 1500; // 1.5 ms apart: ~667 traps/s
      expect(rateValveTrap(valve, now)).toBe(false);
    }
    expect(valve.tripped).toBe(false);
    expect(valve.peakPerSec).toBeGreaterThan(500);
    expect(valve.peakPerSec).toBeLessThan(1000);
  });

  it("trips on handling time when slow traps keep the rate under the limit (the WP9 acceptance hot page)", () => {
    // ≈ 18,000 traps/s at ≈ 55 µs each: the rate never reaches 20,000/s, the thread is in BEA's handlers ~99 %
    const valve = createRateValve({ maxPerSec: 20_000, windowMs: 100 }, 0);
    let now = 0;
    let tripsAt = -1;
    for (let i = 0; i < 20_000 && tripsAt < 0; i++) {
      now += 55;
      const byRate = rateValveTrap(valve, now);
      if (byRate || rateValveBusy(valve, now + 1, 54)) tripsAt = now;
    }
    expect(valve.cause).toBe("busy");
    expect(tripsAt).toBeGreaterThan(50_000); // after half a window of handling, inside the first window
    expect(tripsAt).toBeLessThan(100_000);
    expect(valve.peakBusyPct).toBeGreaterThan(VALVE_MAX_BUSY * 100);
    expect(valve.peakPerSec).toBeGreaterThan(15_000);
    expect(valve.peakPerSec).toBeLessThan(20_000);
    expect(rateValveBusy(valve, now + 100, 1000)).toBe(false); // once
    expect(rateValveTrap(valve, now + 100)).toBe(false);
  });

  it("does not trip on handling time below half a window, and restarts it every window", () => {
    // a game physics page: ~1,500 accesses/s at 55 µs = 8 % of the time, for 10 s
    const valve = createRateValve({ maxPerSec: 20_000, windowMs: 100 }, 0);
    let now = 0;
    for (let i = 0; i < 15_000; i++) {
      now += 667;
      expect(rateValveTrap(valve, now)).toBe(false);
      expect(rateValveBusy(valve, now + 55, 55)).toBe(false);
    }
    expect(valve.tripped).toBe(false);
    expect(valve.peakBusyPct).toBeGreaterThan(5);
    expect(valve.peakBusyPct).toBeLessThan(12);
  });

  it("keeps the rate criterion for fast traps (the CT-lab engine at ≈ 9 µs)", () => {
    const valve = createRateValve({ maxPerSec: 20_000, windowMs: 100 }, 0);
    let now = 0;
    let tripped = false;
    for (let i = 0; i < 5000 && !tripped; i++) {
      now += 40; // 25,000 traps/s
      tripped = rateValveTrap(valve, now) || rateValveBusy(valve, now + 9, 9);
    }
    expect(tripped).toBe(true);
    expect(valve.cause).toBe("rate");
  });
});

describe("poll change cells", () => {
  it("reports the 8-byte cells that differ, with a short last cell", () => {
    const prev = new Uint8Array(20);
    const next = new Uint8Array(20);
    next[9] = 1;
    next[19] = 7;
    const cells = changedCells(prev, next);
    expect(cells.map((c) => c.offset)).toEqual([8, 16]);
    expect(cells[1]?.now).toEqual(new Uint8Array([0, 0, 0, 7]));
    expect(changedCells(prev, prev.slice())).toEqual([]);
  });
});

describe("safety-net tables", () => {
  it("adds once, refuses when full and removes by swapping", () => {
    const list: number[] = [];
    expect(addBounded(list, 1, 2)).toBe(true);
    expect(addBounded(list, 1, 2)).toBe(true);
    expect(addBounded(list, 2, 2)).toBe(true);
    expect(addBounded(list, 3, 2)).toBe(false);
    expect(removeSwap(list, 1)).toBe(true);
    expect(list).toEqual([2]);
    expect(removeSwap(list, 9)).toBe(false);
  });
});
