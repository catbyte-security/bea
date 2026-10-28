import { describe, expect, it } from "vitest";

import { ScanEngine, selectRegions, type ScanJobWork } from "../../../src/agent/pure/scanEngine.js";
import { utf16Encode, utf8Encode } from "../../../src/agent/pure/scanValue.js";
import type { AgentResult, ScanStartParams, ScanStatus } from "../../../src/shared/agentProtocol.js";
import { createFakePlatform, FakeMemory, LIMITS, runToEnd, type FakePlatform } from "./support/fakePlatform.js";

/** WP10-SCAN engine (S4 §9) over a fake address space with the JS reference kernels. */
const MiB = 1024 * 1024;
const HEAP = 0x2000_0000;
const IMAGE = 0x1_4000_0000;

const setup = (limits = LIMITS) => {
  const mem = new FakeMemory();
  const platform = createFakePlatform(mem);
  const engine = new ScanEngine(platform, () => limits);
  return { mem, platform, engine };
};

const unwrap = <T>(r: AgentResult<T>): T => {
  if (!r.ok) throw new Error(`agent error ${JSON.stringify(r.error)}`);
  return r.value;
};

const scan = (engine: ScanEngine, p: Partial<ScanStartParams> & Pick<ScanStartParams, "kind">): ScanStatus => {
  const work = unwrap(engine.start({ regions: { protection: "rw-" }, ...p }));
  runToEnd(work);
  return work.outcome().result;
};

const next = (engine: ScanEngine, scanId: string, p: Omit<Parameters<ScanEngine["next"]>[0], "scan_id">) => {
  const work = unwrap(engine.next({ scan_id: scanId, ...p }));
  runToEnd(work);
  return work.outcome().result;
};

const hitAddresses = (engine: ScanEngine, scanId: string): number[] =>
  unwrap(engine.results({ scan_id: scanId, offset: 0, limit: 1000, read_current: false })).items.map((h) =>
    Number(h.address),
  );

describe("selectRegions", () => {
  const raw = [
    { base: 0x3000, size: 0x1000, protection: "rw-", module: "game.exe" },
    { base: 0x1000, size: 0x1000, protection: "rw-", module: null },
    { base: 0x9000, size: 0x10_0000, protection: "rw-", module: "NTDLL.dll" },
  ];
  it('filters by module ("*" = any image), exclusion, private_only, window and size; sorted by base', () => {
    expect(selectRegions(raw, { protection: "rw-" }).map((r) => r.base)).toEqual([0x1000, 0x3000, 0x9000]);
    expect(selectRegions(raw, { protection: "rw-", modules: ["*"] }).map((r) => r.base)).toEqual([0x3000, 0x9000]);
    expect(selectRegions(raw, { protection: "rw-", modules: ["ntdll.DLL"] }).map((r) => r.base)).toEqual([0x9000]);
    expect(selectRegions(raw, { protection: "rw-", exclude_modules: ["*"] }).map((r) => r.base)).toEqual([0x1000]);
    expect(selectRegions(raw, { protection: "rw-", private_only: true }).map((r) => r.base)).toEqual([0x1000]);
    expect(selectRegions(raw, { protection: "rw-", max_region_bytes: 0x1000 }).map((r) => r.base)).toEqual([
      0x1000, 0x3000,
    ]);
    expect(selectRegions(raw, { protection: "rw-", min: "0x1800", max: "0x3800" })).toEqual([
      { base: 0x1800, size: 0x800, module: null },
      { base: 0x3000, size: 0x800, module: "game.exe" },
    ]);
  });
});

describe("first scans", () => {
  it("exact i32 honours alignment and records history, bytes and regions", () => {
    const { mem, engine } = setup();
    mem.map(HEAP, 0x4000);
    mem.writeI32(HEAP + 0x100, 1337);
    mem.writeI32(HEAP + 0x203, 1337); // unaligned
    const aligned = scan(engine, { kind: "value", value_type: "i32", compare: { op: "eq", value: 1337 } });
    expect(aligned).toMatchObject({ state: "ready", count: 1, regions: 1, bytes_scanned: 0x4000, mode: "explicit" });
    expect(aligned.ops).toEqual([expect.objectContaining({ op: "eq", count_after: 1 })]);
    const any = scan(engine, { kind: "value", value_type: "i32", compare: { op: "eq", value: "0x539" }, align: 1 });
    expect(hitAddresses(engine, any.scan_id)).toEqual([HEAP + 0x100, HEAP + 0x203]);
  });

  it("finds elements that straddle the 8 MiB kernel slice and the pattern slice", () => {
    const { mem, engine } = setup();
    mem.map(HEAP, 9 * MiB);
    mem.writeI32(HEAP + 8 * MiB - 2, -77);
    mem.write(HEAP + 2 * MiB - 5, utf8Encode("BEA_MARKER"));
    const ints = scan(engine, { kind: "value", value_type: "i32", compare: { op: "eq", value: -77 }, align: 2 });
    expect(hitAddresses(engine, ints.scan_id)).toEqual([HEAP + 8 * MiB - 2]);
    const text = scan(engine, { kind: "value", value_type: "utf8", compare: { op: "eq", text: "BEA_MARKER" } });
    expect(hitAddresses(engine, text.scan_id)).toEqual([HEAP + 2 * MiB - 5]);
  });

  it("f32 range, approx, IEEE zero and exact-bits compares", () => {
    const { mem, engine } = setup();
    mem.map(HEAP, 0x1000);
    mem.writeF32(HEAP + 0x10, 24.0);
    mem.writeF32(HEAP + 0x14, 24.5);
    mem.writeF32(HEAP + 0x20, -0);
    mem.writeF32(HEAP + 0x24, 20.0);
    const range = scan(engine, { kind: "value", value_type: "f32", compare: { op: "range", min: 23.9, max: 24.3 } });
    expect(hitAddresses(engine, range.scan_id)).toEqual([HEAP + 0x10]);
    const near = scan(engine, { kind: "value", value_type: "f32", compare: { op: "approx", value: 24.4, eps: 0.2 } });
    expect(hitAddresses(engine, near.scan_id)).toEqual([HEAP + 0x14]);
    const zeros = scan(engine, { kind: "value", value_type: "f32", compare: { op: "eq", value: 0 } });
    expect(zeros.count).toBe(0x1000 / 4 - 3); // +0 everywhere else, and the -0 cell
    const negZero = scan(engine, {
      kind: "value",
      value_type: "f32",
      compare: { op: "eq", value: { bits: "0x80000000" } },
    });
    expect(hitAddresses(engine, negZero.scan_id)).toEqual([HEAP + 0x20]);
    const gt = scan(engine, { kind: "value", value_type: "f32", compare: { op: "gt", value: 20 } });
    expect(gt.count).toBe(2);
  });

  it("patterns with wildcards read the matched bytes; utf16 text; a regex is refused", () => {
    const { mem, engine } = setup();
    mem.map(HEAP, 0x1000);
    mem.write(HEAP + 0x40, Uint8Array.from([0xde, 0x11, 0xbe, 0xef]));
    mem.write(HEAP + 0x80, utf16Encode("Wide"));
    const pat = scan(engine, { kind: "pattern", pattern: "de ?? be ef" });
    const page = unwrap(engine.results({ scan_id: pat.scan_id, offset: 0, limit: 10, read_current: true }));
    expect(page.items).toEqual([
      {
        address: `0x${(HEAP + 0x40).toString(16)}`,
        stored: { type: "bytes", value: null, hex: "de11beef" },
        current: { type: "bytes", value: null, hex: "de11beef" },
      },
    ]);
    const wide = scan(engine, { kind: "value", value_type: "utf16", compare: { op: "eq", text: "Wide" } });
    expect(hitAddresses(engine, wide.scan_id)).toEqual([HEAP + 0x80]);
    const regex = engine.start({ kind: "pattern", pattern: "/BEA_v\\d/", regions: { protection: "rw-" } });
    expect(regex.ok || regex.error._tag).toBe("BadParams");
  });

  it("pointers-to finds aligned words equal to a target, optionally in images only", () => {
    const { mem, engine } = setup();
    mem.map(HEAP, 0x1000);
    mem.map(IMAGE, 0x1000, { module: "game_sim.exe" });
    const target = HEAP + 0x200;
    mem.writeU64(HEAP + 0x10, target);
    mem.writeU64(IMAGE + 0x88, target);
    const all = scan(engine, { kind: "pointers-to", targets: [`0x${target.toString(16)}`] });
    expect(hitAddresses(engine, all.scan_id)).toEqual([HEAP + 0x10, IMAGE + 0x88]);
    const images = scan(engine, {
      kind: "pointers-to",
      targets: [`0x${target.toString(16)}`],
      regions: { protection: "rw-", modules: ["*"] },
    });
    expect(hitAddresses(engine, images.scan_id)).toEqual([IMAGE + 0x88]);
    const stored = unwrap(engine.results({ scan_id: images.scan_id, offset: 0, limit: 1, read_current: false }));
    expect(stored.items[0]?.stored).toEqual({ type: "ptr", value: `0x${target.toString(16)}` });
  });

  it("skips unreadable regions and counts them", () => {
    const { mem, engine } = setup();
    mem.map(HEAP, 0x1000).unreadable = true;
    mem.map(HEAP + 0x10000, 0x1000);
    mem.writeI32(HEAP + 0x10010, 5);
    const r = scan(engine, { kind: "value", value_type: "i32", compare: { op: "eq", value: 5 } });
    expect(r).toMatchObject({ state: "ready", count: 1, unreadable_regions: 1, regions: 2 });
  });
});

describe("caps, growth, slicing and cancellation", () => {
  it("grows the candidate arrays past the initial capacity", () => {
    const { mem, engine, platform } = setup();
    mem.map(HEAP, 512 * 1024);
    const r = scan(engine, { kind: "value", value_type: "i32", compare: { op: "eq", value: 0 } });
    expect(r).toMatchObject({ state: "ready", count: 131_072 });
    expect(r.memory_bytes).toBeGreaterThanOrEqual(131_072 * 12);
    unwrap(engine.close(r.scan_id));
    expect(platform.allocated).toBe(0);
  });

  it("stops at max_candidates with ResourceLimit and keeps what it found (narrowable)", () => {
    const { mem, engine } = setup();
    mem.map(HEAP, 0x1000);
    const r = scan(engine, { kind: "value", value_type: "u8", compare: { op: "eq", value: 0 }, max_candidates: 5 });
    expect(r).toMatchObject({ state: "failed", count: 5 });
    expect(r.error).toMatchObject({ _tag: "ResourceLimit", resource: "scan_candidates", limit: 5 });
    mem.write(HEAP + 2, Uint8Array.from([9]));
    expect(next(engine, r.scan_id, { op: "changed" })).toMatchObject({ state: "ready", count: 1 });
  });

  it("slices by time budget, reports byte progress and can be cancelled with partial results", () => {
    const { mem, engine, platform } = setup();
    for (let i = 0; i < 3; i++) mem.map(HEAP + i * 16 * MiB, 9 * MiB);
    platform.tickMs = 10; // every clock read eats the 8 ms budget: one chunk per step
    const work: ScanJobWork = unwrap(
      engine.start({
        kind: "value",
        value_type: "i64",
        compare: { op: "eq", value: 1 },
        regions: { protection: "rw-" },
      }),
    );
    expect(work.step(8)).toBe("more");
    const first = work.progress();
    expect(first).toEqual({ done: 8 * MiB, total: 27 * MiB, unit: "bytes" });
    expect(work.step(8)).toBe("more");
    expect(work.progress().done).toBe(9 * MiB);
    work.cancel();
    expect(work.step(8)).toBe("done");
    const out = work.outcome();
    expect(out.state).toBe("cancelled");
    expect(out.result).toMatchObject({ state: "failed", error: { _tag: "Cancelled", phase: "scan-first" } });
  });

  it("limits open scans and snapshot size", () => {
    const { mem, engine } = setup({ ...LIMITS, scan_max_concurrent: 2, scan_snapshot_bytes: 0x1800 });
    mem.map(HEAP, 0x1000);
    mem.map(HEAP + 0x10000, 0x1000);
    const unknown = engine.start({ kind: "unknown", value_type: "i32", regions: { protection: "rw-" } });
    expect(unknown.ok || unknown.error).toMatchObject({
      _tag: "ResourceLimit",
      resource: "scan_snapshot",
      limit: 0x1800,
      observed: 0x2000,
    });
    scan(engine, { kind: "value", value_type: "i32", compare: { op: "eq", value: 1 } });
    scan(engine, { kind: "value", value_type: "i32", compare: { op: "eq", value: 1 } });
    const third = engine.start({
      kind: "value",
      value_type: "i32",
      compare: { op: "eq", value: 1 },
      regions: { protection: "rw-" },
    });
    expect(third.ok || third.error).toMatchObject({ _tag: "ResourceLimit", resource: "scans", limit: 2 });
  });
});

describe("next scans", () => {
  const prepared = () => {
    const ctx = setup();
    ctx.mem.map(HEAP, 0x4000);
    for (let i = 0; i < 8; i++) ctx.mem.writeI32(HEAP + 0x100 * i, 50);
    const first = scan(ctx.engine, { kind: "value", value_type: "i32", compare: { op: "eq", value: 50 } });
    return { ...ctx, id: first.scan_id };
  };

  it("narrows with relative ops and keeps first values for same_as_first", () => {
    const { mem, engine, id } = prepared();
    mem.writeI32(HEAP + 0x000, 55); // +5
    mem.writeI32(HEAP + 0x100, 45); // -5
    mem.writeI32(HEAP + 0x200, 52); // +2
    expect(next(engine, id, { op: "changed" })).toMatchObject({ count: 3, state: "ready" });
    mem.writeI32(HEAP + 0x200, 57); // +5 from 52
    expect(next(engine, id, { op: "increased_by", value: 5 })).toMatchObject({ count: 1 });
    expect(hitAddresses(engine, id)).toEqual([HEAP + 0x200]);
    mem.writeI32(HEAP + 0x200, 50);
    expect(next(engine, id, { op: "same_as_first" })).toMatchObject({ count: 1 });
    const status = unwrap(engine.status(id));
    expect(status.ops.map((o) => [o.op, o.count_after])).toEqual([
      ["eq", 8],
      ["changed", 3],
      ["increased_by", 1],
      ["same_as_first", 1],
    ]);
  });

  it("drops the candidates of a page that became unreadable and resumes after it", () => {
    const { mem, engine, id } = prepared();
    mem.regions[0]?.deadPages?.add(HEAP + 0x0000); // candidates at +0x000 … +0x700 live on the first page
    mem.writeI32(HEAP + 0x1000, 50); // not a candidate
    const r = next(engine, id, { op: "unchanged" });
    expect(r).toMatchObject({ count: 0, faulted_candidates_dropped: 8, state: "ready" });
  });

  it("refuses a second job while one runs and unknown ids", () => {
    const { engine, id } = prepared();
    unwrap(engine.next({ scan_id: id, op: "unchanged" }));
    expect(engine.next({ scan_id: id, op: "unchanged" })).toMatchObject({ ok: false, error: { _tag: "BadParams" } });
    expect(engine.results({ scan_id: id, offset: 0, limit: 1, read_current: false })).toMatchObject({ ok: false });
    expect(engine.status("sc999")).toMatchObject({ ok: false, error: { _tag: "NotFound", what: "scan" } });
  });

  it("float increased_by honours eps", () => {
    const { mem, engine } = setup();
    mem.map(HEAP, 0x100);
    mem.writeF32(HEAP + 8, 20);
    const id = scan(engine, { kind: "value", value_type: "f32", compare: { op: "eq", value: 20 } }).scan_id;
    mem.writeF32(HEAP + 8, 21.50001); // +1.50001 in f32
    expect(next(engine, id, { op: "increased_by", value: 1.5 }).count).toBe(0);
    const again = scan(engine, { kind: "value", value_type: "f32", compare: { op: "approx", value: 21.5, eps: 0.01 } });
    mem.writeF32(HEAP + 8, 23.00002);
    expect(next(engine, again.scan_id, { op: "increased_by", value: 1.5, eps: 1e-4 }).count).toBe(1);
  });
});

describe("unknown-value scans", () => {
  it("snapshots, then narrows into explicit candidates", () => {
    const { mem, engine } = setup();
    mem.map(HEAP, 0x1000);
    mem.writeF32(HEAP + 0x40, 10);
    const first = scan(engine, { kind: "unknown", value_type: "f32" });
    expect(first).toMatchObject({ mode: "snapshot", count: 0x1000 / 4, state: "ready" });
    expect(engine.results({ scan_id: first.scan_id, offset: 0, limit: 1, read_current: false })).toMatchObject({
      ok: false,
      error: { _tag: "BadParams" },
    });
    mem.writeF32(HEAP + 0x40, 12);
    mem.writeF32(HEAP + 0x80, -3);
    const up = next(engine, first.scan_id, { op: "increased" });
    expect(up).toMatchObject({ mode: "explicit", count: 1, state: "ready" });
    expect(hitAddresses(engine, first.scan_id)).toEqual([HEAP + 0x40]);
    mem.writeF32(HEAP + 0x40, 10);
    expect(next(engine, first.scan_id, { op: "same_as_first" }).count).toBe(1);
  });
});

describe("results and guards", () => {
  it("pages within scan_page_rows, re-reads current values and reports unreadable ones", () => {
    const { mem, engine } = setup({ ...LIMITS, scan_page_rows: 3 });
    const region = mem.map(HEAP, 0x2000);
    for (let i = 0; i < 5; i++) mem.writeI32(HEAP + 0x1000 + 4 * i, 7);
    const id = scan(engine, { kind: "value", value_type: "i32", compare: { op: "eq", value: 7 } }).scan_id;
    const page = unwrap(engine.results({ scan_id: id, offset: 0, limit: 50, read_current: true }));
    expect(page).toMatchObject({ total: 5, offset: 0, next_offset: 3 });
    expect(page.items[0]).toMatchObject({ stored: { type: "i32", value: 7 }, current: { type: "i32", value: 7 } });
    region.deadPages?.add(HEAP + 0x1000);
    const later = unwrap(engine.results({ scan_id: id, offset: 3, limit: 50, read_current: true }));
    expect(later.next_offset).toBeNull();
    expect(later.items[0]?.current).toMatchObject({ error: { _tag: "AccessViolation" } });
  });

  it("runs every slice, kernel call and read inside a guard-suspension span covering the memory touched", () => {
    const { mem, engine, platform }: { mem: FakeMemory; engine: ScanEngine; platform: FakePlatform } = setup();
    mem.map(HEAP, 0x1000);
    mem.writeI32(HEAP + 0x800, 3);
    const id = scan(engine, { kind: "value", value_type: "i32", compare: { op: "eq", value: 3 } }).scan_id;
    next(engine, id, { op: "unchanged" });
    engine.results({ scan_id: id, offset: 0, limit: 5, read_current: true });
    const covers = (va: number) => platform.suspended.filter((s) => s.base <= va && va + 4 <= s.base + s.size).length;
    expect(covers(HEAP + 0x800)).toBe(3);
  });
});

describe("job refusal and next cancellation", () => {
  it("abandon closes a first scan and leaves a next scan narrowable with its candidates", () => {
    const { mem, engine } = setup();
    mem.map(HEAP, 0x1000);
    for (let i = 0; i < 4; i++) mem.writeI32(HEAP + 16 * i, 9);
    const refused = unwrap(
      engine.start({
        kind: "value",
        value_type: "i32",
        compare: { op: "eq", value: 9 },
        regions: { protection: "rw-" },
      }),
    );
    engine.abandon(refused);
    expect(engine.list()).toEqual([]);
    const id = scan(engine, { kind: "value", value_type: "i32", compare: { op: "eq", value: 9 } }).scan_id;
    const work = unwrap(engine.next({ scan_id: id, op: "changed" }));
    engine.abandon(work);
    expect(unwrap(engine.status(id))).toMatchObject({
      state: "failed",
      count: 4,
      error: { _tag: "Cancelled", phase: "scan-next" },
    });
    expect(next(engine, id, { op: "unchanged" })).toMatchObject({ state: "ready", count: 4 });
  });

  it("a cancelled next keeps the unexamined candidates behind the kept ones", () => {
    const { mem, engine, platform } = setup();
    mem.map(HEAP, 0x400000);
    const id = scan(engine, { kind: "value", value_type: "i32", compare: { op: "eq", value: 0 } }).scan_id; // 1M candidates
    mem.writeI32(HEAP, 1);
    platform.tickMs = 10; // one 262,144-candidate chunk per step
    const work = unwrap(engine.next({ scan_id: id, op: "unchanged" }));
    expect(work.step(8)).toBe("more");
    expect(work.progress()).toEqual({ done: 262_144, total: 1_048_576, unit: "items" });
    work.cancel();
    work.step(8);
    expect(unwrap(engine.status(id)).count).toBe(1_048_575);
    expect(hitAddresses(engine, id)[0]).toBe(HEAP + 4);
  });
});
