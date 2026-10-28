import { describe, expect, it } from "vitest";

import {
  BASE_FIELDS,
  availableFields,
  fieldValue,
  fieldsOfRow,
  matches,
  runQuery,
  validateQuery,
  type QueryRequest,
} from "../../../src/application/instruments/QueryEngine.js";
import {
  FieldStatsAccumulator,
  QuantileSample,
  TopCounter,
  bitsOfFloat,
  compareValues,
  floatOfBits,
  shortestF32,
} from "../../../src/application/instruments/summaryUtil.js";
import type { EventField, EventRecord } from "../../../src/ports/recordings.js";

const FIELDS: readonly EventField[] = availableFields([
  { name: "caller", type: "address" },
  { name: "dt", type: "float" },
  { name: "big", type: "int" },
  { name: "path", type: "string" },
  { name: "bt", type: "array" },
]);
const events: EventRecord[] = Array.from({ length: 10 }, (_, i) => ({
  seq: i + 1,
  t_ms: i * 16.667,
  tid: i % 3,
  caller: `game_sim.exe+0x${(0x10 + (i % 2) * 0x10).toString(16)}`,
  dt: i < 5 ? 0.016666668 : 0.5,
  "dt:bits": i < 5 ? "0x3c888889" : "0x3f000000",
  big: (18446744073709551600n + BigInt(i)).toString(),
  path: i === 9 ? "C:\\" + "x".repeat(300) : `C:\\Data\\File${String(i)}.bin`,
  bt: ["game_sim.exe+0x10", "game_sim.exe+0x99"],
}));
const source = () =>
  (async function* () {
    yield* events;
  })();
const req = (over: Partial<QueryRequest>): QueryRequest => ({
  view: "rows",
  where: [],
  order: "asc",
  offset: 0,
  limit: 50,
  ...over,
});
const opts = { cellChars: 40, maxColumns: 16 };

describe("QueryEngine", () => {
  it("projects rows (seq first) and pages ascending and descending", async () => {
    const asc = await runQuery(source, FIELDS, req({ fields: ["dt", "tid"], offset: 2, limit: 3 }), opts);
    expect(asc.columns).toEqual(["seq", "dt", "tid"]);
    expect(asc.rows).toEqual([
      [3, 0.016666668, 2],
      [4, 0.016666668, 0],
      [5, 0.016666668, 1],
    ]);
    expect([asc.total, asc.next_offset]).toEqual([10, 5]);
    const desc = await runQuery(source, FIELDS, req({ fields: ["seq"], order: "desc", offset: 8, limit: 5 }), opts);
    expect(desc.rows).toEqual([[2], [1]]);
    expect(desc.next_offset).toBeNull();
  });

  it("filters with numeric (64-bit exact), text and case-insensitive operators", async () => {
    const count = async (where: QueryRequest["where"]) => (await runQuery(source, FIELDS, req({ where }), opts)).total;
    expect(await count([{ field: "big", op: "ge", value: "18446744073709551608" }])).toBe(2);
    expect(await count([{ field: "dt", op: "lt", value: 0.1 }])).toBe(5);
    expect(await count([{ field: "path", op: "contains", value: "file3" }])).toBe(1);
    expect(await count([{ field: "caller", op: "prefix", value: "GAME_SIM.EXE+0x2" }])).toBe(5);
    expect(await count([{ field: "bt", op: "contains", value: "0x99" }])).toBe(10);
    expect(
      await count([
        { field: "tid", op: "ne", value: 0 },
        { field: "dt", op: "eq", value: 0.5 },
      ]),
    ).toBe(3);
    expect(matches(null, { field: "x", op: "ne", value: 1 })).toBe(true);
    expect(matches(true, { field: "x", op: "lt", value: true })).toBe(false);
  });

  it("groups by value tuples (count desc) and shortens long cells", async () => {
    const g = await runQuery(source, FIELDS, req({ view: "group", group_by: ["dt", "caller"] }), opts);
    expect(g.columns).toEqual(["dt", "caller", "count", "first_seq", "last_seq"]);
    expect(g.rows[0]).toEqual([0.016666668, "game_sim.exe+0x10", 3, 1, 5]);
    expect(g.total).toBe(4);
    const rows = await runQuery(source, FIELDS, req({ fields: ["path", "bt"], offset: 9 }), opts);
    expect(rows.rows[0]?.[1]).toHaveLength(40);
    expect(rows.rows[0]?.[2]).toBe("game_sim.exe+0x10 < game_sim.exe+0x99");
    expect(rows.truncatedValues).toBe(1);
  });

  it("computes stats with :bits projection", async () => {
    const s = await runQuery(source, FIELDS, req({ view: "stats", fields: ["dt", "dt:bits", "big"] }), opts);
    expect(s.stats).toEqual([
      {
        field: "dt",
        type: "float",
        count: 10,
        min: 0.016666668,
        max: 0.5,
        mean: expect.closeTo(0.258333334, 9),
        distinct: 2,
        distinct_capped: false,
        top: [
          { value: 0.016666668, count: 5 },
          { value: 0.5, count: 5 },
        ],
      },
      expect.objectContaining({ field: "dt:bits", min: "0x3c888889", max: "0x3f000000", distinct: 2 }),
      expect.objectContaining({ field: "big", min: "18446744073709551600", max: "18446744073709551609", mean: null }),
    ]);
  });

  it("validates field names and lists the available ones", () => {
    const issues = validateQuery(
      req({ fields: ["dt:bits", "nope"], where: [{ field: "tid", op: "eq", value: 1 }], group_by: ["zz"] }),
      FIELDS,
    );
    expect(issues.map((i) => i.path)).toEqual(["group_by[0]", "fields[1]"]);
    expect(issues[0]?.message).toContain("Available fields: seq, t_ms, tid, caller, dt, big, path, bt");
  });

  it("derives fields from host rows and computes :bits for floats without stored bits", () => {
    expect(fieldsOfRow({ a: 1, b: 1.5, c: "x", d: true, e: [1], f: {}, "g:aux": 1 })).toEqual([
      { name: "a", type: "int" },
      { name: "b", type: "float" },
      { name: "c", type: "string" },
      { name: "d", type: "bool" },
      { name: "e", type: "array" },
      { name: "f", type: "object" },
    ]);
    const types = new Map<string, EventField["type"]>([["x", "float"]]);
    expect(fieldValue({ seq: 1, x: 1 }, "x:bits", types)).toBe("0x3ff0000000000000");
    expect(availableFields([{ name: "seq", type: "int" }])).toEqual(BASE_FIELDS);
  });
});

describe("summaryUtil", () => {
  it("renders floats as shortest round-trip f32 and exact bits", () => {
    expect(shortestF32(Math.fround(1 / 60))).toBe(0.016666668);
    expect(floatOfBits("f32", "0x3c888889")).toBe(0.016666668);
    expect(floatOfBits("f32", "0x7f800000")).toBe("Infinity");
    expect(floatOfBits("f64", "0x8000000000000000")).toBe(-0);
    expect(bitsOfFloat("f32", 0.016666668)).toBe("0x3c888889");
    expect(bitsOfFloat("f64", "NaN")).toBe("0x7ff8000000000000");
  });

  it("orders mixed values and accumulates field stats with a distinct cap", () => {
    expect(compareValues("18446744073709551615", 1)).toBe(1);
    expect(compareValues("0x10", 15)).toBe(1);
    expect(compareValues(true, "a")).toBeLessThan(0);
    const acc = new FieldStatsAccumulator("int");
    for (let i = 0; i < 10_005; i++) acc.add(i % 10_002);
    const r = acc.result();
    expect([r.count, r.distinct, r.distinct_capped, r.min, r.max]).toEqual([10_005, 10_000, true, 0, 10_001]);
    expect(acc.digest()).toMatchObject({ distinct_capped: true });
    const top = new TopCounter<string>();
    ["a", "b", "b", "c", "c", "c"].forEach((k) => top.add(k));
    expect(top.top(2)).toEqual([
      ["c", 3],
      ["b", 2],
    ]);
  });

  it("keeps percentiles bounded and max exact", () => {
    const q = new QuantileSample(64);
    for (let i = 1; i <= 10_000; i++) q.add(i);
    const s = q.summary();
    expect(s?.max).toBe(10_000);
    expect(Math.abs((s?.p50 ?? 0) - 5000)).toBeLessThan(400);
    expect(new QuantileSample().summary()).toBeNull();
  });
});
