import { existsSync, readFileSync, writeFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { classifyWin64 } from "../../../../src/domain/callModel/classify.js";
import { hexOf } from "../../../../src/domain/callModel/floatBits.js";
import {
  edgeValues,
  fnv1a32,
  generateWindow,
  splitmix32,
  Xoshiro128,
  type GenerateInput,
} from "../../../../src/domain/callModel/generators.js";
import type { SignatureInput } from "../../../../src/domain/callModel/normalize.js";
import type { CallScalarType } from "../../../../src/domain/callModel/types.js";

/**
 * S5 §7.6 goldens: the first 16 rows of 6 specs are pinned in tests/golden/callModel/generators.json. The file is the
 * contract (a continuation regenerates exactly these rows); it is written only when BEA_WRITE_GOLDENS=1 (a reviewed
 * algorithm change) and otherwise compared.
 */
const GOLDEN = new URL("../../../golden/callModel/generators.json", import.meta.url);

interface Spec {
  readonly title: string;
  readonly columns: Readonly<Record<string, CallScalarType>>;
  readonly generate: GenerateInput;
}
const SPECS: readonly Spec[] = [
  {
    title: "f32 uniform [-10, 10]",
    columns: { dt: "f32" },
    generate: { seed: 1, columns: { dt: { dist: "uniform", min: -10, max: 10 } }, grid: "cartesian", count: 16 },
  },
  {
    title: "f64 log_uniform [1e-3, 1e3] both signs",
    columns: { x: "f64" },
    generate: {
      seed: 2,
      columns: { x: { dist: "log_uniform", min: 1e-3, max: 1e3, signs: "both" } },
      grid: "cartesian",
      count: 16,
    },
  },
  {
    title: "i32 uniform [-5, 5]",
    columns: { n: "i32" },
    generate: { seed: 3, columns: { n: { dist: "uniform", min: -5, max: 5 } }, grid: "cartesian", count: 16 },
  },
  {
    title: "u64 bits_uniform",
    columns: { k: "u64" },
    generate: { seed: 4, columns: { k: { dist: "bits_uniform" } }, grid: "cartesian", count: 16 },
  },
  {
    title: "f32 edge",
    columns: { e: "f32" },
    generate: { seed: 5, columns: { e: { dist: "edge" } }, grid: "cartesian", count: 16 },
  },
  {
    title: "cartesian grid 4x4 + per-row f64 uniform",
    columns: { a: "i32", b: "f32", c: "f64" },
    generate: {
      seed: 6,
      columns: {
        a: { dist: "grid", values: "1,2,3,4" },
        b: { dist: "grid", values: "0.5, 1.5, 2.5, 3.5" },
        c: { dist: "uniform", min: 0, max: 1 },
      },
      grid: "cartesian",
    },
  },
];

const planFor = (columns: Readonly<Record<string, CallScalarType>>) => {
  const signature: SignatureInput = {
    args: Object.entries(columns).map(([name, type]) => ({ type, name })),
    returns: "void",
    variadic: false,
  };
  const r = classifyWin64({ signature, buffers: [], supplied: new Set(Object.keys(columns)) });
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  return r.value.plan;
};

const rowsOf = (spec: Spec, from: number, to: number): Record<string, string>[] => {
  const r = generateWindow(planFor(spec.columns), spec.generate, { from, to }, () => undefined);
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  const { bits } = r.value;
  return Array.from({ length: bits.count }, (_, i) =>
    Object.fromEntries([...bits.columns].map(([name, cells]) => [name, hexOf((cells as readonly bigint[])[i] ?? 0n)])),
  );
};

describe("PRNG primitives", () => {
  it("xoshiro128** matches the reference outputs for state [1,2,3,4]", () => {
    const rng = new Xoshiro128([1, 2, 3, 4]);
    expect(Array.from({ length: 6 }, () => rng.next())).toEqual([11520, 0, 5927040, 70819200, 2031721883, 1637235492]);
  });

  it("fnv1a32 and splitmix32 match their reference values", () => {
    expect(fnv1a32("")).toBe(0x811c9dc5);
    expect(fnv1a32("a")).toBe(0xe40c292c);
    expect(fnv1a32("foobar")).toBe(0xbf9cf968);
    expect(splitmix32(0, 4)).toEqual([0x92ca2f0e, 0x3cd6e3f3, 0x1b147dcc, 0x4c081dbf]);
  });

  it("edge lists cover signed extremes and float specials", () => {
    expect(edgeValues("i8").map(hexOf)).toEqual([
      "0x0",
      "0x1",
      "0xffffffffffffffff",
      "0xffffffffffffff80",
      "0x7f",
      "0xffffffffffffff81",
      "0x7e",
    ]);
    expect(edgeValues("u16").map(hexOf)).toEqual(["0x0", "0x1", "0xffff", "0xfffe"]);
    expect(edgeValues("f32")).toHaveLength(16);
  });
});

describe("generators (S5 §7.6) are deterministic and pinned by goldens", () => {
  it("the first 16 rows of the 6 golden specs are unchanged", () => {
    const actual = {
      schema: "bea.callmodel-generators-golden/1",
      note: "S5 §7.6 generator goldens (WP11-CALL). Changing these rows is a breaking change: regenerate only for a reviewed algorithm change (BEA_WRITE_GOLDENS=1).",
      specs: SPECS.map((spec) => ({
        title: spec.title,
        columns: spec.columns,
        generate: spec.generate,
        rows: rowsOf(spec, 0, 16),
      })),
    };
    if (process.env["BEA_WRITE_GOLDENS"] === "1") writeFileSync(GOLDEN, `${JSON.stringify(actual, null, 2)}\n`);
    expect(existsSync(GOLDEN), "tests/golden/callModel/generators.json is missing").toBe(true);
    expect(actual).toEqual(JSON.parse(readFileSync(GOLDEN, "utf8")));
  });

  it("a continuation window regenerates exactly the same rows", () => {
    for (const spec of SPECS) expect(rowsOf(spec, 5, 12), spec.title).toEqual(rowsOf(spec, 0, 16).slice(5, 12));
  });

  it("orders cartesian rows by sorted column name with the last name varying fastest", () => {
    const rows = rowsOf(SPECS[5] as Spec, 0, 6);
    expect(rows.map((r) => [r["a"], r["b"]])).toEqual([
      ["0x1", "0x3f000000"],
      ["0x1", "0x3fc00000"],
      ["0x1", "0x40200000"],
      ["0x1", "0x40600000"],
      ["0x2", "0x3f000000"],
      ["0x2", "0x3fc00000"],
    ]);
  });

  it("keeps f32 uniform draws inside [min, max] and integer draws inside the inclusive range", () => {
    for (const row of rowsOf(SPECS[0] as Spec, 0, 16)) {
      const v = new DataView(new Uint32Array([Number(BigInt(row["dt"] ?? "0x0"))]).buffer).getFloat32(0, true);
      expect(v).toBeGreaterThanOrEqual(-10);
      expect(v).toBeLessThanOrEqual(10);
    }
    for (const row of rowsOf(SPECS[2] as Spec, 0, 16)) {
      const n = BigInt.asIntN(64, BigInt(row["n"] ?? "0x0"));
      expect(n >= -5n && n <= 5n).toBe(true);
    }
  });

  it("refuses a missing count, uneven zip grids and a cartesian count mismatch", () => {
    const plan = planFor({ a: "i32", b: "i32" });
    const noCount = generateWindow(
      plan,
      { seed: 1, columns: { a: { dist: "edge" } }, grid: "cartesian" },
      { from: 0, to: 4 },
      () => undefined,
    );
    expect(!noCount.ok && noCount.error[0]?.path).toBe("generate.count");
    const zip = generateWindow(
      plan,
      { seed: 1, columns: { a: { dist: "grid", values: "1,2" }, b: { dist: "grid", values: "1,2,3" } }, grid: "zip" },
      { from: 0, to: 4 },
      () => undefined,
    );
    expect(!zip.ok && zip.error[0]?.message).toMatch(/same length/u);
    const mismatch = generateWindow(
      plan,
      {
        seed: 1,
        count: 5,
        columns: { a: { dist: "grid", values: "1,2" }, b: { dist: "grid", values: "1,2,3" } },
        grid: "cartesian",
      },
      { from: 0, to: 4 },
      () => undefined,
    );
    expect(!mismatch.ok && mismatch.error[0]?.reason).toBe("conflicting_arguments");
    const logInt = generateWindow(
      plan,
      { seed: 1, count: 2, columns: { a: { dist: "log_uniform", min: 1, max: 2 } }, grid: "cartesian" },
      { from: 0, to: 2 },
      () => undefined,
    );
    expect(logInt.ok).toBe(false);
  });
});
