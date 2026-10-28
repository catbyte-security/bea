import { describe, expect, it } from "vitest";

import { hexOf } from "../../../../src/domain/callModel/floatBits.js";
import {
  arrayCell,
  batchColumns,
  collectAddressExprs,
  normalizeScalar,
  singleCallColumns,
  type ScalarInput,
} from "../../../../src/domain/callModel/normalize.js";
import type { CallScalarType } from "../../../../src/domain/callModel/types.js";

const bits = (type: CallScalarType, input: ScalarInput): string => {
  const r = normalizeScalar(type, input);
  if (!r.ok) return `error: ${r.error}`;
  return r.value.kind === "bits" ? hexOf(r.value.bits) : `address: ${r.value.expr}`;
};

describe('normalizeScalar (S5 §7.2; "0x…" = raw bits of the declared type, D-INT-9)', () => {
  it.each<[CallScalarType, ScalarInput, string]>([
    ["i8", -1, "0xffffffffffffffff"],
    ["i8", "0xff", "0xffffffffffffffff"],
    ["u8", "0xff", "0xff"],
    ["i16", "-32768", "0xffffffffffff8000"],
    ["i32", 7, "0x7"],
    ["i32", "0x80000000", "0xffffffff80000000"],
    ["u32", 4294967295, "0xffffffff"],
    ["i64", "-9223372036854775808", "0x8000000000000000"],
    ["u64", "18446744073709551615", "0xffffffffffffffff"],
    ["u64", "0xFFFFFFFFFFFFFFFF", "0xffffffffffffffff"],
    ["bool", true, "0x1"],
    ["bool", 0, "0x0"],
    ["bool", "false", "0x0"],
    ["ptr", "0x10", "0x10"],
    ["ptr", 4096, "0x1000"],
    ["ptr", "game_sim.exe+0x1760", "address: game_sim.exe+0x1760"],
    ["ptr", "kernel32!IsBadReadPtr", "address: kernel32!IsBadReadPtr"],
    ["f32", 1.5, "0x3fc00000"],
    ["f32", "1.5", "0x3fc00000"],
    ["f32", "NaN", "0x7fc00000"],
    ["f32", "Infinity", "0x7f800000"],
    ["f32", "-Infinity", "0xff800000"],
    ["f32", "-0", "0x80000000"],
    ["f32", -0, "0x80000000"],
    ["f32", "0x7fc12345", "0x7fc12345"],
    ["f32", "0x00000001", "0x1"],
    ["f32", 3.4028235e38, "0x7f7fffff"],
    ["f64", "NaN", "0x7ff8000000000000"],
    ["f64", 2.25, "0x4002000000000000"],
    ["f64", "-0", "0x8000000000000000"],
    ["f64", "1e-310", "0x12688b70e62b"],
  ])("%s %j -> %s", (type, input, expected) => {
    expect(bits(type, input)).toBe(expected);
  });

  it.each<[CallScalarType, ScalarInput, RegExp]>([
    ["u8", -1, /out of range/u],
    ["i8", 128, /out of range/u],
    ["i8", "0x1ff", /must fit 8 bits/u],
    ["f32", "0x1ffffffff", /must fit 32 bits/u],
    ["f32", 1e39, /overflows f32/u],
    ["i32", 1.5, /safe integers/u],
    ["i64", 2 ** 60, /safe integers/u],
    ["i32", true, /only for bool/u],
    ["f64", false, /takes a number/u],
    ["bool", 2, /bool takes/u],
    ["f32", "twelve", /takes a number/u],
  ])("%s %j is refused (%s)", (type, input, message) => {
    const r = normalizeScalar(type, input);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(message);
  });
});

describe("array cells", () => {
  it("fills missing trailing elements from the default, else zero", () => {
    const row = arrayCell("f32", 4, "1.0, 0x40000000", [0n, 0n, 0x40400000n], "vectors.columns.v.xs[0]");
    expect(row.ok && row.value.map(hexOf)).toEqual(["0x3f800000", "0x40000000", "0x40400000", "0x0"]);
  });

  it("refuses more elements than the field count", () => {
    const row = arrayCell("i32", 2, "1,2,3", [], "p");
    expect(row.ok).toBe(false);
    if (!row.ok) expect(row.error).toMatchObject({ path: "p", reason: "out_of_range", maximum: 2 });
  });
});

describe("request columns", () => {
  const signature = {
    args: [{ type: "buffer_ptr", buffer: "car" }, { type: "f32", name: "dt" }, { type: "i32" }] as const,
    returns: "f32" as const,
    variadic: false,
  };

  it("maps positional args to slot columns (name, else argN) and fields to <buffer>.<field>", () => {
    const r = singleCallColumns(signature, [null, 0.5, 3], { "car.speed": 20 });
    expect(r.ok && r.value).toEqual({
      count: 1,
      columns: { dt: [0.5], arg2: [3], "car.speed": [20] },
      paths: { dt: "args[1]", arg2: "args[2]", "car.speed": "fields.car.speed" },
      indexed: false,
    });
  });

  it("refuses a value for a buffer slot and too many args", () => {
    const r = singleCallColumns(signature, [1, null, null, 4], undefined);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.map((i) => i.path)).toEqual(["args[0]", "args[3]"]);
  });

  it("requires equal column lengths and a consistent count", () => {
    const uneven = batchColumns({ columns: { a: [1, 2], b: [1] } });
    expect(uneven.ok).toBe(false);
    const conflicting = batchColumns({ count: 3, columns: { a: [1, 2] } });
    expect(!conflicting.ok && conflicting.error[0]?.reason).toBe("conflicting_arguments");
    const defaults = batchColumns({ count: 5 });
    expect(defaults.ok && defaults.value.count).toBe(5);
  });

  it("collects every AddrExpr in ptr positions so a leg can resolve them first", () => {
    const sig = {
      args: [
        { type: "ptr", default: "kernel32!Sleep" },
        { type: "ptr", name: "p" },
      ] as const,
      returns: "void" as const,
      variadic: false,
    };
    const buffers = [
      {
        name: "b",
        size: 16,
        align: 16,
        placement: "scratch" as const,
        fields: [{ name: "q", offset: 0, type: "ptr" as const, default: "$main:0x140001000" }],
        out: false,
      },
    ];
    const input = batchColumns({ columns: { p: ["0x10", "game.exe+0x20", 7] } });
    expect(input.ok).toBe(true);
    if (input.ok)
      expect(collectAddressExprs(sig, buffers, input.value)).toEqual([
        "$main:0x140001000",
        "game.exe+0x20",
        "kernel32!Sleep",
      ]);
  });
});
