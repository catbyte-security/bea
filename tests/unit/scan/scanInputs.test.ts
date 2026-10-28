import { describe, expect, it } from "vitest";

import { scanMemoryInputSchema, scanNextInputSchema } from "../../../src/contracts/areas/scan.js";
import {
  cellOf,
  checkPattern,
  normalizeNumeric,
  planScanMemory,
  planScanNext,
  withResolvedAddress,
} from "../../../src/application/scans/scanInputs.js";

/** WP10-SCAN host mapping: tool inputs → agent scan params (S6 §2.3, S4 §9.2), agent values → tool cells. */
const SESSION = "6f1c2a4e-8b3d-4e5f-9a7b-1c2d3e4f5a6b";
const mem = (input: Record<string, unknown>) => scanMemoryInputSchema.parse({ session_id: SESSION, ...input });
const plan = (input: Record<string, unknown>) => {
  const r = planScanMemory(mem(input));
  if (!r.ok) throw new Error(JSON.stringify(r.issue));
  return r.value;
};

describe("scan_memory input schema refines", () => {
  const bad = (input: Record<string, unknown>) =>
    scanMemoryInputSchema
      .safeParse({ session_id: SESSION, value_type: "f32", ...input })
      .error?.issues.map((i) => i.path.join("."));
  it("enforces the S6 §4.17 refines with paths", () => {
    expect(bad({})).toEqual(["value"]);
    expect(bad({ compare: "unknown", value: 1 })).toEqual(["value"]);
    expect(bad({ value: 1, value2: 2 })).toEqual(["value2"]);
    expect(bad({ compare: "between", value: 1 })).toEqual(["value2"]);
    expect(bad({ compare: "pointer_to", value: "0x10" })).toEqual(["value_type"]);
    expect(bad({ value_type: "utf8", compare: "between", value: "a", value2: "b" })).toEqual(["compare"]);
    expect(bad({ value_type: "i32", value: 1, epsilon: 0.5 })).toEqual(["epsilon"]);
    expect(bad({ value: 1, module: "game.exe", kind: "private" })).toEqual(["kind"]);
    expect(bad({ value: 1, max_hits: 0 })).toEqual(["max_hits"]);
    expect(bad({ value: 1 })).toBeUndefined();
  });
  it("scan_next refines", () => {
    const issues = (input: Record<string, unknown>) =>
      scanNextInputSchema.safeParse({ scan_id: "scan_0000000a", ...input }).error?.issues.map((i) => i.path.join("."));
    expect(issues({ compare: "increased_by" })).toEqual(["value"]);
    expect(issues({ compare: "changed", value: 1 })).toEqual(["value"]);
    expect(issues({ compare: "between", value: 1 })).toEqual(["value2"]);
    expect(issues({ compare: "decreased" })).toBeUndefined();
  });
});

describe("planScanMemory", () => {
  it("maps exact, epsilon, between, unknown and the region filters", () => {
    expect(plan({ value_type: "f32", value: 20 }).params).toEqual({
      kind: "value",
      value_type: "f32",
      compare: { op: "eq", value: 20 },
      regions: { protection: "rw-" },
      align: 4,
      max_candidates: 10_000_000,
    });
    expect(plan({ value_type: "f64", value: 1.5, epsilon: 0.01, aligned: false }).params).toMatchObject({
      compare: { op: "approx", value: 1.5, eps: 0.01 },
      align: 1,
    });
    expect(plan({ value_type: "u16", compare: "between", value: 3, value2: "0x10" }).params).toMatchObject({
      compare: { op: "range", min: 3, max: "0x10" },
    });
    expect(plan({ value_type: "i64", compare: "unknown", kind: "private", protection: "r--" }).params).toMatchObject({
      kind: "unknown",
      value_type: "i64",
      regions: { protection: "r--", private_only: true },
    });
    expect(plan({ value_type: "i32", value: 1, kind: "image" }).params.regions).toEqual({
      protection: "rw-",
      modules: ["*"],
    });
    expect(plan({ value_type: "i32", value: 1, module: "game.exe" }).params.regions).toEqual({
      protection: "rw-",
      modules: ["game.exe"],
    });
  });

  it("bool is one byte; float bits are exact bits; utf/bytes become text and patterns", () => {
    expect(plan({ value_type: "bool", value: true }).params).toMatchObject({ value_type: "u8", compare: { value: 1 } });
    expect(plan({ value_type: "f32", value: "0x41A00000" }).params).toMatchObject({
      compare: { value: { bits: "0x41a00000" } },
    });
    expect(plan({ value_type: "utf16", value: "Wide" }).params).toMatchObject({
      kind: "value",
      compare: { op: "eq", text: "Wide" },
      align: 2,
    });
    expect(plan({ value_type: "bytes", value: "48 8b ?? 4?" }).params).toMatchObject({
      kind: "pattern",
      pattern: "48 8b ?? 4?",
    });
  });

  it("pointer_to: hex goes straight through, an AddrExpr is resolved by the handler", () => {
    const hex = plan({ value_type: "ptr", compare: "pointer_to", value: "0x1F3A5C40", kind: "image" });
    expect(hex).toMatchObject({ resolve: null, params: { kind: "pointers-to", targets: ["0x1f3a5c40"] } });
    const expr = plan({ value_type: "ptr", compare: "pointer_to", value: "game.exe!g_world" });
    expect(expr.resolve).toEqual({ path: "value", expr: "game.exe!g_world" });
    expect(withResolvedAddress(expr, 0x7ff6_0000_1234n)).toMatchObject({ targets: ["0x7ff600001234"] });
    const exact = plan({ value_type: "ptr", value: "game.exe+0x10" });
    expect(withResolvedAddress(exact, 0x10n)).toMatchObject({ kind: "value", compare: { op: "eq", value: "0x10" } });
  });

  it("refuses out-of-range values, bad order, long text and bad patterns before any RPC", () => {
    const issue = (input: Record<string, unknown>) => {
      const r = planScanMemory(mem(input));
      return r.ok ? null : r.issue.path;
    };
    expect(issue({ value_type: "i8", value: 200 })).toBe("value");
    expect(issue({ value_type: "u32", value: "0x1ffffffff" })).toBe("value");
    expect(issue({ value_type: "f32", value: "fast" })).toBe("value");
    expect(issue({ value_type: "i32", value: true })).toBe("value");
    expect(issue({ value_type: "i32", compare: "between", value: 5, value2: 4 })).toBe("value2");
    expect(issue({ value_type: "utf8", value: "x".repeat(257) })).toBe("value");
    expect(issue({ value_type: "bytes", value: "/regex/" })).toBe("value");
    expect(issue({ value_type: "bytes", value: "zz 00" })).toBe("value");
    expect(checkPattern("40 45 : f0", "value").ok).toBe(false);
  });

  it("normalizes signed hex as two's complement for the range check", () => {
    expect(normalizeNumeric("i8", "0xff", "value")).toEqual({ ok: true, value: "0xff" });
    expect(normalizeNumeric("i8", "-129", "value").ok).toBe(false);
    expect(normalizeNumeric("u64", "18446744073709551615", "value").ok).toBe(true);
  });
});

describe("planScanNext and cells", () => {
  const next = (t: Parameters<typeof planScanNext>[0], input: Record<string, unknown>) =>
    planScanNext(t, scanNextInputSchema.parse({ scan_id: "scan_0000000a", ...input }));
  it("maps compares to agent ops", () => {
    expect(next("f32", { compare: "increased" })).toEqual({ ok: true, value: { op: "increased" } });
    expect(next("f32", { compare: "exact", value: 3, epsilon: 0.1 })).toEqual({
      ok: true,
      value: { op: "approx", value: 3, eps: 0.1 },
    });
    expect(next("i32", { compare: "between", value: 1, value2: 9 })).toEqual({
      ok: true,
      value: { op: "range", min: 1, max: 9 },
    });
    expect(next("u8", { compare: "increased_by", value: 2 })).toEqual({
      ok: true,
      value: { op: "increased_by", value: 2 },
    });
    expect(next("utf8", { compare: "exact", value: "hi" })).toEqual({ ok: true, value: { op: "eq", value: "hi" } });
    expect(next("utf8", { compare: "increased" }).ok).toBe(false);
    expect(next("i32", { compare: "unchanged", epsilon: 1 }).ok).toBe(false);
  });
  it("renders typed values as S6 §2.3 cells", () => {
    expect(cellOf("bool", { type: "u8", value: 1 })).toBe(true);
    expect(cellOf("u64", { type: "u64", value: "18446744073709551615" })).toBe("18446744073709551615");
    expect(cellOf("f32", { type: "f32", value: "NaN", bits: "0x7fc00000" })).toBe("NaN");
    expect(cellOf("bytes", { type: "bytes", value: null, hex: "dead" })).toBe("dead");
    expect(cellOf("utf8", { type: "utf8", value: "x".repeat(2000) })).toHaveLength(1024);
    expect(cellOf("i32", { error: {} })).toBeNull();
    expect(cellOf("i32", undefined)).toBeNull();
  });
});
