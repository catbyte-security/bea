import { describe, expect, it } from "vitest";

import {
  bitsEqual,
  compareLegs,
  type Cell,
  type Leg,
  type LegData,
  type OutcomeClass,
} from "../../../src/application/diff/compare.js";
import { diffHints, hintProbes, HINT_CODES } from "../../../src/application/diff/hints.js";
import type { Hex } from "../../../src/shared/hex.js";

type Spec = { cls: OutcomeClass; bits?: Hex; rva?: string };

const legOf = (leg: Leg, specs: readonly Spec[]): LegData => ({
  leg,
  classes: specs.map((s) => s.cls),
  status: specs.map((s) =>
    s.cls === "returned"
      ? "returned"
      : s.cls === "target_stop"
        ? "fault"
        : s.cls === "harness_stop"
          ? "unsupported_instruction"
          : null,
  ),
  reasons: specs.map((s) =>
    s.cls === "harness_stop" ? `${leg}:vex` : s.cls === "not_run" ? "not_run:deadline" : null,
  ),
  sites: specs.map((s) =>
    s.cls === "target_stop" ? { family: "fault", module: "m.dll", rva: s.rva ?? "0x1010", access: null } : null,
  ),
  cells: { ret: specs.map((s): Cell => (s.cls === "returned" ? (s.bits ?? "0x3f800000") : null)) },
});

const run = (
  a: readonly Spec[],
  b: readonly Spec[],
  options: Partial<Parameters<typeof compareLegs>[0]["options"]> = {},
  type: "f32" | "f64" | "i32" = "f32",
) =>
  compareLegs({
    offset: 10,
    count: a.length,
    legs: [legOf("live", a), legOf("emulation", b)],
    columns: [{ name: "ret", type }],
    options: { nan: "bits", inconclusive: "count", compareFaultSites: true, ...options },
    inputs: { arg0: a.map((_, k) => `0x${k.toString(16)}` as Hex) },
  });

describe("diff comparator truth table (S5 §9.7)", () => {
  const classes: readonly Spec[] = [
    { cls: "returned" },
    { cls: "returned", bits: "0x40000000" },
    { cls: "target_stop" },
    { cls: "target_stop", rva: "0x2020" },
    { cls: "harness_stop" },
    { cls: "not_run" },
  ];
  const expected = (a: Spec, b: Spec): "eq" | "df" | "ic" => {
    if (a.cls === "harness_stop" || a.cls === "not_run" || b.cls === "harness_stop" || b.cls === "not_run") return "ic";
    if (a.cls === "target_stop" && b.cls === "target_stop")
      return (a.rva ?? "0x1010") === (b.rva ?? "0x1010") ? "eq" : "df";
    if (a.cls !== b.cls) return "df";
    return (a.bits ?? "0x3f800000") === (b.bits ?? "0x3f800000") ? "eq" : "df";
  };

  it("classifies every outcome-class combination", () => {
    for (const a of classes)
      for (const b of classes) {
        const result = run([a], [b]);
        const pair = result.pairs[0];
        expect(pair?.vectors[0]?.r, `${JSON.stringify(a)} vs ${JSON.stringify(b)}`).toBe(expected(a, b));
        const verdict =
          expected(a, b) === "df" ? "differ" : expected(a, b) === "ic" ? "unknown" : "equivalent-on-tested-inputs";
        expect(result.verdict).toBe(verdict);
      }
  });

  it("orders pairs (live, emulation), (live, expected), (emulation, expected) and takes the worst verdict", () => {
    const result = compareLegs({
      offset: 0,
      count: 1,
      legs: [
        legOf("expected", [{ cls: "returned", bits: "0x40000000" }]),
        legOf("emulation", [{ cls: "returned" }]),
        legOf("live", [{ cls: "returned" }]),
      ],
      columns: [{ name: "ret", type: "f32" }],
      options: { nan: "bits", inconclusive: "count", compareFaultSites: true },
      inputs: {},
    });
    expect(result.pairs.map((p) => `${p.a}~${p.b}:${p.verdict}`)).toEqual([
      "live~emulation:equivalent-on-tested-inputs",
      "live~expected:differ",
      "emulation~expected:differ",
    ]);
    expect(result.verdict).toBe("differ");
  });

  it("ignores fault sites when asked, and inconclusive vectors under exclude", () => {
    expect(
      run([{ cls: "target_stop" }], [{ cls: "target_stop", rva: "0x9" }], { compareFaultSites: false }).verdict,
    ).toBe("equivalent-on-tested-inputs");
    const excluded = run([{ cls: "returned" }, { cls: "harness_stop" }], [{ cls: "returned" }, { cls: "returned" }], {
      inconclusive: "exclude",
    });
    expect(excluded.verdict).toBe("equivalent-on-tested-inputs");
    expect(excluded.excluded).toBe(1);
    expect(
      run([{ cls: "returned" }, { cls: "harness_stop" }], [{ cls: "returned" }, { cls: "returned" }]).verdict,
    ).toBe("unknown");
    expect(run([{ cls: "not_run" }], [{ cls: "not_run" }], { inconclusive: "exclude" }).verdict).toBe("unknown");
    expect(run([{ cls: "harness_stop" }], [{ cls: "returned" }]).pairs[0]?.inconclusive_reasons).toEqual({
      "live:vex": 1,
    });
  });
});

describe("bit-exact comparison and ulp statistics", () => {
  it("compares raw bits; any_nan equates NaNs; ints compare masked", () => {
    expect(bitsEqual("f32", "0x7fc00000", "0x7fc12345", "bits")).toBe(false);
    expect(bitsEqual("f32", "0x7fc00000", "0x7fc12345", "any_nan")).toBe(true);
    expect(bitsEqual("f32", "0x0", "0x80000000", "any_nan")).toBe(false);
    expect(bitsEqual("i32", "0xffffffffffffffff", "0xffffffff", "bits")).toBe(true);
    expect(bitsEqual("f64", "0x7ff8000000000001", "0x7ff8000000000002", "any_nan")).toBe(true);
  });

  it("counts NaN payloads, NaN vs number, signed zeros and infinities; ulp ignores NaN", () => {
    const a: Spec[] = [
      { cls: "returned", bits: "0x7fc00001" },
      { cls: "returned", bits: "0x7fc00000" },
      { cls: "returned", bits: "0x0" },
      { cls: "returned", bits: "0x7f800000" },
      { cls: "returned", bits: "0x3f800000" },
      { cls: "returned", bits: "0x1" },
    ];
    const b: Spec[] = [
      { cls: "returned", bits: "0x7fc00002" },
      { cls: "returned", bits: "0x3f800000" },
      { cls: "returned", bits: "0x80000000" },
      { cls: "returned", bits: "0x7f7fffff" },
      { cls: "returned", bits: "0x3f800003" },
      { cls: "returned", bits: "0x0" },
    ];
    const stats = run(a, b).pairs[0]?.columns["ret"];
    expect(stats).toMatchObject({
      compared: 6,
      exact_equal: 0,
      differ: 6,
      nan_payload: 1,
      nan_vs_number: 1,
      signed_zero: 1,
      inf_mismatch: 1,
    });
    // non-NaN cells: ±0 (0 ulp), inf vs max (1), 1.0 vs +3 ulp (3), denormal min vs 0 (1)
    expect(stats?.max_ulp).toBe(3);
    expect(stats?.p50_ulp).toBe(1);
    expect(stats?.max_abs).toBeCloseTo(3.576e-7, 9);
  });

  it("computes f64 ulps with BigInt precision and integer deltas as decimal strings", () => {
    const f64 = run(
      [{ cls: "returned", bits: "0x3ff0000000000000" }],
      [{ cls: "returned", bits: "0x3ff0000000100000" }],
      {},
      "f64",
    );
    expect(f64.pairs[0]?.columns["ret"]?.max_ulp).toBe(0x100000);
    const ints = run([{ cls: "returned", bits: "0xfffffffe" }], [{ cls: "returned", bits: "0x5" }], {}, "i32");
    expect(ints.pairs[0]?.columns["ret"]?.int_max_delta).toBe("7");
    expect(ints.profile.integerDiffs).toBe(1);
  });

  it("never lets a tolerance change the verdict", () => {
    const result = run([{ cls: "returned", bits: "0x3f800000" }], [{ cls: "returned", bits: "0x3f800001" }], {
      tolerance: { ulp: 4 },
    });
    expect(result.verdict).toBe("differ");
    expect(result.pairs[0]?.tolerance).toEqual({ within: 1, outside: 0 });
    expect(result.profile).toMatchObject({ allWithin2Ulp: true, floatDiffs: 1, maxUlp: 1 });
  });

  it("ranks worst[]: outcome-class differences first, then the largest ulp", () => {
    const result = run(
      [{ cls: "returned", bits: "0x3f800000" }, { cls: "returned", bits: "0x3f800000" }, { cls: "returned" }],
      [{ cls: "returned", bits: "0x3f800001" }, { cls: "returned", bits: "0x3f800009" }, { cls: "target_stop" }],
    );
    expect(result.worst.map((w) => [w.index, w.reason, w.ulp])).toEqual([
      [12, "outcome_class", null],
      [11, "value", 9],
      [10, "value", 1],
    ]);
    expect(result.worst[1]?.inputs).toEqual({ arg0: "0x1" });
    expect(result.worst[1]?.values).toEqual({
      live: { status: "returned", bits: "0x3f800000" },
      emulation: { status: "returned", bits: "0x3f800009" },
    });
  });

  it("compares array cells element-wise", () => {
    const result = compareLegs({
      offset: 0,
      count: 1,
      legs: [
        { ...legOf("live", [{ cls: "returned" }]), cells: { "b.v": [["0x1", "0x2"]] } },
        { ...legOf("emulation", [{ cls: "returned" }]), cells: { "b.v": [["0x1", "0x3"]] } },
      ],
      columns: [{ name: "b.v", type: "i32" }],
      options: { nan: "bits", inconclusive: "count", compareFaultSites: true },
      inputs: {},
    });
    expect(result.verdict).toBe("differ");
    expect(result.pairs[0]?.columns["b.v"]).toMatchObject({ compared: 1, differ: 1, int_max_delta: "1" });
  });
});

describe("diff hints (S5 §9.8, closed list)", () => {
  const facts = {
    verdict: "differ" as const,
    differences: 2,
    outcomeDifferences: 0,
    profile: {
      floatDiffs: 2,
      allWithin2Ulp: true,
      nanPayloadOnly: false,
      signedZeroOnly: false,
      integerDiffs: 0,
      maxUlp: 1,
    },
    emulationDeviations: new Set(["x87_transcendental_inexact", "cpuid_executed"] as const),
    emulationImportModels: new Set(["builtin-inexact"]),
    imageBackedWithLive: true,
    liveWithSnapshotIsolation: true,
    rawPointerInputs: false,
    imageMismatch: false,
    engineUnvalidated: false,
  };

  it("emits only codes from the closed list, with deduplicated probes (≤ 5)", () => {
    const hints = diffHints(facts);
    expect(hints.map((h) => h.code)).toEqual([
      "x87_inexact",
      "hle_math_model",
      "cpuid_dispatch",
      "file_image_state",
      "possible_state_carryover",
      "last_ulp_only",
    ]);
    for (const hint of hints) expect(HINT_CODES).toContain(hint.code);
    expect(hintProbes(hints).length).toBe(5);
  });

  it("names the emulator's NaN rule for NaN-payload-only differences against the emulated leg (EMU-7)", () => {
    const nanOnly = {
      ...facts,
      profile: { ...facts.profile, allWithin2Ulp: false, nanPayloadOnly: true },
      emulationDeviations: new Set<never>(),
      emulationImportModels: new Set<string>(),
    };
    const withEmu = diffHints({ ...nanOnly, emulationCompared: true }).map((h) => h.code);
    expect(withEmu).toEqual(["emulator_nan_rule"]); // no state-carryover / file-image noise
    const liveOnly = diffHints({
      ...nanOnly,
      emulationCompared: false,
      imageBackedWithLive: false,
      liveWithSnapshotIsolation: false,
    }).map((h) => h.code);
    expect(liveOnly).toEqual(["nan_payload_only"]);
  });

  it("flags outcome classes and keeps value-only hints for value-only differences", () => {
    const hints = diffHints({
      ...facts,
      outcomeDifferences: 1,
      emulationDeviations: new Set(),
      emulationImportModels: new Set(),
      imageBackedWithLive: false,
      liveWithSnapshotIsolation: false,
    });
    expect(hints.map((h) => h.code)).toEqual(["outcome_class"]);
    expect(
      diffHints({
        ...facts,
        verdict: "equivalent-on-tested-inputs",
        differences: 0,
        imageBackedWithLive: false,
        emulationDeviations: new Set(),
        liveWithSnapshotIsolation: false,
      }),
    ).toEqual([]);
  });
});
