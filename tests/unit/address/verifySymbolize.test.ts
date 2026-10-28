import { describe, expect, it } from "vitest";

import { symbolSchema } from "../../../src/domain/address/addressRef.js";
import { symbolize, type FunctionBounds, type SymbolSources } from "../../../src/domain/address/symbolize.js";
import {
  compareWindow,
  diffRanges,
  finishVerification,
  overlayOriginals,
  verificationWithout,
  type CompareInput,
} from "../../../src/domain/address/verify.js";

/** S2 §18.3 (pure part) and S2 §19.1 policy. */
const window = (over: Partial<CompareInput> = {}): CompareInput => {
  const len = over.len ?? 32;
  const expected = over.expected ?? Uint8Array.from({ length: len }, (_, i) => i + 1);
  return {
    rva: 0x1000,
    len,
    live: over.live ?? expected.slice(),
    ownRestored: 0,
    expected,
    backed: over.backed ?? new Uint8Array(len).fill(1),
    loader: [],
    ...over,
  };
};

describe("byte verification (S2 §18.3)", () => {
  it("matches identical code and reports compared/equal", () => {
    const v = finishVerification(compareWindow(window()), null);
    expect(v).toMatchObject({ status: "match", compared: 32, equal: 32, excluded_loader: 0, differences: [] });
  });

  it("excludes loader-written classes and zero-fill, never compares them", () => {
    const expected = Uint8Array.from({ length: 32 }, () => 0xcc);
    const live = expected.slice();
    live.fill(0x11, 0, 8); // IAT slot rewritten by the loader
    live.fill(0x22, 8, 12); // fothk thunk
    live[31] = 0x33; // zero-fill tail differs (bss-like)
    const backed = new Uint8Array(32).fill(1);
    backed[31] = 0;
    const v = finishVerification(
      compareWindow(
        window({
          expected,
          live,
          backed,
          loader: [
            { rva: 0x1000, size: 8, class: "iat" },
            { rva: 0x1008, size: 4, class: "loader-thunk" },
          ],
        }),
      ),
      null,
    );
    expect(v.status).toBe("match");
    expect(v.compared).toBe(19);
    expect(v.excluded).toMatchObject({ iat: 8, loader_thunk: 4, zero_fill: 1 });
    expect(v.excluded_loader).toBe(13);
  });

  it("coalesces differences within 4 bytes and classifies them against the footprint", () => {
    const expected = new Uint8Array(64).fill(0x90);
    const live = expected.slice();
    live[2] = 0xe9; // jmp patch head
    live[5] = 0x00; // gap 3 → same range
    live[40] = 0xcc; // separate range
    const compared = compareWindow(window({ len: 64, expected, live }));
    expect(diffRanges(compared)).toEqual([
      { rva: 0x1002, size: 4 },
      { rva: 0x1028, size: 1 },
    ]);
    const v = finishVerification(compared, [{ rva: 0x1000, size: 16 }]);
    expect(v.status).toBe("mismatch");
    expect(v.differences).toEqual([
      { rva: "0x1002", size: 4, class: "foreign-or-agent-patch", live_hex: "e9909000", expected_hex: "90909090" },
      { rva: "0x1028", size: 1, class: "unexplained", live_hex: "cc", expected_hex: "90" },
    ]);
    // no footprint (scan not run or failed): everything is unexplained
    expect(finishVerification(compared, null).differences.every((d) => d.class === "unexplained")).toBe(true);
  });

  it("restores BEA's own original bytes before comparing (own_effects_restored)", () => {
    const expected = Uint8Array.from({ length: 16 }, (_, i) => 0x40 + i);
    const live = expected.slice();
    live.set([0xff, 0x25, 0, 0, 0, 0], 0); // a BEA hook trampoline over the prologue
    const restored = overlayOriginals(live, 0x7ff600001000n, [{ va: 0x7ff600001000n, bytes: expected.slice(0, 6) }]);
    expect(restored).toBe(6);
    const v = finishVerification(compareWindow(window({ len: 16, expected, live, ownRestored: restored })), null);
    expect(v).toMatchObject({ status: "match", own_effects_restored: 6 });
  });

  it("reports an unreadable tail as partial and an all-unreadable window as partial with a reason", () => {
    const expected = new Uint8Array(16).fill(1);
    expect(
      finishVerification(compareWindow(window({ len: 16, expected, live: expected.slice(0, 10) })), null),
    ).toMatchObject({
      status: "partial",
      compared: 10,
      excluded: { unreadable: 6 },
      reason: "unreadable",
    });
    expect(
      finishVerification(compareWindow(window({ len: 16, expected, live: new Uint8Array(0) })), null),
    ).toMatchObject({
      status: "partial",
      compared: 0,
    });
    expect(verificationWithout("not-applicable", "writable_section")).toMatchObject({
      status: "not-applicable",
      compared: 0,
      reason: "writable_section",
    });
  });

  it("caps the difference list at 8 ranges", () => {
    const expected = new Uint8Array(256);
    const live = expected.slice();
    for (let i = 0; i < 20; i++) live[i * 10] = 1;
    const v = finishVerification(compareWindow(window({ len: 256, expected, live })), null);
    expect(v.differences).toHaveLength(8);
    expect(v.status).toBe("mismatch");
  });
});

describe("symbolization policy (S2 §19.1)", () => {
  // .pdata: f1 = [0x1000,0x1100); f1's chained fragment [0x1800,0x1880) → primary 0x1000; f2 = [0x2000,0x2040) unexported
  const fragments: readonly FunctionBounds[] = [
    { begin: 0x1000, end: 0x1100, primary_begin: 0x1000, fragment: false },
    { begin: 0x1800, end: 0x1880, primary_begin: 0x1000, fragment: true },
    { begin: 0x2000, end: 0x2040, primary_begin: 0x2000, fragment: false },
    { begin: 0x3000, end: 0x3100, primary_begin: 0x3000, fragment: false },
  ];
  const exports = new Map([
    [0x1000, { rva: 0x1000, name: "physics_step", code: true }],
    [0x5000, { rva: 0x5000, name: "g_world", code: false }],
  ]);
  const sources = (over: Partial<SymbolSources> = {}): SymbolSources => ({
    caller: [],
    exportAt: (x) => exports.get(x) ?? null,
    importAt: (x) =>
      x >= 0x6000 && x < 0x6008 ? { slot_rva: 0x6000, dll: "KERNEL32.dll", name: "Sleep", ordinal: null } : null,
    functionAt: (x) => fragments.find((f) => x >= f.begin && x < f.end) ?? null,
    ...over,
  });

  it("names exact and function-start exports, including chained fragments; never the nearest preceding export", () => {
    expect(symbolize(0x1000, sources())).toMatchObject({ name: "physics_step", kind: "export", offset: "0x0" });
    expect(symbolize(0x1036, sources())).toMatchObject({
      name: "physics_step",
      offset: "0x36",
      function_start: "0x1000",
    });
    expect(symbolize(0x1810, sources())).toMatchObject({
      name: "physics_step",
      offset: "0x810",
      fragment: true,
      function_end: "0x1880",
    });
    // 0x2010 is in an unexported function after physics_step: bounds only, name null
    expect(symbolize(0x2010, sources())).toEqual({
      name: null,
      kind: "function",
      source: "pe-pdata",
      offset: "0x10",
      function_start: "0x2000",
      function_end: "0x2040",
      fragment: false,
    });
    // data exports only match exactly
    expect(symbolize(0x5000, sources())).toMatchObject({ name: "g_world", kind: "export" });
    expect(symbolize(0x5004, sources())).toBeNull();
  });

  it("puts caller tables first (exact, sized range, or function start) with their evidence id", () => {
    const evidence = `ev_${"a".repeat(64)}` as const;
    const caller = [
      { rva: 0x2000, name: "Car::update", size: null, evidence_id: evidence },
      { rva: 0x3000, name: "sized", size: 0x20, evidence_id: null },
    ];
    expect(symbolize(0x2010, sources({ caller }))).toMatchObject({
      name: "Car::update",
      kind: "caller",
      source: "caller-table",
      offset: "0x10",
      evidence_id: evidence,
    });
    expect(symbolize(0x3010, sources({ caller }))).toMatchObject({ name: "sized", offset: "0x10" });
    // outside the sized range, inside the same .pdata function that starts at 0x3000 → still the caller name
    expect(symbolize(0x3040, sources({ caller }))).toMatchObject({ name: "sized", offset: "0x40" });
    expect(
      symbolize(0x1000, sources({ caller: [{ rva: 0x1000, name: "ghidra_name", size: null, evidence_id: null }] })),
    ).toMatchObject({ name: "ghidra_name", kind: "caller" });
  });

  it("names import slots and validates against the AddressRef symbol schema", () => {
    const slot = symbolize(0x6004, sources());
    expect(slot).toEqual({ name: "KERNEL32.dll!Sleep", kind: "import-slot", source: "pe-import", offset: "0x4" });
    for (const x of [0x1000, 0x1036, 0x1810, 0x2010, 0x5000, 0x6004])
      expect(symbolSchema.safeParse(symbolize(x, sources())).success).toBe(true);
    expect(symbolize(0x9000, sources())).toBeNull();
  });
});
