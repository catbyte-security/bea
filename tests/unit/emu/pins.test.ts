import { describe, expect, it } from "vitest";

import { classifyPin } from "../../../src/providers/emulator/pythonResolver.js";
import { compareSelftest, SELFTEST_EXPECTATIONS } from "../../../src/providers/emulator/selftestExpectations.js";

const PINNED = { unicorn: "2.1.4", unicornCore: "2.1", capstone: "5.0.9", pefile: "2024.8.26" };

describe("pin classification (S5 §6.1)", () => {
  it("separates exact, compatible and mismatch", () => {
    expect(classifyPin("3.14.6", PINNED).pin).toBe("exact");
    expect(classifyPin("3.10.0", PINNED).pin).toBe("exact");
    expect(classifyPin("3.12.1", { ...PINNED, unicorn: "2.1.3" }).pin).toBe("compatible");
    expect(classifyPin("3.12.1", { ...PINNED, capstone: "5.0.1" }).pin).toBe("compatible");
    expect(classifyPin("3.9.18", PINNED)).toMatchObject({ pin: "mismatch", reason: expect.stringContaining("3.10") });
    expect(classifyPin("3.12.1", { ...PINNED, unicorn: "2.0.1" }).pin).toBe("mismatch");
    expect(classifyPin("3.12.1", { ...PINNED, capstone: "6.0.0" }).pin).toBe("mismatch");
    expect(classifyPin("3.12.1", { unicorn: "2.1.4", capstone: "5.0.9" }).pin).toBe("mismatch");
    expect(classifyPin(undefined, PINNED).pin).toBe("mismatch");
  });
});

const results = (overrides: Record<string, unknown> = {}) => ({
  selftest: "bea-emu/0.1",
  results: {
    ...Object.fromEntries(
      Object.keys(SELFTEST_EXPECTATIONS["2.1.4"] ?? {}).map((name) => [
        name,
        { ok: true, observed: true, expected: true },
      ]),
    ),
    mxcsr_flags_modeled: { ok: true, observed: false, expected: false },
    ...overrides,
  },
});

describe("selftest expectations (S5 §3.16)", () => {
  it("passes the validated set, including the expected negative MXCSR observation", () => {
    expect(compareSelftest(results(), "2.1.4")).toEqual({
      passed: true,
      mismatches: [],
      warnings: [],
      validatedAgainst: "2.1.4",
    });
  });

  it("reports mismatches, missing items, and believed items as warnings only", () => {
    const compared = compareSelftest(
      results({
        cow_lifo_ok: { ok: false, observed: false, expected: true },
        int3_rip: undefined,
        mxcsr_flags_modeled: { ok: false, observed: true, expected: false },
        x87_reset: { ok: false, observed: false, expected: true },
      }),
      "2.1.4",
    );
    expect(compared.passed).toBe(false);
    expect([...compared.mismatches].sort()).toEqual(["cow_lifo_ok", "int3_rip", "mxcsr_flags_modeled"]);
    expect(compared.warnings).toEqual(["x87_reset"]);
  });

  it("validates an unknown engine against the newest known table", () => {
    expect(compareSelftest(results(), "2.1.9").validatedAgainst).toBe("2.1.4");
  });
});
