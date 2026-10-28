import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { assessEmulation, deviationSentence } from "../../../src/application/emu/deviations.js";
import type { DeviationKind } from "../../../src/domain/emuProtocol.js";

/**
 * Review fixes EMU-1 / EMU-6: every deviation kind the bridge can emit (its DEVIATION_NOTES table) must be known to
 * the host. A kind the host cannot map made assessEmulation push `undefined` into `limitations`, which breaks the
 * output contract: emu_call answered "BEA hit an internal error" instead of the (deviating) result. The kinds are read
 * from the bridge source, so a kind added on one side only fails here.
 */
const BRIDGE = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "bridge", "emu", "bea_emu_bridge.py");

const bridgeKinds = (): string[] => {
  const source = readFileSync(BRIDGE, "utf8").replace(/\r\n/gu, "\n");
  const start = source.indexOf("DEVIATION_NOTES = {");
  const end = source.indexOf("\n}\n", start);
  return [...source.slice(start, end).matchAll(/^ {4}"([a-z0-9_]+)":/gmu)].map((m) => m[1] ?? "");
};

describe("bridge deviation kinds vs the host (S5 §4.4)", () => {
  const kinds = bridgeKinds();

  it("reads the bridge's deviation table", () => {
    expect(kinds.length).toBeGreaterThan(25);
    expect(kinds).toContain("x87_transcendental_inexact");
    expect(kinds).toContain("sse_approx_inexact");
    expect(kinds).toContain("hle_heap_exhausted");
  });

  it.each(kinds)("%s maps to a limitation sentence (or deliberately to none)", (kind) => {
    const sentence = deviationSentence({ kind: kind as DeviationKind, count: 2 });
    expect(sentence === null || (typeof sentence === "string" && sentence.length > 20), kind).toBe(true);
    const assessed = assessEmulation({ deviations: [{ kind: kind as DeviationKind, count: 2 }] });
    expect(
      assessed.limitations.every((line) => typeof line === "string"),
      kind,
    ).toBe(true);
  });

  it("approximate SSE results and a full emulated heap make a result partial", () => {
    for (const kind of ["sse_approx_inexact", "hle_heap_exhausted"] as const) {
      const assessed = assessEmulation({ deviations: [{ kind: kind as DeviationKind, count: 1 }] });
      expect(assessed.coverage.status, kind).toBe("partial");
    }
  });
});
