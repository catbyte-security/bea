import { describe, expect, it } from "vitest";

import {
  BlockSet,
  encodeBlockSpans,
  encodeTriples,
  inRanges,
  sumTriples,
  synthesizeEntryBlock,
} from "../../../../src/agent/pure/traceBlocks.js";
import { BINARY_LAYOUTS } from "../../../../src/shared/binaryLayouts.js";

describe("trace block bookkeeping", () => {
  it("dedupes blocks by start, widens a longer span and counts the cap overflow", () => {
    const set = new BlockSet(2);
    expect(set.add(0x20n, 0x30n)).toBe("added");
    expect(set.add(0x10n, 0x18n)).toBe("added");
    expect(set.add(0x20n, 0x38n)).toBe("duplicate");
    expect(set.add(0x40n, 0x48n)).toBe("cap");
    expect(set.size).toBe(2);
    expect(set.overflow).toBe(1);
    expect(set.entries()).toEqual([
      [0x10n, 0x18n],
      [0x20n, 0x38n],
    ]);
  });

  it("filters by module ranges", () => {
    const ranges = [{ base: 0x1000n, end: 0x2000n }];
    expect(inRanges(0x1000n, ranges)).toBe(true);
    expect(inRanges(0x2000n, ranges)).toBe(false);
  });

  it("synthesizes the relocated entry block (CT-M1: E10 saw +0x1765 for a function at +0x1760)", () => {
    expect(synthesizeEntryBlock(0x1760n, 0x1765n)).toEqual({ base: 0x1760n, end: 0x1765n });
    expect(synthesizeEntryBlock(0x1760n, 0x1760n)).toBeNull();
    expect(synthesizeEntryBlock(0x1760n, null)).toBeNull();
    expect(synthesizeEntryBlock(0x1760n, 0x2000n)).toBeNull();
  });

  it("encodes the shared fixed-record layouts", () => {
    const spans = new DataView(encodeBlockSpans([[0x1765n, 0x177en]]));
    expect(spans.byteLength).toBe(BINARY_LAYOUTS["block-span/1"].rec_bytes);
    expect(spans.getBigUint64(0, true)).toBe(0x1765n);
    expect(spans.getBigUint64(8, true)).toBe(0x177en);
    const triples = new DataView(encodeTriples([[1n, 2n, 3n]]));
    expect(triples.byteLength).toBe(BINARY_LAYOUTS["block-count/1"].rec_bytes);
    expect(BINARY_LAYOUTS["call-site-count/1"].rec_bytes).toBe(24);
    expect(triples.getBigUint64(16, true)).toBe(3n);
  });

  it("sums recompiled slab entries by start, or by (site, target)", () => {
    expect(
      sumTriples(
        [
          [0x20n, 0x28n, 2n],
          [0x10n, 0x18n, 1n],
          [0x20n, 0x30n, 3n],
        ],
        "a",
      ),
    ).toEqual([
      [0x10n, 0x18n, 1n],
      [0x20n, 0x30n, 5n],
    ]);
    expect(
      sumTriples(
        [
          [0x10n, 0x80n, 1n],
          [0x10n, 0x90n, 1n],
          [0x10n, 0x80n, 4n],
        ],
        "ab",
      ),
    ).toEqual([
      [0x10n, 0x80n, 5n],
      [0x10n, 0x90n, 1n],
    ]);
  });
});
