import { describe, expect, it } from "vitest";

import {
  anyOverlay,
  FUNCTION_MAX_INSNS,
  hexAt,
  immToBigInt,
  isRelativeBranch,
  overlayMask,
  pageChunks,
  planWindow,
  relocate,
  rewriteBranchText,
  ripRelative,
  stopForOverrun,
  touchesOverlay,
} from "../../../../src/agent/pure/codeDisasm.js";

/** Pure helpers of the agent disassemble RPC (WP6; S4 §8.4 fix-ups). */
describe("agent disassemble helpers", () => {
  it("plans count windows as count x 15 bytes and clips function/range windows to the byte cap", () => {
    expect(planWindow("count", 32, { maxBytes: 65_536, maxInsns: 2048 })).toEqual({
      bytes: 480,
      maxInsns: 32,
      clipped: false,
    });
    expect(planWindow("count", 5000, { maxBytes: 65_536, maxInsns: 2048 })).toEqual({
      bytes: 30_720,
      maxInsns: 2048,
      clipped: false,
    });
    expect(planWindow("count", 10, { maxBytes: 64, maxInsns: 2048 }).bytes).toBe(64);
    expect(planWindow("function", 285, { maxBytes: 65_536, maxInsns: FUNCTION_MAX_INSNS })).toEqual({
      bytes: 285,
      maxInsns: 4096,
      clipped: false,
    });
    expect(planWindow("range", 100_000, { maxBytes: 65_536, maxInsns: 2048 })).toEqual({
      bytes: 65_536,
      maxInsns: 2048,
      clipped: true,
    });
  });

  it("splits a read into page-aligned chunks", () => {
    expect(pageChunks(0x1ff0n, 0x30, 0x1000)).toEqual([
      { offset: 0, length: 0x10 },
      { offset: 0x10, length: 0x20 },
    ]);
    expect(pageChunks(0x2000n, 0x2001, 0x1000).map((c) => c.length)).toEqual([0x1000, 0x1000, 1]);
    expect(pageChunks(0x2000n, 0, 0x1000)).toEqual([]);
  });

  it("parses Frida immediates (decimal strings, numbers, Int64-like, hex)", () => {
    expect(immToBigInt("140701662810544")).toBe(140701662810544n);
    expect(immToBigInt(48)).toBe(48n);
    expect(immToBigInt({ toString: () => "18446744073709551615" })).toBe(18446744073709551615n);
    expect(immToBigInt("0x1A")).toBe(26n);
    expect(immToBigInt(1.5)).toBeNull();
    expect(immToBigInt("rax")).toBeNull();
    expect(immToBigInt(null)).toBeNull();
  });

  it("moves scratch-relative targets to the real code and resolves RIP-relative operands against next", () => {
    const scratch = 0x2_0000_0000n;
    const real = 0x7ff6_a000_1760n;
    expect(relocate(scratch + 0x110n, scratch, real)).toBe(real + 0x110n);
    expect(relocate(scratch - 0x20n, scratch, real)).toBe(real - 0x20n);
    expect(relocate(0x10n, 0x20n, 0x0n)).toBe(0xffff_ffff_ffff_fff0n);
    expect(ripRelative(0x1_4000_17acn, 0xaa60)).toBe(0x1_4000_c20cn);
    expect(ripRelative(0x1000n, -0x10)).toBe(0xff0n);
  });

  it("rewrites the branch operand text and recognizes relative branches", () => {
    expect(rewriteBranchText("0x200000110", 0x2_0000_0110n, 0x7ff6a0001870n)).toBe("0x7ff6a0001870");
    expect(rewriteBranchText("qword ptr 0x200000110", 0x2_0000_0110n, 0x10n)).toBe("qword ptr 0x10");
    expect(rewriteBranchText("weird", 0x5n, 0x7n)).toBe("0x7");
    expect(isRelativeBranch(["jump", "branch_relative"])).toBe(true);
    expect(isRelativeBranch(["call"])).toBe(false);
  });

  it("marks overlaid bytes per instruction", () => {
    const live = new Uint8Array([0xe9, 1, 2, 3, 5, 0x90, 0x90]);
    const orig = new Uint8Array([0xf3, 0x0f, 0x10, 0x41, 0x04, 0x90, 0x90]);
    const mask = overlayMask(live, orig);
    expect([...mask]).toEqual([1, 1, 1, 1, 1, 0, 0]);
    expect(touchesOverlay(mask, 0, 5)).toBe(true);
    expect(touchesOverlay(mask, 5, 2)).toBe(false);
    expect(touchesOverlay(mask, 4, 9)).toBe(true);
    expect(anyOverlay(mask)).toBe(true);
    expect(anyOverlay(overlayMask(live, live))).toBe(false);
  });

  it("names stops and formats real addresses", () => {
    expect(stopForOverrun(4, 480)).toBe("access-violation");
    expect(stopForOverrun(480, 480)).toBe("limit");
    expect(hexAt(0x7ff0n, 0x10)).toBe("0x8000");
  });
});
