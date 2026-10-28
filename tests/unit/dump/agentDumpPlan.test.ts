import { describe, expect, it } from "vitest";

import {
  CONTEXT_BYTES,
  CONTEXT_GPR_OFFSETS,
  DIR_TLS,
  changedRanges,
  chunksOf,
  coalesce,
  holesOf,
  moduleSelector,
  pageSpan,
  parseContext,
  parseTlsDirectory,
  peDirectory,
  readableParts,
  spliceOriginals,
  stackSpan,
  tlsBlockSize,
} from "../../../src/agent/pure/dumpPlan.js";
import { mapPe, sampleImage } from "./peBuilder.js";

describe("agent dump planning helpers (S4 §15.1)", () => {
  it("pageSpan covers whole pages; stackSpan runs from the page of rsp up to the stack base", () => {
    expect(pageSpan(0x1234n, 0x10)).toEqual({ start: 0x1000n, size: 0x1000 });
    expect(pageSpan(0x1ff0n, 0x20)).toEqual({ start: 0x1000n, size: 0x2000 });
    expect(stackSpan(0x7000_1234n, 0x7000_8000n, 0x2000)).toEqual({ start: 0x7000_1000n, size: 0x2000 });
    expect(stackSpan(0x7000_7234n, 0x7000_8000n, 0x10000)).toEqual({ start: 0x7000_7000n, size: 0x1000 });
    expect(stackSpan(0x7000_9000n, 0x7000_8000n, 0x1000)).toBeNull();
    expect(stackSpan(0x7000_1000n, 0x7000_8000n, 0)).toBeNull();
  });

  it("holesOf complements the readable spans inside a region; readableParts cuts a chunk around the holes", () => {
    const region = { start: 0x10000n, size: 0x5000 };
    const holes = holesOf(region, [
      { start: 0x0f000n, size: 0x2000 },
      { start: 0x13000n, size: 0x1000 },
    ]);
    expect(holes).toEqual([
      { offset: 0x1000, size: 0x2000 },
      { offset: 0x4000, size: 0x1000 },
    ]);
    expect(readableParts(0x800, 0x3000, holes)).toEqual([
      { offset: 0x800, size: 0x800 },
      { offset: 0x3000, size: 0x800 },
    ]);
    expect(holesOf(region, [])).toEqual([{ offset: 0, size: 0x5000 }]);
    expect(
      coalesce([
        { offset: 4, size: 2 },
        { offset: 0, size: 4 },
        { offset: 9, size: 1 },
      ]),
    ).toEqual([
      { offset: 0, size: 6 },
      { offset: 9, size: 1 },
    ]);
  });

  it("chunksOf splits at the chunk size (never below a page)", () => {
    expect(chunksOf(0x2800, 0x1000)).toEqual([
      { offset: 0, size: 0x1000 },
      { offset: 0x1000, size: 0x1000 },
      { offset: 0x2000, size: 0x800 },
    ]);
    expect(chunksOf(0x2000, 16)).toHaveLength(2);
    expect(chunksOf(0, 0x1000)).toEqual([]);
  });

  it("spliceOriginals writes BEA's original bytes over a hooked prologue and reports only changed bytes (CT-I6)", () => {
    const chunk = new Uint8Array(32).fill(0x90);
    chunk.set([0xe9, 0x11, 0x22, 0x33, 0x44], 8); // the hook's jmp at base+8
    const restored = spliceOriginals(chunk, 0x1000n, [
      { address: 0x1008n, bytes: Uint8Array.from([0x48, 0x89, 0x5c, 0x24, 0x08, 0x90]) },
      { address: 0x0ff0n, bytes: new Uint8Array(4).fill(0xcc) }, // entirely before the chunk
      { address: 0x101en, bytes: Uint8Array.from([0x90, 0x55, 0x66]) }, // straddles the end
    ]);
    expect(Array.from(chunk.subarray(8, 14))).toEqual([0x48, 0x89, 0x5c, 0x24, 0x08, 0x90]);
    expect(Array.from(chunk.subarray(30, 32))).toEqual([0x90, 0x55]);
    expect(restored).toEqual([
      { offset: 8, size: 5 },
      { offset: 31, size: 1 },
    ]);
    expect(changedRanges(Uint8Array.from([1, 2, 3]), Uint8Array.from([1, 9, 9]))).toEqual([{ offset: 1, size: 2 }]);
  });

  it("parseContext reads GPRs, EFlags, MXCSR, the FPU control word and 128-bit XMM registers at the x64 offsets", () => {
    const ctx = new Uint8Array(CONTEXT_BYTES);
    const v = new DataView(ctx.buffer);
    Object.values(CONTEXT_GPR_OFFSETS).forEach((offset, i) => v.setBigUint64(offset, 0x1000n + BigInt(i), true));
    v.setUint32(0x34, 0x1fa0, true);
    v.setUint32(0x44, 0x246, true);
    v.setUint16(0x100, 0x37f, true);
    v.setBigUint64(0x1a0, 0x3f800000n, true);
    v.setBigUint64(0x1a8, 0x1n, true);
    const parsed = parseContext(ctx, true);
    expect(parsed.registers["rax"]).toBe("0x1000");
    expect(parsed.registers["rip"]).toBe(`0x${(0x1000 + Object.keys(CONTEXT_GPR_OFFSETS).length - 1).toString(16)}`);
    expect(Object.keys(parsed.registers)).toHaveLength(17);
    expect(parsed).toMatchObject({ mxcsr: "0x1fa0", eflags: "0x246", fpcw: "0x37f" });
    expect(parsed.xmm?.[0]).toBe("0x1000000003f800000");
    expect(parsed.xmm).toHaveLength(16);
    expect(parseContext(ctx, false).xmm).toBeNull();
  });

  it("finds the TLS directory of a mapped image and sizes a static TLS block (R6)", () => {
    const image = mapPe(sampleImage().file, 0x7ff6_0000_0000n);
    expect(peDirectory(image, DIR_TLS)).toBeNull();
    expect(peDirectory(image, 5)).not.toBeNull();
    const dir = new Uint8Array(0x28);
    const v = new DataView(dir.buffer);
    v.setBigUint64(0, 0x7ff6_0000_5000n, true);
    v.setBigUint64(8, 0x7ff6_0000_5010n, true);
    v.setBigUint64(16, 0x7ff6_0000_4100n, true);
    v.setUint32(32, 0x20, true);
    const tls = parseTlsDirectory(dir);
    expect(tls).toEqual({
      start: 0x7ff6_0000_5000n,
      end: 0x7ff6_0000_5010n,
      indexAddress: 0x7ff6_0000_4100n,
      zeroFill: 0x20,
    });
    expect(tlsBlockSize(tls!)).toBe(0x30);
    expect(parseTlsDirectory(new Uint8Array(8))).toBeNull();
    expect(peDirectory(new Uint8Array(0x100), 9)).toBeNull();
  });

  it("module selectors: 0x<base> selects by base, anything else by case-insensitive name", () => {
    expect(moduleSelector("0x7FF6A0000000")).toEqual({ kind: "base", base: 0x7ff6a0000000n });
    expect(moduleSelector("Game.EXE")).toEqual({ kind: "name", name: "game.exe" });
  });
});
