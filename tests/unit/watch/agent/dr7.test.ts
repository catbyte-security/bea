import { describe, expect, it } from "vitest";

import {
  clearDr6Hits,
  clearMaskFor,
  clearSlot,
  coveringWatch,
  ctrlBitsFor,
  enableMask,
  firedSlots,
  inferStepSlots,
  pickSlot,
  slotBits,
  validateDebugRegister,
  verifySlot,
} from "../../../../src/agent/pure/dr7.js";

/** Frida sets L_s and LE (bit 8); the a17 table below is what GetThreadContext showed on this host [ext-frida §3.9]. */
const fridaDr7 = (s: 0 | 1 | 2 | 3, rw: "w" | "rw", size: 1 | 2 | 4 | 8): bigint =>
  (1n << BigInt(2 * s)) | 0x100n | ctrlBitsFor(s, rw, size);

describe("DR7 arithmetic (S4 §11.2)", () => {
  it("reproduces the VERIFIED a17 encodings", () => {
    expect(fridaDr7(0, "w", 8)).toBe(0x90101n);
    expect(fridaDr7(1, "rw", 4)).toBe(0xf00104n);
    expect(fridaDr7(2, "w", 2)).toBe(0x5000110n);
    expect(fridaDr7(3, "w", 1)).toBe(0x10000140n);
  });

  it("masks one slot's enable and control bits and nothing else", () => {
    expect(enableMask(0)).toBe(0b11n);
    expect(enableMask(3)).toBe(0b11n << 6n);
    expect(slotBits(1)).toBe((0b11n << 2n) | (0xfn << 20n));
    const all = fridaDr7(0, "w", 8) | fridaDr7(2, "w", 2);
    expect(clearSlot(all, 0)).toBe((1n << 4n) | 0x100n | ctrlBitsFor(2, "w", 2));
    expect(clearMaskFor(0b0101)).toBe(slotBits(0) | slotBits(2));
    expect(clearMaskFor(0)).toBe(0n);
  });

  it("encodes execute breakpoints with RW 00 and LEN 00", () => {
    expect(ctrlBitsFor(2, "x", 8)).toBe(0n);
  });

  it("reads which slots fired from DR6 and clears only B0..B3", () => {
    expect(firedSlots(0b1010n)).toEqual([1, 3]);
    expect(firedSlots(0x4000n)).toEqual([]);
    expect(clearDr6Hits(0x400fn)).toBe(0x4000n);
  });

  it("verifies a slot against GetThreadContext values", () => {
    const dr7 = fridaDr7(1, "rw", 4);
    expect(verifySlot(dr7, 0x1000n, 1, { address: 0x1000n, rw: "rw", size: 4 })).toBe("armed");
    expect(verifySlot(dr7, 0x1004n, 1, { address: 0x1000n, rw: "rw", size: 4 })).toBe("mismatch");
    expect(verifySlot(dr7, 0x1000n, 1, { address: 0x1000n, rw: "w", size: 4 })).toBe("mismatch");
    expect(verifySlot(dr7, 0n, 0, null)).toBe("cleared");
    expect(verifySlot(dr7, 0x1000n, 1, null)).toBe("mismatch");
    expect(verifySlot(0x100n, 0n, 2, { address: 0x10n, rw: "w", size: 1 })).toBe("cleared");
  });
});

describe("debug-register validation (Frida validates nothing)", () => {
  it("accepts 1/2/4/8 aligned and refuses everything else with the nearest covering watch", () => {
    expect(validateDebugRegister(0x1000n, 4, "w")).toEqual({ ok: true, size: 4 });
    expect(validateDebugRegister(0x1002n, 4, "w")).toEqual({
      ok: false,
      reason: "alignment",
      nearest: { address: 0x1000n, size: 8 },
    });
    expect(validateDebugRegister(0x1000n, 3, "rw")).toEqual({
      ok: false,
      reason: "size",
      nearest: { address: 0x1000n, size: 4 },
    });
    expect(validateDebugRegister(0x1006n, 4, "w")).toEqual({ ok: false, reason: "alignment", nearest: null });
    expect(validateDebugRegister(0x1003n, 16, "x")).toEqual({ ok: true, size: 1 });
  });

  it("finds the smallest aligned power-of-two window", () => {
    expect(coveringWatch(0x1001n, 1)).toEqual({ address: 0x1001n, size: 1 });
    expect(coveringWatch(0x1001n, 2)).toEqual({ address: 0x1000n, size: 4 });
    expect(coveringWatch(0x1007n, 2)).toBeNull();
    expect(coveringWatch(0x1000n, 9)).toBeNull();
  });

  it("picks the lowest free slot or the requested free one", () => {
    expect(pickSlot([false, false, false, false], undefined)).toBe(0);
    expect(pickSlot([true, false, true, false], undefined)).toBe(1);
    expect(pickSlot([true, true, true, true], undefined)).toBeNull();
    expect(pickSlot([true, false, false, false], 2)).toBe(2);
    expect(pickSlot([false, false, true, false], 2)).toBeNull();
  });
});

describe("single steps without a DR6 cause (inferStepSlots)", () => {
  const car8 = 0x2a000008n;
  const owned = [{ slot: 0 as const, address: car8 }];
  const dr = [car8, 0n, 0n, 0n];
  const dr7 = fridaDr7(0, "w", 4);

  it("attributes an empty DR6 to the owned slot the context enables at its own address", () => {
    expect(inferStepSlots(0n, dr7, dr, owned)).toEqual([0]);
    expect(inferStepSlots(0xffff0ff0n, dr7, dr, owned)).toEqual([0]); // the reserved-one bits are no cause
  });

  it("never infers when DR6 names a cause or the context does not carry the slot", () => {
    expect(inferStepSlots(0x4000n, dr7, dr, owned)).toEqual([]); // BS: a trap-flag step
    expect(inferStepSlots(0x2n, dr7, dr, owned)).toEqual([]); // B1: another slot fired
    expect(inferStepSlots(0n, clearSlot(dr7, 0), dr, owned)).toEqual([]); // slot not enabled in this context
    expect(inferStepSlots(0n, dr7, [0x2a000010n, 0n, 0n, 0n], owned)).toEqual([]); // DR0 points elsewhere
    expect(inferStepSlots(0n, dr7, dr, [])).toEqual([]);
  });
});
