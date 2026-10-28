import { describe, expect, it } from "vitest";

import { memoryOperandAccess, rwAccessOf, type OperandAccess } from "../../../../src/agent/pure/watchAccess.js";

const bytes = (...b: number[]): Uint8Array => new Uint8Array(b);
const reg = (access: OperandAccess) => ({ type: "reg", access });
const mem = (access: OperandAccess) => ({ type: "mem", access });

describe("access kind of a read/write debug-register hit", () => {
  it("takes the single memory operand's access (game_sim's speed store, readers and frame counter)", () => {
    expect(memoryOperandAccess([mem("w"), reg("r")])).toBe("w"); // movss dword ptr [rax + 8], xmm0
    expect(memoryOperandAccess([reg("w"), mem("r")])).toBe("r"); // movss xmm0, dword ptr [rcx + 8]
    expect(memoryOperandAccess([reg("rw"), mem("r")])).toBe("r"); // mulss xmm0, dword ptr [rcx + 8]
    expect(memoryOperandAccess([mem("rw"), { type: "imm", access: "" }])).toBe("w"); // add dword ptr [rax + 0x38], 1
  });

  it("does not guess for no, several or access-less memory operands", () => {
    expect(memoryOperandAccess([reg("w"), reg("r")])).toBeNull();
    expect(memoryOperandAccess([mem("w"), mem("r")])).toBeNull(); // movsb: which operand hit is unknown
    expect(memoryOperandAccess([reg("w"), mem("")])).toBeNull(); // lea never accesses memory
    expect(memoryOperandAccess([reg("w"), { type: "mem" }])).toBeNull();
  });

  it("lets the instruction decide even when the values say otherwise", () => {
    expect(rwAccessOf("w", bytes(1, 2), bytes(1, 2))).toBe("w"); // a store of the same value is still a write
    expect(rwAccessOf("r", bytes(1, 2), bytes(3, 4))).toBe("r"); // another thread changed it between two hits
    expect(rwAccessOf("w", null, null)).toBe("w");
  });

  it("falls back to the values when the instruction cannot tell", () => {
    expect(rwAccessOf(null, bytes(1, 2), bytes(1, 3))).toBe("w");
    expect(rwAccessOf(null, bytes(1, 2), bytes(1, 2))).toBe("r");
    expect(rwAccessOf(null, bytes(1, 2), null)).toBe("w");
    expect(rwAccessOf(null, null, null)).toBe("r");
  });
});
