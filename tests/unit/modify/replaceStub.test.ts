import { describe, expect, it } from "vitest";

import { replaceStubBytes } from "../../../src/agent/pure/modifyStub.js";

/**
 * The override_function replace stub (src/agent/pure/modifyStub.ts). The expected bytes were disassembled with
 * capstone 5.0.9 (x86-64) when the stub was written: push rcx/rdx/r8/r9; sub rsp,0x68; movdqu [rsp+0x20..0x50],
 * xmm0..3; movabs rax,decide; call rax; movdqu xmm0..3 back; add rsp,0x68; pop r9/r8/rdx/rcx; test eax,eax;
 * je original; [movabs rax,bits; movq xmm0,rax]; ret; original: movabs r11,slot; jmp qword ptr [r11].
 */
const PROLOGUE = "5152415041514883ec68" + "f30f7f442420f30f7f4c2430f30f7f542440f30f7f5c2450" + "48b8"; // ... decide imm64
const AFTER_CALL = "ffd0" + "f30f6f442420f30f6f4c2430f30f6f542440f30f6f5c2450" + "4883c468415941585a59" + "85c0";

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");

describe("replaceStubBytes", () => {
  it("encodes a float constant: rax and the low lane of xmm0, else a jump through the trampoline slot", () => {
    const code = replaceStubBytes({
      decide: 0x1122334455667788n,
      originalSlot: 0x7ff612345678n,
      bits: 0x42f60000n, // 123.0f
      float: true,
    });
    expect(hex(code)).toBe(
      `${PROLOGUE}8877665544332211${AFTER_CALL}7410` +
        "48b80000f64200000000" + // movabs rax, 0x42f60000
        "66480f6ec0" + // movq xmm0, rax
        "c3" +
        "49bb78563412f67f0000" + // movabs r11, slot
        "41ff23", // jmp qword ptr [r11]
    );
  });

  it("encodes an integer constant without touching xmm0, and a void replacement as a bare ret", () => {
    const int = replaceStubBytes({ decide: 0x1000n, originalSlot: 0x2000n, bits: 0xffffffffn, float: false });
    expect(hex(int)).toContain(`${AFTER_CALL}740b48b8ffffffff00000000c349bb`);
    expect(hex(int)).not.toContain("66480f6ec0");
    const none = replaceStubBytes({ decide: 0x1000n, originalSlot: 0x2000n, bits: null, float: false });
    expect(hex(none)).toBe(`${PROLOGUE}0010000000000000${AFTER_CALL}7401c349bb002000000000000041ff23`);
  });

  it("keeps the callee frame 16-byte aligned with shadow space below the saved xmm registers", () => {
    const code = replaceStubBytes({ decide: 1n, originalSlot: 2n, bits: null, float: false });
    // entry rsp ≡ 8 (mod 16): four pushes (32) + sub imm8 must make the call site ≡ 0
    const frame = code[9] ?? 0;
    expect((8 + 32 + frame) % 16).toBe(0);
    expect(frame).toBeGreaterThanOrEqual(0x20 + 4 * 16); // shadow space + xmm0..3
    // the jz displacement skips exactly the constant block and lands on mov r11
    const jz = hex(code).indexOf("85c074") / 2 + 3;
    expect(code[jz + 1 + (code[jz] ?? 0)]).toBe(0x49);
  });

  it("masks immediates to 64 bits (negative i64 constants)", () => {
    const code = replaceStubBytes({ decide: 1n, originalSlot: 2n, bits: -1n, float: false });
    expect(hex(code)).toContain("48b8ffffffffffffffff");
  });
});
