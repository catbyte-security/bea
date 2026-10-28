import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  CALL_BLOCK,
  exceptionTypeOf,
  hexToByteArray,
  memoryOperationOf,
  SEH_PAGE,
  SEH_PAGE_HEX,
  SEH_PAGE_SHA256,
} from "../../../../src/agent/pure/callBlock.js";
import {
  buildBlock,
  checkPlan,
  layoutScratch,
  materializeBuffer,
  parseBlock,
  registerFile,
  writeLE,
} from "../../../../src/agent/pure/callMaterialize.js";
import { classifyWin64, planToAgent } from "../../../../src/domain/callModel/classify.js";
import type { BufferWire, PlanWire, VectorsWire } from "../../../../src/shared/callPlan.js";

describe("the SEH-frame thunk page (DESIGN §5.3.1)", () => {
  it("is the verified 0x200-byte page (sha256 with the imm64 zeroed)", () => {
    const bytes = Uint8Array.from(hexToByteArray(SEH_PAGE_HEX));
    expect(bytes.length).toBe(0x200);
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(SEH_PAGE_SHA256);
  });

  it("carries the unwind info and RUNTIME_FUNCTIONs the design lists", () => {
    const bytes = Uint8Array.from(hexToByteArray(SEH_PAGE_HEX));
    const hex = (from: number, n: number): string => Buffer.from(bytes.subarray(from, from + n)).toString("hex");
    expect(hex(SEH_PAGE.unwindThunk, 16)).toBe("09050305050302500130" + "0000c0000000");
    expect(hex(SEH_PAGE.unwindHandler, 8)).toBe("0104010004620000");
    const rf = new DataView(bytes.buffer, SEH_PAGE.table, 24);
    expect([0, 4, 8, 12, 16, 20].map((o) => rf.getUint32(o, true))).toEqual([0x000, 0x0be, 0x1c0, 0x0c0, 0x19b, 0x1d0]);
    expect(hex(SEH_PAGE.rtlUnwindExImm - 2, 10)).toBe("48b80000000000000000");
    expect(hex(SEH_PAGE.readStub, 7)).toBe("0fae19d97904c3");
  });

  it("recovers the x87 state after a callee fault: fninit, then the caller's FPCW/MXCSR (review fix EMU-5)", () => {
    const bytes = Uint8Array.from(hexToByteArray(SEH_PAGE_HEX));
    const hex = (from: number, n: number): string => Buffer.from(bytes.subarray(from, from + n)).toString("hex");
    // recovery: fninit (db e3; fnclex db e2 left a full x87 stack behind); jmp 0xa6 (eb e8)
    expect(hex(SEH_PAGE.recovery, 4)).toBe("dbe3ebe8");
    // 0xa6: ldmxcsr [rbx+0x98]; fldcw [rbx+0x9c] (the saved environment over fninit's defaults)
    expect(hex(SEH_PAGE.restore, 13)).toBe("0fae9398000000d9ab9c000000");
    // steal fallback restore stub: fninit; ldmxcsr [rcx+0x98]; fldcw [rcx+0x9c]; ret (ends before UNWIND_INFO)
    expect(hex(SEH_PAGE.restoreStub, 16)).toBe("dbe30fae9198000000d9a99c000000c3");
    expect(SEH_PAGE.restoreStub + 16).toBe(SEH_PAGE.unwindThunk);
  });

  it("maps NTSTATUS codes and access operations", () => {
    expect(exceptionTypeOf(0xc0000005)).toBe("access-violation");
    expect(exceptionTypeOf(0xc0000094)).toBe("arithmetic");
    expect(exceptionTypeOf(0xc000001d)).toBe("illegal-instruction");
    expect(exceptionTypeOf(0xc00000fd)).toBe("stack-overflow");
    expect(exceptionTypeOf(0xe06d7363)).toBe("system");
    expect([0, 1, 8].map(memoryOperationOf)).toEqual(["read", "write", "execute"]);
  });
});

const buffer = (over: Partial<BufferWire>): BufferWire => ({
  name: "b",
  size: 16,
  align: 16,
  placement: "scratch",
  template: "00".repeat(16),
  columns: [],
  ptrFields: [],
  out: false,
  ...over,
});

describe("executor-side materialization (S5 §9.5 rule 3)", () => {
  it("lays buffers out by alignment", () => {
    const layout = layoutScratch([
      buffer({ name: "a", size: 3, align: 1 }),
      buffer({ name: "c", size: 8, align: 8 }),
      buffer({ name: "d", size: 1, align: 64 }),
    ]);
    expect([...layout.offsets]).toEqual([
      ["a", 0],
      ["c", 8],
      ["d", 64],
    ]);
    expect(layout.maxAlign).toBe(64);
  });

  it("applies template, then column patches (scalars and arrays), then pointer fields", () => {
    const vectors: VectorsWire = {
      offset: 10,
      count: 2,
      columns: { "b.x": ["0x11223344", "0x55"], "b.ys": [["0x1", "0x2"], ["0x3"]] },
    };
    const b = buffer({
      template: "ff".repeat(16),
      columns: [
        { column: "b.x", offset: 0, width: 4, count: 1 },
        { column: "b.ys", offset: 4, width: 2, count: 2 },
      ],
      ptrFields: [{ offset: 8, buffer: "other", plus: -16 }],
    });
    const at = (name: string): bigint => (name === "other" ? 0x1000n : 0n);
    expect(Buffer.from(materializeBuffer(b, vectors, 0, at)).toString("hex")).toBe(
      "44332211" + "01000200" + "f00f000000000000",
    );
    expect(Buffer.from(materializeBuffer(b, vectors, 1, at)).toString("hex")).toBe(
      "55000000" + "03000000" + "f00f000000000000",
    );
  });

  it("builds the Win64 register file from a host-lowered plan (columns, constants, buffers, byval, dup GPR)", () => {
    const classified = classifyWin64({
      signature: {
        args: [
          { type: "buffer_byval", buffer: "small" },
          { type: "f64", name: "x" },
          { type: "buffer_ptr", buffer: "big", offset: 4 },
          { type: "f32", default: -1 },
          { type: "i64", default: "-2" },
        ],
        returns: "f64",
        variadic: true,
      },
      buffers: [
        { name: "small", size: 4, align: 4, placement: "scratch", init_hex: "78563412", fields: [], out: false },
        { name: "big", size: 32, align: 16, placement: "scratch", fields: [], out: true },
      ],
      supplied: new Set(["x"]),
    });
    if (!classified.ok) throw new Error(JSON.stringify(classified.error));
    const wire = planToAgent(classified.value.plan, "0x140001000", () => undefined);
    if (!wire.ok) throw new Error("lowering failed");
    const plan: PlanWire = wire.value;
    const vectors: VectorsWire = { offset: 0, count: 1, columns: { x: ["0x4002000000000000"] } };
    const addresses = new Map([
      ["small", 0x2000n],
      ["big", 0x3000n],
    ]);
    const images = new Map(
      plan.buffers.map((b) => [b.name, materializeBuffer(b, vectors, 0, (n) => addresses.get(n) ?? 0n)]),
    );
    const regs = registerFile(
      plan,
      vectors,
      0,
      (n) => addresses.get(n) ?? 0n,
      (n) => images.get(n) ?? new Uint8Array(),
    );
    expect(regs.gpr).toEqual([0x12345678n, 0x4002000000000000n, 0x3004n, 0xbf800000n]);
    expect(regs.xmm).toEqual([0n, 0x4002000000000000n, 0n, 0xbf800000n]);
    expect(regs.stack).toEqual([0xfffffffffffffffen]);
    expect(checkPlan(plan, vectors, { scratchBytes: 1 << 20, bufferBytes: 1 << 20 })).toEqual([]);
  });

  it("writes and reads the CallBlock image (status bits cleared from MXCSR)", () => {
    const block = buildBlock(
      0x7ff600001760n,
      { gpr: [1n, 2n, 3n, 4n], xmm: [5n, 6n, 7n, 8n], stack: [9n, 10n] },
      { mxcsr: 0x9fe3, fpcw: 0x37f },
    );
    const view = new DataView(block.buffer);
    expect(view.getBigUint64(CALL_BLOCK.target, true)).toBe(0x7ff600001760n);
    expect(view.getBigUint64(CALL_BLOCK.gpr + 24, true)).toBe(4n);
    expect(view.getBigUint64(CALL_BLOCK.xmm + 16, true)).toBe(6n);
    expect(view.getBigUint64(CALL_BLOCK.xmm + 24, true)).toBe(0n);
    expect(view.getBigUint64(CALL_BLOCK.nstack, true)).toBe(2n);
    expect(view.getBigUint64(CALL_BLOCK.stack + 8, true)).toBe(10n);
    expect(view.getUint32(CALL_BLOCK.mxcsrIn, true)).toBe(0x9fc0);
    expect(view.getUint16(CALL_BLOCK.fpcwIn, true)).toBe(0x37f);
    // a status-2 record as the language handler writes it
    writeLE(block, CALL_BLOCK.status, 4, 2n);
    writeLE(block, CALL_BLOCK.code, 4, 0xc0000005n);
    writeLE(block, CALL_BLOCK.nparams, 4, 2n);
    writeLE(block, CALL_BLOCK.exceptionAddress, 8, 0x7ff600001930n);
    writeLE(block, CALL_BLOCK.info, 8, 1n);
    writeLE(block, CALL_BLOCK.info + 8, 8, 4n);
    const parsed = parseBlock(block);
    expect(parsed).toMatchObject({ status: 2, code: 0xc0000005, nparams: 2, exceptionAddress: 0x7ff600001930n });
    expect(parsed.info.slice(0, 2)).toEqual([1n, 4n]);
  });

  it("re-checks bounds the agent must never exceed", () => {
    const plan: PlanWire = {
      target: "0x1",
      slots: [
        { reg: "rcx", source: { kind: "column", column: "missing" } },
        { reg: "rcx", source: { kind: "byval", buffer: "b" } },
        { reg: "stack", stackIndex: 28, source: { kind: "const", bits: "0x0" } },
      ],
      returns: { kind: "void" },
      buffers: [buffer({ size: 16, template: "00", ptrFields: [{ offset: 12, buffer: "nope", plus: 0 }] })],
    };
    const problems = checkPlan(
      plan,
      { offset: 0, count: 1, columns: {} },
      { scratchBytes: 1 << 20, bufferBytes: 8 },
    ).map((i) => i.problem);
    expect(problems).toEqual(
      expect.arrayContaining([
        "size must be 1..8",
        "template must be size bytes",
        "pointer field ends past the buffer",
        "ptr field names unknown buffer nope",
        "register used twice",
        "byval buffers are 1, 2, 4 or 8 bytes",
        "stack slots are unique indices 0..27",
        "vectors lack column missing",
      ]),
    );
  });
});
