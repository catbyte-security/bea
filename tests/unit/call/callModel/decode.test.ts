import { describe, expect, it } from "vitest";

import { classifyWin64 } from "../../../../src/domain/callModel/classify.js";
import { decodeOutcome, outLayout, typedField, typedValue } from "../../../../src/domain/callModel/decode.js";
import type { BufferInput, SignatureInput } from "../../../../src/domain/callModel/normalize.js";
import type { RawBatchColumns } from "../../../../src/shared/callPlan.js";

const plan = (signature: SignatureInput, buffers: readonly BufferInput[] = []) => {
  const r = classifyWin64({ signature, buffers, supplied: new Set() });
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  return r.value.plan;
};
const raw = (over: Partial<RawBatchColumns>): RawBatchColumns => ({
  completed: 1,
  status: ["ok"],
  rax: ["0x0"],
  xmm0lo: ["0x0"],
  out: {},
  mxcsrOut: ["0x1f80"],
  fpcwOut: ["0x27f"],
  ...over,
});

describe("typedValue (S6 §2.3 value encoding)", () => {
  it.each([
    ["i8", 0xffn, -1, "0xff"],
    ["u8", 0xffn, 255, "0xff"],
    ["i32", 0xffffffff80000000n, -2147483648, "0x80000000"],
    ["i64", 0xffffffffffffffffn, "-1", "0xffffffffffffffff"],
    ["u64", 0xffffffffffffffffn, "18446744073709551615", "0xffffffffffffffff"],
    ["ptr", 0x7ff600001000n, "0x7ff600001000", "0x7ff600001000"],
    ["bool", 1n, true, "0x1"],
    ["f32", 0x449a4000n, 1234, "0x449a4000"],
    ["f32", 0x7fc12345n, "NaN", "0x7fc12345"],
    ["f64", 0x8000000000000000n, "-0", "0x8000000000000000"],
  ] as const)("%s %s", (type, lane, value, bits) => {
    expect(typedValue(type, lane)).toEqual({ type, bits, value });
  });
});

describe("decodeOutcome (S5 §7.5)", () => {
  it("reads f32 returns from the low 32 bits of XMM0 and keeps FP control bits only", () => {
    const p = plan({ args: [{ type: "f32" }], returns: "f32", variadic: false });
    const out = decodeOutcome(p, raw({ xmm0lo: ["0xdeadbeef449a4000"], mxcsrOut: ["0x1fa2"] }), 7, new Map());
    expect(out).toMatchObject({ count: 1, offset: 7, status: ["returned"], attribution: [null], ret: ["0x449a4000"] });
    expect(out.fp_after).toEqual({ mxcsr_control: ["0x1f80"], fpcw: ["0x27f"] });
  });

  it("truncates integer returns to their width and reads bool as AL != 0", () => {
    const i16 = plan({ args: [], returns: "i16", variadic: false });
    expect(decodeOutcome(i16, raw({ rax: ["0x1234ffff"] }), 0, new Map()).ret).toEqual(["0xffff"]);
    const b = plan({ args: [], returns: "bool", variadic: false });
    expect(decodeOutcome(b, raw({ rax: ["0xff00"] }), 0, new Map()).ret).toEqual(["0x0"]);
    expect(decodeOutcome(b, raw({ rax: ["0x2"] }), 0, new Map()).ret).toEqual(["0x1"]);
  });

  it("reports a caught CPU exception as cpu_exception with the emulator's cause name (EMU-3, S5 §9.3.2)", () => {
    const p = plan({ args: [{ type: "i32" }, { type: "i32" }], returns: "i32", variadic: false });
    const columns = (n: number) => Array.from({ length: n }, (): `0x${string}` => "0x0");
    const out = decodeOutcome(
      p,
      raw({
        completed: 5,
        status: ["fault", "fault", "fault", "fault", "fault"],
        rax: columns(5),
        xmm0lo: columns(5),
        mxcsrOut: columns(5).map(() => "0x1f80"),
        fpcwOut: columns(5).map(() => "0x27f"),
      }),
      0,
      new Map(),
      [
        { index: 0, type: "arithmetic", module: "m.dll", rva: "0x1455", code: "0xc0000094" },
        { index: 1, type: "illegal-instruction", module: "m.dll", rva: "0x10", code: "0xc000001d" },
        { index: 2, type: "illegal-instruction", module: "m.dll", rva: "0x20", code: "0xc0000096" },
        { index: 3, type: "breakpoint", module: "m.dll", rva: "0x30", code: "0x80000003" },
        { index: 4, type: "access-violation", module: "m.dll", rva: "0x40", code: "0xc0000005" },
      ],
    );
    expect(out.status).toEqual(["cpu_exception", "cpu_exception", "cpu_exception", "cpu_exception", "fault"]);
    expect(out.faults.map((f) => [f.status, f.cause])).toEqual([
      ["cpu_exception", "div_error"],
      ["cpu_exception", "ud"],
      ["cpu_exception", "gp"],
      ["cpu_exception", "breakpoint"],
      ["fault", "access-violation"],
    ]);
  });

  it("maps statuses, attributes live faults to the target and gives not-returned vectors 0x0 bits", () => {
    const p = plan({ args: [{ type: "ptr" }], returns: "i32", variadic: false });
    const out = decodeOutcome(
      p,
      raw({
        completed: 2,
        status: ["ok", "fault"],
        rax: ["0x5", "0x9"],
        xmm0lo: ["0x0", "0x0"],
        mxcsrOut: ["0x1f80", "0x1f80"],
        fpcwOut: ["0x27f", "0x27f"],
      }),
      10,
      new Map(),
      [{ index: 11, type: "access-violation", module: "live_fixture.exe", rva: "0x1930" }],
    );
    expect(out.status).toEqual(["returned", "fault"]);
    expect(out.attribution).toEqual([null, "target"]);
    expect(out.ret).toEqual(["0x5", "0x0"]);
    expect(out.faults).toEqual([
      {
        index: 11,
        status: "fault",
        attribution: "target",
        cause: "access-violation",
        site: { module: "live_fixture.exe", rva: "0x1930" },
      },
    ]);
  });

  it("decodes out-buffer fields (codecs undone, arrays per element) and hidden struct returns", () => {
    const buffers: BufferInput[] = [
      {
        name: "car",
        size: 16,
        align: 16,
        placement: "scratch",
        fields: [
          { name: "speed", offset: 0, type: "f32" },
          { name: "counter", offset: 4, type: "i32", codec_kind: "mul", codec_key: "0x3" },
          { name: "xs", offset: 8, type: "i16[]", count: 4 },
        ],
        out: true,
      },
    ];
    const p = plan(
      {
        args: [{ type: "buffer_ptr", buffer: "car" }],
        returns: { type: "struct", size: 16, buffer: "car" },
        variadic: false,
      },
      buffers,
    );
    const layout = outLayout(p, buffers);
    // counter stored = 5 * 3 = 15
    const out = decodeOutcome(p, raw({ out: { car: ["0000a0410f0000000100feff0300ffff"] } }), 0, layout);
    expect(out.ret).toBeNull();
    expect(out.fields).toEqual({
      "car.speed": ["0x41a00000"],
      "car.counter": ["0x5"],
      "car.xs": [["0x1", "0xfffe", "0x3", "0xffff"]],
    });
    expect(typedField("i16[]", out.fields["car.xs"]?.[0] as readonly `0x${string}`[])).toEqual([
      { type: "i16", bits: "0x1", value: 1 },
      { type: "i16", bits: "0xfffe", value: -2 },
      { type: "i16", bits: "0x3", value: 3 },
      { type: "i16", bits: "0xffff", value: -1 },
    ]);
  });

  it("builds the bytes of a struct returned in RAX for its named buffer's fields", () => {
    const buffers: BufferInput[] = [
      {
        name: "pair",
        size: 8,
        align: 8,
        placement: "scratch",
        fields: [
          { name: "a", offset: 0, type: "i32" },
          { name: "b", offset: 4, type: "f32" },
        ],
        out: false,
      },
    ];
    const p = plan({ args: [], returns: { type: "struct", size: 8, buffer: "pair" }, variadic: false }, buffers);
    const out = decodeOutcome(p, raw({ rax: ["0x3f800000fffffffe"] }), 0, outLayout(p, buffers));
    expect(out.ret).toEqual(["0x3f800000fffffffe"]);
    expect(out.fields).toEqual({ "pair.a": ["0xfffffffe"], "pair.b": ["0x3f800000"] });
  });
});
