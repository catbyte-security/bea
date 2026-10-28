import { describe, expect, it } from "vitest";

import {
  classifyWin64,
  planAddressExprs,
  planToWire,
  type ClassifyInput,
} from "../../../../src/domain/callModel/classify.js";
import { bytesToHex } from "../../../../src/shared/hex.js";
import type { BufferInput, SignatureInput } from "../../../../src/domain/callModel/normalize.js";

const buf = (name: string, size: number, extra: Partial<BufferInput> = {}): BufferInput => ({
  name,
  size,
  align: 16,
  placement: "scratch",
  fields: [],
  out: false,
  ...extra,
});

const classify = (
  signature: SignatureInput,
  buffers: readonly BufferInput[] = [],
  supplied: readonly string[] = [],
  extra: Partial<ClassifyInput> = {},
) => classifyWin64({ signature, buffers, supplied: new Set(supplied), ...extra });

const regs = (r: ReturnType<typeof classify>) =>
  r.ok
    ? r.value.plan.slots.map(
        (s) =>
          `${s.reg}${s.stackIndex === undefined ? "" : `:${String(s.stackIndex)}`}${s.dupGpr === undefined ? "" : `+${s.dupGpr}`}`,
      )
    : r.error;

describe("classifyWin64: positional Win64 classification (S5 §7.4)", () => {
  it("four floats go to xmm0..xmm3", () => {
    const r = classify({
      args: [{ type: "f32" }, { type: "f32" }, { type: "f32" }, { type: "f32" }],
      returns: "f32",
      variadic: false,
    });
    expect(regs(r)).toEqual(["xmm0", "xmm1", "xmm2", "xmm3"]);
    expect(r.ok && r.value.plan.returns).toEqual({ kind: "f32" });
  });

  it("mix_args(int, float, double, float, int, double): registers by POSITION, then stack slots 0 and 1", () => {
    const r = classify({
      args: [{ type: "i32" }, { type: "f32" }, { type: "f64" }, { type: "f32" }, { type: "i32" }, { type: "f64" }],
      returns: "f64",
      variadic: false,
    });
    expect(regs(r)).toEqual(["rcx", "xmm1", "xmm2", "xmm3", "stack:0", "stack:1"]);
  });

  it("a struct return of 12 bytes is a hidden pointer at position 0 and shifts the declared args", () => {
    const r = classify({
      args: [{ type: "f32" }, { type: "ptr" }],
      returns: { type: "struct", size: 12 },
      variadic: false,
    });
    expect(regs(r)).toEqual(["rcx", "xmm1", "r8"]);
    if (!r.ok) return;
    expect(r.value.plan.slots[0]?.source).toEqual({ kind: "buffer", buffer: "__ret", offset: 0 });
    expect(r.value.plan.returns).toEqual({ kind: "struct", size: 12, via: "hidden", buffer: "__ret" });
    expect(r.value.plan.buffers.find((b) => b.name === "__ret")).toMatchObject({ size: 12, out: true });
  });

  it("an MSVC instance method keeps this in RCX, passes the hidden pointer in RDX, and returns every struct through it (EMU-13)", () => {
    const vel = classify(
      {
        args: [{ type: "ptr", name: "self" }],
        returns: { type: "struct", size: 12 },
        variadic: false,
        convention: "msvc_method",
      },
      [],
      ["self"],
    );
    expect(regs(vel)).toEqual(["rcx", "rdx"]);
    if (!vel.ok) return;
    expect(vel.value.plan.slots[0]?.source).toMatchObject({ kind: "column", column: "self" });
    expect(vel.value.plan.slots[1]?.source).toEqual({ kind: "buffer", buffer: "__ret", offset: 0 });
    // an 8-byte UDT is ALSO returned indirectly by an MSVC method (never in RAX)
    const small = classify({
      args: [{ type: "ptr", name: "self" }, { type: "f32" }],
      returns: { type: "struct", size: 8 },
      variadic: false,
      convention: "msvc_method",
    });
    expect(regs(small)).toEqual(["rcx", "rdx", "xmm2"]);
    expect(small.ok && small.value.plan.returns).toEqual({ kind: "struct", size: 8, via: "hidden", buffer: "__ret" });
    // the C convention (free functions, GCC methods) is unchanged: hidden pointer first
    const c = classify({
      args: [{ type: "ptr", name: "self" }],
      returns: { type: "struct", size: 12 },
      variadic: false,
    });
    expect(regs(c)).toEqual(["rcx", "rdx"]);
    expect(c.ok && c.value.plan.slots[0]?.source).toEqual({ kind: "buffer", buffer: "__ret", offset: 0 });
    // a method without `this` is an input error
    expect(classify({ args: [], returns: "i32", variadic: false, convention: "msvc_method" }).ok).toBe(false);
  });

  it("a struct return of 1/2/4/8 bytes comes back in RAX (no hidden pointer)", () => {
    const r = classify({ args: [{ type: "i32" }], returns: { type: "struct", size: 8 }, variadic: false });
    expect(regs(r)).toEqual(["rcx"]);
    expect(r.ok && r.value.plan.returns).toEqual({ kind: "struct", size: 8, via: "rax", buffer: "__ret" });
  });

  it("variadic floats in register positions are duplicated into the GPR", () => {
    const r = classify({
      args: [{ type: "ptr" }, { type: "f64" }, { type: "f32" }, { type: "f64" }, { type: "f64" }],
      returns: "i32",
      variadic: true,
    });
    expect(regs(r)).toEqual(["rcx", "xmm1+rdx", "xmm2+r8", "xmm3+r9", "stack:0"]);
  });

  it("byval buffers of 1/2/4/8 bytes travel as integers; larger ones as a pointer to a hidden copy", () => {
    const r = classify(
      {
        args: [
          { type: "buffer_byval", buffer: "small" },
          { type: "buffer_byval", buffer: "big" },
        ],
        returns: "void",
        variadic: false,
      },
      [buf("small", 8, { init_hex: "0102030405060708" }), buf("big", 12, { init_fill: 0xaa })],
    );
    expect(regs(r)).toEqual(["rcx", "rdx"]);
    if (!r.ok) return;
    expect(r.value.plan.slots.map((s) => s.source)).toEqual([
      { kind: "byval", buffer: "small" },
      { kind: "buffer", buffer: "__byval_1", offset: 0 },
    ]);
    const copy = r.value.plan.buffers.find((b) => b.name === "__byval_1");
    expect(copy && bytesToHex(copy.template)).toBe("aa".repeat(12));
  });

  it("refuses more than 32 positions (4 registers + 28 stack slots), counting a hidden return pointer", () => {
    const args = Array.from({ length: 32 }, () => ({ type: "i64" as const }));
    expect(classify({ args, returns: "void", variadic: false }).ok).toBe(true);
    const r = classify({ args, returns: { type: "struct", size: 24 }, variadic: false });
    expect(!r.ok && r.error[0]).toMatchObject({ path: "signature.args[31]", reason: "out_of_range" });
  });
});

describe("classifyWin64: columns, constants and buffers", () => {
  const sig: SignatureInput = {
    args: [
      { type: "buffer_ptr", buffer: "car" },
      { type: "f32", name: "dt", default: 0.016 },
      { type: "ptr", default: "kernel32!Sleep" },
    ],
    returns: "f32",
    variadic: false,
  };
  const car = buf("car", 0x20, {
    init_hex: "00002041",
    fields: [
      { name: "speed", offset: 0, type: "f32" },
      { name: "counter", offset: 4, type: "i32", default: "3", codec_kind: "xor", codec_key: "0xff" },
      { name: "pos", offset: 8, type: "f64[]", count: 3, default: "1.0, 0, 4" },
    ],
    out: true,
  });

  it("supplied columns become per-vector columns; defaults become constants (ptr AddrExpr: address-const)", () => {
    const r = classify(sig, [car], ["car.speed", "dt"]);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const { plan } = r.value;
    expect(plan.slots.map((s) => s.source)).toEqual([
      { kind: "buffer", buffer: "car", offset: 0 },
      { kind: "column", column: "dt", type: "f32" },
      { kind: "address-const", expr: "kernel32!Sleep" },
    ]);
    expect(plan.columns).toEqual([
      { name: "car.speed", type: "f32", count: 1 },
      { name: "dt", type: "f32", count: 1 },
    ]);
    expect(planAddressExprs(plan)).toEqual(["kernel32!Sleep"]);
  });

  it("writes non-supplied field defaults into the template, codec applied, over the init bytes", () => {
    const r = classify(sig, [car], ["car.speed"]);
    if (!r.ok) throw new Error(JSON.stringify(r.error));
    const template = bytesToHex(r.value.plan.buffers[0]?.template ?? new Uint8Array());
    // speed stays from init_hex (10.0f), counter = 3 ^ 0xff = 0xfc, pos = [1.0, 0, 4.0]
    expect(template).toBe(
      ["00002041", "fc000000", "000000000000f03f", "0000000000000000", "0000000000001040"].join(""),
    );
    expect(r.value.plan.buffers[0]?.codecs).toEqual([
      { field: "counter", offset: 4, width: 4, kind: "xor", key: 0xffn },
    ]);
  });

  it("keeps a supplied array field's default as the per-element fallback", () => {
    const r = classify(sig, [car], ["car.pos"]);
    if (!r.ok) throw new Error(JSON.stringify(r.error));
    expect(r.value.arrayDefaults.get("car.pos")).toEqual([0x3ff0000000000000n, 0n, 0x4010000000000000n]);
    expect(r.value.plan.buffers[0]?.columns).toEqual([{ column: "car.pos", offset: 8, width: 8, count: 3 }]);
  });

  it("lists the valid columns when a request names an unknown one", () => {
    const r = classify(sig, [car], ["car.sped"]);
    expect(!r.ok && r.error[0]?.message).toBe(
      "Unknown column car.sped; valid columns: arg2, car.counter, car.pos, car.speed, dt.",
    );
  });

  it("resolves ptr_to fields into pointer patches and uses init_from bytes as the template", () => {
    const r = classify(
      { args: [{ type: "buffer_ptr", buffer: "car" }], returns: "void", variadic: false },
      [
        buf("car", 16, {
          init_from: "0x1f3a5c40",
          fields: [{ name: "tyres", offset: 8, type: "ptr_to", buffer: "tyres", plus: 4 }],
        }),
        buf("tyres", 64, { init_fill: 0 }),
      ],
      [],
      { initFrom: new Map([["car", Uint8Array.from({ length: 16 }, (_, i) => i)]]) },
    );
    if (!r.ok) throw new Error(JSON.stringify(r.error));
    expect(r.value.plan.buffers[0]?.ptrFields).toEqual([{ offset: 8, buffer: "tyres", plus: 4 }]);
    expect(bytesToHex(r.value.plan.buffers[0]?.template ?? new Uint8Array())).toBe("000102030405060708090a0b0c0d0e0f");
  });

  it("reports every structural problem at its input path", () => {
    const r = classify(
      {
        args: [{ type: "buffer_ptr", buffer: "nope" }],
        returns: { type: "struct", size: 32, buffer: "small" },
        variadic: false,
      },
      [
        buf("__mine", 8),
        buf("small", 8, {
          fields: [
            { name: "x", offset: 6, type: "i32" },
            { name: "k", offset: 0, type: "i16", codec_kind: "mul", codec_key: "0x2" },
          ],
        }),
        buf("small", 4),
      ],
    );
    expect(!r.ok && r.error.map((i) => i.path)).toEqual([
      "buffers[0].name",
      "buffers[2].name",
      "buffers[1].fields[0].offset",
      "buffers[1].fields[1].codec_key",
      "signature.returns.buffer",
      "signature.args[0].buffer",
    ]);
  });
});

describe("planToWire / planToAgent", () => {
  it("lowers columns, constants, buffers and resolves AddrExpr constants in the leg's address space", () => {
    const r = classifyWin64({
      signature: {
        args: [
          { type: "ptr", default: "kernel32!Sleep" },
          { type: "f32", name: "x" },
          { type: "i8", default: -2 },
        ],
        returns: "i8",
        variadic: false,
      },
      buffers: [],
      supplied: new Set(["x"]),
    });
    if (!r.ok) throw new Error("classification failed");
    const wire = planToWire(r.value.plan, "0x7ff600001000", (expr) =>
      expr === "kernel32!Sleep" ? 0x7ffd12340000n : undefined,
    );
    expect(wire.ok && wire.value).toEqual({
      target: "0x7ff600001000",
      slots: [
        { reg: "rcx", source: { kind: "const", bits: "0x7ffd12340000" } },
        { reg: "xmm1", source: { kind: "column", column: "x" } },
        { reg: "r8", source: { kind: "const", bits: "0xfffffffffffffffe" } },
      ],
      returns: { kind: "int", width: 1 },
      buffers: [],
    });
    const unresolved = planToWire(r.value.plan, "0x1", () => undefined);
    expect(unresolved.ok).toBe(false);
  });
});
