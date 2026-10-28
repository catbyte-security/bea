// WP3-AGENT unit tests: encoding helpers of the agent core (src/agent/pure/coreHex.ts, coreScalar.ts) — canonical hex,
// exact float bits (NaN payloads, -0), ScalarInput → bits per type (D-INT-9: "0x…" is always the raw bit pattern),
// TypedOut / ValueCell projections.
import { fc, test as fcTest } from "@fast-check/vitest";
import { describe, expect, it } from "vitest";

import {
  bytesHex,
  f32Bits,
  f32FromBits,
  f64Bits,
  f64FromBits,
  floatViewOfBits,
  hexBytesToArray,
  hexOfBigint,
  hexOfNumber,
  hexOfU32,
  parseHexText,
  readLeBigint,
  readLeU16,
  readLeU32,
  u64FromLanes,
  xmmHex,
} from "../../../../src/agent/pure/coreHex.js";
import {
  bitsFromBytes,
  bytesFromBits,
  cellOfBits,
  isFloatType,
  isStringType,
  scalarBits,
  signExtend,
  typedOutOfBits,
  VALUE_TYPE_BYTES,
} from "../../../../src/agent/pure/coreScalar.js";
import type { ValueType } from "../../../../src/shared/agentProtocol.js";

describe("coreHex", () => {
  it("formats canonical hex (lowercase, no leading zeros, two's complement for negatives)", () => {
    expect(hexOfNumber(0)).toBe("0x0");
    expect(hexOfNumber(0x17a0)).toBe("0x17a0");
    expect(() => hexOfNumber(-1)).toThrow(RangeError);
    expect(() => hexOfNumber(1.5)).toThrow(RangeError);
    expect(hexOfBigint(-1n)).toBe("0xffffffffffffffff");
    expect(hexOfBigint(1n << 64n)).toBe("0x0");
    expect(hexOfU32(-1)).toBe("0xffffffff");
    expect(hexOfU32(0xc0000005)).toBe("0xc0000005");
  });

  it("round-trips byte strings and little-endian integers", () => {
    const b = new Uint8Array([0x4d, 0x5a, 0x90, 0x00, 0xff]);
    expect(bytesHex(b)).toBe("4d5a9000ff");
    expect(bytesHex(b, 1, 2)).toBe("5a90");
    expect(bytesHex(b, 3, 99)).toBe("00ff");
    expect([...hexBytesToArray("4d5A90")]).toEqual([0x4d, 0x5a, 0x90]);
    expect(() => hexBytesToArray("abc")).toThrow(RangeError);
    expect(() => hexBytesToArray("zz")).toThrow(RangeError);
    expect(readLeU16(b, 0)).toBe(0x5a4d);
    expect(readLeU32(b, 1)).toBe(0xff00905a);
    expect(readLeBigint(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 0x80]), 0, 8)).toBe(0x8007060504030201n);
    expect(readLeU32(b, 4)).toBe(0xff); // past the end reads zero
    expect(u64FromLanes(0xdeadbeef, 0x01234567)).toBe(0x01234567deadbeefn);
  });

  it("keeps floats as exact bits (NaN payloads, -0, denormals)", () => {
    expect(f32Bits(1)).toBe(0x3f800000);
    expect(f32FromBits(0x41a00000)).toBe(20);
    expect(Object.is(f32FromBits(0x80000000), -0)).toBe(true);
    expect(f32FromBits(0x00000001)).toBeGreaterThan(0);
    expect(f64Bits(1)).toBe(0x3ff0000000000000n);
    expect(f64FromBits(0x4034000000000000n)).toBe(20);
    // specials are classified from the bits (Frida's QJS has no infinities and NaN === x is true there)
    expect(floatViewOfBits("f32", 0x7fc00001n)).toBe("NaN");
    expect(floatViewOfBits("f32", 0xff800001n)).toBe("NaN");
    expect(floatViewOfBits("f32", 0x7f800000n)).toBe("Infinity");
    expect(floatViewOfBits("f32", 0xff800000n)).toBe("-Infinity");
    expect(floatViewOfBits("f32", 0x7f7fffffn)).toBe(f32FromBits(0x7f7fffff));
    expect(floatViewOfBits("f32", 0x3fc00000n)).toBe(1.5);
    expect(floatViewOfBits("f64", 0x7ff0000000000000n)).toBe("Infinity");
    expect(floatViewOfBits("f64", 0xfff0000000000000n)).toBe("-Infinity");
    expect(floatViewOfBits("f64", 0x7ff0000000000001n)).toBe("NaN");
    expect(floatViewOfBits("f64", 0x7fefffffffffffffn)).toBe(Number.MAX_VALUE);
    expect(Object.is(floatViewOfBits("f64", 0x8000000000000000n), -0)).toBe(true);
  });

  it("renders xmm registers as fixed 32-digit hex, high qword first", () => {
    const x = new Uint8Array(16);
    x[0] = 0x00;
    x[1] = 0x00;
    x[2] = 0x80;
    x[3] = 0x3f;
    x[15] = 0x12;
    expect(xmmHex(x)).toBe("0x1200000000000000000000003f800000");
  });

  it("parses hex inputs (any case, 1..16 digits) only", () => {
    expect(parseHexText("0X1F")).toBe(0x1fn);
    expect(parseHexText("0x0000000000000001")).toBe(1n);
    expect(parseHexText("0x")).toBeNull();
    expect(parseHexText("0x10000000000000000")).toBeNull();
    expect(parseHexText("12")).toBeNull();
  });

  fcTest.prop([fc.bigInt({ min: 0n, max: (1n << 64n) - 1n })])("hexOfBigint round-trips through parseHexText", (v) => {
    expect(parseHexText(hexOfBigint(v))).toBe(v);
  });
});

describe("coreScalar", () => {
  it("knows type widths and classes", () => {
    expect(VALUE_TYPE_BYTES.bool32).toBe(4);
    expect(VALUE_TYPE_BYTES.utf16).toBeNull();
    expect(isStringType("ansi")).toBe(true);
    expect(isStringType("bytes")).toBe(false);
    expect(isFloatType("f64")).toBe(true);
  });

  it("converts integers exactly with range checks", () => {
    expect(scalarBits(-1, "i8")).toEqual({ ok: true, bits: 0xffn });
    expect(scalarBits(127, "i8")).toEqual({ ok: true, bits: 0x7fn });
    expect(scalarBits(128, "i8")).toMatchObject({ ok: false });
    expect(scalarBits(-1, "u8")).toMatchObject({ ok: false });
    expect(scalarBits("18446744073709551615", "u64")).toEqual({ ok: true, bits: (1n << 64n) - 1n });
    expect(scalarBits("-9223372036854775808", "i64")).toEqual({ ok: true, bits: 1n << 63n });
    expect(scalarBits(2 ** 53, "u64")).toMatchObject({ ok: false }); // not a safe integer: use a string
    expect(scalarBits(1.5, "i32")).toMatchObject({ ok: false });
    expect(scalarBits("12x", "i32")).toMatchObject({ ok: false });
    expect(scalarBits(true, "bool32")).toEqual({ ok: true, bits: 1n });
  });

  it("treats 0x… text and {bits} as the raw bit pattern of the declared type", () => {
    expect(scalarBits("0x3f800000", "f32")).toEqual({ ok: true, bits: 0x3f800000n });
    expect(scalarBits({ bits: "0x7ff8000000000001" }, "f64")).toEqual({ ok: true, bits: 0x7ff8000000000001n });
    expect(scalarBits("0xff", "i8")).toEqual({ ok: true, bits: 0xffn });
    expect(scalarBits("0x100", "u8")).toMatchObject({ ok: false });
    expect(scalarBits({ bits: "0xnope" }, "u32")).toMatchObject({ ok: false });
    expect(scalarBits("x", "utf8")).toMatchObject({ ok: false });
  });

  it("rounds float numbers like Math.fround and accepts decimal text", () => {
    expect(scalarBits(0.1, "f32")).toEqual({ ok: true, bits: BigInt(f32Bits(Math.fround(0.1))) });
    expect(scalarBits("20", "f32")).toEqual({ ok: true, bits: 0x41a00000n });
    expect(scalarBits("-0", "f64")).toEqual({ ok: true, bits: 0x8000000000000000n });
    expect(scalarBits("NaN", "f64")).toEqual({ ok: true, bits: 0x7ff8000000000000n });
    // the special words map to canonical bits without going through a JS number (QJS rule, WP10)
    expect(scalarBits("nan", "f32")).toEqual({ ok: true, bits: 0x7fc00000n });
    expect(scalarBits("Infinity", "f32")).toEqual({ ok: true, bits: 0x7f800000n });
    expect(scalarBits("-Infinity", "f32")).toEqual({ ok: true, bits: 0xff800000n });
    expect(scalarBits("inf", "f64")).toEqual({ ok: true, bits: 0x7ff0000000000000n });
    expect(scalarBits("-inf", "f64")).toEqual({ ok: true, bits: 0xfff0000000000000n });
    expect(scalarBits("speed", "f32")).toMatchObject({ ok: false });
  });

  it("projects bits to TypedOut and ValueCell", () => {
    expect(typedOutOfBits("i16", 0xffffn)).toEqual({ type: "i16", value: -1 });
    expect(typedOutOfBits("u64", (1n << 64n) - 1n)).toEqual({
      type: "u64",
      value: "18446744073709551615",
      bits: "0xffffffffffffffff",
    });
    expect(typedOutOfBits("i64", 1n << 63n)).toMatchObject({ value: "-9223372036854775808" });
    expect(typedOutOfBits("ptr", 0x7ff6n)).toEqual({ type: "ptr", value: "0x7ff6", bits: "0x7ff6" });
    expect(typedOutOfBits("f32", 0x41a00000n)).toEqual({ type: "f32", value: 20, bits: "0x41a00000" });
    expect(typedOutOfBits("f32", 0x7fc00000n)).toMatchObject({ value: "NaN", bits: "0x7fc00000" });
    expect(typedOutOfBits("bool8", 2n)).toEqual({ type: "bool8", value: true });
    expect(cellOfBits("i32", 0xffffffffn)).toBe(-1);
    expect(cellOfBits("u16", 0x1234n)).toBe(0x1234);
    expect(cellOfBits("bool32", 7n)).toBe(1);
    expect(cellOfBits("f64", 0x4034000000000000n)).toBe("0x4034000000000000");
    expect(cellOfBits("ptr", 0n)).toBe("0x0");
    expect(signExtend(0x80n, 1)).toBe(-128n);
  });

  const scalarTypes: ValueType[] = ["i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "ptr", "f32", "f64"];
  fcTest.prop([fc.constantFrom(...scalarTypes), fc.bigInt({ min: 0n, max: (1n << 64n) - 1n })])(
    "bytesFromBits / bitsFromBytes round-trip the type's width",
    (t, v) => {
      const width = VALUE_TYPE_BYTES[t]!;
      const masked = v & ((1n << BigInt(width * 8)) - 1n);
      expect(bitsFromBytes(bytesFromBits(t, masked), 0, t)).toBe(masked);
    },
  );
});
