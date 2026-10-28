import { describe, expect, it } from "vitest";

import {
  decodeValue,
  floatClass,
  floatOrder,
  parseNumericOperand,
  parsePattern,
  readFloat,
  shortestF32,
  utf16Decode,
  utf16Encode,
  utf8Decode,
  utf8Encode,
} from "../../../src/agent/pure/scanValue.js";

/** WP10-SCAN: comparand parsing and value decoding (S6 §2.3, S4 §9.2 "Value encoding"). */
const hex = (b: Uint8Array): string => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

describe("parseNumericOperand", () => {
  it("encodes integers little-endian and sign-extends the operand bits", () => {
    const v = parseNumericOperand("i16", -2);
    expect(v.ok && hex(v.value.bytes)).toBe("feff");
    expect(v.ok && v.value.bits).toEqual({ lo: 0xffff_fffe, hi: 0xffff_ffff });
    const u = parseNumericOperand("u32", "4294967295");
    expect(u.ok && u.value.bits).toEqual({ lo: 0xffff_ffff, hi: 0 });
  });

  it("reads 0x… as the raw bits of the declared width (two's complement for signed types)", () => {
    const v = parseNumericOperand("i8", "0xff");
    expect(v.ok && v.value.bits).toEqual({ lo: 0xffff_ffff, hi: 0xffff_ffff });
    expect(parseNumericOperand("u8", "0x100").ok).toBe(false);
    const big = parseNumericOperand("u64", "0xffffffffffffffff");
    expect(big.ok && big.value.bits).toEqual({ lo: 0xffff_ffff, hi: 0xffff_ffff });
  });

  it("refuses out-of-range and unsafe integers with a reason", () => {
    for (const [vt, value] of [
      ["i8", 128],
      ["u8", -1],
      ["i32", 2 ** 31],
      ["u16", 1.5],
      ["i64", 2 ** 60],
      ["u32", "12abc"],
    ] as const) {
      const r = parseNumericOperand(vt, value);
      expect(r.ok, `${vt} ${String(value)}`).toBe(false);
      if (!r.ok) expect(r.problem).toMatch(/range|integer|number/u);
    }
  });

  it("floats: numbers, specials and exact bits", () => {
    const twenty = parseNumericOperand("f32", 20);
    expect(twenty.ok && twenty.value.bits).toEqual({ lo: 0x41a0_0000, hi: 0 });
    expect(twenty.ok && twenty.value.exactBits).toBe(false);
    const bits = parseNumericOperand("f32", "0x7fc00001");
    expect(bits.ok && bits.value).toMatchObject({ exactBits: true, nan: true });
    const obj = parseNumericOperand("f64", { bits: "0x8000000000000000" });
    expect(obj.ok && obj.value).toMatchObject({ exactBits: true, zero: true });
    expect(parseNumericOperand("f64", "-Infinity").ok).toBe(true);
    expect(parseNumericOperand("f32", "0x123456789").ok).toBe(false);
    expect(parseNumericOperand("f32", true).ok).toBe(false);
  });
});

describe("parsePattern", () => {
  it("accepts the verified Frida forms and reports the element size", () => {
    const exact = parsePattern("48 8B 05");
    expect(exact.ok && exact.value).toMatchObject({ elem: 3, pattern: "48 8b 05" });
    expect(exact.ok && hex(exact.value.exact ?? new Uint8Array())).toBe("488b05");
    const wild = parsePattern("48 ?? 4?");
    expect(wild.ok && wild.value).toMatchObject({ elem: 3, exact: null });
    const masked = parsePattern("40 45 : f0 ff");
    expect(masked.ok && masked.value).toMatchObject({ elem: 2, exact: null });
  });

  it("refuses regexes, bad tokens, wildcard-only patterns and mismatched masks", () => {
    for (const bad of ["/BEA_v\\d/", "4g 00", "", "?? ??", "40 45 : f0", "40 : 00 : 00"])
      expect(parsePattern(bad).ok, bad).toBe(false);
  });
});

describe("text encodings", () => {
  it("round-trips UTF-8 and UTF-16LE without TextEncoder", () => {
    for (const text of ["BEA_GAME_SIM_MARKER_v1", "ünïcødé", "𝔅𝔈𝔄", ""]) {
      expect(utf8Decode(utf8Encode(text))).toBe(text);
      expect(utf16Decode(utf16Encode(text))).toBe(text);
    }
    expect(hex(utf8Encode("é"))).toBe("c3a9");
    expect(Buffer.from(utf8Encode("𝔅")).toString("utf8")).toBe("𝔅");
    expect(utf8Decode(Uint8Array.from([0x41, 0xff, 0x42, 0xe2, 0x82]))).toBe("A�B��");
  });
});

describe("decodeValue", () => {
  const le = (n: number, bytes: number): Uint8Array => {
    const out = new Uint8Array(bytes);
    new DataView(out.buffer).setUint32(0, n, true);
    return out;
  };

  it("f32: shortest round-trip number plus exact bits", () => {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setFloat32(0, 14.905, true);
    expect(decodeValue("f32", b)).toEqual({ type: "f32", value: 14.905, bits: "0x416e7ae1" });
    expect(shortestF32(Math.fround(0.1))).toBe(0.1);
    expect(decodeValue("f32", le(0x7fc0_0000, 4))).toMatchObject({ value: "NaN", bits: "0x7fc00000" });
    expect(decodeValue("f32", le(0xff80_0000, 4))).toMatchObject({ value: "-Infinity" });
  });

  it("64-bit integers as decimal strings, pointers as hex, small ints as numbers", () => {
    const minus1 = new Uint8Array(8).fill(0xff);
    expect(decodeValue("i64", minus1)).toMatchObject({ value: "-1", bits: "0xffffffffffffffff" });
    expect(decodeValue("u64", minus1)).toMatchObject({ value: "18446744073709551615" });
    expect(decodeValue("ptr", Uint8Array.from([0x10, 0x20, 0, 0, 0, 0, 0, 0]))).toEqual({
      type: "ptr",
      value: "0x2010",
    });
    expect(decodeValue("i16", Uint8Array.from([0xfe, 0xff]))).toEqual({ type: "i16", value: -2 });
  });

  it("byte strings carry hex; text types also decode the text", () => {
    expect(decodeValue("bytes", Uint8Array.from([0xde, 0xad]))).toEqual({ type: "bytes", value: null, hex: "dead" });
    expect(decodeValue("utf16", utf16Encode("Hi"))).toEqual({ type: "utf16", value: "Hi", hex: "48006900" });
  });
});

/*
 * Frida 17.23.2's QJS on Windows has no infinities (±Infinity is the canonical NaN, NaN === x is true), so float
 * specials are decided from bits. Node has real infinities; these cases pin the bit logic itself. The QJS behavior is
 * covered in the target by tests/acceptance/scan/scanAgentRaw.test.ts ("float specials in the target's QJS").
 */
describe("float specials from bits", () => {
  const f32 = (bits: number): Uint8Array => {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, bits, true);
    return b;
  };
  const f64 = (hi: number, lo = 0): Uint8Array => {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setUint32(0, lo, true);
    new DataView(b.buffer).setUint32(4, hi, true);
    return b;
  };

  it("classifies ±Inf, NaN payloads, ±0 and denormals of both widths", () => {
    expect(floatClass(false, { lo: 0x7f80_0000, hi: 0 })).toBe("+inf");
    expect(floatClass(false, { lo: 0xff80_0000, hi: 0 })).toBe("-inf");
    expect(floatClass(false, { lo: 0x7f80_0001, hi: 0 })).toBe("nan");
    expect(floatClass(false, { lo: 0xffc0_0000, hi: 0 })).toBe("nan");
    expect(floatClass(false, { lo: 0x8000_0000, hi: 0 })).toBe("finite");
    expect(floatClass(false, { lo: 0x0000_0001, hi: 0 })).toBe("finite");
    expect(floatClass(true, { lo: 0, hi: 0x7ff0_0000 })).toBe("+inf");
    expect(floatClass(true, { lo: 0, hi: 0xfff0_0000 })).toBe("-inf");
    expect(floatClass(true, { lo: 1, hi: 0x7ff0_0000 })).toBe("nan");
    expect(floatClass(true, { lo: 0, hi: 0x7fef_ffff })).toBe("finite");
  });

  it("decodes specials to the S6 §2.3 words with exact bits, finite values as numbers", () => {
    expect(decodeValue("f32", f32(0x41a0_0000))).toEqual({ type: "f32", value: 20, bits: "0x41a00000" });
    expect(decodeValue("f32", f32(0x7f80_0000)).value).toBe("Infinity");
    expect(decodeValue("f32", f32(0xff80_0000)).value).toBe("-Infinity");
    expect(decodeValue("f32", f32(0x7fc0_0001))).toEqual({ type: "f32", value: "NaN", bits: "0x7fc00001" });
    expect(decodeValue("f64", f64(0x7ff0_0000)).value).toBe("Infinity");
    expect(decodeValue("f64", f64(0xfff0_0000)).value).toBe("-Infinity");
    expect(decodeValue("f64", f64(0x7ff8_0000)).value).toBe("NaN");
    expect(decodeValue("f64", f64(0x4034_0000)).value).toBe(20);
  });

  it("encodes the words as canonical bits, compared as values (not bit for bit)", () => {
    const bits = (vt: "f32" | "f64", w: string) => {
      const v = parseNumericOperand(vt, w);
      return v.ok ? { ...v.value.bits, exactBits: v.value.exactBits, nan: v.value.nan, zero: v.value.zero } : null;
    };
    expect(bits("f32", "Infinity")).toEqual({ lo: 0x7f80_0000, hi: 0, exactBits: false, nan: false, zero: false });
    expect(bits("f32", "-Infinity")).toMatchObject({ lo: 0xff80_0000, hi: 0, nan: false });
    expect(bits("f32", "NaN")).toMatchObject({ lo: 0x7fc0_0000, nan: true });
    expect(bits("f64", "Infinity")).toMatchObject({ lo: 0, hi: 0x7ff0_0000, nan: false });
    expect(bits("f64", "-Infinity")).toMatchObject({ lo: 0, hi: 0xfff0_0000 });
    expect(bits("f64", "NaN")).toMatchObject({ lo: 0, hi: 0x7ff8_0000, nan: true });
    expect(bits("f32", "0x80000000")).toMatchObject({ exactBits: true, zero: true, nan: false });
    expect(bits("f32", "0x7f800000")).toMatchObject({ exactBits: true, zero: false, nan: false });
  });

  it("orders by IEEE rules: NaN unordered, ±Inf at the ends, -0 equal to +0", () => {
    const r = (bits: number) => readFloat(false, f32(bits));
    const [ninf, neg, nzero, zero, twenty, inf, nan] = [
      0xff80_0000, 0xc000_0000, 0x8000_0000, 0, 0x41a0_0000, 0x7f80_0000, 0x7fc0_0000,
    ].map(r);
    expect(floatOrder(ninf!, neg!)).toBe(-1);
    expect(floatOrder(inf!, twenty!)).toBe(1);
    expect(floatOrder(inf!, inf!)).toBe(0);
    expect(floatOrder(ninf!, inf!)).toBe(-1);
    expect(floatOrder(nzero!, zero!)).toBe(0);
    expect(floatOrder(twenty!, neg!)).toBe(1);
    expect(floatOrder(nan!, nan!)).toBeNull();
    expect(floatOrder(twenty!, nan!)).toBeNull();
  });
});
