import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  codecDecode,
  codecEncode,
  codecKeyProblem,
  mulInverse,
  type CodecKind,
  type CodecWidth,
} from "../../../../src/domain/callModel/codecs.js";
import {
  extendTo64,
  f32FromBits,
  f32ToBits,
  f64ToBits,
  floatDisplay,
  hexOf,
  isNaNBits,
  ulpDistance,
} from "../../../../src/domain/callModel/floatBits.js";

describe("float bits (S5 §7.2, S6 §2.3)", () => {
  it("round-trips f32/f64 bits and keeps -0 apart from +0", () => {
    expect(hexOf(f32ToBits(1.5))).toBe("0x3fc00000");
    expect(hexOf(f32ToBits(-0))).toBe("0x80000000");
    expect(hexOf(f64ToBits(2.25))).toBe("0x4002000000000000");
    expect(f32FromBits(0x449a4000n)).toBe(1234);
    expect(Object.is(f32FromBits(0x80000000n), -0)).toBe(true);
  });

  it("spells the values JSON cannot carry and prints shortest round-trip f32 numbers", () => {
    expect(floatDisplay("f32", 0x7fc12345n)).toBe("NaN");
    expect(floatDisplay("f32", 0x7f800000n)).toBe("Infinity");
    expect(floatDisplay("f64", 0xfff0000000000000n)).toBe("-Infinity");
    expect(floatDisplay("f32", 0x80000000n)).toBe("-0");
    expect(floatDisplay("f32", f32ToBits(0.1))).toBe(0.1);
    expect(floatDisplay("f32", 0x7f7fffffn)).toBe(3.4028235e38);
    expect(Math.fround(3.4028235e38)).toBe(f32FromBits(0x7f7fffffn));
    expect(floatDisplay("f64", f64ToBits(0.1))).toBe(0.1);
  });

  it("classifies NaN bit patterns, including signalling and negative NaNs", () => {
    expect(isNaNBits("f32", 0x7fa00001n)).toBe(true);
    expect(isNaNBits("f32", 0xffc00000n)).toBe(true);
    expect(isNaNBits("f32", 0x7f800000n)).toBe(false);
    expect(isNaNBits("f64", 0x7ff4000000000000n)).toBe(true);
    expect(isNaNBits("f64", 0x7ff0000000000000n)).toBe(false);
  });

  it("measures ulp distance across zero and refuses NaNs", () => {
    expect(ulpDistance("f32", 0x3f800000n, 0x3f800001n)).toBe(1n);
    expect(ulpDistance("f32", 0x80000000n, 0x0n)).toBe(0n);
    expect(ulpDistance("f32", 0x80000001n, 0x1n)).toBe(2n);
    expect(ulpDistance("f64", 0x7ff8000000000000n, 0x0n)).toBeNull();
  });

  it("sign-extends signed lanes and zero-extends the rest", () => {
    expect(hexOf(extendTo64("i8", 0xffn))).toBe("0xffffffffffffffff");
    expect(hexOf(extendTo64("u8", 0xffn))).toBe("0xff");
    expect(hexOf(extendTo64("i32", 0x80000000n))).toBe("0xffffffff80000000");
    expect(hexOf(extendTo64("f32", 0xbf800000n))).toBe("0xbf800000");
  });
});

describe("codecs (S5 §7.2)", () => {
  it("inverts odd multiplicative keys mod 2^w by Newton iteration", () => {
    expect((3n * mulInverse(3n, 4)) & 0xffffffffn).toBe(1n);
    expect((0x9e3779b97f4a7c15n * mulInverse(0x9e3779b97f4a7c15n, 8)) & 0xffffffffffffffffn).toBe(1n);
    expect(() => mulInverse(4n, 4)).toThrow(RangeError);
  });

  it("reports unusable keys with a corrective message", () => {
    expect(codecKeyProblem("mul", 2n, 4)).toMatch(/odd/u);
    expect(codecKeyProblem("xor", 0x1_0000n, 2)).toMatch(/16-bit/u);
    expect(codecKeyProblem("add", 0xffffn, 2)).toBeNull();
  });

  it("decode(encode(v)) == v for every kind, width and (odd) key", () => {
    const widths: readonly CodecWidth[] = [1, 2, 4, 8];
    fc.assert(
      fc.property(
        fc.constantFrom<CodecKind>("xor", "add", "mul"),
        fc.constantFrom(...widths),
        fc.bigInt({ min: 0n, max: (1n << 64n) - 1n }),
        fc.bigInt({ min: 0n, max: (1n << 64n) - 1n }),
        (kind, width, rawKey, rawValue) => {
          const mask = (1n << BigInt(width * 8)) - 1n;
          const key = kind === "mul" ? (rawKey & mask) | 1n : rawKey & mask;
          const value = rawValue & mask;
          const stored = codecEncode(kind, key, value, width);
          expect(stored >= 0n && stored <= mask).toBe(true);
          expect(codecDecode(kind, key, stored, width)).toBe(value);
        },
      ),
      { numRuns: 2000, seed: 0x5eed },
    );
  });

  it("maps a logical value to the stored value with the key as multiplier (the user's harness convention)", () => {
    expect(codecEncode("mul", 3n, 5n, 1)).toBe(15n);
    expect(codecEncode("add", 0xffn, 2n, 1)).toBe(1n);
    expect(codecDecode("mul", 3n, 15n, 1)).toBe(5n);
  });
});
