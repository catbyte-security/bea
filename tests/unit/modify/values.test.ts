import { fc, test } from "@fast-check/vitest";
import { describe, expect, it } from "vitest";

import { MODIFY_VALUE_TYPES, type ModifyValueType } from "../../../src/contracts/areas/modify.js";
import {
  agentScalarOfBits,
  agentValueType,
  bytesOfBits,
  floatBits,
  parseScalar,
  TYPE_WIDTH,
} from "../../../src/application/modify/values.js";
import { bitsToBytes, scalarBits, type ScalarValueType } from "../../../src/agent/pure/modifyValues.js";
import { bytesToHex } from "../../../src/shared/hex.js";

const hexOf = (type: ModifyValueType, value: number | string | boolean): string => {
  const parsed = parseScalar(type, value);
  if (parsed.kind !== "bits") throw new Error(`expected bits, got ${JSON.stringify(parsed)}`);
  return bytesToHex(bytesOfBits(type, parsed.bits));
};

describe("host scalar encoding (S6 §2.3)", () => {
  it("encodes floats exactly, little-endian", () => {
    expect(hexOf("f32", 1)).toBe("0000803f");
    expect(hexOf("f32", "20.0")).toBe("0000a041");
    expect(hexOf("f64", 0.5)).toBe("000000000000e03f");
    expect(hexOf("f32", "-0")).toBe("00000080");
    expect(hexOf("f32", "NaN")).toBe("0000c07f");
    expect(hexOf("f64", "-Infinity")).toBe("000000000000f0ff");
  });

  it('reads "0x…" as raw bits of the declared type, never as a value', () => {
    expect(hexOf("f32", "0x7fc00001")).toBe("0100c07f"); // NaN payload kept
    expect(hexOf("i8", "0xff")).toBe("ff");
    expect(hexOf("u16", "0x1234")).toBe("3412");
    const wide = parseScalar("u8", "0x100");
    expect(wide).toMatchObject({ kind: "error", reason: "out_of_range" });
  });

  it("range-checks integers and uses two's complement", () => {
    expect(hexOf("i8", -1)).toBe("ff");
    expect(hexOf("i32", -2)).toBe("feffffff");
    expect(hexOf("u64", "18446744073709551615")).toBe("ffffffffffffffff");
    expect(hexOf("i64", "-9223372036854775808")).toBe("0000000000000080");
    expect(parseScalar("i8", 128)).toMatchObject({ kind: "error", reason: "out_of_range" });
    expect(parseScalar("u32", -1)).toMatchObject({ kind: "error", reason: "out_of_range" });
    expect(parseScalar("i32", 1.5)).toMatchObject({ kind: "error", reason: "invalid_value" });
    expect(parseScalar("u64", 2 ** 60)).toMatchObject({ kind: "error", reason: "out_of_range" });
  });

  it("treats bool as one byte and refuses booleans for other types", () => {
    expect(hexOf("bool", true)).toBe("01");
    expect(hexOf("bool", 0)).toBe("00");
    expect(parseScalar("bool", 2)).toMatchObject({ kind: "error" });
    expect(parseScalar("i32", true)).toMatchObject({ kind: "error", reason: "invalid_value" });
    expect(agentValueType("bool")).toBe("bool8");
  });

  it("hands non-numeric ptr strings to the address resolver", () => {
    expect(parseScalar("ptr", "game_sim.exe!g_world")).toEqual({ kind: "address", expr: "game_sim.exe!g_world" });
    expect(hexOf("ptr", "0x140001000")).toBe("0010004001000000");
    expect(parseScalar("i32", "abc")).toMatchObject({ kind: "error", reason: "invalid_value" });
  });

  it("sends floats to the agent as {bits} and integers as raw hex", () => {
    expect(agentScalarOfBits("f32", floatBits(1, 4))).toEqual({ bits: "0x3f800000" });
    expect(agentScalarOfBits("i32", 0xfffffffen)).toBe("0xfffffffe");
  });
});

/** The host encodes values; the agent decodes the agent ScalarInput; both must land on identical bytes. */
const AGENT_TYPE: { readonly [T in ModifyValueType]: ScalarValueType } = {
  i8: "i8",
  u8: "u8",
  i16: "i16",
  u16: "u16",
  i32: "i32",
  u32: "u32",
  i64: "i64",
  u64: "u64",
  ptr: "ptr",
  bool: "bool8",
  f32: "f32",
  f64: "f64",
};

describe("host and agent agree on every encoded value", () => {
  test.prop([fc.constantFrom(...MODIFY_VALUE_TYPES), fc.bigInt({ min: 0n, max: (1n << 64n) - 1n })])(
    "raw bits survive host -> agent ScalarInput -> agent bytes",
    (type, raw) => {
      const bits = raw & ((1n << BigInt(TYPE_WIDTH[type] * 8)) - 1n);
      const scalar = agentScalarOfBits(type, bits);
      const decoded = scalarBits(AGENT_TYPE[type], scalar);
      expect(decoded.ok).toBe(true);
      if (decoded.ok)
        expect(bytesToHex(bitsToBytes(decoded.bits, TYPE_WIDTH[type]))).toBe(bytesToHex(bytesOfBits(type, bits)));
    },
  );

  test.prop([fc.double({ noNaN: false })])("f64 numbers encode identically on both sides", (value) => {
    const host = parseScalar("f64", value);
    const agent = scalarBits("f64", value);
    expect(host.kind).toBe("bits");
    expect(agent.ok).toBe(true);
    if (host.kind === "bits" && agent.ok) expect(agent.bits).toBe(host.bits);
  });

  test.prop([fc.integer({ min: -(2 ** 31), max: 2 ** 31 - 1 })])("i32 numbers encode identically", (value) => {
    const host = parseScalar("i32", value);
    const agent = scalarBits("i32", value);
    if (host.kind !== "bits" || !agent.ok) throw new Error("both sides must accept an in-range i32");
    expect(agent.bits).toBe(host.bits);
  });
});
