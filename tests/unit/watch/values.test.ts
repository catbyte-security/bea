import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { coveringWatch as agentCovering } from "../../../src/agent/pure/dr7.js";
import { pagesOf } from "../../../src/agent/pure/watchPlan.js";
import { WATCH_MARKER_FINAL, WATCH_MARKER_RATE_LIMIT } from "../../../src/application/watch/decoders.js";
import { coveringWatch, isDrSize, pageCount } from "../../../src/application/watch/plan.js";
import {
  decodeElement,
  decodeWatched,
  f32Out,
  insnConfidence,
  numericKey,
  pollElementWidth,
  structBaseOf,
} from "../../../src/application/watch/values.js";

const le = (...bytes: number[]): Uint8Array => new Uint8Array(bytes);

describe("value views (S6 §2.3)", () => {
  it("decodes every view little-endian; 64-bit as decimal strings", () => {
    expect(decodeElement(le(0xff), "i8")).toBe(-1);
    expect(decodeElement(le(0xff), "u8")).toBe(255);
    expect(decodeElement(le(0xfe, 0xff), "i16")).toBe(-2);
    expect(decodeElement(le(0x34, 0x12), "u16")).toBe(0x1234);
    expect(decodeElement(le(0xff, 0xff, 0xff, 0xff), "i32")).toBe(-1);
    expect(decodeElement(le(0xff, 0xff, 0xff, 0xff), "u32")).toBe(4_294_967_295);
    expect(decodeElement(le(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff), "i64")).toBe("-1");
    expect(decodeElement(le(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff), "u64")).toBe("18446744073709551615");
    expect(decodeElement(le(0, 0, 0xa0, 0x41), "f32")).toBe(20);
    expect(decodeElement(le(0, 0, 0, 0, 0, 0, 0xf0, 0x3f), "f64")).toBe(1);
    expect(decodeElement(le(0xde, 0xad), "hex")).toBe("dead");
    expect(decodeElement(le(1, 2), "u32")).toBeNull();
  });

  it("renders floats as the shortest f32 round trip and specials as text", () => {
    expect(f32Out(Math.fround(1 / 60))).toBe(0.016666668);
    expect(Math.fround(f32Out(Math.fround(0.1)) as number)).toBe(Math.fround(0.1));
    expect(f32Out(Number.NaN)).toBe("NaN");
    expect(f32Out(Number.NEGATIVE_INFINITY)).toBe("-Infinity");
    expect(decodeElement(le(0, 0, 0xc0, 0x7f), "f32")).toBe("NaN");
  });

  it("decodes a watched value by view, else as hex", () => {
    expect(decodeWatched("0000a041", "f32")).toBe(20);
    expect(decodeWatched("0000a0410000a041", "f32")).toBe("0000a0410000a041");
    expect(decodeWatched(null, "f32")).toBeNull();
    expect(decodeWatched("zz", "f32")).toBeNull();
  });

  it("splits poll cells by view (hex uses 4-byte cells when the size allows)", () => {
    expect(pollElementWidth("f64", 64)).toBe(8);
    expect(pollElementWidth("hex", 128)).toBe(4);
    expect(pollElementWidth("hex", 6)).toBe(1);
  });

  it("orders numeric views for min/max", () => {
    expect(numericKey(3, "i32")).toBe(3);
    expect(numericKey("18446744073709551615", "u64")).toBe(18_446_744_073_709_551_615n);
    expect(numericKey("ff", "hex")).toBeNull();
    expect(numericKey("NaN", "f32")).toBeNull();
  });
});

describe("instructions and struct bases (S6 §4.22, CI-M12)", () => {
  it("maps agent confidence to tool confidence", () => {
    expect(insnConfidence("exact")).toBe("exact");
    expect(insnConfidence("swept")).toBe("exact");
    expect(insnConfidence("heuristic")).toBe("recovered");
    expect(insnConfidence("unknown")).toBe("ambiguous");
  });

  it("takes the struct base from the base register unless it is RIP or was overwritten after the access", () => {
    const mem = {
      base: "rax",
      index: null,
      scale: 1 as const,
      disp: 8,
      size: 4,
      base_value: "0x1f3a5c40" as const,
      base_written: false,
    };
    expect(structBaseOf(mem)).toEqual({
      operand: { base: "rax", index: null, scale: 1, disp: 8 },
      struct_base: "0x1f3a5c40",
      disp: "0x8",
    });
    expect(structBaseOf({ ...mem, base_written: true }).struct_base).toBeNull();
    expect(structBaseOf({ ...mem, base: "rip" }).struct_base).toBeNull();
    expect(structBaseOf({ ...mem, disp: -16 }).disp).toBe("-0x10");
    expect(structBaseOf(null)).toEqual({ operand: null, struct_base: null, disp: null });
  });
});

describe("host planning rules match the agent's", () => {
  it("agrees on covering watches and page counts", () => {
    for (const address of [0x1000n, 0x1001n, 0x1002n, 0x1006n, 0x1007n, 0x1ffcn])
      for (const size of [1, 2, 3, 4, 5, 8, 9])
        expect(coveringWatch(address, size), `${address.toString(16)}/${String(size)}`).toEqual(
          agentCovering(address, size),
        );
    for (const [address, size] of [
      [0x1000n, 4],
      [0x1ffen, 4],
      [0x1001n, 65_536],
    ] as const)
      expect(pageCount(address, size)).toBe(pagesOf(address, size).length);
    expect(isDrSize(8)).toBe(true);
    expect(isDrSize(16)).toBe(false);
  });

  it("names the same marker rows as the agent", () => {
    const agent = readFileSync(join(import.meta.dirname, "..", "..", "..", "src", "agent", "watch.ts"), "utf8");
    expect(agent).toContain(`WATCH_MARKER_RATE_LIMIT = "${WATCH_MARKER_RATE_LIMIT}"`);
    expect(agent).toContain(`WATCH_MARKER_FINAL = "${WATCH_MARKER_FINAL}"`);
  });
});
