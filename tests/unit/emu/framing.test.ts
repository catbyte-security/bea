import { describe, expect, it } from "vitest";

import {
  encodeFrame,
  FrameTooLarge,
  MAX_FRAME_BYTES,
  NdjsonSplitter,
  nonFiniteNumberPath,
} from "../../../src/providers/emulator/framing.js";

const text = (frames: Buffer[]): string[] => frames.map((f) => f.toString("utf8"));

describe("NdjsonSplitter (S5 §5.1)", () => {
  it("splits frames across chunk boundaries, strips one CR and skips empty lines", () => {
    const splitter = new NdjsonSplitter();
    expect(text(splitter.push(Buffer.from('{"a":1}\n{"b"')))).toEqual(['{"a":1}']);
    expect(text(splitter.push(Buffer.from(':2}\r\n\n\r\n{"c":3}')))).toEqual(['{"b":2}']);
    expect(splitter.pendingBytes).toBe(7);
    expect(text(splitter.push(Buffer.from("\n")))).toEqual(['{"c":3}']);
    expect(splitter.pendingBytes).toBe(0);
  });

  it("never decodes a partial UTF-8 sequence", () => {
    const splitter = new NdjsonSplitter();
    const bytes = Buffer.from('{"s":"Ж€😀"}\n', "utf8");
    const out: Buffer[] = [];
    for (const byte of bytes) out.push(...splitter.push(Buffer.from([byte])));
    expect(text(out)).toEqual(['{"s":"Ж€😀"}']);
  });

  it("refuses a frame larger than 64 MiB", () => {
    const splitter = new NdjsonSplitter();
    expect(() => splitter.push(Buffer.alloc(MAX_FRAME_BYTES + 1, 0x61))).toThrow(FrameTooLarge);
    const complete = new NdjsonSplitter();
    const line = Buffer.alloc(MAX_FRAME_BYTES + 2, 0x61);
    line[line.length - 1] = 0x0a;
    expect(() => complete.push(line)).toThrow(FrameTooLarge);
  });
});

describe("encodeFrame", () => {
  it("writes compact JSON plus LF", () => {
    const encoded = encodeFrame({ id: 7, method: "bridge.ping", params: {} });
    expect(encoded.ok && encoded.bytes.toString("utf8")).toBe('{"id":7,"method":"bridge.ping","params":{}}\n');
  });

  it("refuses non-finite numbers (every float travels as bits)", () => {
    const encoded = encodeFrame({ id: 1, method: "emu.call", params: { options: { list: [1, Number.NaN] } } });
    expect(encoded.ok).toBe(false);
    expect(encoded.ok ? "" : encoded.reason).toContain("$.params.options.list[1]");
    expect(nonFiniteNumberPath({ a: [{ b: Number.POSITIVE_INFINITY }] })).toBe("$.a[0].b");
    expect(nonFiniteNumberPath({ a: [1, "NaN", null, { c: 2 }] })).toBeNull();
  });
});
