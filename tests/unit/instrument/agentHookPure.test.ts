import { describe, expect, it } from "vitest";

import {
  bytesOfHex64,
  cellOfWord,
  decodeText,
  estimateBytes,
  frameRefText,
  hexBytes,
  hexLE,
  scalarCell,
  arrayCell,
  textReadBytes,
} from "../../../src/agent/pure/hookCells.js";
import {
  TokenBucket,
  decodeThunk,
  describeSource,
  looksPatched,
  planHook,
  siteRuleHit,
  stackSlotOffset,
} from "../../../src/agent/pure/hookPlan.js";
import { AGENT_LIMIT_DEFAULTS } from "../../../src/shared/agentLimits.js";
import type { HookInstallParams } from "../../../src/shared/agentProtocol.js";

const base = (over: Partial<HookInstallParams> = {}): HookInstallParams => ({
  target: { va: "0x140001760" },
  engine: "js",
  relocation: "auto",
  capture: { args: [], ret: null, backtrace: null, registers: "none" },
  emit: "enter",
  probe: false,
  hidden_ret_ptr: false,
  lifetime: { duration_ms: 1000, max_hits: 100 },
  observe_agent_calls: false,
  force_caution: false,
  ...over,
});
const L = AGENT_LIMIT_DEFAULTS;
const plan = (p: HookInstallParams, features: readonly string[] = ["hooks.js", "hooks.native", "hooks.native.xmm"]) => {
  const r = planHook(p, L, features as never);
  if (!r.ok) throw new Error(JSON.stringify(r.issues));
  return r.plan;
};

describe("planHook: Win64 slot mapping (S4 §10.3)", () => {
  it("maps int slots to args[p], floats < 4 to xmm<p>, floats >= 4 to [rsp+8+8p], registers to themselves", () => {
    const p = plan(
      base({
        capture: {
          args: [
            { slot: 0, class: "int", type: "i32" },
            { slot: 1, type: "f32" },
            { slot: 2, type: "f64" },
            { slot: 4, class: "int", type: "i32" },
            { slot: 5, type: "f64" },
            { reg: "rbx", type: "ptr" },
            { slot: 0, type: "f32", deref: [8] },
          ],
          ret: { type: "f64" },
          backtrace: null,
          registers: "none",
        },
      }),
    );
    expect(p.captures.map((c) => c.source)).toEqual([
      { kind: "slot-int", p: 0 },
      { kind: "slot-xmm", p: 1 },
      { kind: "slot-xmm", p: 2 },
      { kind: "slot-int", p: 4 },
      { kind: "slot-stack", p: 5, offset: 0x30 },
      { kind: "reg", reg: "rbx" },
      { kind: "slot-int", p: 0 },
    ]);
    expect(stackSlotOffset(4)).toBe(0x28);
    expect(p.emit).toBe("leave"); // a return value forces leave rows
    expect(p.ret).toMatchObject({ type: "f64", fromXmm0: true });
    expect(p.captures.map((c) => describeSource(c.source))).toEqual([
      "rcx",
      "xmm1",
      "xmm2",
      "[rsp+0x28]",
      "[rsp+0x30]",
      "rbx",
      "rcx",
    ]);
  });

  it("shifts every slot by one with hidden_ret_ptr", () => {
    const p = plan(
      base({
        hidden_ret_ptr: true,
        capture: {
          args: [
            { slot: 0, class: "int", type: "ptr" },
            { slot: 3, type: "f32" },
          ],
          ret: null,
          backtrace: null,
          registers: "none",
        },
      }),
    );
    expect(p.captures.map((c) => c.source)).toEqual([
      { kind: "slot-int", p: 1 },
      { kind: "slot-stack", p: 4, offset: 0x28 },
    ]);
  });

  it("applies text/bytes defaults and agent clamps", () => {
    const p = plan(
      base({
        capture: {
          args: [
            { slot: 0, class: "int", type: "utf16" },
            { slot: 1, class: "int", type: "bytes" },
            { slot: 2, class: "int", type: "utf8", max_len: 1_000_000 },
            { slot: 3, class: "int", type: "u32", deref: [0], count: 8 },
          ],
          ret: null,
          backtrace: { depth: 64, max_per_sec: 5000 },
          registers: "none",
        },
      }),
    );
    expect(p.captures.map((c) => [c.maxLen, c.count])).toEqual([
      [256, 1],
      [64, 1],
      [L.max_string_chars, 1],
      [0, 8],
    ]);
    expect(p.backtrace).toEqual({ depth: L.max_backtrace_depth, perSec: L.backtrace_per_sec });
  });
});

describe("planHook: refusals and the native tier (S4 §10.4)", () => {
  it("reports structural problems as BadParams issues", () => {
    const r = planHook(
      base({
        probe: true,
        capture: {
          args: [
            { slot: 0, reg: "rax", type: "ptr" },
            { slot: 1, type: "f32", at: "leave" },
            { slot: 2, class: "float", type: "ptr", deref: [1] },
            { slot: 3, class: "int", type: "u8", deref: [1, 2, 3, 4, 5, 6, 7, 8, 9] },
          ],
          ret: { type: "i32" },
          backtrace: null,
          registers: "none",
        },
      }),
      L,
      [],
    );
    expect(r.ok).toBe(false);
    if (r.ok) return;
    const problems = r.issues.map((i) => `${i.path}: ${i.problem}`).join("\n");
    expect(problems).toContain("capture.args[0]: give exactly one of slot (+class) or reg");
    expect(problems).toContain("registers only");
    expect(problems).toContain("has no leave");
    expect(problems).toContain("deref chain starts from an integer-class slot");
    expect(problems).toContain("deref has 9 offsets");
    expect(problems).toContain("capture.ret: an instruction probe has no return value");
  });

  it("maps native captures onto hook-native/1 fields and refuses what the ring cannot hold", () => {
    const p = plan(
      base({
        engine: "native",
        filter: { thread_ids: [1, 2] },
        capture: {
          args: [
            { slot: 0, class: "int", type: "u32" },
            { slot: 1, type: "f32" },
            { slot: 5, class: "int", type: "i32" },
            { reg: "r9", type: "u64" },
          ],
          ret: { type: "f32" },
          backtrace: null,
          registers: "none",
        },
      }),
    );
    expect(p.native).toEqual({
      fields: [
        { index: 0, field: "w0", type: "u32" },
        { index: 1, field: "x1", type: "f32" },
        { index: 2, field: "s5", type: "i32" },
        { index: 3, field: "w3", type: "u64" },
      ],
      ret: "xmm0_ret",
      threads: [1, 2],
    });
    const bad = planHook(
      base({
        engine: "native",
        capture: {
          args: [
            { slot: 8, class: "int", type: "u32" },
            { reg: "rbx", type: "u64" },
            { slot: 1, type: "f32" },
            { slot: 0, class: "int", type: "utf8" },
          ],
          ret: null,
          backtrace: { depth: 4, max_per_sec: 10 },
          registers: "none",
        },
      }),
      L,
      ["hooks.native"],
    );
    expect(bad.ok).toBe(false);
    if (bad.ok) return;
    const text = bad.issues.map((i) => i.problem).join("\n");
    expect(text).toContain("slots 0..7");
    expect(text).toContain("cannot record xmm registers");
    expect(text).toContain("bare slot or register values");
    expect(text).toContain("no backtrace");
  });
});

describe("thunks, deny list, sampling", () => {
  it("decodes jmp [rip+d], rex jmp [rip+d] and jmp rel32", () => {
    expect(decodeThunk(new Uint8Array([0xff, 0x25, 0x10, 0, 0, 0]))).toEqual({ kind: "jmp-rip", length: 6, disp: 16 });
    expect(decodeThunk(new Uint8Array([0x48, 0xff, 0x25, 0xfc, 0xff, 0xff, 0xff]))).toEqual({
      kind: "jmp-rip",
      length: 7,
      disp: -4,
    });
    expect(decodeThunk(new Uint8Array([0xe9, 0x00, 0x01, 0, 0]))).toEqual({ kind: "jmp-rel", length: 5, rel: 256 });
    expect(decodeThunk(new Uint8Array([0x48, 0x83, 0xec, 0x28]))).toBeNull();
    expect(looksPatched(new Uint8Array([0xe9, 1, 2, 3, 4]))).toBe(true);
    expect(looksPatched(new Uint8Array([0x48, 0x83]))).toBe(false);
  });

  it("prefers deny over caution and matches thunk targets too", () => {
    const rules = [
      { api: "kernelbase.dll!VirtualAlloc", va: "0x7ffa0010", reason: "deadlock-risk" as const },
      { api: "ntdll.dll!RtlAllocateHeap", va: "0x7ffb0020", reason: "caution" as const },
    ];
    expect(siteRuleHit(["0x1000", "0x7FFA0010"], rules)?.api).toBe("kernelbase.dll!VirtualAlloc");
    expect(siteRuleHit(["0x7ffb0020"], rules)?.reason).toBe("caution");
    expect(siteRuleHit(["0x1"], rules)).toBeNull();
  });

  it("token bucket refills at the configured rate", () => {
    const b = new TokenBucket(2, 0);
    expect([b.take(0), b.take(0), b.take(0)]).toEqual([true, true, false]);
    expect(b.take(400_000)).toBe(false);
    expect(b.take(500_000)).toBe(true);
  });
});

describe("value cells (bit-exact floats)", () => {
  it("encodes scalars from little-endian bytes", () => {
    const b = new Uint8Array([0x89, 0x88, 0x88, 0x3c, 0xff, 0xff, 0xff, 0xff]);
    expect(scalarCell("f32", b)).toBe("0x3c888889");
    expect(scalarCell("u32", b)).toBe(0x3c888889);
    expect(scalarCell("i8", b)).toBe(-119);
    expect(scalarCell("u64", b)).toBe("0xffffffff3c888889");
    expect(scalarCell("f64", b)).toBe("0xffffffff3c888889");
    expect(scalarCell("bool8", new Uint8Array([2]))).toBe(1);
    expect(scalarCell("i64", new Uint8Array(8))).toBe("0x0");
    expect(scalarCell("utf8", b)).toEqual({ e: "unsupported" });
    expect(arrayCell("u16", new Uint8Array([1, 0, 2, 0, 3, 0]), 3)).toEqual([1, 2, 3]);
  });

  it("keeps NaN payloads exact (no JS number on the way)", () => {
    expect(cellOfWord("f32", "0x7fc00001")).toBe("0x7fc00001");
    expect(cellOfWord("f64", "0x7ff8000000000001")).toBe("0x7ff8000000000001");
    expect(cellOfWord("i32", "0xffffffff")).toBe(-1);
    expect(Array.from(bytesOfHex64("0x0102"))).toEqual([2, 1, 0, 0, 0, 0, 0, 0]);
  });

  it("decodes text with caps and NUL termination", () => {
    const utf8 = new TextEncoder().encode("héllo\0junk");
    expect(decodeText(utf8, "utf8", 100)).toEqual({ s: "héllo", trunc: false });
    expect(decodeText(utf8, "utf8", 2)).toEqual({ s: "hé", trunc: true });
    const utf16 = new Uint8Array([0x41, 0, 0x42, 0, 0, 0]);
    expect(decodeText(utf16, "utf16", 10)).toEqual({ s: "AB", trunc: false });
    expect(decodeText(new Uint8Array([0xff, 0x41, 0]), "utf8", 10)).toEqual({ s: "�A", trunc: false });
    expect(textReadBytes("utf16", 4)).toBe(10);
  });

  it("formats hex, frames and size estimates", () => {
    expect(hexLE(new Uint8Array([0x10, 0, 0, 0]), 0, 4)).toBe("0x10");
    expect(hexBytes(new Uint8Array([0xab, 0x01]))).toBe("ab01");
    expect(frameRefText(0x140001b2cn, { name: "game_sim.exe", base: 0x140000000n })).toBe("game_sim.exe+0x1b2c");
    expect(frameRefText(0x5000n, null)).toBe("0x5000");
    expect(estimateBytes([1, "ab", null])).toBe(2 + 13 + 5 + 5);
  });
});
