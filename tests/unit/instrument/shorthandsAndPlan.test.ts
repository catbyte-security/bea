import { describe, expect, it } from "vitest";

import { buildHookPlan } from "../../../src/application/handlers/instrument.js";
import { INSTRUMENT_TOOLS } from "../../../src/contracts/areas/instrument.js";
import { TOOL_CONTRACTS } from "../../../src/contracts/index.js";
import { expandCliShorthands, parseCaptureShorthand } from "../../../src/cli/shorthands.js";

const hook = INSTRUMENT_TOOLS[0];
const status = TOOL_CONTRACTS.find((c) => c.name === "bea_status");

describe("--capture shorthand (S6 §8.1)", () => {
  it("parses names, slots, registers, deref chains and leave/both suffixes", () => {
    expect(parseCaptureShorthand("speed=arg0:f32+0x8@both")).toEqual({
      ok: true,
      value: { name: "speed", arg: 0, type: "f32", deref: [8], when: "both" },
    });
    expect(parseCaptureShorthand("dt=arg1:f32")).toEqual({ ok: true, value: { name: "dt", arg: 1, type: "f32" } });
    expect(parseCaptureShorthand("x=XMM1:f32")).toEqual({ ok: true, value: { name: "x", reg: "xmm1", type: "f32" } });
    expect(parseCaptureShorthand("arg2:ptr+0x40+0-8@leave")).toEqual({
      ok: true,
      value: { arg: 2, type: "ptr", deref: [0x40, 0, -8], when: "leave" },
    });
    expect(parseCaptureShorthand("n=rcx:utf16")).toEqual({ ok: true, value: { name: "n", reg: "rcx", type: "utf16" } });
  });

  it("explains malformed values", () => {
    const problem = (s: string) => {
      const r = parseCaptureShorthand(s);
      return r.ok ? "" : r.problem;
    };
    expect(problem("speed=arg0")).toContain('missing ":type"');
    expect(problem("speed=arg0:float")).toContain("is not a value type");
    expect(problem("speed=arg16:f32")).toContain("arg is 0..15");
    expect(problem("speed=eax:u32")).toContain("neither argN nor a register");
    expect(problem("speed=arg0:f32+zz")).toContain("is not a +0xOFFSET");
    expect(problem("9x=arg0:f32")).toContain("is not a capture name");
    expect(problem("a=arg0:f32@later")).toContain("is not @leave or @both");
    expect(problem("a=arg0:f32+1+2+3+4+5")).toContain("at most 4 deref offsets");
  });

  it("expands hook_function argv only, keeps program arguments after --, and validates through the contract", () => {
    const argv = [
      "0x140001760",
      "--capture",
      "dt=arg1:f32",
      "--capture=speed=arg0:f32+0x8@both",
      "--returns",
      "f32",
      "--spawn",
      "game.exe",
      "--",
      "--capture",
      "x",
    ];
    const r = expandCliShorthands(hook, argv);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.value.argv).toEqual(["0x140001760", "--returns", "f32", "--spawn", "game.exe", "--", "--capture", "x"]);
    expect(r.value.input).toEqual({
      capture: [
        { name: "dt", arg: 1, type: "f32" },
        { name: "speed", arg: 0, type: "f32", deref: [8], when: "both" },
      ],
    });
    const parsed = hook.inputSchema.safeParse({
      session_id: "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b",
      address: "0x140001760",
      ...r.value.input,
    });
    expect(parsed.success).toBe(true);
    if (status !== undefined)
      expect(expandCliShorthands(status, ["--capture", "x"])).toEqual({
        ok: true,
        value: { argv: ["--capture", "x"], input: {} },
      });
    const bad = expandCliShorthands(hook, ["--capture", "nope", "--capture"]);
    expect(bad.ok).toBe(false);
    if (bad.ok) return;
    expect(bad.error.issues.map((i) => i.reason)).toEqual(["invalid_format", "missing_argument"]);
  });
});

describe("buildHookPlan (tool input -> agent params + decoders)", () => {
  const parse = (over: Record<string, unknown>) =>
    hook.inputSchema.parse({ session_id: "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b", address: "0x1", ...over });

  it("maps classes, both-captures, strings, filters and lifetimes", () => {
    const { params, decoders } = buildHookPlan(
      parse({
        capture: [
          { name: "car", arg: 0, type: "ptr" },
          { name: "dt", arg: 1, type: "f32" },
          { arg: 2, type: "f64", deref: [0x10] },
          { reg: "rdx", type: "utf16", count: 40 },
          { name: "v", arg: 0, type: "u32", deref: [0x20], count: 4, when: "both" },
          { name: "on", arg: 3, type: "bool" },
        ],
        backtrace: 8,
        thread_id: 77,
        sample_every: 20,
        max_events: 10_000_000,
        duration_ms: 500,
      }),
      0x1234n,
      false,
    );
    expect(params.target).toEqual({ va: "0x1234" });
    expect(params.emit).toBe("leave");
    expect(params.capture.args).toEqual([
      { name: "car", type: "ptr", at: "enter", slot: 0, class: "int" },
      { name: "dt", type: "f32", at: "enter", slot: 1, class: "float" },
      { name: "arg2", type: "f64", at: "enter", slot: 2, class: "int", deref: [16] },
      { name: "rdx", type: "utf16", at: "enter", reg: "rdx", max_len: 40 },
      { name: "v", type: "u32", at: "enter", slot: 0, class: "int", deref: [32], count: 4 },
      { name: "v@leave", type: "u32", at: "leave", slot: 0, class: "int", deref: [32], count: 4 },
      { name: "on", type: "bool8", at: "enter", slot: 3, class: "int" },
    ]);
    expect(params.capture.backtrace).toEqual({ depth: 8, max_per_sec: 100 });
    expect(params.filter).toEqual({ thread_ids: [77] });
    expect(params.sample).toEqual({ every_n: 20 });
    expect(params.lifetime).toEqual({ duration_ms: 500, max_hits: 100_000_000, clock: "install" });
    expect(decoders.cells.map((c) => c.field)).toEqual(["car", "dt", "arg2", "rdx", "v", "v@leave", "on"]);
    expect(decoders).toMatchObject({ engine: "js", backtrace: 8, ret: null, ret_source: null });
  });

  it("emits at enter without return or leave captures, and maps native sources", () => {
    const enter = buildHookPlan(parse({ capture: [{ arg: 0, type: "u32" }] }), 1n, true);
    expect(enter.params.emit).toBe("enter");
    expect(enter.params.lifetime.clock).toBe("resume");
    const native = buildHookPlan(
      parse({
        engine: "native",
        capture: [
          { arg: 0, type: "u32" },
          { arg: 1, type: "f32" },
          { arg: 6, type: "f64" },
          { reg: "r9", type: "u64" },
        ],
        returns: "f32",
      }),
      1n,
      false,
    );
    expect(native.decoders.native).toEqual([
      { field: "arg0", type: "u32", source: "rcx" },
      { field: "arg1", type: "f32", source: "xmm1" },
      { field: "arg6", type: "f64", source: "s6" },
      { field: "r9", type: "u64", source: "r9" },
    ]);
    expect(native.decoders.ret_source).toBe("xmm0_ret");
  });

  it("refuses numeric arrays without deref or above 64 elements", () => {
    expect(
      hook.inputSchema.safeParse({
        session_id: "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b",
        address: "0x1",
        capture: [{ arg: 0, type: "u32", count: 4 }],
      }).success,
    ).toBe(false);
    expect(
      hook.inputSchema.safeParse({
        session_id: "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b",
        address: "0x1",
        capture: [{ arg: 0, type: "u32", count: 65, deref: [0] }],
      }).success,
    ).toBe(false);
    expect(
      hook.inputSchema.safeParse({
        session_id: "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b",
        address: "0x1",
        capture: [{ arg: 0, type: "utf8", count: 4000 }],
      }).success,
    ).toBe(true);
  });
});
