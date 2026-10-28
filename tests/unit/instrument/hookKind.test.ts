import { describe, expect, it } from "vitest";

import {
  HOOK_KIND,
  decodeHookRecord,
  hookFieldsOf,
  hookSummary,
  parseHookDecoders,
  valueOfCell,
  valueOfRaw,
  type HookDecoders,
} from "../../../src/application/instruments/kinds/hook.js";
import { RECORDING_KINDS } from "../../../src/application/instruments/kinds/index.js";
import type { JsonValue } from "../../../src/domain/json.js";
import type { DecodeContext, EventRecord } from "../../../src/ports/recordings.js";
import { BINARY_LAYOUTS } from "../../../src/shared/binaryLayouts.js";

const JS: HookDecoders = {
  v: 1,
  engine: "js",
  caller: true,
  backtrace: 4,
  sample_every: 1,
  cells: [
    { field: "car", type: "ptr" },
    { field: "dt", type: "f32" },
    { field: "speed@leave", type: "f32" },
    { field: "flag", type: "bool" },
    { field: "big", type: "i64" },
    { field: "name", type: "utf16" },
  ],
  native: [],
  ret: "f32",
  ret_source: "xmm0_ret",
};
const ctx = (decoders: HookDecoders): DecodeContext => ({
  sessionId: "s",
  decoders: decoders as unknown as JsonValue,
  startedAtUs: 1000,
  frame: (f) => ({
    at: f.startsWith("0x") ? `game_sim.exe+${f.slice(2)}` : f,
    static: f.startsWith("0x") ? `game_sim.exe:${f}` : null,
  }),
});
const decode = (fields: JsonValue, d: HookDecoders, seq = 1): EventRecord[] => [
  ...decodeHookRecord({ seq, module_map_epoch: 1, fields }, ctx(d)),
];

describe("hook kind decoding", () => {
  it("is pre-wired in the recording-kind registry", () => {
    expect(RECORDING_KINDS.hook).toBe(HOOK_KIND);
    expect(HOOK_KIND?.rowKinds).toEqual(["hook/1", "hook-native/1"]);
  });

  it("decodes a phase-2 JSON row: floats with bits, 64-bit decimal, errors, caller, bt, dur_us", () => {
    const [e] = decode(
      [
        7,
        3500,
        42,
        2,
        1,
        "0x1b2c",
        ["0x1d2f0e40", "0x3c888889", { e: "av", a: "0x8" }, 1, "0xfffffffffffffffe", { s: "Wheel", trunc: true }],
        "0x7fc00001",
        ["game_sim.exe+0x10", "0x99"],
        { t_leave: "0xdb6" },
      ],
      JS,
    );
    expect(e).toEqual({
      seq: 1,
      t_ms: 2.5,
      tid: 42,
      depth: 1,
      caller: "game_sim.exe+1b2c",
      "caller:static": "game_sim.exe:0x1b2c",
      dur_us: 10,
      bt: ["game_sim.exe+0x10", "game_sim.exe+99"],
      car: "0x1d2f0e40",
      dt: 0.016666668,
      "dt:bits": "0x3c888889",
      "speed@leave": null,
      "speed@leave:err": "av",
      flag: true,
      big: "-2",
      name: "Wheel",
      ret: "NaN",
      "ret:bits": "0x7fc00001",
    });
  });

  it("decodes native records from object or layout-ordered array fields", () => {
    const d: HookDecoders = {
      ...JS,
      engine: "native",
      backtrace: 0,
      cells: [],
      native: [
        { field: "x", type: "u32", source: "rcx" },
        { field: "dt", type: "f32", source: "xmm1" },
        { field: "e", type: "i32", source: "s4" },
      ],
      ret: "u32",
      ret_source: "rax",
    };
    const record: Record<string, JsonValue> = {
      g: 9,
      t: 1600,
      tid: 5,
      hook_index: 1,
      phase: 2,
      depth: 0,
      ret_addr: "0x140001b2c",
      rcx: "0xffffffff00000007",
      rdx: 0,
      r8: 0,
      r9: 0,
      xmm0: 0,
      xmm1: "0x3c888889",
      xmm2: 0,
      xmm3: 0,
      s4: "0xfffffffffffffff9",
      s5: 0,
      s6: 0,
      s7: 0,
      rax: "14",
      xmm0_ret: 0,
      reserved: 1700,
      commit: "0xbea0bea0bea0bea0",
    };
    const expected = {
      seq: 3,
      t_ms: 0.6,
      tid: 5,
      depth: 0,
      caller: "game_sim.exe+140001b2c",
      "caller:static": "game_sim.exe:0x140001b2c",
      dur_us: 100,
      x: 7,
      dt: 0.016666668,
      "dt:bits": "0x3c888889",
      e: -7,
      ret: 14,
    };
    expect(decode(record, d, 3)).toEqual([expected]);
    const ordered = BINARY_LAYOUTS["hook-native/1"].fields.map((f) => record[f.name] ?? 0);
    expect(decode(ordered, d, 3)).toEqual([expected]);
  });

  it("ignores rows of a recording whose decoders are malformed", () => {
    expect([
      ...decodeHookRecord({ seq: 1, module_map_epoch: null, fields: [] }, { ...ctx(JS), decoders: { v: 2 } }),
    ]).toEqual([]);
    expect(parseHookDecoders(null)).toBeNull();
  });

  it("converts cells and raw words per declared type", () => {
    expect(valueOfCell("f64", "0x3ff0000000000000")).toEqual({ value: 1, bits: "0x3ff0000000000000" });
    expect(valueOfCell("u64", "0xffffffffffffffff").value).toBe("18446744073709551615");
    expect(valueOfCell("i32", [1, 2]).value).toEqual([1, 2]);
    expect(valueOfCell("bytes", { x: "00ff" }).value).toBe("00ff");
    expect(valueOfRaw("i16", 0xffffn).value).toBe(-1);
    expect(valueOfRaw("f32", 0xff800000n).value).toBe("-Infinity");
  });

  it("lists the recording's fields from its decoders", () => {
    expect(hookFieldsOf(JS).map((f) => `${f.name}:${f.type}`)).toEqual([
      "depth:int",
      "caller:address",
      "dur_us:int",
      "bt:array",
      "car:address",
      "dt:float",
      "speed@leave:float",
      "flag:bool",
      "big:int",
      "name:string",
      "ret:float",
    ]);
  });
});

describe("HookSummary (S6 §5.3)", () => {
  it("digests calls, threads, callers, durations, fields and returns", () => {
    const s = hookSummary.init();
    for (let i = 0; i < 20; i++)
      hookSummary.add(s, {
        seq: i + 1,
        t_ms: i,
        tid: i < 15 ? 1 : 2,
        depth: 0,
        caller: i % 2 === 0 ? "game_sim.exe+0x10" : "game_sim.exe+0x20",
        "caller:static": "game_sim.exe:0x140000010",
        dur_us: i,
        dt: 0.016666668,
        "dt:bits": "0x3c888889",
        ...(i === 3 ? { speed: null, "speed:err": "null" } : { speed: i }),
        ret: i * 2,
      });
    const out = hookSummary.finish(s);
    expect(out).toMatchObject({
      calls: 20,
      recorded: 20,
      read_failures: 1,
      threads: [
        { tid: 1, calls: 15 },
        { tid: 2, calls: 5 },
      ],
      callers: [
        { at: "game_sim.exe+0x10", static: "game_sim.exe:0x140000010", calls: 10 },
        { at: "game_sim.exe+0x20", calls: 10 },
      ],
      duration_us: { p50: 10, p90: 18, max: 19 },
      fields: {
        dt: { count: 20, distinct: 1, min: 0.016666668, max: 0.016666668 },
        speed: { count: 19, min: 0, max: 19, distinct: 19 },
      },
      returns: { count: 20, min: 0, max: 38 },
    });
    expect(Object.keys(out["fields"] as object)).toEqual(["dt", "speed"]);
  });
});
