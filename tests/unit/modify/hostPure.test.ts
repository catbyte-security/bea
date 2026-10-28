import { describe, expect, it } from "vitest";

import { OVERRIDE_KIND, parseOverrideRow } from "../../../src/application/instruments/kinds/override.js";
import { RECORDING_KINDS } from "../../../src/application/instruments/kinds/index.js";
import { fingerprintInterference } from "../../../src/application/modify/fingerprint.js";
import { MODIFY_TOOLS } from "../../../src/contracts/areas/modify.js";
import { toolContract } from "../../../src/contracts/index.js";
import { MODIFY_LIMITATIONS } from "../../../src/domain/evidence/limitations/modify.js";
import { LIMITATIONS } from "../../../src/domain/evidence/limitations.js";
import type { DecodeContext, EventRecord } from "../../../src/ports/recordings.js";
import type { Fingerprint } from "../../../src/shared/agentProtocol.js";

const SESSION = "3f2b8c1e-4d5a-4e6f-9a0b-1c2d3e4f5a6b";

describe("modify contracts (DESIGN §6.2 I)", () => {
  it("registers three gated, destructive P3 tools with S6 descriptions", () => {
    expect(MODIFY_TOOLS.map((c) => [c.name, c.gate?.id, c.gate?.scope, c.phase])).toEqual([
      ["write_memory", "write_memory", "always", "P3"],
      ["override_function", "override_function", "always", "P3"],
      ["run_script", "run_script", "always", "P3"],
    ]);
    for (const c of MODIFY_TOOLS) {
      expect(c.annotations.destructiveHint, c.name).toBe(true);
      expect(c.annotations.readOnlyHint, c.name).toBe(false);
      expect(c.description.startsWith(`GATED: needs server opt-in ${c.name}.`), c.name).toBe(true);
    }
    expect(toolContract("run_script").cli).toEqual({
      tier: "session-oneshot",
      command: "script",
      positional: ["source"],
      fileFields: ["source"],
    });
    expect(toolContract("run_script").maxInputBytes).toBe(2 * 1024 * 1024);
    expect(toolContract("write_memory").evidence).toEqual({ predicate: "bea.memory.write", recorded: "always" });
  });

  it("write_memory takes exactly one of hex or type+value", () => {
    const schema = toolContract("write_memory").inputSchema;
    const ok = (input: object) => schema.safeParse({ session_id: SESSION, address: "0x1000", ...input }).success;
    expect(ok({ hex: "0000803f" })).toBe(true);
    expect(ok({ type: "f32", value: 1 })).toBe(true);
    expect(ok({})).toBe(false);
    expect(ok({ hex: "00", type: "u8", value: 1 })).toBe(false);
    expect(ok({ type: "u8" })).toBe(false);
    expect(ok({ hex: "0" })).toBe(false);
    expect(ok({ hex: "00".repeat(4097) })).toBe(false);
    expect(ok({ type: "utf8", value: "x" })).toBe(false);
  });

  it("override_function enforces the mode rules", () => {
    const schema = toolContract("override_function").inputSchema;
    const ok = (input: object) =>
      schema.safeParse({ session_id: SESSION, address: "game_sim.exe!tiny_add", ...input }).success;
    expect(ok({ mode: "args", set_args: [{ arg: 1, type: "f32", value: 0 }] })).toBe(true);
    expect(ok({ mode: "args" })).toBe(false);
    expect(ok({ mode: "args", set_args: [{ arg: 1, type: "f32", value: 0 }], return_value: 1 })).toBe(false);
    expect(
      ok({
        mode: "args",
        set_args: [
          { arg: 1, type: "f32", value: 0 },
          { arg: 1, type: "i32", value: 0 },
        ],
      }),
    ).toBe(false);
    expect(ok({ mode: "return", returns: "f32", return_value: 123 })).toBe(true);
    expect(ok({ mode: "return", return_value: 123 })).toBe(false);
    expect(ok({ mode: "replace", returns: "i32", return_value: 7 })).toBe(true);
    expect(ok({ mode: "replace", returns: "i32" })).toBe(false);
    expect(ok({ mode: "return", returns: "i32", return_value: 1, set_args: [{ arg: 0, type: "i32", value: 1 }] })).toBe(
      false,
    );
    expect(ok({ mode: "return", returns: "i32", return_value: 1, duration_ms: 0 })).toBe(false);
    const parsed = schema.parse({
      session_id: SESSION,
      address: "0x1",
      mode: "replace",
      returns: "i32",
      return_value: 1,
    });
    expect([parsed.duration_ms, parsed.max_events, parsed.record]).toEqual([10_000, 100_000, true]);
  });

  it("run_script bounds the script and its rpc call", () => {
    const schema = toolContract("run_script").inputSchema;
    const ok = (input: object) => schema.safeParse({ session_id: SESSION, ...input }).success;
    expect(ok({ source: "send(1)" })).toBe(true);
    expect(ok({ source: "" })).toBe(false);
    expect(ok({ source: "x", rpc_args: [1] })).toBe(false);
    expect(ok({ source: "x", rpc_method: "go", rpc_args: [1, { a: [true] }] })).toBe(true);
    expect(ok({ source: "x", duration_ms: 60_001 })).toBe(false);
    expect(ok({ source: "x", rpc_method: "bad name" })).toBe(false);
    const parsed = schema.parse({ session_id: SESSION, source: "x" });
    expect([parsed.runtime, parsed.duration_ms, parsed.max_messages, parsed.rpc_args]).toEqual(["qjs", 1000, 1000, []]);
  });
});

describe("modify limitations", () => {
  it("are fixed sentences merged into the catalog", () => {
    for (const [key, text] of Object.entries(MODIFY_LIMITATIONS)) {
      expect(LIMITATIONS[key as keyof typeof LIMITATIONS], key).toBe(text);
      expect(typeof text === "string" && text.length > 20 && text.length <= 1000, key).toBe(true);
    }
  });
});

const fp = (over: Partial<Fingerprint> = {}): Fingerprint => ({
  t: 1,
  patches: [{ owner: "h1", address: "0x1000", expected_head: "e9", actual_head: "e9", ok: true }],
  debug_registers: [{ tid: 4, dr7: "0x1", ok: true }],
  guard_pages: [{ page: "0x2000", guarded: true, ok: true }],
  stalker_threads: [9],
  ...over,
});

describe("run_script interference (S4 §16)", () => {
  it("is false when nothing BEA owns changed", () => {
    expect(fingerprintInterference(fp(), fp({ t: 99 }))).toBe(false);
  });
  it("flags altered patch heads, debug registers, guard pages and dropped follows", () => {
    expect(
      fingerprintInterference(
        fp(),
        fp({ patches: [{ owner: "h1", address: "0x1000", expected_head: "e9", actual_head: "55", ok: false }] }),
      ),
    ).toBe(true);
    expect(fingerprintInterference(fp(), fp({ debug_registers: [{ tid: 4, dr7: "0x0", ok: false }] }))).toBe(true);
    expect(fingerprintInterference(fp(), fp({ guard_pages: [{ page: "0x2000", guarded: false, ok: false }] }))).toBe(
      true,
    );
    expect(fingerprintInterference(fp(), fp({ stalker_threads: [] }))).toBe(true);
  });
  it("does not blame the script for entries that were already broken or were removed by BEA", () => {
    const broken = fp({ debug_registers: [{ tid: 4, dr7: "0x0", ok: false }] });
    expect(fingerprintInterference(broken, broken)).toBe(false);
    expect(fingerprintInterference(fp(), fp({ patches: [] }))).toBe(false);
  });
});

describe("override recording kind (override/1)", () => {
  const ctx: DecodeContext = {
    sessionId: SESSION,
    decoders: null,
    startedAtUs: 1_000_000,
    frame: () => ({ at: null, static: null }),
  };

  it("is registered in the pre-wired kind registry", () => {
    expect(RECORDING_KINDS.override).toBe(OVERRIDE_KIND);
    expect(OVERRIDE_KIND.rowKinds).toEqual(["override/1"]);
  });

  it("decodes rows and skips malformed ones", () => {
    const events = [
      ...OVERRIDE_KIND.decode(
        { seq: 1, module_map_epoch: 1, fields: [10, 1_002_500, 7, "o1", "ret", ["0x41a00000"]] },
        ctx,
      ),
      ...OVERRIDE_KIND.decode({ seq: 2, module_map_epoch: 1, fields: [11, 1_003_000, 7, "o1", "bogus", []] }, ctx),
      ...OVERRIDE_KIND.decode({ seq: 3, module_map_epoch: 1, fields: { x: 1 } }, ctx),
    ];
    expect(events).toEqual([{ seq: 1, t_ms: 2.5, tid: 7, applied: "ret", original: ["0x41a00000"] }]);
    expect(parseOverrideRow([1, 2, -1, "o1", "args", []])).toBeNull();
  });

  it("summarizes applications per kind and thread, bounded", () => {
    const builder = OVERRIDE_KIND.summary;
    const state = builder.init();
    const rows: EventRecord[] = [];
    for (let i = 0; i < 40; i++)
      rows.push({ seq: i + 1, t_ms: i, tid: i % 20, applied: i % 2 === 0 ? "args" : "replace", original: [] });
    for (const row of rows) builder.add(state, row);
    const summary = builder.finish(state);
    expect(summary).toMatchObject({
      applications: 40,
      by_applied: { args: 20, ret: 0, replace: 20 },
      threads_total: 20,
      first_t_ms: 0,
      last_t_ms: 39,
    });
    expect((summary["threads"] as unknown[]).length).toBe(16);
  });
});
