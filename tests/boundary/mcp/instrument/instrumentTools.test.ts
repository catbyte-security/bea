import { afterEach, describe, expect, it, vi } from "vitest";

import type { HandleKindSpec } from "../../../../src/ports/handles.js";
import type { StId } from "../../../../src/domain/ids.js";
import type { ArgCapture, HookInstallParams } from "../../../../src/shared/agentProtocol.js";
import { INSTRUMENT_LIMITATIONS } from "../../../../src/domain/evidence/limitations/instrument.js";
import { connectInMemoryBea, type InMemoryBea } from "../../../support/mcp/inMemory.js";
import { expectToolSuccess, parseToolError } from "../../../support/mcp/parseToolError.js";
import { ok } from "../../../../src/domain/result.js";
import { createGate } from "../../../support/frida/gate.js";
import { FakeWorld, hookInstallResult, OTHER_SESSION, SESSION_ID } from "./fakes.js";

/**
 * MCP boundary tests of the instrument area (WP7-HOOK): the production server, invokeTool, the real contracts and
 * handlers, with local fakes behind the session/evidence/address/recording ports (tests/boundary/mcp/instrument/fakes.ts).
 */
let bea: InMemoryBea | null = null;
afterEach(async () => {
  await bea?.close();
  bea = null;
});

const start = async (world: FakeWorld): Promise<InMemoryBea> => {
  bea = await connectInMemoryBea({ services: world.services() });
  return bea;
};
const call = async (b: InMemoryBea, name: string, args: Record<string, unknown>) =>
  b.client.callTool({ name, arguments: args });

const PHYSICS = {
  session_id: SESSION_ID,
  address: "game_sim.exe!physics_step",
  capture: [
    { name: "car", arg: 0, type: "ptr" },
    { name: "dt", arg: 1, type: "f32" },
    { name: "speed", arg: 0, type: "f32", deref: [8], when: "both" },
  ],
  returns: "f32",
  duration_ms: 2000,
};

/** decoders the handler writes for PHYSICS (used to build recordings directly) */
const PHYSICS_DECODERS = {
  v: 1,
  engine: "js",
  caller: true,
  backtrace: 0,
  sample_every: 1,
  cells: [
    { field: "car", type: "ptr" },
    { field: "dt", type: "f32" },
    { field: "speed", type: "f32" },
    { field: "speed@leave", type: "f32" },
  ],
  native: [],
  ret: "f32",
  ret_source: "xmm0_ret",
};
/** physics_step rows: dt = 1/60 f32 (0x3c888889); speed grows; ret == speed@leave */
const physicsRows = (n: number) =>
  Array.from({ length: n }, (_, i) => {
    const before = `0x${(0x41000000 + i * 0x10000).toString(16)}`;
    const after = `0x${(0x41000000 + (i + 1) * 0x10000).toString(16)}`;
    return [
      i + 1,
      2000 + i * 16_667,
      100 + (i % 2),
      2,
      0,
      "0x140001b2c",
      ["0x1d2f0e40", "0x3c888889", before, after],
      after,
      null,
      { t_leave: `0x${(2000 + i * 16_667 + 3).toString(16)}` },
    ];
  });

describe("hook_function", () => {
  it("installs through hookInstall, binds the stream, applies the effect and records the install", async () => {
    const world = new FakeWorld();
    world.paused = true;
    const b = await start(world);
    const out = expectToolSuccess(await call(b, "hook_function", { ...PHYSICS, sample_every: 2, max_events: 50 }));
    expect(out).toMatchObject({
      instrument: { kind: "hook", state: "active", events: 0 },
      target: { module: "game_sim.exe", rva: "0x1760" },
      function_start: true,
      bytes_match_file: true,
      relocation: "default",
      predicate_type: "bea.instrument.install",
      coverage: { status: "complete" },
    });
    expect(out["limitations"]).toContain(
      "Only every 2th call was recorded (sample_every); event counts and value statistics cover the recorded calls only.",
    );
    // UX-3: the target is paused, so the blocking step is resume_process, not a wait that can never finish
    expect((out["next"] as { tool: string }[]).map((n) => n.tool)).toEqual(["resume_process", "query_events"]);
    const install = world.calls.find((c) => c.method === "hookInstall")?.params as HookInstallParams;
    expect(install.target).toEqual({ va: "0x140001760" });
    expect(install.emit).toBe("leave");
    expect(install.capture.ret).toEqual({ type: "f32" });
    expect(install.lifetime).toEqual({ duration_ms: 2000, max_hits: 100, clock: "resume" });
    expect(install.sample).toEqual({ every_n: 2 });
    const args = install.capture.args as ArgCapture[];
    expect(args.map((a) => [a.name, a.slot, a.class, a.at, a.deref ?? null])).toEqual([
      ["car", 0, "int", "enter", null],
      ["dt", 1, "float", "enter", null],
      ["speed", 0, "int", "enter", [8]],
      ["speed@leave", 0, "int", "leave", [8]],
    ]);
    expect(world.boundStreams[0]?.spec.encoding).toEqual({ kind: "json-rows", row_kind: "hook/1" });
    expect(world.effects.size).toBe(1);
    const rec = [...world.recordings.values()][0];
    expect(rec?.create).toMatchObject({
      kind: "hook",
      agentInstrumentId: "h1",
      agentStream: "s1",
      startsAtResume: true,
    });
    expect(world.recorded.map((r) => r.predicate_type)).toEqual(["bea.instrument.install"]);
  });

  it("does not block on a paused target: wait_ms and wait return at once with TARGET_PAUSED (UX-3)", async () => {
    const world = new FakeWorld();
    world.paused = true;
    const b = await start(world);
    const started = performance.now();
    const out = expectToolSuccess(await call(b, "hook_function", { ...PHYSICS, wait_ms: 5000 }));
    expect(performance.now() - started).toBeLessThan(2500);
    const id = (out["instrument"] as { recording_id: string }).recording_id;
    const waitStarted = performance.now();
    const waited = expectToolSuccess(await call(b, "wait", { session_id: SESSION_ID, ids: [id], timeout_ms: 10_000 }));
    expect(performance.now() - waitStarted).toBeLessThan(2500);
    expect(waited).toMatchObject({ satisfied: false, reason: "timeout" });
    expect(waited["limitations"]).toEqual([INSTRUMENT_LIMITATIONS.TARGET_PAUSED]);
  });

  it("blocks for wait_ms and returns the finished recording with its summary", async () => {
    const world = new FakeWorld();
    const b = await start(world);
    setTimeout(() => {
      const rec = [...world.recordings.values()][0];
      if (rec === undefined) return;
      physicsRows(3).forEach((row, i) => rec.records.push({ seq: i + 1, module_map_epoch: 1, fields: row }));
      rec.state = "finished";
      rec.endReason = "duration";
    }, 30);
    const out = expectToolSuccess(await call(b, "hook_function", { ...PHYSICS, wait_ms: 2000 }));
    expect(out["instrument"]).toMatchObject({
      state: "finished",
      end_reason: "duration",
      events: 3,
      summary: { recorded: 3, read_failures: 0, fields: { dt: { count: 3, distinct: 1 } } },
    });
  });

  it("maps a native install to hook-native/1 fixed records", async () => {
    const world = new FakeWorld();
    world.agentOverride = (m) =>
      m === "hookInstall"
        ? {
            ok: true,
            value: {
              ...(world.calls.length > 0 ? {} : {}),
              instrument_id: "h7",
              stream_id: "s7",
              row_kind: "hook-native/1",
              layout: null,
              resolved: {
                va: "0x1",
                module: null,
                module_base: null,
                rva: null,
                export: null,
                function: null,
                protection: "r-x",
              },
              thunk: null,
              patched_at: ["0x1"],
              relocation: "default",
              stalker_invalidated: [],
              arg_map: [],
              effect: { kind: "hook-installed", reversible: true, targets: [], thread_ids: null, before: [] },
            },
          }
        : undefined;
    const b = await start(world);
    const out = expectToolSuccess(
      await call(b, "hook_function", {
        session_id: SESSION_ID,
        address: "game_sim.exe!hot_hash",
        engine: "native",
        capture: [{ name: "x", arg: 0, type: "u32" }],
        returns: "u32",
      }),
    );
    expect(out["function_start"]).toBe(true); // falls back to the export symbol at offset 0
    expect(world.boundStreams[0]?.spec.encoding).toMatchObject({
      kind: "fixed-records",
      row_kind: "hook-native/1",
      record_bytes: 160,
    });
    expect(world.boundStreams[0]?.spec.decoders).toMatchObject({
      engine: "native",
      native: [{ field: "x", type: "u32", source: "rcx" }],
      ret_source: "rax",
    });
  });
});

describe("hook_function refusals", () => {
  it("refuses contradictory inputs with corrective invalid_request messages", async () => {
    const world = new FakeWorld();
    const b = await start(world);
    const probe = parseToolError(
      await call(b, "hook_function", { ...PHYSICS, probe: true, capture: [{ arg: 0, type: "ptr" }], returns: "void" }),
    );
    expect(probe.code).toBe("invalid_request");
    expect(JSON.stringify(probe.details)).toContain("registers only");
    const native = parseToolError(
      await call(b, "hook_function", {
        ...PHYSICS,
        engine: "native",
        returns: "void",
        capture: [{ arg: 0, type: "f32", deref: [8] }],
      }),
    );
    expect(JSON.stringify(native.details)).toContain('engine \\"native\\"');
    const dup = parseToolError(
      await call(b, "hook_function", {
        ...PHYSICS,
        capture: [
          { name: "a", arg: 0, type: "ptr" },
          { name: "a", arg: 1, type: "f32" },
        ],
      }),
    );
    expect(JSON.stringify(dup.details)).toContain("already used");
    const both = parseToolError(
      await call(b, "hook_function", { ...PHYSICS, capture: [{ arg: 0, reg: "rax", type: "ptr" }] }),
    );
    expect(both.code).toBe("invalid_request");
    expect(world.calls).toEqual([]);
  });

  it("passes address and agent refusals through and rolls the hook back when a later step fails", async () => {
    const world = new FakeWorld();
    const b = await start(world);
    expect(parseToolError(await call(b, "hook_function", { ...PHYSICS, address: "unmapped!x" })).code).toBe(
      "address_unmapped",
    );
    world.agentOverride = (m) =>
      m === "hookInstall"
        ? {
            ok: false,
            error: {
              _tag: "InstrumentationFailed",
              operation: "hook_function",
              reason: "hook-denied",
              address: "0x7ffa00001000",
              conflicting_id: null,
            },
          }
        : undefined;
    expect(parseToolError(await call(b, "hook_function", PHYSICS)).code).toBe("instrumentation_failed");
    world.agentOverride = () => undefined;
    world.bindFails = true;
    const failed = parseToolError(await call(b, "hook_function", PHYSICS));
    expect(failed.code).toBe("execution_failure");
    expect(world.calls.map((c) => c.method)).toEqual(["hookInstall", "hookInstall", "instrumentStop"]);
    expect(world.recordings.size).toBe(0);
  });

  it("refuses a non-probe hook inside a function body before installing, and allows it as a probe (UX-1)", async () => {
    const world = new FakeWorld();
    world.functionStartRva = 0x1750; // the fake resolves every address to game_sim.exe+0x1760
    const b = await start(world);
    const e = parseToolError(await call(b, "hook_function", PHYSICS));
    expect(e.code).toBe("invalid_request");
    expect(e.details).toMatchObject({
      issues: [{ path: "address", reason: "invalid_value" }],
      diagnostics: { reason: "not_function_start", function_start: "game_sim.exe+0x1750", offset: 16 },
    });
    expect(JSON.stringify(e)).toContain("probe: true");
    expect(world.calls).toEqual([]);
    expectToolSuccess(await call(b, "hook_function", { ...PHYSICS, probe: true, capture: [], returns: "void" }));
    expect(world.calls.map((c) => c.method)).toEqual(["hookInstall"]);
    world.functionStartRva = 0x1760; // at the start: allowed
    expectToolSuccess(await call(b, "hook_function", PHYSICS));
  });

  it("a cancel that lands while the agent installs stops the installed hook again (LIFE-6)", async () => {
    const world = new FakeWorld();
    const b = await start(world);
    const entered = createGate();
    const reply = createGate();
    world.agentOverride = (m) => {
      if (m !== "hookInstall") return undefined;
      return (async () => {
        void entered.wait();
        await reply.wait();
        return ok(hookInstallResult(1));
      })();
    };
    const controller = new AbortController();
    const pending = b.client
      .callTool({ name: "hook_function", arguments: PHYSICS }, { signal: controller.signal })
      .catch(() => null);
    await entered.entered;
    controller.abort(); // the client cancels after the install request was dispatched
    await new Promise((resolve) => setTimeout(resolve, 50));
    reply.release();
    await pending;
    await vi.waitFor(() => expect(world.calls.map((c) => c.method)).toEqual(["hookInstall", "instrumentStop"]), {
      interval: 25,
    });
    // the install ran on a detached op, so the compensating stop did not inherit the caller's abort
    expect(world.calls.every((c) => c.opAborted === false)).toBe(true);
    expect((world.calls[1]?.params as { id: string }).id).toBe(hookInstallResult(1).instrument_id);
    expect(world.recordings.size).toBe(0);
  });

  it("caps active instruments at 16 per session", async () => {
    const world = new FakeWorld();
    for (let i = 0; i < 16; i++) world.addHookRecording([], PHYSICS_DECODERS, "active");
    const b = await start(world);
    const e = parseToolError(await call(b, "hook_function", PHYSICS));
    expect(e.code).toBe("resource_constraint");
    expect(world.calls).toEqual([]);
  });

  it("rejects an emulation-free unknown session with session_not_found", async () => {
    const b = await start(new FakeWorld());
    expect(parseToolError(await call(b, "hook_function", { ...PHYSICS, session_id: OTHER_SESSION })).code).toBe(
      "session_not_found",
    );
  });
});

describe("wait", () => {
  it("is satisfied at once when the listed recordings already finished, and repeats identically", async () => {
    const world = new FakeWorld();
    const rec = world.addHookRecording(physicsRows(2), PHYSICS_DECODERS);
    const b = await start(world);
    const first = expectToolSuccess(await call(b, "wait", { session_id: SESSION_ID, ids: [rec.id] }));
    const second = expectToolSuccess(await call(b, "wait", { session_id: SESSION_ID, ids: [rec.id] }));
    expect(first).toMatchObject({
      satisfied: true,
      reason: "condition",
      evidence_id: null,
      target: { state: "running" },
    });
    expect((first["recordings"] as unknown[])[0]).toMatchObject({
      state: "finished",
      events: 2,
      summary: { recorded: 2 },
    });
    expect({ ...second, waited_ms: 0 }).toEqual({ ...first, waited_ms: 0 });
    expect(world.recorded).toEqual([]);
  });

  it("times out as a poll (not an error) and reports target_exited when the process is gone", async () => {
    const world = new FakeWorld();
    const rec = world.addHookRecording([], PHYSICS_DECODERS, "active");
    const b = await start(world);
    const poll = expectToolSuccess(
      await call(b, "wait", { session_id: SESSION_ID, until: "events", ids: [rec.id], min_events: 5, timeout_ms: 40 }),
    );
    expect(poll).toMatchObject({ satisfied: false, reason: "timeout" });
    world.exited = true;
    world.state = "exited";
    const gone = expectToolSuccess(await call(b, "wait", { session_id: SESSION_ID, ids: [rec.id], timeout_ms: 1000 }));
    expect(gone).toMatchObject({
      satisfied: false,
      reason: "target_exited",
      target: { state: "exited", exit: { code: 0 } },
    });
    const exit = expectToolSuccess(await call(b, "wait", { session_id: SESSION_ID, until: "exit", timeout_ms: 1000 }));
    expect(exit).toMatchObject({ satisfied: true, reason: "condition" });
  });

  it("a done wait on a target that just exited lets its recordings end and reports them finished (WP18)", async () => {
    const world = new FakeWorld();
    const rec = world.addHookRecording(physicsRows(2), PHYSICS_DECODERS, "active");
    const b = await start(world);
    world.exited = true;
    world.state = "exited";
    // the registry ends the recording a moment after the exit (exit-time final batch, then end with target_exited)
    const ending = setTimeout(() => {
      rec.state = "finished";
      rec.endReason = "target_exited";
    }, 100);
    try {
      const out = expectToolSuccess(await call(b, "wait", { session_id: SESSION_ID, ids: [rec.id], timeout_ms: 5000 }));
      expect(out).toMatchObject({ satisfied: true, reason: "condition", target: { state: "exited" } });
      expect((out["recordings"] as unknown[])[0]).toMatchObject({ state: "finished", end_reason: "target_exited" });
      expect(out["waited_ms"] as number).toBeLessThan(2000);
    } finally {
      clearTimeout(ending);
    }
  });

  it("until exit waits for the exit report that follows Frida's process-terminated detach", async () => {
    const world = new FakeWorld();
    const b = await start(world);
    // liveness() already says exited (detach), but the session is still running until the root-exit report lands
    world.exited = true;
    world.exitReported = false;
    const report = setTimeout(() => {
      world.exitReported = true;
      world.state = "exited";
    }, 60);
    try {
      const exit = expectToolSuccess(
        await call(b, "wait", { session_id: SESSION_ID, until: "exit", timeout_ms: 5000 }),
      );
      expect(exit).toMatchObject({
        satisfied: true,
        reason: "condition",
        target: { state: "exited", exit: { code: 0, code_hex: "0x0" } },
      });
      expect(exit["waited_ms"]).toBeGreaterThanOrEqual(40);
    } finally {
      clearTimeout(report);
    }
  });

  it("waits for output on owned targets only and validates its condition fields", async () => {
    const world = new FakeWorld();
    world.outputText = "READY pid=1\nFRAME 60 speed=1.0\n";
    const b = await start(world);
    expect(
      expectToolSuccess(
        await call(b, "wait", { session_id: SESSION_ID, until: "output", output_contains: "FRAME 60" }),
      ),
    ).toMatchObject({ satisfied: true, reason: "condition" });
    expect(parseToolError(await call(b, "wait", { session_id: SESSION_ID, until: "events" })).code).toBe(
      "invalid_request",
    );
    world.ownership = "attached";
    const attached = parseToolError(
      await call(b, "wait", { session_id: SESSION_ID, until: "output", output_contains: "x" }),
    );
    expect(attached.code).toBe("invalid_request");
    expect(JSON.stringify(attached.details)).toContain("BEA-spawned");
  });

  it("resolves scan ids through the HandleRegistry and unknown ids to reference_not_found", async () => {
    const world = new FakeWorld();
    const b = await start(world);
    const scan: HandleKindSpec = {
      kind: "scan",
      owns: (id) => id === "scan_0000000a",
      list: () => [],
      get: (id) =>
        id === "scan_0000000a"
          ? { id, kind: "scan", sessionId: SESSION_ID, state: "ready", summary: { count: 12, value_type: "f32" } }
          : undefined,
      doneCondition: () => null,
      stop: async () => ({ ok: true, value: { id: "scan_0000000a", kind: "scan", status: "released" } }),
    };
    b.app.services.handles.register(scan);
    const out = expectToolSuccess(await call(b, "wait", { session_id: SESSION_ID, ids: ["scan_0000000a"] }));
    expect(out).toMatchObject({ satisfied: true, scans: [{ scan_id: "scan_0000000a", state: "ready", count: 12 }] });
    const missing = parseToolError(await call(b, "wait", { session_id: SESSION_ID, ids: ["rec_deadbeef"] }));
    expect(missing.code).toBe("reference_not_found");
  });
});

describe("stop_instrumentation", () => {
  it("stops a hook: agent instrumentStop, effect reverted, registry end, stream manifest, stop evidence", async () => {
    const world = new FakeWorld();
    const b = await start(world);
    const installed = expectToolSuccess(await call(b, "hook_function", PHYSICS));
    const id = (installed["instrument"] as { recording_id: string }).recording_id;
    const out = expectToolSuccess(await call(b, "stop_instrumentation", { session_id: SESSION_ID, ids: [id] }));
    expect(out).toMatchObject({
      stopped: [{ id, kind: "hook", status: "reverted", events: 0, dropped: 0 }],
      active_remaining: 0,
      predicate_type: "bea.instrument.stop",
    });
    expect((out["stopped"] as { manifest_evidence_id: string }[])[0]?.manifest_evidence_id).toMatch(
      /^ev_[0-9a-f]{64}$/u,
    );
    expect(world.calls.find((c) => c.method === "instrumentStop")?.params).toEqual({ id: "h1", final_flush: true });
    expect(world.transitions.map((t) => t.to)).toEqual(["reverted"]);
    expect(world.endedStreams).toEqual(["s1"]);
    const again = expectToolSuccess(await call(b, "stop_instrumentation", { session_id: SESSION_ID, ids: [id] }));
    expect(again["stopped"]).toMatchObject([{ id, status: "already_ended" }]);
  });

  it("reports a failed revert as retryable effect_unreverted", async () => {
    const world = new FakeWorld();
    const b = await start(world);
    expectToolSuccess(await call(b, "hook_function", PHYSICS));
    world.agentOverride = (m, p) =>
      m === "instrumentStop"
        ? {
            ok: true,
            value: {
              stopped: [],
              not_found: [],
              unreverted: [{ id: (p as { id: string }).id, detail: "bytes differ" }],
            },
          }
        : undefined;
    const e = parseToolError(await call(b, "stop_instrumentation", { session_id: SESSION_ID, all: true }));
    expect(e.code).toBe("effect_unreverted");
    expect(e.retryable).toBe(true);
    expect(world.transitions.map((t) => t.to)).toEqual(["revert-failed"]);
  });

  it("refuses built-in recordings, needs exactly one of ids/all, and releases scans through their handle kind", async () => {
    const world = new FakeWorld();
    const builtin = world.registry.create({
      sessionId: SESSION_ID,
      kind: "exceptions",
      agentInstrumentId: null,
      agentStream: "s:exceptions",
      streamId: null,
      effectId: null,
      durationMs: null,
      maxEvents: null,
      startsAtResume: false,
      decoders: null,
    });
    const b = await start(world);
    const e = parseToolError(await call(b, "stop_instrumentation", { session_id: SESSION_ID, ids: [builtin.id] }));
    expect(e.code).toBe("invalid_request");
    expect(JSON.stringify(e.details)).toContain("close_session");
    expect(parseToolError(await call(b, "stop_instrumentation", { session_id: SESSION_ID })).code).toBe(
      "invalid_request",
    );
    let released = false;
    b.app.services.handles.register({
      kind: "scan",
      owns: (id) => id.startsWith("scan_"),
      list: () =>
        released ? [] : [{ id: "scan_00000001", kind: "scan", sessionId: SESSION_ID, state: "ready", summary: {} }],
      get: (id) =>
        id === "scan_00000001"
          ? { id, kind: "scan", sessionId: SESSION_ID, state: released ? "released" : "ready", summary: {} }
          : undefined,
      doneCondition: () => null,
      stop: async (_s, id) => {
        released = true;
        return { ok: true, value: { id, kind: "scan", status: "released" } };
      },
    });
    const out = expectToolSuccess(await call(b, "stop_instrumentation", { session_id: SESSION_ID, all: true }));
    expect(out).toMatchObject({
      stopped: [{ id: "scan_00000001", kind: "scan", status: "released" }],
      active_remaining: 0,
    });
  });
});

describe("query_events", () => {
  const setup = async (state: "finished" | "active" = "finished") => {
    const world = new FakeWorld();
    const rec = world.addHookRecording(physicsRows(6), PHYSICS_DECODERS, state);
    return { world, rec, b: await start(world) };
  };

  it("pages rows as columns, newest first, with chosen fields and :bits", async () => {
    const { rec, b } = await setup();
    const out = expectToolSuccess(
      await call(b, "query_events", {
        recording_id: rec.id,
        view: "rows",
        fields: ["dt", "dt:bits", "speed@leave", "ret"],
        order: "desc",
        limit: 2,
      }),
    );
    expect(out["columns"]).toEqual(["seq", "dt", "dt:bits", "speed@leave", "ret"]);
    const rows = out["rows"] as unknown[][];
    expect(rows.map((r) => r[0])).toEqual([6, 5]);
    expect(rows[0]?.[1]).toBe(0.016666668);
    expect(rows[0]?.[2]).toBe("0x3c888889");
    expect(rows.every((r) => r[3] === r[4])).toBe(true); // ret == speed@leave
    expect(out["page"]).toEqual({ offset: 0, limit: 2, total: 6, next_offset: 2 });
    expect((out["fields"] as { name: string }[]).map((f) => f.name)).toEqual([
      "seq",
      "t_ms",
      "tid",
      "depth",
      "caller",
      "dur_us",
      "car",
      "dt",
      "speed",
      "speed@leave",
      "ret",
    ]);
    expect(out).toMatchObject({ predicate_type: "bea.events.query", coverage: { status: "complete" } });
  });

  it("groups, filters and computes stats", async () => {
    const { rec, b } = await setup();
    const group = expectToolSuccess(
      await call(b, "query_events", { recording_id: rec.id, view: "group", group_by: ["dt"] }),
    );
    expect(group["columns"]).toEqual(["dt", "count", "first_seq", "last_seq"]);
    expect(group["rows"]).toEqual([[0.016666668, 6, 1, 6]]);
    const where = expectToolSuccess(
      await call(b, "query_events", {
        recording_id: rec.id,
        view: "rows",
        fields: ["tid"],
        where: [{ field: "tid", op: "eq", value: 101 }],
      }),
    );
    expect((where["page"] as { total: number }).total).toBe(3);
    const stats = expectToolSuccess(
      await call(b, "query_events", { recording_id: rec.id, view: "stats", fields: ["speed@leave"] }),
    );
    expect(stats["stats"]).toMatchObject([{ field: "speed@leave", count: 6, distinct: 6, min: 8.0625, max: 8.375 }]);
  });

  it("sends the digest once: never on rows/stats pages, only as the summary view's top-level summary (UX-2)", async () => {
    const { rec, b } = await setup("finished");
    const rows = expectToolSuccess(await call(b, "query_events", { recording_id: rec.id, view: "rows", limit: 2 }));
    expect(rows["recording"]).not.toHaveProperty("summary");
    const stats = expectToolSuccess(
      await call(b, "query_events", { recording_id: rec.id, view: "stats", fields: ["dt"] }),
    );
    expect(stats["recording"]).not.toHaveProperty("summary");
    const summary = expectToolSuccess(await call(b, "query_events", { recording_id: rec.id, view: "summary" }));
    expect(summary["summary"]).toMatchObject({ recorded: 6 });
    expect(summary["recording"]).not.toHaveProperty("summary");
  });

  it("returns the summary view, marks active recordings partial and lists fields on unknown names", async () => {
    const { rec, b } = await setup("active");
    const summary = expectToolSuccess(await call(b, "query_events", { recording_id: rec.id }));
    expect(summary).toMatchObject({
      view: "summary",
      rows: [],
      summary: { recorded: 6, threads: [{ calls: 3 }, { calls: 3 }], duration_us: { max: 3 } },
      coverage: { status: "partial", reasons: ["recording_active"] },
    });
    const bad = parseToolError(await call(b, "query_events", { recording_id: rec.id, view: "rows", fields: ["nope"] }));
    expect(bad.code).toBe("invalid_request");
    expect(JSON.stringify(bad.details)).toContain("speed@leave");
  });

  it("pages a host NDJSON row stream by stream_id and validates the id choice", async () => {
    const world = new FakeWorld();
    const st = `st_${"a".repeat(64)}` as StId;
    world.hostStreams.set(
      st,
      [1, 2, 3].map((i) => ({ seq: i, module_map_epoch: null, fields: { vector: i, ret: i * 2, ok: i !== 2 } })),
    );
    const b = await start(world);
    const out = expectToolSuccess(
      await call(b, "query_events", { stream_id: st, view: "rows", where: [{ field: "ok", op: "eq", value: true }] }),
    );
    expect(out).toMatchObject({ recording: null, stream_id: st, columns: ["seq", "vector", "ret", "ok"] });
    expect(out["rows"]).toEqual([
      [1, 1, 2, true],
      [3, 3, 6, true],
    ]);
    expect(parseToolError(await call(b, "query_events", { stream_id: st, recording_id: "rec_00000001" })).code).toBe(
      "invalid_request",
    );
    expect(parseToolError(await call(b, "query_events", { recording_id: "rec_0000ffff" })).code).toBe(
      "reference_not_found",
    );
  });
});
