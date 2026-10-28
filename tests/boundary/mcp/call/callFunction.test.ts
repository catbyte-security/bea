import { afterEach, describe, expect, it } from "vitest";

import { manualClock } from "../../../../src/domain/clock.js";
import type { CallFunctionParams } from "../../../../src/shared/agentProtocol.js";
import { connectInMemoryBea, type InMemoryBea } from "../../../support/mcp/inMemory.js";
import { expectToolSuccess, parseToolError } from "../../../support/mcp/parseToolError.js";
import {
  ATTACHED_ID,
  createFakeAgent,
  fakeAddress,
  fakeEvidence,
  fakeLiveSession,
  fakeSessions,
  SESSION_ID,
  type FakeAgent,
  type FakeAgentOptions,
} from "./support/callFakes.js";

/** call_function over the production MCP server (invokeTool + Delivery) with WP11-local fakes (DESIGN §8.2 mcp-boundary). */
let bea: InMemoryBea | null = null;
afterEach(async () => {
  await bea?.close();
  bea = null;
});

const start = async (
  options: {
    agent?: FakeAgentOptions;
    ownership?: "owned" | "attached";
    paused?: boolean;
    env?: Record<string, string>;
    clock?: ReturnType<typeof manualClock>;
  } = {},
) => {
  const agent = createFakeAgent(options.agent);
  const evidence = fakeEvidence();
  const address = fakeAddress();
  const owned = fakeLiveSession(agent, { paused: options.paused ?? false });
  const attached = fakeLiveSession(agent, { id: ATTACHED_ID, ownership: "attached" });
  bea = await connectInMemoryBea({
    services: { sessions: fakeSessions([owned, attached]), evidence, address },
    ...(options.env === undefined ? {} : { env: options.env }),
    ...(options.clock === undefined ? {} : { clock: options.clock }),
  });
  return { client: bea.client, agent, evidence, address };
};

const call = async (client: InMemoryBea["client"], args: Record<string, unknown>) =>
  client.callTool({ name: "call_function", arguments: { session_id: SESSION_ID, ...args } });

const ADD = { args: [{ type: "i32" }, { type: "i32" }], returns: "i32" };
const callParams = (agent: FakeAgent): CallFunctionParams[] =>
  agent.calls.filter((c) => c.method === "callFunction").map((c) => c.params as CallFunctionParams);

describe("call_function: single calls", () => {
  it("runs one call through the SEH-frame executor and returns the recorded envelope", async () => {
    const { client, agent, evidence } = await start();
    const out = expectToolSuccess(
      await call(client, { address: "live_fixture.exe!add_ints", signature: ADD, args: [2, 3] }),
    );
    expect(out).toMatchObject({
      mode: "single",
      target: { va: "0x7ff600001500", module: "live_fixture.exe", rva: "0x1500" },
      fp: { mxcsr: "0x1f80", fpcw: "0x27f", source: "windows-default" },
      exception_model: "seh-frame",
      callee_exceptions: 0,
      call: { status: "returned", ret: { type: "i32", bits: "0x5", value: 5 }, fault: null },
      block_coverage: null,
      predicate_type: "bea.call.oracle",
      confidence: "observed",
      authority: "live-process",
    });
    expect(out["limitations"]).toEqual(
      expect.arrayContaining([expect.stringMatching(/Windows default FP environment/u)]),
    );
    expect(out["effects_applied"]).toHaveLength(1);
    expect(evidence.effectDrafts[0]).toMatchObject({
      kind: "function-called",
      applied_by: "call_function",
      target: { size: null, threads: [4242] },
    });
    expect(evidence.records).toHaveLength(1);
    expect(evidence.records[0]?.effects).toEqual(out["effects_applied"]);
    const [params] = callParams(agent);
    expect(params?.plan.slots).toEqual([
      { reg: "rcx", source: { kind: "column", column: "arg0" } },
      { reg: "rdx", source: { kind: "column", column: "arg1" } },
    ]);
    expect(params?.thread).toEqual({ kind: "agent" });
    expect(params?.fp).toEqual({ mxcsr: 0x1f80, fpcw: 0x27f });
  });

  it("decodes out buffers and typed fields of a scratch struct (template from init_from bytes, read once)", async () => {
    const memory = new Map([[0x1f3a5c40n, Uint8Array.from([0, 0, 0xa0, 0x41, 7, 0, 0, 0])]]);
    const { client, agent } = await start({ agent: { memory } });
    const out = expectToolSuccess(
      await call(client, {
        address: "live_fixture.exe!bump_speed",
        signature: { args: [{ type: "buffer_ptr", buffer: "car" }], returns: "f32" },
        buffers: [
          {
            name: "car",
            size: 8,
            init_from: "0x1f3a5c40",
            out: true,
            fields: [
              { name: "speed", offset: 0, type: "f32" },
              { name: "counter", offset: 4, type: "i32" },
            ],
          },
        ],
      }),
    );
    expect(out["call"]).toMatchObject({
      status: "returned",
      ret: { type: "f32", bits: "0x41a80000", value: 21 },
      outputs: {
        "car.speed": { type: "f32", bits: "0x41a80000", value: 21 },
        "car.counter": { type: "i32", bits: "0x7", value: 7 },
      },
      out_buffers: { car: { address: "0x100000", bytes: 8, hex: "0000a84107000000", truncated: false } },
    });
    expect(agent.calls.filter((c) => c.method === "readMemory")).toHaveLength(1);
    expect(callParams(agent)[0]?.plan.buffers[0]?.template).toBe("0000a04107000000");
  });

  it("reports an unreadable init_from source as memory_access_failed before any call", async () => {
    const { client, agent } = await start();
    const error = parseToolError(
      await call(client, {
        address: "live_fixture.exe!bump_speed",
        signature: { args: [{ type: "buffer_ptr", buffer: "car" }], returns: "f32" },
        buffers: [{ name: "car", size: 8, init_from: "0x2000" }],
      }),
    );
    expect(error.code).toBe("memory_access_failed");
    expect(callParams(agent)).toHaveLength(0);
  });

  it("returns a fault as a result (code, access, address) and the next call still works", async () => {
    const { client } = await start();
    const out = expectToolSuccess(
      await call(client, {
        address: "live_fixture.exe!touch_counter",
        signature: { args: [{ type: "ptr" }], returns: "void" },
        args: [0],
      }),
    );
    expect(out["call"]).toMatchObject({
      status: "fault",
      ret: null,
      fault: {
        type: "access-violation",
        code: "0xc0000005",
        memory: { operation: "write", address: "0x4" },
        address: { at: "live_fixture.exe+0x1704" },
        insn: null,
      },
    });
    const again = expectToolSuccess(
      await call(client, { address: "live_fixture.exe!add_ints", signature: ADD, args: [40, 2] }),
    );
    expect(again["call"]).toMatchObject({ status: "returned", ret: { value: 42 } });
  });

  it("refuses an attached target without call_attached BEFORE any agent RPC or address resolution", async () => {
    const { client, agent, address } = await start();
    const error = parseToolError(
      await client.callTool({
        name: "call_function",
        arguments: { session_id: ATTACHED_ID, address: "live_fixture.exe!add_ints", signature: ADD, args: [1, 2] },
      }),
    );
    expect(error.code).toBe("capability_unavailable");
    expect(error.details).toMatchObject({ gate: "call_attached" });
    expect(agent.calls).toHaveLength(0);
    expect(address.resolved).toHaveLength(0);
  });

  it("calls an attached target when the server opted in (BEA_ALLOW_CALL_ATTACHED=1)", async () => {
    const { client } = await start({ env: { BEA_ALLOW_CALL_ATTACHED: "1" } });
    const out = expectToolSuccess(
      await client.callTool({
        name: "call_function",
        arguments: { session_id: ATTACHED_ID, address: "live_fixture.exe!add_ints", signature: ADD, args: [1, 2] },
      }),
    );
    expect(out["call"]).toMatchObject({ ret: { value: 3 } });
  });
});

describe("call_function: batches", () => {
  it("returns inline columns up to inline_limit", async () => {
    const { client } = await start();
    const out = expectToolSuccess(
      await call(client, {
        address: "live_fixture.exe!four_floats",
        signature: {
          args: [
            { type: "f32", name: "a" },
            { type: "f32", default: 2 },
            { type: "f32", default: 3 },
            { type: "f32", default: 4 },
          ],
          returns: "f32",
        },
        vectors: { columns: { a: [1, "0x7fc12345", "-0"] } },
      }),
    );
    expect(out["batch"]).toMatchObject({
      offset: 0,
      vectors: 3,
      completed: 3,
      returned: 3,
      by_status: { returned: 3 },
      status: ["returned", "returned", "returned"],
      stream_id: null,
      preview: null,
      continuation: null,
      columns: {
        ret: { bits: ["0x449a4000", expect.stringMatching(/^0x7fc/u), "0x436a0000"], value: [1234, "NaN", 234] },
      },
    });
  });

  it("writes a call-batch row stream above inline_limit and returns a preview", async () => {
    const { client, evidence } = await start();
    const n = 100;
    const out = expectToolSuccess(
      await call(client, {
        address: "live_fixture.exe!add_ints",
        signature: ADD,
        vectors: {
          columns: { arg0: Array.from({ length: n }, (_, i) => i), arg1: Array.from({ length: n }, () => 1) },
        },
      }),
    );
    const batch = out["batch"] as Record<string, unknown>;
    expect(batch).toMatchObject({ completed: n, columns: null, status: null });
    expect(batch["stream_id"]).toMatch(/^st_[0-9a-f]{64}$/u);
    expect((batch["preview"] as { first: unknown[]; last: unknown[] }).first[0]).toEqual({
      i: 0,
      s: "returned",
      r: "0x1",
      f: {},
      e: null,
    });
    expect((batch["preview"] as { last: { i: number }[] }).last.map((r) => r.i)).toEqual([
      92, 93, 94, 95, 96, 97, 98, 99,
    ]);
    expect(evidence.streamsOpened).toHaveLength(1);
    expect(evidence.streamsOpened[0]?.spec.source).toMatchObject({ kind: "call-batch", channel: "call_function" });
    expect(evidence.streamsOpened[0]?.rows).toHaveLength(n);
    expect(evidence.streamsOpened[0]?.ended).toBe(true);
    expect(evidence.records[0]?.evidence_links).toHaveLength(1);
  });

  it("chunks RPCs on next_offset and continues with vector_offset when the deadline nears", async () => {
    const clock = manualClock();
    const { client, agent } = await start({ clock, agent: { perRpc: 10, afterRpc: () => clock.advanceMs(12_000) } });
    const out = expectToolSuccess(
      await call(client, {
        address: "live_fixture.exe!add_ints",
        signature: ADD,
        timeout_ms: 30_000,
        vectors: {
          columns: { arg0: Array.from({ length: 40 }, (_, i) => i), arg1: Array.from({ length: 40 }, () => 0) },
        },
      }),
    );
    const batch = out["batch"] as Record<string, unknown>;
    expect(callParams(agent).map((p) => p.vectors.offset)).toEqual([0, 10, 20]);
    expect(batch).toMatchObject({ completed: 30, continuation: { vector_offset: 30 } });
    expect(out["coverage"]).toMatchObject({ status: "partial", reasons: ["deadline"] });
    const next = expectToolSuccess(
      await call(client, {
        address: "live_fixture.exe!add_ints",
        signature: ADD,
        vector_offset: 30,
        vectors: {
          columns: { arg0: Array.from({ length: 40 }, (_, i) => i), arg1: Array.from({ length: 40 }, () => 0) },
        },
      }),
    );
    expect(next["batch"]).toMatchObject({
      offset: 30,
      vectors: 10,
      completed: 10,
      continuation: null,
      columns: { ret: { bits: ["0x1e", "0x1f", "0x20", "0x21", "0x22", "0x23", "0x24", "0x25", "0x26", "0x27"] } },
    });
  });

  it("generates seeded vectors (the same rows on every call)", async () => {
    const { client, agent } = await start();
    const args = {
      address: "live_fixture.exe!add_ints",
      signature: ADD,
      generate: { seed: 7, count: 5, columns: { arg0: { dist: "uniform", min: -5, max: 5 }, arg1: { dist: "edge" } } },
    };
    expectToolSuccess(await call(client, args));
    expectToolSuccess(await call(client, args));
    const [first, second] = callParams(agent);
    expect(first?.vectors.columns).toEqual(second?.vectors.columns);
    expect(first?.vectors.columns["arg1"]).toEqual([
      "0x0",
      "0x1",
      "0xffffffffffffffff",
      "0xffffffff80000000",
      "0x7fffffff",
    ]);
  });
});

describe("call_function: failures before and during a batch", () => {
  it("a thread_at hook that cannot be installed applies no function-called effect (EMU-14)", async () => {
    const { client, evidence } = await start({
      agent: {
        failOnRpc: {
          n: 1,
          error: {
            _tag: "HookInstallFailed",
            message: "unable to intercept function at 00007FF66CF01760",
            address: "0x7ff66cf01760",
            attempts: ["default"],
            frida_message: "unable to intercept function at 00007FF66CF01760",
            alternatives: [],
          },
        },
      },
    });
    const error = parseToolError(
      await call(client, {
        address: "live_fixture.exe!add_ints",
        signature: ADD,
        vectors: { columns: { arg0: [1], arg1: [1] } },
      }),
    );
    expect(error.code).toBe("instrumentation_failed");
    expect(error.details["effects_applied"] ?? []).toEqual([]);
    expect(evidence.records).toEqual([]);
  });

  it("records partial evidence and reports provider_timeout when a later chunk times out", async () => {
    const { client, evidence } = await start({
      agent: {
        perRpc: 2,
        failOnRpc: { n: 2, error: { _tag: "Timeout", message: "x", timeout_ms: 5000, phase: "rpc" } },
      },
    });
    const error = parseToolError(
      await call(client, {
        address: "live_fixture.exe!add_ints",
        signature: ADD,
        vectors: { columns: { arg0: [1, 2, 3, 4], arg1: [1, 1, 1, 1] } },
      }),
    );
    expect(error.code).toBe("provider_timeout");
    expect(error.details["effects_applied"]).toHaveLength(1);
    expect(error.details["partial_observation"]).toMatchObject({ kind: "retained-evidence" });
    expect(evidence.records[0]?.coverage).toMatchObject({ status: "partial" });
  });
});

describe("call_function: coverage and the steal fallback", () => {
  it("stores per-call block coverage as a bea.coverage/1 blob and summarizes it by function", async () => {
    const { client, evidence } = await start();
    const out = expectToolSuccess(
      await call(client, {
        address: "live_fixture.exe!add_ints",
        signature: ADD,
        vectors: { columns: { arg0: [1, 2], arg1: [3, 4] } },
        coverage: true,
      }),
    );
    expect(out["block_coverage"]).toMatchObject({
      blocks: 2,
      modules: 1,
      functions: [{ func: "live_fixture.exe+0x1500", blocks: 2, vectors: 2 }],
    });
    expect(evidence.records[0]?.blobs.map((b) => b.role)).toEqual(["coverage"]);
  });

  it("reports the steal fallback (no registered frame) as partial coverage with CALL_SEH_UNAVAILABLE", async () => {
    const { client } = await start({ agent: { exceptionModel: "steal" } });
    const out = expectToolSuccess(
      await call(client, { address: "live_fixture.exe!add_ints", signature: ADD, args: [1, 2] }),
    );
    expect(out["exception_model"]).toBe("steal");
    expect(out["coverage"]).toMatchObject({ status: "partial", reasons: ["callee_handlers_not_honoured"] });
    expect(out["limitations"]).toEqual(
      expect.arrayContaining([expect.stringMatching(/could not register its exception frame/u)]),
    );
  });
});

describe("call_function: threads, FP environment and refusals", () => {
  it("fp auto reads a known thread's MXCSR/FPCW (status bits cleared) and runs on that thread", async () => {
    const { client, agent } = await start({ agent: { threads: new Map([[77, { mxcsr: "0x9fe3", fpcw: "0x37f" }]]) } });
    const out = expectToolSuccess(
      await call(client, { address: "live_fixture.exe!add_ints", signature: ADD, args: [1, 1], thread_id: 77 }),
    );
    expect(out["fp"]).toEqual({ mxcsr: "0x9fc0", fpcw: "0x37f", source: "thread" });
    expect(out["limitations"]).not.toEqual(expect.arrayContaining([expect.stringMatching(/Windows default FP/u)]));
    const params = callParams(agent)[0];
    expect(params?.fp).toEqual({ mxcsr: 0x9fc0, fpcw: 0x37f });
    expect(params?.thread).toMatchObject({ kind: "thread", tid: 77 });
  });

  it("runs at a safe point with thread_at (hook mode) restricted to thread_id", async () => {
    const { client, agent } = await start({ agent: { threads: new Map([[5, { mxcsr: "0x1f80", fpcw: "0x27f" }]]) } });
    expectToolSuccess(
      await call(client, {
        address: "live_fixture.exe!add_ints",
        signature: ADD,
        args: [1, 1],
        thread_at: "live_fixture.exe!four_floats",
        thread_id: 5,
      }),
    );
    expect(callParams(agent)[0]?.thread).toMatchObject({ kind: "hook", at: "0x7ff600001600", tid: 5 });
  });

  it("maps an agent ThreadBusy (thread in a syscall) to invalid_state", async () => {
    const { client } = await start({
      agent: { failOnRpc: { n: 1, error: { _tag: "ThreadBusy", message: "x", thread_id: 9, reason: "in-syscall" } } },
    });
    const error = parseToolError(
      await call(client, {
        address: "live_fixture.exe!add_ints",
        signature: ADD,
        args: [1, 1],
        thread_id: 9,
        fp: { source: "windows-default" },
      }),
    );
    expect(error.code).toBe("invalid_state");
    expect(error.details).toMatchObject({ state: "thread-in-syscall" });
  });

  it("refuses thread_id while the target is paused", async () => {
    const { client, agent } = await start({ paused: true });
    const error = parseToolError(
      await call(client, { address: "live_fixture.exe!add_ints", signature: ADD, args: [1, 1], thread_id: 3 }),
    );
    expect(error.code).toBe("invalid_request");
    expect(error.details["issues"]).toEqual([expect.objectContaining({ path: "thread_id" })]);
    expect(agent.calls).toHaveLength(0);
  });

  it.each([
    [{ args: [1, 1], vectors: { count: 2 } }, ""],
    [{ args: [1, 1], hooks: "observe" }, "hooks"],
    [{ fields: { "car.speed": 1 } }, "car.speed"],
    [{ args: [1, 1], vector_offset: 3 }, "vector_offset"],
  ])("refuses an invalid request %j", async (extra, path) => {
    const { client, agent } = await start();
    const error = parseToolError(
      await call(client, { address: "live_fixture.exe!add_ints", signature: ADD, ...extra }),
    );
    expect(error.code).toBe("invalid_request");
    expect((error.details["issues"] as { path: string }[])[0]?.path).toBe(path);
    expect(callParams(agent)).toHaveLength(0);
  });

  it("enforces the aggregate vector budget (CT-B3)", async () => {
    const { client } = await start();
    const cells = Array.from({ length: 100_001 }, () => 1);
    const error = parseToolError(
      await call(client, {
        address: "live_fixture.exe!add_ints",
        signature: ADD,
        vectors: { columns: { arg0: cells, arg1: cells } },
      }),
    );
    expect(error.code).toBe("invalid_request");
    expect(JSON.stringify(error.details)).toMatch(/200000 vector cells/u);
  });
});
