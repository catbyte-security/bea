import { describe, expect, it } from "vitest";

import type { BeaCore } from "../../../src/application/BeaApplication.js";
import { createOracleCallPort } from "../../../src/application/call/OracleService.js";
import { classifyWin64 } from "../../../src/domain/callModel/classify.js";
import { outLayout } from "../../../src/domain/callModel/decode.js";
import {
  batchColumns,
  encodeColumns,
  finalizeVectors,
  typeColumns,
  type BufferInput,
  type SignatureInput,
} from "../../../src/domain/callModel/normalize.js";
import { systemClock } from "../../../src/domain/clock.js";
import { Deadline } from "../../../src/domain/deadline.js";
import type { BeaError } from "../../../src/domain/errors/beaError.js";
import { gateDisabled } from "../../../src/domain/errors/constructors.js";
import { err, ok } from "../../../src/domain/result.js";
import type { AgentRpc } from "../../../src/ports/agentRpc.js";
import type { OracleBatchRequest } from "../../../src/ports/emu.js";
import type { OperationContext } from "../../../src/ports/sessions.js";
import {
  BASE,
  createFakeAgent,
  type FakeAgent,
  fakeAddress,
  fakeEvidence,
  fakeLiveSession,
  RVAS,
} from "../../boundary/mcp/call/support/callFakes.js";

/** OracleCallPort.callPlanBatch: the diff_function live leg's entry (S5 §9.4), with WP11-local fakes. */
const core = (allowAttached: boolean): BeaCore =>
  ({
    clock: systemClock,
    gates: {
      isEnabled: () => allowAttached,
      require: (gate: "call_attached", operation: string) =>
        allowAttached ? ok(undefined) : err(gateDisabled(operation, gate)),
      requireUnlessOwned: (gate: "call_attached", operation: string, ownership: string) =>
        ownership === "owned" || allowAttached ? ok(undefined) : err(gateDisabled(operation, gate)),
    },
  }) as unknown as BeaCore;

const op = (): OperationContext => ({
  opId: 1,
  name: "diff_function",
  signal: new AbortController().signal,
  deadline: Deadline.after(30_000),
});

const request = (
  signature: SignatureInput,
  buffers: readonly BufferInput[],
  columns: Record<string, readonly (number | string)[]>,
  fn: keyof typeof RVAS,
): OracleBatchRequest => {
  const input = batchColumns(Object.keys(columns).length === 0 ? { count: 1 } : { columns });
  if (!input.ok) throw new Error("columns");
  const classified = classifyWin64({ signature, buffers, supplied: new Set(Object.keys(columns)) });
  if (!classified.ok) throw new Error(JSON.stringify(classified.error));
  const typed = typeColumns(classified.value.plan, input.value, () => undefined, classified.value.arrayDefaults);
  if (!typed.ok) throw new Error("typed");
  const va = BASE + RVAS[fn];
  return {
    target: { va: `0x${va.toString(16)}`, module: "live_fixture.exe", rva: `0x${RVAS[fn].toString(16)}` },
    plan: classified.value.plan,
    vectors: finalizeVectors(encodeColumns(classified.value.plan, typed.value), { kind: "inline" }),
    offset: 0,
    fp: { mxcsr: 0x1f80, fpcw: 0x27f, source: "windows-default", threadId: null },
    thread: "agent",
    chunk: 1024,
    coverage: false,
    deadlineAt: performance.now() + 30_000,
  };
};

const ADD: SignatureInput = { args: [{ type: "i32" }, { type: "i32" }], returns: "i32", variadic: false };
const BUMP: SignatureInput = { args: [{ type: "buffer_ptr", buffer: "car" }], returns: "f32", variadic: false };
const CAR: BufferInput[] = [
  {
    name: "car",
    size: 8,
    align: 8,
    placement: "scratch",
    init_hex: "0000a04107000000",
    fields: [{ name: "speed", offset: 0, type: "f32" }],
    out: true,
  },
];

describe("OracleCallPort.callPlanBatch", () => {
  it("checks call_attached itself before any agent RPC (defense in depth)", async () => {
    const agent = createFakeAgent();
    const port = createOracleCallPort(core(false), { evidence: fakeEvidence(), address: fakeAddress() });
    const r = await port.callPlanBatch(
      fakeLiveSession(agent, { ownership: "attached" }),
      request(ADD, [], { arg0: [1], arg1: [2] }, "add_ints"),
      op(),
    );
    expect(!r.ok && r.error).toMatchObject({ _tag: "GateDisabled", gate: "call_attached" });
    expect(agent.calls).toHaveLength(0);
  });

  it("runs the plan, applies one function-called effect and records bea.call.oracle", async () => {
    const evidence = fakeEvidence();
    const port = createOracleCallPort(core(false), { evidence, address: fakeAddress() });
    const r = await port.callPlanBatch(
      fakeLiveSession(createFakeAgent()),
      request(ADD, [], { arg0: [1, 2, 3], arg1: [10, 10, 10] }, "add_ints"),
      op(),
    );
    if (!r.ok) throw new Error(JSON.stringify(r.error));
    expect(r.value).toMatchObject({
      completed: 3,
      nextOffset: null,
      lostTarget: false,
      exceptionModel: "seh-frame",
      calleeExceptions: 0,
    });
    expect(r.value.outcome.ret).toEqual(["0xb", "0xc", "0xd"]);
    expect(evidence.effectDrafts).toHaveLength(1);
    expect(evidence.records[0]).toMatchObject({
      predicate_type: "bea.call.oracle",
      effects: [r.value.effect_id],
      evidence_id: r.value.evidence_id,
    });
  });

  it("decodes out buffers as raw bytes by default, and by field with the request outLayout", async () => {
    const port = createOracleCallPort(core(true), { evidence: fakeEvidence(), address: fakeAddress() });
    const plain = await port.callPlanBatch(
      fakeLiveSession(createFakeAgent()),
      request(BUMP, CAR, {}, "bump_speed"),
      op(),
    );
    if (!plain.ok) throw new Error(JSON.stringify(plain.error));
    expect(plain.value.outcome.fields["car.__bytes"]).toEqual([
      ["0x0", "0x0", "0xa8", "0x41", "0x7", "0x0", "0x0", "0x0"],
    ]);
    const req = request(BUMP, CAR, {}, "bump_speed");
    const named = await port.callPlanBatch(
      fakeLiveSession(createFakeAgent()),
      { ...req, outLayout: outLayout(req.plan, CAR) },
      op(),
    );
    if (!named.ok) throw new Error(JSON.stringify(named.error));
    expect(named.value.outcome.fields).toEqual({ "car.speed": ["0x41a80000"] });
  });

  it("streams rows above 64 vectors and keeps the record small", async () => {
    const evidence = fakeEvidence();
    const port = createOracleCallPort(core(false), { evidence, address: fakeAddress() });
    const n = 65;
    const r = await port.callPlanBatch(
      fakeLiveSession(createFakeAgent()),
      request(
        ADD,
        [],
        { arg0: Array.from({ length: n }, (_, i) => i), arg1: Array.from({ length: n }, () => 0) },
        "add_ints",
      ),
      op(),
    );
    if (!r.ok) throw new Error(JSON.stringify(r.error));
    expect(evidence.streamsOpened[0]?.rows).toHaveLength(n);
    const recorded = evidence.records[0]?.result as { stream_id: string | null; status: unknown } | undefined;
    expect(recorded?.stream_id).toMatch(/^st_/u);
    expect(recorded?.status).toBeNull();
  });

  /** The fake agent, but the n-th callFunction RPC fails with a HOST-side error (the agent cannot reply). */
  const failingAgent = (n: number, error: BeaError): FakeAgent => {
    const inner = createFakeAgent();
    let rpcs = 0;
    return {
      ...inner,
      call: (async (method: string, params: unknown, opts: { op: OperationContext }) => {
        if (method === "callFunction" && ++rpcs === n) return err(error);
        return (inner.call as (m: string, p: unknown, o: { op: OperationContext }) => Promise<unknown>)(
          method,
          params,
          opts,
        );
      }) as AgentRpc["call"],
    };
  };
  const exited: BeaError = {
    _tag: "TargetExited",
    operation: "diff_function",
    instance_id: "pi_x",
    exit: { code: 7, code_hex: "0x7", kind: "normal", name: null },
    detach_reason: "process-terminated",
  };

  it("a target that exits during a later chunk is a lost-target result, not a failure (EMU-10)", async () => {
    const evidence = fakeEvidence();
    const port = createOracleCallPort(core(false), { evidence, address: fakeAddress() });
    const r = await port.callPlanBatch(
      fakeLiveSession(failingAgent(2, exited), {
        liveness: () => ({ state: "exited", basis: "jobhost-root-exit", exit: null, tree: null }),
      }),
      { ...request(ADD, [], { arg0: [1, 2, 3, 4], arg1: [10, 10, 10, 10] }, "add_ints"), chunk: 2 },
      op(),
    );
    if (!r.ok) throw new Error(JSON.stringify(r.error));
    expect(r.value).toMatchObject({ completed: 2, nextOffset: 2, lostTarget: true });
    expect(r.value.outcome.ret).toEqual(["0xb", "0xc"]);
    expect(evidence.effectDrafts).toHaveLength(1); // the first chunk ran: the call happened
    expect(evidence.records[0]?.coverage).toMatchObject({ status: "partial", reasons: ["process_exited"] });
    // the same loss on the FIRST chunk still records the call (the callee may have exited the process)
    const first = await port.callPlanBatch(
      fakeLiveSession(failingAgent(1, exited)),
      request(ADD, [], { arg0: [1], arg1: [2] }, "add_ints"),
      op(),
    );
    expect(first.ok && first.value).toMatchObject({ completed: 0, lostTarget: true });
  });

  it("a thread chunk that timed out before it ran executes nothing; one still running says so (AGENT-1)", async () => {
    const timeout = (started: boolean) => ({
      _tag: "Timeout" as const,
      message: "x",
      timeout_ms: 300,
      phase: "run-on-thread",
      started,
    });
    const notRun = fakeEvidence();
    const port = createOracleCallPort(core(false), { evidence: notRun, address: fakeAddress() });
    const r = await port.callPlanBatch(
      fakeLiveSession(createFakeAgent({ failOnRpc: { n: 1, error: timeout(false) } })),
      request(ADD, [], { arg0: [1], arg1: [2] }, "add_ints"),
      op(),
    );
    expect(!r.ok && r.error).toMatchObject({ _tag: "ProviderTimeout", diagnostics: { started: false } });
    expect(notRun.effectDrafts).toHaveLength(0); // no function-called effect: the function was not called
    const running = fakeEvidence();
    const port2 = createOracleCallPort(core(false), { evidence: running, address: fakeAddress() });
    const r2 = await port2.callPlanBatch(
      fakeLiveSession(createFakeAgent({ failOnRpc: { n: 1, error: timeout(true) } })),
      request(ADD, [], { arg0: [1], arg1: [2] }, "add_ints"),
      op(),
    );
    expect(!r2.ok && r2.error).toMatchObject({ _tag: "ProviderTimeout", effects_applied: [expect.any(String)] });
    expect(!r2.ok && r2.error.message).toMatch(/may still be running/u);
    expect(running.effectDrafts).toHaveLength(1);
  });
});
