import { afterEach, describe, expect, it } from "vitest";

import { GATE_SPECS, gateEnableInstruction, type GateId } from "../../../../src/domain/gates.js";
import { ok } from "../../../../src/domain/result.js";
import { connectInMemoryBea, type InMemoryBea } from "../../../support/mcp/inMemory.js";
import { expectToolSuccess, parseToolError } from "../../../support/mcp/parseToolError.js";
import {
  createFakeWorld,
  fakeOp,
  installWriteAgent,
  SESSION_ID,
  type FakeWorld,
} from "../../../unit/modify/support/modifyFakes.js";

/**
 * S6 §10.8 rows for the three gated tools through the production MCP server (in-memory transport, fake ports):
 * gate off → capability_unavailable with the exact enable text and NO session admission or agent RPC; gate on →
 * schema-valid recorded envelopes (invokeTool's output self-check runs on every call).
 */
const ALL_GATES_ON = { BEA_ALLOW_WRITE_MEMORY: "1", BEA_ALLOW_OVERRIDE: "1", BEA_ALLOW_RUN_SCRIPT: "1" };

let bea: InMemoryBea | undefined;
afterEach(async () => {
  await bea?.close();
  bea = undefined;
});

const connect = async (world: FakeWorld, env: Readonly<Record<string, string>> = {}): Promise<InMemoryBea> => {
  bea = await connectInMemoryBea({ services: world.services, env });
  return bea;
};

const CALLS: readonly { readonly gate: GateId; readonly name: string; readonly args: Record<string, unknown> }[] = [
  { gate: "write_memory", name: "write_memory", args: { session_id: SESSION_ID, address: "0x1000", hex: "90" } },
  {
    gate: "override_function",
    name: "override_function",
    args: { session_id: SESSION_ID, address: "0x1000", mode: "replace", returns: "i32", return_value: 1 },
  },
  { gate: "run_script", name: "run_script", args: { session_id: SESSION_ID, source: "send(1)" } },
];

describe("modify tools over MCP", () => {
  it("advertises the three tools as gated and destructive", async () => {
    const { client } = await connect(createFakeWorld());
    const { tools } = await client.listTools();
    for (const name of ["write_memory", "override_function", "run_script"]) {
      const tool = tools.find((t) => t.name === name);
      expect(tool?.annotations, name).toMatchObject({ destructiveHint: true, readOnlyHint: false });
    }
  });

  for (const call of CALLS)
    it(`${call.name} with its gate off: capability_unavailable, exact enable text, no agent contact`, async () => {
      const world = createFakeWorld();
      // every OTHER gate on: only the tool's own gate decides
      const env = Object.fromEntries(Object.entries(ALL_GATES_ON).filter(([key]) => key !== GATE_SPECS[call.gate].env));
      const { client } = await connect(world, env);
      const error = parseToolError(await client.callTool({ name: call.name, arguments: call.args }));
      expect(error.code).toBe("capability_unavailable");
      expect(error.details).toMatchObject({
        gate: call.gate,
        enables: GATE_SPECS[call.gate].enables,
        enable: gateEnableInstruction(call.gate),
      });
      expect(world.admissions).toBe(0);
      expect(world.agentCalls).toEqual([]);
      expect(world.scripts).toEqual([]);
    });

  it("write_memory with the gate on returns a recorded envelope and its fx_ handle reverts through the registry", async () => {
    const world = createFakeWorld();
    installWriteAgent(world, { before: "0000a041" });
    const { client, app } = await connect(world, ALL_GATES_ON);
    const result = expectToolSuccess(
      await client.callTool({
        name: "write_memory",
        arguments: { session_id: SESSION_ID, address: "game_sim.exe+0x300c", type: "f32", value: 1 },
      }),
    );
    expect(result).toMatchObject({ verified: true, method: "direct", after_hex: "0000803f", before_hex: "0000a041" });
    const fx = result["effect_id"] as string;
    expect(result["effects_applied"]).toEqual([fx]);
    const spec = app.services.handles.find(fx);
    expect(spec?.kind).toBe("write");
    expect(app.services.handles.list(SESSION_ID).map((h) => h.id)).toEqual([fx]);
    world.handlers.revertWrite = (p) =>
      ok({ write_id: p.write_id, reverted: true, current_before_revert: "0000803f", after: "0000a041" });
    const stopped = await spec?.stop(world.session, fx, fakeOp("stop_instrumentation"));
    expect(stopped).toEqual(ok({ id: fx, kind: "write", status: "reverted" }));
  });

  it("write_memory input errors are invalid_request before admission", async () => {
    const world = createFakeWorld();
    const { client } = await connect(world, ALL_GATES_ON);
    const error = parseToolError(
      await client.callTool({
        name: "write_memory",
        arguments: { session_id: SESSION_ID, address: "0x1000", hex: "90", type: "u8", value: 1 },
      }),
    );
    expect(error.code).toBe("invalid_request");
    expect(world.admissions).toBe(0);
  });
});

describe("override_function and run_script over MCP", () => {
  it("override_function refuses an address inside a function body before the agent installs (UX-1)", async () => {
    const world = createFakeWorld();
    world.functionStart = 0x7ff6_0000_1640n;
    const { client } = await connect(world, ALL_GATES_ON);
    const error = parseToolError(
      await client.callTool({
        name: "override_function",
        arguments: {
          session_id: SESSION_ID,
          address: "game_sim.exe+0x1650",
          mode: "return",
          returns: "f32",
          return_value: 1,
        },
      }),
    );
    expect(error.code).toBe("invalid_request");
    expect(error.details).toMatchObject({
      diagnostics: { reason: "not_function_start", function_start: "game_sim.exe+0x1640", offset: 16 },
    });
    expect(world.agentCalls).toEqual([]);
  });

  it("override_function with the gate on returns the recording and the effect", async () => {
    const world = createFakeWorld();
    world.handlers.overrideInstall = (p) =>
      ok({
        instrument_id: "o3",
        stream_id: "s4",
        resolved: {
          va: p.target && "va" in p.target ? p.target.va : "0x1",
          module: null,
          module_base: null,
          rva: null,
          export: null,
          function: null,
          protection: "r-x",
        },
        mode: p.mode,
        relocation: "forced",
        stalker_invalidated: [],
        effect: { kind: "override-installed", reversible: true, targets: [], thread_ids: null, before: [] },
      });
    const { client } = await connect(world, ALL_GATES_ON);
    const result = expectToolSuccess(
      await client.callTool({
        name: "override_function",
        arguments: {
          session_id: SESSION_ID,
          address: "game_sim.exe+0x1650",
          mode: "return",
          returns: "f32",
          return_value: 123,
        },
      }),
    );
    expect(result).toMatchObject({
      instrument: { kind: "override", state: "active" },
      predicate_type: "bea.instrument.install",
    });
    expect(world.recordings[0]?.agentInstrumentId).toBe("o3");
  });

  it("run_script with the gate on captures messages; a syntax error is invalid_request", async () => {
    const world = createFakeWorld();
    world.scriptOutcome = ok({
      messages: [{ i: 0 }, { i: 1 }, { i: 2 }],
      errors: [],
      truncated: false,
      unloaded: true,
    });
    const { client } = await connect(world, ALL_GATES_ON);
    const result = expectToolSuccess(
      await client.callTool({
        name: "run_script",
        arguments: { session_id: SESSION_ID, source: "for (let i = 0; i < 3; i++) send({i});" },
      }),
    );
    expect(result).toMatchObject({
      messages: ['{"i":0}', '{"i":1}', '{"i":2}'],
      messages_total: 3,
      unloaded: true,
      interference: null,
    });
    world.scriptOutcome = {
      ok: false,
      error: {
        _tag: "InputError",
        operation: "run_script",
        issues: [{ path: "source", reason: "invalid_value", message: "The script does not compile." }],
      },
    };
    const error = parseToolError(
      await client.callTool({ name: "run_script", arguments: { session_id: SESSION_ID, source: "send(" } }),
    );
    expect(error.code).toBe("invalid_request");
  });

  it("an unknown session is session_not_found even with the gate on", async () => {
    const world = createFakeWorld();
    const { client } = await connect(world, ALL_GATES_ON);
    const error = parseToolError(
      await client.callTool({
        name: "run_script",
        arguments: { session_id: "00000000-0000-4000-8000-000000000000", source: "send(1)" },
      }),
    );
    expect(error.code).toBe("session_not_found");
    expect(world.scripts).toEqual([]);
  });
});
