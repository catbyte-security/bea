import { afterEach, describe, expect, it } from "vitest";

import { BEHAVIOR_LIMITATIONS } from "../../../../src/domain/evidence/limitations/behavior.js";
import { TRACE_API_OPTIONS } from "../../../../src/application/behavior/TraceApiService.js";
import { connectInMemoryBea, type InMemoryBea } from "../../../support/mcp/inMemory.js";
import { expectToolSuccess, parseToolError } from "../../../support/mcp/parseToolError.js";
import {
  EMU_SESSION_ID,
  SESSION_ID,
  createFakeWorld,
  failWith,
  installResult,
  type FakeWorld,
} from "./behaviorFakes.js";

const ALWAYS = [
  BEHAVIOR_LIMITATIONS.DIRECT_SYSCALLS,
  BEHAVIOR_LIMITATIONS.BROKERED_ACTIONS,
  BEHAVIOR_LIMITATIONS.CHILDREN_UNINSTRUMENTED,
  BEHAVIOR_LIMITATIONS.PREEXISTING_HANDLES,
  BEHAVIOR_LIMITATIONS.NO_PAYLOADS,
  BEHAVIOR_LIMITATIONS.LATE_MODULES,
];

/** trace_api over the production MCP server (in-memory transport) with fake session/evidence/recording ports. */
let bea: InMemoryBea | null = null;
afterEach(async () => {
  await bea?.close();
  bea = null;
});
const start = async (world: FakeWorld): Promise<InMemoryBea> => {
  bea = await connectInMemoryBea({
    services: { sessions: world.sessions, evidence: world.evidence, recordings: world.recordings },
  });
  return bea;
};
const onWindows = describe.skipIf(process.platform !== "win32");

onWindows("trace_api (MCP boundary): contract and install", () => {
  it("advertises the contract: IN MS, not read-only, instrument-oneshot CLI, profiles enum", async () => {
    const { client } = await start(createFakeWorld());
    const tool = (await client.listTools()).tools.find((t) => t.name === "trace_api");
    if (tool === undefined) throw new Error("trace_api is not advertised");
    expect(tool.annotations).toMatchObject({
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    });
    const props = (tool.inputSchema as { properties: Record<string, { items?: { enum?: string[] } }> }).properties;
    expect(props.profiles?.items?.enum).toEqual([
      "file",
      "registry",
      "network",
      "process",
      "module_load",
      "memory_protection",
    ]);
    expect(Object.keys(props).sort()).toEqual([
      "backtrace",
      "caller",
      "duration_ms",
      "include_failed",
      "max_events",
      "profiles",
      "session_id",
      "wait_ms",
    ]);
  });

  it("installs on a paused target: agent params, stream binding, one effect, recording, install evidence, envelope", async () => {
    const world = createFakeWorld();
    const { client } = await start(world);
    const out = expectToolSuccess(
      await client.callTool({
        name: "trace_api",
        arguments: { session_id: SESSION_ID, profiles: ["file", "network"], duration_ms: 30_000 },
      }),
    );
    // agent RPC
    expect(world.agentCalls).toHaveLength(1);
    expect(world.agentCalls[0]?.method).toBe("profileInstall");
    expect(world.agentCalls[0]?.params).toEqual({
      profiles: ["file", "network"],
      options: TRACE_API_OPTIONS,
      lifetime: { duration_ms: 30_000, max_hits: 200_000, clock: "resume" },
      label: "trace_api",
    });
    // stream, effect, recording, evidence (record-before-reference order is enforced by awaiting each step)
    expect(world.binds).toEqual([
      {
        agentStream: "sp1",
        spec: expect.objectContaining({
          source: { kind: "api", instance_id: expect.stringMatching(/^pi_/u), effect_id: null, channel: "sp1" },
          encoding: { kind: "json-rows", row_kind: "api/1" },
          decoders: { catalog_minor: 0, include_failed: true, caller: true, user_sid: null },
        }),
      },
    ]);
    expect(world.effects).toHaveLength(1);
    expect(world.effects[0]).toMatchObject({
      kind: "hook-installed",
      target: { address: null, size: null, threads: "all" },
      applied_by: "trace_api",
      lifetime: { duration_ms: 30_000, max_hits: 200_000 },
      stream_ids: [expect.stringMatching(/^st_/u)],
    });
    expect(world.created[0]).toMatchObject({
      kind: "api",
      agentInstrumentId: "p1",
      agentStream: "sp1",
      startsAtResume: true,
      maxEvents: 200_000,
    });
    expect(world.drafts).toHaveLength(1);
    expect(world.drafts[0]).toMatchObject({
      predicate_type: "bea.instrument.install",
      operation: "trace_api",
      identityExclude: ["wait_ms"],
      result: {
        kind: "api",
        installed: ["ntdll.dll!NtCreateFile", "ntdll.dll!NtOpenFile"],
        pending: ["winhttp.dll!WinHttpConnect"],
        failed: [{ api: "ntdll.dll!NtDeleteFile", reason: "export-not-found" }],
      },
    });
    // tool result
    expect(out).toMatchObject({
      instrument: { recording_id: "rec_00000001", kind: "api", state: "active", ends_in_ms: 30_000, end_reason: null },
      hooks_installed: 2,
      hooks_pending: 1,
      hooks_failed: [{ api: "ntdll.dll!NtDeleteFile", reason: "export-not-found" }],
      predicate_type: "bea.instrument.install",
      confidence: "observed",
      authority: "live-process",
      coverage: { status: "complete", truncated: false, reasons: [] },
      observed_at: { seq: 7, effect_epoch: 1, module_map_epoch: 2 },
    });
    expect(out.evidence_id).toMatch(/^ev_/u);
    expect(out.effects_applied).toEqual([expect.stringMatching(/^fx_/u)]);
    expect(out.limitations).toEqual([...ALWAYS, BEHAVIOR_LIMITATIONS.API_HOOKS_FAILED(1)]);
    expect(world.waits).toEqual([]);
  });
});

onWindows("trace_api (MCP boundary): running targets and waits", () => {
  it("running target: duration clock starts at install; conditional limitations; wait_ms returns the finished summary", async () => {
    const world = createFakeWorld();
    world.paused = false;
    world.state = "running";
    world.agentReply = { ok: true, value: installResult({ failed: [], pending: [] }) };
    world.finishedView = {
      recording_id: "rec_00000001",
      kind: "api",
      state: "finished",
      events: 3,
      dropped: 0,
      ends_in_ms: null,
      end_reason: "duration",
      summary: { file: { distinct: 0, rows: [] }, totals: {}, truncated: false },
    };
    const { client } = await start(world);
    const out = expectToolSuccess(
      await client.callTool({
        name: "trace_api",
        arguments: {
          session_id: SESSION_ID,
          profiles: ["memory_protection"],
          backtrace: 4,
          include_failed: false,
          caller: false,
          wait_ms: 2_000,
        },
      }),
    );
    expect(world.agentCalls[0]?.params.lifetime.clock).toBe("install");
    expect(world.binds[0]?.spec.decoders).toEqual({
      catalog_minor: 0,
      include_failed: false,
      caller: false,
      user_sid: null,
    });
    expect(world.waits).toEqual([{ cond: { kind: "stream-end", agentStream: "sp1" }, timeoutMs: 2_000 }]);
    expect(out.instrument).toMatchObject({
      state: "finished",
      end_reason: "duration",
      summary: { totals: {}, truncated: false },
    });
    expect(out.hooks_failed).toEqual([]);
    expect(out.limitations).toEqual([
      ...ALWAYS,
      BEHAVIOR_LIMITATIONS.API_BACKTRACE_UNAVAILABLE,
      BEHAVIOR_LIMITATIONS.API_FAILED_EXCLUDED,
      BEHAVIOR_LIMITATIONS.API_EXEC_REGIONS_SAMPLED,
    ]);
  });
});

onWindows("trace_api (MCP boundary): errors", () => {
  it("input errors: duplicate or unknown profiles, out-of-range numbers, no profiles", async () => {
    const world = createFakeWorld();
    const { client } = await start(world);
    for (const args of [
      { session_id: SESSION_ID, profiles: ["file", "file"] },
      { session_id: SESSION_ID, profiles: ["disk"] },
      { session_id: SESSION_ID, profiles: [] },
      { session_id: SESSION_ID, profiles: ["file"], backtrace: 17 },
      { session_id: SESSION_ID, profiles: ["file"], max_events: 0 },
      { session_id: SESSION_ID, profiles: ["file"], extra: 1 },
    ]) {
      const e = parseToolError(await client.callTool({ name: "trace_api", arguments: args }));
      expect(e.code, JSON.stringify(args)).toBe("invalid_request");
    }
    expect(world.agentCalls).toEqual([]);
  });

  it("session errors: unknown session, emulation session, exited target", async () => {
    const world = createFakeWorld();
    const { client } = await start(world);
    const unknown = parseToolError(
      await client.callTool({
        name: "trace_api",
        arguments: { session_id: "99999999-9999-4999-8999-999999999999", profiles: ["file"] },
      }),
    );
    expect(unknown.code).toBe("session_not_found");
    const emu = parseToolError(
      await client.callTool({ name: "trace_api", arguments: { session_id: EMU_SESSION_ID, profiles: ["file"] } }),
    );
    expect(emu.code).toBe("invalid_request");
    world.state = "exited";
    const exited = parseToolError(
      await client.callTool({ name: "trace_api", arguments: { session_id: SESSION_ID, profiles: ["file"] } }),
    );
    expect(exited.code).toBe("target_exited");
    expect(world.agentCalls).toEqual([]);
  });

  it("agent failures pass through as tool errors and nothing is recorded", async () => {
    const world = createFakeWorld();
    world.agentReply = failWith({
      _tag: "InstrumentationFailed",
      operation: "trace_api",
      reason: "install-failed",
      address: null,
      conflicting_id: null,
    });
    const { client } = await start(world);
    const e = parseToolError(
      await client.callTool({ name: "trace_api", arguments: { session_id: SESSION_ID, profiles: ["file"] } }),
    );
    expect(e.code).toBe("instrumentation_failed");
    expect(world.binds).toEqual([]);
    expect(world.effects).toEqual([]);
    expect(world.drafts).toEqual([]);
  });

  it("host setup failures after the agent install stop the agent instrument (stream bind, effect)", async () => {
    const world = createFakeWorld();
    world.bindError = { _tag: "ResourceConstraint", operation: "trace_api", resource: "disk", limits: {} };
    const { client } = await start(world);
    const e = parseToolError(
      await client.callTool({ name: "trace_api", arguments: { session_id: SESSION_ID, profiles: ["file"] } }),
    );
    expect(e.code).toBe("resource_constraint");
    expect(world.agentCalls.map((c) => [c.method, c.params])).toEqual([
      ["profileInstall", expect.anything()],
      ["instrumentStop", { id: "p1", final_flush: false }],
    ]);
    world.bindError = null;
    world.effectError = { _tag: "Internal", operation: "trace_api" };
    const e2 = parseToolError(
      await client.callTool({ name: "trace_api", arguments: { session_id: SESSION_ID, profiles: ["file"] } }),
    );
    expect(e2.code).toBe("execution_failure");
    expect(world.ended).toEqual([{ agentStream: "sp1", reason: "install-failed" }]);
    expect(world.agentCalls.filter((c) => c.method === "instrumentStop")).toHaveLength(2);
    expect(world.drafts).toEqual([]);
  });
});
