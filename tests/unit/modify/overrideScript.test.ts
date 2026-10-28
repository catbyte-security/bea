import { beforeEach, describe, expect, it } from "vitest";

import type { BeaApplication } from "../../../src/application/BeaApplication.js";
import { createHandleRegistry } from "../../../src/application/handles/createHandleRegistry.js";
import { createOverrideService, type OverrideInput } from "../../../src/application/modify/overrideService.js";
import { createScriptService, type ScriptInput } from "../../../src/application/modify/scriptService.js";
import { LIMITATIONS } from "../../../src/domain/evidence/limitations.js";
import { err, ok } from "../../../src/domain/result.js";
import type { Fingerprint, OverrideInstallParams, OverrideInstallResult } from "../../../src/shared/agentProtocol.js";
import { bytesToHex } from "../../../src/shared/hex.js";
import { createFakeWorld, fakeOp, MODULE_BASE, SESSION_ID, type FakeWorld } from "./support/modifyFakes.js";

let world: FakeWorld;
let app: BeaApplication;
beforeEach(() => {
  world = createFakeWorld();
  app = { services: { ...world.services, handles: createHandleRegistry() } } as unknown as BeaApplication;
});
const methods = () => world.agentCalls.map((c) => c.method);

const HEAD = "4883ec28".padEnd(64, "90");
const installReply = (p: OverrideInstallParams): OverrideInstallResult => ({
  instrument_id: "o1",
  stream_id: p.record ? "s7" : null,
  resolved: {
    va: "0x7ff600001650",
    module: "game_sim.exe",
    module_base: "0x7ff600000000",
    rva: "0x1650",
    export: null,
    function: null,
    protection: "r-x",
  },
  mode: p.mode,
  relocation: "default",
  stalker_invalidated: [],
  effect: {
    kind: "override-installed",
    reversible: true,
    targets: [{ address: "0x7ff600001650", size: null }],
    thread_ids: null,
    before: [{ address: "0x7ff600001650", hex: HEAD }],
  },
});

describe("override_function service", () => {
  const op = fakeOp("override_function");
  const input = (over: Partial<OverrideInput>): OverrideInput => ({
    session_id: SESSION_ID,
    address: "game_sim.exe+0x1650",
    mode: "return",
    set_args: [],
    returns: "f32",
    return_value: 123,
    duration_ms: 2000,
    max_events: 50,
    record: true,
    ...over,
  });

  it("installs a return override with exact bits, a stream, an effect, a recording and evidence", async () => {
    world.handlers.overrideInstall = (p) => ok(installReply(p));
    const result = await createOverrideService(app).install(world.session, input({}), op);
    if (!result.ok) throw new Error(JSON.stringify(result.error));
    expect(world.agentCalls[0]).toEqual({
      method: "overrideInstall",
      params: {
        target: { va: `0x${(MODULE_BASE + 0x1650n).toString(16)}` },
        relocation: "auto",
        lifetime: { duration_ms: 2000, max_hits: 50, clock: "install" },
        record: true,
        mode: "rewrite",
        rewrite: { ret: { type: "f32", value: { bits: "0x42f60000" } } },
      },
    });
    expect(world.binds).toEqual([
      {
        agentStream: "s7",
        spec: expect.objectContaining({
          source: { kind: "override", instance_id: world.session.instanceId, effect_id: null, channel: "s7" },
          encoding: { kind: "json-rows", row_kind: "override/1" },
        }),
      },
    ]);
    const effect = world.effects[0]?.draft;
    expect(effect?.kind).toBe("override-installed");
    expect(bytesToHex(effect?.before ?? new Uint8Array())).toBe(HEAD);
    expect(effect?.stream_ids).toHaveLength(1);
    expect(effect?.lifetime).toEqual({ duration_ms: 2000, max_hits: 50 });
    expect(world.recordings[0]).toMatchObject({
      kind: "override",
      agentInstrumentId: "o1",
      agentStream: "s7",
      effectId: world.effects[0]?.id,
      durationMs: 2000,
      maxEvents: 50,
      startsAtResume: false,
    });
    expect(world.records[0]?.predicate_type).toBe("bea.instrument.install");
    expect(result.value).toMatchObject({
      instrument: { recording_id: "rec_00000001", kind: "override", state: "active" },
      effect_id: world.effects[0]?.id,
      target: { rva: "0x1650" },
      limitations: [LIMITATIONS.OVERRIDE_ACTIVE],
    });
  });

  it("rewrites float and int args and starts the clock at resume on a paused target", async () => {
    world.session.paused = true;
    world.handlers.overrideInstall = (p) => ok(installReply(p));
    const result = await createOverrideService(app).install(
      world.session,
      input({
        mode: "args",
        returns: "void",
        return_value: undefined,
        set_args: [
          { arg: 1, type: "f32", value: 0 },
          { arg: 0, type: "ptr", value: "game_sim.exe!g_world" },
        ],
      } as Partial<OverrideInput>),
      op,
    );
    expect(result.ok).toBe(true);
    const params = world.agentCalls[0]?.params as OverrideInstallParams;
    expect(params.lifetime.clock).toBe("resume");
    expect(params.rewrite?.args).toEqual([
      { slot: 1, class: "float", type: "f32", value: { bits: "0x0" } },
      { slot: 0, class: "int", type: "ptr", value: `0x${(MODULE_BASE + 0x5000n).toString(16)}` },
    ]);
    expect(world.recordings[0]?.startsAtResume).toBe(true);
  });

  it("replaces with a constant; record:false binds no stream and says so", async () => {
    world.handlers.overrideInstall = (p) => ok(installReply(p));
    const result = await createOverrideService(app).install(
      world.session,
      input({ mode: "replace", returns: "bool", return_value: true, record: false }),
      op,
    );
    if (!result.ok) throw new Error(JSON.stringify(result.error));
    expect((world.agentCalls[0]?.params as OverrideInstallParams | undefined)?.replace).toEqual({
      ret_type: "bool8",
      arg_types: [],
      returns: "0x1",
    });
    expect(world.binds).toEqual([]);
    expect(world.recordings[0]?.streamId).toBeNull();
    expect(result.value.limitations).toEqual([LIMITATIONS.OVERRIDE_ACTIVE, LIMITATIONS.OVERRIDE_NOT_RECORDED]);
  });

  it("maps a second replace to instrumentation_failed(conflict) without an effect", async () => {
    world.handlers.overrideInstall = () =>
      err({ _tag: "HookConflict", message: "x", address: "0x1", existing: "o1", kind: "replace" });
    const result = await createOverrideService(app).install(world.session, input({ mode: "replace" }), op);
    expect(result.ok || result.error).toMatchObject({
      _tag: "InstrumentationFailed",
      reason: "conflict",
      conflicting_id: "o1",
    });
    expect(world.effects).toEqual([]);
  });

  it("stops the agent instrument when the effect cannot be recorded", async () => {
    world.handlers.overrideInstall = (p) => ok(installReply(p));
    world.handlers.instrumentStop = () => ok({ stopped: [], not_found: [], unreverted: [] });
    world.failEffects = true;
    const result = await createOverrideService(app).install(world.session, input({}), op);
    expect(result.ok).toBe(false);
    expect(methods()).toEqual(["overrideInstall", "instrumentStop"]);
    expect(world.agentCalls[1]?.params).toEqual({ id: "o1", final_flush: false });
    expect(world.streamEnds).toEqual(["s7"]);
    expect(world.recordings).toEqual([]);
  });

  it("refuses an unrepresentable value before contacting the agent", async () => {
    const result = await createOverrideService(app).install(
      world.session,
      input({ returns: "u8", return_value: 999 }),
      op,
    );
    expect(result.ok || result.error).toMatchObject({ _tag: "InputError", issues: [{ path: "return_value" }] });
    expect(methods()).toEqual([]);
  });
});

describe("run_script service", () => {
  const op = fakeOp("run_script");
  const input = (over: Partial<ScriptInput> = {}): ScriptInput => ({
    session_id: SESSION_ID,
    source: "send(1); send(2); send(3);",
    runtime: "qjs",
    duration_ms: 500,
    max_messages: 1000,
    rpc_args: [],
    ...over,
  });
  const print: Fingerprint = {
    t: 1,
    patches: [{ owner: "h1", address: "0x1", expected_head: "e9", actual_head: "e9", ok: true }],
    debug_registers: [],
    guard_pages: [],
    stalker_threads: [],
  };

  it("runs the script in its own script, checks the fingerprint and records a script-run taint", async () => {
    world.handlers.fingerprint = () => ok(print);
    world.scriptOutcome = ok({
      messages: [{ i: 1 }, 2, "three"],
      errors: [],
      rpcResult: { pid: 42 },
      truncated: false,
      unloaded: true,
    });
    const result = await createScriptService(app).run(world.session, input({ rpc_method: "go", rpc_args: [1] }), op);
    if (!result.ok) throw new Error(JSON.stringify(result.error));
    expect(world.scripts).toEqual([
      { source: input().source, runtime: "qjs", durationMs: 500, maxMessages: 1000, rpcMethod: "go", rpcArgs: [1] },
    ]);
    expect(methods()).toEqual(["fingerprint", "fingerprint"]);
    expect(result.value).toMatchObject({
      messages: ['{"i":1}', "2", '"three"'],
      messages_total: 3,
      rpc_result: '{"pid":42}',
      truncated: false,
      unloaded: true,
      interference: false,
      predicate_type: "bea.script.run",
      limitations: [LIMITATIONS.SCRIPT_RAN],
    });
    expect(world.effects[0]?.draft).toMatchObject({
      kind: "script-run",
      applied_by: "run_script",
      target: { address: null, size: null, threads: "all" },
    });
    expect((world.effects[0]?.draft.parameters["source_sha256"] as string | undefined)?.length).toBe(64);
    // the complete capture is an NDJSON evidence blob cited by the record
    expect(world.blobs).toEqual([{ role: "script.messages", text: '{"i":1}\n2\n"three"\n' }]);
    expect(world.records[0]?.blobs).toEqual([expect.objectContaining({ role: "script.messages" })]);
  });

  it("shortens the inline result but keeps everything in the blob; a redacted blob is partial coverage", async () => {
    const big = "x".repeat(5000);
    world.scriptOutcome = ok({
      messages: Array.from({ length: 1200 }, (_v, i) => (i === 0 ? big : i)),
      errors: [],
      truncated: false,
      unloaded: true,
    });
    const result = await createScriptService(app).run(world.session, input({ max_messages: 5000 }), op);
    if (!result.ok) throw new Error(JSON.stringify(result.error));
    expect(result.value.messages).toHaveLength(1000);
    expect(result.value.messages[0]).toHaveLength(1024);
    expect(result.value.messages[0]?.endsWith("…")).toBe(true);
    expect([result.value.messages_total, result.value.truncated]).toEqual([1200, false]);
    expect(result.value.coverage).toEqual({ status: "complete", truncated: false, reasons: [] });
    expect(result.value.limitations).toContain(LIMITATIONS.SCRIPT_MESSAGES_INLINE);
    expect(world.blobs[0]?.text.split("\n")).toHaveLength(1201);
    world.redactBlobs = true;
    const redacted = await createScriptService(app).run(world.session, input(), op);
    expect(redacted.ok && redacted.value.coverage).toEqual({
      status: "partial",
      truncated: true,
      reasons: ["explicit_sensitive_value", "row_cap"],
    });
    expect(redacted.ok && redacted.value.limitations).toContain(LIMITATIONS.REDACTED(1));
  });

  it("reports interference and an unknown fingerprint", async () => {
    let calls = 0;
    world.handlers.fingerprint = () => {
      calls += 1;
      return ok(calls === 1 ? print : { ...print, patches: [{ ...print.patches[0]!, ok: false, actual_head: "55" }] });
    };
    const changed = await createScriptService(app).run(world.session, input(), op);
    expect(changed.ok && [changed.value.interference, changed.value.limitations]).toEqual([
      true,
      [LIMITATIONS.SCRIPT_RAN, LIMITATIONS.SCRIPT_INTERFERENCE],
    ]);
    delete world.handlers.fingerprint;
    const unknown = await createScriptService(app).run(world.session, input(), op);
    expect(unknown.ok && unknown.value.interference).toBeNull();
    expect(unknown.ok && unknown.value.limitations).toContain(LIMITATIONS.SCRIPT_FINGERPRINT_UNAVAILABLE);
  });

  it("applies no effect when createScript rejects the source", async () => {
    world.scriptOutcome = err({
      _tag: "InputError",
      operation: "run_script",
      issues: [{ path: "source", reason: "invalid_value", message: "syntax error" }],
    });
    const result = await createScriptService(app).run(world.session, input(), op);
    expect(result.ok || result.error._tag).toBe("InputError");
    expect(world.effects).toEqual([]);
    expect(world.records).toEqual([]);
  });

  it("taints and reports other failures with effects_applied", async () => {
    world.scriptOutcome = err({ _tag: "ProviderTimeout", operation: "run_script", timeout_ms: 500, phase: "unload" });
    const result = await createScriptService(app).run(world.session, input(), op);
    expect(result.ok || result.error).toMatchObject({
      _tag: "ProviderTimeout",
      effects_applied: [world.effects[0]?.id],
    });
  });

  it("records the evidence, then reports effect_unreverted when the script stayed loaded", async () => {
    world.scriptOutcome = ok({ messages: [], errors: [], truncated: false, unloaded: false });
    const result = await createScriptService(app).run(world.session, input(), op);
    expect(world.records).toHaveLength(1);
    expect(result.ok || result.error).toMatchObject({
      _tag: "EffectUnreverted",
      effect_ids: [world.effects[0]?.id],
      effects_applied: [world.effects[0]?.id],
      partial: { kind: "retained-evidence" },
    });
  });

  it("caps messages and errors with partial coverage", async () => {
    world.scriptOutcome = ok({
      messages: [1, 2, 3],
      errors: Array.from({ length: 70 }, (_v, i) => ({ description: "e".repeat(2000), line: i === 0 ? -1 : i })),
      truncated: false,
      unloaded: true,
    });
    const result = await createScriptService(app).run(world.session, input({ max_messages: 2 }), op);
    if (!result.ok) throw new Error(JSON.stringify(result.error));
    expect(result.value.messages).toEqual(["1", "2"]);
    expect(result.value.messages_total).toBe(2);
    expect(result.value.truncated).toBe(true);
    expect(result.value.errors).toHaveLength(64);
    expect(result.value.errors[0]).toEqual({ description: "e".repeat(1000), line: null });
    expect(result.value.coverage).toEqual({ status: "partial", truncated: true, reasons: ["row_cap"] });
    expect(result.value.limitations).toContain(LIMITATIONS.CAP("message", 2));
  });
});
