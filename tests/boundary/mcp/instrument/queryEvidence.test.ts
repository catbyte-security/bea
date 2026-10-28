import { afterEach, describe, expect, it } from "vitest";

import { createRecordingRegistry } from "../../../../src/application/instruments/createRecordingRegistry.js";
import { notImplementedPort } from "../../../../src/application/notImplemented.js";
import { COMPLETE } from "../../../../src/domain/evidence/coverage.js";
import type { EvId, FxId, PiId } from "../../../../src/domain/ids.js";
import type { JsonObject } from "../../../../src/domain/json.js";
import { NO_LITERALS } from "../../../../src/domain/redaction/literals.js";
import type { RecordingRegistry } from "../../../../src/ports/recordings.js";
import { fakeServices } from "../../../support/fakes/fakeServices.js";
import { connectInMemoryBea, type InMemoryBea } from "../../../support/mcp/inMemory.js";
import { expectToolSuccess } from "../../../support/mcp/parseToolError.js";
import { makeRuntime, observation, type RuntimeFixture } from "../../../unit/evidence/support.js";

/**
 * Integrator regression (implement stage, WP9 change request): query_events records a DERIVED bea.events.query, which
 * the real Recorder accepts only with a parent link (S2 §7.1 invariant 6). Before the fix every query_events answered
 * an internal error against the real evidence runtime; the area fakes accepted link-less drafts. These tests run the
 * production handler over the real LedgerEvidenceRuntime and the real RecordingRegistry.
 */
let fx: RuntimeFixture | undefined;
let bea: InMemoryBea | undefined;
afterEach(async () => {
  await bea?.close();
  await fx?.cleanup();
  bea = undefined;
  fx = undefined;
});

const SESSION = "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b";

const setup = async (): Promise<{ fx: RuntimeFixture; instance: PiId; recordings: () => RecordingRegistry }> => {
  fx = await makeRuntime();
  const registered = await fx.runtime.instances.register(await observation(fx.home));
  if (!registered.ok) throw new Error(JSON.stringify(registered.error));
  const runtime = fx.runtime;
  let registry: RecordingRegistry | undefined;
  bea = await connectInMemoryBea({
    services: async (core) => {
      registry = createRecordingRegistry(core, { evidence: runtime, address: notImplementedPort("address") });
      return { ...(await fakeServices({ evidence: runtime })(core)), recordings: registry };
    },
  });
  return {
    fx,
    instance: registered.value.instance.instance_id,
    recordings: () => {
      if (registry === undefined) throw new Error("registry not composed");
      return registry;
    },
  };
};

const linksOf = async (f: RuntimeFixture, id: unknown): Promise<readonly unknown[]> => {
  const complete = await f.runtime.query.complete(String(id));
  if (!complete.ok) throw new Error(JSON.stringify(complete.error));
  return ((complete.value["value"] as JsonObject)["evidence_links"] ?? []) as readonly unknown[];
};

describe("query_events evidence links (integrator regression)", () => {
  it("a stream query cites the stream's newest bea.stream.manifest", async () => {
    const { fx: f, instance } = await setup();
    const opened = await f.runtime.streams.open({
      source: { kind: "call-batch", instance_id: instance, effect_id: null, channel: "batch-1" },
      encoding: { kind: "ndjson" },
      decoders: { schema: "test-rows/1" },
      literals: NO_LITERALS,
    });
    if (!opened.ok) throw new Error(JSON.stringify(opened.error));
    const writer = opened.value;
    const payload = new TextEncoder().encode('{"i":0,"r":"0x1"}\n{"i":1,"r":"0x2"}\n');
    expect(writer.append({ first_seq: 1, count: 2, dropped_before: 0, module_map_epoch: null }, payload)).toBe(
      "accepted",
    );
    const ended = await writer.end("stopped");
    if (!ended.ok) throw new Error(JSON.stringify(ended.error));
    const manifest = ended.value.record.evidence_id;

    const out = expectToolSuccess(
      await bea!.client.callTool({ name: "query_events", arguments: { stream_id: writer.stream_id, view: "rows" } }),
    ) as JsonObject;
    expect(out).toMatchObject({ predicate_type: "bea.events.query", confidence: "derived", authority: "live-process" });
    expect((out["rows"] as unknown[]).length).toBe(2);
    expect(await linksOf(f, out["evidence_id"])).toEqual([manifest]);
  });

  it("an active hook recording without a manifest cites the bea.instrument.install that applied its effect", async () => {
    const { fx: f, instance, recordings } = await setup();
    const effect = await f.runtime.effects.apply({
      instance_id: instance,
      kind: "hook-installed",
      target: { address: null, size: null, threads: null },
      parameters: {},
      applied_by: "hook_function",
      literals: NO_LITERALS,
    });
    if (!effect.ok) throw new Error(JSON.stringify(effect.error));
    const effectId: FxId = effect.value.effect_id;
    const install = await f.runtime.recorder.record({
      predicate_type: "bea.instrument.install",
      operation: "hook_function",
      input: { address: "game_sim.exe+0x1000" },
      subject: { kind: "process-instance", instance_id: instance },
      capture: f.runtime.instances.capture(instance),
      provider: { id: "frida", name: "frida", version: null },
      result: { recording_id: "rec_00000001" },
      coverage: COMPLETE,
      effects: [effectId],
      literals: NO_LITERALS,
    });
    if (!install.ok) throw new Error(JSON.stringify(install.error));
    const opened = await f.runtime.streams.open({
      source: { kind: "hook", instance_id: instance, effect_id: effectId, channel: "s1" },
      encoding: { kind: "json-rows", row_kind: "hook/1" },
      decoders: null,
      literals: NO_LITERALS,
    });
    if (!opened.ok) throw new Error(JSON.stringify(opened.error));
    const rec = recordings().create({
      sessionId: SESSION,
      kind: "hook",
      agentInstrumentId: "h1",
      agentStream: "s1",
      streamId: opened.value.stream_id,
      effectId,
      durationMs: null,
      maxEvents: null,
      startsAtResume: false,
      decoders: null,
    });

    const out = expectToolSuccess(
      await bea!.client.callTool({ name: "query_events", arguments: { recording_id: rec.id, view: "rows" } }),
    ) as JsonObject;
    expect(out).toMatchObject({ predicate_type: "bea.events.query", confidence: "derived", authority: "live-process" });
    expect(await linksOf(f, out["evidence_id"])).toEqual([install.value.record.evidence_id as EvId]);
  });

  it("a built-in recording (no effect, no manifest yet) cites the instance's bea.process.instance", async () => {
    const { fx: f, instance, recordings } = await setup();
    const opened = await f.runtime.streams.open({
      source: { kind: "exceptions", instance_id: instance, effect_id: null, channel: "s:exceptions" },
      encoding: { kind: "json-rows", row_kind: "exception/1" },
      decoders: null,
      literals: NO_LITERALS,
    });
    if (!opened.ok) throw new Error(JSON.stringify(opened.error));
    const rec = recordings().create({
      sessionId: SESSION,
      kind: "exceptions",
      agentInstrumentId: null,
      agentStream: "s:exceptions",
      streamId: opened.value.stream_id,
      effectId: null,
      durationMs: null,
      maxEvents: null,
      startsAtResume: false,
      decoders: null,
    });
    const instanceEvidence = f.runtime.query.summary({
      entity: "evidence",
      filters: { predicate_type: "bea.process.instance", instance_id: instance },
    });
    if (!instanceEvidence.ok) throw new Error(JSON.stringify(instanceEvidence.error));
    const rows = instanceEvidence.value["rows"] as readonly JsonObject[];
    expect(rows).toHaveLength(1);

    const out = expectToolSuccess(
      await bea!.client.callTool({ name: "query_events", arguments: { recording_id: rec.id, view: "rows" } }),
    ) as JsonObject;
    expect(out).toMatchObject({ predicate_type: "bea.events.query", confidence: "derived", authority: "live-process" });
    expect(await linksOf(f, out["evidence_id"])).toEqual([rows[0]?.["evidence_id"]]);
  });
});

describe("query_events on instance-less host row streams (integrator, WP14 option B)", () => {
  it.each([
    { predicate: "bea.emu.batch" as const, result: (st: string) => ({ mode: "batch", batch: { stream_id: st } }) },
    { predicate: "bea.emu.sweep" as const, result: (st: string) => ({ mode: "sweep", sweep: { stream_id: st } }) },
  ])("an instance-less $predicate row stream cites the record that produced it (WP14, option B)", async (c) => {
    const { fx: f } = await setup();
    // a host row stream with no process behind it: sealed chunks, but ending it records no bea.stream.manifest
    const opened = await f.runtime.streams.open({
      source: {
        kind: c.predicate === "bea.emu.batch" ? "emu-batch" : "emu-sweep",
        instance_id: null,
        effect_id: null,
        channel: "emu-1",
      },
      encoding: { kind: "ndjson" },
      decoders: { schema: "test-rows/1" },
      literals: NO_LITERALS,
    });
    if (!opened.ok) throw new Error(JSON.stringify(opened.error));
    const writer = opened.value;
    const payload = new TextEncoder().encode('{"i":0,"s":"returned"}\n{"i":1,"s":"returned"}\n');
    expect(writer.append({ first_seq: 1, count: 2, dropped_before: 0, module_map_epoch: null }, payload)).toBe(
      "accepted",
    );
    expect((await writer.end("stopped")).ok).toBe(false); // InvalidState{host-stream}: no manifest
    const produced = await f.runtime.recorder.record({
      predicate_type: c.predicate,
      operation: "emu_call",
      input: { vectors: 2 },
      subject: {
        kind: "emulation",
        image_sha256: "a".repeat(64),
        config_digest: "b".repeat(64),
        state: { basis: "baseline" },
        module_map_id: null,
      },
      provider: { id: "unicorn", name: "unicorn", version: "2.1.4" },
      result: c.result(writer.stream_id) as unknown as JsonObject,
      coverage: COMPLETE,
      literals: NO_LITERALS,
    });
    if (!produced.ok) throw new Error(JSON.stringify(produced.error));

    const out = expectToolSuccess(
      await bea!.client.callTool({ name: "query_events", arguments: { stream_id: writer.stream_id, view: "rows" } }),
    ) as JsonObject;
    expect(out).toMatchObject({ predicate_type: "bea.events.query", confidence: "derived", authority: "emulation" });
    expect((out["rows"] as unknown[]).length).toBe(2);
    expect(await linksOf(f, out["evidence_id"])).toEqual([produced.value.record.evidence_id]);
  });
});
