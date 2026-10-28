import { describe, expect, it } from "vitest";

import { COMPLETE } from "../../../src/domain/evidence/coverage.js";
import { NO_LITERALS } from "../../../src/domain/redaction/literals.js";
import { fakeEvidence } from "../../support/fakes/fakeEvidence.js";

describe("fakeEvidence (in-memory EvidenceRuntime for area unit tests)", () => {
  it("records through the production build pipeline and exposes what was recorded", async () => {
    const evidence = fakeEvidence();
    const instance = await evidence.addInstance();
    const recorded = await evidence.recorder.record({
      predicate_type: "bea.memory.read",
      operation: "read_memory",
      input: { session_id: "s", address: "0x140001000" },
      subject: { kind: "process-instance", instance_id: instance },
      capture: evidence.instances.capture(instance),
      provider: { id: "frida", name: "frida", version: null },
      result: { data: "00" },
      coverage: COMPLETE,
      locations: [
        evidence.locationOf({
          va: "0x140001000",
          module: "game.exe",
          rva: "0x1000",
          static_va: null,
          static_base: null,
          static_base_source: null,
          module_map_id: evidence.instances.capture(instance).module_map_id,
        }),
      ],
      literals: NO_LITERALS,
    });
    if (!recorded.ok) throw new Error(JSON.stringify(recorded.error));
    expect(recorded.value.record.parameters).toEqual({ address: "0x140001000" });
    expect(recorded.value.record.evidence_links).toHaveLength(1); // the materialized bea.modules.map
    expect(evidence.records.map((r) => r.predicate_type)).toEqual([
      "bea.modules.map",
      "bea.process.instance",
      "bea.memory.read",
    ]);
    const bad = await evidence.recorder.record({
      predicate_type: "bea.memory.read",
      operation: "read_memory",
      input: {},
      subject: { kind: "process-instance", instance_id: instance },
      provider: { id: "frida", name: "frida", version: null },
      result: {},
      coverage: COMPLETE,
      literals: NO_LITERALS,
    });
    expect(bad.ok || bad.error._tag).toBe("Internal");
  });

  it("models effects, streams, unknowns, literals and injected failures", async () => {
    const evidence = fakeEvidence();
    const instance = await evidence.addInstance();
    const hook = await evidence.effects.apply({
      instance_id: instance,
      kind: "hook-installed",
      target: { address: null, size: null, threads: null },
      parameters: {},
      applied_by: "hook_function",
      literals: NO_LITERALS,
    });
    expect(hook.ok && evidence.effects.perturbation(instance).level).toBe("passive");
    const writer = await evidence.streams.open({
      source: { kind: "hook", instance_id: instance, effect_id: null, channel: "s1" },
      encoding: { kind: "json-rows", row_kind: "hook/1" },
      decoders: null,
      literals: NO_LITERALS,
    });
    if (!writer.ok) throw new Error("stream");
    writer.value.append(
      { first_seq: 1, count: 1, dropped_before: 0, module_map_epoch: 1 },
      new TextEncoder().encode("[7]\n"),
    );
    const reader = evidence.streams.reader(writer.value.stream_id);
    const rows = [];
    if (reader.ok) for await (const r of reader.value.records({})) rows.push(r.fields);
    expect(rows).toEqual([[7]]);
    const manifest = await writer.value.end("stopped");
    expect(manifest.ok && manifest.value.record.coverage.status).toBe("complete");
    const unknown = await evidence.unknowns.upsert(
      {
        question: "Does it work at all?",
        domain: "runtime",
        scope_image_sha256: null,
        status: "open",
        severity: "low",
        supporting: [],
        contradicting: [],
        probes: [],
        resolution: null,
      },
      "record_unknown",
    );
    expect(unknown.ok && evidence.unknownHead(unknown.value.unknown_id)?.revision).toBe(1);
    expect(evidence.literals(["abc"]).ok).toBe(false);
    evidence.failNextRecord({ _tag: "ResourceConstraint", operation: "x", resource: "disk", limits: {} });
    const failed = await evidence.recorder.record({
      predicate_type: "bea.unknown.mutation",
      operation: "record_unknown",
      input: {},
      subject: null,
      provider: { id: "bea", name: "bea", version: null },
      result: {},
      coverage: COMPLETE,
      literals: NO_LITERALS,
    });
    expect(failed.ok || failed.error._tag).toBe("ResourceConstraint");
    expect((await evidence.finalize("shutdown")).ok).toBe(true);
  });
});
