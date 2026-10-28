import { afterEach, describe, expect, it } from "vitest";

import type { EvId, PiId } from "../../../src/domain/ids.js";
import type { JsonObject } from "../../../src/domain/json.js";
import { NO_LITERALS } from "../../../src/domain/redaction/literals.js";
import { SLICE_MAX_ITEMS } from "../../../src/providers/evidence/EvidenceQuery.js";
import { SLICE_ITEMS_MAX } from "../../../src/contracts/areas/evidence.js";
import { makeRuntime, observation, readDraft, type RuntimeFixture } from "./support.js";

let fx: RuntimeFixture | undefined;
afterEach(async () => {
  await fx?.cleanup();
  fx = undefined;
});

const setup = async (): Promise<{ fixture: RuntimeFixture; instance: PiId; table: EvId }> => {
  fx = await makeRuntime();
  const runtime = fx.runtime;
  const r = await runtime.instances.register(await observation(fx.home));
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  const instance = r.value.instance.instance_id;
  const rows = Array.from({ length: 40 }, (_, i) => ({ i, name: `row${String(i)}` }));
  const ndjson = await runtime.blobs.put(new TextEncoder().encode(rows.map((x) => `${JSON.stringify(x)}\n`).join("")), {
    role: "rows",
    media_type: "application/x-ndjson",
    literals: NO_LITERALS,
  });
  const binary = await runtime.blobs.put(
    new Uint8Array(3000).map((_, i) => i & 0xff),
    { role: "memory", media_type: "application/octet-stream", literals: NO_LITERALS },
  );
  if (!ndjson.ok || "redacted" in ndjson.value || !binary.ok || "redacted" in binary.value) throw new Error("blobs");
  const table = await runtime.recorder.record({
    ...readDraft(runtime, instance),
    predicate_type: "bea.modules.list",
    operation: "list_modules",
    result: { rows: rows.slice(0, 30), total: 40 } as never,
    blobs: [ndjson.value, binary.value],
    locations: [
      runtime.locationOf(
        {
          va: "0x140001a00",
          module: "Game_Sim.exe",
          rva: "0x1a00",
          static_va: null,
          static_base: null,
          static_base_source: null,
          module_map_id: null,
        },
        4,
      ),
    ],
  });
  if (!table.ok) throw new Error(JSON.stringify(table.error));
  for (let i = 0; i < 3; i++) await runtime.recorder.record(readDraft(runtime, instance, `0${String(i)}`));
  return { fixture: fx, instance, table: table.value.record.evidence_id };
};

describe("evidence queries (S2 §12)", () => {
  it("summarizes evidence with exact filters and pages (paging is not truncation)", async () => {
    const { fixture, instance } = await setup();
    const q = fixture.runtime.query;
    const all = q.summary({});
    expect(all.ok && all.value).toMatchObject({ entity: "evidence", total: 6 });
    const reads = q.summary({ filters: { predicate_type: "bea.memory.read" }, offset: 1, limit: 1 });
    expect(reads.ok && reads.value).toMatchObject({
      matching: 3,
      page: { offset: 1, limit: 1, total: 3, next_offset: 2 },
    });
    expect(reads.ok && (reads.value["rows"] as JsonObject[])[0]).toMatchObject({
      kind: "evidence",
      predicate_type: "bea.memory.read",
      instance_id: instance,
      origin: "local",
    });
    const byModule = q.summary({ filters: { module: "GAME_SIM.EXE", rva_from: "0x1000", rva_to: "0x1FFF" } });
    expect(byModule.ok && byModule.value["matching"]).toBe(1);
    const outside = q.summary({ filters: { module: "game_sim.exe", rva_from: "0x2000" } });
    expect(outside.ok && outside.value["matching"]).toBe(0);
    const seq = q.summary({ filters: { seq_from: 1, seq_to: 3 } });
    expect(seq.ok && Number(seq.value["matching"])).toBeGreaterThan(0);
    const instances = q.summary({ entity: "instances" });
    expect(instances.ok && (instances.value["rows"] as JsonObject[])[0]).toMatchObject({
      kind: "instance",
      pid: 4242,
      ownership: "owned",
      image_name: "game_sim.exe",
      state: "suspended",
    });
  });

  it("returns any ledger id complete, re-authenticated, and a missing id as reference_not_found (UX-13)", async () => {
    const { fixture, instance, table } = await setup();
    const q = fixture.runtime.query;
    const ev = await q.complete(table);
    expect(ev.ok && ev.value).toMatchObject({
      record_kind: "evidence",
      origin: "local",
      value: { evidence_id: table },
    });
    const pi = await q.complete(instance);
    expect(pi.ok && pi.value).toMatchObject({
      record_kind: "instance",
      value: { instance_id: instance, state: "suspended" },
    });
    const mm = [...fixture.runtime.index.moduleMaps.keys()][0] ?? "";
    expect((await q.complete(mm)).ok).toBe(true);
    const missing = await q.complete(`ev_${"8".repeat(64)}`);
    expect(missing.ok || missing.error).toMatchObject({
      _tag: "ReferenceNotFound",
      reference: { kind: "evidence", id: `ev_${"8".repeat(64)}` },
    });
    for (const [id, kind] of [
      [`fx_${"8".repeat(64)}`, "effect"],
      [`unk_${"8".repeat(64)}`, "unknown"],
      [`pi_${"8".repeat(64)}`, "instance"],
      [`mm_${"8".repeat(64)}`, "module_map"],
      [`st_${"8".repeat(64)}`, "stream"],
    ] as const) {
      const gone = await q.complete(id);
      expect(gone.ok || gone.error, id).toMatchObject({ _tag: "ReferenceNotFound", reference: { kind } });
    }
  });

  it("slices arrays, NDJSON blobs and binary blobs by page", async () => {
    const { fixture, table } = await setup();
    const q = fixture.runtime.query;
    expect(SLICE_MAX_ITEMS).toBe(SLICE_ITEMS_MAX);
    const array = await q.slice(table, "/result/rows", 10, 500, "hex");
    expect(array.ok && array.value).toMatchObject({
      evidence_id: table,
      total: 30,
      page: { offset: 10, limit: SLICE_MAX_ITEMS, next_offset: 10 + SLICE_MAX_ITEMS },
    });
    expect(array.ok && (array.value["items"] as JsonObject[])[0]).toEqual({ i: 10, name: "row10" });
    const rows = await q.slice(table, "#blob:rows", 35, 10, "hex");
    expect(rows.ok && rows.value).toMatchObject({ total: 40, page: { next_offset: null } });
    expect(rows.ok && (rows.value["items"] as JsonObject[]).map((r) => r["i"])).toEqual([35, 36, 37, 38, 39]);
    const bytes = await q.slice(table, "#blob:memory", 2048, 1, "base64");
    expect(bytes.ok && bytes.value).toMatchObject({
      total: 3000,
      format: "base64",
      page: { offset: 2048, limit: 1024, next_offset: null },
    });
    expect(bytes.ok && Buffer.from(String(bytes.value["data"]), "base64").length).toBe(952);
    const bad = await q.slice(table, "/result/total", 0, 5, "hex");
    expect(bad.ok || bad.error).toMatchObject({ _tag: "InputError", issues: [{ path: "pointer" }] });
    const noBlob = await q.slice(table, "#blob:nope", 0, 5, "hex");
    expect(noBlob.ok).toBe(false);
  });

  it("reports storage status and usage", async () => {
    const { fixture } = await setup();
    const status = fixture.runtime.status();
    expect(status.counts).toMatchObject({ evidence: 6, instances: 1, effects_active: 0 });
    expect(status.usage.ledger.bytes).toBeGreaterThan(0);
    expect(fixture.runtime.storageStatus()).toMatchObject({
      run_dir: fixture.runtime.run.dir,
      usage_mb: { ledger: 1, blobs: 1, streams: 0 },
    });
  });
});
