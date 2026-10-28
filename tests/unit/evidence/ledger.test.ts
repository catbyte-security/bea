import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { COMPLETE } from "../../../src/domain/evidence/coverage.js";
import type { PiId } from "../../../src/domain/ids.js";
import { NO_LITERALS } from "../../../src/domain/redaction/literals.js";
import { Ledger } from "../../../src/providers/evidence/Ledger.js";
import { QuotaGuard } from "../../../src/providers/evidence/Quotas.js";
import { markCrashedRuns, runHeaderSchema } from "../../../src/providers/evidence/RunStore.js";
import { openPersistedRun, reloadLedger } from "../../../src/providers/evidence/reloadRun.js";
import { createTempHome, type TempHome } from "../../support/workspace/tempHome.js";
import { makeRuntime, observation, readDraft, type RuntimeFixture } from "./support.js";

let fx: RuntimeFixture | undefined;
let home: TempHome | undefined;
afterEach(async () => {
  await fx?.cleanup();
  await home?.cleanup();
  fx = undefined;
  home = undefined;
});

const withInstance = async (): Promise<{ fixture: RuntimeFixture; instance: PiId }> => {
  fx = await makeRuntime();
  const r = await fx.runtime.instances.register(await observation(fx.home));
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  return { fixture: fx, instance: r.value.instance.instance_id };
};

describe("ledger (S2 §9.3–9.7, §22 ledger)", () => {
  it("reloads and re-authenticates every line; the index matches the live one", async () => {
    const { fixture, instance } = await withInstance();
    for (let i = 0; i < 5; i++)
      await fixture.runtime.recorder.record(readDraft(fixture.runtime, instance, `0${String(i)}`));
    await fixture.runtime.finalize("shutdown");
    const reloaded = await reloadLedger(join(fixture.runtime.run.dir, "ledger.jsonl"));
    if (!reloaded.ok) throw new Error(JSON.stringify(reloaded.error));
    expect(reloaded.value.tornBytes).toBe(0);
    expect(reloaded.value.index.rows.map((r) => r.evidence_id)).toEqual(
      fixture.runtime.index.rows.map((r) => r.evidence_id),
    );
    expect([...reloaded.value.index.instances.keys()]).toEqual([instance]);
    const persisted = await openPersistedRun(fixture.config, fixture.runId);
    if (!persisted.ok) throw new Error("open");
    expect(persisted.value.header?.status).toBe("closed");
    const summary = persisted.value.query.summary({ filters: { predicate_type: "bea.memory.read" } });
    expect(summary.ok && summary.value["matching"]).toBe(5);
    const first = fixture.runtime.index.rows[0]?.evidence_id ?? "";
    const complete = await persisted.value.query.complete(first);
    expect(complete.ok && complete.value["record_kind"]).toBe("evidence");
    await persisted.value.close();
  });

  it("tolerates a torn final line and refuses a corrupted committed line", async () => {
    const { fixture, instance } = await withInstance();
    await fixture.runtime.recorder.record(readDraft(fixture.runtime, instance));
    await fixture.runtime.finalize("shutdown");
    const path = join(fixture.runtime.run.dir, "ledger.jsonl");
    const before = await reloadLedger(path);
    await appendFile(path, '{"t":"ev","record":{"sch');
    const torn = await reloadLedger(path);
    expect(torn.ok && torn.value.tornBytes).toBe(24);
    expect(torn.ok && before.ok && torn.value.index.rows.length).toBe(before.ok ? before.value.index.rows.length : -1);
    const text = await readFile(path, "utf8");
    await writeFile(path, text.replace('"operation":"read_memory"', '"operation":"read_memorx"'));
    const corrupted = await reloadLedger(path);
    expect(corrupted.ok || corrupted.error._tag).toBe("EvidenceIntegrity");
  });

  it("ignores lines of an import bracket without its commit", async () => {
    home = await createTempHome("ledger");
    const path = join(home.work, "ledger.jsonl");
    const quotas = new QuotaGuard({
      ledgerBytes: 1 << 20,
      ledgerReserveBytes: 1024,
      streamBytes: 1,
      streamTotalBytes: 1,
      blobBytes: 1,
    });
    const ledger = new Ledger(path, quotas, { prepare: async () => undefined, initial: () => [] });
    const fixture = await makeRuntime({ home });
    fx = fixture;
    const r = await fixture.runtime.instances.register(await observation(home));
    if (!r.ok) throw new Error("register");
    const line = (await readFile(join(fixture.runtime.run.dir, "ledger.jsonl"), "utf8")).split("\n")[1] ?? "";
    await ledger.append(
      { t: "import-begin", import_id: `imp_${"0".repeat(16)}`, bundle_digest: "d".repeat(64), source_runs: [] },
      { operation: "t" },
    );
    await ledger.drain();
    await appendFile(path, `${line}\n`);
    await ledger.close();
    const reloaded = await reloadLedger(path);
    expect(reloaded.ok && reloaded.value.ignoredUncommitted).toBe(1);
    expect(reloaded.ok && reloaded.value.index.instances.size).toBe(0);
  });

  it("keeps the last MiBs for lifecycle lines and refuses ordinary lines first (reserve)", async () => {
    home = await createTempHome("ledger");
    const quotas = new QuotaGuard({
      ledgerBytes: 4000,
      ledgerReserveBytes: 1000,
      streamBytes: 1,
      streamTotalBytes: 1,
      blobBytes: 1,
    });
    const ledger = new Ledger(join(home.work, "ledger.jsonl"), quotas, {
      prepare: async () => undefined,
      initial: () => [],
    });
    const line = { t: "end", ended_wall: "x".repeat(900), counts: {} } as const;
    const results = [];
    for (let i = 0; i < 4; i++) results.push(await ledger.append(line, { operation: "t" }));
    expect(results.map((r) => r.ok)).toEqual([true, true, true, false]);
    const refused = results[3];
    expect(refused?.ok === false && refused.error).toMatchObject({
      _tag: "ResourceConstraint",
      resource: "disk",
      limits: { quota: "ledger", knob: "BEA_LEDGER_QUOTA_MB" },
    });
    expect((await ledger.append(line, { operation: "t", lifecycle: true })).ok).toBe(true);
    expect((await ledger.append(line, { operation: "t", lifecycle: true })).ok).toBe(false);
    await ledger.close();
  });

  it("returns the I/O failure with effects_applied when the run cannot be written (record-before-deliver)", async () => {
    home = await createTempHome("ledger");
    await writeFile(join(home.beaHome, "runs"), "not a directory");
    fx = await makeRuntime({ home });
    const recorded = await fx.runtime.recorder.record({
      predicate_type: "bea.unknown.mutation",
      operation: "record_unknown",
      input: {},
      subject: null,
      provider: { id: "bea", name: "bea", version: null },
      result: {},
      coverage: COMPLETE,
      effects: [`fx_${"2".repeat(64)}`],
      literals: NO_LITERALS,
    });
    expect(recorded.ok).toBe(false);
    if (!recorded.ok) {
      expect(["FileOperationFailed", "ResourceConstraint"]).toContain(recorded.error._tag);
      expect(recorded.error.effects_applied).toEqual([`fx_${"2".repeat(64)}`]);
    }
  });

  it("marks sibling open runs whose lock pid is dead as crashed, and leaves live ones alone", async () => {
    home = await createTempHome("ledger");
    const runs = join(home.beaHome, "runs");
    const header = (id: string) => ({
      schema: "bea.run/1",
      run_id: id,
      kind: "cli",
      bea_version: "0.1.0",
      node: "v24",
      platform: "win32",
      pid: 1,
      started_wall: "2026-01-01T00:00:00.000Z",
      ended_wall: null,
      status: "open",
      quotas: { ledger_bytes: 1, ledger_reserve_bytes: 1, stream_bytes: 1, stream_total_bytes: 1, blob_bytes: 1 },
      final: null,
    });
    const dead = "run_20260101T000000Z_00000000000000aa";
    const alive = "run_20260101T000000Z_00000000000000bb";
    for (const [id, pid] of [
      [dead, 2 ** 31 - 2],
      [alive, process.pid],
    ] as const) {
      await mkdir(join(runs, id), { recursive: true });
      await writeFile(join(runs, id, "run.json"), JSON.stringify(header(id)));
      await writeFile(join(runs, id, ".lock"), JSON.stringify({ pid }));
    }
    expect(await markCrashedRuns(runs, "run_20260101T000000Z_00000000000000cc")).toBe(1);
    const status = async (id: string) =>
      runHeaderSchema.parse(JSON.parse(await readFile(join(runs, id, "run.json"), "utf8"))).status;
    expect(await status(dead)).toBe("crashed");
    expect(await status(alive)).toBe("open");
  });
});
