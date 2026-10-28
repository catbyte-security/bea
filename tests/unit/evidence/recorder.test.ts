import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { COMPLETE } from "../../../src/domain/evidence/coverage.js";
import { authenticateEvidence } from "../../../src/domain/evidence/authenticate.js";
import { LIMITATIONS } from "../../../src/domain/evidence/limitations.js";
import type { PiId } from "../../../src/domain/ids.js";
import { literalsOf, NO_LITERALS } from "../../../src/domain/redaction/literals.js";
import { decodeLine } from "../../../src/providers/evidence/LedgerLines.js";
import { runHeaderSchema } from "../../../src/providers/evidence/RunStore.js";
import { makeRuntime, observation, readDraft, type RuntimeFixture } from "./support.js";

let fx: RuntimeFixture | undefined;
afterEach(async () => {
  await fx?.cleanup();
  fx = undefined;
});

const setup = async (): Promise<{ fixture: RuntimeFixture; instance: PiId }> => {
  fx = await makeRuntime();
  const registered = await fx.runtime.instances.register(await observation(fx.home));
  if (!registered.ok) throw new Error(JSON.stringify(registered.error));
  return { fixture: fx, instance: registered.value.instance.instance_id };
};

const ledgerLines = async (fixture: RuntimeFixture): Promise<string[]> =>
  (await readFile(join(fixture.runtime.run.dir, "ledger.jsonl"), "utf8")).split("\n").filter((l) => l.length > 0);

describe("run start and the record pipeline (S2 §7.9, §9)", () => {
  it("touches nothing on disk until the first write, then creates run dir, lock, run.json and the run line", async () => {
    fx = await makeRuntime();
    await expect(stat(fx.runtime.run.dir)).rejects.toThrow();
    const registered = await fx.runtime.instances.register(await observation(fx.home));
    expect(registered.ok).toBe(true);
    const header = runHeaderSchema.parse(JSON.parse(await readFile(join(fx.runtime.run.dir, "run.json"), "utf8")));
    expect(header).toMatchObject({ status: "open", run_id: fx.runId, final: null });
    await expect(stat(join(fx.runtime.run.dir, ".lock"))).resolves.toBeDefined();
    const lines = await ledgerLines(fx);
    expect(JSON.parse(lines[0] ?? "{}")).toMatchObject({ t: "run", run_id: fx.runId });
    // pi, then the module map materialized by the instance evidence, then the instance evidence itself
    expect(lines.map((l) => (JSON.parse(l) as { t: string }).t)).toEqual(["run", "pi", "mm", "ev", "ev"]);
  });

  it("records an anchored observation that authenticates, links nothing extra and is indexed", async () => {
    const { fixture, instance } = await setup();
    const recorded = await fixture.runtime.recorder.record(readDraft(fixture.runtime, instance));
    if (!recorded.ok) throw new Error(JSON.stringify(recorded.error));
    const record = recorded.value.record;
    expect(recorded.value.outcome).toBe("added");
    expect(authenticateEvidence(JSON.parse(JSON.stringify(record))).ok).toBe(true);
    expect(record.parameters).toEqual({ address: "0x140001000", size: 4 });
    expect(record.subject).toMatchObject({ kind: "process-instance", instance_id: instance });
    expect(record.observed_at?.module_map_epoch).toBe(1);
    expect(record.perturbation.level).toBe("agent-only");
    expect(fixture.runtime.index.byId.get(record.evidence_id)?.predicate_type).toBe("bea.memory.read");
    const last = await ledgerLines(fixture);
    const decoded = decodeLine(last.at(-1) ?? "");
    expect(decoded.ok && decoded.value.t === "ev" && decoded.value.record.evidence_id).toBe(record.evidence_id);
  });

  it("deduplicates identical records and rejects a conflicting record with the same id", async () => {
    const { fixture, instance } = await setup();
    const { capture: _capture, ...rest } = readDraft(fixture.runtime, instance);
    const draft = { ...rest, predicate_type: "bea.symbols.module" as const };
    const image = {
      kind: "image" as const,
      image_sha256: "c".repeat(64),
      format: "pe32+" as const,
      machine: "x64" as const,
    };
    const first = await fixture.runtime.recorder.record({ ...draft, subject: image, confidence: "observed" });
    const second = await fixture.runtime.recorder.record({ ...draft, subject: image, confidence: "observed" });
    expect(first.ok && second.ok).toBe(true);
    if (!first.ok || !second.ok) return;
    expect(second.value.outcome).toBe("duplicate");
    expect(second.value.record.evidence_id).toBe(first.value.record.evidence_id);
    expect(fixture.runtime.index.rows.filter((r) => r.evidence_id === first.value.record.evidence_id)).toHaveLength(1);
  });

  it("drops delivery keys, counts sensitive values and redacts result fields and parameters whole", async () => {
    const { fixture, instance } = await setup();
    const literals = literalsOf(["hunter22"]);
    const recorded = await fixture.runtime.recorder.record(
      readDraft(fixture.runtime, instance, "68756e7465723232", {
        input: {
          session_id: "s",
          address: "0x1",
          sensitive_values: ["hunter22"],
          label: "the hunter22 secret",
          limit: 5,
        },
        result: { data: "68756e7465723232", note: "contains hunter22" },
        literals,
      }),
    );
    if (!recorded.ok) throw new Error(JSON.stringify(recorded.error));
    const r = recorded.value.record;
    expect(r.parameters).toEqual({ address: "0x1", sensitive_value_count: 1 });
    expect(r.result).toEqual({ data: null, note: null });
    expect(r.redactions.map((x) => [x.pointer, x.scope])).toEqual([
      ["/parameters/label", "parameter"],
      ["/result/data", "value"],
      ["/result/note", "value"],
    ]);
    expect(r.coverage).toMatchObject({ status: "partial", truncated: true, reasons: ["explicit_sensitive_value"] });
    expect(r.limitations).toContain(LIMITATIONS.REDACTED(2));
    expect(JSON.stringify(await ledgerLines(fixture))).not.toContain("hunter22");
  });

  it("refuses a dangling evidence link and an unregistered predicate as producer errors", async () => {
    const { fixture, instance } = await setup();
    const dangling = await fixture.runtime.recorder.record({
      ...readDraft(fixture.runtime, instance),
      evidence_links: [`ev_${"9".repeat(64)}`],
    });
    expect(dangling.ok || dangling.error._tag).toBe("EvidenceIntegrity");
    const unregistered = await fixture.runtime.recorder.record({
      ...readDraft(fixture.runtime, instance),
      predicate_type: "bea.not.registered" as never,
      effects: [`fx_${"1".repeat(64)}`],
    });
    expect(unregistered.ok).toBe(false);
    if (!unregistered.ok) {
      expect(unregistered.error._tag).toBe("Internal");
      expect(unregistered.error.effects_applied).toEqual([`fx_${"1".repeat(64)}`]);
    }
  });

  it("derived records take the weakest parent authority and the union of parent perturbation", async () => {
    const { fixture, instance } = await setup();
    const parent = await fixture.runtime.recorder.record(readDraft(fixture.runtime, instance));
    if (!parent.ok) throw new Error("parent");
    const derived = await fixture.runtime.recorder.record({
      predicate_type: "bea.events.query",
      operation: "query_events",
      input: { recording_id: "rec_00000001" },
      subject: { kind: "process-instance", instance_id: instance },
      provider: { id: "bea", name: "bea", version: null },
      result: { rows: [] },
      coverage: COMPLETE,
      evidence_links: [parent.value.record.evidence_id],
      literals: NO_LITERALS,
    });
    if (!derived.ok) throw new Error(JSON.stringify(derived.error));
    expect(derived.value.record).toMatchObject({
      confidence: "derived",
      authority: "live-process",
      observed_at: null,
      perturbation: { level: "agent-only" },
    });
  });

  it("finalize fences late appends, ends effects, writes the end line, closes run.json and removes the lock", async () => {
    const { fixture, instance } = await setup();
    const effect = await fixture.runtime.effects.apply({
      instance_id: instance,
      kind: "hook-installed",
      target: { address: null, size: null, threads: null },
      parameters: {},
      applied_by: "hook_function",
      literals: NO_LITERALS,
    });
    expect(effect.ok).toBe(true);
    const finalizing = fixture.runtime.finalize("shutdown");
    const late = await fixture.runtime.recorder.record(readDraft(fixture.runtime, instance));
    expect(late.ok).toBe(false);
    expect((await finalizing).ok).toBe(true);
    expect(await fixture.runtime.finalize("shutdown")).toEqual({ ok: true, value: undefined });
    const header = runHeaderSchema.parse(JSON.parse(await readFile(join(fixture.runtime.run.dir, "run.json"), "utf8")));
    expect(header.status).toBe("closed");
    expect(header.final?.late_appends).toBe(1);
    expect(header.final?.ledger_sha256).toMatch(/^[0-9a-f]{64}$/u);
    await expect(stat(join(fixture.runtime.run.dir, ".lock"))).rejects.toThrow();
    const kinds = (await ledgerLines(fixture)).map((l) => (JSON.parse(l) as { t: string }).t);
    expect(kinds.slice(-2)).toEqual(["fxt", "end"]);
  });
});
