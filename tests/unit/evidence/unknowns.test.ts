import { afterEach, describe, expect, it } from "vitest";

import { LIMITATIONS } from "../../../src/domain/evidence/limitations.js";
import type { EvId, PiId, UnkId } from "../../../src/domain/ids.js";
import {
  nextRevision,
  residualUnknownSchema,
  revisionDigestOf,
  unknownIdOf,
  verifiedResolutionIssue,
} from "../../../src/domain/unknowns/unknown.js";
import type { UnknownInput } from "../../../src/ports/evidence.js";
import { makeRuntime, observation, readDraft, type RuntimeFixture } from "./support.js";

let fx: RuntimeFixture | undefined;
afterEach(async () => {
  await fx?.cleanup();
  fx = undefined;
});

const base: UnknownInput = {
  question: "Which function writes Car.speed?",
  domain: "runtime",
  scope_image_sha256: "e".repeat(64),
  status: "open",
  severity: "high",
  supporting: [],
  contradicting: [],
  probes: ["hook_function physics_step"],
  resolution: null,
};

const setup = async (): Promise<{ fixture: RuntimeFixture; instance: PiId; live: EvId }> => {
  fx = await makeRuntime();
  const r = await fx.runtime.instances.register(await observation(fx.home));
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  const instance = r.value.instance.instance_id;
  const read = await fx.runtime.recorder.record(readDraft(fx.runtime, instance));
  if (!read.ok) throw new Error("read");
  return { fixture: fx, instance, live: read.value.record.evidence_id };
};

describe("unknown registry (S2 §14, §22 unknowns)", () => {
  it("creates revision 1, CAS-updates to 2, refuses a stale revision and a second create", async () => {
    const { fixture } = await setup();
    const created = await fixture.runtime.unknowns.upsert(base, "record_unknown");
    if (!created.ok) throw new Error(JSON.stringify(created.error));
    expect(created.value).toMatchObject({ revision: 1, status: "open" });
    expect(created.value.unknown_id).toBe(
      unknownIdOf("runtime", "Which  function writes Car.speed? ", { kind: "image", image_sha256: "e".repeat(64) }),
    );
    const mutation = fixture.runtime.index.byId.get(created.value.evidence_id);
    expect(mutation).toMatchObject({
      predicate_type: "bea.unknown.mutation",
      confidence: "derived",
      authority: "analyst-inference",
    });
    const update = {
      ...base,
      unknown_id: created.value.unknown_id,
      expected_revision: 1,
      status: "investigating",
    } as const;
    const updated = await fixture.runtime.unknowns.upsert(update, "record_unknown");
    expect(updated.ok && updated.value.revision).toBe(2);
    const stale = await fixture.runtime.unknowns.upsert(update, "record_unknown");
    expect(stale.ok || stale.error).toMatchObject({
      _tag: "RevisionConflict",
      expected_revision: 1,
      actual_revision: 2,
    });
    const again = await fixture.runtime.unknowns.upsert(base, "record_unknown");
    expect(again.ok || again.error._tag).toBe("InputError");
    const revisions =
      fixture.runtime.index.unknowns.get(created.value.unknown_id)?.revisions.map((r) => r.revision) ?? [];
    expect(revisions[1]?.previous_revision_digest).toBe(revisions[0]?.revision_digest);
    for (const r of revisions) expect(revisionDigestOf(r)).toBe(r.revision_digest);
    expect(revisions[1]?.mutation_evidence_ids).toHaveLength(2);
  });

  it("resolves only with supporting evidence of an accepted authority and confidence", async () => {
    const { fixture, live } = await setup();
    const created = await fixture.runtime.unknowns.upsert(base, "record_unknown");
    if (!created.ok) throw new Error("create");
    const resolve = (supporting: EvId[], expected: number) =>
      fixture.runtime.unknowns.upsert(
        {
          ...base,
          unknown_id: created.value.unknown_id as UnkId,
          expected_revision: expected,
          status: "resolved",
          supporting,
          resolution: "physics_step.",
        },
        "record_unknown",
      );
    const unsupported = await resolve([], 1);
    expect(unsupported.ok || unsupported.error._tag).toBe("InputError");
    const mutationOnly = await resolve([created.value.evidence_id], 1);
    expect(mutationOnly.ok || mutationOnly.error._tag).toBe("InputError");
    const resolved = await resolve([live], 1);
    expect(resolved.ok && resolved.value).toMatchObject({ revision: 2, status: "resolved" });
  });

  it("refuses dangling evidence ids and records the mutation evidence with its fixed limitation", async () => {
    const { fixture, live } = await setup();
    const dangling = await fixture.runtime.unknowns.upsert(
      { ...base, supporting: [`ev_${"7".repeat(64)}`] },
      "record_unknown",
    );
    expect(dangling.ok || dangling.error._tag).toBe("ReferenceNotFound");
    const created = await fixture.runtime.unknowns.upsert({ ...base, contradicting: [live] }, "record_unknown");
    if (!created.ok) throw new Error("create");
    expect(created.value.status).toBe("contradicted");
    const read = await fixture.runtime.query.complete(created.value.evidence_id);
    if (!read.ok) throw new Error("read");
    const record = read.value["value"] as { limitations: string[]; evidence_links: string[]; subject: unknown };
    expect(record.limitations).toEqual([LIMITATIONS.UNKNOWN_MUTATION_INTENT]);
    expect(record.evidence_links).toEqual([live]);
    expect(record.subject).toBeNull();
  });

  it("autoRecord is idempotent per deterministic question", async () => {
    const { fixture } = await setup();
    const auto = { ...base, question: "Diff of physics_step differs on 2 vectors (Evidence ev_x)." };
    const a = await fixture.runtime.unknowns.autoRecord(auto, "diff_function");
    const b = await fixture.runtime.unknowns.autoRecord(auto, "diff_function");
    expect(a.ok && b.ok && a.value.unknown_id === b.value.unknown_id && b.value.revision === 1).toBe(true);
  });
});

describe("verified-resolution rule (pure)", () => {
  const u = {
    supporting_evidence_ids: [`ev_${"1".repeat(64)}`] as EvId[],
    contradicting_evidence_ids: [] as EvId[],
    accepted_authorities: ["live-process"] as const,
    required_confidence: "observed" as const,
  };
  it("accepts live observed support and rejects emulation, imported-origin, unknown coverage and contradiction", () => {
    const facts =
      (authority: "live-process" | "emulation" | "imported", coverage: "complete" | "unknown" = "complete") =>
      () => ({
        predicate_type: "bea.memory.read",
        authority,
        confidence: "observed" as const,
        coverage_status: coverage,
      });
    expect(verifiedResolutionIssue({ ...u, accepted_authorities: ["live-process"] }, facts("live-process"))).toBeNull();
    expect(
      verifiedResolutionIssue({ ...u, accepted_authorities: ["live-process"] }, facts("emulation")),
    ).not.toBeNull();
    expect(verifiedResolutionIssue({ ...u, accepted_authorities: ["live-process"] }, facts("imported"))).not.toBeNull();
    expect(
      verifiedResolutionIssue({ ...u, accepted_authorities: ["live-process"] }, facts("live-process", "unknown")),
    ).not.toBeNull();
    expect(
      verifiedResolutionIssue({ ...u, accepted_authorities: ["emulation", "live-process"] }, facts("emulation")),
    ).toBeNull();
    expect(
      verifiedResolutionIssue(
        { ...u, accepted_authorities: ["live-process"], contradicting_evidence_ids: [`ev_${"2".repeat(64)}`] },
        facts("live-process"),
      ),
    ).not.toBeNull();
  });

  it("builds digest-linked revisions that satisfy the schema invariants", () => {
    const fields = {
      scope: { kind: "global" } as const,
      domain: "function-semantics",
      question: "Is mf_spring pure?",
      status: "open" as const,
      severity: "low" as const,
      supporting: [],
      contradicting: [],
      probes: [],
      resolution: null,
    };
    const r1 = nextRevision(undefined, fields, `ev_${"3".repeat(64)}`);
    const r2 = nextRevision(r1, { ...fields, status: "blocked" }, `ev_${"4".repeat(64)}`);
    expect(residualUnknownSchema.safeParse(r1).success).toBe(true);
    expect(residualUnknownSchema.safeParse(r2).success).toBe(true);
    expect(r1.accepted_authorities).toEqual(["emulation", "live-process"]);
    expect(r2.previous_revision_digest).toBe(r1.revision_digest);
    expect(residualUnknownSchema.safeParse({ ...r2, status: "resolved" }).success).toBe(false);
  });
});
