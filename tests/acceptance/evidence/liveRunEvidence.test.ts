import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { Deadline } from "../../../src/domain/deadline.js";
import { evidenceIdOf } from "../../../src/domain/evidence/authenticate.js";
import type { BeaEvidence } from "../../../src/domain/evidence/record.js";
import type { EventRecord } from "../../../src/ports/recordings.js";
import type { OperationContext } from "../../../src/ports/sessions.js";
import {
  fixtureArtifact,
  fridaSkip,
  gccSkip,
  jobhostSkip,
  loadFixtures,
  skipNote,
  type FixtureArtifact,
} from "../../support/acceptance/fixtures.js";
import { OwnedPidLedger } from "../../support/process/ownedPidLedger.js";
import {
  spawnOwned,
  startInProcessBea,
  value,
  type InProcessBea,
  type Output,
} from "../sessions/support/inProcessBea.js";

/**
 * WP1 on the real stack (the rows WP1 left to the WP4 integration): the evidence a real session writes through
 * SessionEvidenceSink and StreamBinder — the instance, the crash report recorded before its ack, the derived crash, the
 * exit, one bea.stream.manifest per system stream (StreamBinder.end) — the RecordingRegistry decoding real agent
 * streams through the built-in kinds, every record re-authenticating by its id, and the export → import_evidence round
 * trip of a run that holds real agent stream chunks (validate_only, then a fresh server: added = records, a re-import =
 * duplicates). crashy av-write is the target: it exercises the lifecycle reserve paths (crash and exit records).
 */
const skip = fridaSkip() || jobhostSkip() || gccSkip();

let crashy: FixtureArtifact;
let ledger: OwnedPidLedger;
const servers: InProcessBea[] = [];

const testOp = (name: string): OperationContext => ({
  opId: 1,
  name,
  signal: new AbortController().signal,
  deadline: Deadline.after(30_000),
});

const drain = async (events: AsyncIterable<EventRecord>): Promise<EventRecord[]> => {
  const out: EventRecord[] = [];
  for await (const event of events) out.push(event);
  return out;
};

beforeAll(async () => {
  if (skip !== false) return;
  const manifest = await loadFixtures();
  const artifact = fixtureArtifact(manifest, "crashy");
  if (artifact === null) throw new Error("fixtures unavailable");
  crashy = artifact;
  ledger = new OwnedPidLedger(fixtureArtifact(manifest, "pidcheck")?.path ?? null);
});

afterAll(async () => {
  if (skip !== false) return;
  // the importing server first: the bundles live in the exporting server's temp home
  for (const bea of [...servers].reverse()) await bea.close();
  await ledger.assertClean();
}, 60_000);

describe.skipIf(skip !== false)(`evidence written by a real session${skipNote(skip)}`, () => {
  it("records, recordings and a bundle round trip of a crashy av-write session", async () => {
    const bea = await startInProcessBea({ label: "core-evidence" });
    servers.push(bea);
    const spawned = await spawnOwned({ bea, ledger }, crashy.path, ["av-write", "--delay-ms", "50"]);
    const id = spawned["session_id"] as string;
    const instance = spawned["instance_id"] as string;
    expect(instance).toMatch(/^pi_[0-9a-f]{64}$/u);
    const resumed = value(await bea.call("resume_process", { session_id: id, wait_ms: 20_000, until: "exit" }));
    expect(resumed).toMatchObject({ state: "exited", crash: { type: "access-violation" } });

    // the built-in recordings decode the real agent streams (checkpointed through StreamSpec.flush)
    const recordings = bea.app.services.recordings.list(id);
    expect(recordings.map((r) => r.create.kind).sort()).toEqual(["exceptions", "modules", "output"]);
    const byKind = (kind: string) => recordings.find((r) => r.create.kind === kind)?.id ?? "";
    const exceptions = await drain(bea.app.services.recordings.events(byKind("exceptions"), {}, testOp("test")));
    expect(exceptions).toContainEqual(expect.objectContaining({ type: "access-violation", memory_op: "write" }));
    const output = await drain(bea.app.services.recordings.events(byKind("output"), {}, testOp("test")));
    expect(output.map((e) => String(e["text"])).join("")).toContain("READY pid=");
    // module rows (loads after resume, if any) decode too: every event carries its stream seq
    const modules = await drain(bea.app.services.recordings.events(byKind("modules"), {}, testOp("test")));
    for (const event of modules) expect(event.seq).toBeGreaterThan(0);

    const closed = value(await bea.call("close_session", { session_id: id }));
    expect(closed).toMatchObject({ target_state: "exited" });
    const manifests = closed["manifests"] as string[];
    expect(manifests.length).toBeGreaterThanOrEqual(3);

    // the session's records, by predicate
    const summary = value(await bea.call("get_evidence", { filters: { instance_id: instance }, limit: 500 }))[
      "summary"
    ] as { rows: { evidence_id: string; predicate_type: string }[]; total: number };
    const predicates = new Set(summary.rows.map((r) => r.predicate_type));
    for (const predicate of [
      "bea.process.instance",
      "bea.exception.report",
      "bea.process.crash",
      "bea.process.exit",
      "bea.stream.manifest",
    ])
      expect(predicates, predicate).toContain(predicate);
    const manifestRows = summary.rows
      .filter((r) => r.predicate_type === "bea.stream.manifest")
      .map((r) => r.evidence_id);
    for (const manifest of manifests) expect(manifestRows).toContain(manifest);

    // every record re-authenticates: its id is the digest of its own body
    for (const row of summary.rows) {
      const complete = value(await bea.call("get_evidence", { detail: "complete", id: row.evidence_id }));
      const record = (complete["record"] as { value: Output }).value as unknown as BeaEvidence;
      const { evidence_id: _id, ...body } = record;
      expect(evidenceIdOf(body), row.predicate_type).toBe(row.evidence_id);
    }

    // export with every stream chunk, verify, import into a fresh server, re-import
    const zip = value(await bea.call("export_evidence", { format: "zip", streams: "all" }));
    expect(zip["streams"] as number).toBeGreaterThanOrEqual(3);
    const verdict = value(await bea.call("import_evidence", { path: String(zip["path"]), validate_only: true }));
    expect(verdict).toMatchObject({ valid: true, records: zip["records"], added: 0 });
    const dir = value(await bea.call("export_evidence", { streams: "all" }));
    expect(value(await bea.call("import_evidence", { path: String(dir["path"]), validate_only: true }))).toMatchObject({
      valid: true,
      records: dir["records"],
    });

    const other = await startInProcessBea({ label: "core-evidence-import" });
    servers.push(other);
    const imported = value(await other.call("import_evidence", { path: String(zip["path"]) }));
    expect(imported).toMatchObject({ valid: true, records: zip["records"], added: zip["records"], duplicates: 0 });
    const again = value(await other.call("import_evidence", { path: String(zip["path"]) }));
    expect(again).toMatchObject({ valid: true, added: 0, duplicates: zip["records"] });
    const importedRows = value(
      await other.call("get_evidence", { filters: { instance_id: instance, origin: "imported" }, limit: 500 }),
    )["summary"] as { total: number; matching: number };
    expect(importedRows.matching).toBe(summary.rows.length);
  }, 120_000);
});
