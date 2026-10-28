import { mkdir, readdir } from "node:fs/promises";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import type { BeaCore } from "../../../../src/application/BeaApplication.js";
import { createRecordingRegistry } from "../../../../src/application/instruments/createRecordingRegistry.js";
import type { BeaServices } from "../../../../src/application/services/index.js";
import { notImplementedPort } from "../../../../src/application/notImplemented.js";
import { err, ok } from "../../../../src/domain/result.js";
import type { PiId } from "../../../../src/domain/ids.js";
import type { DynamicSessionPort, LiveSession } from "../../../../src/ports/sessions.js";
import { createEvidenceRuntime } from "../../../../src/providers/evidence/createEvidenceRuntime.js";
import { fakeServices } from "../../../support/fakes/fakeServices.js";
import { connectInMemoryBea, type InMemoryBea } from "../../../support/mcp/inMemory.js";
import { expectToolSuccess, parseToolError } from "../../../support/mcp/parseToolError.js";

const SESSION = "00000000-0000-4000-8000-0000000000aa";
const IMAGE_SHA = "9".repeat(64);
const INSTANCE = `pi_${"5".repeat(64)}` as PiId;

/** Minimal live-session port: one known session, admission passes through (sessionAccess does the dispatch). */
const fakeSessions = (): DynamicSessionPort => {
  const session = {
    id: SESSION,
    kind: "live",
    ownership: "owned",
    state: "running",
    instanceId: INSTANCE,
    identity: {
      image: {
        path: "C:\\game.exe",
        sha256: IMAGE_SHA,
        size: null,
        machine: "x64",
        peTimestamp: null,
        preferredBase: null,
      },
    },
  } as unknown as LiveSession;
  const base = notImplementedPort<DynamicSessionPort>("sessions");
  return new Proxy(base, {
    get: (target, prop) => {
      if (prop === "admit")
        return (name: string, _req: unknown, fn: (op: unknown) => Promise<unknown>) =>
          fn({ opId: 1, name, signal: new AbortController().signal });
      if (prop === "kindOf") return (id: string) => (id === SESSION ? "live" : null);
      if (prop === "withSession")
        return (_id: string, _op: unknown, _mode: unknown, fn: (s: LiveSession) => Promise<unknown>) => fn(session);
      return Reflect.get(target, prop);
    },
  });
};

const services =
  () =>
  async (core: BeaCore): Promise<BeaServices> => {
    const evidence = createEvidenceRuntime(core, {});
    const base = await fakeServices({ evidence, sessions: fakeSessions() })(core);
    return { ...base, recordings: createRecordingRegistry(core, { evidence, address: base.address }) };
  };

let bea: InMemoryBea | undefined;
afterEach(async () => {
  await bea?.close();
  bea = undefined;
});

const call = async (name: string, args: Record<string, unknown>) => {
  if (bea === undefined) throw new Error("no server");
  return bea.client.callTool({ name, arguments: args });
};

describe("evidence tools over MCP (in-memory server, real evidence runtime, fake sessions)", () => {
  it("advertises the four tools with derived annotations and the untrusted marker only where target text may appear", async () => {
    bea = await connectInMemoryBea({ services: services() });
    const tools = (await bea.client.listTools()).tools.filter((t) =>
      ["get_evidence", "export_evidence", "import_evidence", "record_unknown"].includes(t.name),
    );
    expect(tools.map((t) => [t.name, t.annotations?.readOnlyHint, t.annotations?.idempotentHint])).toEqual([
      ["get_evidence", true, true],
      ["export_evidence", false, false],
      ["import_evidence", true, true],
      ["record_unknown", true, false],
    ]);
    const empty = await call("get_evidence", {});
    expect(expectToolSuccess(empty)).toMatchObject({
      view: "summary",
      evidence_id: null,
      summary: { entity: "evidence", total: 0, rows: [] },
    });
    expect(empty._meta).toMatchObject({ provenance: { untrusted_content: true } });
    const invalid = parseToolError(await call("get_evidence", { detail: "complete", filters: {} }));
    expect(invalid.code).toBe("invalid_request");
    // UX-6: an id with the default summary view is refused with a hint, never silently ignored
    const idOnly = parseToolError(await call("get_evidence", { id: `ev_${"0".repeat(64)}` }));
    expect(idOnly.code).toBe("invalid_request");
    expect(JSON.stringify(idOnly.details)).toContain('detail: \\"complete\\"');
  });

  it("records unknowns with CAS, lists them, and refuses stale revisions and unsupported resolutions", async () => {
    bea = await connectInMemoryBea({ services: services() });
    const created = await call("record_unknown", {
      question: "Which function writes Car.speed?",
      session_id: SESSION,
      severity: "high",
    });
    const value = expectToolSuccess(created);
    expect(value).toMatchObject({
      revision: 1,
      status: "open",
      predicate_type: "bea.unknown.mutation",
      confidence: "derived",
      authority: "analyst-inference",
    });
    expect(created._meta).toBeUndefined();
    const updated = expectToolSuccess(
      await call("record_unknown", { unknown_id: value["unknown_id"], expected_revision: 1, status: "investigating" }),
    );
    expect(updated["revision"]).toBe(2);
    const stale = parseToolError(
      await call("record_unknown", { unknown_id: value["unknown_id"], expected_revision: 1, status: "blocked" }),
    );
    expect(stale).toMatchObject({ code: "revision_conflict", retryable: true });
    const unsupported = parseToolError(
      await call("record_unknown", {
        unknown_id: value["unknown_id"],
        expected_revision: 2,
        status: "resolved",
        resolution: "physics_step",
      }),
    );
    expect(unsupported.code).toBe("invalid_request");
    const listed = expectToolSuccess(await call("get_evidence", { entity: "unknowns" }));
    expect(listed["summary"]).toMatchObject({
      total: 1,
      rows: [{ kind: "unknown", revision: 2, status: "investigating", severity: "high" }],
    });
    const complete = expectToolSuccess(await call("get_evidence", { detail: "complete", id: value["unknown_id"] }));
    expect(complete["record"]).toMatchObject({
      record_kind: "unknown",
      value: { scope: { kind: "image", image_sha256: IMAGE_SHA } },
    });
    const missing = parseToolError(
      await call("record_unknown", {
        question: "Dangling supporting evidence id",
        supporting: [`ev_${"4".repeat(64)}`],
      }),
    );
    expect(missing.code).toBe("reference_not_found");
    const unknownSession = parseToolError(
      await call("record_unknown", {
        question: "Unknown session scope",
        session_id: "00000000-0000-4000-8000-0000000000bb",
      }),
    );
    expect(unknownSession.code).toBe("session_not_found");
  });

  it("exports to the run's exports directory (directory and zip), refuses policy paths and existing targets, and verifies", async () => {
    bea = await connectInMemoryBea({ services: services() });
    expectToolSuccess(await call("record_unknown", { question: "Something to export at least" }));
    const dir = expectToolSuccess(await call("export_evidence", {}));
    const exports = bea.app.config.layout.exportsDir(bea.app.run.runId);
    expect(String(dir["path"]).startsWith(exports)).toBe(true);
    expect(dir).toMatchObject({ evidence_id: null, records: 2 });
    const zip = expectToolSuccess(await call("export_evidence", { format: "zip" }));
    expect(String(zip["path"]).endsWith(".zip")).toBe(true);
    expect(zip["bundle_digest"]).toBe(dir["bundle_digest"]);
    const outside = parseToolError(await call("export_evidence", { out_path: join(bea.home.work, "bundle") }));
    expect(outside.code).toBe("access_denied");
    await mkdir(join(exports, "taken"));
    const taken = parseToolError(await call("export_evidence", { out_path: join(exports, "taken") }));
    expect(taken.code).toBe("file_operation_failed");
    const verdict = expectToolSuccess(
      await call("import_evidence", { path: String(zip["path"]), validate_only: true }),
    );
    expect(verdict).toMatchObject({ valid: true, records: 2, added: 0, evidence_id: null });
    const relative = parseToolError(await call("import_evidence", { path: "bundle-1" }));
    expect(relative.code).toBe("invalid_request");
    expect((await readdir(exports)).filter((n) => n.includes("staging"))).toEqual([]);
    const status = expectToolSuccess(await call("bea_status", {}));
    expect(status["storage"]).toMatchObject({
      run_dir: bea.app.config.layout.runDir(bea.app.run.runId),
      usage_mb: { ledger: 1 },
    });
  });

  it("export_evidence with a session id selects that instance's closure", async () => {
    bea = await connectInMemoryBea({ services: services() });
    const exported = expectToolSuccess(await call("export_evidence", { session_id: SESSION }));
    expect(exported).toMatchObject({ records: 0, blobs: 0, streams: 0 });
    const unknown = parseToolError(
      await call("export_evidence", { session_id: "00000000-0000-4000-8000-0000000000cc" }),
    );
    expect(unknown.code).toBe("session_not_found");
    void err;
    void ok;
  });
});
