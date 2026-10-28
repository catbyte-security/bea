import { existsSync } from "node:fs";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { scanToolDeps } from "../../../../src/application/handlers/scan.js";
import { SCAN_LIMITATIONS } from "../../../../src/domain/evidence/limitations/scan.js";
import { expectToolSuccess, parseToolError } from "../../../support/mcp/parseToolError.js";
import { connectInMemoryBea, type InMemoryBea } from "../../../support/mcp/inMemory.js";
import {
  createFakeScanWorld,
  IMAGE_BASE,
  IMAGE_NAME,
  SESSION_ID,
  type FakeScanWorld,
} from "./support/fakeScanServices.js";

/**
 * WP10-SCAN MCP boundary (DESIGN §8.2): the production server + invokeTool + the scan handlers, over a fake session
 * whose agent is the real ScanEngine on a fake address space (tests/boundary/mcp/scan/support).
 */
const HEAP = 0x2000_0000;
let bea: InMemoryBea | undefined;
let world: FakeScanWorld | undefined;

const open = async (): Promise<{ bea: InMemoryBea; world: FakeScanWorld }> => {
  world = createFakeScanWorld();
  world.target.mem.map(HEAP, 0x4000);
  world.target.mem.map(IMAGE_BASE, 0x4000, { module: IMAGE_NAME });
  world.target.mem.writeF32(HEAP + 0x108, 20);
  world.target.mem.writeF32(HEAP + 0x208, 20);
  world.target.mem.writeF32(IMAGE_BASE + 0x40, 20);
  bea = await connectInMemoryBea({ services: world.services });
  return { bea, world };
};
afterEach(async () => {
  await bea?.close();
  world?.cleanup();
  bea = undefined;
  world = undefined;
});

const call = async (b: InMemoryBea, name: string, args: Record<string, unknown>) =>
  b.client.callTool({ name, arguments: args });
const ok = async (b: InMemoryBea, name: string, args: Record<string, unknown>) =>
  expectToolSuccess(await call(b, name, args));

describe("scan_memory", () => {
  it("runs a first scan, records bea.scan.result and returns the recorded envelope", async () => {
    const { bea: b, world: w } = await open();
    const out = await ok(b, "scan_memory", { session_id: SESSION_ID, value_type: "f32", value: 20 });
    expect(out).toMatchObject({
      state: "done",
      count: 3,
      truncated: false,
      ranges_failed: 0,
      predicate_type: "bea.scan.result",
      confidence: "observed",
      coverage: { status: "complete", truncated: false, reasons: [] },
      instance_id: w.records.length === 1 ? expect.stringMatching(/^pi_/u) : "",
    });
    expect(out["scan_id"]).toMatch(/^scan_[0-9a-f]{8}$/u);
    expect(out["evidence_id"]).toMatch(/^ev_/u);
    expect(out["scanned_bytes"]).toBe(0x8000);
    expect(out["limitations"]).toEqual(
      expect.arrayContaining([SCAN_LIMITATIONS.SCAN_SCOPE, SCAN_LIMITATIONS.SCAN_FLOAT_EQUALITY]),
    );
    const draft = w.records[0];
    expect(draft).toMatchObject({
      predicate_type: "bea.scan.result",
      identityExclude: ["wait_ms"],
      subject: { kind: "process-instance" },
    });
    expect(draft?.result).toMatchObject({
      scan_id: out["scan_id"],
      value_type: "f32",
      compare: "exact",
      iteration: 0,
      count: 3,
    });
    expect(w.target.calls[0]).toEqual({
      method: "scanStart",
      params: {
        kind: "value",
        value_type: "f32",
        compare: { op: "eq", value: 20 },
        regions: { protection: "rw-" },
        align: 4,
        max_candidates: 10_000_000,
      },
    });
  });

  it("returns a running poll after wait_ms and finishes in the background", async () => {
    const { bea: b, world: w } = await open();
    w.target.autoRun = false;
    const out = await ok(b, "scan_memory", { session_id: SESSION_ID, value_type: "f32", value: 20, wait_ms: 0 });
    const scanId = out["scan_id"] as string;
    expect(out).toMatchObject({
      state: "running",
      evidence_id: null,
      predicate_type: null,
      coverage: { status: "partial" },
    });
    expect(out["limitations"]).toContain(SCAN_LIMITATIONS.SCAN_RUNNING(scanId));
    const spec = b.app.services.handles.find(scanId);
    expect(spec?.doneCondition(scanId)).toEqual({ kind: "agent-job", jobId: w.target.pendingJobs()[0] });
    expect(parseToolError(await call(b, "scan_results", { scan_id: scanId }))).toMatchObject({ code: "invalid_state" });
    for (const id of w.target.pendingJobs()) w.target.finish(id);
    await scanToolDeps(b.app).service.get(scanId)?.pending;
    expect(spec?.get(scanId)).toMatchObject({ state: "ready", summary: { count: 3, iteration: 0, value_type: "f32" } });
    expect(spec?.doneCondition(scanId)).toBeNull();
    const page = await ok(b, "scan_results", { scan_id: scanId });
    expect(page["page"]).toMatchObject({ total: 3 });
  });

  it("a client cancel stops the running scan at its next slice (jobCancel) and keeps the partial result", async () => {
    const { bea: b, world: w } = await open();
    w.target.autoRun = false;
    const abort = new AbortController();
    const call = b.client.callTool(
      { name: "scan_memory", arguments: { session_id: SESSION_ID, value_type: "f32", value: 20, wait_ms: 30_000 } },
      { signal: abort.signal },
    );
    await vi.waitFor(() => expect(w.target.pendingJobs()).toHaveLength(1), { interval: 5 });
    const [jobId] = w.target.pendingJobs();
    abort.abort();
    await expect(call).rejects.toThrow();
    await vi.waitFor(() => expect(w.target.calls).toContainEqual({ method: "jobCancel", params: { job_id: jobId } }), {
      interval: 5,
    });
    expect(w.target.pendingJobs()).toEqual([]);
    const service = scanToolDeps(b.app).service;
    const [rec] = service.active(SESSION_ID);
    await rec?.pending;
    // S6 §2.6: the scan stopped and kept what it had (done + cancelled), still listed and pageable
    expect(rec).toMatchObject({ state: "done", cancelled: true });
    const page = await ok(b, "scan_results", { scan_id: rec?.id ?? "" });
    expect(page["page"]).toMatchObject({ total: rec?.count });
    expect(page["coverage"]).toMatchObject({ status: "partial", reasons: ["cancelled"] });
  });

  it("resolves an AddrExpr pointer_to target and finds the static pointer in the image", async () => {
    const { bea: b, world: w } = await open();
    const worldPtr = IMAGE_BASE + 0x3000;
    w.target.mem.writeU64(IMAGE_BASE + 0x88, worldPtr);
    w.target.mem.writeU64(HEAP + 0x500, worldPtr);
    const out = await ok(b, "scan_memory", {
      session_id: SESSION_ID,
      value_type: "ptr",
      compare: "pointer_to",
      value: `${IMAGE_NAME}!g_world`,
      kind: "image",
    });
    expect(out).toMatchObject({ state: "done", count: 1 });
    const page = await ok(b, "scan_results", { scan_id: out["scan_id"] as string });
    expect(page["rows"]).toEqual([
      {
        va: `0x${(IMAGE_BASE + 0x88).toString(16)}`,
        at: `${IMAGE_NAME}+0x88`,
        static: expect.stringMatching(/^game_sim\.exe:0x/u),
        value: `0x${worldPtr.toString(16)}`,
        prev: `0x${worldPtr.toString(16)}`,
      },
    ]);
    expect(w.target.calls[0]?.params).toMatchObject({
      kind: "pointers-to",
      targets: [`0x${worldPtr.toString(16)}`],
      regions: { modules: ["*"] },
    });
  });

  it("refuses bad input before any agent call and caps scans per session at 8", async () => {
    const { bea: b, world: w } = await open();
    const pattern = parseToolError(
      await call(b, "scan_memory", { session_id: SESSION_ID, value_type: "bytes", value: "zz 11" }),
    );
    expect(pattern).toMatchObject({ code: "invalid_request" });
    expect(JSON.stringify(pattern)).toContain("invalid match pattern");
    expect(
      parseToolError(await call(b, "scan_memory", { session_id: SESSION_ID, value_type: "f32", value: 1, value2: 2 })),
    ).toMatchObject({
      code: "invalid_request",
    });
    expect(w.target.calls).toEqual([]);
    for (let i = 0; i < 8; i++) await ok(b, "scan_memory", { session_id: SESSION_ID, value_type: "u8", value: 7 });
    const ninth = parseToolError(await call(b, "scan_memory", { session_id: SESSION_ID, value_type: "u8", value: 7 }));
    expect(ninth).toMatchObject({ code: "resource_constraint" });
    expect(b.app.services.handles.list(SESSION_ID)).toHaveLength(8);
  });

  it("reports the hit cap as truncated partial coverage", async () => {
    const { bea: b } = await open();
    const out = await ok(b, "scan_memory", { session_id: SESSION_ID, value_type: "u8", value: 0, max_hits: 10 });
    expect(out).toMatchObject({
      state: "done",
      count: 10,
      truncated: true,
      coverage: { status: "partial", truncated: true, reasons: ["value_cap"] },
    });
    expect(out["limitations"]).toContain(SCAN_LIMITATIONS.SCAN_TRUNCATED(10));
  });
});

describe("scan_next and scan_results", () => {
  it("narrows with increased, pages rows with values and stored values", async () => {
    const { bea: b, world: w } = await open();
    const first = await ok(b, "scan_memory", { session_id: SESSION_ID, value_type: "f32", value: 20 });
    const scanId = first["scan_id"] as string;
    w.target.mem.writeF32(HEAP + 0x108, 21.5);
    const narrowed = await ok(b, "scan_next", { scan_id: scanId, compare: "increased" });
    expect(narrowed).toMatchObject({
      state: "done",
      count: 1,
      previous_count: 3,
      iteration: 1,
      predicate_type: "bea.scan.result",
    });
    w.target.mem.writeF32(HEAP + 0x108, 22);
    const page = await ok(b, "scan_results", { scan_id: scanId });
    expect(page).toMatchObject({
      evidence_id: null,
      rows: [{ va: `0x${(HEAP + 0x108).toString(16)}`, at: null, static: null, value: 22, prev: 21.5 }],
      page: { offset: 0, limit: 50, total: 1, next_offset: null },
    });
    const stored = await ok(b, "scan_results", { scan_id: scanId, values: false });
    expect(stored["rows"]).toEqual([expect.objectContaining({ value: null, prev: 21.5 })]);
    expect(stored["limitations"]).toContain(SCAN_LIMITATIONS.SCAN_STORED_VALUES);
    expect(parseToolError(await call(b, "scan_next", { scan_id: "scan_0badf00d", compare: "changed" }))).toMatchObject({
      code: "reference_not_found",
    });
  });

  it("withholds cells whose bytes contain a server-level sensitive value, in both paging paths (SEC-3)", async () => {
    const { bea: b, world: w } = await open();
    w.sensitive.push("HUNTER2SECRET");
    w.target.mem.write(HEAP + 0x300, new Uint8Array(Buffer.from("xxHUNTER2SECRETyy", "utf16le")));
    // a known prefix and wildcards: the hit's hex cell would spell the whole secret
    const pattern = [...Buffer.from("HUNTER2", "utf16le")].map((x) => x.toString(16).padStart(2, "0")).join(" ");
    const first = await ok(b, "scan_memory", {
      session_id: SESSION_ID,
      value_type: "bytes",
      value: `${pattern} ${"?? ".repeat(12).trim()}`,
    });
    expect(first["count"]).toBe(1);
    const scanId = first["scan_id"] as string;
    for (const values of [true, false]) {
      const page = await ok(b, "scan_results", { scan_id: scanId, values });
      expect(page["rows"], String(values)).toEqual([expect.objectContaining({ value: null, prev: null })]);
      expect(page["coverage"]).toMatchObject({
        status: "partial",
        reasons: expect.arrayContaining(["explicit_sensitive_value"]),
      });
      expect(JSON.stringify(page)).not.toContain(Buffer.from("SECRET", "utf16le").toString("hex"));
    }
    const text = await ok(b, "scan_memory", { session_id: SESSION_ID, value_type: "utf16", value: "HUNTER2SECRET" });
    const textPage = await ok(b, "scan_results", { scan_id: text["scan_id"] as string });
    expect(textPage["rows"]).toEqual([expect.objectContaining({ value: null, prev: null })]);
  });

  it("an unknown-value scan must be narrowed before paging", async () => {
    const { bea: b, world: w } = await open();
    const first = await ok(b, "scan_memory", { session_id: SESSION_ID, value_type: "i32", compare: "unknown" });
    expect(first).toMatchObject({ state: "done", count: (2 * 0x4000) / 4 });
    const refused = parseToolError(await call(b, "scan_results", { scan_id: first["scan_id"] as string }));
    expect(refused).toMatchObject({ code: "invalid_request" });
    w.target.mem.writeI32(HEAP + 0x40, 99);
    const changed = await ok(b, "scan_next", { scan_id: first["scan_id"] as string, compare: "changed" });
    expect(changed).toMatchObject({ count: 1, previous_count: 0x2000 });
  });

  it("serves stored values from the host hit store after the target exited; values:true is target_exited", async () => {
    const { bea: b, world: w } = await open();
    const first = await ok(b, "scan_memory", { session_id: SESSION_ID, value_type: "f32", value: 20 });
    const scanId = first["scan_id"] as string;
    expect(existsSync(join(w.runDir, "scans", scanId, "hits.json"))).toBe(true);
    w.target.state = "exited";
    w.endSession("exited"); // WP4 fires onSessionEnded once, at exit; the session stays open (exited)
    await new Promise((r) => setTimeout(r, 10));
    expect(b.app.services.handles.list(SESSION_ID).map((v) => v.id)).toEqual([scanId]);
    const stored = await ok(b, "scan_results", { scan_id: scanId, values: false, limit: 2 });
    expect(stored).toMatchObject({
      page: { total: 3, next_offset: 2 },
      rows: [expect.objectContaining({ prev: 20, value: null }), expect.anything()],
    });
    expect(stored["limitations"]).toContain(SCAN_LIMITATIONS.SCAN_HOST_STORE);
    expect(parseToolError(await call(b, "scan_results", { scan_id: scanId }))).toMatchObject({ code: "target_exited" });
  });
});

describe("handles (CI-B6)", () => {
  it("stop releases a scan (agent scanClose, host store removed); later calls answer reference_not_found", async () => {
    const { bea: b, world: w } = await open();
    const scanId = (await ok(b, "scan_memory", { session_id: SESSION_ID, value_type: "f32", value: 20 }))[
      "scan_id"
    ] as string;
    const spec = b.app.services.handles.find(scanId);
    expect(spec?.kind).toBe("scan");
    expect(spec?.list(SESSION_ID).map((v) => v.id)).toEqual([scanId]);
    const op = { opId: 1, name: "stop_instrumentation", signal: new AbortController().signal } as never;
    expect(await spec?.stop(w.target.session, scanId, op)).toEqual({
      ok: true,
      value: { id: scanId, kind: "scan", status: "released" },
    });
    expect(w.target.calls.at(-1)?.method).toBe("scanClose");
    expect(existsSync(join(w.runDir, "scans", scanId))).toBe(false);
    expect(await spec?.stop(w.target.session, scanId, op)).toMatchObject({
      ok: true,
      value: { status: "already_ended" },
    });
    expect(spec?.list(SESSION_ID)).toEqual([]);
    expect(parseToolError(await call(b, "scan_results", { scan_id: scanId }))).toMatchObject({
      code: "reference_not_found",
    });
    expect(b.app.services.handles.find("scan_0badf00d")).toBeUndefined();
  });

  it("releases every scan of a session when it ends", async () => {
    const { bea: b, world: w } = await open();
    const scanId = (await ok(b, "scan_memory", { session_id: SESSION_ID, value_type: "f32", value: 20 }))[
      "scan_id"
    ] as string;
    w.endSession("closed");
    await new Promise((r) => setTimeout(r, 10));
    expect(b.app.services.handles.list(SESSION_ID)).toEqual([]);
    expect(parseToolError(await call(b, "scan_next", { scan_id: scanId, compare: "changed" }))).toMatchObject({
      code: "reference_not_found",
    });
  });
});
