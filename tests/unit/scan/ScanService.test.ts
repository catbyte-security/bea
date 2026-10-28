import { describe, expect, it } from "vitest";

import { createHandleRegistry } from "../../../src/application/handles/createHandleRegistry.js";
import { createHitStore } from "../../../src/application/scans/scanHitStore.js";
import { scanCoverage, scanLimitations } from "../../../src/application/scans/scanOutputs.js";
import { MAX_SCANS_PER_SESSION, ScanService } from "../../../src/application/scans/ScanService.js";
import { sequentialIdSource } from "../../../src/domain/canonical.js";
import { manualClock } from "../../../src/domain/clock.js";
import { Deadline } from "../../../src/domain/deadline.js";
import type { BeaError } from "../../../src/domain/errors/beaError.js";
import { silentLogger } from "../../../src/domain/logger.js";
import { err, ok, type Result } from "../../../src/domain/result.js";
import type {
  AgentJobOutcome,
  DynamicSessionPort,
  LiveSession,
  OperationContext,
  SessionEndedEvent,
} from "../../../src/ports/sessions.js";
import type { ScanStatus } from "../../../src/shared/agentProtocol.js";

/** WP10-SCAN ScanService: job outcome mapping, refresh, capacity and release (CI-B6). */
const status = (over: Partial<ScanStatus>): ScanStatus => ({
  scan_id: "sc1",
  label: null,
  state: "ready",
  mode: "explicit",
  value_type: "i32",
  count: 4,
  ops: [],
  bytes_scanned: 4096,
  regions: 1,
  unreadable_regions: 0,
  faulted_candidates_dropped: 0,
  job: "j1",
  memory_bytes: 0,
  error: null,
  ...over,
});
const outcome = (st: ScanStatus | null, state: AgentJobOutcome["info"]["state"] = "done"): AgentJobOutcome => ({
  info: {
    job_id: "j1",
    kind: "scan-first",
    state,
    progress: { done: 1, total: 1, unit: "bytes" },
    started_t: 0,
    ended_t: 1,
    error: null,
  },
  result: st,
  error: st?.error ?? null,
  blobs: new Map(),
});

const harness = () => {
  const calls: string[] = [];
  let resolveJob: (r: Result<AgentJobOutcome, BeaError>) => void = () => undefined;
  const listeners: ((e: SessionEndedEvent) => void)[] = [];
  let next: Result<unknown, BeaError> = ok({ scan_id: "sc1", job_id: "j1" });
  const statusReply: { value: ScanStatus } = { value: status({}) };
  const session = {
    id: "s1",
    state: "running",
    instanceId: `pi_${"1".repeat(64)}`,
    agent: {
      call: async (method: string) => {
        calls.push(method);
        if (method === "scanStatus") return ok(statusReply.value);
        if (method === "scanClose") return ok({ closed: true, freed_bytes: 0 });
        return next;
      },
    },
    jobs: { await: () => new Promise<Result<AgentJobOutcome, BeaError>>((r) => (resolveJob = r)) },
  } as unknown as LiveSession;
  const sessions = {
    onSessionEnded: (l: (e: SessionEndedEvent) => void) => void listeners.push(l),
  } as unknown as DynamicSessionPort;
  const handles = createHandleRegistry();
  const service = new ScanService({
    clock: manualClock(),
    ids: sequentialIdSource(),
    sessions,
    handles,
    store: createHitStore(() => null),
    logger: silentLogger,
  });
  const op: OperationContext = {
    opId: 1,
    name: "scan_memory",
    signal: new AbortController().signal,
    deadline: Deadline.after(1000),
  };
  const begin = () =>
    service.begin(
      session,
      op,
      { kind: "value", value_type: "i32", compare: { op: "eq", value: 1 }, regions: { protection: "rw-" } },
      {
        operation: "scan_memory",
        valueType: "i32",
        compare: "exact",
        maxHits: 100,
      },
    );
  return {
    service,
    handles,
    session,
    op,
    calls,
    begin,
    finish: async (r: Result<AgentJobOutcome, BeaError>) => {
      resolveJob(r);
      await new Promise((res) => setTimeout(res, 0));
    },
    setNext: (r: Result<unknown, BeaError>) => (next = r),
    statusReply,
    end: (e: SessionEndedEvent) => listeners.forEach((l) => l(e)),
  };
};

const begun = async (h: ReturnType<typeof harness>) => {
  const r = await h.begin();
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  return r.value;
};

describe("ScanService", () => {
  it("maps a done job to done with counts, and a failed job (non-cap error) to failed with a mapped BeaError", async () => {
    const h = harness();
    const rec = await begun(h);
    expect(rec).toMatchObject({ id: "scan_00000001", state: "running", agentScanId: "sc1", jobId: "j1" });
    await h.finish(ok(outcome(status({ count: 4 }))));
    expect(rec).toMatchObject({ state: "done", count: 4, scannedBytes: 4096, truncated: false });
    const h2 = harness();
    const bad = await begun(h2);
    await h2.finish(
      ok(
        outcome(
          status({
            state: "failed",
            error: { _tag: "BadParams", message: "x", issues: [{ path: "pattern", problem: "invalid match pattern" }] },
          }),
          "failed",
        ),
      ),
    );
    expect(bad.state).toBe("failed");
    expect(bad.error).toMatchObject({ _tag: "InputError", operation: "scan_memory" });
  });

  it("a cancelled or capped job keeps its hits: done + cancelled / truncated, reflected in coverage and limitations", async () => {
    const h = harness();
    const rec = await begun(h);
    await h.finish(
      ok(
        outcome(
          status({ state: "failed", error: { _tag: "Cancelled", message: "c", phase: "scan-first" } }),
          "cancelled",
        ),
      ),
    );
    expect(rec).toMatchObject({ state: "done", cancelled: true });
    expect(scanCoverage(rec)).toEqual({ status: "partial", truncated: false, reasons: ["cancelled"] });
    const h2 = harness();
    const capped = await begun(h2);
    await h2.finish(
      ok(
        outcome(
          status({
            state: "failed",
            count: 100,
            error: { _tag: "ResourceLimit", message: "c", resource: "scan_candidates", limit: 100 },
          }),
          "failed",
        ),
      ),
    );
    expect(capped).toMatchObject({ state: "done", truncated: true, cap: 100 });
    expect(scanLimitations(capped).join(" ")).toContain("hit cap (100)");
  });

  it("a job without a result fails as a provider failure; a lost await is recovered with scanStatus", async () => {
    const h = harness();
    const rec = await begun(h);
    await h.finish(ok(outcome(null, "failed")));
    expect(rec.error).toMatchObject({ _tag: "ProviderFailure", provider: "agent" });
    const h2 = harness();
    const lost = await begun(h2);
    await h2.finish(err({ _tag: "ProviderTimeout", operation: "x", timeout_ms: 1, phase: "job" }));
    expect(lost).toMatchObject({ state: "running", pending: null });
    h2.statusReply.value = status({ count: 9 });
    expect(await h2.service.refresh(h2.session, h2.op, lost)).toEqual({ ok: true, value: undefined });
    expect(lost).toMatchObject({ state: "done", count: 9 });
    expect(h2.calls).toContain("scanStatus");
  });

  it("caps open scans per session and passes agent errors through", async () => {
    const h = harness();
    for (let i = 0; i < MAX_SCANS_PER_SESSION; i++) await begun(h);
    const ninth = await h.begin();
    expect(ninth).toMatchObject({
      ok: false,
      error: { _tag: "ResourceConstraint", resource: "capacity", limits: { max_scans_per_session: 8 } },
    });
    const h2 = harness();
    h2.setNext(
      err({
        _tag: "ResourceConstraint",
        operation: "scan_memory",
        resource: "capacity",
        limits: { resource: "scan_snapshot" },
      }),
    );
    expect(await h2.begin()).toMatchObject({ ok: false, error: { limits: { resource: "scan_snapshot" } } });
  });

  it("narrow refuses a running scan; exit orphans scans (kept for the host store), close releases them", async () => {
    const h = harness();
    const rec = await begun(h);
    expect(await h.service.narrow(h.session, h.op, rec, { op: "changed" })).toMatchObject({
      ok: false,
      error: { _tag: "InvalidState", state: "running" },
    });
    h.end({ sessionId: "s1", kind: "live", reason: "exited" });
    await new Promise((res) => setTimeout(res, 0));
    expect(rec).toMatchObject({ state: "failed", agentGone: true, error: { _tag: "TargetExited" } });
    expect(h.handles.list("s1").map((v) => v.id)).toEqual([rec.id]);
    expect(await h.service.refresh(h.session, h.op, rec)).toEqual({ ok: true, value: undefined });
    expect(h.calls).not.toContain("scanStatus");
    const h2 = harness();
    const closed = await begun(h2);
    h2.end({ sessionId: "s1", kind: "live", reason: "closed" });
    await new Promise((res) => setTimeout(res, 0));
    expect(closed.state).toBe("released");
    expect(h2.calls).not.toContain("scanClose");
    expect(h2.handles.list("s1")).toEqual([]);
    expect(h2.handles.find(closed.id)?.get(closed.id)).toMatchObject({ state: "released" });
  });
});
