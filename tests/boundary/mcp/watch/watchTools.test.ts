import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { LIMITATIONS } from "../../../../src/domain/evidence/limitations.js";
import type { JsonObject } from "../../../../src/domain/json.js";
import { err, ok } from "../../../../src/domain/result.js";
import { BINARY_LAYOUTS } from "../../../../src/shared/binaryLayouts.js";
import type { TraceStartResult, WatchInstallResult } from "../../../../src/shared/agentProtocol.js";
import { parseDrcov } from "../../../support/drcov.js";
import { connectInMemoryBea, type InMemoryBea } from "../../../support/mcp/inMemory.js";
import { expectToolSuccess, parseToolError } from "../../../support/mcp/parseToolError.js";
import { createWorld, FakeRecording, SESSION, type FakeWorld } from "./fakes.js";

const DR_RESULT: WatchInstallResult = {
  instrument_id: "w1",
  stream_id: "s3",
  method: "debug-register",
  slot: 0,
  pages: null,
  armed_threads: 5,
  arm_errors: [],
  verified: { threads_checked: 5, ok: 5 },
  initial_value: "0000a041",
  effect: { kind: "watchpoint-set", reversible: true, targets: [], thread_ids: null, before: [] },
};
const PG_RESULT: WatchInstallResult = {
  ...DR_RESULT,
  method: "page-guard",
  slot: null,
  pages: ["0x2a000000"],
  armed_threads: 0,
  verified: null,
};
const POLL_RESULT: WatchInstallResult = { ...DR_RESULT, method: "poll", slot: null, armed_threads: 0, verified: null };
const TRACE_RESULT: TraceStartResult = {
  instrument_id: "t1",
  stream_id: "s4",
  row_kind: "block-count/1",
  layout: BINARY_LAYOUTS["block-count/1"],
  threads: [],
  queue: { capacity: 2_097_152, drain_ms: 50 },
  excluded: [{ module: "msvcrt.dll", base: "0x7ffa00000000", size: 0x100000 }],
  effect: { kind: "stalker-followed", reversible: true, targets: [], thread_ids: null, before: [] },
};

let bea: InMemoryBea | null = null;
let world: FakeWorld;
const start = async (): Promise<InMemoryBea> => {
  world = createWorld();
  bea = await connectInMemoryBea({ services: world.services });
  return bea;
};
afterEach(async () => {
  await bea?.close();
  bea = null;
});
const call = async (name: string, args: JsonObject) => (bea as InMemoryBea).client.callTool({ name, arguments: args });

describe("watch_memory installs (DESIGN §6.2 #23)", () => {
  it("arms a debug register on every thread and records effect, stream, recording and install evidence", async () => {
    await start();
    world.agent = (method) => (method === "watchInstall" ? ok(DR_RESULT) : err({ _tag: "Internal", operation: "x" }));
    const out = expectToolSuccess(
      await call("watch_memory", {
        session_id: SESSION,
        address: "0x2a000008",
        size: 4,
        view: "f32",
        duration_ms: 2000,
      }),
    );
    expect(world.agentCalls).toEqual([
      {
        method: "watchInstall",
        params: {
          method: "debug-register",
          address: "0x2a000008",
          size: 4,
          access: "write",
          threads: "all",
          capture: { registers: "none", backtrace: 0, values: true },
          lifetime: { duration_ms: 2000, max_hits: 10_000, clock: "install" },
        },
      },
    ]);
    expect(out).toMatchObject({
      method: "debug_register",
      slot: 0,
      threads_armed: 5,
      target: { va: "0x2a000008" },
      instrument: { recording_id: "rec_000000a1", kind: "watch", state: "active", end_reason: null },
      predicate_type: "bea.instrument.install",
      effects_applied: [`fx_${"0".repeat(63)}1`],
    });
    expect(out["limitations"]).toContain(LIMITATIONS.WATCH_DR_TRAP_AFTER);
    expect(world.effects[0]).toMatchObject({
      kind: "watch-armed",
      applied_by: "watch_memory",
      target: { size: 4, threads: "all" },
    });
    expect(world.binds[0]).toMatchObject({
      agentStream: "s3",
      spec: { source: { kind: "watch", channel: "s3" }, encoding: { kind: "json-rows", row_kind: "watch/1" } },
    });
    const decoders = world.binds[0]?.spec.decoders as JsonObject | undefined;
    expect(decoders?.["modules"]).toHaveLength(2);
    expect([...world.recordings.values()][0]?.create).toMatchObject({
      kind: "watch",
      agentInstrumentId: "w1",
      agentStream: "s3",
      maxEvents: 10_000,
      startsAtResume: false,
    });
    expect(world.drafts[0]).toMatchObject({
      predicate_type: "bea.instrument.install",
      operation: "watch_memory",
      result: { recording_id: "rec_000000a1", method: "debug_register", slot: 0, threads_armed: 5 },
    });
  });

  it("auto falls back to page_guard when no debug register is free (CT-I4)", async () => {
    await start();
    world.agent = (_method, params) =>
      (params as { method: string }).method === "debug-register"
        ? err({
            _tag: "InstrumentationFailed",
            operation: "watch_memory",
            reason: "no-free-slot",
            address: null,
            conflicting_id: null,
          })
        : ok(PG_RESULT);
    const out = expectToolSuccess(await call("watch_memory", { session_id: SESSION, address: "0x2a000008" }));
    expect(world.agentCalls.map((c) => (c.params as { method: string }).method)).toEqual([
      "debug-register",
      "page-guard",
    ]);
    expect(world.agentCalls[1]?.params).toMatchObject({ rate_limit: { max_per_sec: 20_000, window_ms: 100 } });
    expect(out).toMatchObject({ method: "page_guard", slot: null, threads_armed: null });
    expect(out["limitations"]).toContain(LIMITATIONS.WATCH_PAGE_GUARD_COST);
    // review fix AGENT-3: the fallback is announced, and the guard's effect on the target's system calls is stated
    expect(out["limitations"]).toEqual(
      expect.arrayContaining([LIMITATIONS.WATCH_AUTO_PAGE_GUARD, LIMITATIONS.WATCH_KERNEL_ACCESS]),
    );
    expect(LIMITATIONS.WATCH_KERNEL_ACCESS).toMatch(/fail with STATUS_GUARD_PAGE_VIOLATION/u);
  });

  it("a refused debug register names the holders' rec_ ids and a valid method spelling (UX-9)", async () => {
    await start();
    // a watch installed earlier holds slot 0 (agent instrument w1)
    world.agent = () => ok(DR_RESULT);
    const held = expectToolSuccess(
      await call("watch_memory", { session_id: SESSION, address: "0x2a000008", method: "debug_register" }),
    );
    const holder = (held["instrument"] as { recording_id: string }).recording_id;
    const agentId = [...world.recordings.values()].find((r) => r.id === holder)?.create.agentInstrumentId;
    world.agent = () =>
      err({
        _tag: "InstrumentationFailed",
        operation: "watch_memory",
        reason: "no-free-slot",
        address: null,
        conflicting_id: null,
        diagnostics: { in_use: [{ slot: 0, owner: agentId ?? "w1", kind: "watch" }] },
      });
    const error = parseToolError(
      await call("watch_memory", { session_id: SESSION, address: "0x2a000010", method: "debug_register" }),
    );
    expect(error.code).toBe("instrumentation_failed");
    expect(error.remediation?.action).toContain('"page_guard"');
    expect(error.remediation?.action).not.toContain("page-guard");
    expect(error.details).toMatchObject({
      conflicting_id: holder,
      diagnostics: { holders: [holder], slots_in_use: 1 },
    });
    expect(JSON.stringify(error.details)).not.toContain('"w1"');
  });

  it("names the nearest valid watch for a misaligned debug register, without touching the target", async () => {
    await start();
    const error = parseToolError(
      await call("watch_memory", { session_id: SESSION, address: "0x2a000002", size: 4, method: "debug_register" }),
    );
    expect(error.code).toBe("invalid_request");
    expect(JSON.stringify(error.details)).toContain("watch 8 bytes at 0x2a000000");
    expect(world.agentCalls).toEqual([]);
  });
});

describe("watch_memory refusals, waits and failures (DESIGN §6.2 #23)", () => {
  it("restates an agent WatchInvalid refusal at the address", async () => {
    await start();
    world.agent = () =>
      err({
        _tag: "InputError",
        operation: "watch_memory",
        issues: [{ path: "size", reason: "invalid_value", message: "The watch is invalid (stack-page)." }],
        diagnostics: { agent_tag: "WatchInvalid", reason: "stack-page" },
      });
    const error = parseToolError(
      await call("watch_memory", { session_id: SESSION, address: "0x2a000008", method: "page_guard" }),
    );
    expect(error.code).toBe("invalid_request");
    expect(JSON.stringify(error.details)).toContain("thread stack");
  });

  it("poll records no effect and uses poll/1 rows", async () => {
    await start();
    world.agent = () => ok(POLL_RESULT);
    const out = expectToolSuccess(
      await call("watch_memory", {
        session_id: SESSION,
        address: "0x2a000000",
        size: 128,
        method: "poll",
        view: "f32",
        interval_ms: 16,
      }),
    );
    expect(out).toMatchObject({ method: "poll", instrument: { kind: "poll" } });
    expect(out).not.toHaveProperty("effects_applied");
    expect(world.effects).toEqual([]);
    expect(world.binds[0]?.spec.encoding).toEqual({ kind: "json-rows", row_kind: "poll/1" });
    expect(world.agentCalls[0]?.params).toMatchObject({ method: "poll", size: 128, interval_ms: 16 });
    expect(out["limitations"]).toContain(LIMITATIONS.WATCH_POLL_SAMPLED(16));
  });

  it("waits, returns the finished summary and reports a rate-limit end and suspension windows", async () => {
    await start();
    world.agent = () => ok(PG_RESULT);
    world.onWait = (rec) => {
      rec.state = "finished";
      rec.end_reason = "rate-limit"; // the agent's "rate-limit" end (SessionRecord END_REASONS, CT-I4)
      rec.summary = {
        hits: 5,
        method: "page_guard",
        writers: [],
        writers_total: 0,
        rate_limited: { cause: "rate", limit_per_sec: 20_000, peak_per_sec: 31_000, busy_pct: 17 },
        guard: { bea_guard_suspended: 2, kernel_rearms: 0, rearm_fails: 0 },
      };
    };
    const out = expectToolSuccess(
      await call("watch_memory", { session_id: SESSION, address: "0x2a000008", method: "page_guard", wait_ms: 1000 }),
    );
    expect(world.waits).toHaveLength(1);
    expect(out["instrument"]).toMatchObject({ state: "finished", summary: { hits: 5 } });
    expect(out["coverage"]).toEqual({
      status: "partial",
      truncated: false,
      reasons: ["guard_suspended", "watch_rate_limit"],
    });
    expect(out["limitations"]).toEqual(
      expect.arrayContaining([LIMITATIONS.WATCH_RATE_LIMIT(20_000), LIMITATIONS.WATCH_SUSPEND_WINDOWS(2)]),
    );
    expect(out["limitations"]).not.toContain(LIMITATIONS.WATCH_RATE_LIMIT_BUSY(17));
  });

  it("explains a busy trip of the valve by the share of time the target spent in BEA's handlers", async () => {
    await start();
    world.agent = () => ok(PG_RESULT);
    world.onWait = (rec) => {
      rec.state = "finished";
      rec.end_reason = "rate-limit"; // the agent's "rate-limit" end (SessionRecord END_REASONS, CT-I4)
      rec.summary = {
        hits: 900,
        method: "page_guard",
        writers: [],
        writers_total: 0,
        rate_limited: { cause: "busy", limit_per_sec: 20_000, peak_per_sec: 18_002, busy_pct: 93 },
        guard: { bea_guard_suspended: 0, kernel_rearms: 3, rearm_fails: 0 },
      };
    };
    const out = expectToolSuccess(
      await call("watch_memory", { session_id: SESSION, address: "0x2a000008", method: "page_guard", wait_ms: 1000 }),
    );
    expect(out["coverage"]).toEqual({ status: "partial", truncated: false, reasons: ["watch_rate_limit"] });
    expect(out["limitations"]).toContain(LIMITATIONS.WATCH_RATE_LIMIT_BUSY(93));
    expect(out["limitations"]).not.toContain(LIMITATIONS.WATCH_RATE_LIMIT(20_000));
    // review fix AGENT-3: guards consumed outside a trap (the target's failed system calls) are counted
    expect(out["limitations"]).toContain(LIMITATIONS.WATCH_KERNEL_ACCESS_SEEN(3));
    expect(out["limitations"]).not.toContain(LIMITATIONS.WATCH_AUTO_PAGE_GUARD); // method was explicit
  });

  it("answers session_not_found for an unknown session and stops the agent instrument when recording fails", async () => {
    await start();
    world.sessionKind = null;
    expect(parseToolError(await call("watch_memory", { session_id: SESSION, address: "0x10" })).code).toBe(
      "session_not_found",
    );
    world.sessionKind = "live";
    world.agent = (method) =>
      method === "watchInstall" ? ok(DR_RESULT) : ok({ stopped: [], not_found: [], unreverted: [] });
    (world.services.evidence as unknown as { recorder: { record: unknown } }).recorder.record = async () =>
      err({ _tag: "ResourceConstraint", operation: "ledger", resource: "disk", limits: {} });
    const error = parseToolError(await call("watch_memory", { session_id: SESSION, address: "0x2a000008" }));
    expect(error.code).toBe("resource_constraint");
    expect(world.agentCalls.map((c) => c.method)).toEqual(["watchInstall", "instrumentStop"]);
    expect(world.ended).toEqual(["s3"]);
    expect(world.transitions).toEqual([{ id: `fx_${"0".repeat(63)}1`, to: "reverted" }]);
  });
});

describe("trace_execution (DESIGN §6.2 #24)", () => {
  it("follows N invocations of a function, records only the named modules and excludes the others", async () => {
    await start();
    world.agent = () => ok(TRACE_RESULT);
    const out = expectToolSuccess(
      await call("trace_execution", { session_id: SESSION, on_call: "game_sim.exe!physics_step", invocations: 2 }),
    );
    expect(world.agentCalls[0]).toEqual({
      method: "traceStart",
      params: {
        on_call: { target: { va: "0x7ff7000017a0" }, invocations: 2 },
        mode: "coverage",
        modules: ["game_sim.exe"],
        exclude_modules: ["msvcrt.dll"],
        lifetime: { duration_ms: 10_000, max_hits: 1_000_000, clock: "install" },
      },
    });
    expect(out).toMatchObject({ instrument: { kind: "trace", state: "active" }, followed_threads: [] });
    expect(out["limitations"]).toEqual(
      expect.arrayContaining([
        LIMITATIONS.TRACE_ENTRY_SYNTHESIZED,
        LIMITATIONS.TRACE_EXCLUDED_MODULES(1),
        LIMITATIONS.TRACE_DYNAMIC_BLOCKS,
      ]),
    );
    expect(world.binds[0]?.spec.encoding).toMatchObject({
      kind: "fixed-records",
      row_kind: "block-count/1",
      record_bytes: 24,
    });
    expect(world.binds[0]?.spec.decoders).toMatchObject({
      mode: "coverage",
      on_call: "0x7ff7000017a0",
      invocations: 2,
    });
    expect(world.effects[0]).toMatchObject({ kind: "trace-following", applied_by: "trace_execution" });
  });

  it("refuses an on_call address inside a function body before tracing (UX-1)", async () => {
    await start();
    world.agent = () => ok(TRACE_RESULT);
    world.functionStart = 0x7ff700001790n; // physics_step resolves to 0x7ff7000017a0, 0x10 bytes in
    const error = parseToolError(
      await call("trace_execution", { session_id: SESSION, on_call: "game_sim.exe!physics_step", invocations: 2 }),
    );
    expect(error.code).toBe("invalid_request");
    expect(error.details).toMatchObject({
      issues: [{ path: "on_call" }],
      diagnostics: { reason: "not_function_start", function_start: "game_sim.exe+0x1790", offset: 16 },
    });
    expect(world.agentCalls).toEqual([]);
  });

  it("waits out a thread that is still settling once, and refuses a thread another owner follows", async () => {
    await start();
    const busy = (retryAfterMs: number) =>
      err({
        _tag: "ResourceConstraint",
        operation: "trace_execution",
        resource: "capacity",
        limits: { thread_id: 77, retry_after_ms: retryAfterMs },
        retryable: true,
      } as const);
    let calls = 0;
    world.agent = () => (++calls === 1 ? busy(40) : ok({ ...TRACE_RESULT, threads: [77] }));
    expectToolSuccess(await call("trace_execution", { session_id: SESSION, thread_ids: [77] }));
    expect(world.agentCalls.map((c) => c.method)).toEqual(["traceStart", "traceStart"]);
    world.agentCalls.length = 0;
    world.agent = () => busy(0);
    expect(parseToolError(await call("trace_execution", { session_id: SESSION, thread_ids: [77] })).code).toBe(
      "resource_constraint",
    );
    expect(world.agentCalls.map((c) => c.method)).toEqual(["traceStart"]);
  });

  it("maps calls to the agent's call_summary and refuses an unknown module", async () => {
    await start();
    world.agent = () =>
      ok({
        ...TRACE_RESULT,
        row_kind: "call-site-count/1",
        layout: BINARY_LAYOUTS["call-site-count/1"],
        threads: [77],
      });
    expectToolSuccess(await call("trace_execution", { session_id: SESSION, thread_ids: [77], mode: "calls" }));
    expect(world.agentCalls[0]?.params).toMatchObject({ threads: [77], mode: "call_summary" });
    const error = parseToolError(
      await call("trace_execution", { session_id: SESSION, thread_ids: [77], modules: ["nope.dll"] }),
    );
    expect(error.code).toBe("invalid_request");
    expect(JSON.stringify(error.details)).toContain("modules[0]");
  });

  it("returns the finished summary with the installed mode and threads and suggests export_coverage", async () => {
    await start();
    world.agent = () =>
      ok({ ...TRACE_RESULT, row_kind: "block-span/1", layout: BINARY_LAYOUTS["block-span/1"], threads: [77] });
    world.onWait = (rec) => {
      rec.state = "finished";
      rec.end_reason = "duration";
      rec.summary = {
        mode: "coverage",
        invocations: 0,
        threads: [],
        blocks: 1,
        modules: [{ name: "game_sim.exe", blocks: 1 }],
        functions: [],
      };
      rec.events = [{ seq: 1, va: "0x7ff7000017a0", size: 5, block: "game_sim.exe+0x17a0", module: "game_sim.exe" }];
    };
    const out = expectToolSuccess(
      await call("trace_execution", { session_id: SESSION, thread_ids: [77], wait_ms: 500 }),
    );
    expect(out["instrument"]).toMatchObject({
      state: "finished",
      summary: { mode: "coverage", threads: [77], functions: [] },
    });
    expect(out["limitations"]).toContain(LIMITATIONS.TRACE_FUNCTIONS_UNRESOLVED(1));
    expect(out["next"]).toEqual([
      { tool: "export_coverage", arguments: { recording_id: "rec_000000a1" }, reason: expect.any(String) as string },
    ]);
  });
});

describe("export_coverage (DESIGN §6.2 #25)", () => {
  const traceRecording = (w: FakeWorld, mode: "coverage" | "calls"): FakeRecording => {
    const rec = new FakeRecording("rec_000000f1", {
      sessionId: SESSION,
      kind: "trace",
      agentInstrumentId: "t9",
      agentStream: "s9",
      streamId: null,
      effectId: null,
      durationMs: 1000,
      maxEvents: 100,
      startsAtResume: false,
      decoders: {
        v: 1,
        kind: "trace",
        mode,
        layout: "block-count/1",
        on_call: null,
        invocations: 0,
        threads: [77],
        modules: [["game_sim.exe", "0x7ff700000000", 0x1e000, "C:\\fixtures\\game_sim.exe"]],
        instance_id: `pi_${"a".repeat(64)}`,
      },
    });
    rec.state = "finished";
    rec.events = [
      { seq: 1, va: "0x7ff7000017a5", size: 25, hits: 2, block: "x", module: "game_sim.exe" },
      { seq: 2, va: "0x7ff7000017a0", size: 5, hits: 2, block: "x", module: "game_sim.exe" },
      { seq: 3, va: "0x7ff7000017a5", size: 25, hits: 1, block: "x", module: "game_sim.exe" },
    ];
    w.recordings.set(rec.id, rec);
    return rec;
  };

  it("writes a drcov file under the run's exports directory that the independent reader parses", async () => {
    const b = await start();
    traceRecording(world, "coverage");
    const out = expectToolSuccess(await call("export_coverage", { recording_id: "rec_000000f1" }));
    const exportsDir = b.app.config.layout.exportsDir(b.app.run.runId);
    expect(await readdir(exportsDir)).toEqual(["rec_000000f1.drcov"]);
    const bytes = new Uint8Array(await readFile(join(exportsDir, "rec_000000f1.drcov")));
    const parsed = parseDrcov(bytes);
    expect(parsed.blocks).toEqual([
      { start: 0x17a0, size: 5, moduleId: 0 },
      { start: 0x17a5, size: 25, moduleId: 0 },
    ]);
    expect(parsed.modules[0]?.path).toBe("C:\\fixtures\\game_sim.exe");
    expect(out).toMatchObject({
      path: join(exportsDir, "rec_000000f1.drcov"),
      bytes: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      format: "drcov",
      blocks: 2,
      modules: [{ name: "game_sim.exe", blocks: 2 }],
      functions: [],
      predicate_type: "bea.coverage.export",
    });
    expect(out["limitations"]).toContain(LIMITATIONS.COVERAGE_DRCOV_LAYOUT);
    const blob = JSON.parse(new TextDecoder().decode([...world.blobs.values()][0]));
    expect(blob).toMatchObject({
      schema: "bea.coverage/1",
      blocks: [
        [0, 0x17a0, 5, 2],
        [0, 0x17a5, 25, 3],
      ],
    });
    expect(world.drafts[0]?.blobs).toHaveLength(1);
    // writers never overwrite
    expect(parseToolError(await call("export_coverage", { recording_id: "rec_000000f1" })).code).toBe(
      "file_operation_failed",
    );
  });

  it("refuses out_path outside the exports roots, calls-mode recordings and unknown sources", async () => {
    await start();
    traceRecording(world, "calls");
    const policy = parseToolError(
      await call("export_coverage", { recording_id: "rec_000000f1", out_path: "C:\\Windows\\cov.drcov" }),
    );
    expect(policy.code).toBe("access_denied");
    expect(parseToolError(await call("export_coverage", { recording_id: "rec_000000f1" })).code).toBe(
      "invalid_request",
    );
    expect(parseToolError(await call("export_coverage", { recording_id: "rec_0000ffff" })).code).toBe(
      "reference_not_found",
    );
    expect(parseToolError(await call("export_coverage", { evidence_id: `ev_${"9".repeat(64)}` })).code).toBe(
      "reference_not_found",
    );
  });

  it("exports a call or emulation result's bea.coverage/1 blob as module+offset lines", async () => {
    const b = await start();
    const blob = {
      schema: "bea.coverage/1",
      source: {
        kind: "emulation",
        engine: "unicorn",
        granularity: "translation-block",
        session_id: "e",
        evidence_id: null,
        vectors: 1,
      },
      address_space: "emulation-image",
      modules: [
        {
          id: 0,
          name: "mathlib.dll",
          path: null,
          base: "0x180000000",
          size: 0x10000,
          file_sha256: null,
          preferred_base: null,
          entry_rva: null,
          timestamp: null,
        },
      ],
      blocks: [[0, 0x1010, 8, 1]],
      unattributed: [],
      totals: { distinct_blocks: 1, executions: 1, truncated: false },
    };
    const bytes = new TextEncoder().encode(JSON.stringify(blob));
    world.blobs.set("f".repeat(64), bytes);
    const id = `ev_${"7".repeat(64)}`;
    world.evidence.set(id, {
      predicate_type: "bea.emu.run",
      subject: null,
      blobs: [{ role: "coverage", sha256: "f".repeat(64), bytes: bytes.length, media_type: "application/json" }],
    });
    const out = expectToolSuccess(await call("export_coverage", { evidence_id: id, format: "modoff" }));
    const exportsDir = b.app.config.layout.exportsDir(b.app.run.runId);
    expect(await readFile(join(exportsDir, `${id}.txt`), "utf8")).toBe("mathlib.dll+0x1010\n");
    expect(out).toMatchObject({ format: "modoff", blocks: 1 });
    expect(world.drafts[0]?.evidence_links).toEqual([id]);
  });
});
