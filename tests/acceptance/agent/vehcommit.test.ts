// BEA-FEEDBACK.md item 4 acceptance (raw Frida, no BEA host). vehcommit.exe models ASan on Win64: worker threads
// fault inside their allocator's lock on reserved pages, and the program's own vectored handler (registered after
// Frida's) commits them. With --intercept-crt, dbghelp's CRT heap imports take that lock first, which is what ASan's
// CRT interception amounts to. A first-chance handler that unwinds with dbghelp (Thread.backtrace ACCURATE, the old
// report path) self-deadlocks on the lock its own thread holds, and every other thread queues behind it: the control
// test shows that. The core agent keeps the same target running, with a JS hook on the hot vc_hot and blocking
// first-chance reports switched ON (its backtraces come from ntdll's unwinder, never dbghelp), and passes ASan-like
// faults (shadow range, pass-through modules) through with no row and no report.
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import type { CrashReport, ExceptionRow } from "../../../src/shared/agentProtocol.js";
import { skipNote } from "../../support/acceptance/fixtures.js";
import { buildTestAgent } from "../../support/agent/coreAgent.js";
import { agentLaneSkip, setupAgentLane, type AgentLane } from "../../support/agent/lane.js";
import { defaultHello, RawAgent } from "../../support/agent/rawAgent.js";
import { TEST_ENTRY_NAME, TEST_ENTRY_SOURCE } from "../../support/agent/testEntry.js";
import { OwnedPidLedger } from "../../support/process/ownedPidLedger.js";

const skip = agentLaneSkip();

/** Test-only RPCs on top of the lane's test entry: the dispatcher's counters and a counting JS hook. */
const COUNTERS_ENTRY = `${TEST_ENTRY_SOURCE}
let hotCalls = 0;
const hotHooks: InvocationListener[] = [];
Object.assign(rpc.exports, {
  testCrashCounters(): unknown {
    return { passthrough: core.exceptions.passthrough, blocking_reports: core.exceptions.blockingReports,
      by_type: { ...core.exceptions.byType }, hot_calls: hotCalls };
  },
  testHotHook(p: { module: string; export: string }): unknown {
    const target = Process.getModuleByName(p.module).getExportByName(p.export);
    hotHooks.push(Interceptor.attach(target, { onEnter() { hotCalls++; } }));
    Interceptor.flush();
    return { target: target.toString() };
  },
});
`;

/** The old first-chance report path in isolation: a dbghelp unwind on the faulting thread (no BEA agent). */
const ACCURATE_CONTROL = `
Process.setExceptionHandler((d) => {
  if (d.type === "access-violation") Thread.backtrace(d.context, Backtracer.ACCURATE);
  return false;
});
rpc.exports = { ping() { return 1; } };
send({ bea: "ready" });
`;

interface Beat {
  readonly n: number;
  readonly commits: number;
  readonly crt: number;
  readonly ms: number;
}
const beatsOf = (output: string): Beat[] =>
  [...output.matchAll(/HEARTBEAT n=(\d+) commits=(\d+) crt=(\d+) ms=(\d+)/gu)].map((m) => ({
    n: Number(m[1]),
    commits: Number(m[2]),
    crt: Number(m[3]),
    ms: Number(m[4]),
  }));

interface Counters {
  readonly passthrough: number;
  readonly blocking_reports: number;
  readonly by_type: Record<string, number>;
  readonly hot_calls: number;
}

/** An RPC answer within `ms`, else "timeout" (a deadlocked target holds the JS lock). */
const within = async <T>(work: Promise<T>, ms: number): Promise<T | "timeout"> => {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([work, new Promise<"timeout">((r) => (timer = setTimeout(() => r("timeout"), ms)))]);
  } finally {
    clearTimeout(timer);
  }
};

describe.skipIf(skip !== false)(`ASan-like on-demand commit under the agent (vehcommit)${skipNote(skip)}`, () => {
  let lane: AgentLane;
  let bundle: string;
  let ledger: OwnedPidLedger;
  const agents: RawAgent[] = [];

  const start = async (args: readonly string[], source = bundle): Promise<RawAgent> => {
    const a = await RawAgent.start({
      bundle: source,
      program: lane.fixtures.vehcommit,
      args: ["--threads", "4", "--heartbeat-ms", "100", ...args],
      cwd: lane.fixtureDir,
    });
    agents.push(a);
    ledger.recordOwned(a.pid, null, `vehcommit ${args.join(" ")}`);
    return a;
  };

  /** Resume and collect the heartbeats of the first `ms` milliseconds the program ran. */
  const runFor = async (a: RawAgent, ms: number): Promise<Beat[]> => {
    await a.resume();
    expect(await a.waitFor(() => a.output().includes("READY pid="), 10_000)).toBe(true);
    await a.waitFor(() => (beatsOf(a.output()).at(-1)?.ms ?? 0) >= ms, ms + 15_000);
    return beatsOf(a.output());
  };

  /** Allocations made in every 1 s window of the run (a stalled window shows 0). */
  const perSecond = (beats: readonly Beat[], ms: number): number[] => {
    const at = (t: number): number => beats.filter((b) => b.ms <= t).at(-1)?.n ?? 0;
    const out: number[] = [];
    for (let t = 1000; t <= ms; t += 1000) out.push(at(t) - at(t - 1000));
    return out;
  };

  beforeAll(async () => {
    lane = await setupAgentLane();
    ledger = new OwnedPidLedger(lane.pidcheck);
    bundle = (await buildTestAgent({ mode: "core", entry: { name: TEST_ENTRY_NAME, source: COUNTERS_ENTRY } })).bundle;
  }, 180_000);

  afterEach(async () => {
    for (const a of agents.splice(0)) await a.close();
  });

  afterAll(async () => {
    await RawAgent.shutdownFrida();
    await ledger?.assertClean();
  });

  it("control: a dbghelp unwind in the first-chance handler (the old report path) deadlocks the target", async () => {
    const a = await start(["--intercept-crt"], ACCURATE_CONTROL);
    const beats = await runFor(a, 2500);
    // the main thread still prints, but no worker allocates past its first fault, and the JS lock is gone for good
    expect(beats.length).toBeGreaterThan(10);
    expect(perSecond(beats, 2000)).toEqual([0, 0]);
    expect(await within(a.rpc("ping"), 1500)).toBe("timeout");
  }, 60_000);

  it("blocking first-chance reports ON + a JS hook on the hot function: the target keeps running for 6 s", async () => {
    const a = await start(["--intercept-crt"]);
    await a.hello(); // the lane's policy: first_chance_blocking true, access violations are crash class
    await a.rpc("testHotHook", { module: "vehcommit.exe", export: "vc_hot" });
    const beats = await runFor(a, 6000);
    const windows = perSecond(beats, 6000);
    expect(
      windows.every((n) => n > 1000),
      `allocations per second ${JSON.stringify(windows)}`,
    ).toBe(true);
    // nothing called dbghelp's CRT imports on the way (its startup calls end before the first second)
    const settled = beats.filter((b) => b.ms >= 1000);
    expect(new Set(settled.map((b) => b.crt)).size).toBe(1);
    // the agent answers, and it did the work: hook hits, blocking reports (rate-limited), rows
    expect(await within(a.rpc("ping"), 2000)).not.toBe("timeout");
    const counters = (await a.rpc<{ ok: true; value: Counters } | Counters>("testCrashCounters")) as Counters;
    expect(counters.hot_calls).toBeGreaterThan(10_000);
    expect(counters.blocking_reports).toBeGreaterThanOrEqual(1);
    expect(counters.passthrough).toBe(0);
    const reports = a.messages("crash").map((m) => m["report"] as CrashReport);
    expect(reports.length).toBe(counters.blocking_reports);
    const report = reports[0]!;
    expect(report).toMatchObject({
      phase: "first-chance",
      type: "access-violation",
      memory: { operation: "write" },
      backtrace_source: "exception-context",
    });
    // [pc in vc_alloc, the worker's return site, ..., the thread's start in ntdll]: unwound without dbghelp
    expect(report.backtrace[0]?.module).toBe("vehcommit.exe");
    expect(report.backtrace[1]?.module).toBe("vehcommit.exe");
    expect(report.backtrace.map((f) => f.module?.toLowerCase())).toContain("ntdll.dll");
    expect(a.acked.filter((t) => t.startsWith("crash-"))).toHaveLength(reports.length);
    const rows = a.rows("s:exceptions") as ExceptionRow[];
    expect(rows.some((r) => r[3] === "access-violation" && r[7] === "reported")).toBe(true);
  }, 90_000);

  it("ASan's shadow range: access violations there pass through with no row and no report", async () => {
    const a = await start(["--asan-shadow"]);
    await a.hello(); // blocking first-chance reports ON: a pass-through never reaches them
    await a.rpc("testHotHook", { module: "vehcommit.exe", export: "vc_hot" });
    const beats = await runFor(a, 3000);
    expect(perSecond(beats, 3000).every((n) => n > 1000)).toBe(true);
    const counters = (await a.rpc("testCrashCounters")) as Counters;
    const commits = beats.at(-1)?.commits ?? 0;
    expect(commits).toBeGreaterThan(1000);
    expect(counters.passthrough).toBeGreaterThanOrEqual(Math.floor(commits * 0.9));
    expect(counters.blocking_reports).toBe(0);
    expect(a.messages("crash")).toEqual([]);
    expect((a.rows("s:exceptions") as ExceptionRow[]).filter((r) => r[3] === "access-violation")).toEqual([]);
  }, 60_000);

  it("crash.passthrough_modules: faults whose pc lies in a listed module pass through (case-insensitive)", async () => {
    const a = await start([]);
    await a.hello({ crash: { ...defaultHello().crash, passthrough_modules: ["VehCommit.EXE"] } });
    const beats = await runFor(a, 3000);
    expect(perSecond(beats, 3000).every((n) => n > 1000)).toBe(true);
    const counters = (await a.rpc("testCrashCounters")) as Counters;
    expect(counters.passthrough).toBeGreaterThan(1000);
    expect(counters.blocking_reports).toBe(0);
    expect(a.messages("crash")).toEqual([]);
    expect((a.rows("s:exceptions") as ExceptionRow[]).filter((r) => r[3] === "access-violation")).toEqual([]);
  }, 60_000);
});
