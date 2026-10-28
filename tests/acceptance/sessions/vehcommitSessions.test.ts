import { spawn, type ChildProcess } from "node:child_process";
import { dirname } from "node:path";

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

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
import { spawnOwned, startInProcessBea, value, type InProcessBea, type Output } from "./support/inProcessBea.js";

/**
 * BEA-FEEDBACK items 3 and 4 through the real composition (session tools, jobhost, the agent bundle of BEA_DIST_DIR):
 * vehcommit.exe faults inside its allocator's lock on every new page and commits it from its own vectored handler
 * (ASan's shadow pattern); --intercept-crt routes dbghelp's CRT heap calls through that lock (ASan's CRT interception).
 * With a JS hook on the hot vc_hot, a spawned target (default policy: blocking first-chance reports off) and an
 * attached one (config file: blocking first-chance reports ON, limits.attach_timeout_ms 30000) keep allocating every
 * second while session_status answers; bea_status reports the crash policy and the attach deadline with their source.
 * The old report path deadlocked such a target at its first fault (tests/acceptance/agent/vehcommit.test.ts, control).
 */
const skip = fridaSkip() || jobhostSkip() || gccSkip();
const ARGS = ["--threads", "4", "--heartbeat-ms", "100", "--intercept-crt"] as const;
const RUN_MS = 6000;

let vehcommit: FixtureArtifact;
let ledger: OwnedPidLedger;
const servers: InProcessBea[] = [];
const foreign: ChildProcess[] = [];

const server = async (options: Parameters<typeof startInProcessBea>[0] = {}): Promise<InProcessBea> => {
  const bea = await startInProcessBea({ label: "vehcommit", ...options });
  servers.push(bea);
  return bea;
};

/** The newest HEARTBEAT of an output text: allocations so far. */
const lastN = (text: string): number | null => {
  const m = [...text.matchAll(/HEARTBEAT n=(\d+) /gu)].at(-1);
  return m === undefined ? null : Number(m[1]);
};

/**
 * Hook vc_hot (every call enters the agent's JS; one row per 1000 calls), sample the heartbeat once per second for
 * RUN_MS through `read`, timing a session_status call each time, then stop the hook. Returns allocations per second,
 * the slowest session_status round trip and the hook's recorded events.
 */
const exercise = async (
  bea: InProcessBea,
  id: string,
  read: () => Promise<string>,
): Promise<{ perSecond: number[]; slowestStatusMs: number; hookEvents: number }> => {
  const hook = value(
    await bea.call("hook_function", {
      session_id: id,
      address: "vehcommit.exe!vc_hot",
      caller: false,
      sample_every: 1000,
      max_events: 10_000_000,
      duration_ms: 120_000,
    }),
  );
  const instrument = hook["instrument"] as { recording_id: string; kind: string; state: string };
  expect(instrument).toMatchObject({ kind: "hook", state: "active" });
  const samples: number[] = [];
  let slowest = 0;
  let next = performance.now();
  while (samples.length <= RUN_MS / 1000) {
    await new Promise((resolve) => setTimeout(resolve, Math.max(0, next - performance.now())));
    next += 1000;
    const t0 = performance.now();
    value(await bea.call("session_status", { session_id: id }));
    slowest = Math.max(slowest, performance.now() - t0);
    samples.push(lastN(await read()) ?? -1);
  }
  const stopped = value(await bea.call("stop_instrumentation", { session_id: id, ids: [instrument.recording_id] }));
  const hookEvents = (stopped["stopped"] as { events: number | null }[])[0]?.events ?? 0;
  return {
    perSecond: samples.slice(1).map((n, i) => n - (samples[i] ?? 0)),
    slowestStatusMs: Math.round(slowest),
    hookEvents,
  };
};

beforeAll(async () => {
  if (skip !== false) return;
  const manifest = await loadFixtures();
  const artifact = fixtureArtifact(manifest, "vehcommit");
  if (artifact === null) throw new Error("fixtures unavailable");
  vehcommit = artifact;
  ledger = new OwnedPidLedger(fixtureArtifact(manifest, "pidcheck")?.path ?? null);
});

afterAll(async () => {
  if (skip !== false) return;
  for (const bea of servers) await bea.close();
  try {
    await ledger.assertClean();
  } finally {
    await ledger.killAttachTargets();
    for (const child of foreign) if (child.exitCode === null) child.kill();
    await vi.waitFor(() => expect(foreign.every((c) => c.exitCode !== null || c.signalCode !== null)).toBe(true), {
      interval: 50,
      timeout: 5000,
    });
  }
}, 60_000);

describe.skipIf(skip !== false)(`an ASan-like target under BEA (vehcommit)${skipNote(skip)}`, () => {
  it("spawned, default policy: keeps allocating with a hot hook; first-chance faults are rows, not reports", async () => {
    const bea = await server();
    const status = value(await bea.call("bea_status", {}));
    expect(status["crash"]).toEqual({
      first_chance_blocking: false,
      source: "default",
      env: "BEA_CRASH_FIRST_CHANCE_BLOCKING",
      passthrough_modules: [],
    });
    expect(status["limits"]).toMatchObject({ attach_timeout_ms: 10_000 });

    const spawned = await spawnOwned({ bea, ledger }, vehcommit.path, ARGS);
    const id = spawned["session_id"] as string;
    const exceptions = (spawned["recordings"] as { recording_id: string; kind: string }[]).find(
      (r) => r.kind === "exceptions",
    );
    expect(value(await bea.call("resume_process", { session_id: id }))).toMatchObject({ state: "running" });
    const read = async (): Promise<string> =>
      (value(await bea.call("session_status", { session_id: id }))["output_tail"] as string | null) ?? "";
    await vi.waitFor(async () => expect(lastN(await read())).not.toBeNull(), { interval: 50, timeout: 10_000 });
    const run = await exercise(bea, id, read);
    expect(
      run.perSecond.every((n) => n > 1000),
      `allocations per second ${JSON.stringify(run.perSecond)}`,
    ).toBe(true);
    expect(run.slowestStatusMs).toBeLessThan(2000);
    expect(run.hookEvents).toBeGreaterThan(10);
    // the faults were recorded as first-chance rows, and no crash was reported
    const summary = value(
      await bea.call("query_events", { recording_id: exceptions?.recording_id ?? "", view: "summary" }),
    )["summary"] as Output | undefined;
    expect(summary?.["count"]).toBeGreaterThan(0);
    const after = value(await bea.call("session_status", { session_id: id }));
    expect(after).toMatchObject({ state: "running", crash: null });
    expect(value(await bea.call("close_session", { session_id: id }))).toMatchObject({ target_state: "killed" });
  }, 120_000);

  it("attached, config file: blocking first-chance reports ON and a 30 s attach deadline; still no stall", async () => {
    const bea = await server({
      config: { crash: { first_chance_blocking: true }, limits: { attach_timeout_ms: 30_000 } },
    });
    const status = value(await bea.call("bea_status", {}));
    expect(status["crash"]).toMatchObject({ first_chance_blocking: true, source: "config-file" });
    expect(status["limits"]).toMatchObject({ attach_timeout_ms: 30_000 });

    // The workers start after the attach: Frida 17.23.2's injection into a process that already faults ~10^5 times a
    // second crashed it in 4 of 5 attempts, with or without BEA's agent (a Frida race, see vehcommit.c --wait-stdin).
    const child = spawn(vehcommit.path, [...ARGS, "--wait-stdin"], {
      cwd: dirname(vehcommit.path),
      stdio: ["pipe", "pipe", "ignore"],
      windowsHide: true,
    });
    foreign.push(child);
    const out: string[] = [];
    child.stdout?.on("data", (chunk: Buffer) => out.push(chunk.toString()));
    await vi.waitFor(() => expect(out.join("")).toContain("READY"), { interval: 20, timeout: 10_000 });
    ledger.recordAttachTarget(child.pid ?? 0, null, "test-spawned vehcommit --wait-stdin");

    const attached = value(await bea.call("attach_process", { pid: child.pid ?? 0 }));
    const id = attached["session_id"] as string;
    child.stdin?.write("go\n");
    await vi.waitFor(() => expect(lastN(out.join(""))).not.toBeNull(), { interval: 20, timeout: 10_000 });
    const run = await exercise(bea, id, async () => out.join(""));
    expect(
      run.perSecond.every((n) => n > 1000),
      `allocations per second ${JSON.stringify(run.perSecond)}`,
    ).toBe(true);
    expect(run.slowestStatusMs).toBeLessThan(2000);
    expect(run.hookEvents).toBeGreaterThan(10);
    expect(value(await bea.call("close_session", { session_id: id }))).toMatchObject({
      target_state: "detached-running",
    });
    // the detached target keeps running
    const atClose = lastN(out.join("")) ?? 0;
    await vi.waitFor(() => expect(lastN(out.join("")) ?? 0).toBeGreaterThan(atClose), { interval: 50, timeout: 5000 });
    expect(child.exitCode).toBeNull();
  }, 120_000);
});
