import { spawn as nodeSpawn } from "node:child_process";

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { silentLogger } from "../../../src/domain/logger.js";
import type { PlanWire } from "../../../src/shared/callPlan.js";
import { EmuBridge, type EmuBridgeOptions } from "../../../src/providers/emulator/EmuBridge.js";
import { nodeAsPython, tempDir, writeScenario, type FakeScenario, type TempDir } from "../../support/emu/harness.js";

/**
 * EmuBridge against the protocol-faithful fake bridge (S5 §14.1 test:fast): startup checks, request/response,
 * progress, out-of-band ping and cancel, the cancel-grace kill, deadlines, crashes and the 900 ms close escalation.
 */
let work: TempDir;
const bridges: EmuBridge[] = [];
const now = (): number => performance.now();

beforeAll(async () => {
  work = await tempDir("bridge");
});
afterEach(async () => {
  await Promise.all(bridges.splice(0).map((b) => b.close()));
});
afterAll(async () => {
  await work.cleanup();
});

let counter = 0;
const start = async (scenario: FakeScenario, overrides: Partial<EmuBridgeOptions> = {}, expectFileSha = false) => {
  counter += 1;
  const file = await writeScenario(work.dir, scenario, `scenario-${String(counter)}.json`);
  const started = await EmuBridge.start(
    {
      python: nodeAsPython,
      bridge: {
        path: file.path,
        sha256: expectFileSha ? file.sha256 : (scenario.sha256 ?? file.sha256),
        version: "0.1.0",
      },
      memoryLimitBytes: 64 * 1024 * 1024,
      cacheDir: null,
      cwd: work.dir,
      clientVersion: "0.1.0",
      startupTimeoutMs: 5_000,
      cancelGraceMs: 400,
      deadlineBackstopMs: 100,
      ...overrides,
    },
    { now, logger: silentLogger },
  );
  if (started.ok) bridges.push(started.value);
  return started;
};

const PLAN: PlanWire = {
  target: "0x180001000",
  slots: [
    { reg: "xmm0" as const, source: { kind: "column" as const, column: "a" } },
    { reg: "xmm1" as const, source: { kind: "column" as const, column: "b" } },
  ],
  returns: { kind: "f32" as const },
  buffers: [],
};
const options = {
  maxInstructions: 1000,
  timeoutMs: 0,
  mxcsr: 0x1f80,
  fpcw: 0x27f,
  faultPolicy: "stop" as const,
  trace: {
    imports: "counts" as const,
    blocks: false,
    coverage: false,
    countInstructions: false,
    memory: "off" as const,
    instructions: false,
    disassemble: false,
    maxEvents: 10,
  },
};
const batchParams = (count: number, extra: { deadlineMs?: number } = {}) => ({
  session: "s1",
  plan: PLAN,
  vectors: {
    offset: 0,
    count,
    columns: {
      a: Array.from({ length: count }, () => "0x3f800000" as const),
      b: Array.from({ length: count }, () => "0x40000000" as const),
    },
  },
  state: { from: "baseline", writes: [], saveAs: null },
  options: { ...options, isolation: "snapshot" as const, stopOnFault: false, deadlineMs: extra.deadlineMs ?? 10_000 },
});

describe("EmuBridge startup (S5 §4.2)", () => {
  it("checks ready, hello and records both pids", async () => {
    const started = await start({});
    expect(started.ok).toBe(true);
    if (!started.ok) return;
    expect(started.value.state()).toBe("ready");
    expect(started.value.hello.protocol).toBe("bea-emu/0.1");
    expect(started.value.pids.child).toBeGreaterThan(0);
    expect(started.value.pids.bridge).toBeGreaterThan(0);
    expect(started.value.readyEvent.memoryLimit).toMatchObject({ applied: true, bytes: 64 * 1024 * 1024 });
  });

  it("refuses a bridge whose sha256, version or protocol differs, and kills it", async () => {
    const sha = await start({ sha256: "f".repeat(64) }, {}, true);
    expect(sha.ok).toBe(false);
    if (!sha.ok) expect(sha.error).toMatchObject({ kind: "version_mismatch", field: "sha256" });
    const version = await start({ version: "9.9.9" });
    expect(!version.ok && version.error).toMatchObject({ kind: "version_mismatch", field: "version" });
    const protocol = await start({ protocol: "bea-emu/0.2" });
    expect(!protocol.ok && protocol.error).toMatchObject({ kind: "version_mismatch", field: "protocol" });
  });

  it("maps fatal, silence, garbage, early exit and a missing interpreter", async () => {
    expect(await start({ ready: "fatal" })).toMatchObject({
      ok: false,
      error: { kind: "engine_unavailable", missing: ["unicorn"] },
    });
    const silent = await start({ ready: "none" }, { startupTimeoutMs: 400 });
    expect(!silent.ok && silent.error.kind).toBe("timeout");
    const garbage = await start({ ready: "garbage" });
    expect(!garbage.ok && garbage.error).toMatchObject({ kind: "exited", exit: { reason: "protocol_violation" } });
    const exited = await start({ ready: "exit" });
    expect(!exited.ok && exited.error).toMatchObject({ kind: "exited", exit: { code: 3, reason: "startup_failed" } });
    const file = await writeScenario(work.dir, {}, "missing.json");
    const missing = await EmuBridge.start(
      {
        python: { command: "C:\\definitely\\not\\python-bea-test.exe", prefixArgs: [] },
        bridge: { path: file.path, sha256: file.sha256, version: "0.1.0" },
        memoryLimitBytes: 1,
        cacheDir: null,
        cwd: work.dir,
        clientVersion: "0.1.0",
      },
      { now, logger: silentLogger, spawn: (c, a, o) => nodeSpawn(c, a, o) },
    );
    expect(!missing.ok && missing.error.kind).toBe("spawn_failed");
  });

  it("cancels a startup when the signal aborts", async () => {
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 50);
    const file = await writeScenario(work.dir, { readyDelayMs: 2_000 }, "slow.json");
    const started = performance.now();
    const cancelled = await EmuBridge.start(
      {
        python: nodeAsPython,
        bridge: { path: file.path, sha256: file.sha256, version: "0.1.0" },
        memoryLimitBytes: 1,
        cacheDir: null,
        cwd: work.dir,
        clientVersion: "0.1.0",
      },
      { now, logger: silentLogger },
      controller.signal,
    );
    expect(!cancelled.ok && cancelled.error.kind).toBe("cancelled");
    expect(performance.now() - started).toBeLessThan(1_900);
  });
});

describe("EmuBridge requests", () => {
  it("answers by id with progress events and results", async () => {
    const started = await start({ functions: { "0x180001000": "sum_f32" } });
    if (!started.ok) throw new Error("start failed");
    const bridge = started.value;
    const phases: string[] = [];
    const opened = await bridge.request(
      "session.open",
      { source: { kind: "image", path: "C:\\lab\\mathlib.dll" } },
      { onProgress: (e) => phases.push(e.phase) },
    );
    expect(opened.ok && opened.value.session).toBe("s1");
    expect(phases).toEqual(["load"]);
    const progress: number[] = [];
    const batch = await bridge.request("emu.batch", batchParams(250), {
      onProgress: (e) => progress.push(e.completed),
    });
    expect(batch.ok).toBe(true);
    if (batch.ok) {
      expect(batch.value.summary.completed).toBe(250);
      expect(batch.value.columns.xmm0lo[0]).toBe("0x40400000");
    }
    expect(progress).toEqual([100, 200]);
    const error = await bridge.request("state.restore", { session: "s1", name: "nope" });
    expect(!error.ok && error.error).toMatchObject({ kind: "bridge_error", error: { code: "unknown_snapshot" } });
    const local = await bridge.request("emu.batch", {
      ...batchParams(1),
      options: { ...batchParams(1).options, maxInstructions: Number.NaN },
    });
    expect(!local.ok && local.error.kind).toBe("local");
  });

  it("pings out of band while a request runs, and cancels it through the signal", async () => {
    const started = await start({ functions: { "0x180001000": "spin" }, spinMs: 20 });
    if (!started.ok) throw new Error("start failed");
    const bridge = started.value;
    const controller = new AbortController();
    const running = bridge.request("emu.batch", batchParams(1000), { signal: controller.signal });
    await new Promise((r) => setTimeout(r, 150));
    const ping = await bridge.ping(1_000);
    expect(ping.alive).toBe(true);
    expect(ping.busy).toBeGreaterThan(0);
    const cancelledAt = performance.now();
    controller.abort();
    const result = await running;
    expect(performance.now() - cancelledAt).toBeLessThan(500);
    expect(!result.ok && result.error.kind).toBe("cancelled");
    if (!result.ok && result.error.kind === "cancelled") {
      const partial = result.error.partial as { summary: { cancelled: boolean; completed: number } };
      expect(partial.summary.cancelled).toBe(true);
      expect(partial.summary.completed).toBeGreaterThan(0);
    }
    expect(bridge.state()).toBe("ready");
  });

  it("kills a bridge that ignores a cancel for cancelGraceMs; every pending request is lost", async () => {
    const started = await start({ functions: { "0x180001000": "spin" }, spinMs: 20, ignoreCancel: true });
    if (!started.ok) throw new Error("start failed");
    const bridge = started.value;
    const exits: string[] = [];
    bridge.onExit((exit) => exits.push(exit.reason));
    const controller = new AbortController();
    const running = bridge.request("emu.batch", batchParams(10_000), { signal: controller.signal });
    const queued = bridge.request("session.info", { session: "s1" });
    await new Promise((r) => setTimeout(r, 100));
    controller.abort();
    const [a, b] = await Promise.all([running, queued]);
    expect(!a.ok && a.error).toMatchObject({ kind: "bridge_lost", exit: { reason: "killed" } });
    expect(!b.ok && b.error.kind).toBe("bridge_lost");
    expect(exits).toEqual(["killed"]);
    expect(bridge.state()).toBe("exited");
    const after = await bridge.request("session.info", { session: "s1" });
    expect(!after.ok && after.error.kind).toBe("bridge_lost");
  });

  it("backstops a passed deadline with a host cancel", async () => {
    const started = await start({ functions: { "0x180001000": "spin" }, spinMs: 20 });
    if (!started.ok) throw new Error("start failed");
    const result = await started.value.request("emu.batch", batchParams(1000, { deadlineMs: 60_000 }), {
      deadlineAt: now() + 50,
    });
    expect(!result.ok && result.error.kind).toBe("deadline");
  });

  it("reports a crash as bridge_lost with the exit code", async () => {
    const started = await start({ crash: { method: "emu.call" } });
    if (!started.ok) throw new Error("start failed");
    const call = await started.value.request("emu.call", {
      session: "s1",
      plan: PLAN,
      vectors: { offset: 0, count: 1, columns: { a: ["0x0"], b: ["0x0"] } },
      state: { from: "baseline", writes: [], saveAs: null },
      options,
    });
    expect(!call.ok && call.error).toMatchObject({ kind: "bridge_lost", exit: { code: 70, reason: "crashed" } });
  });
});

describe("EmuBridge close (CT-M9)", () => {
  it("shuts down cleanly and idempotently", async () => {
    const started = await start({});
    if (!started.ok) throw new Error("start failed");
    const t0 = performance.now();
    const [a, b] = await Promise.all([started.value.close(), started.value.close()]);
    expect(a).toBe(b);
    expect(a.reason).toBe("shutdown");
    expect(a.code).toBe(0);
    expect(performance.now() - t0).toBeLessThan(900);
  });

  it("kills a busy bridge that ignores shutdown and EOF at 900 ms", async () => {
    const started = await start({ functions: { "0x180001000": "spin" }, spinMs: 20, ignoreCancel: true });
    if (!started.ok) throw new Error("start failed");
    const running = started.value.request("emu.batch", batchParams(100_000));
    await new Promise((r) => setTimeout(r, 100));
    const t0 = performance.now();
    const exit = await started.value.close();
    const elapsed = performance.now() - t0;
    expect(exit.reason).toBe("killed");
    expect(elapsed).toBeGreaterThanOrEqual(850);
    expect(elapsed).toBeLessThan(1_300);
    expect((await running).ok).toBe(false);
  });
});
