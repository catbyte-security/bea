import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { loadConfig, type BeaConfig } from "../../../src/domain/config.js";
import { Deadline } from "../../../src/domain/deadline.js";
import type { OpenParams } from "../../../src/domain/emuProtocol.js";
import { projectBeaError } from "../../../src/domain/errors/projection.js";
import { silentLogger } from "../../../src/domain/logger.js";
import type { HostPlatform } from "../../../src/domain/paths.js";
import { ok } from "../../../src/domain/result.js";
import type { EmuRequestOptions } from "../../../src/ports/emu.js";
import type { OperationContext } from "../../../src/ports/sessions.js";
import type { PlanWire } from "../../../src/shared/callPlan.js";
import type { LocatedBridge } from "../../../src/providers/emulator/bridgeLocator.js";
import { EmuAdapter } from "../../../src/providers/emulator/EmuAdapter.js";
import { PythonResolver, runBridgeProbe } from "../../../src/providers/emulator/pythonResolver.js";
import {
  fakeSpawn,
  FakeSessionPort,
  tempDir,
  writeScenario,
  type FakeScenario,
  type TempDir,
} from "../../support/emu/harness.js";

/**
 * EmuAdapter + EmuSessionRuntime over the fake bridge (S5 §5.3–§5.6): shared-id registration, capacity, lookups,
 * the restart policy (lazy re-open, generation + 1, lost snapshots, crash loop, identity check), close during a
 * request, partial batches and closeAll.
 */
let work: TempDir;
const adapters: EmuAdapter[] = [];
const now = (): number => performance.now();

beforeAll(async () => {
  work = await tempDir("adapter");
});
afterEach(async () => {
  await Promise.all(adapters.splice(0).map((a) => a.closeAll()));
});
afterAll(async () => {
  await work.cleanup();
});

const configWith = async (env: Record<string, string> = {}): Promise<BeaConfig> => {
  const loaded = await loadConfig({
    env: { BEA_HOME: join(work.dir, "home"), ...env },
    platform: process.platform as HostPlatform,
    accountHome: work.dir,
    readConfigFile: async () => null,
  });
  if (!loaded.ok) throw new Error("config");
  return loaded.value;
};

const op = (name = "emu_open", timeoutMs = 20_000): OperationContext => ({
  opId: 1,
  name,
  signal: new AbortController().signal,
  deadline: Deadline.after(timeoutMs),
});
const opts = (timeoutMs = 20_000, signal?: AbortSignal): EmuRequestOptions => ({
  signal: signal ?? new AbortController().signal,
  deadlineAt: now() + timeoutMs,
});

let counter = 0;
const setup = async (scenario: FakeScenario, env: Record<string, string> = {}) => {
  counter += 1;
  const file = await writeScenario(work.dir, scenario, `adapter-${String(counter)}.json`);
  const sha = scenario.sha256 ?? file.sha256;
  const located: LocatedBridge = {
    path: file.path,
    sha256: sha,
    version: "0.1.0",
    protocol: "bea-emu/0.1",
    requirementsLock: join(work.dir, "requirements.lock"),
    lockSha256: null,
    manifestPath: join(work.dir, "bridge-manifest.json"),
    source: "computed",
  };
  const config = await configWith(env);
  const resolver = new PythonResolver({
    platform: config.platform,
    configured: { value: process.execPath, source: "env" },
    venvDir: config.layout.venvDir,
    bridge: async () => ok(located),
    probe: (request) => runBridgeProbe(request, fakeSpawn),
  });
  const sessions = new FakeSessionPort();
  const adapter = new EmuAdapter({
    config,
    sessions: sessions.port(),
    resolver,
    bridge: async () => ok(located),
    logger: silentLogger,
    now,
    spawn: fakeSpawn,
    bridgeOptions: { cancelGraceMs: 400, deadlineBackstopMs: 100 },
    crashLoop: { losses: 3, windowMs: 60_000 },
  });
  adapters.push(adapter);
  return { adapter, sessions, file };
};

const IMAGE: OpenParams = { source: { kind: "image", path: "C:\\lab\\mathlib.dll" } };
const PLAN: PlanWire = {
  target: "0x180001000",
  slots: [
    { reg: "xmm0" as const, source: { kind: "column" as const, column: "a" } },
    { reg: "xmm1" as const, source: { kind: "column" as const, column: "b" } },
  ],
  returns: { kind: "f32" as const },
  buffers: [],
};
const RUN = {
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
const callReq = {
  plan: PLAN,
  vectors: { offset: 0, count: 1, columns: { a: ["0x3f800000" as const], b: ["0x40000000" as const] } },
  state: { from: "baseline", writes: [], saveAs: null },
  options: RUN,
};
const batchReq = (count: number) => ({
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
  options: { ...RUN, isolation: "snapshot" as const, stopOnFault: false, deadlineMs: 10_000 },
});

describe("EmuAdapter (EmuPort)", () => {
  it("registers the session in the shared id space and answers lookups from memory", async () => {
    const { adapter, sessions } = await setup({ functions: { "0x180001000": "sum_f32" } });
    expect(adapter.availability().state).toBe("not-resolved");
    const opened = await adapter.open(IMAGE, op());
    expect(opened.ok).toBe(true);
    if (!opened.ok) return;
    const id = opened.value.runtime.sessionId;
    expect(sessions.kindOf(id)).toBe("emulation");
    expect(adapter.availability()).toMatchObject({ state: "available", source: "BEA_PYTHON", pin: "exact" });
    const handle = adapter.lookup(id);
    expect(handle).toEqual({ sessionId: id, generation: 0 });
    if (handle === null) return;
    expect(adapter.modules(handle).map((m) => [m.name, m.base, m.primary])).toEqual([
      ["mathlib.dll", "0x180000000", true],
    ]);
    expect(adapter.status(handle)).toMatchObject({ status: "ready", generation: 0, calls: 0 });
    const call = await adapter.call(handle, callReq, opts());
    expect(call.ok && call.value.raw.xmm0).toBe("0x40400000");
    const info = await adapter.info(handle, opts());
    expect(info.ok && info.value.state.poisoned).toBe(false);
    const driver = sessions.externals.get(id);
    expect(driver?.summary()).toMatchObject({
      session_id: id,
      kind: "emulation",
      state: "ready",
      ownership: "none",
      pid: null,
    });
    const detail = await driver?.detail("complete", op("session_status"));
    expect(detail?.ok && detail.value).toMatchObject({
      kind: "emulation",
      status: "ready",
      alive: true,
      calls: 1,
      source: "image",
    });
    const closed = await sessions.close(id, op("close_session"));
    expect(closed.ok && closed.value).toMatchObject({ kind: "emulation", cleanup: { status: "complete" } });
    expect(adapter.lookup(id)).toBeNull();
    expect(adapter.counts().open).toBe(0);
  });

  it("refuses an emulation session over emu.max_sessions with resource_constraint(capacity)", async () => {
    const { adapter } = await setup({}, { BEA_EMU_MAX_SESSIONS: "1" });
    expect((await adapter.open(IMAGE, op())).ok).toBe(true);
    const second = await adapter.open(IMAGE, op());
    expect(second.ok).toBe(false);
    if (!second.ok)
      expect(projectBeaError(second.error)).toMatchObject({
        code: "resource_constraint",
        retryable: true,
        details: { resource: "capacity" },
      });
  });

  it("maps a bridge open error and keeps nothing registered", async () => {
    const { adapter, sessions } = await setup({ openError: { code: "unsupported_image", message: "x86" } });
    const opened = await adapter.open(IMAGE, op());
    expect(!opened.ok && opened.error._tag).toBe("UnsupportedTarget");
    expect(sessions.externals.size).toBe(0);
    expect(adapter.counts().open).toBe(0);
  });
});

describe("EmuAdapter restart policy, cancel and teardown", () => {
  it("re-opens a lost bridge lazily: generation + 1, named snapshots reported lost (S5 §5.4)", async () => {
    const marker = join(work.dir, `crash-once-${String(counter + 1)}`);
    const { adapter } = await setup({ crash: { method: "emu.call", marker }, functions: { "0x180001000": "sum_f32" } });
    const opened = await adapter.open(IMAGE, op());
    if (!opened.ok) throw new Error("open");
    const handle = opened.value.runtime;
    expect((await adapter.state(handle, { save: "n1" }, opts())).ok).toBe(true);
    expect(adapter.status(handle).namedSnapshots).toEqual([{ name: "n1", bytes: 4096 }]);
    const lost = await adapter.call(handle, callReq, opts());
    expect(lost.ok).toBe(false);
    if (!lost.ok)
      expect(projectBeaError(lost.error)).toMatchObject({
        code: "capability_unavailable",
        retryable: true,
        details: { reason: "bridge-lost" },
      });
    expect(adapter.status(handle).status).toBe("lost");
    const again = await adapter.call(handle, callReq, opts());
    expect(again.ok).toBe(true);
    if (again.ok) {
      expect(again.value.raw.xmm0).toBe("0x40400000");
      expect(again.value.deviations).toContainEqual(
        expect.objectContaining({
          kind: "bridge_restarted_state_reset",
          detail: { generation: 1, lost_snapshots: ["n1"] },
        }),
      );
    }
    expect(adapter.lookup(handle.sessionId)?.generation).toBe(1);
    expect(adapter.status(handle)).toMatchObject({
      status: "ready",
      generation: 1,
      namedSnapshots: [],
      lostSnapshots: ["n1"],
    });
    const next = await adapter.call(handle, callReq, opts());
    expect(next.ok && next.value.deviations.some((d) => d.kind === "bridge_restarted_state_reset")).toBe(false);
  });

  it("ensureReady re-opens a lost bridge before the next call and returns that generation (EMU-8)", async () => {
    const marker = join(work.dir, `crash-once-${String(counter + 1)}`);
    const { adapter } = await setup({ crash: { method: "emu.call", marker }, functions: { "0x180001000": "sum_f32" } });
    const opened = await adapter.open(IMAGE, op());
    if (!opened.ok) throw new Error("open");
    const handle = opened.value.runtime;
    expect((await adapter.call(handle, callReq, opts())).ok).toBe(false); // the bridge dies
    expect(adapter.status(handle).status).toBe("lost");
    const ready = await adapter.ensureReady(handle, opts());
    expect(ready).toEqual({ ok: true, value: { sessionId: handle.sessionId, generation: 1 } });
    expect(adapter.status(handle)).toMatchObject({ status: "ready", generation: 1 });
    // the call that follows runs in that generation and still carries the one-shot restart deviation
    const after = await adapter.call(handle, callReq, opts());
    expect(after.ok && after.value.deviations.some((d) => d.kind === "bridge_restarted_state_reset")).toBe(true);
    // a ready bridge is left alone
    expect(await adapter.ensureReady(handle, opts())).toEqual({
      ok: true,
      value: { sessionId: handle.sessionId, generation: 1 },
    });
  });

  it("fails the session after three losses within the window (crash loop)", async () => {
    const { adapter } = await setup({ crash: { method: "emu.call" } });
    const opened = await adapter.open(IMAGE, op());
    if (!opened.ok) throw new Error("open");
    const handle = opened.value.runtime;
    for (let i = 0; i < 3; i++) {
      const r = await adapter.call(handle, callReq, opts());
      expect(!r.ok && r.error._tag, `loss ${String(i + 1)}`).toBe("CapabilityUnavailable");
    }
    expect(adapter.status(handle).status).toBe("failed");
    const failed = await adapter.call(handle, callReq, opts());
    expect(!failed.ok && projectBeaError(failed.error)).toMatchObject({ code: "execution_failure", retryable: false });
  });

  it("refuses to re-open when the image identity changed on disk", async () => {
    const marker = join(work.dir, `crash-id-${String(counter + 1)}`);
    const scenario: FakeScenario = {
      sha256: "c".repeat(64),
      crash: { method: "emu.call", marker },
      imageSha256: "aa".repeat(32),
    };
    const { adapter, file } = await setup(scenario);
    const opened = await adapter.open(IMAGE, op());
    if (!opened.ok) throw new Error("open");
    const handle = opened.value.runtime;
    expect((await adapter.call(handle, callReq, opts())).ok).toBe(false);
    await writeFile(file.path, JSON.stringify({ ...scenario, imageSha256: "bb".repeat(32) }), "utf8");
    const reopened = await adapter.call(handle, callReq, opts());
    expect(!reopened.ok && projectBeaError(reopened.error).code).toBe("evidence_integrity_mismatch");
    expect(adapter.status(handle).status).toBe("failed");
  });

  it("returns a partial batch after a cancel and session_not_found for a request cut by close", async () => {
    const { adapter, sessions } = await setup({ functions: { "0x180001000": "spin" }, spinMs: 10 });
    const opened = await adapter.open(IMAGE, op());
    if (!opened.ok) throw new Error("open");
    const handle = opened.value.runtime;
    const controller = new AbortController();
    const running = adapter.batch(handle, batchReq(1000), opts(20_000, controller.signal));
    await new Promise((r) => setTimeout(r, 120));
    controller.abort();
    const partial = await running;
    expect(partial.ok).toBe(false);
    if (!partial.ok) {
      expect("kind" in partial.error && partial.error.kind).toBe("partial");
      if ("kind" in partial.error) {
        expect(partial.error.reason).toBe("cancelled");
        expect(partial.error.result.summary.completed).toBeGreaterThan(0);
      }
    }
    const inflight = adapter.batch(handle, batchReq(1000), opts());
    await new Promise((r) => setTimeout(r, 100));
    const t0 = performance.now();
    await sessions.close(handle.sessionId, op("close_session"));
    expect(performance.now() - t0).toBeLessThan(1_300);
    const cut = await inflight;
    expect(!cut.ok && !("kind" in cut.error) && cut.error._tag).toBe("SessionNotFound");
  });

  it("closes every bridge on closeAll (teardown-targets)", async () => {
    const { adapter } = await setup({});
    const a = await adapter.open(IMAGE, op());
    const b = await adapter.open(IMAGE, op());
    expect(a.ok && b.ok).toBe(true);
    expect(adapter.counts().open).toBe(2);
    await adapter.closeAll();
    expect(adapter.counts().open).toBe(0);
    if (a.ok) expect(adapter.lookup(a.value.runtime.sessionId)).toBeNull();
  });
});
