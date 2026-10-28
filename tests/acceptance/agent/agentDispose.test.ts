// WP3-AGENT acceptance (raw Frida; S4 §18, A-36 VERIFIED [CT-lab E4], DESIGN §5.3): rpc.exports.dispose disarms what
// BEA armed when the script unloads — on a normal unload and when the HOST is killed with taskkill /F (no host-side
// cleanup at all). The target is an ATTACHED process the test started itself (child_process, not Frida), with a BEA
// guard on the page of game_sim's g_mix_result, which the main thread writes every frame: a guard left armed after
// unload would kill it with STATUS_GUARD_PAGE_VIOLATION (0x80000001, [CT-lab E4c]). After the unload the target must
// keep running and the page must have its original protection again.
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { skipNote } from "../../support/acceptance/fixtures.js";
import {
  agentLaneSkip,
  bundleFile,
  isAlive,
  killTestProcess,
  PAGE_GUARD,
  PROTECT_PROBE_SCRIPT,
  setupAgentLane,
  type AgentLane,
} from "../../support/agent/lane.js";
import { RawAgent } from "../../support/agent/rawAgent.js";
import { OwnedPidLedger } from "../../support/process/ownedPidLedger.js";

const skip = agentLaneSkip();
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

interface Target {
  readonly child: ChildProcess;
  readonly pid: number;
  output: string;
}

describe.skipIf(skip !== false)(`rpc.exports.dispose disarms BEA's guards on unload${skipNote(skip)}`, () => {
  let lane: AgentLane;
  let ledger: OwnedPidLedger;
  const targets: Target[] = [];
  const hosts: ChildProcess[] = [];
  /**
   * TEMP of each killed host: Frida extracts its agent copies (~45 MB) into %TEMP%\frida-<id> and deletes them only at
   * DeviceManager.close(), which a host killed with taskkill /F never reaches. The test owns that directory and
   * removes it once the attach targets (which may still map frida-agent.dll) are gone.
   */
  const hostTemps: string[] = [];

  /** game_sim started by the TEST (an attach target: BEA must never kill it). */
  const startTarget = async (): Promise<Target> => {
    const child = spawn(lane.fixtures.game_sim, ["--hz", "60"], { cwd: lane.fixtureDir, windowsHide: true });
    const t: Target = { child, pid: child.pid!, output: "" };
    child.stdout?.on("data", (d: Buffer) => (t.output += d.toString("utf8")));
    child.stderr?.resume();
    targets.push(t);
    for (let i = 0; i < 200 && !t.output.includes("READY"); i++) await sleep(25);
    ledger.recordAttachTarget(t.pid, null, "game_sim attach target");
    return t;
  };

  /** Protection of `address` in the target, read by a separate probe script (fresh attach). */
  const probeProtect = async (pid: number, address: string): Promise<number> => {
    const probe = await RawAgent.start({ bundle: PROTECT_PROBE_SCRIPT_READY, attachPid: pid });
    try {
      return await probe.rpc<number>("protect", address);
    } finally {
      await probe.close();
    }
  };

  const frames = (t: Target): number => (t.output.match(/FRAME \d+/gu) ?? []).length;
  /** The target printed another FRAME line (one per 60 frames ≈ 1 s) within `ms`. */
  const advances = async (t: Target, ms: number): Promise<boolean> => {
    const n = frames(t);
    for (let waited = 0; waited < ms; waited += 50) {
      if (frames(t) > n) return true;
      await sleep(50);
    }
    return false;
  };

  beforeAll(async () => {
    lane = await setupAgentLane();
    ledger = new OwnedPidLedger(lane.pidcheck);
  }, 180_000);

  afterAll(async () => {
    await RawAgent.shutdownFrida();
    for (const h of hosts) if (h.exitCode === null && h.pid !== undefined) killTestProcess(h.pid);
    const audit = ledger === undefined ? null : await ledger.audit();
    for (const t of targets) if (isAlive(t.pid)) killTestProcess(t.pid);
    for (let i = 0; i < 200 && targets.some((t) => isAlive(t.pid)); i++) await sleep(25);
    for (const dir of hostTemps) rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
    expect(audit?.deadAttachTargets ?? []).toEqual([]);
  });

  it("a normal script unload restores the page protection and the target keeps running", async () => {
    const t = await startTarget();
    const a = await RawAgent.start({ bundle: lane.bundle, attachPid: t.pid });
    let page: string;
    try {
      await a.hello({
        session: { session_id: "00000000-0000-4000-8000-0000000000d2", instance_id: "pi_d2", owned: false },
      });
      const resolved = await a.ok<{ results: { target: { va: string } }[] }>("resolveTargets", {
        targets: [{ module: "game_sim.exe", export: "g_mix_result" }],
      });
      const g = await a.rpc<{ page: string; armed: boolean; protect: number }>("testGuardAddress", {
        address: resolved.results[0]!.target.va,
      });
      page = g.page;
      expect(g.armed).toBe(true);
      await sleep(300);
      expect((await a.rpc<{ fallbackTraps: number }>("testGuardState", { page })).fallbackTraps).toBeGreaterThan(0);
      await a.script.unload();
    } finally {
      await a.close();
    }
    expect(await advances(t, 4000)).toBe(true);
    expect(isAlive(t.pid)).toBe(true);
    expect((await probeProtect(t.pid, page)) & PAGE_GUARD).toBe(0);
  });

  it("taskkill /F of the host: dispose still runs, the target survives with its page unguarded", async () => {
    const t = await startTarget();
    const file = bundleFile(lane.bundle);
    const hostTemp = mkdtempSync(join(tmpdir(), "bea-wp3-host-temp-"));
    hostTemps.push(hostTemp);
    try {
      const host = spawn(
        process.execPath,
        [
          join(import.meta.dirname, "..", "..", "support", "agent", "disposeHost.ts"),
          String(t.pid),
          file.path,
          "game_sim.exe",
          "g_mix_result",
        ],
        {
          stdio: ["ignore", "pipe", "pipe"],
          windowsHide: true,
          env: { ...process.env, TEMP: hostTemp, TMP: hostTemp },
        },
      );
      hosts.push(host);
      let out = "";
      host.stdout?.on("data", (d: Buffer) => (out += d.toString("utf8")));
      host.stderr?.on("data", (d: Buffer) => (out += d.toString("utf8")));
      for (let i = 0; i < 600 && !out.includes("READY "); i++) await sleep(25);
      const line = out.split(/\r?\n/u).find((l) => l.startsWith("READY "));
      expect(line, out).toBeDefined();
      const ready = JSON.parse(line!.slice("READY ".length)) as {
        armed: { page: string; armed: boolean };
        state: { fallbackTraps: number };
      };
      expect(ready.armed.armed).toBe(true);
      expect(ready.state.fallbackTraps).toBeGreaterThan(0);
      killTestProcess(host.pid!); // TerminateProcess: no JS cleanup in the host
      await sleep(1500); // the agent notices the lost transport and unloads (dispose)
      expect(await advances(t, 4000)).toBe(true);
      expect(isAlive(t.pid)).toBe(true);
      expect((await probeProtect(t.pid, ready.armed.page)) & PAGE_GUARD).toBe(0);
    } finally {
      file.cleanup();
    }
  });
});

/** The protect probe as a loadable bundle: RawAgent waits for a ready message. */
const PROTECT_PROBE_SCRIPT_READY = `${PROTECT_PROBE_SCRIPT}\nsend({ bea: "ready" });\n`;
