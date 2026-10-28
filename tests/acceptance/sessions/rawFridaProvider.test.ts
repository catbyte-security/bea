import { spawn, spawnSync } from "node:child_process";
import { dirname, join } from "node:path";

import { afterAll, describe, expect, it, vi } from "vitest";

import { Deadline } from "../../../src/domain/deadline.js";
import { silentLogger } from "../../../src/domain/logger.js";
import type { DetachReason, OperationContext } from "../../../src/ports/sessions.js";
import { AgentChannel } from "../../../src/providers/frida/AgentChannel.js";
import { AgentJobs } from "../../../src/providers/frida/AgentJobs.js";
import { defaultAgentBundleFiles, loadAgentBundle } from "../../../src/providers/frida/agentBundle.js";
import { AgentRpcClient } from "../../../src/providers/frida/AgentRpcClient.js";
import { CrashProtocol } from "../../../src/providers/frida/CrashProtocol.js";
import { FlowTracker } from "../../../src/providers/frida/flowTracker.js";
import { FridaHost } from "../../../src/providers/frida/FridaHost.js";
import { EXPECTED_FRIDA_VERSION, loadFridaModule } from "../../../src/providers/frida/fridaLoader.js";
import { isoToFiletime100ns } from "../../../src/providers/frida/spawnSession.js";
import { SessionStreamBinder } from "../../../src/providers/frida/StreamBinder.js";
import { fixtureArtifact, fridaSkip, loadFixtures, skipNote } from "../../support/acceptance/fixtures.js";
import { FakeEvidence } from "../../unit/sessions/support/fakeEvidence.js";

/**
 * Raw-Frida acceptance of the WP4 provider layer that needs only WP0 + WP4 (DESIGN §8.4 wave rule: raw agent RPCs, no
 * other WP's tools): the real frida 17.23.2 binding through fridaLoader/fridaAdapters/NativeCancel, a TEST-OWNED
 * game_sim spawned suspended with a piped stdout, Frida's metadata start time (µs → FILETIME, tolerance 10), the real
 * built agent bundle (BEA_DIST_DIR snapshot) through AgentChannel's ready handshake and AgentRpcClient, the
 * process-terminated detach and the "Script is destroyed" mapping, and FridaHost.close (release-frida). Containment and
 * evidence are WP2/WP1's; this test kills its own process directly. Also: a metadata listing never injects.
 */
/** By absolute path (no PATH lookup). */
const TASKLIST = join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", "tasklist.exe");
const skip = fridaSkip();
const owned = new Set<number>();
const opFor = (ms: number): OperationContext => ({
  opId: 1,
  name: "raw_frida_test",
  signal: new AbortController().signal,
  deadline: Deadline.after(ms),
});

const newHost = (orphanOutputBytes: number): FridaHost =>
  new FridaHost({
    logger: silentLogger,
    loadModule: loadFridaModule,
    loadAgentBundle: () => loadAgentBundle(defaultAgentBundleFiles()),
    now: () => performance.now(),
    orphanOutputBytes,
    orphanOutputTtlMs: 5000,
  });

/** The WP4 host side of one agent: stream binder, jobs and crash protocol behind the channel's ready handshake. */
const wireChannel = (pid: number, buildId: string): { readonly channel: AgentChannel; readonly flow: FlowTracker } => {
  const evidence = new FakeEvidence();
  const flow = new FlowTracker({ post: () => undefined, everyBytes: 1 << 20, everyMs: 100 });
  const binder = new SessionStreamBinder({
    streams: evidence.streams,
    flushAgent: async () => undefined,
    flow,
    moduleEpoch: () => null,
    onRows: () => undefined,
    onQuota: () => undefined,
    notify: () => undefined,
    logger: silentLogger,
    now: () => performance.now(),
    parking: { maxBytes: 256 * 1024, maxAgeMs: 2000 },
  });
  const channel = new AgentChannel({
    operation: "raw_frida_test",
    expected: { pid, buildId },
    binder,
    jobs: new AgentJobs({
      blobs: evidence.blobs,
      literals: () => ({ count: 0, texts: [], spellings: [] }),
      flow,
      jobStatus: async () => ({ ok: false, error: { _tag: "Internal", operation: "x" } }),
      notify: () => undefined,
      logger: silentLogger,
    }),
    crash: new CrashProtocol({
      post: () => undefined,
      recordCrash: async () => undefined,
      recordExit: async () => undefined,
      ackTimeoutMs: 5000,
      ringSize: 16,
      now: () => performance.now(),
      logger: silentLogger,
      onReport: () => undefined,
    }),
    onInstrument: () => undefined,
    onFault: () => undefined,
    onNotice: () => undefined,
    logger: silentLogger,
    now: () => performance.now(),
    wallIso: () => new Date().toISOString(),
    monoNs: () => process.hrtime.bigint(),
    limits: { logEntries: 256, logBytes: 256 * 1024, logEntryBytes: 4096, agentFaults: 32 },
  });
  return { channel, flow };
};

afterAll(() => {
  for (const pid of owned)
    try {
      process.kill(pid);
    } catch {
      // already gone
    }
});

describe.skipIf(skip !== false)(`WP4 provider against the real Frida binding${skipNote(skip)}`, () => {
  it("spawns, injects the real agent, validates ready, maps RPC outcomes and closes cleanly", async () => {
    const game = fixtureArtifact(await loadFixtures(), "game_sim");
    expect(game, "fixtures unavailable").not.toBeNull();
    if (game === null) return;
    const host = newHost(64 * 1024);
    const live = await host.device({ signal: new AbortController().signal });
    expect(live.ok, live.ok ? "" : JSON.stringify(live.error)).toBe(true);
    if (!live.ok) return;
    expect(host.availability().binding).toMatchObject({ state: "ready", version: EXPECTED_FRIDA_VERSION });
    expect(live.value.system.os).toBe("windows");
    const bundle = await host.agentBundle();
    expect(bundle.ok, bundle.ok ? "" : JSON.stringify(bundle.error)).toBe(true);
    if (!bundle.ok) return;

    const device = live.value.device;
    const pid = await device.spawn([game.path, "--frames", "0", "--no-threads"], {
      envp: { SystemRoot: process.env["SystemRoot"] ?? "C:\\Windows", PATH: process.env["PATH"] ?? "" },
      cwd: dirname(game.path),
      stdio: "pipe",
    });
    owned.add(pid);
    const unroute = host.routeOutput(pid, () => undefined);
    try {
      const listing = await device.enumerateProcesses({ scope: "metadata" });
      const started = isoToFiletime100ns(listing.find((p) => p.pid === pid)?.parameters["started"]);
      expect(started?.precision100ns).toBe(10n);

      const session = await device.attach(pid);
      const detaches: DetachReason[] = [];
      const onDetached = (reason: DetachReason): void => {
        detaches.push(reason);
      };
      session.detached.connect(onDetached);
      const script = await session.createScript(bundle.value.source, { name: "bea-agent", runtime: "qjs" });
      const { channel, flow } = wireChannel(pid, bundle.value.buildId);
      script.logHandler = channel.onLog;
      script.message.connect(channel.onMessage);
      script.destroyed.connect(channel.onDestroyed);
      await script.load();
      const timer = setTimeout(
        () => channel.failReady({ _tag: "ProviderTimeout", operation: "x", timeout_ms: 5000, phase: "ready" }),
        5000,
      );
      const ready = await channel.ready;
      clearTimeout(timer);
      expect(ready.ok, ready.ok ? "" : JSON.stringify(ready.error)).toBe(true);
      if (ready.ok)
        expect(ready.value).toMatchObject({
          protocol: "bea-agent/1",
          pid,
          arch: "x64",
          runtime: "QJS",
          build_id: bundle.value.buildId,
        });

      const mod = host.module;
      if (mod === null) throw new Error("binding not loaded");
      const rpc = new AgentRpcClient({
        script,
        createCancellable: () => mod.createCancellable(),
        defaultTimeoutMs: 5000,
        pingTimeoutMs: 1000,
        pingIntervalMs: 2000,
        instanceId: () => "pi_raw",
        terminal: async () => ({
          closing: false,
          exited: detaches.includes("process-terminated") ? { exit: null } : null,
          detachReason: detaches[0] ?? null,
          instanceId: "pi_raw",
        }),
        logger: silentLogger,
        now: () => performance.now(),
      });
      // The agent core is WP3's: a stubbed method answers the agent's Unsupported, a real one a valid result.
      const ping = await rpc.call("ping", {}, { op: opFor(5000) });
      if (!ping.ok) expect(ping.error._tag).toBe("UnsupportedTarget");
      else expect(ping.value.phase).toMatch(/loaded|ready/u);
      expect(channel.protocolViolations).toBe(0);
      expect(script.isDestroyed).toBe(false);

      await device.kill(pid);
      await vi.waitFor(() => expect(detaches).toContain("process-terminated"), { interval: 25, timeout: 5000 });
      const after = await rpc.call("ping", {}, { op: opFor(2000) });
      expect(!after.ok && after.error._tag).toBe("TargetExited");
      session.detached.disconnect(onDetached);
      script.message.disconnect(channel.onMessage);
      script.destroyed.disconnect(channel.onDestroyed);
      flow.stop();
    } finally {
      unroute();
      try {
        await device.kill(pid);
      } catch {
        // already gone
      }
    }
    const closed = await host.close(Deadline.after(2000));
    expect(closed.ok && closed.value).toMatchObject({ outputDisconnected: true, deviceManagerClosed: true });
  }, 60_000);
});

describe.skipIf(skip !== false)(`list_processes' Frida listing${skipNote(skip)}`, () => {
  it("a metadata process listing never injects (no frida-agent.dll in the listed process)", async () => {
    const game = fixtureArtifact(await loadFixtures(), "game_sim");
    if (game === null) return;
    const child = spawn(game.path, ["--frames", "0", "--no-threads"], {
      cwd: dirname(game.path),
      stdio: "ignore",
      windowsHide: true,
    });
    const childPid = child.pid ?? 0;
    owned.add(childPid);
    const host = newHost(1024);
    try {
      const live = await host.device({ signal: new AbortController().signal });
      if (!live.ok) throw new Error(JSON.stringify(live.error));
      const listing = await live.value.device.enumerateProcesses({ scope: "metadata" });
      expect(listing.some((p) => p.pid === childPid)).toBe(true);
      const modules = spawnSync(
        TASKLIST,
        ["/M", "frida-agent.dll", "/FI", `PID eq ${String(childPid)}`, "/FO", "CSV", "/NH"],
        { encoding: "utf8", windowsHide: true },
      );
      expect(modules.stdout).not.toContain(String(childPid));
    } finally {
      child.kill();
      await host.close(Deadline.after(2000));
    }
  }, 60_000);
});
