import { existsSync, readFileSync } from "node:fs";

import { afterAll, afterEach, describe, expect, it } from "vitest";

import { buildHookPlan } from "../../../src/application/handlers/instrument.js";
import { INSTRUMENT_TOOLS } from "../../../src/contracts/areas/instrument.js";
import type { HookInstallResult, InstrumentStopResult } from "../../../src/shared/agentProtocol.js";
import { fixtureArtifact, fridaSkip, gccSkip, loadFixtures, skipNote } from "../../support/acceptance/fixtures.js";
import { harnessLayout } from "../../support/mcp/stdioSubprocess.js";
import {
  decodeStream,
  shutdownRawFrida,
  startRawTarget,
  until,
  useLivenessProbe,
  type RawTarget,
} from "./support/rawHookAgent.js";

/**
 * WP7 on the BUILT agent (dist/agent/bea-agent.js of BEA_DIST_DIR — take a snapshot first, docs/testing.md): the
 * production link to WP3's core (InstrumentRegistry, StreamRegistry, NativeCore, CallRegistry, OriginalBytes).
 * Raw agent RPCs only (wave rule): hello → hookInstall (JS and native tiers) → batches → status → instrumentStop.
 */
const layout = harnessLayout();
const skip =
  fridaSkip() !== false
    ? fridaSkip()
    : gccSkip() !== false
      ? gccSkip()
      : existsSync(layout.agentBundle)
        ? false
        : `AGENT_SKIP: ${layout.agentBundle} is missing; run npm run build (and snapshot it)`;
const SID = "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b";
const hookTool = INSTRUMENT_TOOLS[0];

let target: RawTarget | null = null;
afterEach(async () => {
  await target?.close();
  target = null;
}, 30_000);
afterAll(shutdownRawFrida, 30_000); // after every target is gone: Frida then removes its %TEMP%\frida-<id> agent copy

const HELLO = {
  protocol: "bea-agent/1",
  min_minor: 0,
  host: { name: "bea", version: "0.1.0" },
  session: { session_id: SID, instance_id: `pi_${"1".repeat(64)}`, owned: true },
  gates: { write_memory: false, override_function: false, call_function: true },
  crash: {
    first_chance_rows: true,
    first_chance_blocking: false,
    crash_class: [],
    ack_timeout_ms: 1000,
    last_chance_ack_timeout_ms: 2000,
    max_blocking_per_10s: 8,
    rows_per_sec: 1000,
    stack_bytes: 256,
    backtrace_depth: 32,
    include_xmm: false,
  },
  streams: { flush_ms: 50, exceptions: true, threads: false },
  flow: { high_water_bytes: 512 * 1024 * 1024, low_water_bytes: 256 * 1024 * 1024 },
};

describe.skipIf(skip !== false)(`hook engine on the built agent (WP3 core link)${skipNote(skip)}`, () => {
  it("installs JS and native hooks through the core registry, streams rows, reports counters and stops cleanly", async () => {
    const manifest = await loadFixtures();
    const game = fixtureArtifact(manifest, "game_sim");
    useLivenessProbe(fixtureArtifact(manifest, "pidcheck")?.path ?? null);
    if (game === null) throw new Error("game_sim fixture unavailable");
    target = await startRawTarget(
      readFileSync(layout.agentBundle, "utf8"),
      [game.path, "--no-threads", "--hot", "200"],
      {
        paused: true,
      },
    );
    const t = target;
    const hello = (await t.rpc("hello", HELLO)) as { ok: boolean; value?: { features: string[] } };
    expect(hello.ok).toBe(true);
    expect(hello.value?.features).toEqual(expect.arrayContaining(["hooks.js", "hooks.native", "hooks.native.xmm"]));
    await t.resume();
    const resolved = (await t.rpc("resolveTargets", {
      targets: [
        { module: "game_sim.exe", export: "physics_step" },
        { module: "game_sim.exe", export: "hot_hash" },
      ],
    })) as { value: { results: { target: { va: string } }[] } };
    const [physics, hot] = resolved.value.results.map((r) => r.target.va);
    const plan = (va: string | undefined, input: Record<string, unknown>) =>
      buildHookPlan(
        hookTool.inputSchema.parse({ session_id: SID, address: va ?? "0x0", ...input }),
        BigInt(va ?? 0),
        false,
      );
    const js = plan(physics, {
      capture: [
        { name: "dt", arg: 1, type: "f32" },
        { name: "speed", arg: 0, type: "f32", deref: [8], when: "both" },
      ],
      returns: "f32",
    });
    const native = plan(hot, { engine: "native", capture: [{ name: "x", arg: 0, type: "u32" }], returns: "u32" });
    const rj = (await t.rpc("hookInstall", js.params)) as { ok: boolean; value: HookInstallResult };
    const rn = (await t.rpc("hookInstall", native.params)) as { ok: boolean; value: HookInstallResult };
    expect([rj.ok, rn.ok]).toEqual([true, true]);
    expect(rj.value.instrument_id).toMatch(/^h\d+$/u);
    expect(rj.value.stream_id).toMatch(/^s\d+$/u); // core-allocated stream ids
    expect(await until(() => decodeStream(t.batches, rj.value.stream_id, js.decoders).length >= 5, 10_000)).toBe(true);
    expect(await until(() => decodeStream(t.batches, rn.value.stream_id, native.decoders).length >= 1000, 10_000)).toBe(
      true,
    );
    for (const e of decodeStream(t.batches, rj.value.stream_id, js.decoders)) {
      expect(e["dt:bits"]).toBe("0x3c888889");
      expect(e["ret:bits"]).toBe(e["speed@leave:bits"]);
    }
    expect(
      t.batches.filter((b) => b.stream === rj.value.stream_id).every((b) => b.instrument === rj.value.instrument_id),
    ).toBe(true);
    const status = (await t.rpc("status", { detail: "summary" })) as {
      value: { instruments: { id: string; state: string; counters: { hits: number; recorded: number } }[] };
    };
    const listed = status.value.instruments.filter(
      (i) => i.id === rj.value.instrument_id || i.id === rn.value.instrument_id,
    );
    expect(listed.map((i) => i.state)).toEqual(["active", "active"]);
    expect(listed.every((i) => i.counters.hits > 0 && i.counters.recorded > 0)).toBe(true);
    const stop = (await t.rpc("instrumentStop", { id: "all", final_flush: true })) as {
      ok: boolean;
      value: InstrumentStopResult;
    };
    expect(stop.ok).toBe(true);
    expect(stop.value.unreverted).toEqual([]);
    const ours = stop.value.stopped.filter((s) => s.id === rj.value.instrument_id || s.id === rn.value.instrument_id);
    expect(ours.map((s) => [s.end_reason, s.reverted, s.verification?.ok])).toEqual([
      ["requested", true, true],
      ["requested", true, true],
    ]);
    expect(await until(() => t.batches.some((b) => b.stream === rj.value.stream_id && b.final), 5000)).toBe(true);
  }, 60_000);
});
