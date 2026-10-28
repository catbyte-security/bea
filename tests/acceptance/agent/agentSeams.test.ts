// WP3-AGENT acceptance (raw Frida; DESIGN §5.3, S4 §5.7, §6): the core services feature WPs build on, exercised in a
// live agent through the test entry — an instrument opened through the WP9 seam (core.watchSeam.openInstrument:
// rows on its own stream, max_hits stops it with a final batch, the revert runs once, the ended summary carries the
// counters) and feature-managed instruments (WP7/WP8 registerExternal: the feature sends its own ended message;
// WP12 register(id, handle): the registry sends it) listed and stopped through instrumentList / instrumentStop.
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import type { InstrumentSummary } from "../../../src/shared/agentProtocol.js";
import { skipNote } from "../../support/acceptance/fixtures.js";
import { agentLaneSkip, setupAgentLane, type AgentLane } from "../../support/agent/lane.js";
import { RawAgent } from "../../support/agent/rawAgent.js";
import { OwnedPidLedger } from "../../support/process/ownedPidLedger.js";

const skip = agentLaneSkip();

describe.skipIf(skip !== false)(`core services for feature work packages${skipNote(skip)}`, () => {
  let lane: AgentLane;
  let ledger: OwnedPidLedger;
  const agents: RawAgent[] = [];
  const start = async (): Promise<RawAgent> => {
    const a = await RawAgent.start({
      bundle: lane.bundle,
      program: lane.fixtures.game_sim,
      args: ["--hz", "60"],
      cwd: lane.fixtureDir,
    });
    agents.push(a);
    ledger.recordOwned(a.pid, null, "game_sim");
    await a.hello();
    await a.resume();
    return a;
  };

  beforeAll(async () => {
    lane = await setupAgentLane();
    ledger = new OwnedPidLedger(lane.pidcheck);
  }, 180_000);

  afterEach(async () => {
    for (const a of agents.splice(0)) await a.close();
  });

  afterAll(async () => {
    await RawAgent.shutdownFrida();
    await ledger?.assertClean();
  });

  it("an instrument opened through core.watchSeam records rows and ends at max_hits with a final batch", async () => {
    const a = await start();
    const r = await a.rpc<{ id: string; stream: string; hits: boolean[]; active: boolean }>("testSeamInstrument");
    expect(r.id).toMatch(/^w\d+$/u);
    expect(r.hits).toEqual([true, true, false]); // the 2nd hit reaches max_hits (recorded); the 3rd is ignored
    expect(r.active).toBe(false);
    const ended = (await a.waitFor(() => a.messages("instrument").find((m) => m["id"] === r.id), 3000)) as {
      detail: InstrumentSummary;
    } | null;
    expect(ended?.detail).toMatchObject({
      id: r.id,
      kind: "watch",
      label: "seam",
      state: "ended",
      end_reason: "max_hits",
      reverted: true,
      verification: { kind: "dr7", ok: true },
      counters: { hits: 2, recorded: 2, filtered: 5 },
    });
    expect(await a.rpc<number>("testSeamReverts")).toBe(1);
    const rows = a.rows(r.stream);
    expect(rows).toHaveLength(2);
    expect(rows.map((row) => row[3])).toEqual([r.id, r.id]);
    expect(
      a
        .messages("batch")
        .filter((b) => b["stream"] === r.stream)
        .at(-1),
    ).toMatchObject({ final: true, kind: "watch/1" });
  });

  it('a clock:"resume" lifetime starts at the host\'s resumed post, not at install (CI-I3)', async () => {
    const a = await RawAgent.start({
      bundle: lane.bundle,
      program: lane.fixtures.game_sim,
      args: ["--hz", "60"],
      cwd: lane.fixtureDir,
    });
    agents.push(a);
    ledger.recordOwned(a.pid, null, "game_sim paused");
    await a.hello();
    const lifetime = { duration_ms: 300, max_hits: 100_000 };
    const paused = await a.rpc<{ instrument_id: string }>("testHookRows", {
      module: "kernelbase.dll",
      export: "Sleep",
      lifetime: { ...lifetime, clock: "resume" },
    });
    const installClock = await a.rpc<{ instrument_id: string }>("testHookRows", {
      module: "kernelbase.dll",
      export: "SleepEx",
      lifetime,
    });
    const info = await a.ok<{ instruments: { id: string; deadline_t: number | null }[] }>("instrumentList");
    expect(info.instruments.find((i) => i.id === paused.instrument_id)?.deadline_t).toBeNull();
    expect(info.instruments.find((i) => i.id === installClock.instrument_id)?.deadline_t).toEqual(expect.any(Number));
    // the install-clock instrument ends on its own timer while the target is still suspended
    const endedOf = (id: string) => a.messages("instrument").find((m) => m["id"] === id && m["event"] === "ended");
    expect(await a.waitFor(() => endedOf(installClock.instrument_id), 3000)).not.toBeNull();
    expect(endedOf(paused.instrument_id)).toBeUndefined();
    await a.resume();
    const resumedAt = a.elapsedMs();
    a.post({ type: "resumed" });
    const ended = (await a.waitFor(() => endedOf(paused.instrument_id), 3000)) as {
      detail: { end_reason: string };
    } | null;
    expect(ended?.detail.end_reason).toBe("duration");
    expect(a.elapsedMs() - resumedAt).toBeGreaterThanOrEqual(250);
  });

  it("feature-managed instruments are listed and stopped; only registry-owned ended messages come from the core", async () => {
    const a = await start();
    const ids = await a.rpc<{ ownId: string; regId: string }>("testExternalInstruments");
    const listed = await a.ok<{ instruments: { id: string; state: string }[] }>("instrumentList");
    expect(listed.instruments.map((i) => i.id)).toEqual(expect.arrayContaining([ids.ownId, ids.regId]));
    const stopped = await a.ok<{ stopped: { id: string }[]; not_found: string[] }>("instrumentStop", {
      id: "all",
      final_flush: true,
    });
    expect(stopped.stopped.map((s) => s.id).sort()).toEqual([ids.ownId, ids.regId].sort());
    expect(stopped.not_found).toEqual([]);
    const ended = a.messages("instrument").map((m) => m["id"]);
    expect(ended.filter((id) => id === ids.ownId)).toHaveLength(1); // sent by the feature itself, not duplicated
    expect(ended.filter((id) => id === ids.regId)).toHaveLength(1); // sent by the registry
    expect(await a.ok("instrumentStop", { id: "h999", final_flush: false })).toMatchObject({ not_found: ["h999"] });
    const after = await a.ok<{ instruments: unknown[] }>("status", { detail: "summary" });
    expect(after.instruments).toEqual([]);
  });
});
