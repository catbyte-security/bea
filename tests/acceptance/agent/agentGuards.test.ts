// WP3-AGENT acceptance (raw Frida; DESIGN §5.3, §5.3.1, §8.4 WP3 row; CT-B1, CT-I5, S4 F15/A-33):
//  - BEA guard pages: Frida omits a PAGE_GUARD page from enumerateRanges and its try-scope APIs consume the guard
//    [CT-lab E16b]; listRanges/describeAddresses re-insert the page with its original protection, readMemory and a
//    scanSync inside withBeaGuardsSuspended find a planted value and the guard stays armed; a scan outside the window
//    "steals" the guard and the core re-arms it at once.
//  - THE dispatcher's in-call branch: an exception inside a BEA call (core.calls.enter on the agent thread or on a
//    target thread through runOnThread) is an `in-call` row, never a blocking report; without the bracket the same
//    exception is reported.
//  - THE dispatcher is first: a user script's handler registered later never sees BEA's traps, but sees the rest.
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import type { ExceptionRow } from "../../../src/shared/agentProtocol.js";
import { skipNote } from "../../support/acceptance/fixtures.js";
import {
  agentLaneSkip,
  PAGE_GUARD,
  setupAgentLane,
  USER_HANDLER_SCRIPT,
  type AgentLane,
} from "../../support/agent/lane.js";
import { RawAgent } from "../../support/agent/rawAgent.js";
import { OwnedPidLedger } from "../../support/process/ownedPidLedger.js";

const skip = agentLaneSkip();
const MARKER = 0x13371337;

interface GuardState {
  readonly protect: number;
  readonly guarded: boolean;
  readonly windows: number;
  readonly stolen: number;
  readonly fallbackTraps: number;
}

describe.skipIf(skip !== false)(`BEA guard pages, the in-call branch and dispatcher order${skipNote(skip)}`, () => {
  let lane: AgentLane;
  let ledger: OwnedPidLedger;
  const agents: RawAgent[] = [];
  const start = async (args: readonly string[]): Promise<RawAgent> => {
    const a = await RawAgent.start({
      bundle: lane.bundle,
      program: lane.fixtures.game_sim,
      args,
      cwd: lane.fixtureDir,
    });
    agents.push(a);
    ledger.recordOwned(a.pid, null, `game_sim ${args.join(" ")}`);
    await a.hello();
    await a.resume();
    await a.waitFor(() => a.output().includes("READY"), 5000);
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

  it("a planted value on a BEA-guarded page is found through withBeaGuardsSuspended; the guard stays armed", async () => {
    const a = await start(["--hz", "60"]);
    const g = await a.rpc<{ page: string; armed: boolean; protect: number }>("testGuardPage", { marker: MARKER });
    expect(g.armed).toBe(true);
    expect(g.protect & PAGE_GUARD).toBe(PAGE_GUARD);
    // listRanges / describeAddresses re-insert the page with its original protection (rw-)
    const ranges = await a.ok<{ items: { base: string; protection: string; kind: string }[] }>("listRanges", {
      protection: "rw-",
      coalesce: false,
      kind: "all",
      offset: 0,
      limit: 5000,
    });
    expect(ranges.items.filter((r) => r.base === g.page)).toEqual([
      expect.objectContaining({ protection: "rw-", kind: "private" }),
    ]);
    const described = await a.ok<{ results: { bea_guarded: boolean; range: { protection: string } | null }[] }>(
      "describeAddresses",
      { addresses: [g.page] },
    );
    expect(described.results[0]).toMatchObject({ bea_guarded: true, range: { protection: "rw-" } });
    // readMemory inside a suspension window
    const at = `0x${(BigInt(g.page) + 0x100n).toString(16)}`;
    const reply = await a.rpc<[{ ok: true; value: { bea_guard_suspended: string[]; complete: boolean } }, Buffer]>(
      "readMemory",
      {
        address: at,
        size: 4,
      },
    );
    expect(reply[0].value).toMatchObject({ complete: true, bea_guard_suspended: [g.page] });
    expect(reply[1].readUInt32LE(0)).toBe(MARKER);
    // scanSync through withBeaGuardsSuspended finds the planted value; the guard is armed again afterwards
    const scan = await a.rpc<{ hits: string[]; protectAfter: number }>("testScanSuspended", {
      page: g.page,
      pattern: "37 13 37 13",
    });
    expect(scan.hits).toEqual([at]);
    expect(scan.protectAfter & PAGE_GUARD).toBe(PAGE_GUARD);
    const state = await a.rpc<GuardState>("testGuardState", { page: g.page });
    expect(state).toMatchObject({ guarded: true, windows: 2, stolen: 0 });
    // outside a window Frida's try-scope consumes the guard: the core re-arms it (stolen guard, one more window)
    const stolen = await a.rpc<{ threw: string | null; protectAfter: number }>("testScanUnsuspended", {
      page: g.page,
      pattern: "37 13 37 13",
    });
    expect(stolen.threw).toMatch(/guard page was hit/u);
    expect(stolen.protectAfter & PAGE_GUARD).toBe(PAGE_GUARD);
    expect(await a.rpc<GuardState>("testGuardState", { page: g.page })).toMatchObject({ guarded: true, stolen: 1 });
  });

  it("exceptions inside core.calls are in-call rows with stashed GPRs and never a blocking report", async () => {
    const a = await start(["--hz", "60"]);
    const onAgent = await a.rpc<{ result: number; exited: { inCall: number; registers: Record<string, string> } }>(
      "testInCallAgentThread",
    );
    expect(onAgent.result).toBe(1); // IsBadReadPtr's own SEH handled its AV (exceptions:"propagate")
    expect(onAgent.exited.inCall).toBe(1);
    expect(onAgent.exited.registers).toMatchObject({ rcx: "0x10", rip: expect.stringMatching(/^0x/u) });
    const main = await a.rpc<number>("testMainThread");
    const onMain = await a.rpc<{ result: number; tid: number; exited: { inCall: number } }>("testInCallOnThread", {
      tid: main,
      bracket: true,
    });
    expect(onMain).toMatchObject({ result: 1, tid: main, exited: { inCall: 1 } });
    expect(a.messages("crash")).toEqual([]);
    const rows = (await a.waitFor(() => {
      const r = a.rows("s:exceptions") as ExceptionRow[];
      return r.length >= 2 ? r : null;
    }, 3000)) as ExceptionRow[];
    expect(rows.map((r) => r[7])).toEqual(["in-call", "in-call"]);
    expect(rows[1]![2]).toBe(main);
    const status = await a.ok<{ exceptions: { in_call: number; blocking_reports: number } }>("status", {
      detail: "summary",
    });
    expect(status.exceptions).toMatchObject({ in_call: 2, blocking_reports: 0 });
    // control: the same exception on the same thread WITHOUT the bracket is reported (blocking, acked)
    const control = await a.rpc<{ result: number }>("testInCallOnThread", { tid: main, bracket: false });
    expect(control.result).toBe(1);
    expect(await a.waitFor(() => a.messages("crash")[0], 3000)).toMatchObject({
      report: { phase: "first-chance", tid: main },
    });
    expect((a.rows("s:exceptions") as ExceptionRow[]).map((r) => r[7])).toEqual(["in-call", "in-call", "reported"]);
  });

  it("BEA's handler runs first: a later user handler never sees BEA traps but sees the target's exceptions", async () => {
    const a = await start(["--hz", "60"]);
    const resolved = await a.ok<{ results: { target: { va: string } }[] }>("resolveTargets", {
      targets: [{ module: "game_sim.exe", export: "g_mix_result" }],
    });
    // the main thread writes g_mix_result every frame: the core's fallback engine traps and re-arms each access
    const g = await a.rpc<{ page: string; armed: boolean }>("testGuardAddress", {
      address: resolved.results[0]!.target.va,
    });
    expect(g.armed).toBe(true);
    const user = await a.session.createScript(USER_HANDLER_SCRIPT, { name: "bea-user-1", runtime: "qjs" });
    user.logHandler = () => undefined;
    await user.load();
    const before = (await a.rpc<GuardState>("testGuardState", { page: g.page })).fallbackTraps;
    await new Promise((r) => setTimeout(r, 500));
    const after = await a.rpc<GuardState>("testGuardState", { page: g.page });
    expect(after.fallbackTraps).toBeGreaterThan(before);
    const main = await a.rpc<number>("testMainThread");
    await a.rpc("testInCallOnThread", { tid: main, bracket: false });
    const counts = (await user.exports["counts"]!()) as Record<string, number>;
    expect(counts["guard-page"] ?? 0).toBe(0);
    expect(counts["single-step"] ?? 0).toBe(0);
    expect(counts["access-violation"]).toBeGreaterThanOrEqual(1);
    const status = await a.ok<{ exceptions: { bea_traps: number } }>("status", { detail: "summary" });
    expect(status.exceptions.bea_traps).toBeGreaterThan(0);
    await user.unload();
    // the target kept running under BEA's trap traffic (FRAME every 60 frames)
    expect(await a.waitFor(() => /FRAME \d+/u.test(a.output()), 5000)).toBe(true);
  });
});
