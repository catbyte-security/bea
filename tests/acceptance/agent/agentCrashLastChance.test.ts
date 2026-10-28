// BEA-FEEDBACK.md item 4 (raw Frida, under a bea-jobhost job like agentCrash.test.ts): with blocking first-chance
// reports off, the host default, a crash is reported once, at last chance (the UEF listener), and that report carries
// the faulting frames unwound from the exception's own CONTEXT by ntdll's unwinder: no dbghelp, and none of the
// exception-dispatch frames the old walk from inside the UEF call listed first. A faulting pc outside every image
// (DEP, a call through a bad pointer) still gets its caller through the leaf rule.
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import type { CrashReport, ExceptionRow } from "../../../src/shared/agentProtocol.js";
import { fixtureArtifact, jobhostSkip, loadFixtures, skipNote } from "../../support/acceptance/fixtures.js";
import { agentLaneSkip, setupAgentLane, type AgentLane } from "../../support/agent/lane.js";
import { defaultHello, RawAgent } from "../../support/agent/rawAgent.js";
import { harnessLayout } from "../../support/mcp/stdioSubprocess.js";
import { OwnedPidLedger } from "../../support/process/ownedPidLedger.js";

const skip = agentLaneSkip() || jobhostSkip();
const REPORTS_OFF = { crash: { ...defaultHello().crash, first_chance_blocking: false } };
const rva = (n: number): string => `0x${n.toString(16)}`;

describe.skipIf(skip !== false)(`last-chance crash reports, first-chance reports off${skipNote(skip)}`, () => {
  let lane: AgentLane;
  let ledger: OwnedPidLedger;
  let sites: { crashWrite: { rva: number }; returnSites: { level1: number; level2: number } };
  const agents: RawAgent[] = [];

  /** crashy <mode>, adopted into a job, hello with blocking first-chance reports off, resumed; its reports at exit. */
  const crash = async (mode: string): Promise<{ agent: RawAgent; reports: CrashReport[] }> => {
    const a = await RawAgent.start({
      bundle: lane.bundle,
      program: lane.fixtures.crashy,
      args: [mode, "--delay-ms", "100"],
      cwd: lane.fixtureDir,
      jobhost: harnessLayout().jobhostExe,
    });
    agents.push(a);
    ledger.recordOwned(a.pid, null, `crashy ${mode}`);
    await a.hello(REPORTS_OFF);
    await a.resume();
    expect(await a.waitFor(() => a.jobhostEvents.find((e) => e.event === "root-exit"), 8000)).toMatchObject({
      codeHex: "0xC0000005",
    });
    return { agent: a, reports: a.messages("crash").map((m) => m["report"] as CrashReport) };
  };

  beforeAll(async () => {
    lane = await setupAgentLane();
    ledger = new OwnedPidLedger(lane.pidcheck);
    sites = fixtureArtifact(await loadFixtures(), "crashy")?.expectations as typeof sites;
  }, 180_000);

  afterEach(async () => {
    for (const a of agents.splice(0)) await a.close();
  });

  afterAll(async () => {
    await RawAgent.shutdownFrida();
    await ledger?.assertClean();
  });

  it("av-write: one acked last-chance report with pc, instruction, registers and the faulting frames", async () => {
    const { agent, reports } = await crash("av-write");
    expect(reports.map((r) => r.phase)).toEqual(["last-chance"]);
    const last = reports[0]!;
    expect(last).toMatchObject({
      type: "access-violation",
      code: "0xc0000005",
      memory: { operation: "write", address: "0x0" },
      exception_information: ["0x1", "0x0"],
      backtrace_source: "exception-context",
    });
    expect(last.instruction?.text).toMatch(/^mov dword ptr \[r\w+\], 0x2a$/u);
    expect(last.registers.rip).toBe(last.address);
    // [crash site, level1's return site, level2's return site, …, the thread's start in ntdll]
    expect(last.backtrace.slice(0, 3).map((f) => [f.module, f.rva])).toEqual([
      ["crashy.exe", rva(sites.crashWrite.rva)],
      ["crashy.exe", rva(sites.returnSites.level1)],
      ["crashy.exe", rva(sites.returnSites.level2)],
    ]);
    const ntdll = last.backtrace.filter((f) => f.module?.toLowerCase() === "ntdll.dll");
    expect(ntdll).toHaveLength(1);
    expect(last.backtrace.at(-1)).toEqual(ntdll[0]);
    // the first-chance access violation was a row only, and the one report was acked
    const rows = agent.rows("s:exceptions") as ExceptionRow[];
    expect(rows.find((r) => r[3] === "access-violation")?.[7]).toBe("passed");
    expect(agent.acked.filter((t) => t.startsWith("crash-"))).toHaveLength(1);
  });

  it("av-exec: the pc lies outside every image; the leaf rule recovers the caller", async () => {
    const { reports } = await crash("av-exec");
    expect(reports.map((r) => r.phase)).toEqual(["last-chance"]);
    const last = reports[0]!;
    expect(last).toMatchObject({ memory: { operation: "execute" }, backtrace_source: "exception-context" });
    expect(last.backtrace[0]?.module).toBeNull();
    expect(last.backtrace[1]?.module).toBe("crashy.exe");
    expect(last.backtrace.at(-1)?.module?.toLowerCase()).toBe("ntdll.dll");
  });
});
