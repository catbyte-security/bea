// WP3-AGENT acceptance (raw Frida; DESIGN §8.4 WP3 row, S4 §7.4, §19 tests 3–4): crash capture and exit flush of
// owned targets adopted into a bea-jobhost job (kill-on-close, DIE_ON_UNHANDLED_EXCEPTION). A crash → first-chance
// blocking report + last-chance (UEF) report, both acked, and the root exit code 0xC0000005 within 3 s. A fast exit
// right after resume → the exit hook flushes every buffered row (hook rows through the instrument stream + first-chance
// exception rows) before the bounded ack.
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import type { CrashReport, ExceptionRow, ExitMessage } from "../../../src/shared/agentProtocol.js";
import { jobhostSkip, skipNote } from "../../support/acceptance/fixtures.js";
import { agentLaneSkip, setupAgentLane, type AgentLane } from "../../support/agent/lane.js";
import { RawAgent } from "../../support/agent/rawAgent.js";
import { harnessLayout } from "../../support/mcp/stdioSubprocess.js";
import { OwnedPidLedger } from "../../support/process/ownedPidLedger.js";

const skip = agentLaneSkip() || jobhostSkip();

describe.skipIf(skip !== false)(`agent crash capture and exit flush under a job${skipNote(skip)}`, () => {
  let lane: AgentLane;
  let ledger: OwnedPidLedger;
  const agents: RawAgent[] = [];
  const crashy = async (args: readonly string[]): Promise<RawAgent> => {
    const a = await RawAgent.start({
      bundle: lane.bundle,
      program: lane.fixtures.crashy,
      args,
      cwd: lane.fixtureDir,
      jobhost: harnessLayout().jobhostExe,
    });
    agents.push(a);
    ledger.recordOwned(a.pid, null, `crashy ${args.join(" ")}`);
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

  it("av-write: first-chance + last-chance reports acked, exit 0xC0000005 within 3 s", async () => {
    const a = await crashy(["av-write", "--delay-ms", "200"]);
    await a.hello();
    const t0 = a.elapsedMs();
    await a.resume();
    const rootExit = await a.waitFor(() => a.jobhostEvents.find((e) => e.event === "root-exit"), 8000);
    expect(rootExit).toMatchObject({ codeHex: "0xC0000005", byKill: false });
    expect(a.elapsedMs() - t0).toBeLessThan(3000 + 200);
    const reports = a.messages("crash").map((m) => m["report"] as CrashReport);
    expect(reports.map((r) => r.phase)).toEqual(["first-chance", "last-chance"]);
    const [first, last] = reports as [CrashReport, CrashReport];
    expect(first).toMatchObject({
      type: "access-violation",
      code: null,
      memory: { operation: "write", address: "0x0" },
    });
    expect(first.instruction?.text).toMatch(/^mov dword ptr \[r\w+\], 0x2a$/u);
    expect(first.backtrace[0]).toMatchObject({ module: "crashy.exe" });
    expect(first.backtrace_source).toBe("exception-context");
    expect(last).toMatchObject({
      type: "access-violation",
      code: "0xc0000005",
      memory: { operation: "write", address: "0x0" },
      exception_information: ["0x1", "0x0"],
      backtrace_source: "first-chance-cache",
    });
    expect(last.registers.rip).toBe(first.registers.rip);
    expect(last.mxcsr).not.toBeNull();
    expect(last.fpcw).not.toBeNull();
    // every crash message was acked by token (record-before-ack is the host's part)
    expect(a.acked.filter((t) => t.startsWith("crash-"))).toHaveLength(2);
    // the first-chance row reached the host before the report (flushAll precedes the blocking send)
    const order = a.records.map((r) => r.payload["bea"]);
    const rowIndex = a.records.findIndex(
      (r) =>
        r.payload["bea"] === "batch" &&
        r.payload["stream"] === "s:exceptions" &&
        (r.payload["rows"] as unknown[]).length > 0,
    );
    expect(rowIndex).toBeGreaterThanOrEqual(0);
    expect(rowIndex).toBeLessThan(order.indexOf("crash"));
    const rows = a.rows("s:exceptions") as ExceptionRow[];
    expect(rows.find((r) => r[3] === "access-violation")?.[7]).toBe("reported");
    // DIE_ON_UNHANDLED_EXCEPTION terminates through NtTerminateProcess(self): the second exit hook flushes (S4 A-15)
    expect(await a.waitFor(() => a.messages("exit")[0], 2000)).toMatchObject({
      via: "NtTerminateProcess(self)",
      exit_code: 0xc0000005,
    });
    expect(a.detached).toContain("process-terminated");
  });

  it("div0: the reports carry the arithmetic type and STATUS_INTEGER_DIVIDE_BY_ZERO", async () => {
    const a = await crashy(["div0", "--delay-ms", "100"]);
    await a.hello();
    await a.resume();
    expect(await a.waitFor(() => a.jobhostEvents.find((e) => e.event === "root-exit"), 8000)).toMatchObject({
      codeHex: "0xC0000094",
    });
    const reports = a.messages("crash").map((m) => m["report"] as CrashReport);
    expect(reports.map((r) => [r.phase, r.type, r.code])).toEqual([
      ["first-chance", "arithmetic", null],
      ["last-chance", "arithmetic", "0xc0000094"],
    ]);
    expect(reports[0]!.instruction?.text).toMatch(/^idiv /u);
  });

  it("fast exit: the exit hook flushes every row before the bounded ack (crashy handled, test hook rows)", async () => {
    const a = await crashy(["handled", "--delay-ms", "0"]);
    const hello = await a.hello({
      crash: {
        first_chance_rows: true,
        first_chance_blocking: false,
        crash_class: ["access-violation"],
        ack_timeout_ms: 1000,
        last_chance_ack_timeout_ms: 2000,
        max_blocking_per_10s: 8,
        rows_per_sec: 1000,
        stack_bytes: 256,
        backtrace_depth: 32,
        include_xmm: false,
      },
    });
    expect(hello.system_streams.exceptions).toBe("s:exceptions");
    const hook = await a.rpc<{ instrument_id: string; stream_id: string }>("testHookRows", {
      module: "kernel32.dll",
      export: "IsBadReadPtr",
    });
    await a.resume();
    const exit = (await a.waitFor(() => a.messages("exit")[0], 8000)) as ExitMessage | null;
    expect(exit).toMatchObject({ via: "RtlExitUserProcess", exit_code: 0 });
    expect(await a.waitFor(() => a.jobhostEvents.find((e) => e.event === "root-exit"), 5000)).toMatchObject({
      codeHex: "0x00000000",
    });
    expect(a.output()).toContain("HANDLED count=10");
    // all ten calls and all ten handled first-chance AVs arrived, marked final, before the exit message
    expect(a.rows(hook.stream_id)).toHaveLength(10);
    const rows = a.rows("s:exceptions") as ExceptionRow[];
    expect(rows).toHaveLength(10);
    expect(new Set(rows.map((r) => r[7]))).toEqual(new Set(["passed"]));
    const exitIndex = a.records.findIndex((r) => r.payload["bea"] === "exit");
    const finals = a.records.filter(
      (r, i) => i < exitIndex && r.payload["bea"] === "batch" && r.payload["final"] === true,
    );
    expect(finals.map((r) => r.payload["stream"])).toEqual(
      expect.arrayContaining([hook.stream_id, "s:exceptions", "s:modules"]),
    );
    expect(exit!.flushed.rows).toBeGreaterThanOrEqual(20);
    expect(a.acked).toContain(exit!.ack);
  });
});
