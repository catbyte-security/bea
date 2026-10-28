import { describe, expect, it } from "vitest";

import { INSTRUMENT_GRACE_MS, runInstrument } from "../../../src/cli/instrumentRunner.js";
import type { CliRun } from "../../../src/cli/runtime.js";
import type { ToolOutput } from "../../../src/application/invokeTool.js";
import { ok, type Result } from "../../../src/domain/result.js";
import type { BeaError } from "../../../src/domain/errors/beaError.js";
import { FAKE_CONTRACTS } from "../../support/cli/fakeCatalog.js";

/** A CliRun stub over a scripted clock: every `wait` advances time by its timeout_ms, as a real blocking wait would. */
const scriptedRun = (
  clock: { now: number },
  calls: { tool: string; input: Readonly<Record<string, unknown>> }[],
): CliRun => {
  const call = async (
    tool: string,
    input: Readonly<Record<string, unknown>>,
  ): Promise<Result<ToolOutput, BeaError>> => {
    calls.push({ tool, input });
    const base = { evidence_id: null };
    if (tool === "hook_function") return ok({ ...base, instrument: { recording_id: "rec_00000001", kind: "hook" } });
    if (tool === "wait") {
      clock.now += input["timeout_ms"] as number;
      return ok({ ...base, satisfied: false, reason: "timeout" });
    }
    return ok({ ...base, tool });
  };
  return {
    app: undefined as never,
    signal: new AbortController().signal,
    call,
    cleanupCall: call,
    signalStatus: () => undefined,
    findContract: (name) => FAKE_CONTRACTS.find((c) => c.name === name),
    close: async () => ({ ok: true, reason: "test", elapsed_ms: 0, phases: [] }),
  };
};

describe("instrument runner deadline (duration starts at resume, CI-I3)", () => {
  it("waits in ≤ 60 s slices until duration + grace, then queries and stops", async () => {
    const clock = { now: 0 };
    const calls: { tool: string; input: Readonly<Record<string, unknown>> }[] = [];
    const hook = FAKE_CONTRACTS.find((c) => c.name === "hook_function");
    if (hook === undefined) throw new Error("missing");
    const session = "11111111-1111-4111-8111-111111111111";
    const outcome = await runInstrument(
      scriptedRun(clock, calls),
      hook,
      { session_id: session, address: "0x1", duration_ms: 90_000 },
      session,
      true,
      () => clock.now,
    );
    expect(outcome.result.ok && outcome.result.value.stop_reason).toBe("duration");
    expect(outcome.degraded).toBe(false);
    const waits = calls.filter((c) => c.tool === "wait").map((c) => c.input["timeout_ms"]);
    expect(waits).toEqual([60_000, 30_000 + INSTRUMENT_GRACE_MS]);
    expect(calls.map((c) => c.tool)).toEqual([
      "hook_function",
      "resume_process",
      "wait",
      "wait",
      "query_events",
      "stop_instrumentation",
    ]);
    expect(calls[1]?.input).toEqual({ session_id: session });
  });
});

describe("instrument runner document (review fix ONBOARD-7)", () => {
  it("prints the recording digest once: the wait result's recordings drop the summary the summary query carries", async () => {
    const session = "11111111-1111-4111-8111-111111111111";
    const hook = FAKE_CONTRACTS.find((c) => c.name === "hook_function");
    if (hook === undefined) throw new Error("missing");
    const digest = { calls: 3, callers: [{ at: "game_sim.exe+0x10", calls: 3 }] };
    const call = async (tool: string): Promise<Result<ToolOutput, BeaError>> => {
      const base = { evidence_id: null };
      if (tool === "hook_function") return ok({ ...base, instrument: { recording_id: "rec_00000001", kind: "hook" } });
      if (tool === "wait")
        return ok({
          ...base,
          satisfied: true,
          recordings: [{ id: "rec_00000001", state: "finished", events: 3, summary: digest }],
        });
      if (tool === "query_events")
        return ok({ ...base, recording: { id: "rec_00000001", events: 3 }, summary: digest });
      return ok({ ...base, tool });
    };
    const run: CliRun = { ...scriptedRun({ now: 0 }, []), call, cleanupCall: call };
    const outcome = await runInstrument(
      run,
      hook,
      { session_id: session, address: "0x1", duration_ms: 1000 },
      session,
      false,
      () => 0,
    );
    if (!outcome.result.ok) throw new Error(outcome.result.error._tag);
    const doc = outcome.result.value as {
      wait: { recordings: Record<string, unknown>[] };
      summary: { summary: unknown };
    };
    expect(doc.wait.recordings[0]).toEqual({ id: "rec_00000001", state: "finished", events: 3 });
    expect(doc.summary.summary).toEqual(digest);
  });
});
