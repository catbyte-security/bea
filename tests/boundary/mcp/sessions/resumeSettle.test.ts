import { afterEach, describe, expect, it } from "vitest";

import { FakeSessions } from "../../../support/fakes/fakeSession.js";
import { connectInMemoryBea, type InMemoryBea } from "../../../support/mcp/inMemory.js";
import { expectToolSuccess } from "../../../support/mcp/parseToolError.js";
import { FakeEvidence, FakeRecordings } from "../../../unit/sessions/support/fakeEvidence.js";

/**
 * Integrator regression (WP18): resume_process {wait_ms} returns FINISHED instrument summaries. The agent's final
 * batch (an instrument's end, or the exit-time flush of a target that is exiting) ends the stream before the recording
 * registry has ended the recording; the handler used to return at that instant with the recording still "active"
 * (seen on the real stack: trace_api + behavior.exe answered "running" after ~40 ms while the target was exiting).
 */
let bea: InMemoryBea | undefined;
afterEach(async () => {
  await bea?.close();
  bea = undefined;
});

const setup = async () => {
  const sessions = new FakeSessions();
  const recordings = new FakeRecordings();
  const evidence = new FakeEvidence();
  bea = await connectInMemoryBea({ services: { sessions, recordings, evidence } });
  const session = sessions.add();
  await session.streams.bind("s7", {
    source: { kind: "api", instance_id: null, effect_id: null, channel: "s7" },
    encoding: { kind: "json-rows", row_kind: "api/1" },
    decoders: null,
    literals: { count: 0, texts: [], spellings: [] },
  });
  const rec = recordings.create({
    sessionId: session.id,
    kind: "api",
    agentInstrumentId: "p1",
    agentStream: "s7",
    streamId: null,
    effectId: null,
    durationMs: 30_000,
    maxEvents: null,
    startsAtResume: true,
    decoders: null,
  });
  return { session, recordings, rec };
};

describe("resume_process waits for the recordings it waited on to finish", () => {
  it("a stream that ended before its recording did: the result carries the finished state, not 'active'", async () => {
    const { session, recordings, rec } = await setup();
    const resuming = bea!.client.callTool({
      name: "resume_process",
      arguments: { session_id: session.id, wait_ms: 5000 },
    });
    // the final batch lands first (the wait condition holds) …
    setTimeout(() => {
      session.streams.markEnded("s7");
      session.notify(); // wakes the fake's waiters, as the real binder's notify does
    }, 50);
    // … the registry ends the recording a little later (the instrument "ended" message / the root-exit report)
    setTimeout(() => void recordings.end(rec.id, "target_exited"), 300);
    const result = expectToolSuccess(await resuming);
    const instruments = result["instruments"] as { recording_id: string; state: string; end_reason: string | null }[];
    expect(instruments).toContainEqual(
      expect.objectContaining({ recording_id: rec.id, state: "finished", end_reason: "target_exited" }),
    );
    expect(result["waited_ms"] as number).toBeGreaterThanOrEqual(200);
    expect(result["waited_ms"] as number).toBeLessThan(2000); // ended by the stream end + settle, not by wait_ms
  });

  it("until exit settles the BUILT-IN recordings too, and marks a still-active one partial (UX-5)", async () => {
    const sessions = new FakeSessions();
    const recordings = new FakeRecordings();
    const evidence = new FakeEvidence();
    bea = await connectInMemoryBea({ services: { sessions, recordings, evidence } });
    const session = sessions.add();
    const builtin = (kind: "exceptions" | "output", stream: string) =>
      recordings.create({
        sessionId: session.id,
        kind,
        agentInstrumentId: null,
        agentStream: stream,
        streamId: null,
        effectId: null,
        durationMs: null,
        maxEvents: null,
        startsAtResume: false,
        decoders: null,
      });
    const exceptions = builtin("exceptions", "s:exceptions");
    const output = builtin("output", "s:output");
    const resuming = bea.client.callTool({
      name: "resume_process",
      arguments: { session_id: session.id, wait_ms: 5000, until: "exit" },
    });
    setTimeout(() => session.exitWith({ code: 0, code_hex: "0x0", kind: "normal", name: null }), 50);
    // the exit report ends the built-in recordings a little after the process-exit condition held
    setTimeout(() => void recordings.end(exceptions.id, "target_exited"), 300);
    const result = expectToolSuccess(await resuming);
    const instruments = result["instruments"] as { recording_id: string; state: string }[];
    expect(instruments).toContainEqual(expect.objectContaining({ recording_id: exceptions.id, state: "finished" }));
    // the output recording never ended within the budget: the result says so instead of claiming complete
    expect(instruments).toContainEqual(expect.objectContaining({ recording_id: output.id, state: "active" }));
    expect(result["coverage"]).toMatchObject({ status: "partial", reasons: ["recording_active"] });
  });

  it("the settle is bounded by wait_ms: a recording that never finishes does not hold the call", async () => {
    const { session, rec } = await setup();
    const started = performance.now();
    const resuming = bea!.client.callTool({
      name: "resume_process",
      arguments: { session_id: session.id, wait_ms: 400 },
    });
    setTimeout(() => {
      session.streams.markEnded("s7");
      session.notify(); // wakes the fake's waiters, as the real binder's notify does
    }, 50);
    const result = expectToolSuccess(await resuming);
    expect(performance.now() - started).toBeLessThan(2500);
    const instruments = result["instruments"] as { recording_id: string; state: string }[];
    expect(instruments).toContainEqual(expect.objectContaining({ recording_id: rec.id, state: "active" }));
  });
});
