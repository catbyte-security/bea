import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { connectBea } from "../../support/acceptance/harness.js";
import {
  fixtureArtifact,
  fridaSkip,
  gccSkip,
  jobhostSkip,
  loadFixtures,
  skipNote,
  type FixtureArtifact,
} from "../../support/acceptance/fixtures.js";
import { expectToolSuccess } from "../../support/mcp/parseToolError.js";
import { OwnedPidLedger } from "../../support/process/ownedPidLedger.js";

/**
 * WP18 regression for the Frida 17.23.2 exceptor deadlock WP9 diagnosed (docs/limitations.md): Stalker.follow(tid) of
 * a thread blocked in a system call arms a debug register at the stub's return, and gum's exceptor can re-trap on it
 * inside its own critical section, freezing the thread and then the agent (seen in ~1 of 8 tool-level runs, 3–8 of
 * 40 agent-level iterations around a thread creation). The agent now follows such a thread from its next entry into
 * that stub (src/agent/trace.ts followAtNextEntry). game_sim's main thread spends nearly all its time in Sleep, so
 * every trace here takes the deferred path; threads are being created around the first traces (input, telemetry and
 * a late engine thread), which is when the deadlock showed. Each start must answer, record the main loop and leave
 * the target running.
 */
const skip = fridaSkip() || gccSkip() || jobhostSkip();
const SERVERS = 8;
const TARGETS_PER_SERVER = 3; // the S6 §10.7 hygiene budget

let game: FixtureArtifact;
let ledger: OwnedPidLedger;

beforeAll(async () => {
  if (skip !== false) return;
  const manifest = await loadFixtures();
  const sim = fixtureArtifact(manifest, "game_sim");
  if (sim === null) throw new Error("game_sim fixture unavailable");
  game = sim;
  ledger = new OwnedPidLedger(fixtureArtifact(manifest, "pidcheck")?.path ?? null);
});

afterAll(async () => {
  if (skip !== false) return;
  await ledger.assertClean();
});

describe.skipIf(skip !== false)(`trace_execution threads mode on a sleeping thread${skipNote(skip)}`, () => {
  // Each target's main thread is traced twice, back to back: the second trace of the same thread used to record nothing
  // every other time (the first trace's exec context never let go of the thread; review fix AGENT-8).
  it(`${String(SERVERS * TARGETS_PER_SERVER)} block_counts traces of game_sim's main thread, each while threads are being created, never wedge the target or the agent`, async () => {
    for (let server = 0; server < SERVERS; server += 1) {
      const bea = await connectBea({ ledger });
      try {
        for (let target = 0; target < TARGETS_PER_SERVER; target += 1) {
          const label = `server ${String(server)} target ${String(target)}`;
          // the engine thread is created 50–250 ms after start: around the trace's follow
          const spawned = expectToolSuccess(
            await bea.call("spawn_process", {
              program: game.path,
              args: ["--engine-start-ms", String(50 + 100 * target)],
            }),
          );
          const id = String(spawned["session_id"]);
          expectToolSuccess(await bea.call("resume_process", { session_id: id }));
          expectToolSuccess(
            await bea.call("wait", { session_id: id, until: "output", output_contains: "READY", timeout_ms: 15_000 }),
          );
          const threads = expectToolSuccess(await bea.call("list_threads", { session_id: id }));
          const main = (threads["rows"] as { tid: number; main: boolean }[]).find((row) => row.main)?.tid;
          expect(main, label).toBeDefined();
          const started = performance.now();
          const trace = expectToolSuccess(
            await bea.call("trace_execution", {
              session_id: id,
              thread_ids: [main],
              mode: "block_counts",
              duration_ms: 400,
              wait_ms: 5000,
            }),
          );
          const instrument = trace["instrument"] as { state: string; events: number; end_reason: string | null };
          const detail = `${label}: ${JSON.stringify(instrument).slice(0, 400)}`;
          expect(instrument.state, detail).toBe("finished");
          expect(instrument.end_reason, detail).toBe("duration");
          expect(instrument.events, detail).toBeGreaterThan(0); // the main loop ran under Stalker
          expect(performance.now() - started, detail).toBeLessThan(5000);
          const again = expectToolSuccess(
            await bea.call("trace_execution", {
              session_id: id,
              thread_ids: [main],
              mode: "block_counts",
              duration_ms: 400,
              wait_ms: 5000,
            }),
          );
          const second = again["instrument"] as { state: string; events: number; end_reason: string | null };
          const secondDetail = `${label}, second trace: ${JSON.stringify(second).slice(0, 400)}`;
          expect(second.state, secondDetail).toBe("finished");
          expect(second.events, secondDetail).toBeGreaterThan(0);
          // the target is alive and the agent still answers
          expect(expectToolSuccess(await bea.call("session_status", { session_id: id }))["state"], label).toBe(
            "running",
          );
          expectToolSuccess(
            await bea.call("read_memory", { session_id: id, address: "game_sim.exe!g_marker", size: 8, view: "u64" }),
          );
          expectToolSuccess(await bea.call("close_session", { session_id: id }));
        }
      } finally {
        await bea.close();
      }
    }
  }, 600_000);
});
