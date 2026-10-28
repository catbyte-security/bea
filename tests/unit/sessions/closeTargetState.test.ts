import { describe, expect, it } from "vitest";

import { hostFactsOf } from "../../../src/application/sessions/hostFacts.js";
import { ok } from "../../../src/domain/result.js";
import type { LiveSession } from "../../../src/ports/sessions.js";
import { ownedTargetState } from "../../../src/providers/frida/closeSession.js";
import { createHarness, settle, type Harness } from "./support/harness.js";

/**
 * The owned target's state after close (found by the real-Frida acceptance run, S6 §10.8 close_session row "behavior
 * with a lingering child → killed"): a root that exited on its own is `already-exited` unless the job still held
 * processes that the close killed — then BEA killed part of the target tree and reports `killed` with the
 * process-killed effect.
 */
const termination = (activeBefore: number | null) => ({
  method: "terminate-job" as const,
  activeBefore,
  settled: "observed-zero-active" as const,
  elapsedMs: 3,
});

const sessionOf = async (h: Harness, id: string): Promise<LiveSession> => {
  const r = await h.run("test", (op) => h.manager.withSession(id, op, "concurrent", async (s) => ok(s)));
  if (!r.ok) throw new Error(r.error._tag);
  return r.value;
};

describe("ownedTargetState", () => {
  it("is killed for a running root, already-exited for an empty job, killed when stragglers were terminated", () => {
    expect(ownedTargetState(false, true, termination(1))).toBe("killed");
    expect(ownedTargetState(true, true, termination(null))).toBe("already-exited");
    expect(ownedTargetState(true, true, termination(0))).toBe("already-exited");
    expect(ownedTargetState(true, true, termination(2))).toBe("killed");
    expect(ownedTargetState(true, false, termination(2))).toBe("already-exited");
    expect(ownedTargetState(false, false, null)).toBe("unknown");
  });
});

describe("close_session after the root exited on its own", () => {
  const exitedSession = async (stragglers: number) => {
    const h = createHarness();
    const spawned = await h.spawn();
    if (!spawned.ok) throw new Error(spawned.error._tag);
    const id = spawned.value.sessionId;
    await h.run("resume_process", (op) => h.manager.resume(id, op), { sessionId: id });
    h.fake.terminate(spawned.value.identity.pid);
    h.jobhost.hostOf(spawned.value.identity.pid)?.exitRoot(0, stragglers);
    await settle();
    await settle();
    expect((await sessionOf(h, id)).state).toBe("exited");
    const session = await sessionOf(h, id);
    const closed = await h.run("close_session", (op) => h.manager.close(id, { force: false }, op), { sessionId: id });
    if (!closed.ok) throw new Error(closed.error._tag);
    const lifecycle = (await hostFactsOf(session)?.lifecycleEffects())?.map((e) => e.kind) ?? [];
    await h.closeAll();
    return { report: closed.value, lifecycle };
  };

  it("a straggler left in the job is killed by the close: killed, with the process-killed effect", async () => {
    const { report, lifecycle } = await exitedSession(1);
    expect(report.targetState).toBe("killed");
    expect(report.termination).toMatchObject({ activeBefore: 1 });
    expect(lifecycle).toContain("process-killed");
  });

  it("an empty job: already-exited and no process-killed effect", async () => {
    const { report, lifecycle } = await exitedSession(0);
    expect(report.targetState).toBe("already-exited");
    expect(lifecycle).not.toContain("process-killed");
  });
});
