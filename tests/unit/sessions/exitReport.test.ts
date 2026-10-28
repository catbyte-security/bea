import { describe, expect, it } from "vitest";

import { hostFactsOf } from "../../../src/application/sessions/hostFacts.js";
import { LIMITATIONS } from "../../../src/domain/evidence/limitations.js";
import { ok } from "../../../src/domain/result.js";
import type { LiveSession } from "../../../src/ports/sessions.js";
import { createHarness, settle, type Harness } from "./support/harness.js";

/**
 * Exit ordering (found by the real-Frida acceptance run): Frida's process-terminated detach arrives a few ms BEFORE the
 * jobhost root-exit that carries the exit code. "process-exit" waits must return with the code (and the crash verdict
 * derivable), not on the detach alone; without any report the session is marked exited after the grace.
 */
const sessionOf = async (h: Harness, id: string): Promise<LiveSession> => {
  const r = await h.run("test", (op) => h.manager.withSession(id, op, "concurrent", async (s) => ok(s)));
  if (!r.ok) throw new Error(r.error._tag);
  return r.value;
};

describe("exit report after Frida's process-terminated detach", () => {
  it("a process-exit wait is satisfied by the jobhost root-exit, so the exit code and crash verdict are known", async () => {
    const h = createHarness();
    const spawned = await h.spawn();
    if (!spawned.ok) throw new Error(spawned.error._tag);
    const id = spawned.value.sessionId;
    const pid = spawned.value.identity.pid;
    await h.run("resume_process", (op) => h.manager.resume(id, op), { sessionId: id });
    const session = await sessionOf(h, id);
    let settled = false;
    const waiting = h
      .run("resume_process", async (op) => ok(await session.waitFor({ kind: "process-exit" }, op, 5_000)), {
        sessionId: id,
      })
      .finally(() => {
        settled = true;
      });

    h.fake.terminate(pid); // the Frida detach first
    await settle();
    await settle();
    expect(settled).toBe(false);
    expect(session.state).toBe("running");

    h.jobhost.hostOf(pid)?.exitRoot(0xc0000005); // then the exit report
    const outcome = await waiting;
    expect(outcome.ok && outcome.value).toMatchObject({ satisfied: true, timedOut: false, state: "exited" });
    const crash = await h.run("x", (op) => session.crash(op));
    expect(crash.ok && crash.value).toMatchObject({ ntstatus: "STATUS_ACCESS_VIOLATION" });
    expect(hostFactsOf(session)?.limitations()).not.toContain(LIMITATIONS.EXIT_REPORT_LATE);
    await h.closeAll();
  });

  it("without an exit report the session is marked exited after the grace, with EXIT_REPORT_LATE", async () => {
    const h = createHarness({ limits: (limits) => ({ ...limits, exitReportGraceMs: 30 }) });
    const spawned = await h.spawn();
    if (!spawned.ok) throw new Error(spawned.error._tag);
    const id = spawned.value.sessionId;
    await h.run("resume_process", (op) => h.manager.resume(id, op), { sessionId: id });
    const session = await sessionOf(h, id);
    const ended: string[] = [];
    h.manager.onSessionEnded((e) => ended.push(e.reason));

    h.fake.terminate(spawned.value.identity.pid);
    const outcome = await h.run(
      "resume_process",
      async (op) => ok(await session.waitFor({ kind: "process-exit" }, op, 5_000)),
      { sessionId: id },
    );
    expect(outcome.ok && outcome.value).toMatchObject({ satisfied: true, state: "exited" });
    expect(hostFactsOf(session)?.limitations()).toContain(LIMITATIONS.EXIT_REPORT_LATE);
    expect(ended).toEqual(["exited"]);
    await h.closeAll();
    expect(ended).toEqual(["exited"]);
  });

  it("a session with no exit source (no jobhost, no watcher) is marked exited on the detach itself", async () => {
    const h = createHarness({ limits: (limits) => ({ ...limits, exitReportGraceMs: 60_000 }) });
    const spawned = await h.spawn();
    if (!spawned.ok) throw new Error(spawned.error._tag);
    const id = spawned.value.sessionId;
    const host = h.jobhost.hostOf(spawned.value.identity.pid);
    if (host === undefined) throw new Error("no jobhost");
    host.state = "helper-lost";
    const session = await sessionOf(h, id);
    h.fake.terminate(spawned.value.identity.pid);
    await settle();
    expect(session.state).toBe("exited");
    await h.closeAll();
  });
});
