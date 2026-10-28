import { describe, expect, it } from "vitest";

import { addForeign, createHarness, errTag, settle } from "./support/harness.js";

/**
 * S3 §21 fast-lane case 11: liveness never comes from a pid-filtered `enumerateProcesses` (the jobhost/watcher
 * report exits; a metadata listing is only used for names and spawn timestamps). The narrow port type has no `pids`
 * field and the module-boundary lint bans the call shape; this spy checks the behaviour over a whole lifecycle:
 * spawn, resume, attach by pid and by name, a target exit, close and closeAll.
 */
const hasPids = (options: unknown): boolean =>
  typeof options === "object" && options !== null && Object.hasOwn(options, "pids");

describe("liveness (S3 §21 case 11)", () => {
  it("never calls enumerateProcesses with a pid filter during a full lifecycle", async () => {
    const h = createHarness();
    const spawned = await h.spawn();
    if (!spawned.ok) throw new Error(spawned.error._tag);
    const id = spawned.value.sessionId;
    expect(errTag(await h.run("resume_process", (op) => h.manager.resume(id, op), { sessionId: id }))).toBe("ok");
    addForeign(h, 7400);
    addForeign(h, 7401, "unique_target.exe");
    expect(errTag(await h.attach(7400))).toBe("ok");
    // attach_process {name} resolves through the metadata listing (the handler), then attaches by pid
    const listed = await h.run("list_processes", (op) => h.manager.processes(op));
    if (!listed.ok) throw new Error(listed.error._tag);
    const named = listed.value.filter((p) => p.name.toLowerCase() === "unique_target.exe");
    expect(named.map((p) => p.pid)).toEqual([7401]);
    expect(errTag(await h.attach(named[0]?.pid ?? 0))).toBe("ok");
    h.fake.terminate(spawned.value.identity.pid);
    h.jobhost.hostOf(spawned.value.identity.pid)?.exitRoot(0);
    await settle();
    const closed = await h.run("close_session", (op) => h.manager.close(id, { force: false }, op), { sessionId: id });
    expect(errTag(closed)).toBe("ok");
    await h.closeAll();
    expect(h.fake.enumerateOptions.length).toBeGreaterThan(0);
    expect(h.fake.enumerateOptions.filter(hasPids)).toEqual([]);
  });
});
