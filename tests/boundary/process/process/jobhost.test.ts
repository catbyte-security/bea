import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, readdirSync, rmdirSync, rmSync, statSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import type { Readable } from "node:stream";

import { afterAll, beforeAll, expect, it, vi } from "vitest";

import { resolveDistLayout } from "../../../../src/application/distLayout.js";
import { Deadline } from "../../../../src/domain/deadline.js";
import { jobHostEventSchema, type JobHostEvent } from "../../../../src/domain/jobhostProtocol.js";
import type { JobHostPort } from "../../../../src/ports/jobhost.js";
import { HelperSession, launchHelperProcess } from "../../../../src/providers/process/JobHostSession.js";
import { createJobHostFactory } from "../../../../src/providers/process/createJobHostFactory.js";
import { JobHostService } from "../../../../src/providers/process/JobHostService.js";
import { jobhostSkip, skipNote } from "../../../support/acceptance/fixtures.js";
import { pidStatus } from "../../../support/process/ownedPidLedger.js";
import { testCore } from "../../../unit/process/support/core.js";

/**
 * Process lane (WP2 acceptance): the S3 lab cases of jh-smoke.mjs and jh-fd4.mjs, ported 1:1, against the BUILT
 * bea-jobhost.exe of BEA_DIST_DIR (a snapshot; docs/testing.md) or dist/. Targets are node.exe children this file
 * starts itself; every pid it causes to exist is tracked and reaped in afterAll. Every status line any helper emits
 * passes through jobHostEventSchema (a failing line would terminate the helper and fail the test).
 */
const SKIP = jobhostSkip();
const layout = resolveDistLayout();
const NODE = process.execPath;
const ENV: Record<string, string> = Object.fromEntries(
  ["SystemRoot", "SYSTEMROOT", "TEMP", "TMP", "PATH", "Path"].flatMap((k) => {
    const v = process.env[k];
    return v === undefined ? [] : [[k, v]];
  }),
);

const tracked = new Set<number>();
const alive = (pid: number): boolean => pidStatus(null, pid).alive;
const track = (pid: number | undefined): number => {
  if (pid === undefined || pid === 0) throw new Error("no pid");
  tracked.add(pid);
  return pid;
};

/** A node.exe target the test owns: sleeps until killed. */
const startTarget = (): ChildProcess => {
  const child = spawn(NODE, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore", windowsHide: true });
  track(child.pid);
  return child;
};

let service: JobHostService;
const events: JobHostEvent[] = [];
const record = (port: { on(l: (e: JobHostEvent) => void): () => void }) => port.on((e) => void events.push(e));

beforeAll(async () => {
  service = new JobHostService(await testCore("win32"), {
    exePath: layout.jobhostExe,
    manifestPath: layout.jobhostManifest,
  });
});

afterAll(async () => {
  for (const pid of tracked)
    if (alive(pid))
      try {
        process.kill(pid);
      } catch {
        // already gone
      }
  // every event the wrapper delivered satisfies the protocol schema
  for (const event of events) expect(jobHostEventSchema.safeParse(event).success).toBe(true);
});

const ctOf = async (pid: number): Promise<bigint> => {
  const inspected = await service.inspect(pid, Deadline.after(5000));
  if (!inspected.ok || inspected.value.creationTime100ns === null) throw new Error("inspect failed");
  return inspected.value.creationTime100ns;
};

const adoptTarget = async (): Promise<{ target: ChildProcess; handle: JobHostPort; pid: number }> => {
  const target = startTarget();
  const pid = target.pid ?? 0;
  const result = await service.adopt({
    pid,
    creationTime100ns: await ctOf(pid),
    tolerance100ns: 0n,
    expectImage: NODE,
    expectParentPid: process.pid,
    deadline: Deadline.after(5000),
  });
  if (!result.ok) throw new Error(JSON.stringify(result.error));
  track(result.value.helperPid);
  record(result.value);
  return { target, handle: result.value, pid };
};

const readUntil = (stream: Readable | null, pattern: RegExp): Promise<RegExpExecArray> =>
  new Promise((resolve, reject) => {
    let text = "";
    if (stream === null) return reject(new Error("no stream"));
    const onData = (chunk: Buffer) => {
      text += chunk.toString("utf8");
      const match = pattern.exec(text);
      if (match !== null) {
        stream.off("data", onData);
        resolve(match);
      }
    };
    stream.on("data", onData);
  });

/** Named skip (missing toolchain or build only): JOBHOST_SKIP. */
const lane = (title: string, body: () => Promise<void>) => it.skipIf(SKIP !== false)(`${title}${skipNote(SKIP)}`, body);

lane("probe proves containment; version and status row report protocol 1", async () => {
  const probe = await service.probe(Deadline.after(10_000));
  expect(probe).toMatchObject({
    ok: true,
    value: {
      ok: true,
      jobPolicyVerified: true,
      jobListAttribute: true,
      assignedBeforeFirstInstruction: true,
      adoptAssign: true,
      terminateJob: true,
    },
  });
  expect(service.availability()).toMatchObject({ state: "available", reason: null });
  expect(await service.statusRow()).toEqual({
    id: "jobhost",
    state: "available",
    version: "0.1.0",
    detail: "probe ok",
  });
  const binary = await service.checkBinary(new AbortController().signal);
  expect(binary).toMatchObject({ ok: true, classification: "healthy" });
});

lane("inspect self: identity and refusal facts of the test process; unknown pid → invalid_request", async () => {
  const self = await service.inspect(process.pid, Deadline.after(5000));
  if (!self.ok) throw new Error(JSON.stringify(self.error));
  expect(self.value).toMatchObject({
    pid: process.pid,
    access: "limited+synchronize",
    exited: false,
    sameUser: true,
    wow64: false,
    protected: false,
  });
  expect(self.value.imagePath?.toLowerCase()).toBe(NODE.toLowerCase());
  expect(self.value.creationTime100ns).not.toBeNull();
  expect(self.value.parentPid).toBe(process.ppid);
  const elevation = await service.checkElevation(new AbortController().signal);
  expect(elevation).toMatchObject({ name: "host:elevation", ok: true });
  expect(await service.inspect(0xffff_fff0, Deadline.after(5000))).toMatchObject({
    ok: false,
    error: { _tag: "InputError" },
  });
});

lane("identity refusals happen before assignment and leave the target untouched", async () => {
  const target = startTarget();
  const pid = target.pid ?? 0;
  const ct = await ctOf(pid);
  const base = { pid, tolerance100ns: 0n, expectParentPid: process.pid, deadline: Deadline.after(5000) };
  const refusals = [
    { ...base, creationTime100ns: ct + 5n, expectImage: NODE, detail: "creation-time" },
    { ...base, creationTime100ns: ct, expectImage: "C:\\Windows\\System32\\cmd.exe", detail: "image-path" },
    { ...base, creationTime100ns: ct, expectImage: NODE, expectParentPid: 4, detail: "parent-pid" },
  ];
  for (const { detail, ...req } of refusals) {
    const result = await service.adopt(req);
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "InstanceMismatch", observed: { pid }, diagnostics: { stage: "identity", detail } },
    });
    expect(alive(pid)).toBe(true);
  }
  expect(service.live.owned).toBe(0);
  target.kill();
});

lane(
  "adopt through a junction: the same file is accepted, another file is still refused (review fix LIFE-5)",
  async () => {
    // QueryFullProcessImageNameW reports the reparse-resolved path; the helper compared strings only, so a program reached
    // through a junction (a moved Steam library) was always refused as image-path. A junction needs no privilege.
    const root = mkdtempSync(join(tmpdir(), "bea-jh-jct-"));
    const jct = join(root, "jct");
    symlinkSync(dirname(NODE), jct, "junction");
    try {
      const target = startTarget();
      const pid = target.pid ?? 0;
      const ct = await ctOf(pid);
      const req = { pid, creationTime100ns: ct, tolerance100ns: 0n, expectParentPid: process.pid };
      const other = readdirSync(dirname(NODE)).find(
        (f) => f.toLowerCase() !== basename(NODE).toLowerCase() && statSync(join(dirname(NODE), f)).isFile(),
      );
      if (other === undefined) throw new Error("no other file next to node.exe");
      expect(
        await service.adopt({ ...req, expectImage: join(jct, other), deadline: Deadline.after(5000) }),
      ).toMatchObject({
        ok: false,
        error: {
          _tag: "InstanceMismatch",
          observed: { pid },
          diagnostics: { stage: "identity", detail: "image-path" },
        },
      });
      expect(alive(pid)).toBe(true);
      const result = await service.adopt({
        ...req,
        expectImage: join(jct, basename(NODE)),
        deadline: Deadline.after(5000),
      });
      if (!result.ok) throw new Error(JSON.stringify(result.error));
      track(result.value.helperPid);
      record(result.value);
      expect(result.value.imagePath?.toLowerCase()).toBe(NODE.toLowerCase());
      expect(await result.value.kill("close-session", 2000)).toMatchObject({ active: 0 });
      expect(alive(pid)).toBe(false);
    } finally {
      rmdirSync(jct); // the junction itself, never the directory it points to
      rmSync(root, { recursive: true, force: true });
    }
  },
);

lane("nested-job adopt, then kill(): control kill settles with zero active and the target dies", async () => {
  const { handle, pid } = await adoptTarget();
  expect(handle).toMatchObject({ rootPid: pid, wasInJob: true, state: "contained" });
  expect(handle.policy).toEqual({
    killOnClose: true,
    dieOnUnhandledException: true,
    breakawayAllowed: false,
    memLimitBytes: null,
  });
  expect(handle.imagePath?.toLowerCase()).toBe(NODE.toLowerCase());
  const seen: string[] = [];
  handle.on((e) => void seen.push(e.event));
  const settlement = await handle.kill("close-session", 2000);
  expect(settlement).toMatchObject({ method: "control-kill", observation: "observed-zero-active", active: 0 });
  // proc-* lines come from the completion-port thread and may interleave anywhere (S3 §5.2)
  expect(seen.filter((e) => !e.startsWith("proc-"))).toEqual(["killed", "root-exit", "settled"]);
  expect(handle.rootExit).toMatchObject({ code: 0xbea, byKill: true });
  expect(handle.state).toBe("settled");
  expect(alive(pid)).toBe(false);
});

lane("EOF on the control pipe kills the job (reason eof)", async () => {
  const target = startTarget();
  const pid = target.pid ?? 0;
  const session = new HelperSession({
    binaryPath: layout.jobhostExe,
    mode: "adopt",
    args: [
      "adopt",
      String(pid),
      (await ctOf(pid)).toString(),
      "--expect-image",
      NODE,
      "--expect-parent",
      String(process.pid),
    ],
    spawnMode: null,
    launch: launchHelperProcess,
    systemRoot: ENV["SystemRoot"] ?? "C:\\Windows",
  });
  const seen: JobHostEvent[] = [];
  session.subscribe((e) => void seen.push(e));
  expect((await session.waitDecisive("t", Deadline.after(5000), undefined, { pid })).ok).toBe(true);
  track(session.helperPid);
  session.endControl();
  const exit = await session.finished;
  expect(seen.find((e) => e.event === "killed")).toMatchObject({ reason: "eof", ok: true });
  expect(exit.code).toBe(0xbea);
  expect(session.violation).toBeNull();
  expect(alive(pid)).toBe(false);
});

lane("stragglers outlive the root until kill (spawn mode), then die with the job", async () => {
  const script =
    "const c=require('child_process').spawn(process.execPath,['-e','setTimeout(()=>{},30000)'],{detached:true,stdio:'ignore',windowsHide:true});" +
    "console.log('CHILD '+c.pid);c.unref();";
  const result = await service.spawn({
    exe: NODE,
    args: ["-e", script],
    cwd: process.cwd(),
    env: ENV,
    suspended: false,
    stdin: "nul",
    killOnRootExit: false,
    deadline: Deadline.after(5000),
  });
  if (!result.ok) throw new Error(JSON.stringify(result.error));
  const handle = result.value;
  track(handle.helperPid);
  track(handle.rootPid);
  record(handle);
  handle.stderr?.resume();
  const straggler = track(Number((await readUntil(handle.stdout, /CHILD (\d+)/u))[1]));
  handle.stdout?.resume();
  await vi.waitFor(() => expect(handle.state).toBe("root-exited"), { timeout: 10_000, interval: 25 });
  expect(handle.rootExit).toMatchObject({ code: 0, byKill: false });
  expect(handle.rootExit?.activeAfterRoot).toBeGreaterThanOrEqual(1);
  handle.requestStatus();
  await vi.waitFor(
    () => expect(events.some((e) => e.event === "status" && e.rootAlive === false && e.active >= 1)).toBe(true),
    {
      interval: 25,
    },
  );
  expect(alive(straggler)).toBe(true);
  const settlement = await handle.kill("close-session", 2000);
  expect(settlement).toMatchObject({
    method: "control-kill",
    observation: "observed-zero-active",
    outputComplete: true,
  });
  expect(alive(straggler)).toBe(false);
});

lane("watch never kills: `kill` is refused, EOF ends the watch, the target survives", async () => {
  const target = startTarget();
  const pid = target.pid ?? 0;
  const ct = await ctOf(pid);
  const session = new HelperSession({
    binaryPath: layout.jobhostExe,
    mode: "watch",
    args: ["watch", String(pid), ct.toString()],
    spawnMode: null,
    launch: launchHelperProcess,
    systemRoot: ENV["SystemRoot"] ?? "C:\\Windows",
  });
  const seen: JobHostEvent[] = [];
  session.subscribe((e) => void seen.push(e));
  expect((await session.waitDecisive("t", Deadline.after(5000), undefined, { pid })).ok).toBe(true);
  track(session.helperPid);
  session.sendControl("kill");
  await vi.waitFor(() => expect(seen.some((e) => e.event === "error")).toBe(true), { interval: 25 });
  expect(seen.find((e) => e.event === "error")).toMatchObject({
    stage: "control",
    detail: "kill-not-permitted-in-watch",
  });
  session.endControl();
  expect((await session.finished).code).toBe(0);
  expect(seen.at(-1)).toEqual({ event: "watch-ended", reason: "eof" });
  expect(alive(pid)).toBe(true);

  const watcher = await service.watch({
    pid,
    creationTime100ns: ct,
    tolerance100ns: 0n,
    deadline: Deadline.after(5000),
  });
  if (!watcher.ok) throw new Error(JSON.stringify(watcher.error));
  track(watcher.value.helperPid);
  record(watcher.value);
  await watcher.value.stop();
  expect(await watcher.value.exited).toBeNull();
  expect(alive(pid)).toBe(true);

  const wrong = await service.watch({
    pid,
    creationTime100ns: ct + 50n,
    tolerance100ns: 10n,
    deadline: Deadline.after(5000),
  });
  expect(wrong).toMatchObject({ ok: false, error: { _tag: "InstanceMismatch" } });

  const again = await service.watch({
    pid,
    creationTime100ns: ct,
    tolerance100ns: 0n,
    deadline: Deadline.after(5000),
  });
  if (!again.ok) throw new Error(JSON.stringify(again.error));
  track(again.value.helperPid);
  target.kill(); // the TEST kills its own child; the watcher only observes
  expect(await again.value.exited).toMatchObject({ byKill: false, activeAfterRoot: null });
});

lane("kill while suspended: the root never runs and dies with the job", async () => {
  const result = await service.spawn({
    exe: NODE,
    args: ["-e", "setInterval(() => {}, 1000)"],
    cwd: process.cwd(),
    env: ENV,
    suspended: true,
    stdin: "nul",
    killOnRootExit: false,
    deadline: Deadline.after(5000),
  });
  if (!result.ok) throw new Error(JSON.stringify(result.error));
  const handle = result.value;
  const pid = track(handle.rootPid);
  track(handle.helperPid);
  record(handle);
  handle.stdout?.resume();
  handle.stderr?.resume();
  expect(handle.state).toBe("contained");
  const settlement = await handle.kill("startup-cancelled", 2000);
  expect(settlement).toMatchObject({ method: "control-kill", observation: "observed-zero-active" });
  expect(handle.rootExit).toMatchObject({ code: 0xbea, byKill: true });
  expect(alive(pid)).toBe(false);
});

lane("fd4 stdin: a JSON-lines child under --kill-on-root-exit and a memory limit (the bridge launch)", async () => {
  const result = await service.spawn({
    exe: NODE,
    args: [
      "-e",
      "process.stdin.on('data', d => process.stdout.write('echo:' + d)); process.stdin.on('end', () => process.exit(0));",
    ],
    cwd: process.cwd(),
    env: ENV,
    suspended: false,
    stdin: "pipe",
    killOnRootExit: true,
    memLimitBytes: 268_435_456,
    deadline: Deadline.after(5000),
  });
  if (!result.ok) throw new Error(JSON.stringify(result.error));
  const handle = result.value;
  track(handle.rootPid);
  track(handle.helperPid);
  record(handle);
  expect(handle.policy.memLimitBytes).toBe(268_435_456);
  handle.stderr?.resume();
  const echoed = readUntil(handle.stdout, /echo:(\{.*\})\n/u);
  handle.stdin?.write('{"id":1,"method":"bridge.hello"}\n');
  expect((await echoed)[1]).toBe('{"id":1,"method":"bridge.hello"}');
  handle.stdout?.resume();
  handle.stdin?.end();
  const settlement = await handle.settled;
  expect(handle.rootExit).toMatchObject({ code: 0, byKill: false });
  // conhost.exe may still be in the job when the root exits; --kill-on-root-exit then terminates it (S3 §5.4)
  expect(["natural", "root-exit-policy"]).toContain(settlement.method);
  expect(settlement).toMatchObject({ helperExitCode: 0, active: 0, outputComplete: true });
});

lane("kill() escalation to TerminateProcess(helper) still kills the tree", async () => {
  const { handle, pid } = await adoptTarget();
  const settlement = await handle.kill("server-shutdown", 0);
  expect(settlement.method).toBe("helper-terminated");
  await vi.waitFor(() => expect(alive(pid)).toBe(false), { timeout: 2000, interval: 25 });
  expect(alive(handle.helperPid)).toBe(false);
});

lane("a helper killed from outside (helper-lost): the kernel closes the job and the target dies", async () => {
  const { handle, pid } = await adoptTarget();
  process.kill(handle.helperPid);
  const settlement = await handle.settled;
  expect(handle.state).toBe("helper-lost");
  expect(settlement).toMatchObject({ method: "helper-terminated", observation: "kernel-enforced-unobserved" });
  await vi.waitFor(() => expect(alive(pid)).toBe(false), { timeout: 2000, interval: 25 });
});

lane(
  "server shutdown: the lifecycle backstop kills an owned target and stops a watcher, within the budget",
  async () => {
    const core = await testCore("win32");
    const factory = createJobHostFactory(core, { exePath: layout.jobhostExe, manifestPath: layout.jobhostManifest });
    const owned = startTarget();
    const watched = startTarget();
    const ownedPid = owned.pid ?? 0;
    const watchedPid = watched.pid ?? 0;
    const adopted = await factory.adopt({
      pid: ownedPid,
      creationTime100ns: await ctOf(ownedPid),
      tolerance100ns: 0n,
      expectImage: NODE,
      expectParentPid: process.pid,
      deadline: Deadline.after(5000),
    });
    const watcher = await factory.watch({
      pid: watchedPid,
      creationTime100ns: await ctOf(watchedPid),
      tolerance100ns: 0n,
      deadline: Deadline.after(5000),
    });
    if (!adopted.ok || !watcher.ok) throw new Error("start failed");
    track(adopted.value.helperPid);
    track(watcher.value.helperPid);
    const report = await core.lifecycle.closeAll("test-shutdown");
    expect(report.ok).toBe(true);
    expect(report.elapsed_ms).toBeLessThan(1800);
    expect(await adopted.value.settled).toMatchObject({ method: "control-kill" });
    expect(alive(ownedPid)).toBe(false);
    expect(alive(watchedPid)).toBe(true);
    expect(alive(watcher.value.helperPid)).toBe(false);
    watched.kill();
  },
);

lane("crash safety: a hard-killed owner process takes its helper and the adopted target with it", async () => {
  const target = startTarget();
  const pid = target.pid ?? 0;
  const ct = await ctOf(pid);
  // A stand-in BEA server: launches the helper exactly like JobHostSession (non-detached, fd3 status) and waits.
  const owner = spawn(
    NODE,
    [
      "-e",
      `const { spawn } = require("node:child_process");
       const h = spawn(process.argv[1], ["adopt", process.argv[2], process.argv[3], "--expect-parent", process.argv[4]],
         { stdio: ["pipe", "ignore", "pipe", "pipe"], detached: false, windowsHide: true });
       h.stdio[3].on("data", (d) => { if (String(d).includes('"adopted"')) console.log("ADOPTED " + h.pid); });
       setInterval(() => {}, 1000);`,
      layout.jobhostExe,
      String(pid),
      ct.toString(),
      String(process.pid),
    ],
    { stdio: ["ignore", "pipe", "ignore"], windowsHide: true },
  );
  track(owner.pid);
  const helperPid = track(Number((await readUntil(owner.stdout, /ADOPTED (\d+)/u))[1]));
  expect(alive(pid)).toBe(true);
  owner.kill(); // TerminateProcess: no JS cleanup runs in the owner
  await vi.waitFor(() => expect(alive(helperPid)).toBe(false), { timeout: 3000, interval: 25 });
  await vi.waitFor(() => expect(alive(pid)).toBe(false), { timeout: 3000, interval: 25 });
});

lane("leaves no helper or target behind", async () => {
  expect(service.live).toEqual({ owned: 0, watchers: 0 });
  await vi.waitFor(() => expect([...tracked].filter(alive)).toEqual([]), { timeout: 3000, interval: 50 });
});
