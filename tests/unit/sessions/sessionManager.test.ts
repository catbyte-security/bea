import { describe, expect, it, vi } from "vitest";

import { hostFactsOf } from "../../../src/application/sessions/hostFacts.js";
import { Deadline } from "../../../src/domain/deadline.js";
import { LIMITATIONS } from "../../../src/domain/evidence/limitations.js";
import { ok } from "../../../src/domain/result.js";
import type { LiveSession } from "../../../src/ports/sessions.js";
import { addForeign, createHarness, errTag, PROGRAM, settle, type Harness } from "./support/harness.js";

/** S3 §21 fast lane over fakes: spawn/attach/resume/close/closeAll, capacity, admission, crash, jobs, scripts. */
const sessionOf = async (h: Harness, id: string): Promise<LiveSession> => {
  const r = await h.run("test", (op) => h.manager.withSession(id, op, "concurrent", async (s) => ok(s)));
  if (!r.ok) throw new Error(r.error._tag);
  return r.value;
};

describe("spawn (Path 1, owned)", () => {
  it("spawns paused inside the job, injects, registers the instance and binds the built-in recordings", async () => {
    const h = createHarness();
    const spawned = await h.spawn({ argv: ["--frames", "10"], env: { GAME_MODE: "1", BEA_SECRET: "x" } });
    expect(errTag(spawned)).toBe("ok");
    if (!spawned.ok) return;
    const obs = spawned.value;
    expect(obs.state).toBe("paused");
    expect(obs.ownership).toBe("owned");
    expect(obs.containment).toMatchObject({
      kind: "win32-job",
      killOnClose: true,
      assignedBeforeResume: true,
      crashSafe: true,
    });
    expect(obs.identity.startTime.source).toBe("os-creation-time");
    expect(obs.identity.image).toMatchObject({ path: PROGRAM, sha256: "ab".repeat(32), preferredBase: "0x140000000" });
    expect(obs.builtinRecordings).toHaveLength(3);
    expect([...h.recordings.all.values()].map((r) => r.create.kind).sort()).toEqual([
      "exceptions",
      "modules",
      "output",
    ]);
    expect(obs.environment).toMatchObject({ mode: "allowlist", allowlistVersion: 1, callerKeys: 1 });
    // the target environment: allowlist + caller env, BEA_* stripped, a non-allowlisted server secret withheld
    const target = [...h.fake.processes.values()].find((p) => p.spec.path === PROGRAM);
    expect(target?.env).toMatchObject({ SystemRoot: "C:\\Windows", PATH: "C:\\Windows", GAME_MODE: "1" });
    expect(target?.env).not.toHaveProperty("SECRET_TOKEN");
    expect(Object.keys(target?.env ?? {}).some((k) => k.startsWith("BEA_"))).toBe(false);
    expect(obs.limitations).toContain(LIMITATIONS.ENV_ALLOWLIST(2));
    expect(obs.limitations).toContain(LIMITATIONS.AGENT_FOOTPRINT);
    expect(obs.limitations).toContain(LIMITATIONS.STDIN_EMPTY_PIPE);
    // LIFE-4: adoption comes first (identity: the program and the node pid as parent); the creation time is
    // cross-checked against Frida's metadata after assignment
    expect(h.jobhost.adoptRequests[0]).toMatchObject({
      creationTime100ns: 0n,
      expectImage: PROGRAM,
      expectParentPid: process.pid,
    });
    const steps = obs.startup.steps.map((s) => s.step);
    expect(steps.indexOf("adopt")).toBeLessThan(steps.indexOf("metadata"));
    // the agent got hello with max_instruments 16 and call_function enabled for an owned target
    const script = h.fake.agentScript(obs.identity.pid);
    expect(script?.defaultLogUsed).toBe(false);
    // lifecycle effects through the sink
    const session = await sessionOf(h, obs.sessionId);
    const lifecycle = await hostFactsOf(session)?.lifecycleEffects();
    expect(lifecycle?.map((e) => e.kind).sort()).toEqual(["agent-injected", "process-spawned", "process-suspended"]);
    expect(h.manager.kindOf(obs.sessionId)).toBe("live");
    expect(h.manager.list()).toHaveLength(1);
    await h.closeAll();
  });

  it("refuses interpreters/LOLBins, batch files, relative paths and 32-bit images before anything starts", async () => {
    const h = createHarness();
    expect(errTag(await h.spawn({ program: "C:\\Windows\\System32\\cmd.exe" }))).toBe("AccessDenied");
    expect(errTag(await h.spawn({ program: "C:\\tools\\run.bat" }))).toBe("InputError");
    expect(errTag(await h.spawn({ program: "game.exe" }))).toBe("InputError");
    h.pe.set("C:\\x86\\old.exe", {
      ok: false,
      error: { _tag: "UnsupportedTarget", operation: "spawn_process", reason: "wow64" },
    });
    expect(errTag(await h.spawn({ program: "C:\\x86\\old.exe" }))).toBe("UnsupportedTarget");
    expect(h.fake.log.filter((l) => l.startsWith("spawn"))).toEqual([]);
    const allowed = createHarness({ policy: { allowInterpreters: true } });
    expect(errTag(await allowed.spawn({ program: "C:\\Windows\\System32\\cmd.exe" }))).toBe("ok");
    await allowed.closeAll();
  });

  it("refuses conhost, system-directory images and renamed interpreters; allowed_programs lifts it (SEC-1)", async () => {
    const h = createHarness();
    const conhost = await h.spawn({
      program: "C:\\Windows\\System32\\conhost.exe",
      argv: ["--headless", "C:\\Windows\\System32\\cmd.exe", "/c", "calc"],
    });
    expect(errTag(conhost)).toBe("AccessDenied");
    const system = await h.spawn({ program: "C:\\Windows\\System32\\whoami.exe" });
    expect(errTag(system)).toBe("AccessDenied");
    if (!system.ok) expect(system.error.diagnostics).toEqual({ rule: "location", location: "system-root" });
    // a renamed copy of cmd.exe: the version resource still names it
    const renamedCmd = ok({
      machine: 0x8664,
      imageBase: "0x140000000" as const,
      sizeOfImage: 0x40000,
      timeDateStamp: 1,
      fileSize: 4096,
      imports: [],
      importsComplete: true,
      versionNames: ["Cmd.Exe.MUI", "cmd"],
    });
    h.pe.set("C:\\Temp\\x.exe", renamedCmd);
    const renamed = await h.spawn({ program: "C:\\Temp\\x.exe" });
    expect(errTag(renamed)).toBe("AccessDenied");
    if (!renamed.ok) expect(renamed.error.diagnostics).toEqual({ rule: "version-info" });
    expect(h.fake.log.filter((l) => l.startsWith("spawn"))).toEqual([]);
    // the harness hashes every image to ab…ab: listing that digest allows the renamed copy
    const listed = createHarness({
      policy: { allowedPrograms: ["C:\\Windows\\System32\\whoami.exe", "ab".repeat(32)] },
    });
    expect(errTag(await listed.spawn({ program: "C:\\Windows\\System32\\whoami.exe" }))).toBe("ok");
    listed.pe.set("C:\\Temp\\x.exe", renamedCmd);
    expect(errTag(await listed.spawn({ program: "C:\\Temp\\x.exe" }))).toBe("ok");
    await listed.closeAll();
  });
});

describe("spawn preflight and identity (Path 1)", () => {
  it("refuses anti-cheat signals of the target and honours the user's overrides", async () => {
    const h = createHarness();
    h.neighbourhood.set(PROGRAM, ["game_sim.exe", "EasyAntiCheat"]);
    const refused = await h.spawn();
    expect(errTag(refused)).toBe("AccessDenied");
    if (!refused.ok) expect(refused.error.diagnostics?.["signals"]).toEqual(["dir:EasyAntiCheat"]);
    const byImage = createHarness({ policy: { allowAntiCheatImages: ["AB".repeat(32)] } });
    byImage.neighbourhood.set(PROGRAM, ["EasyAntiCheat"]);
    const allowed = await byImage.spawn();
    expect(errTag(allowed)).toBe("ok");
    if (allowed.ok) {
      expect(allowed.value.antiCheatSignals).toEqual(["dir:EasyAntiCheat"]);
      expect(allowed.value.limitations).toContain(LIMITATIONS.ANTI_CHEAT_ALLOWED);
    }
    await byImage.closeAll();
  });

  it("notes a machine-wide anti-cheat process without refusing the target", async () => {
    const h = createHarness();
    h.fake.addProcess({ pid: 50, name: "vgc.exe", path: "C:\\Program Files\\Riot Vanguard\\vgc.exe" });
    const spawned = await h.spawn();
    expect(errTag(spawned)).toBe("ok");
    if (spawned.ok) expect(spawned.value.limitations).toContain(LIMITATIONS.ANTI_CHEAT_GLOBAL_PRESENT);
    expect(h.manager.machineWideAntiCheat).toEqual(["vgc.exe"]);
    await h.closeAll();
  });

  it("refuses a UNC, relative or network-resolving cwd before spawning (SEC-2)", async () => {
    const h = createHarness();
    for (const cwd of ["\\\\host\\share\\dir", "//host/share", "relative\\dir", "C:dir"]) {
      const refused = await h.spawn({ cwd });
      expect(errTag(refused), cwd).toBe("InputError");
    }
    expect(h.fake.log.filter((l) => l.startsWith("spawn"))).toEqual([]);
    const ok = await h.spawn({ cwd: "C:\\fixtures" });
    expect(errTag(ok)).toBe("ok");
    await h.closeAll();
    // a drive path that resolves to a share (mapped drive, junction) is refused too
    const network = createHarness({ inspectDirectory: async () => "network" });
    const mapped = await network.spawn({ cwd: "Z:\\builds" });
    expect(!mapped.ok && mapped.error).toMatchObject({ _tag: "AccessDenied", reason: "policy" });
    const missing = createHarness({ inspectDirectory: async () => "missing" });
    expect(errTag(await missing.spawn({ cwd: "C:\\nope" }))).toBe("InputError");
  });

  it("reads the anti-cheat neighbourhood around the real path and refuses a program on a share (LIFE-5)", async () => {
    // C:\j is a junction straight to the game's Binaries\Win64: EasyAntiCheat sits beside Binaries in the real tree
    const real = "D:\\Games\\X\\Binaries\\Win64\\game_sim.exe";
    const h = createHarness({ realPath: async (path) => (path === "C:\\j\\game_sim.exe" ? real : path) });
    h.neighbourhood.set(real, ["game_sim.exe", "EasyAntiCheat"]);
    const refused = await h.spawn({ program: "C:\\j\\game_sim.exe" });
    expect(!refused.ok && refused.error).toMatchObject({ _tag: "AccessDenied", reason: "anti-cheat-detected" });
    const share = createHarness({ realPath: async () => "\\\\server\\games\\game_sim.exe" });
    const network = await share.spawn({ program: "Z:\\game_sim.exe" });
    expect(!network.ok && network.error).toMatchObject({
      _tag: "AccessDenied",
      reason: "policy",
      diagnostics: { field: "program" },
    });
    expect([...h.fake.log, ...share.fake.log].filter((l) => l.startsWith("spawn"))).toEqual([]);
  });

  it("adopts before the metadata listing and kills the job when the creation times disagree (LIFE-4)", async () => {
    const h = createHarness();
    h.jobhost.creationSkew100ns = 10_000_000n; // one second
    const result = await h.spawn();
    expect(errTag(result)).toBe("InstanceMismatch");
    const pid = [...h.fake.processes.keys()].at(-1) ?? 0;
    expect(h.fake.process(pid)?.alive).toBe(false);
    expect(h.jobhost.hostOf(pid)?.killReasons.length).toBeGreaterThan(0);
    expect(h.manager.list()).toHaveLength(0);
    await h.closeAll();
  });

  it("checks expect_sha256 before spawning", async () => {
    const h = createHarness();
    const wrong = await h.spawn({ expectSha256: "cd".repeat(32) });
    expect(errTag(wrong)).toBe("InstanceMismatch");
    expect(h.fake.log.some((l) => l.startsWith("spawned"))).toBe(false);
    expect(errTag(await h.spawn({ expectSha256: "ab".repeat(32) }))).toBe("ok");
    await h.closeAll();
  });

  it("refuses a 5th live session and a 4th piped target with the capacity error; capture_output:false spawns beyond", async () => {
    const h = createHarness();
    for (let i = 0; i < 3; i += 1) expect(errTag(await h.spawn())).toBe("ok");
    const fourthPiped = await h.spawn();
    expect(errTag(fourthPiped)).toBe("ResourceConstraint");
    if (!fourthPiped.ok) expect(fourthPiped.error.message).toContain("At most 3 targets can capture output");
    expect(errTag(await h.spawn({ captureOutput: false }))).toBe("ok");
    const fifth = await h.spawn({ captureOutput: false });
    expect(errTag(fifth)).toBe("ResourceConstraint");
    if (!fifth.ok) {
      expect(fifth.error.message).toContain("BEA already has 4 live sessions");
      expect(fifth.error.message).toContain("This release has no runtime override.");
    }
    await h.closeAll();
  });

  it("does not overshoot capacity when startups race (reservations are synchronous)", async () => {
    const h = createHarness({ maxLiveSessions: 2 });
    const gate = h.fake.hold("attach");
    const racing = [
      h.spawn({ captureOutput: false }),
      h.spawn({ captureOutput: false }),
      h.spawn({ captureOutput: false }),
    ];
    await gate.entered;
    gate.release();
    const results = await Promise.all(racing);
    expect(results.map(errTag).sort()).toEqual(["ResourceConstraint", "ok", "ok"]);
    await h.closeAll();
  });
});

describe("startup cleanup (S3 §8.3)", () => {
  it.each(["adopt", "attach", "createScript", "load", "rpc:hello", "rpc:listModules"])(
    "a cancel while held at %s kills the owned root and leaves no session",
    async (step) => {
      const h = createHarness();
      const gate = h.fake.hold(step);
      const controller = new AbortController();
      const pending = h.spawn({}, { signal: controller.signal });
      await gate.entered;
      controller.abort();
      gate.release();
      const result = await pending;
      expect(errTag(result)).toMatch(/Cancelled|CapabilityUnavailable/u);
      const pid = [...h.fake.processes.keys()].at(-1) ?? 0;
      expect(h.fake.process(pid)?.alive).toBe(false);
      expect(h.manager.list()).toHaveLength(0);
      expect(h.manager.ownedTargets()).toHaveLength(0);
      await h.closeAll();
    },
  );

  it("a spawn guard expiry returns provider_timeout and kills the pid when the spawn resolves later", async () => {
    const h = createHarness({ limits: (l) => ({ ...l, startup: { ...l.startup, spawnGuardMs: 30 } }) });
    const gate = h.fake.hold("spawn");
    const pending = h.spawn();
    await gate.entered;
    const timedOut = await pending;
    expect(errTag(timedOut)).toBe("ProviderTimeout");
    gate.release();
    await settle();
    await settle();
    const pid = [...h.fake.processes.keys()].at(-1) ?? 0;
    expect(h.fake.log).toContain(`frida.kill:${String(pid)}`);
    expect(h.fake.process(pid)?.alive).toBe(false);
  });

  it("an attach startup failure unloads and detaches but never kills the attached process", async () => {
    const h = createHarness();
    addForeign(h, 7000);
    h.fake.behaviors.set(7000, { ready: false });
    const result = await h.attach(7000);
    expect(errTag(result)).toBe("ProviderTimeout");
    expect(h.fake.process(7000)?.alive).toBe(true);
    expect(h.fake.log.some((l) => l.startsWith("frida.kill") || l.startsWith("jobhost.kill"))).toBe(false);
    expect(h.fake.log).toContain("unload:7000");
    expect(h.fake.log).toContain("detach:7000");
  }, 10_000);

  it("a load-time agent error fails the startup with a curated message (no agent text)", async () => {
    const h = createHarness();
    h.fake.defaultBehavior = { loadError: "ReferenceError: target-controlled text" };
    const result = await h.spawn();
    expect(errTag(result)).toBe("ProviderFailure");
    if (!result.ok) expect(JSON.stringify(result.error)).not.toContain("target-controlled");
  });
});

describe("attach", () => {
  it("attaches by pid: running, watcher containment, never killable", async () => {
    const h = createHarness();
    addForeign(h, 7100);
    const attached = await h.attach(7100);
    expect(errTag(attached)).toBe("ok");
    if (!attached.ok) return;
    expect(attached.value.state).toBe("running");
    expect(attached.value.containment).toMatchObject({ kind: "none", killOnClose: false, crashSafe: false });
    expect(attached.value.environment).toBeNull();
    expect(attached.value.limitations).toContain(LIMITATIONS.AGENT_FOOTPRINT);
    const closed = await h.run(
      "close_session",
      (op) => h.manager.close(attached.value.sessionId, { force: false }, op),
      {
        sessionId: attached.value.sessionId,
      },
    );
    expect(errTag(closed)).toBe("ok");
    if (closed.ok) expect(closed.value.targetState).toBe("alive-detached");
    expect(h.fake.process(7100)?.alive).toBe(true);
    expect(h.jobhost.watcherOf(7100)?.stopped).toBe(true);
  });

  it("refuses a second session on the same pid, BEA's own tree and anti-cheat ancestry", async () => {
    const h = createHarness();
    addForeign(h, 7200);
    expect(errTag(await h.attach(7200))).toBe("ok");
    expect(errTag(await h.attach(7200))).toBe("InputError");
    expect(errTag(await h.attach(process.pid))).toBe("AccessDenied");
    h.fake.addProcess({ pid: 7300, name: "vgc.exe", path: "C:\\vgc.exe", ppid: 1 });
    addForeign(h, 7301, "shooter.exe", { ppid: 7300 });
    const refused = await h.attach(7301);
    expect(errTag(refused)).toBe("AccessDenied");
    if (!refused.ok) expect(refused.error.diagnostics?.["signals"]).toEqual(["ancestor:vgc.exe"]);
    await h.closeAll();
    expect(h.fake.process(7200)?.alive).toBe(true);
  });

  it("refuses anti-cheat modules found in the live module list after injection, without killing", async () => {
    const h = createHarness();
    addForeign(h, 7400);
    h.fake.behaviors.set(7400, {
      rpc: {
        listModules: (_p, script) => ({
          ok: true,
          value: {
            module_map_epoch: 1,
            modules: [
              h.fake.mainModule(script.pid),
              {
                name: "BEClient_x64.dll",
                path: "C:\\g\\BEClient_x64.dll",
                base: "0x7ff800000000",
                size: 4096,
                pe: null,
              },
            ],
          },
        }),
      },
    });
    const refused = await h.attach(7400);
    expect(errTag(refused)).toBe("AccessDenied");
    expect(h.fake.process(7400)?.alive).toBe(true);
    expect(h.fake.log).toContain("detach:7400");
  });
});

describe("resume, exit and crash", () => {
  it("resume posts {type:resumed}, starts recording clocks, records process-resumed and reverts process-suspended", async () => {
    const h = createHarness();
    const spawned = await h.spawn();
    if (!spawned.ok) throw new Error(spawned.error._tag);
    const id = spawned.value.sessionId;
    const resumed = await h.run("resume_process", (op) => h.manager.resume(id, op), { sessionId: id });
    expect(errTag(resumed)).toBe("ok");
    const script = h.fake.agentScript(spawned.value.identity.pid);
    expect(script?.posts).toContainEqual({ type: "resumed" });
    expect(h.recordings.resumed).toEqual([id]);
    await h.sink.settle(id);
    expect(h.evidence.effectsOfKind("process-resumed")).toHaveLength(1);
    expect(h.evidence.effectsOfKind("process-suspended")[0]?.status).toBe("reverted");
    const again = await h.run("resume_process", (op) => h.manager.resume(id, op), { sessionId: id });
    expect(errTag(again)).toBe("InvalidState");
    await h.closeAll();
  });

  it("refuses resume of an attached target with invalid_state", async () => {
    const h = createHarness();
    addForeign(h, 7500);
    const attached = await h.attach(7500);
    if (!attached.ok) throw new Error(attached.error._tag);
    const id = attached.value.sessionId;
    expect(errTag(await h.run("resume_process", (op) => h.manager.resume(id, op), { sessionId: id }))).toBe(
      "InvalidState",
    );
    await h.closeAll();
  });

  it("a crash: the report is recorded before exactly one ack, the root exit derives a CrashReport", async () => {
    const h = createHarness();
    const spawned = await h.spawn();
    if (!spawned.ok) throw new Error(spawned.error._tag);
    const pid = spawned.value.identity.pid;
    const id = spawned.value.sessionId;
    const script = h.fake.agentScript(pid);
    script?.emitPayload({
      bea: "crash",
      ack: "crash-1",
      report: {
        report_id: "r1",
        phase: "first-chance",
        g: 5,
        t: 100,
        tid: 12,
        type: "access-violation",
        code: null,
        address: "0x7ff6a0001650",
        memory: { operation: "write", address: "0x0" },
        exception_information: [],
        registers: { rax: "0x0", rip: "0x7ff6a0001650" },
        eflags: null,
        mxcsr: null,
        fpcw: null,
        xmm: null,
        instruction: { address: "0x7ff6a0001650", bytes: "c70000000000", text: "mov dword ptr [rax], 0" },
        backtrace: [{ va: "0x7ff6a0001650", module: "game_sim.exe", rva: "0x1650" }],
        backtrace_source: "exception-context",
        stack: null,
        module_map_epoch: 1,
        flushed: { streams: 1, rows: 3 },
      },
    });
    await settle();
    await settle();
    expect(script?.posts.filter((p) => JSON.stringify(p).includes("crash-1"))).toEqual([
      { type: "ack", token: "crash-1" },
    ]);
    expect(h.evidence.records.some((r) => r.predicate_type === "bea.exception.report")).toBe(true);
    h.jobhost.hostOf(pid)?.exitRoot(0xc0000005);
    const session = await sessionOf(h, id);
    expect(session.state).toBe("exited");
    const crash = await h.run("session_status", (op) => session.crash(op), { sessionId: id });
    expect(errTag(crash)).toBe("ok");
    if (crash.ok) {
      expect(crash.value).toMatchObject({
        type: "access-violation",
        ntstatus: "STATUS_ACCESS_VIOLATION",
        thread_id: 12,
      });
      expect(crash.value?.pc).toMatchObject({ va: "0x7ff6a0001650", at: "game_sim.exe+0x1650" });
      expect(crash.value?.evidence_id).toMatch(/^ev_/u);
    }
    const again = await h.run("session_status", (op) => session.crash(op), { sessionId: id });
    if (again.ok && crash.ok) expect(again.value?.evidence_id).toBe(crash.value?.evidence_id);
    expect(h.evidence.records.filter((r) => r.predicate_type === "bea.process.crash")).toHaveLength(1);
    await h.closeAll();
  });

  it("an error exit without a report derives pc:null with CRASH_PC_UNKNOWN", async () => {
    const h = createHarness();
    const spawned = await h.spawn();
    if (!spawned.ok) throw new Error(spawned.error._tag);
    h.jobhost.hostOf(spawned.value.identity.pid)?.exitRoot(0xc0000409);
    const session = await sessionOf(h, spawned.value.sessionId);
    const crash = await h.run("x", (op) => session.crash(op));
    expect(crash.ok && crash.value).toMatchObject({
      type: "fast-fail",
      pc: null,
      ntstatus: "STATUS_STACK_BUFFER_OVERRUN",
    });
    expect(hostFactsOf(session)?.limitations()).toContain(LIMITATIONS.CRASH_PC_UNKNOWN);
    await h.closeAll();
  });

  it("an RPC pending when the process terminates answers target_exited; a connection loss answers agent-gone", async () => {
    const h = createHarness();
    const spawned = await h.spawn();
    if (!spawned.ok) throw new Error(spawned.error._tag);
    const id = spawned.value.sessionId;
    h.fake.hold("rpc:ping");
    const pending = h.run(
      "t",
      (op) => h.manager.withSession(id, op, "exclusive", (s) => s.agent.call("ping", {}, { op })),
      { sessionId: id },
    );
    await settle();
    h.jobhost.hostOf(spawned.value.identity.pid)?.exitRoot(0xc0000005);
    expect(errTag(await pending)).toBe("TargetExited");

    const h2 = createHarness();
    addForeign(h2, 7600);
    const attached = await h2.attach(7600);
    if (!attached.ok) throw new Error(attached.error._tag);
    h2.fake.hold("rpc:ping");
    const id2 = attached.value.sessionId;
    const pending2 = h2.run(
      "t",
      (op) => h2.manager.withSession(id2, op, "exclusive", (s) => s.agent.call("ping", {}, { op })),
      { sessionId: id2 },
    );
    await settle();
    h2.fake.sessionsOf(7600)[0]?.markDetached("connection-terminated");
    const lost = await pending2;
    expect(errTag(lost)).toBe("CapabilityUnavailable");
    if (!lost.ok && lost.error._tag === "CapabilityUnavailable") expect(lost.error.reason).toBe("agent-gone");
    const session = await sessionOf(h2, id2);
    expect(session.state).toBe("detached");
    await h.closeAll();
    await h2.closeAll();
  });
});

describe("close and closeAll", () => {
  it("close_session (owned) kills the job first, finalizes streams with manifests and tombstones the session", async () => {
    const h = createHarness();
    const spawned = await h.spawn();
    if (!spawned.ok) throw new Error(spawned.error._tag);
    const id = spawned.value.sessionId;
    const ended: string[] = [];
    h.manager.onSessionEnded((e) => ended.push(`${e.sessionId}:${e.reason}`));
    const closed = await h.run("close_session", (op) => h.manager.close(id, { force: false }, op), { sessionId: id });
    expect(errTag(closed)).toBe("ok");
    if (!closed.ok) return;
    expect(closed.value.targetState).toBe("killed");
    expect(closed.value.termination).toMatchObject({ method: "terminate-job", settled: "observed-zero-active" });
    expect(h.fake.log.indexOf(`jobhost.kill:${String(spawned.value.identity.pid)}`)).toBeGreaterThan(-1);
    expect(h.evidence.writers.every((w) => w.endReason === "process-killed")).toBe(true);
    expect(h.manager.kindOf(id)).toBe("closed");
    expect(ended).toEqual([`${id}:closed`]);
    const tomb = await sessionOf(h, id);
    expect(tomb.state).toBe("closed");
    expect(hostFactsOf(tomb)?.manifests()).toHaveLength(4);
    const lifecycle = await hostFactsOf(tomb)?.lifecycleEffects();
    expect(lifecycle?.map((e) => e.kind)).toContain("process-killed");
    const again = await h.run("close_session", (op) => h.manager.close(id, { force: false }, op), { sessionId: id });
    expect(errTag(again)).toBe("ok");
    expect(ended).toHaveLength(1);
    // only the device.output handler stays connected until FridaHost.close (release-frida)
    expect(h.fake.signals.connected - h.fake.signals.disconnected).toBe(1);
  });

  it("an attached close keeps the session cleanup_pending when the agent cannot revert, and force detaches", async () => {
    const h = createHarness();
    addForeign(h, 7700);
    h.fake.behaviors.set(7700, {
      rpc: {
        shutdown: () => ({
          ok: true,
          value: {
            stopped: [],
            unreverted: [{ id: "w1", detail: "dr7 still set" }],
            scans_freed: 0,
            jobs_cancelled: 0,
            final_batches: 0,
          },
        }),
      },
    });
    const attached = await h.attach(7700);
    if (!attached.ok) throw new Error(attached.error._tag);
    const id = attached.value.sessionId;
    const refused = await h.run("close_session", (op) => h.manager.close(id, { force: false }, op), { sessionId: id });
    expect(errTag(refused)).toBe("EffectUnreverted");
    expect(h.manager.kindOf(id)).toBe("live");
    expect((await sessionOf(h, id)).state).toBe("cleanup_pending");
    expect(h.fake.log).not.toContain("unload:7700");
    const forced = await h.run("close_session", (op) => h.manager.close(id, { force: true }, op), { sessionId: id });
    expect(errTag(forced)).toBe("ok");
    expect(h.fake.log).toContain("unload:7700");
    expect(h.fake.process(7700)?.alive).toBe(true);
  });

  it("an unresponsive agent: close says a retry cannot help; force reports the agent left loaded (LIFE-8)", async () => {
    const h = createHarness({
      limits: (l) => ({
        ...l,
        health: { pingTimeoutMs: 50, pingIntervalMs: 0 },
        closeSession: { ...l.closeSession, revertMs: 100, unloadMs: 100 },
      }),
    });
    addForeign(h, 7710);
    const attached = await h.attach(7710);
    if (!attached.ok) throw new Error(attached.error._tag);
    const id = attached.value.sessionId;
    // a call that never returns holds the agent's thread: every RPC hangs from now on, and the unload fails
    const never = (): Promise<never> => new Promise<never>(() => undefined);
    h.fake.behaviors.set(7710, { rpc: { ping: never, shutdown: never, readMemory: never } });
    h.fake.fail("unload", new Error("unload timed out"));
    const session = await sessionOf(h, id);
    const timedOut = await h.run("read_memory", (op) =>
      session.agent.call("readMemory", { address: "0x1000", size: 4 } as never, { op, timeoutMs: 50 }),
    );
    expect(errTag(timedOut)).toBe("ProviderTimeout");
    await vi.waitFor(() => expect(session.agent.health.state).toBe("unresponsive"), { interval: 10, timeout: 2000 });
    const refused = await h.run("close_session", (op) => h.manager.close(id, { force: false }, op), { sessionId: id });
    expect(!refused.ok && refused.error).toMatchObject({
      _tag: "EffectUnreverted",
      diagnostics: { reason: "agent-unresponsive" },
      remediation: expect.stringMatching(/A retry cannot succeed/u),
    });
    const forced = await h.run("close_session", (op) => h.manager.close(id, { force: true }, op), { sessionId: id });
    if (!forced.ok) throw new Error(forced.error._tag);
    expect(forced.value).toMatchObject({
      agentUnloaded: false,
      cleanup: { status: "incomplete", resources: ["agent:pid:7710"] },
    });
    expect(forced.value.limitations).toContain(LIMITATIONS.AGENT_LEFT_LOADED);
    expect(h.fake.process(7710)?.alive).toBe(true);
  });

  it("closeAll kills every owned job before the first attached unload, closes the device manager last, disconnects everything", async () => {
    const h = createHarness();
    for (let i = 0; i < 3; i += 1) await h.spawn();
    addForeign(h, 7800);
    await h.attach(7800);
    const closed = await h.closeAll();
    expect(errTag(closed)).toBe("ok");
    if (closed.ok) {
      expect(closed.value.owned).toHaveLength(3);
      expect(closed.value.attached).toHaveLength(1);
      expect(closed.value.failures).toEqual([]);
    }
    const kills = h.fake.log.map((l, i) => (l.startsWith("jobhost.kill") ? i : -1)).filter((i) => i >= 0);
    const unload = h.fake.log.indexOf("unload:7800");
    expect(kills).toHaveLength(3);
    expect(Math.max(...kills)).toBeLessThan(unload);
    const released = await h.host.close(Deadline.after(250));
    expect(errTag(released)).toBe("ok");
    expect(h.fake.log.at(-1)).toBe("dm.close");
    expect(h.fake.signals.connected).toBe(h.fake.signals.disconnected);
    expect(h.fake.process(7800)?.alive).toBe(true);
    expect(h.manager.list()).toHaveLength(0);
    expect(errTag(await h.spawn())).toBe("CapabilityUnavailable");
  });

  it("closeAll keeps a failed owner for a retry: the second run covers only it, the third is a no-op", async () => {
    const h = createHarness();
    const a = await h.spawn();
    const b = await h.spawn();
    if (!a.ok || !b.ok) throw new Error("spawn failed");
    const stuck = h.jobhost.hostOf(b.value.identity.pid);
    if (stuck !== undefined) stuck.stuck = true;
    const first = await h.closeAll();
    expect(first.ok && first.value.failures.length).toBe(1);
    if (stuck !== undefined) stuck.stuck = false;
    const second = await h.closeAll();
    expect(second.ok && second.value.owned.map((o) => o.sessionId)).toEqual([b.value.sessionId]);
    const killsBefore = h.fake.log.filter((l) => l.startsWith("jobhost.kill")).length;
    const third = await h.closeAll();
    // memoized after a clean run: the same report, no new work
    expect(third).toBe(second);
    expect(h.fake.log.filter((l) => l.startsWith("jobhost.kill")).length).toBe(killsBefore);
    expect(h.manager.ownedTargets()).toEqual([]);
  }, 10_000);
});

describe("close and closeAll: startups in flight", () => {
  it.each(["createScript", "load"])(
    "an attach cancelled while %s is in flight waits for it, unloads the agent, then detaches (LIFE-1)",
    async (step) => {
      const h = createHarness();
      addForeign(h, 7800);
      const gate = h.fake.hold(step);
      const controller = new AbortController();
      const pending = h.attach(7800, { signal: controller.signal });
      await gate.entered;
      controller.abort();
      await settle();
      await settle();
      // nothing detaches while the native step is in flight (Frida would strand frida-agent.dll in the target)
      expect(h.fake.log.filter((l) => l.startsWith("detach") || l.startsWith("unload"))).toEqual([]);
      gate.release();
      const result = await pending;
      expect(errTag(result)).toBe("Cancelled");
      const tail = h.fake.log.filter((l) => /^(?:createScript|load|unload|detach):/u.test(l));
      expect(tail.slice(-2)).toEqual(["unload:7800", "detach:7800"]);
      expect(h.fake.process(7800)?.alive).toBe(true);
      expect(h.manager.list()).toHaveLength(0);
      await h.closeAll();
    },
  );

  it("a create-script step past its timeout keeps its promise: cleanup unloads the late script before detaching (LIFE-1)", async () => {
    const h = createHarness({ limits: (l) => ({ ...l, startup: { ...l.startup, createScriptMs: 20 } }) });
    addForeign(h, 7850);
    const gate = h.fake.hold("createScript");
    const pending = h.attach(7850);
    await gate.entered;
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(h.fake.log.some((l) => l.startsWith("detach"))).toBe(false);
    gate.release();
    const result = await pending;
    expect(errTag(result)).toBe("ProviderTimeout");
    const tail = h.fake.log.filter((l) => /^(?:createScript|unload|detach):/u.test(l));
    expect(tail).toEqual(["createScript:7850", "unload:7850", "detach:7850"]);
    await h.closeAll();
  });

  it("closeAll during an in-flight attach aborts it and cleans the startup up", async () => {
    const h = createHarness();
    addForeign(h, 7900);
    const gate = h.fake.hold("load");
    const pending = h.attach(7900);
    await gate.entered;
    const closing = h.closeAll();
    gate.release();
    const result = await pending;
    expect(result.ok).toBe(false);
    await closing;
    expect(h.fake.process(7900)?.alive).toBe(true);
    expect(h.manager.list()).toHaveLength(0);
  });
});

describe("agent jobs, user scripts, session-ended", () => {
  it("jobs.await resolves after the job message and every blob is stored (sha256 recomputed)", async () => {
    const h = createHarness();
    const spawned = await h.spawn();
    if (!spawned.ok) throw new Error(spawned.error._tag);
    const id = spawned.value.sessionId;
    const script = h.fake.agentScript(spawned.value.identity.pid);
    const session = await sessionOf(h, id);
    const waiting = h.run("dump_memory", (op) => session.jobs.await("j1", op, 5_000), { sessionId: id });
    script?.emitPayload(
      { bea: "blob", blob: "b1", job: "j1", part: 0, offset: 0, bytes: 3, last: false, total: 6 },
      Buffer.from("abc"),
    );
    script?.emitPayload(
      { bea: "blob", blob: "b1", job: "j1", part: 1, offset: 3, bytes: 3, last: true, total: 6 },
      Buffer.from("def"),
    );
    script?.emitPayload({
      bea: "job",
      job: "j1",
      kind: "dump",
      state: "done",
      progress: { done: 6, total: 6, unit: "bytes" },
      result: {
        format: "bea-dump/1",
        pid: spawned.value.identity.pid,
        taken: { t0: 1, t1: 2, suspended: false },
        modules: [],
        regions: [
          {
            blob: "b1",
            kind: "range",
            base: "0x1000",
            size: 6,
            protection: "rw-",
            module: null,
            holes: [],
            bea_patches_restored: [],
            sha256: null,
          },
        ],
        threads: [],
        module_map_epoch: 1,
        truncated: false,
      },
    });
    const outcome = await waiting;
    expect(errTag(outcome)).toBe("ok");
    if (outcome.ok) {
      const blob = outcome.value.blobs.get("b1");
      expect(blob).toMatchObject({
        bytes: 6,
        sha256: "bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721",
      });
      expect(outcome.value.info.state).toBe("done");
    }
    await h.closeAll();
  });

  it("scripts.run hosts the caller script separately and unloads it; a syntax error is invalid_request", async () => {
    const h = createHarness();
    const spawned = await h.spawn();
    if (!spawned.ok) throw new Error(spawned.error._tag);
    const id = spawned.value.sessionId;
    const session = await sessionOf(h, id);
    const ran = await h.run(
      "run_script",
      (op) =>
        session.scripts.run({ source: "send(1)", runtime: "qjs", durationMs: 10, maxMessages: 4, rpcArgs: [] }, op),
      { sessionId: id },
    );
    expect(errTag(ran)).toBe("ok");
    if (ran.ok) expect(ran.value.unloaded).toBe(true);
    const scripts = h.fake.sessionsOf(spawned.value.identity.pid).flatMap((s) => s.scripts);
    expect(scripts.filter((s) => !s.isDestroyed).map((s) => s.name)).toEqual(["bea-agent"]);
    const broken = await h.run(
      "run_script",
      (op) =>
        session.scripts.run(
          { source: "SYNTAX_ERROR(", runtime: "qjs", durationMs: 10, maxMessages: 4, rpcArgs: [] },
          op,
        ),
      { sessionId: id },
    );
    expect(errTag(broken)).toBe("InputError");
    await h.closeAll();
  });

  it("a fast clean exit is no brokered-launch evidence; a child that already exited is (UX-4/ONBOARD-5)", async () => {
    const run = async (children: readonly number[], stragglers: number) => {
      const h = createHarness();
      const spawned = await h.spawn();
      if (!spawned.ok) throw new Error(spawned.error._tag);
      const id = spawned.value.sessionId;
      expect(errTag(await h.run("resume_process", (op) => h.manager.resume(id, op), { sessionId: id }))).toBe("ok");
      const host = h.jobhost.hostOf(spawned.value.identity.pid);
      for (const pid of children) host?.procStart(pid);
      host?.exitRoot(0, stragglers);
      await settle();
      const session = await sessionOf(h, id);
      const limitations = [...(hostFactsOf(session)?.limitations() ?? [])];
      await h.closeAll();
      return limitations;
    };
    // a CLI program that printed and exited (a console host may linger): no limitation
    expect(await run([], 0)).not.toContain(LIMITATIONS.BROKERED_LAUNCH);
    expect(await run([9001], 1)).not.toContain(LIMITATIONS.BROKERED_LAUNCH);
    // it started a child that is already gone: a possible hand-off, worded without target-picking advice
    const handoff = await run([9001, 9002], 1);
    expect(handoff).toContain(LIMITATIONS.BROKERED_LAUNCH);
    expect(LIMITATIONS.BROKERED_LAUNCH).not.toMatch(/list_processes|attach_process/u);
  });

  it("onSessionEnded fires exactly once per session: exited first, not again at close", async () => {
    const h = createHarness();
    const spawned = await h.spawn();
    if (!spawned.ok) throw new Error(spawned.error._tag);
    const events: string[] = [];
    const off = h.manager.onSessionEnded((e) => events.push(e.reason));
    h.jobhost.hostOf(spawned.value.identity.pid)?.exitRoot(0);
    await settle();
    await h.run("close_session", (op) => h.manager.close(spawned.value.sessionId, { force: false }, op), {
      sessionId: spawned.value.sessionId,
    });
    expect(events).toEqual(["exited"]);
    off();
  });
});
