import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, mkdir, readdir, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import type { BeaApplication } from "../../../src/application/BeaApplication.js";
import { createApplication } from "../../../src/application/createApplication.js";
import type { ToolHandler } from "../../../src/application/handlerContext.js";
import { createToolHandlers } from "../../../src/application/handlers/index.js";
import { invokeTool } from "../../../src/application/invokeTool.js";
import { findToolContract } from "../../../src/contracts/index.js";
import type { ToolContract } from "../../../src/contracts/toolContract.js";
import { loadConfig, type ConfigFile } from "../../../src/domain/config.js";
import type { BeaError } from "../../../src/domain/errors/beaError.js";
import { LIMITATIONS } from "../../../src/domain/evidence/limitations.js";
import { silentLogger } from "../../../src/domain/logger.js";
import { ok, type Result } from "../../../src/domain/result.js";
import { composeServices } from "../../../src/main/composeServices.js";
import type { LiveSession, OperationContext, SessionEndedEvent } from "../../../src/ports/sessions.js";
import {
  fixtureArtifact,
  fridaSkip,
  gccSkip,
  jobhostSkip,
  loadFixtures,
  skipNote,
  type FixtureManifest,
} from "../../support/acceptance/fixtures.js";
import { OwnedPidLedger } from "../../support/process/ownedPidLedger.js";
import { createTempHome, type TempHome } from "../../support/workspace/tempHome.js";

/**
 * WP4 acceptance, in-process (DESIGN §8.4 WP4 row; S6 §10.8 rows of the seven session tools with the §8.4 edits): the
 * real composition (composeServices: evidence, jobhost, PE, address, recordings, sessions …) driven through the real
 * tool handlers (invokeTool: input parse, admission, output self-check), with raw LiveSession access where the wave
 * rule needs it (READY through LiveSession.waitFor, dump jobs and user scripts through raw agent RPCs and ports).
 * BEA_DIST_DIR names the snapshot that holds the agent bundle and bea-jobhost. Every target is BEA-owned (ledger: dead
 * after close) or test-spawned for attach (ledger: ALIVE after close); nothing else on the machine is touched.
 */
/** By absolute path (no PATH lookup). */
const TASKLIST = join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", "tasklist.exe");
const skip = fridaSkip() || jobhostSkip() || gccSkip();

type Output = Readonly<Record<string, unknown>>;
interface Bea {
  readonly app: BeaApplication;
  readonly home: TempHome;
  readonly call: (name: string, args: Output) => Promise<Result<Output, BeaError>>;
  readonly raw: <T>(
    id: string,
    fn: (s: LiveSession, op: OperationContext) => Promise<Result<T, BeaError>>,
  ) => Promise<Result<T, BeaError>>;
}

const bound: Bea[] = [];
const testSpawned: ChildProcess[] = [];
let manifest: FixtureManifest;
let ledger: OwnedPidLedger;

const startBea = async (configFile: Omit<ConfigFile, "schema"> = {}): Promise<Bea> => {
  const home = await createTempHome("wp4-inproc");
  const loaded = await loadConfig({
    env: home.env,
    platform: "win32",
    accountHome: home.home,
    readConfigFile: async () =>
      Object.keys(configFile).length === 0 ? null : JSON.stringify({ schema: "bea.config/1", ...configFile }),
  });
  if (!loaded.ok) throw new Error(JSON.stringify(loaded.error));
  const app = await createApplication({
    config: loaded.value,
    logger: silentLogger,
    transport: "stdio",
    services: composeServices,
  });
  const table = createToolHandlers(app) as unknown as Readonly<Record<string, ToolHandler<ToolContract>>>;
  const bea: Bea = {
    app,
    home,
    call: async (name, args) => {
      const contract = findToolContract(name);
      if (contract === undefined) throw new Error(`no tool ${name}`);
      return invokeTool(app, (n) => table[n], contract, args, {
        surface: "mcp",
        clientSignal: new AbortController().signal,
        progress: { report: () => undefined },
        requestId: name,
      });
    },
    raw: (id, fn) =>
      app.services.sessions.admit("acceptance_raw", { timeoutMs: 60_000, sessionId: id }, (op) =>
        app.services.sessions.withSession(id, op, "exclusive", (s) => fn(s, op)),
      ),
  };
  bound.push(bea);
  return bea;
};

const value = <T>(result: Result<T, BeaError>): T => {
  if (!result.ok) throw new Error(`expected success, got ${JSON.stringify(result.error)}`);
  return result.value;
};
const errorOf = (result: Result<unknown, BeaError>): Output => {
  if (result.ok) throw new Error(`expected an error, got ${JSON.stringify(result.value).slice(0, 400)}`);
  return result.error as unknown as Output;
};

const spawnOwned = async (bea: Bea, program: string, args: readonly string[], extra: Output = {}): Promise<Output> => {
  const spawned = value(await bea.call("spawn_process", { program, args: [...args], ...extra }));
  ledger.recordIdentity(spawned["identity"] as Output, `spawn ${program} ${args.join(" ")}`);
  return spawned;
};

/** A game_sim the TEST starts (attach target): stdout keeps flowing into `out` so the pipe never fills. */
const startForeignGame = async (): Promise<{ readonly child: ChildProcess; readonly out: string[] }> => {
  const game = fixtureArtifact(manifest, "game_sim");
  if (game === null) throw new Error("fixtures unavailable");
  const child = spawn(game.path, ["--frames", "0", "--no-threads"], {
    cwd: dirname(game.path),
    stdio: ["ignore", "pipe", "ignore"],
    windowsHide: true,
  });
  testSpawned.push(child);
  const out: string[] = [];
  child.stdout?.on("data", (chunk: Buffer) => out.push(chunk.toString()));
  await vi.waitFor(() => expect(out.join("")).toContain("READY"), { interval: 20, timeout: 10_000 });
  ledger.recordAttachTarget(child.pid ?? 0, null, "test-spawned game_sim");
  return { child, out };
};

const fridaAgentLoaded = (pid: number): boolean => {
  const run = spawnSync(TASKLIST, ["/M", "frida-agent.dll", "/FI", `PID eq ${String(pid)}`, "/FO", "CSV", "/NH"], {
    encoding: "utf8",
    windowsHide: true,
  });
  return run.stdout.includes(`"${String(pid)}"`);
};

const frameCount = (out: readonly string[]): number => out.join("").split("FRAME ").length - 1;

beforeAll(async () => {
  if (skip !== false) return;
  const loaded = await loadFixtures();
  if ("unavailable" in loaded) throw new Error(loaded.unavailable);
  manifest = loaded;
  ledger = new OwnedPidLedger(fixtureArtifact(manifest, "pidcheck")?.path ?? null);
});

afterAll(async () => {
  if (skip !== false) return;
  for (const bea of bound) await bea.app.lifecycle.closeAll("test");
  try {
    await ledger.assertClean();
  } finally {
    await ledger.killAttachTargets();
    for (const child of testSpawned) if (child.exitCode === null) child.kill();
    for (const bea of bound) await bea.home.cleanup();
  }
}, 60_000);

describe.skipIf(skip !== false)(`spawn_process against the real composition${skipNote(skip)}`, () => {
  it("spawn_process: paused in a job at an ASLR base, 3 recordings; READY after resume_process; close_session kills", async () => {
    const bea = await startBea();
    const game = fixtureArtifact(manifest, "game_sim");
    if (game === null) throw new Error("fixtures unavailable");
    const spawned = await spawnOwned(bea, game.path, ["--frames", "0", "--no-threads"]);
    expect(spawned).toMatchObject({
      state: "paused",
      identity: { ownership: "owned" },
      containment: {
        kind: "win32-job",
        kill_on_close: true,
        breakaway: false,
        assigned_before_first_instruction: true,
      },
      main_module: { name: "game_sim.exe", preferred_base: "0x140000000" },
      predicate_type: "bea.process.instance",
      anti_cheat_signals: [],
    });
    expect((spawned["main_module"] as { base: string }).base).not.toBe("0x140000000");
    expect((spawned["recordings"] as { kind: string }[]).map((r) => r.kind).sort()).toEqual([
      "exceptions",
      "modules",
      "output",
    ]);
    expect(spawned["limitations"]).toContain(LIMITATIONS.AGENT_FOOTPRINT);
    const id = spawned["session_id"] as string;
    const pid = (spawned["identity"] as { pid: number }).pid;
    expect(fridaAgentLoaded(pid)).toBe(true);
    // review fix LIFE-3: Frida's agent extraction lands in BEA's own per-run directory (reclaimable after a kill),
    // and the server's TEMP is back to the user's once the attach returned
    const fridaRoot = join(bea.home.beaHome, "tmp", "frida");
    const runDirs = await readdir(fridaRoot);
    expect(runDirs).toHaveLength(1);
    const extracted = await readdir(join(fridaRoot, runDirs[0] ?? ""));
    expect(extracted).toContain("owner.json");
    expect(extracted.some((name) => name.startsWith("frida-"))).toBe(true);
    expect(process.env["TEMP"] ?? "").not.toContain(fridaRoot);

    const resumed = value(await bea.call("resume_process", { session_id: id }));
    expect(resumed).toMatchObject({ state: "running", exit: null, crash: null });
    const ready = value(
      await bea.raw(id, async (s, op) => ok(await s.waitFor({ kind: "output-contains", text: "READY" }, op, 10_000))),
    );
    expect(ready).toMatchObject({ satisfied: true, state: "running" });
    const status = value(await bea.call("session_status", { session_id: id }));
    expect(status).toMatchObject({ kind: "live", state: "running" });
    expect(String(status["output_tail"])).toContain(`READY pid=${String(pid)}`);

    const started = performance.now();
    const closed = value(await bea.call("close_session", { session_id: id }));
    expect(performance.now() - started).toBeLessThan(2000);
    expect(closed).toMatchObject({ already_closed: false, target_state: "killed", predicate_type: "bea.process.exit" });
    expect((closed["manifests"] as string[]).length).toBeGreaterThanOrEqual(3);
    expect(value(await bea.call("close_session", { session_id: id }))["already_closed"]).toBe(true);
    expect(value(await bea.call("session_status", { session_id: id }))["state"]).toBe("closed");
  }, 60_000);

  it("refusals before anything starts (expect_sha256, 32-bit, interpreter, anti-cheat beside the image) and the caps", async () => {
    const bea = await startBea();
    const game = fixtureArtifact(manifest, "game_sim");
    if (game === null) throw new Error("fixtures unavailable");
    const mismatch = await bea.call("spawn_process", { program: game.path, expect_sha256: "0".repeat(64) });
    expect(errorOf(mismatch)["_tag"]).toBe("InstanceMismatch");
    const pe32 = join(bea.home.work, "old32.exe");
    await copyFile(join(process.cwd(), "fixtures", "golden", "pe32-minimal.bin"), pe32);
    expect(errorOf(await bea.call("spawn_process", { program: pe32 }))).toMatchObject({
      _tag: "UnsupportedTarget",
      reason: "wow64",
    });
    const cmd = join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", "cmd.exe");
    expect(errorOf(await bea.call("spawn_process", { program: cmd }))).toMatchObject({
      _tag: "AccessDenied",
      reason: "policy",
    });
    const guarded = join(bea.home.work, "guarded", "bin");
    await mkdir(join(bea.home.work, "guarded", "EasyAntiCheat"), { recursive: true });
    await mkdir(guarded, { recursive: true });
    await copyFile(game.path, join(guarded, "game_sim.exe"));
    expect(errorOf(await bea.call("spawn_process", { program: join(guarded, "game_sim.exe") }))).toMatchObject({
      _tag: "AccessDenied",
      reason: "anti-cheat-detected",
    });
    expect(bea.app.services.sessions.list()).toEqual([]);

    const piped: string[] = [];
    for (let i = 0; i < 3; i += 1)
      piped.push((await spawnOwned(bea, game.path, ["--frames", "0", "--no-threads"]))["session_id"] as string);
    expect(errorOf(await bea.call("spawn_process", { program: game.path }))).toMatchObject({
      _tag: "ResourceConstraint",
    });
    const inherit = await spawnOwned(bea, game.path, ["--frames", "0", "--no-threads"], { capture_output: false });
    expect((inherit["recordings"] as { kind: string }[]).map((r) => r.kind)).not.toContain("output");
    expect(errorOf(await bea.call("spawn_process", { program: game.path, capture_output: false }))).toMatchObject({
      _tag: "ResourceConstraint",
    });
    for (const id of [...piped, inherit["session_id"] as string])
      value(await bea.call("close_session", { session_id: id }));
  }, 120_000);
});

describe.skipIf(skip !== false)(`spawn policy overrides and the target environment${skipNote(skip)}`, () => {
  it("a user-allowed image (attach.allow_anti_cheat_images) spawns with its signals reported", async () => {
    const game = fixtureArtifact(manifest, "game_sim");
    if (game === null) throw new Error("fixtures unavailable");
    const sha = createHash("sha256")
      .update(await readFile(game.path))
      .digest("hex");
    const bea = await startBea({ attach: { allow_anti_cheat_images: [sha] } });
    const dir = join(bea.home.work, "allowed", "bin");
    await mkdir(join(bea.home.work, "allowed", "EasyAntiCheat"), { recursive: true });
    await mkdir(dir, { recursive: true });
    await copyFile(game.path, join(dir, "game_sim.exe"));
    const spawned = await spawnOwned(bea, join(dir, "game_sim.exe"), ["--frames", "0", "--no-threads"]);
    expect(spawned["anti_cheat_signals"]).toEqual(["dir:EasyAntiCheat"]);
    expect(spawned["limitations"]).toContain(LIMITATIONS.ANTI_CHEAT_ALLOWED);
    value(await bea.call("close_session", { session_id: spawned["session_id"] }));
  }, 60_000);

  it("the target environment is the OS allowlist plus env entries: no BEA_* key and no other server variable", async () => {
    process.env["WP4_SECRET_CANARY"] = "secret";
    process.env["BEA_CANARY"] = "1";
    try {
      const bea = await startBea({ spawn: { allow_interpreters: true } });
      const script = "console.log('KEYS ' + JSON.stringify(Object.keys(process.env).sort()))";
      const spawned = await spawnOwned(bea, process.execPath, ["-e", script], {
        env: ["CALLER_VAR=1", "BEA_SNEAKY=1"],
      });
      expect(spawned["environment"]).toMatchObject({ mode: "allowlist", allowlist_version: 1 });
      const id = spawned["session_id"] as string;
      const resumed = value(await bea.call("resume_process", { session_id: id, wait_ms: 20_000, until: "exit" }));
      expect(resumed).toMatchObject({ state: "exited", exit: { code: 0, kind: "normal" }, crash: null });
      const status = value(await bea.call("session_status", { session_id: id }));
      const match = /KEYS (\[.*\])/u.exec(String(status["output_tail"]));
      const keys = JSON.parse(match?.[1] ?? "null") as string[] | null;
      expect(keys).not.toBeNull();
      expect(keys).toContain("CALLER_VAR");
      expect(keys?.map((k) => k.toUpperCase())).toContain("SYSTEMROOT");
      expect(keys?.filter((k) => k.toUpperCase().startsWith("BEA_"))).toEqual([]);
      expect(keys).not.toContain("WP4_SECRET_CANARY");
      value(await bea.call("close_session", { session_id: id }));
    } finally {
      delete process.env["WP4_SECRET_CANARY"];
      delete process.env["BEA_CANARY"];
    }
  }, 60_000);
});

describe.skipIf(skip !== false)(`list_processes, attach_process and crashes${skipNote(skip)}`, () => {
  it("list_processes never injects; attach by pid; name ambiguity lists candidates; close detaches, target keeps running", async () => {
    const bea = await startBea();
    const first = await startForeignGame();
    const second = await startForeignGame();
    const firstPid = first.child.pid ?? 0;
    const listed = value(await bea.call("list_processes", { filter: "game_sim" }));
    expect((listed["rows"] as { pid: number }[]).map((p) => p.pid)).toEqual(
      expect.arrayContaining([firstPid, second.child.pid]),
    );
    expect(fridaAgentLoaded(firstPid)).toBe(false);

    const ambiguous = errorOf(await bea.call("attach_process", { name: "game_sim.exe" }));
    expect(ambiguous["_tag"]).toBe("InputError");
    expect((ambiguous["diagnostics"] as { candidates: number[] }).candidates).toEqual(
      expect.arrayContaining([firstPid, second.child.pid]),
    );

    const attached = value(await bea.call("attach_process", { pid: firstPid }));
    expect(attached).toMatchObject({
      state: "running",
      identity: { pid: firstPid, ownership: "attached" },
      containment: { kind: "none", kill_on_close: false },
      predicate_type: "bea.process.instance",
    });
    expect(attached["limitations"]).toContain(LIMITATIONS.AGENT_FOOTPRINT);
    expect(fridaAgentLoaded(firstPid)).toBe(true);
    const id = attached["session_id"] as string;
    expect(errorOf(await bea.call("resume_process", { session_id: id }))["_tag"]).toBe("InvalidState");
    expect(value(await bea.call("session_status", { session_id: id }))).toMatchObject({ state: "running" });

    const closed = value(await bea.call("close_session", { session_id: id }));
    expect(closed).toMatchObject({ already_closed: false, target_state: "detached-running" });
    const framesAtClose = frameCount(first.out);
    await vi.waitFor(() => expect(frameCount(first.out)).toBeGreaterThan(framesAtClose), {
      interval: 50,
      timeout: 5000,
    });
    expect(first.child.exitCode).toBeNull();
  }, 60_000);

  it("crashy av-write: resume_process waits for the exit; 0xc0000005 with a CrashReport recorded via LiveSession.crash", async () => {
    const bea = await startBea();
    const crashy = fixtureArtifact(manifest, "crashy");
    if (crashy === null) throw new Error("fixtures unavailable");
    const spawned = await spawnOwned(bea, crashy.path, ["av-write", "--delay-ms", "100"]);
    const id = spawned["session_id"] as string;
    const resumed = value(await bea.call("resume_process", { session_id: id, wait_ms: 20_000, until: "exit" }));
    expect(resumed).toMatchObject({
      state: "exited",
      exit: { code_hex: "0xc0000005", kind: "ntstatus", name: "STATUS_ACCESS_VIOLATION" },
      crash: { type: "access-violation", memory: { op: "write" } },
    });
    const crash = value(await bea.raw(id, (s, op) => s.crash(op)));
    expect(crash).toMatchObject({ type: "access-violation", ntstatus: "STATUS_ACCESS_VIOLATION" });
    expect(crash?.evidence_id).toMatch(/^ev_/u);
    expect(value(await bea.call("session_status", { session_id: id }))).toMatchObject({ state: "exited" });
    expect(value(await bea.call("close_session", { session_id: id }))).toMatchObject({ target_state: "exited" });
  }, 60_000);
});

describe.skipIf(skip !== false)(`raw LiveSession seams (wave rule)${skipNote(skip)}`, () => {
  it('raw seams: clock:"resume" arms at the resumed post; jobs.await returns dump blobs; scripts.run unloads', async () => {
    const bea = await startBea();
    const game = fixtureArtifact(manifest, "game_sim");
    if (game === null) throw new Error("fixtures unavailable");
    const spawned = await spawnOwned(bea, game.path, ["--frames", "0", "--no-threads"]);
    const id = spawned["session_id"] as string;

    // CI-I3: an instrument installed while paused with clock:"resume" gets its deadline only at the resumed post.
    const hook = value(
      await bea.raw(id, (s, op) =>
        s.agent.call(
          "hookInstall",
          {
            target: { module: "game_sim.exe", export: "physics_step" },
            engine: "js",
            relocation: "auto",
            capture: { args: [], ret: null, backtrace: null, registers: "none" },
            emit: "enter",
            probe: false,
            hidden_ret_ptr: false,
            lifetime: { duration_ms: 300, max_hits: 1_000_000, clock: "resume" },
            observe_agent_calls: false,
            force_caution: false,
            label: "wp4-resume-clock",
          },
          { op },
        ),
      ),
    );
    const infoOf = async () =>
      value(await bea.raw(id, (s, op) => s.agent.call("instrumentList", {}, { op }))).instruments.find(
        (i) => i.id === hook.instrument_id,
      );
    await new Promise((resolve) => setTimeout(resolve, 600));
    expect(await infoOf()).toMatchObject({ state: "active", deadline_t: null });
    value(await bea.call("resume_process", { session_id: id }));
    await vi.waitFor(async () => expect((await infoOf())?.state).toBe("ended"), { interval: 50, timeout: 5000 });

    // CI-B3: the dump job's JobMessage and every blob are stored before jobs.await resolves.
    const outcome = value(
      await bea.raw(id, async (s, op) => {
        const started = await s.agent.call(
          "dumpStart",
          {
            items: [{ kind: "module", module: "game_sim.exe" }],
            suspend: "none",
            max_total_bytes: 8 << 20,
            original_bytes: true,
          },
          { op },
        );
        if (!started.ok) return started;
        return s.jobs.await(started.value.job_id, op, 30_000);
      }),
    );
    expect(outcome.error).toBeNull();
    expect(outcome.info.state).toBe("done");
    expect(outcome.blobs.size).toBeGreaterThanOrEqual(1);
    for (const blob of outcome.blobs.values()) expect(blob).not.toHaveProperty("failed");

    // CI-B4: a caller script runs in its own Script and is unloaded; the BEA agent keeps answering.
    for (const n of [2, 3]) {
      const run = value(
        await bea.raw(id, (s, op) =>
          s.scripts.run(
            {
              source: "send({ hello: 1 }); rpc.exports = { add: (a, b) => a + b };",
              runtime: "qjs",
              durationMs: 2000,
              maxMessages: 16,
              rpcMethod: "add",
              rpcArgs: [n, 40],
            },
            op,
          ),
        ),
      );
      expect(run).toMatchObject({ rpcResult: n + 40, unloaded: true, errors: [] });
    }
    const syntax = await bea.raw(id, (s, op) =>
      s.scripts.run(
        { source: "this is not javascript (", runtime: "qjs", durationMs: 1000, maxMessages: 4, rpcArgs: [] },
        op,
      ),
    );
    expect(errorOf(syntax)["_tag"]).toBe("InputError");
    expect(value(await bea.raw(id, (s, op) => s.agent.call("ping", {}, { op })))).toMatchObject({ phase: "ready" });
    value(await bea.call("close_session", { session_id: id }));
  }, 90_000);
});

describe.skipIf(skip !== false)(`closeAll with live and external sessions${skipNote(skip)}`, () => {
  it("closeAll: 3 piped owned + 1 attached + 1 external in < 2 s; owned dead, attached alive; onSessionEnded once each", async () => {
    const bea = await startBea();
    const game = fixtureArtifact(manifest, "game_sim");
    if (game === null) throw new Error("fixtures unavailable");
    const ended: SessionEndedEvent[] = [];
    bea.app.services.sessions.onSessionEnded((e) => ended.push(e));
    for (let i = 0; i < 3; i += 1) await spawnOwned(bea, game.path, ["--frames", "0", "--no-threads"]);
    const foreign = await startForeignGame();
    value(await bea.call("attach_process", { pid: foreign.child.pid }));
    const external = await bea.app.services.sessions.admit("emu_open", { timeoutMs: 5000 }, (op) =>
      bea.app.services.sessions.registerExternal(
        "emulation",
        async (sessionId) =>
          ok({
            kind: "emulation" as const,
            shutdown: async () => ok(undefined),
            close: async () =>
              ok({
                sessionId,
                kind: "emulation" as const,
                ownership: null,
                targetState: "none" as const,
                termination: null,
                exit: null,
                revert: null,
                agentUnloaded: null,
                fridaDetached: false,
                streamsFinalized: [],
                cleanup: { status: "complete" as const },
                limitations: [],
              }),
            summary: () => ({
              session_id: sessionId,
              kind: "emulation" as const,
              state: "ready" as const,
              pid: null,
              ownership: "none" as const,
              image: null,
              instance_id: null,
              active_instruments: 0,
              active_effects: 0,
            }),
            detail: async () => ok({ status: "ready" }),
          }),
        op,
      ),
    );
    expect(external.ok).toBe(true);
    expect(bea.app.services.sessions.list()).toHaveLength(5);

    const started = performance.now();
    const report = await bea.app.lifecycle.closeAll("test");
    expect(performance.now() - started).toBeLessThan(2000);
    expect(report.ok, JSON.stringify(report.phases)).toBe(true);
    expect(ended.map((e) => `${e.kind}:${e.reason}`).sort()).toEqual([
      "emulation:shutdown",
      "live:shutdown",
      "live:shutdown",
      "live:shutdown",
      "live:shutdown",
    ]);
    expect(new Set(ended.map((e) => e.sessionId)).size).toBe(5);
    const audit = await ledger.audit();
    expect(audit.leaks).toEqual([]);
    expect(audit.deadAttachTargets).toEqual([]);
    expect(foreign.child.exitCode).toBeNull();
  }, 90_000);
});

describe.skipIf(skip !== false)(`doctor checks of the sessions area${skipNote(skip)}`, () => {
  it("frida:binding, frida:local-device, build:agent and frida:inject-probe pass on this machine", async () => {
    const bea = await startBea();
    const names = ["build:agent", "frida:binding", "frida:inject-probe", "frida:local-device"];
    const checks = bea.app.doctor.list().filter((c) => names.includes(c.name));
    expect(checks.map((c) => c.name).sort()).toEqual(names);
    for (const check of checks) {
      const result = await check.run(new AbortController().signal);
      expect(result, `${check.name}: ${result.detail ?? ""}`).toMatchObject({ name: check.name, ok: true });
    }
    expect(bea.app.services.sessions.list()).toEqual([]);
  }, 60_000);
});
