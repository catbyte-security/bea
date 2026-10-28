import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { connectBea, type BeaConnection } from "../../support/acceptance/harness.js";
import {
  emuSkip,
  fixtureArtifact,
  fridaSkip,
  gccSkip,
  jobhostSkip,
  loadFixtures,
  skipNote,
  type FixtureArtifact,
  type FixtureManifest,
} from "../../support/acceptance/fixtures.js";
import { realPython } from "../../support/emu/python.js";
import { expectToolSuccess, parseToolError } from "../../support/mcp/parseToolError.js";
import { OwnedPidLedger, pidStatus } from "../../support/process/ownedPidLedger.js";
import { createTempHome } from "../../support/workspace/tempHome.js";

/**
 * S6 §10.9 lifecycle must-haves 1–8 on the real stack (DESIGN §10.2 "lifecycle", WP18): the BUILT server over stdio
 * (BEA_DIST_DIR snapshot), real Frida, the jobhost and the emulator bridge. One fresh server per test (S6 §10.7);
 * every BEA-owned process is in the owned-PID ledger (creation times from the spawn identities) and every attach
 * target is spawned by this file and must outlive detach, close and shutdown. No sleeps for synchronization: READY /
 * DONE markers through `wait {until:"output"}`, liveness through pidcheck polled with vi.waitFor.
 */
const skip = fridaSkip() || gccSkip() || jobhostSkip();
const emuReason = emuSkip();
type Obj = Readonly<Record<string, unknown>>;
const TASKKILL = join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", "taskkill.exe");
const GAME_ARGS = ["--no-threads", "--speed", "20", "--throttle", "0.125"] as const;

let manifest: FixtureManifest;
let game: FixtureArtifact;
let pidcheck: string | null;
let ledger: OwnedPidLedger;
const foreign: ChildProcess[] = [];
const scratch: string[] = [];

const artifact = (id: Parameters<typeof fixtureArtifact>[1]): FixtureArtifact => {
  const found = fixtureArtifact(manifest, id);
  if (found === null) throw new Error(`fixture ${id} unavailable`);
  return found;
};
const ok = async (bea: BeaConnection, name: string, args: Obj): Promise<Obj> =>
  expectToolSuccess(await bea.call(name, args));
const identityOf = (spawned: Obj): { pid: number; creation: string | null } => {
  const identity = spawned["identity"] as { pid: number; start_time: { source: string; value: string } };
  return {
    pid: identity.pid,
    creation: identity.start_time.source === "os-creation-time" ? identity.start_time.value : null,
  };
};
const alive = (pid: number, creation: string | null): boolean => pidStatus(pidcheck, pid, creation).alive;
const expectGone = async (targets: readonly { pid: number; creation: string | null }[], timeout = 10_000) =>
  vi.waitFor(() => expect(targets.filter((t) => alive(t.pid, t.creation))).toEqual([]), { interval: 50, timeout });

/** spawn_process + resume_process + READY (owned; the harness records the identity in the ledger). */
const startGame = async (bea: BeaConnection, args: readonly string[] = GAME_ARGS) => {
  const spawned = await ok(bea, "spawn_process", { program: game.path, args: [...args] });
  const id = String(spawned["session_id"]);
  await ok(bea, "resume_process", { session_id: id });
  await ok(bea, "wait", { session_id: id, until: "output", output_contains: "READY", timeout_ms: 15_000 });
  return { id, ...identityOf(spawned) };
};

/** A game_sim the TEST starts for attach_process; it must survive everything BEA does. */
const startForeign = async (): Promise<{ child: ChildProcess; frames: () => number }> => {
  const child = spawn(game.path, [...GAME_ARGS], {
    cwd: dirname(game.path),
    stdio: ["ignore", "pipe", "ignore"],
    windowsHide: true,
  });
  foreign.push(child);
  let out = "";
  child.stdout?.on("data", (chunk: Buffer) => (out += chunk.toString()));
  await vi.waitFor(() => expect(out).toContain("READY"), { interval: 25, timeout: 10_000 });
  ledger.recordAttachTarget(child.pid ?? 0, null, "lifecycle attach target");
  return { child, frames: () => out.split("FRAME ").length - 1 };
};

/** emu_open on mathlib.dll; the bridge launcher and interpreter are owned helpers (ledger). */
const openEmulation = async (bea: BeaConnection): Promise<{ id: string; pids: number[] }> => {
  const opened = await ok(bea, "emu_open", { image_path: artifact("mathlib").path });
  const bridge = opened["bridge"] as { pid: number; child_pid: number };
  const pids = [...new Set([bridge.pid, bridge.child_pid])];
  for (const pid of pids) ledger.recordOwned(pid, null, "lifecycle emulation bridge");
  return { id: String(opened["session_id"]), pids };
};
const emuEnv = (): Record<string, string> => {
  const python = realPython();
  return python === null ? {} : { BEA_PYTHON: python };
};

beforeAll(async () => {
  if (skip !== false) return;
  const loaded = await loadFixtures();
  if ("unavailable" in loaded) throw new Error(loaded.unavailable);
  manifest = loaded;
  game = artifact("game_sim");
  pidcheck = fixtureArtifact(manifest, "pidcheck")?.path ?? null;
  ledger = new OwnedPidLedger(pidcheck);
});

afterAll(async () => {
  if (skip !== false) return;
  try {
    await ledger.assertClean();
  } finally {
    await ledger.killAttachTargets();
    for (const child of foreign) if (child.exitCode === null) child.kill();
    for (const dir of scratch) await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
}, 60_000);

const mustHave1 = async (): Promise<void> => {
  const bea = await connectBea({ ledger, env: emuEnv() });
  // DESIGN §10.3: the run records the machine-wide anti-cheat services bea_status reports (CI-I12); the fixtures carry
  // no target-scoped signal, so they must spawn and attach below whatever is listed here
  process.stderr.write(
    `[acceptance environment] machine-wide anti-cheat notes: ${JSON.stringify(bea.antiCheatNotes)}\n`,
  );
  const owned: { pid: number; creation: string | null }[] = [];
  let bridge: number[] = [];
  let target: Awaited<ReturnType<typeof startForeign>> | undefined;
  let outcome;
  try {
    for (let i = 0; i < 3; i += 1) owned.push(await startGame(bea));
    target = await startForeign();
    const attached = await ok(bea, "attach_process", { pid: target.child.pid });
    expect(attached).toMatchObject({ identity: { ownership: "attached" } });
    bridge = (await openEmulation(bea)).pids;
    const status = await ok(bea, "bea_status", {});
    expect((status["sessions"] as { kind: string }[]).map((s) => s.kind).sort()).toEqual([
      "emulation",
      "live",
      "live",
      "live",
      "live",
    ]);
  } finally {
    outcome = await bea.close();
  }
  expect(outcome).toMatchObject({ exitCode: 0, signal: null });
  expect(outcome.closeMs).toBeLessThan(2000);
  await expectGone([...owned, ...bridge.map((pid) => ({ pid, creation: null }))], 5000);
  // BEA never kills what it attached to: the target keeps simulating frames after the server is gone
  const atClose = target?.frames() ?? 0;
  await vi.waitFor(() => expect(target?.frames() ?? 0).toBeGreaterThan(atClose), { interval: 50, timeout: 5000 });
  expect((await ledger.audit()).deadAttachTargets).toEqual([]);
};

const mustHave2 = async (): Promise<void> => {
  const bea = await connectBea({ ledger, env: emuEnv() });
  const owned: { pid: number; creation: string | null }[] = [];
  try {
    for (let i = 0; i < 2; i += 1) owned.push(await startGame(bea));
    const target = await startForeign();
    await ok(bea, "attach_process", { pid: target.child.pid });
    const { pids } = await openEmulation(bea);
    for (const t of owned) expect(alive(t.pid, t.creation)).toBe(true);
    const killed = spawnSync(TASKKILL, ["/F", "/PID", String(bea.pid)], { encoding: "utf8", windowsHide: true });
    expect(killed.status, killed.stderr).toBe(0);
    await expectGone([...owned, ...pids.map((pid) => ({ pid, creation: null }))], 10_000);
    expect(target.child.exitCode).toBeNull();
    const atKill = target.frames();
    await vi.waitFor(() => expect(target.frames()).toBeGreaterThan(atKill), { interval: 50, timeout: 5000 });
  } finally {
    await bea.close();
  }
};

const mustHave3 = async (): Promise<void> => {
  const bea = await connectBea({ ledger });
  try {
    // (a) crashy crashes while resume_process and wait are both blocked on it
    const crashy = await ok(bea, "spawn_process", {
      program: artifact("crashy").path,
      args: ["av-write", "--delay-ms", "1500"],
    });
    const crashId = String(crashy["session_id"]);
    const started = performance.now();
    const resuming = bea.call("resume_process", { session_id: crashId, wait_ms: 60_000, until: "exit" });
    const waiting = bea.call("wait", {
      session_id: crashId,
      until: "events",
      min_events: 100_000_000,
      timeout_ms: 60_000,
    });
    const [resumed, waited] = await Promise.all([resuming, waiting]);
    expect(performance.now() - started).toBeLessThan(15_000);
    expect(expectToolSuccess(resumed)).toMatchObject({ state: "exited", exit: { code_hex: "0xc0000005" } });
    expect(expectToolSuccess(waited)).toMatchObject({ satisfied: false, reason: "target_exited" });
    // (b) an owned target killed from outside BEA while a wait on an instrument that never fires is pending
    const t = await startGame(bea);
    const hook = await ok(bea, "hook_function", {
      session_id: t.id,
      address: "game_sim.exe!engine_update", // never called with --no-threads
      duration_ms: 60_000,
    });
    const rec = (hook["instrument"] as { recording_id: string }).recording_id;
    const pending = bea.call("wait", { session_id: t.id, until: "done", ids: [rec], timeout_ms: 60_000 });
    const killedAt = performance.now();
    process.kill(t.pid); // TerminateProcess on our own owned target
    const outcome = expectToolSuccess(await pending);
    expect(performance.now() - killedAt).toBeLessThan(10_000);
    // the instrument it waited for finished BECAUSE the target exited (a "done" wait holds; the exit is the cause)
    expect(outcome).toMatchObject({ target: { state: "exited" } });
    expect(outcome["recordings"]).toEqual([
      expect.objectContaining({ recording_id: rec, state: "finished", end_reason: "target_exited" }),
    ]);
    expect(parseToolError(await bea.call("resume_process", { session_id: t.id })).code).toBe("target_exited");
    for (const id of [crashId, t.id]) await ok(bea, "close_session", { session_id: id });
  } finally {
    await bea.close();
  }
};

const mustHave4 = async (): Promise<void> => {
  const bea = await connectBea({ ledger });
  try {
    const t = await startGame(bea, [...GAME_ARGS, "--ballast-mb", "768"]);
    const hook = await ok(bea, "hook_function", {
      session_id: t.id,
      address: "game_sim.exe!physics_step",
      duration_ms: 60_000,
    });
    const hookRec = (hook["instrument"] as { recording_id: string }).recording_id;
    const cancelAfter = (ms: number): AbortSignal => AbortSignal.timeout(ms);
    // wait: cancelled by the client
    await expect(
      bea.call(
        "wait",
        { session_id: t.id, until: "done", ids: [hookRec], timeout_ms: 30_000 },
        { signal: cancelAfter(300) },
      ),
    ).rejects.toThrow();
    // a running scan over ~768 MiB: cancelled mid-way; it keeps its partial result and stays listed
    await expect(
      bea.call(
        "scan_memory",
        { session_id: t.id, value_type: "f32", compare: "between", value: 19.99, value2: 20.01, wait_ms: 60_000 },
        { signal: cancelAfter(150) },
      ),
    ).rejects.toThrow();
    // a trace_api window (blocking for its duration) cancelled by the client
    await expect(
      bea.call(
        "trace_api",
        { session_id: t.id, profiles: ["file", "memory_protection"], duration_ms: 30_000, wait_ms: 30_000 },
        { signal: cancelAfter(1500) },
      ),
    ).rejects.toThrow();
    // the server still answers, and the session lists every instrument as still there
    expect((await ok(bea, "bea_status", {}))["sessions"]).toContainEqual(expect.objectContaining({ session_id: t.id }));
    const status = await vi.waitFor(
      async () => {
        const s = await ok(bea, "session_status", { session_id: t.id });
        const kinds = (s["instruments"] as { kind: string }[]).map((i) => i.kind);
        if (!kinds.includes("api") || (s["scans"] as unknown[]).length === 0)
          throw new Error(`not listed yet: ${kinds.join(",")}`);
        return s;
      },
      { interval: 50, timeout: 10_000 },
    );
    const instruments = status["instruments"] as { recording_id: string; kind: string; state: string }[];
    const api = instruments.find((i) => i.kind === "api");
    expect(api?.state).toBe("active");
    expect(instruments.find((i) => i.recording_id === hookRec)?.state).toBe("active");
    const scan = (status["scans"] as { scan_id: string }[])[0];
    // the abort reasons are on the server's record (one cancelled call each)
    const cancelled = bea
      .stderr()
      .split("\n")
      .filter((line) => /"msg":"tool done"/u.test(line) && /"aborted":"client"/u.test(line))
      .map((line) => /"tool":"([a-z_]+)"/u.exec(line)?.[1]);
    expect(cancelled).toEqual(expect.arrayContaining(["wait", "scan_memory", "trace_api"]));
    // a later stop works for all three
    const stopped = await ok(bea, "stop_instrumentation", {
      session_id: t.id,
      ids: [hookRec, api?.recording_id ?? "", scan?.scan_id ?? ""],
    });
    expect((stopped["stopped"] as { status: string }[]).map((s) => s.status).sort()).toEqual(
      expect.arrayContaining(["released"]),
    );
    expect(stopped["stopped"]).toHaveLength(3);
    await ok(bea, "close_session", { session_id: t.id });
  } finally {
    await bea.close();
  }
};

const mustHave5 = async (): Promise<void> => {
  const outDir = await mkdtemp(join(tmpdir(), "bea-lifecycle-"));
  scratch.push(outDir);
  const bea = await connectBea({ ledger });
  try {
    const spawned = await ok(bea, "spawn_process", {
      program: artifact("behavior").path,
      args: ["--out-dir", outDir, "--steps", "process", "--child-hold-ms", "30000"],
    });
    const id = String(spawned["session_id"]);
    const resumed = await ok(bea, "resume_process", { session_id: id, wait_ms: 30_000, until: "exit" });
    expect(resumed).toMatchObject({ state: "exited", exit: { code: 0 } });
    const status = await ok(bea, "session_status", { session_id: id });
    const child = Number(/CHILD pid=(\d+)/u.exec(String(status["output_tail"]))?.[1]);
    ledger.recordOwned(child, null, "behavior.exe --child (straggler)");
    expect(status).toMatchObject({ state: "exited", containment: { kind: "win32-job" } });
    const containment = status["containment"] as { active_processes: number; children_seen: number[] };
    expect(containment.active_processes).toBeGreaterThanOrEqual(1);
    expect(containment.children_seen).toContain(child);
    expect(alive(child, null)).toBe(true);
    const closed = await ok(bea, "close_session", { session_id: id });
    expect(closed).toMatchObject({ target_state: "killed" });
    await expectGone([{ pid: child, creation: null }], 5000);
  } finally {
    await bea.close();
  }
};

const mustHave6 = async (): Promise<void> => {
  const bea = await connectBea({ ledger });
  try {
    const t = await startGame(bea);
    expect(t.creation).toMatch(/^\d{15,}$/u);
    expect(pidStatus(pidcheck, t.pid, t.creation)).toMatchObject({ alive: true, matches: true });
    // the same pid with a different creation time reads as reuse: never reaped, never counted as a leak
    const other = (BigInt(t.creation ?? "0") - 10_000_000n).toString();
    expect(pidStatus(pidcheck, t.pid, other)).toMatchObject({ alive: true, matches: false });
    for (const entry of ledger.entries().filter((e) => e.role === "owned" && e.label.startsWith("spawn_process")))
      expect(entry.creation100ns, entry.label).toMatch(/^\d{15,}$/u);
    await ok(bea, "close_session", { session_id: t.id });
    expect(pidStatus(pidcheck, t.pid, t.creation).alive).toBe(false);
  } finally {
    await bea.close();
  }
};

const mustHave7 = async (): Promise<void> => {
  const outDir = await mkdtemp(join(tmpdir(), "bea-lifecycle-"));
  scratch.push(outDir);
  const bea = await connectBea({ ledger, gates: { override_function: true } });
  const owned: { pid: number; creation: string | null }[] = [];
  let outcome;
  try {
    const t = await startGame(bea, ["--speed", "20", "--throttle", "0.125"]);
    owned.push(t);
    const car = BigInt(
      String(
        (
          (
            await ok(bea, "read_memory", {
              session_id: t.id,
              address: "game_sim.exe!g_world",
              deref: [8],
              size: 8,
              view: "ptr",
            })
          )["values"] as unknown[]
        )[0],
      ),
    );
    const kinds: string[] = [];
    const add = (r: Obj): void => {
      kinds.push(String((r["instrument"] as { kind: string }).kind));
    };
    add(
      await ok(bea, "hook_function", { session_id: t.id, address: "game_sim.exe!physics_step", duration_ms: 60_000 }),
    );
    add(
      await ok(bea, "watch_memory", {
        session_id: t.id,
        address: `0x${(car + 8n).toString(16)}`,
        size: 4,
        access: "write",
        duration_ms: 60_000,
      }),
    );
    add(
      await ok(bea, "trace_execution", {
        session_id: t.id,
        on_call: "game_sim.exe!physics_step",
        invocations: 1000,
        mode: "coverage",
        duration_ms: 60_000,
      }),
    );
    add(
      await ok(bea, "override_function", {
        session_id: t.id,
        address: "game_sim.exe!telemetry_sample",
        mode: "return",
        returns: "f32",
        return_value: 123,
        duration_ms: 60_000,
      }),
    );
    const scan = await ok(bea, "scan_memory", {
      session_id: t.id,
      value_type: "f32",
      compare: "unknown",
      wait_ms: 0,
    });
    expect(String(scan["scan_id"])).toMatch(/^scan_/u);
    // the api profile on a second (paused) target: installed before resume, so it stays active
    const behavior = await ok(bea, "spawn_process", {
      program: artifact("behavior").path,
      args: ["--out-dir", outDir],
    });
    owned.push(identityOf(behavior));
    add(
      await ok(bea, "trace_api", {
        session_id: String(behavior["session_id"]),
        profiles: ["file"],
        duration_ms: 60_000,
      }),
    );
    expect(kinds.sort()).toEqual(["api", "hook", "override", "trace", "watch"]);
    for (const target of owned) expect(alive(target.pid, target.creation)).toBe(true);
  } finally {
    outcome = await bea.close();
  }
  expect(outcome).toMatchObject({ exitCode: 0, signal: null });
  expect(outcome.closeMs).toBeLessThan(2000);
  await expectGone(owned, 5000);
};

/**
 * Review fix LIFE-3: Frida extracts ~45 MB into the BEA-owned run directory <BEA_HOME>/tmp/frida/<run>; a hard-killed
 * server never reaches DeviceManager.close, so the next server's first attach reclaims it, and a graceful exit removes
 * its own.
 */
const mustHave9 = async (): Promise<void> => {
  const home = await createTempHome("lifecycle-frida-temp");
  const fridaRoot = join(home.beaHome, "tmp", "frida");
  try {
    const first = await connectBea({ ledger, home });
    let leftover: string[];
    try {
      const owned = await startGame(first);
      leftover = await readdir(fridaRoot);
      expect(leftover).toHaveLength(1);
      expect((await readdir(join(fridaRoot, leftover[0] ?? ""))).some((name) => name.startsWith("frida-"))).toBe(true);
      const killed = spawnSync(TASKKILL, ["/F", "/PID", String(first.pid)], { encoding: "utf8", windowsHide: true });
      expect(killed.status, killed.stderr).toBe(0);
      await expectGone([owned], 10_000);
    } finally {
      await first.close();
    }
    expect(await readdir(fridaRoot)).toEqual(leftover);
    const second = await connectBea({ ledger, home });
    let outcome;
    try {
      await startGame(second);
      const now = await readdir(fridaRoot);
      expect(now).toHaveLength(1);
      expect(now).not.toContain(leftover[0]);
    } finally {
      outcome = await second.close();
    }
    expect(outcome).toMatchObject({ exitCode: 0, signal: null });
    expect(await readdir(fridaRoot)).toEqual([]);
  } finally {
    await home.cleanup();
  }
};

describe.skipIf(skip !== false)(`S6 §10.9 lifecycle must-haves on the built server${skipNote(skip)}`, () => {
  it.skipIf(emuReason !== false)(
    `1+5. graceful close (stdin EOF) with 3 owned + 1 attached + 1 emulation session: exit 0 < 2 s, owned and bridge gone, the attached target runs on${skipNote(emuReason)}`,
    mustHave1,
    120_000,
  );
  it.skipIf(emuReason !== false)(
    `2. hard kill of the server (taskkill /F): the jobhost chain kills every owned target, the bridge dies, the attached target lives${skipNote(emuReason)}`,
    mustHave2,
    120_000,
  );
  it(
    "3. a target that dies on its own settles pending resume and wait calls; an externally killed one settles a wait with target_exited",
    mustHave3,
    120_000,
  );
  it(
    "4. cancelling wait, a running scan and a trace_api window: the server keeps serving, the instruments stay listed and a later stop works",
    mustHave4,
    180_000,
  );
  it(
    "6. straggler policy: behavior's child outlives the root; the session is exited with an active process, and close kills it",
    mustHave5,
    120_000,
  );
  it(
    "7. pid-reuse guard: owned entries carry creation times, and a live pid with another creation time is not ours",
    mustHave6,
    60_000,
  );
  it(
    "8. shutdown with an active hook, api, watch, trace, override and scan: exit 0 in < 2 s and every owned target is dead",
    mustHave7,
    180_000,
  );
  it(
    "9. Frida's extraction lives in BEA_HOME: a hard-killed server's is reclaimed by the next server, a graceful exit removes its own",
    mustHave9,
    120_000,
  );
});
