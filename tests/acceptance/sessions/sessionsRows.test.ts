import { spawnSync, type ChildProcess } from "node:child_process";
import { copyFile, mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { Deadline } from "../../../src/domain/deadline.js";
import { LIMITATIONS } from "../../../src/domain/evidence/limitations.js";
import type { PiId } from "../../../src/domain/ids.js";
import { NO_LITERALS } from "../../../src/domain/redaction/literals.js";
import { ok } from "../../../src/domain/result.js";
import {
  fixtureArtifact,
  fridaSkip,
  gccSkip,
  jobhostSkip,
  loadFixtures,
  skipNote,
  type FixtureArtifact,
  type FixtureManifest,
} from "../../support/acceptance/fixtures.js";
import { OwnedPidLedger, pidStatus } from "../../support/process/ownedPidLedger.js";
import {
  errorOf,
  spawnOwned,
  startForeign,
  startInProcessBea,
  value,
  type InProcessBea,
  type Output,
} from "./support/inProcessBea.js";

/**
 * The S6 §10.8 rows of the session tools that sessionsInProcess.test.ts does not cover, against the real composition
 * (DESIGN §8.4 with its edits and the wave rule: READY through LiveSession.waitFor, code bytes through raw readMemory):
 * list_processes rows and paging; attach by name; the BEA_ALLOW_ANTI_CHEAT override; cancelled spawns leave nothing
 * behind; a root exit with a straggler (session_status containment) and close killing both; an attached close that
 * reverts the agent's patch (physics_step equals the file in a fresh session); the crash site of crashy av-write
 * through LiveSession.crash (moved from WP4 to WP5 in §8.4). Every process is BEA-owned (ledger: dead after close) or
 * test-spawned (ledger: alive after close); copies of the fixtures carry unique image names so a by-name listing or
 * attach can only match this file's processes.
 */
const TASKLIST = join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", "tasklist.exe");
const skip = fridaSkip() || jobhostSkip() || gccSkip();
const GAME_ARGS = ["--frames", "0", "--no-threads"] as const;

let manifest: FixtureManifest;
let game: FixtureArtifact;
let ledger: OwnedPidLedger;
let pidcheck: string | null = null;
let scratch: string;
const servers: InProcessBea[] = [];
const foreign: ChildProcess[] = [];

const server = async (options: Parameters<typeof startInProcessBea>[0] = {}): Promise<InProcessBea> => {
  const bea = await startInProcessBea({ label: "core-rows", ...options });
  servers.push(bea);
  return bea;
};

/** A copy of a fixture under a name no other process on this machine has. */
const uniqueCopy = async (artifact: FixtureArtifact, stem: string): Promise<string> => {
  const dir = await mkdtemp(join(scratch, `${stem}-`));
  const target = join(dir, `${stem}_${process.pid.toString(36)}${Date.now().toString(36)}.exe`);
  await copyFile(artifact.path, target);
  return target;
};

/** Pids of every running process with this image name (tasklist, independent of Frida). */
const pidsNamed = (image: string): number[] => {
  const run = spawnSync(TASKLIST, ["/FI", `IMAGENAME eq ${image}`, "/FO", "CSV", "/NH"], {
    encoding: "utf8",
    windowsHide: true,
  });
  return [...run.stdout.matchAll(/^"[^"]*","(\d+)"/gmu)].map((m) => Number(m[1]));
};

const frameCount = (out: readonly string[]): number => out.join("").split("FRAME ").length - 1;
const hex = (n: number | bigint): `0x${string}` => `0x${n.toString(16)}`;

beforeAll(async () => {
  if (skip !== false) return;
  const loaded = await loadFixtures();
  if ("unavailable" in loaded) throw new Error(loaded.unavailable);
  manifest = loaded;
  const artifact = fixtureArtifact(manifest, "game_sim");
  if (artifact === null) throw new Error("fixtures unavailable");
  game = artifact;
  pidcheck = fixtureArtifact(manifest, "pidcheck")?.path ?? null;
  ledger = new OwnedPidLedger(pidcheck);
  scratch = await mkdtemp(join(tmpdir(), "bea-core-rows-"));
});

afterAll(async () => {
  if (skip !== false) return;
  for (const bea of servers) await bea.close();
  try {
    await ledger.assertClean();
  } finally {
    await ledger.killAttachTargets();
    for (const child of foreign) if (child.exitCode === null) child.kill();
    await vi.waitFor(() => expect(foreign.every((c) => c.exitCode !== null || c.signalCode !== null)).toBe(true), {
      interval: 50,
      timeout: 5000,
    });
    await rm(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
}, 60_000);

describe.skipIf(skip !== false)(`list_processes and attach_process by name${skipNote(skip)}`, () => {
  it("rows carry pid, path and start time; paging totals agree; a unique name attaches; close leaves it running", async () => {
    const bea = await server();
    const exe = await uniqueCopy(game, "gsim_name");
    const image = basename(exe);
    const first = await startForeign(ledger, exe, GAME_ARGS);
    foreign.push(first.child);
    const firstPid = first.child.pid ?? 0;

    const listed = value(await bea.call("list_processes", { filter: image }));
    expect(listed["rows"]).toEqual([expect.objectContaining({ pid: firstPid, name: image, bea_session: null })]);
    const row = (listed["rows"] as { path: string | null; started: string | null }[])[0];
    expect(row?.path?.toLowerCase()).toBe(exe.toLowerCase());
    expect(Number.isNaN(Date.parse(row?.started ?? ""))).toBe(false);
    expect(Math.abs(Date.parse(row?.started ?? "") - Date.now())).toBeLessThan(120_000);

    const attached = value(await bea.call("attach_process", { name: image.toUpperCase() }));
    expect(attached).toMatchObject({
      state: "running",
      identity: { pid: firstPid, ownership: "attached", start_time: { source: "os-creation-time" } },
      containment: { kind: "none", kill_on_close: false },
    });
    expect(attached["limitations"]).toContain(LIMITATIONS.AGENT_FOOTPRINT);
    const id = attached["session_id"] as string;
    expect(value(await bea.call("list_processes", { filter: image }))["rows"]).toEqual([
      expect.objectContaining({ pid: firstPid, bea_session: id }),
    ]);
    expect(value(await bea.call("close_session", { session_id: id }))).toMatchObject({
      target_state: "detached-running",
    });
    const atClose = frameCount(first.out);
    await vi.waitFor(() => expect(frameCount(first.out)).toBeGreaterThan(atClose), { interval: 50, timeout: 5000 });

    // two instances: page through them one row at a time; the totals agree and the pages cover both exactly once
    const second = await startForeign(ledger, exe, GAME_ARGS);
    foreign.push(second.child);
    const p1 = value(await bea.call("list_processes", { filter: image, limit: 1 }));
    expect(p1["page"]).toEqual({ offset: 0, limit: 1, total: 2, next_offset: 1 });
    const p2 = value(await bea.call("list_processes", { filter: image, offset: 1, limit: 1 }));
    expect(p2["page"]).toEqual({ offset: 1, limit: 1, total: 2, next_offset: null });
    const paged = [...(p1["rows"] as { pid: number }[]), ...(p2["rows"] as { pid: number }[])].map((r) => r.pid);
    expect(paged.sort()).toEqual([firstPid, second.child.pid ?? 0].sort());
    const past = value(await bea.call("list_processes", { filter: image, offset: 5 }));
    expect(past).toMatchObject({ rows: [], page: { total: 2, next_offset: null } });
  }, 90_000);
});

describe.skipIf(skip !== false)(`spawn_process overrides and cancellation${skipNote(skip)}`, () => {
  it("BEA_ALLOW_ANTI_CHEAT=1 spawns an image beside an anti-cheat folder and reports the signal", async () => {
    const bea = await server({ env: { BEA_ALLOW_ANTI_CHEAT: "1" } });
    const dir = await mkdtemp(join(scratch, "ac-"));
    await mkdir(join(dir, "BattlEye"), { recursive: true });
    await mkdir(join(dir, "bin"), { recursive: true });
    const exe = join(dir, "bin", "game_sim.exe");
    await copyFile(game.path, exe);
    const spawned = await spawnOwned({ bea, ledger }, exe, GAME_ARGS);
    expect(spawned["anti_cheat_signals"]).toEqual(["dir:BattlEye"]);
    expect(spawned["limitations"]).toContain(LIMITATIONS.ANTI_CHEAT_ALLOWED);
    value(await bea.call("close_session", { session_id: spawned["session_id"] }));
    // without the override the same image is refused before anything starts
    const strict = await server();
    expect(errorOf(await strict.call("spawn_process", { program: exe }))).toMatchObject({
      _tag: "AccessDenied",
      reason: "anti-cheat-detected",
    });
    expect(strict.app.services.sessions.list()).toEqual([]);
  }, 60_000);

  it("a spawn cancelled at any point of its startup leaves no process and no session", async () => {
    const bea = await server();
    const exe = await uniqueCopy(game, "gsim_cancel");
    const image = basename(exe);
    // the warm startup time (the first spawn also loads Frida)
    let startupMs = 0;
    for (let i = 0; i < 2; i += 1) {
      const t0 = performance.now();
      const spawned = await spawnOwned({ bea, ledger }, exe, GAME_ARGS);
      startupMs = performance.now() - t0;
      value(await bea.call("close_session", { session_id: spawned["session_id"] }));
    }
    const outcomes: string[] = [];
    for (const fraction of [0.1, 0.25, 0.4, 0.55, 0.7, 0.85]) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(new Error("test cancel")), Math.max(1, startupMs * fraction));
      const result = await bea.call("spawn_process", { program: exe, args: [...GAME_ARGS] }, controller.signal);
      clearTimeout(timer);
      if (result.ok) {
        ledger.recordIdentity(result.value["identity"] as Output, `spawn ${image} (not cancelled)`);
        value(await bea.call("close_session", { session_id: result.value["session_id"] }));
        outcomes.push("completed");
      } else {
        expect(result.error._tag).toBe("Cancelled");
        outcomes.push(`cancelled@${fraction}`);
      }
      // whatever the stage, nothing of this image survives and no live session remains
      await vi.waitFor(() => expect(pidsNamed(image)).toEqual([]), { interval: 50, timeout: 5000 });
      expect(bea.app.services.sessions.list().filter((s) => s.state !== "closed")).toEqual([]);
    }
    expect(outcomes.filter((o) => o.startsWith("cancelled")).length, outcomes.join(", ")).toBeGreaterThanOrEqual(2);
  }, 120_000);
});

describe.skipIf(skip !== false)(`stragglers and the attached close${skipNote(skip)}`, () => {
  it("a root exit with a straggler: session_status exited with active processes; close kills root and child in < 2 s", async () => {
    const bea = await server();
    const behavior = fixtureArtifact(manifest, "behavior");
    if (behavior === null) throw new Error("fixtures unavailable");
    const outDir = await mkdtemp(join(scratch, "behavior-"));
    const spawned = await spawnOwned({ bea, ledger }, behavior.path, [
      "--out-dir",
      outDir,
      "--steps",
      "process",
      "--child-hold-ms",
      "30000",
    ]);
    const id = spawned["session_id"] as string;
    const resumed = value(await bea.call("resume_process", { session_id: id, wait_ms: 20_000, until: "exit" }));
    expect(resumed).toMatchObject({ state: "exited", exit: { code: 0 }, crash: null });
    const status = value(await bea.call("session_status", { session_id: id }));
    const tail = String(status["output_tail"]);
    ledger.recordChildLines(tail, "behavior --steps process");
    const child = Number(/CHILD pid=(\d+)/u.exec(tail)?.[1] ?? "0");
    expect(child).toBeGreaterThan(0);
    expect(tail).toContain("DONE ok=1");
    expect(status).toMatchObject({ state: "exited", kind: "live" });
    const containment = status["containment"] as { active_processes: number | null; children_seen: number[] };
    expect(containment.active_processes).toBeGreaterThanOrEqual(1);
    expect(containment.children_seen).toContain(child);
    expect(pidStatus(pidcheck, child).alive).toBe(true);

    const started = performance.now();
    const closed = value(await bea.call("close_session", { session_id: id }));
    expect(performance.now() - started).toBeLessThan(2000);
    expect(closed).toMatchObject({ already_closed: false, target_state: "killed" });
    await vi.waitFor(() => expect(pidStatus(pidcheck, child).alive).toBe(false), { interval: 50, timeout: 3000 });
    const root = (spawned["identity"] as { pid: number }).pid;
    expect(pidStatus(pidcheck, root).alive).toBe(false);
  }, 90_000);

  it("an attached close reverts the agent's patch: physics_step equals the file in a fresh session; the target runs on", async () => {
    const bea = await server();
    const target = await startForeign(ledger, game.path, GAME_ARGS);
    foreign.push(target.child);
    const pid = target.child.pid ?? 0;
    const rva = game.pe.exportRvas["physics_step"] ?? 0;
    const image = await bea.app.services.pe.images.open(game.path);
    if (!image.ok) throw new Error(JSON.stringify(image.error));

    const readCode = async (id: string, base: bigint) =>
      value(
        await bea.raw(id, async (s, op) => {
          const read = await s.agent.call("readMemory", { address: hex(base + BigInt(rva)), size: 32 }, { op });
          return read.ok ? ok(Buffer.from(read.value.data)) : read;
        }),
      );
    const baseOf = (out: Output): bigint => BigInt((out["main_module"] as { base: string }).base);

    const first = value(await bea.call("attach_process", { pid }));
    const id = first["session_id"] as string;
    const base = baseOf(first);
    const fileBytes = Buffer.from(await image.value.imageBytes(rva, 32, base));
    expect((await readCode(id, base)).equals(fileBytes)).toBe(true);
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
            lifetime: { duration_ms: 60_000, max_hits: 1_000_000, clock: "install" },
            observe_agent_calls: false,
            force_caution: false,
            label: "core-attached-revert",
          },
          { op },
        ),
      ),
    );
    expect(hook.instrument_id).toBeTruthy();
    expect((await readCode(id, base)).equals(fileBytes)).toBe(false);
    expect(value(await bea.call("close_session", { session_id: id }))).toMatchObject({
      already_closed: false,
      target_state: "detached-running",
    });
    const atClose = frameCount(target.out);
    await vi.waitFor(() => expect(frameCount(target.out)).toBeGreaterThan(atClose), { interval: 50, timeout: 5000 });

    const fresh = value(await bea.call("attach_process", { pid }));
    const freshId = fresh["session_id"] as string;
    expect(baseOf(fresh)).toBe(base);
    expect((await readCode(freshId, base)).equals(fileBytes)).toBe(true);
    value(await bea.call("close_session", { session_id: freshId }));
    expect(target.child.exitCode).toBeNull();
  }, 90_000);
});

describe.skipIf(skip !== false)(`crash sites, exit flush and recorded status${skipNote(skip)}`, () => {
  it("crashy av-write: the CrashReport's pc is the manifest crash site in the exported crash function", async () => {
    const bea = await server();
    const crashy = fixtureArtifact(manifest, "crashy");
    if (crashy === null) throw new Error("fixtures unavailable");
    const spawned = await spawnOwned({ bea, ledger }, crashy.path, ["av-write", "--delay-ms", "50"]);
    const id = spawned["session_id"] as string;
    const resumed = value(await bea.call("resume_process", { session_id: id, wait_ms: 20_000, until: "exit" }));
    const site = (crashy.expectations["crashWrite"] as { rva: number }).rva;
    const fn = crashy.pe.exportRvas["crash_write"] ?? 0;
    const offset = site - fn;
    const pc = {
      at: `crashy.exe+${hex(site)}`,
      static: `crashy.exe:${hex(0x140000000 + site)}`,
      func: `crashy.exe+${hex(fn)}`,
      sym: offset === 0 ? "crash_write" : `crash_write+${hex(offset)}`,
    };
    expect(resumed).toMatchObject({
      state: "exited",
      exit: { code_hex: "0xc0000005", name: "STATUS_ACCESS_VIOLATION" },
      crash: { type: "access-violation", memory: { op: "write" }, pc },
    });
    expect(value(await bea.raw(id, (s, op) => s.crash(op)))).toMatchObject({ pc });
    expect(value(await bea.call("session_status", { session_id: id }))).toMatchObject({ crash: { pc } });
    // detail:"complete" is recorded (bea.session.status) even after the target died
    const complete = value(await bea.call("session_status", { session_id: id, detail: "complete" }));
    expect(complete).toMatchObject({ state: "exited", crash: { pc }, predicate_type: "bea.session.status" });
    expect(complete["evidence_id"]).toMatch(/^ev_[0-9a-f]{64}$/u);
    value(await bea.call("close_session", { session_id: id }));
  }, 60_000);

  it("a fast exit after resume: the exit flush delivers every exception row and the output before the process dies", async () => {
    const bea = await server();
    const crashy = fixtureArtifact(manifest, "crashy");
    if (crashy === null) throw new Error("fixtures unavailable");
    const spawned = await spawnOwned({ bea, ledger }, crashy.path, ["handled", "--delay-ms", "0"]);
    const id = spawned["session_id"] as string;
    const resumed = value(await bea.call("resume_process", { session_id: id, wait_ms: 20_000, until: "exit" }));
    expect(resumed).toMatchObject({ state: "exited", exit: { code: 0, kind: "normal" }, crash: null });
    const op = { opId: 1, name: "test", signal: new AbortController().signal, deadline: Deadline.after(20_000) };
    const recording = bea.app.services.recordings.list(id).find((r) => r.create.kind === "exceptions");
    let handled = 0;
    for await (const event of bea.app.services.recordings.events(recording?.id ?? "", {}, op))
      if (event["type"] === "access-violation") handled += typeof event["repeat"] === "number" ? event["repeat"] : 1;
    expect(handled).toBe(10);
    const status = value(await bea.call("session_status", { session_id: id }));
    expect(String(status["output_tail"])).toContain("HANDLED count=10");
    expect(value(await bea.call("close_session", { session_id: id }))).toMatchObject({ target_state: "exited" });
  }, 60_000);

  it("an instrument the agent ends at its lifetime: its recording finishes and its effect expires (S2 §6.3)", async () => {
    const bea = await server();
    const spawned = await spawnOwned({ bea, ledger }, game.path, GAME_ARGS);
    const id = spawned["session_id"] as string;
    value(await bea.call("resume_process", { session_id: id }));
    // what an instrument tool does (wave rule: raw RPC + ports): install, bind the stream, apply the effect, create
    // the recording that cites both
    const installed = value(
      await bea.raw(id, async (s, op) => {
        const hook = await s.agent.call(
          "hookInstall",
          {
            target: { module: "game_sim.exe", export: "physics_step" },
            engine: "js",
            relocation: "auto",
            capture: { args: [], ret: null, backtrace: null, registers: "none" },
            emit: "enter",
            probe: false,
            hidden_ret_ptr: false,
            lifetime: { duration_ms: 300, max_hits: 1_000_000, clock: "install" },
            observe_agent_calls: false,
            force_caution: false,
            label: "core-lifetime",
          },
          { op },
        );
        if (!hook.ok) return hook;
        const channel = hook.value.stream_id;
        const bound = await s.streams.bind(channel, {
          source: { kind: "hook", instance_id: s.instanceId, effect_id: null, channel },
          encoding: { kind: "json-rows", row_kind: "hook/1" },
          decoders: null,
          literals: NO_LITERALS,
        });
        if (!bound.ok) return bound;
        const effect = await bea.app.services.evidence.effects.apply({
          instance_id: s.instanceId,
          kind: "hook-installed",
          target: { address: null, size: null, threads: "all" },
          parameters: { agent_instrument: hook.value.instrument_id },
          stream_ids: [bound.value.stream_id],
          applied_by: "acceptance",
          literals: NO_LITERALS,
        });
        if (!effect.ok) return effect;
        const recording = bea.app.services.recordings.create({
          sessionId: id,
          kind: "hook",
          agentInstrumentId: hook.value.instrument_id,
          agentStream: channel,
          streamId: bound.value.stream_id,
          effectId: effect.value.effect_id,
          durationMs: 300,
          maxEvents: null,
          startsAtResume: false,
          decoders: null,
        });
        return ok({ effectId: effect.value.effect_id, recordingId: recording.id });
      }),
    );
    const effects = bea.app.services.evidence.effects;
    await vi.waitFor(() => expect(effects.state(installed.effectId)?.status).toBe("expired"), {
      interval: 50,
      timeout: 5000,
    });
    expect(effects.state(installed.effectId)?.transitions.at(-1)).toMatchObject({ reason: "lifetime-duration" });
    expect(bea.app.services.recordings.get(installed.recordingId)?.view()).toMatchObject({
      state: "finished",
      end_reason: "duration",
    });
    expect(effects.active(spawned["instance_id"] as PiId).map((e) => e.effect.effect_id)).not.toContain(
      installed.effectId,
    );
    value(await bea.call("close_session", { session_id: id }));
  }, 60_000);

  it('session_status detail:"complete" on a running target is a recorded, anchored observation', async () => {
    const bea = await server();
    const spawned = await spawnOwned({ bea, ledger }, game.path, GAME_ARGS);
    const id = spawned["session_id"] as string;
    value(await bea.call("resume_process", { session_id: id }));
    const complete = value(await bea.call("session_status", { session_id: id, detail: "complete" }));
    expect(complete).toMatchObject({
      state: "running",
      predicate_type: "bea.session.status",
      confidence: "observed",
      authority: "live-process",
    });
    const summary = value(await bea.call("session_status", { session_id: id }));
    expect(summary["evidence_id"]).toBeNull();
    const record = value(await bea.call("get_evidence", { detail: "complete", id: complete["evidence_id"] }));
    expect((record["record"] as { value: Output }).value).toMatchObject({
      predicate_type: "bea.session.status",
      subject: { kind: "process-instance", instance_id: spawned["instance_id"] },
    });
    value(await bea.call("close_session", { session_id: id }));
  }, 60_000);
});
