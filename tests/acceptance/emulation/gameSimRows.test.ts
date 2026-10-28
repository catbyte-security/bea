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
} from "../../support/acceptance/fixtures.js";
import { realPython } from "../../support/emu/python.js";
import { expectToolSuccess } from "../../support/mcp/parseToolError.js";
import { OwnedPidLedger } from "../../support/process/ownedPidLedger.js";
import { createTempHome, type TempHome } from "../../support/workspace/tempHome.js";

/**
 * The S6 §10.8 rows that run on game_sim (owned) plus an emulation session captured from it
 * (emu_open {live_session_id}; DESIGN §8.4 errata: `live_session_id`, `capture` = `dump_path` of the bundle):
 *   emu_open      a live capture includes the module and the car region; the bundle replays with the same identity
 *   diff_function physics_step over 64 vectors -> equivalent-on-tested-inputs; mf_avx_dot (mathlib.dll loaded in
 *                 game_sim) -> unknown (the emulation leg stops on unsupported_instruction); `expected` with one wrong
 *                 value -> differ, an unknown_id and NO function-called effect (no live call is made)
 * Wave rule: spawn_process / resume_process / session_status / close_session / read_memory / get_evidence (earlier
 * waves) and call_function (WP11, the live leg) besides the emulation tools. Run from a snapshot (BEA_DIST_DIR).
 */
const skip = fridaSkip() || gccSkip() || jobhostSkip() || emuSkip();

let home: TempHome;
let bea: BeaConnection;
let ledger: OwnedPidLedger;
let game: FixtureArtifact;
let mathlib: FixtureArtifact;
let liveSession = "";
/** the capture of game_sim (game_sim.exe + mathlib.dll + the car), opened once in beforeAll */
let captured: Record<string, unknown> = {};
let carVa = "";

const f32 = (v: number): string => `0x${(new Uint32Array(new Float32Array([v]).buffer)[0] ?? 0).toString(16)}`;
const ok = async (name: string, args: Record<string, unknown>): Promise<Record<string, unknown>> =>
  expectToolSuccess(await bea.call(name, args));
const emuOpen = async (args: Record<string, unknown>): Promise<Record<string, unknown>> => {
  const opened = await ok("emu_open", args);
  const bridge = opened["bridge"] as { pid: number; child_pid: number };
  for (const pid of new Set([bridge.pid, bridge.child_pid])) ledger.recordOwned(pid, null, "emulation bridge");
  return opened;
};
const emuSession = (): string => String(captured["session_id"]);
type Leg = { leg: string; completed: number; by_status: Record<string, number>; effect_id?: string };
type Pair = {
  verdict: string;
  inconclusive: number;
  inconclusive_reasons: Record<string, number>;
  columns: { column: string; compared: number; exact_equal: number }[];
};
const legOf = (result: Record<string, unknown>, leg: string): Leg | undefined =>
  (result["legs"] as Leg[]).find((l) => l.leg === leg);
/** the Car of game_sim.c (0x80 bytes); tyres is a ptr_to field into a 4 x Tyre buffer, so both legs own it */
const CAR_BUFFERS = [
  {
    name: "car",
    size: 128,
    out: true,
    fields: [
      { name: "speed", offset: 0x08, type: "f32" },
      { name: "throttle", offset: 0x0c, type: "f32" },
      { name: "steer", offset: 0x10, type: "f32", default: "0.25" },
      { name: "rpm", offset: 0x14, type: "f32" },
      { name: "pos", offset: 0x18, type: "f32[]", count: 3 },
      { name: "vel", offset: 0x24, type: "f32[]", count: 3 },
      { name: "odometer", offset: 0x30, type: "f64" },
      { name: "frame", offset: 0x38, type: "u32" },
      { name: "tyres", offset: 0x40, type: "ptr_to", buffer: "tyres" },
      { name: "mass", offset: 0x48, type: "f32", default: "1200" },
      { name: "drag", offset: 0x4c, type: "f32", default: "0.05" },
    ],
  },
  {
    name: "tyres",
    size: 64,
    out: true,
    fields: [{ name: "t", offset: 0, type: "f32[]", count: 16, default: "1,20,0,0,1,20,0,0,1,20,0,0,1,20,0,0" }],
  },
];
/** how many bea.call.oracle records (live calls) the run holds */
const oracleRecords = async (): Promise<number> => {
  const summary = await ok("get_evidence", { filters: { predicate_type: "bea.call.oracle" }, limit: 1 });
  return Number((summary["summary"] as { matching: number }).matching);
};

beforeAll(async () => {
  if (skip !== false) return;
  const manifest = await loadFixtures();
  const sim = fixtureArtifact(manifest, "game_sim");
  const lib = fixtureArtifact(manifest, "mathlib");
  if (sim === null || lib === null) throw new Error("game_sim / mathlib fixtures unavailable");
  game = sim;
  mathlib = lib;
  ledger = new OwnedPidLedger(fixtureArtifact(manifest, "pidcheck")?.path ?? null);
  home = await createTempHome("wp14-gamesim");
  const python = realPython();
  bea = await connectBea({ home, ledger, ...(python === null ? {} : { env: { BEA_PYTHON: python } }) });
  // single-writer world (no input/engine threads); mathlib.dll is loaded at frame 1 (game_sim.c --load-mathlib-at)
  const spawned = await ok("spawn_process", { program: game.path, args: ["--no-threads", "--load-mathlib-at", "1"] });
  liveSession = String(spawned["session_id"]);
  await ok("resume_process", { session_id: liveSession });
  const tail = await vi.waitFor(
    async () => {
      const out = String((await ok("session_status", { session_id: liveSession }))["output_tail"] ?? "");
      if (!/MATHLIB loaded=1/u.test(out)) throw new Error(`mathlib not loaded yet: ${out.slice(-200)}`);
      return out;
    },
    { timeout: 15_000, interval: 25 },
  );
  const car = /car=(?:0x)?([0-9a-fA-F]+)/u.exec(tail)?.[1];
  if (car === undefined) throw new Error(`no READY car pointer in ${tail}`);
  carVa = `0x${BigInt(`0x${car}`).toString(16)}`;
  captured = await emuOpen({
    live_session_id: liveSession,
    capture_modules: ["$main", "mathlib.dll"],
    capture_regions: [{ address: carVa, size: 0x80 }],
  });
}, 120_000);

afterAll(async () => {
  if (skip !== false) return;
  if (liveSession !== "") await bea.call("close_session", { session_id: liveSession });
  // the dump-backed emulation session is still open at shutdown: exit 0, and no bridge or target is left
  const outcome = await bea.close();
  expect(outcome.exitCode).toBe(0);
  await vi.waitFor(async () => expect((await ledger.audit()).leaks).toEqual([]), { timeout: 5_000, interval: 25 });
  await ledger.assertClean();
  await home.cleanup();
});

describe.skipIf(skip !== false)(`emu_open on a live game_sim (S6 §10.8)${skipNote(skip)}`, () => {
  it("a live capture includes game_sim.exe, mathlib.dll and the car region; the bundle replays with the same identity", async () => {
    expect(captured).toMatchObject({
      source: "dump",
      primary: { name: "game_sim.exe", sha256: game.artifactSha256 },
      fp: { source: "dump-thread" },
      capture: { modules: 2 },
    });
    const capture = captured["capture"] as { evidence_id: string; bundle_path: string };
    expect(capture.evidence_id).toMatch(/^ev_/u);
    const modules = captured["modules"] as { name: string; captured: string; sha256: string | null }[];
    expect(modules.find((m) => m.name === "game_sim.exe")).toMatchObject({
      captured: "full",
      sha256: game.artifactSha256,
    });
    expect(modules.find((m) => m.name === "mathlib.dll")).toMatchObject({
      captured: "full",
      sha256: mathlib.artifactSha256,
    });
    // the car region is in the bundle: the emulated memory holds the live Car (magic 'CAR1', id, mass, drag)
    const emulated = await ok("read_memory", { session_id: emuSession(), address: carVa, size: 0x80 });
    const liveRead = await ok("read_memory", { session_id: liveSession, address: carVa, size: 0x80 });
    expect(emulated).toMatchObject({ complete: true, authority: "emulation" });
    const emuBytes = Buffer.from(String(emulated["data"]), "hex");
    const liveBytes = Buffer.from(String(liveRead["data"]), "hex");
    expect(emuBytes.readUInt32LE(0)).toBe(0x31524143);
    for (const [from, to] of [
      [0x00, 0x10],
      [0x40, 0x50],
    ] as const)
      expect(
        emuBytes.subarray(from, to).equals(liveBytes.subarray(from, to)),
        `car bytes 0x${from.toString(16)}..`,
      ).toBe(true);
    // A.4 #2: "capture replays with the same sha256" = emu_open {dump_path} of that bundle
    const replay = await emuOpen({ dump_path: capture.bundle_path });
    try {
      expect(replay).toMatchObject({
        source: "dump",
        bundle_id: captured["bundle_id"],
        primary: { sha256: game.artifactSha256 },
      });
    } finally {
      await ok("close_session", { session_id: String(replay["session_id"]) });
    }
  });
});

describe.skipIf(skip !== false)(`diff_function on game_sim vs its capture (S6 §10.8)${skipNote(skip)}`, () => {
  it("physics_step over 64 vectors (live vs emulation) is equivalent-on-tested-inputs, every column bit-exact", async () => {
    const n = 64;
    const result = await ok("diff_function", {
      live_session_id: liveSession,
      emu_session_id: emuSession(),
      address: "game_sim.exe!physics_step",
      signature: { args: [{ type: "buffer_ptr", buffer: "car" }, { type: "f32" }], returns: "f32" },
      buffers: CAR_BUFFERS,
      vectors: {
        columns: {
          // speeds across the 80 m/s limiter, throttles 0..1, four step sizes
          "car.speed": Array.from({ length: n }, (_, i) => f32(Math.fround((i * 1.37) % 90))),
          "car.throttle": Array.from({ length: n }, (_, i) => ((i * 7) % 11) / 10),
          arg1: Array.from({ length: n }, (_, i) => [1 / 60, 0.5, 0.001, 0.1][i % 4] ?? 0),
        },
      },
    });
    expect(result).toMatchObject({ verdict: "equivalent-on-tested-inputs", predicate_type: "bea.diff" });
    expect(legOf(result, "live")).toMatchObject({ completed: n, by_status: { returned: n } });
    expect(legOf(result, "emulation")).toMatchObject({ completed: n, by_status: { returned: n } });
    const pair = (result["pairs"] as Pair[])[0];
    expect(pair?.columns.map((c) => c.column)).toContain("tyres.t");
    for (const column of pair?.columns ?? []) expect(column.exact_equal, column.column).toBe(n);
  });

  it("mf_avx_dot (mathlib.dll loaded in game_sim) is unknown: the emulation leg stops on the first VEX instruction", async () => {
    const vec = (name: string, values: string) => ({
      name,
      size: 32,
      fields: [{ name: "v", offset: 0, type: "f32[]", count: 8, default: values }],
    });
    const result = await ok("diff_function", {
      live_session_id: liveSession,
      emu_session_id: emuSession(),
      address: "mathlib.dll!mf_avx_dot",
      signature: {
        args: [{ type: "buffer_ptr", buffer: "a" }, { type: "buffer_ptr", buffer: "b" }, { type: "i32" }],
        returns: "f32",
      },
      buffers: [vec("a", "1,2,3,4,5,6,7,8"), vec("b", "1,1,1,1,1,1,1,1")],
      vectors: { columns: { arg2: [8, 4] } },
    });
    expect(result["verdict"]).toBe("unknown");
    expect(String(result["unknown_id"])).toMatch(/^unk_/u);
    expect(legOf(result, "emulation")).toMatchObject({ completed: 2, by_status: { unsupported_instruction: 2 } });
    // the live oracle computes the dot products (36 and 10): the inconclusive vectors are the emulator's limit
    expect(legOf(result, "live")).toMatchObject({ by_status: { returned: 2 } });
    const rows = result["rows"] as { legs: { leg: string; r: string | null }[] }[];
    expect(rows.map((r) => r.legs.find((l) => l.leg === "live")?.r)).toEqual([f32(36), f32(10)]);
    const pair = (result["pairs"] as Pair[])[0];
    expect(pair).toMatchObject({ verdict: "unknown", inconclusive: 2 });
    expect(Object.keys(pair?.inconclusive_reasons ?? {}).every((reason) => reason.startsWith("emulation:"))).toBe(true);
  });

  it("from_recording: the hooked mix_args calls of the running game replay in the emulator bit-exactly", async () => {
    // S6 R9 / investigation 3: the expected leg is the recorded returns, the vectors are the recorded arguments
    const hooked = await ok("hook_function", {
      session_id: liveSession,
      address: "game_sim.exe!mix_args",
      capture: [
        { arg: 0, type: "i32" },
        { arg: 1, type: "f32" },
        { arg: 2, type: "f64" },
        { arg: 3, type: "f32" },
        { arg: 4, type: "i32" },
        { arg: 5, type: "f64" },
      ],
      returns: "f64",
      max_events: 12,
      wait_ms: 5_000,
    });
    const recording = hooked["instrument"] as { recording_id: string; state: string; events: number };
    expect(recording).toMatchObject({ state: "finished", events: 12 });
    const oracleBefore = await oracleRecords();
    const result = await ok("diff_function", {
      emu_session_id: emuSession(),
      address: "game_sim.exe!mix_args",
      signature: {
        args: [{ type: "i32" }, { type: "f32" }, { type: "f64" }, { type: "f32" }, { type: "i32" }, { type: "f64" }],
        returns: "f64",
      },
      from_recording: {
        recording_id: recording.recording_id,
        args: ["arg0", "arg1", "arg2", "arg3", "arg4", "arg5"],
        ret: "ret",
      },
    });
    expect(result).toMatchObject({
      verdict: "equivalent-on-tested-inputs",
      vectors: { count: 12, source: "recording" },
    });
    expect((result["legs"] as Leg[]).map((l) => [l.leg, l.completed])).toEqual([
      ["emulation", 12],
      ["expected", 12],
    ]);
    // mix_args(frame, 1.5f, 2.25, 3.125f, 7, 0.5) = frame + 14.375 for twelve consecutive frames
    const rows = result["rows"] as { legs: { leg: string; r: string | null }[] }[];
    const frames = rows.map((r) => {
      const bits = r.legs.find((l) => l.leg === "expected")?.r ?? "0x0";
      return new Float64Array(new BigUint64Array([BigInt(bits)]).buffer)[0] ?? Number.NaN;
    });
    expect(frames.map((v, i) => v - (frames[0] ?? 0) - i)).toEqual(Array.from({ length: 12 }, () => 0));
    expect(await oracleRecords()).toBe(oracleBefore);
  });

  it("expected with one wrong value: differ, an unknown_id, and no live call (no function-called effect)", async () => {
    const oracleBefore = await oracleRecords();
    const result = await ok("diff_function", {
      live_session_id: liveSession,
      emu_session_id: emuSession(),
      legs: ["emulation", "expected"],
      address: "game_sim.exe!tiny_add",
      signature: { args: [{ type: "i32" }, { type: "i32" }], returns: "i32" },
      vectors: { columns: { arg0: [1, 2, 3], arg1: [10, 20, 30] } },
      expected: { columns: { ret: [11, 22, 34] } },
    });
    expect(result["verdict"]).toBe("differ");
    expect(String(result["unknown_id"])).toMatch(/^unk_/u);
    expect((result["legs"] as Leg[]).map((l) => l.leg)).toEqual(["emulation", "expected"]);
    expect((result["legs"] as Leg[]).some((l) => l.effect_id !== undefined)).toBe(false);
    expect(result["effects_applied"]).toBeUndefined();
    expect(await oracleRecords()).toBe(oracleBefore);
  });
});
