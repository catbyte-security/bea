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
 * Live vs emulator acceptance (WP14 card; S5 §14.1 parity lane; DESIGN §8.4): the S5 §9.6 parity set (12 vectors,
 * golden bits) through diff_function (live oracle leg = call_function's exact-bits SEH-frame thunk, emulation leg =
 * the bridge), the dump-backed physics_step on the RUNTIME g_car equal to the live call (plus the uncaptured-fault
 * classification of a dump-backed session), and the hooked physics_step captured with emu_open {live_session_id}
 * (original bytes restored, CT-I6) equal to the live call. The server is closed with emulation sessions still open:
 * it must exit 0 and leave no bridge and no target behind (owned-PID ledger). Wave rule: spawn_process /
 * resume_process / close_session (wave 2), call_function, dump_memory, hook_function (wave 4) besides the emulation
 * tools. Run from a snapshot (BEA_DIST_DIR).
 */
const skip = fridaSkip() || gccSkip() || jobhostSkip() || emuSkip();

let home: TempHome;
let bea: BeaConnection;
let ledger: OwnedPidLedger;
let live: FixtureArtifact;
let liveSession = "";
let emuSession = "";

const f32 = (v: number): string => `0x${(new Uint32Array(new Float32Array([v]).buffer)[0] ?? 0).toString(16)}`;
const f64 = (v: number): string => `0x${new BigUint64Array(new Float64Array([v]).buffer)[0]?.toString(16) ?? "0"}`;
const ok = async (name: string, args: Record<string, unknown>): Promise<Record<string, unknown>> =>
  expectToolSuccess(await bea.call(name, args));
/** emu_open, with the bridge's launcher and interpreter recorded as owned processes */
const emuOpen = async (args: Record<string, unknown>): Promise<Record<string, unknown>> => {
  const opened = await ok("emu_open", args);
  const bridge = opened["bridge"] as { pid: number; child_pid: number };
  for (const pid of new Set([bridge.pid, bridge.child_pid])) ledger.recordOwned(pid, null, "emulation bridge");
  return opened;
};
const FOUR = { args: [{ type: "f32" }, { type: "f32" }, { type: "f32" }, { type: "f32" }], returns: "f32" };
const CAR_FIELDS = [
  { name: "speed", offset: 0, type: "f32" },
  { name: "counter", offset: 4, type: "i32" },
  { name: "pos", offset: 8, type: "f64[]", count: 3 },
];
const PHYSICS = { args: [{ type: "buffer_ptr", buffer: "car" }, { type: "f32" }], returns: "f32" };
type DiffRow = { legs: { leg: string; s: string; r: string | null }[] };
const legBits = (result: Record<string, unknown>, leg: string): (string | null)[] =>
  (result["rows"] as DiffRow[]).map((row) => row.legs.find((l) => l.leg === leg)?.r ?? null);
const liveDiff = (address: string, signature: unknown, extra: Record<string, unknown>) =>
  ok("diff_function", { live_session_id: liveSession, emu_session_id: emuSession, address, signature, ...extra });
/** both legs produced the same bits (or both stopped), and the live bits are the S5 §9.6 goldens */
const expectParity = (result: Record<string, unknown>, golden: (string | null)[]): void => {
  expect(result["verdict"]).toBe("equivalent-on-tested-inputs");
  expect(legBits(result, "live")).toEqual(golden);
  expect(legBits(result, "emulation")).toEqual(golden);
};

/** g_car's runtime address through call_function(ntdll!memcpy) is not needed: the export resolves per leg. */
const physicsCall = (session: string, initFrom: string) =>
  ok("call_function", {
    session_id: session,
    address: "live_fixture.exe!physics_step",
    signature: PHYSICS,
    buffers: [{ name: "car", size: 32, init_from: initFrom, out: true, fields: CAR_FIELDS }],
    args: [null, 0.016],
  });

beforeAll(async () => {
  if (skip !== false) return;
  const manifest = await loadFixtures();
  const artifact = fixtureArtifact(manifest, "live_fixture");
  if (artifact === null) throw new Error("live_fixture unavailable");
  live = artifact;
  ledger = new OwnedPidLedger(fixtureArtifact(manifest, "pidcheck")?.path ?? null);
  home = await createTempHome("wp14-parity");
  const python = realPython();
  bea = await connectBea({ home, ledger, ...(python === null ? {} : { env: { BEA_PYTHON: python } }) });
  // one frame, then a long sleep: g_car holds its RUNTIME state (counter 1, speed 0.157) while the tests run
  const spawned = await ok("spawn_process", { program: live.path, args: ["--sleep", "600000"] });
  liveSession = String(spawned["session_id"]);
  await ok("resume_process", { session_id: liveSession });
  await vi.waitFor(
    async () => {
      const read = await ok("call_function", {
        session_id: liveSession,
        address: "live_fixture.exe!car_energy",
        signature: { args: [{ type: "buffer_ptr", buffer: "car" }, { type: "f64" }], returns: "f64" },
        buffers: [{ name: "car", size: 32, init_from: "live_fixture.exe!g_car", fields: CAR_FIELDS }],
        args: [null, 2],
      });
      expect((read["call"] as { ret: { value: number } }).ret.value).toBeGreaterThan(0);
    },
    { timeout: 10_000, interval: 25 },
  );
  emuSession = String((await emuOpen({ image_path: live.path }))["session_id"]);
}, 120_000);

afterAll(async () => {
  if (skip !== false) return;
  if (liveSession !== "") await bea.call("close_session", { session_id: liveSession });
  // the image-backed emulation session is still open: stdio EOF must still end the server with exit 0, inside the
  // shutdown budget, and take the bridge with it (the WP4 row "exit 0 with a REAL emulation session open")
  const outcome = await bea.close();
  expect(outcome.exitCode).toBe(0);
  expect(outcome.closeMs).toBeLessThan(2_000);
  await vi.waitFor(async () => expect((await ledger.audit()).leaks).toEqual([]), { timeout: 5_000, interval: 25 });
  await ledger.assertClean();
  await home.cleanup();
});

describe.skipIf(skip !== false)(`live vs emulator parity on live_fixture.exe (S5 §9.6)${skipNote(skip)}`, () => {
  it("four_floats: qNaN payload, sNaN quieting, −0, denormals (RN) are bit-exact in both legs", async () => {
    const result = await liveDiff("live_fixture.exe!four_floats", FOUR, {
      vectors: {
        columns: {
          arg0: [f32(1), "0x7fc12345", "0x7fa00001", "0x80000000", "0x00000001"],
          arg1: [f32(2), f32(2), f32(2), "0x80000000", "0x00400000"],
          arg2: [f32(3), f32(3), f32(3), "0x80000000", "0x00000003"],
          arg3: [f32(4), f32(4), f32(4), "0x80000000", "0x00000005"],
        },
      },
      fp: { mxcsr: "0x1f80", fpcw: "0x27f" },
    });
    expect(result).toMatchObject({ fp: { source: "explicit" } });
    expectParity(result, ["0x449a4000", "0x7fc12345", "0x7fe00001", "0x80000000", "0x3480020"]);
  });

  it("four_floats: denormals under FTZ/DAZ (0x9FC0) flush to 0x0; RN 0x1F80 vs RZ 0x7F80 round apart", async () => {
    const denormal = {
      columns: { arg0: ["0x00000001"], arg1: ["0x00400000"], arg2: ["0x00000003"], arg3: ["0x00000005"] },
    };
    expectParity(
      await liveDiff("live_fixture.exe!four_floats", FOUR, {
        vectors: denormal,
        fp: { mxcsr: "0x9fc0", fpcw: "0x27f" },
      }),
      ["0x0"],
    );
    // the S5 lab vector (bea-lab/design-S5-emu/e6_live_vs_emu.mjs) whose exact sum lies between two f32 values
    const rounding = { columns: { arg0: [f32(1.0000001)], arg1: [f32(0.1)], arg2: [f32(0.3)], arg3: [f32(1e-8)] } };
    expectParity(
      await liveDiff("live_fixture.exe!four_floats", FOUR, {
        vectors: rounding,
        fp: { mxcsr: "0x1f80", fpcw: "0x27f" },
      }),
      ["0x447d4002"],
    );
    expectParity(
      await liveDiff("live_fixture.exe!four_floats", FOUR, {
        vectors: rounding,
        fp: { mxcsr: "0x7f80", fpcw: "0x27f" },
      }),
      ["0x447d4001"],
    );
  });

  it("mix_args (stack args) and car_energy (struct) are bit-exact and equal JS references", async () => {
    const mix = await liveDiff(
      "live_fixture.exe!mix_args",
      {
        args: [{ type: "i32" }, { type: "f32" }, { type: "f64" }, { type: "f32" }, { type: "i32" }, { type: "f64" }],
        returns: "f64",
      },
      { vectors: { columns: { arg0: [7], arg1: [1.5], arg2: [2.25], arg3: [3.125], arg4: [11], arg5: [0.5] } } },
    );
    expectParity(mix, ["0x4039600000000000"]);
    const energy = await liveDiff(
      "live_fixture.exe!car_energy",
      { args: [{ type: "buffer_ptr", buffer: "car" }, { type: "f64" }], returns: "f64" },
      {
        buffers: [
          {
            name: "car",
            size: 32,
            fields: [
              { name: "speed", offset: 0, type: "f32", default: "60" },
              { name: "pos", offset: 8, type: "f64[]", count: 3, default: "1,0,4" },
            ],
          },
        ],
        // the last vector is the S5 §9.6 golden (speed 12.5, pos[2] 3, mass 1200 -> 0x40f6e39000000000)
        vectors: {
          columns: {
            "car.speed": [60, 60, 60, 12.5],
            "car.pos": ["1,0,4", "1,0,4", "1,0,4", "0,0,3"],
            arg1: [1200, 0.5, 3, 1200],
          },
        },
      },
    );
    const reference = [
      [60, 4, 1200],
      [60, 4, 0.5],
      [60, 4, 3],
      [12.5, 3, 1200],
    ].map(([speed = 0, z = 0, mass = 0]) => f64(0.5 * mass * speed * speed + z));
    expectParity(energy, reference);
    expect(reference[3]).toBe("0x40f6e39000000000");
  });

  it("physics_step: two struct vectors (bits and out fields) and the NULL car (both legs fault: same outcome class)", async () => {
    const structs = await liveDiff("live_fixture.exe!physics_step", PHYSICS, {
      buffers: [{ name: "car", size: 32, out: true, fields: CAR_FIELDS }],
      vectors: {
        columns: { "car.speed": [10, 60], "car.counter": [3, 3], "car.pos": ["1,0,4", "1,0,4"], arg1: [0.016, 0.5] },
      },
    });
    expectParity(structs, ["0x412282e8", "0x426c0000"]);
    // ret plus every out-buffer field is compared (S5 §9.7): the struct bytes are equal too
    const pair = (structs["pairs"] as { columns: { column: string; compared: number; exact_equal: number }[] }[])[0];
    expect(pair?.columns.map((c) => c.column)).toEqual(["ret", "car.speed", "car.counter", "car.pos"]);
    for (const column of pair?.columns ?? []) expect(column.exact_equal, column.column).toBe(2);
    const nullCar = await liveDiff(
      "live_fixture.exe!physics_step",
      { args: [{ type: "ptr" }, { type: "f32" }], returns: "f32" },
      { vectors: { columns: { arg0: [0], arg1: [0.1] } } },
    );
    expect(nullCar["verdict"]).toBe("equivalent-on-tested-inputs");
    expect((nullCar["rows"] as DiffRow[])[0]?.legs.map((l) => [l.leg, l.s])).toEqual([
      ["live", "fault"],
      ["emulation", "fault"],
    ]);
  });
});

describe.skipIf(skip !== false)(`dump-backed and captured sessions of live_fixture.exe${skipNote(skip)}`, () => {
  it("dump-backed physics_step on the runtime g_car equals the live call; uncaptured memory is classified", async () => {
    const dumped = await ok("dump_memory", {
      session_id: liveSession,
      format: "bundle",
      bundle: { modules: ["$main"], regions: [{ address: "live_fixture.exe!g_car", size: 4096 }] },
    });
    const opened = await emuOpen({ dump_path: dumped["path"] });
    const dumpSession = String(opened["session_id"]);
    // CT-I9: the session's FP default is the captured thread's MXCSR/FPCW, not the Windows default
    expect(opened).toMatchObject({ source: "dump", fp: { source: "dump-thread" } });
    try {
      const emulated = await ok("emu_call", {
        session_id: dumpSession,
        address: "live_fixture.exe!physics_step",
        signature: PHYSICS,
        buffers: [{ name: "car", size: 32, init_from: "live_fixture.exe!g_car", out: true, fields: CAR_FIELDS }],
        args: [null, 0.016],
      });
      const liveCall = await physicsCall(liveSession, "live_fixture.exe!g_car");
      const emu = emulated["call"] as { ret: { bits: string }; outputs: Record<string, unknown> };
      const lv = liveCall["call"] as { ret: { bits: string }; outputs: Record<string, unknown> };
      expect(emu.ret.bits).toBe(lv.ret.bits);
      expect(emu.outputs["car.speed"]).toEqual(lv.outputs["car.speed"]);
      expect(emu.outputs["car.counter"]).toEqual(lv.outputs["car.counter"]);
      expect((emu.outputs["car.counter"] as { value: number }).value).toBeGreaterThanOrEqual(2);
      // S5 §10: a read of memory the process had mapped but the bundle did not capture is a HARNESS stop that names
      // the module to capture; a read of memory that was not mapped live (the NULL page) is a TARGET fault
      const fault = async (pointer: string) => {
        const result = await ok("emu_call", {
          session_id: dumpSession,
          address: "live_fixture.exe!physics_step",
          signature: { args: [{ type: "ptr" }, { type: "f32" }], returns: "f32" },
          args: [pointer, 0.016],
        });
        return result["call"] as {
          status: string;
          attribution: string;
          stop: { fault: { region: Record<string, unknown> } };
        };
      };
      const uncaptured = await fault("ntdll.dll+0x1000");
      expect(uncaptured).toMatchObject({ status: "fault", attribution: "harness" });
      expect(uncaptured.stop.fault.region).toMatchObject({
        module: "ntdll.dll",
        rva: "0x1000",
        capture: "not-captured-mapped-live",
      });
      expect(String(uncaptured.stop.fault.region["remediation"])).toContain("ntdll.dll");
      const nullPage = await fault("0x10");
      expect(nullPage).toMatchObject({ status: "fault", attribution: "target" });
      expect(nullPage.stop.fault.region).toMatchObject({ capture: "unmapped-live" });
    } finally {
      await bea.call("close_session", { session_id: dumpSession });
    }
  });

  it("hooked physics_step: emu_open {live_session_id} emulates the original code and equals the live call (CT-I6)", async () => {
    const hooked = await ok("hook_function", {
      session_id: liveSession,
      address: "live_fixture.exe!physics_step",
      duration_ms: 60_000,
    });
    expect(hooked).toBeDefined();
    const captured = await emuOpen({
      live_session_id: liveSession,
      capture_regions: [{ address: "live_fixture.exe!g_car", size: 4096 }],
    });
    const capturedSession = String(captured["session_id"]);
    expect(captured).toMatchObject({ source: "dump" });
    expect((captured["capture"] as { evidence_id: string }).evidence_id).toMatch(/^ev_/u);
    try {
      const emulated = await ok("emu_call", {
        session_id: capturedSession,
        address: "live_fixture.exe!physics_step",
        signature: PHYSICS,
        buffers: [{ name: "car", size: 32, init_from: "live_fixture.exe!g_car", out: true, fields: CAR_FIELDS }],
        args: [null, 0.016],
      });
      const liveCall = await physicsCall(liveSession, "live_fixture.exe!g_car");
      expect((emulated["call"] as { status: string }).status).toBe("returned");
      expect((emulated["call"] as { ret: { bits: string } }).ret.bits).toBe(
        (liveCall["call"] as { ret: { bits: string } }).ret.bits,
      );
    } finally {
      await bea.call("close_session", { session_id: capturedSession });
    }
  });
});
