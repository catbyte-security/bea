import { readFile } from "node:fs/promises";

import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { parsePe } from "../../../scripts/lib/peParse.mjs";
import { gateEnableInstruction } from "../../../src/domain/gates.js";
import { connectBea, type BeaConnection } from "../../support/acceptance/harness.js";
import {
  fixtureArtifact,
  fridaSkip,
  jobhostSkip,
  loadFixtures,
  skipNote,
  type FixtureArtifact,
} from "../../support/acceptance/fixtures.js";
import { expectToolSuccess, parseToolError } from "../../support/mcp/parseToolError.js";
import { OwnedPidLedger } from "../../support/process/ownedPidLedger.js";
import { createTempHome, type TempHome } from "../../support/workspace/tempHome.js";

/**
 * S6 §10.8 rows of write_memory, override_function and run_script through the BUILT server (snapshot via
 * BEA_DIST_DIR, docs/testing.md), plus the row moved here from WP5 (DESIGN §8.4): map_address after a gated write
 * still reports `match` with own_effects_restored > 0. Wave rule (CI-I1): only earlier-wave tools besides the three
 * under test — spawn_process/resume_process/session_status/close_session (WP4), map_address (WP5), read_memory (WP6),
 * stop_instrumentation (WP7), call_function (WP11). Needs the WP4/5/6/7/11 implementations merged to run.
 */
const SKIP = fridaSkip() || jobhostSkip();
const GAME_ARGS = ["--no-threads", "--speed", "20", "--throttle", "0.125"];
const f32Hex = (value: number): string => Buffer.from(new Float32Array([value]).buffer).toString("hex");

let game: FixtureArtifact;
let ledger: OwnedPidLedger;
let home: TempHome | undefined;
let bea: BeaConnection | undefined;

beforeAll(async () => {
  if (SKIP !== false) return;
  const manifest = await loadFixtures();
  const artifact = fixtureArtifact(manifest, "game_sim");
  if (artifact === null) throw new Error(`fixtures unavailable: ${JSON.stringify(manifest)}`);
  game = artifact;
  ledger = new OwnedPidLedger(fixtureArtifact(manifest, "pidcheck")?.path ?? null);
}, 300_000);

afterEach(async () => {
  await bea?.close();
  bea = undefined;
  await home?.cleanup();
  home = undefined;
});

afterAll(async () => {
  if (SKIP === false) await ledger.assertClean();
});

const start = async (gates: Partial<Record<"write_memory" | "override_function" | "run_script", boolean>>) => {
  home = await createTempHome("wp12");
  bea = await connectBea({ home, gates, ledger });
  return bea;
};

/** spawn + resume game_sim; returns the session id and car's VA (via read_memory's Cheat-Engine deref). */
const spawnGame = async (b: BeaConnection, args: readonly string[] = GAME_ARGS) => {
  const spawned = expectToolSuccess(await b.call("spawn_process", { program: game.path, args: [...args] }));
  const session_id = spawned["session_id"] as string;
  expectToolSuccess(await b.call("resume_process", { session_id }));
  let car = 0n;
  await vi.waitFor(
    async () => {
      const read = expectToolSuccess(
        await b.call("read_memory", { session_id, address: "game_sim.exe!g_world", deref: [8, 0], size: 4 }),
      );
      car = BigInt((read["address"] as { va: string }).va);
      expect(car).not.toBe(0n);
    },
    { timeout: 10_000, interval: 50 },
  );
  return { session_id, car, hex: (offset: bigint) => `0x${(car + offset).toString(16)}` };
};

const readF32 = async (b: BeaConnection, session_id: string, address: string): Promise<number> => {
  const read = expectToolSuccess(await b.call("read_memory", { session_id, address, size: 4, view: "f32" }));
  return (read["values"] as number[])[0] ?? Number.NaN;
};
const readHex = async (b: BeaConnection, session_id: string, address: string, size: number): Promise<string> => {
  const read = expectToolSuccess(await b.call("read_memory", { session_id, address, size }));
  return read["data"] as string;
};
/** g_mix_result changes every frame (it sums frame-dependent terms): a frame clock that needs no sleeps. */
const readMix = async (b: BeaConnection, session_id: string): Promise<number | string> => {
  const read = expectToolSuccess(
    await b.call("read_memory", { session_id, address: "game_sim.exe!g_mix_result", size: 8, view: "f64" }),
  );
  return (read["values"] as (number | string)[])[0] ?? Number.NaN;
};
const nextFrames = async (b: BeaConnection, session_id: string, frames: number): Promise<void> => {
  for (let i = 0; i < frames; i++) {
    const before = await readMix(b, session_id);
    await vi.waitFor(async () => expect(await readMix(b, session_id)).not.toBe(before), {
      timeout: 5000,
      interval: 20,
    });
  }
};
/** map_address verify of `bytes` at `address`: the live bytes against the relocated file bytes (WP5). */
const verifyRow = async (b: BeaConnection, session_id: string, address: string, bytes: number) => {
  const mapped = expectToolSuccess(
    await b.call("map_address", { session_id, addresses: [address], verify_bytes: bytes }),
  );
  return (mapped["rows"] as Record<string, unknown>[])[0] as {
    status: string;
    verify: { status: string; own_effects_restored: number } | null;
  };
};
const effectStatus = async (b: BeaConnection, session_id: string, effect: string): Promise<string | undefined> => {
  const status = expectToolSuccess(await b.call("session_status", { session_id }));
  return (status["effects"] as { effect: string; status: string }[]).find((e) => e.effect === effect)?.status;
};

describe.skipIf(SKIP !== false)(`write_memory (S6 §10.8)${skipNote(SKIP)}`, () => {
  it("writes throttle = 1.0, speed rises, stop_instrumentation(fx) restores the bytes", async () => {
    const b = await start({ write_memory: true });
    const { session_id, hex } = await spawnGame(b);
    const written = expectToolSuccess(
      await b.call("write_memory", { session_id, address: hex(0xcn), type: "f32", value: 1 }),
    );
    expect(written).toMatchObject({
      verified: true,
      method: "direct",
      before_hex: f32Hex(0.125),
      after_hex: f32Hex(1),
    });
    await vi.waitFor(async () => expect(await readF32(b, session_id, hex(8n))).toBeGreaterThan(20.5), {
      timeout: 5000,
      interval: 50,
    });
    const status = expectToolSuccess(await b.call("session_status", { session_id }));
    expect((status["effects"] as { effect: string }[]).map((e) => e.effect)).toContain(written["effect_id"]);
    const stopped = expectToolSuccess(
      await b.call("stop_instrumentation", { session_id, ids: [written["effect_id"] as string] }),
    );
    expect(stopped["stopped"]).toEqual([
      expect.objectContaining({ id: written["effect_id"], kind: "write", status: "reverted" }),
    ]);
    expect(await readF32(b, session_id, hex(0xcn))).toBe(0.125);
    // session_status lists active effects (plus recording and lifecycle ones): the reverted write is no longer there
    expect(await effectStatus(b, session_id, written["effect_id"] as string)).toBeUndefined();
    expectToolSuccess(await b.call("close_session", { session_id }));
  });

  it("map_address after a gated code write still reports match with own_effects_restored > 0 (row from WP5)", async () => {
    const b = await start({ write_memory: true });
    const { session_id } = await spawnGame(b);
    const tiny = game.pe.pdata["tiny_add"];
    if (tiny === undefined) throw new Error("tiny_add .pdata missing");
    const padRva = tiny.rva + tiny.size; // alignment padding after tiny_add's ret: never executed
    const pe = parsePe(await readFile(game.path));
    expect(pe.readRva(padRva, 1).toString("hex")).not.toBe("cc");
    const written = expectToolSuccess(
      await b.call("write_memory", { session_id, address: `game_sim.exe+0x${padRva.toString(16)}`, hex: "cc" }),
    );
    expect(written).toMatchObject({ method: "patchCode", verified: true, after_hex: "cc" });
    const mapped = expectToolSuccess(
      await b.call("map_address", {
        session_id,
        addresses: [`game_sim.exe+0x${padRva.toString(16)}`],
        verify_bytes: 1,
      }),
    );
    const row = (mapped["rows"] as Record<string, unknown>[])[0];
    expect(row).toMatchObject({ status: "mapped", verify: { status: "match" } });
    expect((row?.["verify"] as { own_effects_restored: number } | undefined)?.own_effects_restored).toBeGreaterThan(0);

    // revert restores the bytes equal to the file (padding carries no relocation): raw read and map_address agree
    const stopped = expectToolSuccess(
      await b.call("stop_instrumentation", { session_id, ids: [written["effect_id"] as string] }),
    );
    expect(stopped["stopped"]).toEqual([expect.objectContaining({ kind: "write", status: "reverted" })]);
    const pad = `game_sim.exe+0x${padRva.toString(16)}`;
    expect(await readHex(b, session_id, pad, 1)).toBe(pe.readRva(padRva, 1).toString("hex"));
    expect(await verifyRow(b, session_id, pad, 1)).toMatchObject({
      status: "mapped",
      verify: { status: "match", own_effects_restored: 0 },
    });
    expectToolSuccess(await b.call("close_session", { session_id }));
  });

  it("gate off: capability_unavailable with the exact enable text", async () => {
    const b = await start({});
    const { session_id, hex } = await spawnGame(b);
    const error = parseToolError(await b.call("write_memory", { session_id, address: hex(0xcn), hex: "00" }));
    expect(error.code).toBe("capability_unavailable");
    expect(error.details).toMatchObject({ gate: "write_memory", enable: gateEnableInstruction("write_memory") });
    expect(await readF32(b, session_id, hex(0xcn))).toBe(0.125);
    const status = expectToolSuccess(await b.call("session_status", { session_id }));
    expect((status["effects"] as { kind: string }[]).filter((e) => /written|patched/u.test(e.kind))).toEqual([]);
    expectToolSuccess(await b.call("close_session", { session_id }));
  });
});

describe.skipIf(SKIP !== false)(`override_function (S6 §10.8)${skipNote(SKIP)}`, () => {
  it("return on telemetry_sample = 123 shows in g_telemetry_kmh; stop restores the behavior", async () => {
    const b = await start({ override_function: true });
    const { session_id } = await spawnGame(b, ["--speed", "20", "--throttle", "0.125"]);
    const installed = expectToolSuccess(
      await b.call("override_function", {
        session_id,
        address: "game_sim.exe!telemetry_sample",
        mode: "return",
        returns: "f32",
        return_value: 123,
        duration_ms: 30_000,
      }),
    );
    expect(installed).toMatchObject({ instrument: { kind: "override", state: "active" } });
    await vi.waitFor(async () => expect(await readF32(b, session_id, "game_sim.exe!g_telemetry_kmh")).toBe(123), {
      timeout: 5000,
      interval: 50,
    });
    const recording = (installed["instrument"] as { recording_id: string }).recording_id;
    const live = await verifyRow(b, session_id, "game_sim.exe!telemetry_sample", 16);
    expect(live).toMatchObject({ verify: { status: "match" } }); // own patch restored in the comparison
    expect(live.verify?.own_effects_restored).toBeGreaterThan(0);
    const stopped = expectToolSuccess(await b.call("stop_instrumentation", { session_id, ids: [recording] }));
    expect(stopped["stopped"]).toEqual([
      expect.objectContaining({ id: recording, kind: "override", status: "reverted" }),
    ]);
    await vi.waitFor(async () => expect(await readF32(b, session_id, "game_sim.exe!g_telemetry_kmh")).toBe(72), {
      timeout: 5000,
      interval: 50,
    }); // 20 m/s * 3.6
    // the patch site is back to the file bytes with no BEA patch left to account for
    await vi.waitFor(
      async () =>
        expect(await verifyRow(b, session_id, "game_sim.exe!telemetry_sample", 16)).toMatchObject({
          verify: { status: "match", own_effects_restored: 0 },
        }),
      { timeout: 5000, interval: 50 },
    );
    expect(await effectStatus(b, session_id, installed["effect_id"] as string)).toBe("reverted");
    expectToolSuccess(await b.call("close_session", { session_id }));
  });

  it("args dt = 0 on physics_step freezes speed; replace on tiny_add returns the constant", async () => {
    const b = await start({ override_function: true, write_memory: true });
    const { session_id, hex } = await spawnGame(b);
    expectToolSuccess(await b.call("write_memory", { session_id, address: hex(0xcn), type: "f32", value: 1 }));
    const frozen = expectToolSuccess(
      await b.call("override_function", {
        session_id,
        address: "game_sim.exe!physics_step",
        mode: "args",
        set_args: [{ arg: 1, type: "f32", value: 0 }],
      }),
    );
    expect(frozen["effect_id"]).toMatch(/^fx_[0-9a-f]{64}$/u);
    await nextFrames(b, session_id, 1); // a frame in flight at install time may still integrate with the real dt
    const first = await readF32(b, session_id, hex(8n));
    await nextFrames(b, session_id, 3);
    expect(await readF32(b, session_id, hex(8n))).toBe(first);
    expectToolSuccess(
      await b.call("override_function", {
        session_id,
        address: "game_sim.exe!tiny_add",
        mode: "replace",
        returns: "i32",
        return_value: 7,
      }),
    );
    const callTiny = async (overrides: "apply" | "bypass") => {
      const called = expectToolSuccess(
        await b.call("call_function", {
          session_id,
          address: "game_sim.exe!tiny_add",
          signature: { returns: "i32", args: [{ type: "i32" }, { type: "i32" }] },
          args: [1, 2],
          overrides,
        }),
      );
      return (called["call"] as { ret: { value: unknown } | null }).ret?.value;
    };
    expect(await callTiny("apply")).toBe(7); // the replacement constant
    expect(await callTiny("bypass")).toBe(3); // the default bypasses overrides, so the original runs
    const second = parseToolError(
      await b.call("override_function", {
        session_id,
        address: "game_sim.exe!tiny_add",
        mode: "replace",
        returns: "i32",
        return_value: 8,
      }),
    );
    expect(second.code).toBe("instrumentation_failed");
    expectToolSuccess(await b.call("close_session", { session_id }));
  });

  it("gate off: capability_unavailable", async () => {
    const b = await start({});
    const { session_id } = await spawnGame(b);
    const error = parseToolError(
      await b.call("override_function", {
        session_id,
        address: "game_sim.exe!tiny_add",
        mode: "replace",
        returns: "i32",
        return_value: 7,
      }),
    );
    expect(error.code).toBe("capability_unavailable");
    expect(error.details).toMatchObject({
      gate: "override_function",
      enable: gateEnableInstruction("override_function"),
    });
    expectToolSuccess(await b.call("close_session", { session_id }));
  });
});

describe.skipIf(SKIP !== false)(`run_script (S6 §10.8)${skipNote(SKIP)}`, () => {
  it("captures send() messages and an rpc result, rejects a syntax error, leaves no script behind", async () => {
    const b = await start({ run_script: true });
    const { session_id } = await spawnGame(b, ["--speed", "20", "--throttle", "0.125"]); // telemetry thread on
    await vi.waitFor(async () => expect(await readF32(b, session_id, "game_sim.exe!g_telemetry_kmh")).toBe(72), {
      timeout: 5000,
      interval: 50,
    });
    // The script replaces telemetry_sample while loaded and reports what the telemetry thread then wrote; if it
    // stayed loaded after run_script, g_telemetry_kmh would stay 999 instead of returning to 72.
    const source = [
      'const m = Process.getModuleByName("game_sim.exe");',
      'Interceptor.replace(m.getExportByName("telemetry_sample"), new NativeCallback(() => 999, "float", ["pointer"]));',
      "for (let i = 0; i < 3; i++) send({ i });",
      'rpc.exports = { kmh: () => new Promise((done) => setTimeout(() => done(m.getExportByName("g_telemetry_kmh").readFloat()), 250)) };',
    ].join("\n");
    const ran = expectToolSuccess(
      await b.call("run_script", { session_id, source, rpc_method: "kmh", duration_ms: 400 }),
    );
    expect(ran).toMatchObject({ unloaded: true, truncated: false, interference: false });
    expect((ran["messages"] as string[]).map((m) => JSON.parse(m) as unknown)).toEqual([{ i: 0 }, { i: 1 }, { i: 2 }]);
    expect(JSON.parse(ran["rpc_result"] as string)).toBe(999); // compact JSON text: the replacement was live
    await vi.waitFor(async () => expect(await readF32(b, session_id, "game_sim.exe!g_telemetry_kmh")).toBe(72), {
      timeout: 5000,
      interval: 50,
    });
    expect(await verifyRow(b, session_id, "game_sim.exe!telemetry_sample", 16)).toMatchObject({
      verify: { status: "match", own_effects_restored: 0 },
    });
    const syntax = parseToolError(await b.call("run_script", { session_id, source: "send(" }));
    expect(syntax.code).toBe("invalid_request");
    const status = expectToolSuccess(await b.call("session_status", { session_id, detail: "complete" }));
    expect(JSON.stringify(status)).not.toContain("bea-user-");
    expectToolSuccess(await b.call("close_session", { session_id }));
  });

  it("gate off: capability_unavailable", async () => {
    const b = await start({});
    const { session_id } = await spawnGame(b);
    const error = parseToolError(await b.call("run_script", { session_id, source: "send(1)" }));
    expect(error.code).toBe("capability_unavailable");
    expect(error.details).toMatchObject({ gate: "run_script", enable: gateEnableInstruction("run_script") });
    expectToolSuccess(await b.call("close_session", { session_id }));
  });
});
