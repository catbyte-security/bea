// WP3-AGENT acceptance (raw Frida; S4 §8.4, §10.3): the core readers feature WPs share, on real calls in game_sim —
// Win64 slot capture by POSITION with exact float bits from xmm registers and stack slots (mix_args: int, f32, f64,
// f32, int@stack, f64@stack), a deref capture (physics_step's Car* → speed at +8 on the f32 equilibrium), the
// overlay-aware decoder (a hooked function decodes to its original first instruction) and findAccessInsn (the
// trap-after pc of the speed writer sweeps back to exactly that instruction). RVAs come from the fixture manifest.
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { loadFixtures, skipNote } from "../../support/acceptance/fixtures.js";
import { agentLaneSkip, setupAgentLane, type AgentLane } from "../../support/agent/lane.js";
import { RawAgent } from "../../support/agent/rawAgent.js";
import { OwnedPidLedger } from "../../support/process/ownedPidLedger.js";

const skip = agentLaneSkip();
const f32 = (v: number): string => {
  const dv = new DataView(new ArrayBuffer(4));
  dv.setFloat32(0, v, true);
  return `0x${dv.getUint32(0, true).toString(16)}`;
};
const f64 = (v: number): string => {
  const dv = new DataView(new ArrayBuffer(8));
  dv.setFloat64(0, v, true);
  return `0x${dv.getBigUint64(0, true).toString(16)}`;
};

describe.skipIf(skip !== false)(`core capture readers and the overlay-aware decoder${skipNote(skip)}`, () => {
  let lane: AgentLane;
  let ledger: OwnedPidLedger;
  let speedWriterRva = 0;
  let physicsStepRva = 0;
  const agents: RawAgent[] = [];
  const start = async (args: readonly string[]): Promise<RawAgent> => {
    const a = await RawAgent.start({
      bundle: lane.bundle,
      program: lane.fixtures.game_sim,
      args,
      cwd: lane.fixtureDir,
    });
    agents.push(a);
    ledger.recordOwned(a.pid, null, `game_sim ${args.join(" ")}`);
    await a.hello();
    await a.resume();
    return a;
  };
  const mainBase = async (a: RawAgent): Promise<bigint> =>
    BigInt((await a.ok<{ main_module: { base: string } }>("processInfo")).main_module.base);

  beforeAll(async () => {
    lane = await setupAgentLane();
    ledger = new OwnedPidLedger(lane.pidcheck);
    const manifest = await loadFixtures();
    if ("unavailable" in manifest) throw new Error(manifest.unavailable);
    const writers = manifest.artifacts.game_sim.expectations["speedWriters"] as { rva: number; text: string }[];
    expect(writers).toHaveLength(1);
    speedWriterRva = writers[0]!.rva;
    physicsStepRva = manifest.artifacts.game_sim.pe.exportRvas["physics_step"]!;
  }, 180_000);

  afterEach(async () => {
    for (const a of agents.splice(0)) await a.close();
  });

  afterAll(async () => {
    await RawAgent.shutdownFrida();
    await ledger?.assertClean();
  });

  it("captures Win64 slots by position with exact float bits (registers and stack)", async () => {
    const a = await start(["--hz", "60", "--no-threads"]);
    const cells = await a.rpc<unknown[]>("testCapture", {
      export: "mix_args",
      specs: [
        { slot: 0, class: "int", type: "i32" },
        { slot: 1, class: "float", type: "f32" },
        { slot: 2, class: "float", type: "f64" },
        { slot: 3, class: "float", type: "f32" },
        { slot: 4, class: "int", type: "i32" },
        { slot: 5, class: "float", type: "f64" },
        { reg: "xmm1", type: "bytes" },
      ],
    });
    // mix_args((int)frame, 1.5f, 2.25, 3.125f, 7, 0.5)
    expect(typeof cells[0]).toBe("number");
    expect(cells.slice(1, 6)).toEqual([f32(1.5), f64(2.25), f32(3.125), 7, f64(0.5)]);
    expect(cells[6]).toMatchObject({ x: expect.stringMatching(/^0000c03f/u) });
  });

  it("follows a deref chain from a pointer slot (physics_step: Car* → speed at +8 on the f32 equilibrium)", async () => {
    const a = await start(["--hz", "60", "--no-threads", "--speed", "20", "--throttle", "0.125"]);
    const cells = await a.rpc<unknown[]>("testCapture", {
      export: "physics_step",
      specs: [
        { slot: 0, class: "int", type: "f32", deref: [8] },
        { slot: 1, class: "float", type: "f32" },
        { slot: 0, class: "int", type: "u32", deref: [0] },
        { slot: 0, class: "int", type: "ptr", deref: [0x40, 0] },
        { slot: 0, class: "int", type: "u32", deref: [0x38, 0] }, // Car.frame (a small integer) as a pointer
      ],
    });
    expect(cells[0]).toBe(f32(20));
    expect(cells[1]).toBe(f32(1 / 60));
    expect(cells[2]).toBe(0x31524143); // Car.magic 'CAR1'
    expect(cells[3]).toMatch(/^0x[0-9a-f]+$/u); // Car.tyres → first Tyre (grip 1.0f, temp 20.0f) as raw bits
    expect(cells[4]).toMatchObject({ e: "av" }); // a failure cell, never a throw
  });

  it("decodes a hooked function to its original bytes (overlay) and recovers a watch writer by sweeping", async () => {
    const a = await start(["--hz", "60", "--no-threads"]);
    const base = await mainBase(a);
    const fn = `0x${(base + BigInt(physicsStepRva)).toString(16)}`;
    const before = await a.rpc<{ text: string; bytes: string }>("testDecode", { address: fn, overlay: true });
    expect(before.text).not.toMatch(/^jmp /u);
    await a.rpc("testHookRows", { module: "game_sim.exe", export: "physics_step" });
    const live = await a.rpc<{ text: string; overlay: boolean }>("testDecode", { address: fn, overlay: false });
    expect(live.text).toMatch(/^jmp /u); // Interceptor's patch
    const overlaid = await a.rpc<{ text: string; bytes: string; overlay: boolean }>("testDecode", {
      address: fn,
      overlay: true,
    });
    expect(overlaid).toMatchObject({ text: before.text, bytes: before.bytes, overlay: true });
    const writer = base + BigInt(speedWriterRva);
    const insn = await a.rpc<{ text: string; size: number }>("testDecode", {
      address: `0x${writer.toString(16)}`,
      overlay: true,
    });
    expect(insn.text).toMatch(/^movss dword ptr \[r\w+ \+ 8\], xmm0$/u);
    const found = await a.rpc<{ address: string; size: number; conf: string; text: string }>("testAccessInsn", {
      pcAfter: `0x${(writer + BigInt(insn.size)).toString(16)}`,
    });
    expect(found).toEqual({ address: `0x${writer.toString(16)}`, size: insn.size, text: insn.text, conf: "swept" });
  });
});
