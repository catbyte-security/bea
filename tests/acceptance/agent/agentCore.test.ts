// WP3-AGENT acceptance (raw Frida, no BEA host; DESIGN §8.4 WP3 row, §9.3 WP3 card): the core agent bundle in a real
// target — ready → hello → ping/status/flush, the pre-hello admission rule, all 40 RPCs answer (feature stubs
// Unsupported until their WPs land), readMemory's binary tuple equals the image bytes on disk, readTyped pointer
// chains, the module epoch on LoadLibrary, s:modules / s:threads rows, fingerprint of the core's own hooks, and
// shutdown with revert. Bundle ≤ 512 KiB.
import { readFileSync } from "node:fs";

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { parsePe } from "../../../scripts/lib/peParse.mjs";
import type { AgentMethodName, HelloResult, ModuleRow } from "../../../src/shared/agentProtocol.js";
import { skipNote } from "../../support/acceptance/fixtures.js";
import { FEATURE_STUBS } from "../../support/agent/coreAgent.js";
import { agentLaneSkip, setupAgentLane, type AgentLane } from "../../support/agent/lane.js";
import { RawAgent } from "../../support/agent/rawAgent.js";
import { OwnedPidLedger } from "../../support/process/ownedPidLedger.js";

const skip = agentLaneSkip();
const ALL_METHODS: readonly AgentMethodName[] = [
  "hello",
  "ping",
  "status",
  "flush",
  "shutdown",
  "fingerprint",
  "processInfo",
  "listModules",
  "listExports",
  "listImports",
  "listSections",
  "listFunctions",
  "findFunction",
  "listRanges",
  "listThreads",
  "resolveTargets",
  "describeAddresses",
  "readMemory",
  "readTyped",
  "writeMemory",
  "revertWrite",
  "disassemble",
  "scanStart",
  "scanNext",
  "scanStatus",
  "scanResults",
  "scanClose",
  "jobStatus",
  "jobCancel",
  "hookInstall",
  "profileInstall",
  "watchInstall",
  "traceStart",
  "overrideInstall",
  "instrumentStop",
  "instrumentList",
  "debugRegisterState",
  "callFunction",
  "dumpStart",
  "captureThreadState",
];

const state: { lane: AgentLane | null; ledger: OwnedPidLedger | null; agents: RawAgent[] } = {
  lane: null,
  ledger: null,
  agents: [],
};
const laneOf = (): AgentLane => {
  if (state.lane === null) throw new Error("lane not set up");
  return state.lane;
};
const start = async (args: readonly string[]): Promise<RawAgent> => {
  const lane = laneOf();
  const a = await RawAgent.start({ bundle: lane.bundle, program: lane.fixtures.game_sim, args, cwd: lane.fixtureDir });
  state.agents.push(a);
  state.ledger?.recordOwned(a.pid, null, `game_sim ${args.join(" ")}`);
  return a;
};

describe.skipIf(skip !== false)(`agent core in a live target${skipNote(skip)}`, () => {
  beforeAll(async () => {
    state.lane = await setupAgentLane();
    state.ledger = new OwnedPidLedger(state.lane.pidcheck);
  }, 180_000);

  afterEach(async () => {
    for (const a of state.agents.splice(0)) await a.close();
  });

  afterAll(async () => {
    await RawAgent.shutdownFrida();
    await state.ledger?.assertClean();
  });

  describe("handshake and the RPC surface", handshakeTests);
  describe("memory, modules and lifecycle", memoryTests);
});

function handshakeTests(): void {
  it("ready → hello → ping/status/flush; pre-hello admission; bundle ≤ 512 KiB", async () => {
    expect(laneOf().bundleBytes).toBeLessThanOrEqual(512 * 1024);
    const a = await start(["--hz", "60"]);
    const ready = a.ready!;
    expect(ready).toMatchObject({
      bea: "ready",
      protocol: "bea-agent/1",
      protocol_minor: 0,
      runtime: "QJS",
      arch: "x64",
      pid: a.pid,
    });
    expect(ready["early"]).toEqual({
      exception_handler: true,
      exit_hook: true,
      last_chance_hook: true,
      module_observer: true,
    });
    expect(ready["features"]).toEqual(
      expect.arrayContaining(["crash.first-chance", "crash.last-chance", "exit-flush"]),
    );
    // before hello only hello / ping / processInfo are admitted
    expect(await a.rpc("status", { detail: "summary" })).toMatchObject({ ok: false, error: { _tag: "NotReady" } });
    expect(await a.rpc("ping")).toMatchObject({ ok: true, value: { phase: "loaded" } });
    const pre = await a.ok<{ main_module: { name: string; pe: { section_count: number } } }>("processInfo");
    expect(pre.main_module.name).toBe("game_sim.exe");
    expect(pre.main_module.pe.section_count).toBeGreaterThan(3);
    // hello: protocol check, clamped limits, system streams, resolved deny list
    expect(await a.rpc("hello", { protocol: "bea-agent/2", min_minor: 0 })).toMatchObject({
      ok: false,
      error: { _tag: "ProtocolMismatch" },
    });
    const hello: HelloResult = await a.hello({ limits: { max_instruments: 16, flush_ms: 999_999 } });
    expect(hello.limits.max_instruments).toBe(16);
    expect(hello.limits.flush_ms).toBe(1000);
    expect(hello.system_streams).toEqual({ exceptions: "s:exceptions", modules: "s:modules", threads: null });
    expect(hello.deny_list.map((d) => d.api)).toEqual([
      "ntdll.dll!NtAllocateVirtualMemory",
      "kernelbase.dll!VirtualAlloc",
    ]);
    expect(hello.boot.early_rows).toBeGreaterThan(10);
    await a.resume();
    expect(await a.waitFor(() => a.output().includes("READY"), 5000)).toBe(true);
    const ping = await a.ok<{ phase: string; g: number; t: number }>("ping");
    expect(ping.phase).toBe("ready");
    const status = await a.ok<Record<string, unknown>>("status", { detail: "full" });
    expect(status).toMatchObject({
      phase: "ready",
      exceptions: { safety_net: "none", in_call: 0 },
      calls: { active: [] },
    });
    expect(await a.ok("flush")).toMatchObject({ batches: expect.any(Number) });
    // every module of the boot snapshot arrived on s:modules after hello
    const loaded = await a.waitFor(
      () => (a.rows("s:modules").length >= hello.module_map_epoch ? a.rows("s:modules") : null),
      3000,
    );
    expect((loaded as ModuleRow[]).some((r) => r[2] === "L" && r[3] === "game_sim.exe")).toBe(true);
  });

  it("all 40 RPCs answer with an AgentResult; feature stubs are Unsupported{not-implemented}", async () => {
    const a = await start(["--hz", "60"]);
    await a.hello();
    await a.resume();
    const stubbed = new Set(Object.values(FEATURE_STUBS).flat());
    const closedGates = new Set(["writeMemory", "revertWrite", "overrideInstall"]); // write_memory / override_function off
    expect(ALL_METHODS).toHaveLength(40);
    for (const method of ALL_METHODS) {
      if (method === "shutdown") continue;
      const reply = await a.rpc<unknown>(method, {});
      const result = Array.isArray(reply) ? reply[0] : reply;
      expect(result, method).toMatchObject({ ok: expect.any(Boolean) });
      // gates are re-checked agent-side (defense in depth) before the stub runs
      if (closedGates.has(method)) expect(result, method).toMatchObject({ ok: false, error: { _tag: "GateClosed" } });
      else if (stubbed.has(method))
        expect(result, method).toMatchObject({ ok: false, error: { _tag: "Unsupported", reason: "not-implemented" } });
    }
  });
}

function memoryTests(): void {
  it("readMemory returns [meta, bytes] equal to the image on disk; readTyped follows S4 pointer chains", async () => {
    const a = await start(["--hz", "60", "--speed", "20", "--throttle", "0.125", "--no-threads"]);
    await a.hello();
    await a.resume();
    await a.waitFor(() => a.output().includes("READY"), 5000);
    const file = parsePe(readFileSync(laneOf().fixtures.game_sim));
    const target = await a.ok<{ results: { ok: boolean; target: { va: string; rva: string } }[] }>("resolveTargets", {
      targets: [
        { module: "game_sim.exe", export: "physics_step" },
        { module: "game_sim.exe", export: "g_world" },
      ],
    });
    const fn = target.results[0]!.target;
    const reply = await a.rpc<[{ ok: true; value: Record<string, unknown> }, Buffer]>("readMemory", {
      address: fn.va,
      size: 64,
    });
    expect(Array.isArray(reply)).toBe(true);
    expect(reply[0]).toMatchObject({ ok: true, value: { requested: 64, returned: 64, complete: true, stop: null } });
    expect(Buffer.isBuffer(reply[1])).toBe(true);
    expect(reply[1].toString("hex")).toBe(Buffer.from(file.readRva(Number(fn.rva), 64)).toString("hex"));
    // unreadable start → AccessViolation, no tuple
    expect(await a.rpc("readMemory", { address: "0x10", size: 4 })).toMatchObject({
      ok: false,
      error: { _tag: "AccessViolation", partial_bytes: 0 },
    });
    // [[&g_world]+0]+8 → the Car; Car.magic 'CAR1' at +0 and speed 20.0f (exact f32 equilibrium) at +8
    const world = target.results[1]!.target.va;
    const typed = await a.ok<{ results: { ok: boolean; path: string[]; value: { value: unknown; bits?: string } }[] }>(
      "readTyped",
      {
        reads: [
          { address: world, type: "u32", chain: [0, 8] },
          { address: world, type: "f32", chain: [0, 8, 0] },
          { address: world, type: "ptr", chain: [0] },
        ],
      },
    );
    expect(typed.results[0]).toMatchObject({ ok: true, value: { type: "u32", value: 0x31524143 } });
    expect(typed.results[0]!.path).toHaveLength(3);
    expect(typed.results[1]).toMatchObject({ ok: false, error: { _tag: "AccessViolation" } });
    expect(typed.results[2]!.ok).toBe(true);
  });

  it("listModules epoch increments on LoadLibrary (game_sim --load-mathlib-at)", async () => {
    const a = await start(["--hz", "60", "--load-mathlib-at", "20", "--no-threads"]);
    const hello = await a.hello({ streams: { flush_ms: 50, exceptions: true, threads: true } });
    expect(hello.system_streams.threads).toBe("s:threads");
    const before = await a.ok<{ module_map_epoch: number; modules: { name: string }[] }>("listModules", {
      with_pe: false,
    });
    expect(before.modules.some((m) => m.name.toLowerCase() === "mathlib.dll")).toBe(false);
    await a.resume();
    expect(await a.waitFor(() => a.output().includes("MATHLIB loaded=1"), 10_000)).toBe(true);
    const listed = await a.ok<{ module_map_epoch: number; modules: { name: string; base: string; pe: unknown }[] }>(
      "listModules",
      {
        with_pe: true,
        name_glob: "math*",
      },
    );
    expect(listed.module_map_epoch).toBeGreaterThan(before.module_map_epoch);
    expect(listed.modules.map((m) => m.name.toLowerCase())).toEqual(["mathlib.dll"]);
    // the in-memory OptionalHeader.ImageBase is the runtime base (the loader rewrites it; ASLR may move the DLL)
    expect(listed.modules[0]!.pe).toMatchObject({ machine: 0x8664, mapped_image_base: listed.modules[0]!.base });
    const rows = (await a.waitFor(
      () => a.rows("s:modules").find((r) => r[2] === "L" && String(r[3]).toLowerCase() === "mathlib.dll"),
      3000,
    )) as ModuleRow | null;
    expect(rows).not.toBeNull();
    expect(rows![7]).toBeGreaterThan(before.module_map_epoch);
    // the thread observer rows: the existing threads at attach (S rows)
    expect(a.rows("s:threads").some((r) => r[2] === "S")).toBe(true);
  });

  it("fingerprint reports the core's own patches intact; shutdown stops instruments with revert", async () => {
    const a = await start(["--hz", "60"]);
    await a.hello();
    await a.resume();
    const fp = await a.ok<{ patches: { owner: string; ok: boolean }[]; guard_pages: unknown[] }>("fingerprint");
    expect(fp.patches.filter((p) => p.owner === "core")).toHaveLength(3);
    expect(fp.patches.every((p) => p.ok)).toBe(true);
    const hook = await a.rpc<{ instrument_id: string; stream_id: string }>("testHookRows", {
      module: "kernelbase.dll",
      export: "Sleep",
    });
    const listed = await a.ok<{ instruments: { id: string; state: string }[] }>("instrumentList");
    expect(listed.instruments).toEqual([expect.objectContaining({ id: hook.instrument_id, state: "active" })]);
    const shut = await a.ok<{
      stopped: { id: string; reverted: boolean; end_reason: string }[];
      unreverted: unknown[];
    }>("shutdown", {
      revert: true,
      timeout_ms: 5000,
    });
    expect(shut.stopped).toEqual([
      expect.objectContaining({ id: hook.instrument_id, reverted: true, end_reason: "shutdown" }),
    ]);
    expect(shut.unreverted).toEqual([]);
    expect(a.messages("instrument")).toEqual([expect.objectContaining({ id: hook.instrument_id, event: "ended" })]);
    expect(a.messages("batch").some((b) => b["stream"] === hook.stream_id && b["final"] === true)).toBe(true);
    expect(await a.rpc("listModules", { with_pe: false })).toMatchObject({
      ok: false,
      error: { _tag: "ShuttingDown" },
    });
    expect(await a.rpc("ping")).toMatchObject({ ok: true, value: { phase: "shutting-down" } });
  });
}
