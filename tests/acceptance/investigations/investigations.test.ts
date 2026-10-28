import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { parsePe } from "../../../scripts/lib/peParse.mjs";
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
import { parseDrcov } from "../../support/drcov.js";
import { realPython } from "../../support/emu/python.js";
import { OwnedPidLedger } from "../../support/process/ownedPidLedger.js";
import { createTempHome, type TempHome } from "../../support/workspace/tempHome.js";
import { fileFacts, fileSectionBytes } from "../../unit/dump/peBuilder.js";
import { REG_EXE, expectBehaviorTable } from "../behavior/behaviorTable.js";
import { expectScenarioPassed, f32Bits, runScenario } from "./support/scenario.js";

/**
 * The seven investigations of S6 §1 as `bea run scenario.json` files through the BUILT CLI (DESIGN §10.2
 * "investigations", WP18), with the inputs re-expressed per Appendix A.4 and the call counts of S6 §1.8 counted over
 * analysis calls only (CI-M26: sync steps such as `wait {until:"output"}` and the test's own ground-truth reads are not
 * counted). They are also the skill's recipes R1–R7 (skills/bea-dynamic-analysis/SKILL.md §7). Fixture adaptations,
 * each stated where it applies: game_sim is SPAWNED (S6 §1.1 "spawns the game when that is possible"), so the session
 * set-up is spawn + resume instead of list_processes + attach; the user's accelerate/brake is game_sim's --ramp-at-ms
 * (an "increased" round after RAMP, then a "between" round for the new HUD value, which also drops the slowly warming
 * tyres); the Ghidra VA is game_sim's own static VA. Assertions are pointer-free (module+RVA, static
 * VAs, manifest RVAs, bit patterns). Every scenario runs in a fresh temp home and leaves no process (owned-PID ledger).
 */
const skip = fridaSkip() || gccSkip() || jobhostSkip();
type Obj = Readonly<Record<string, unknown>>;

let manifest: FixtureManifest;
let game: FixtureArtifact;
let ledger: OwnedPidLedger;
const homes: TempHome[] = [];
const scratch: string[] = [];

const artifact = (id: Parameters<typeof fixtureArtifact>[1]): FixtureArtifact => {
  const found = fixtureArtifact(manifest, id);
  if (found === null) throw new Error(`fixture ${id} unavailable`);
  return found;
};
const rvaOf = (name: string): number => {
  const rva = game.pe.exportRvas[name];
  if (rva === undefined) throw new Error(`game_sim exports no ${name}`);
  return rva;
};
const hex = (n: number | bigint): string => `0x${n.toString(16)}`;
const at = (rva: number): string => `game_sim.exe+${hex(rva)}`;
const home = async (label: string): Promise<TempHome> => {
  const created = await createTempHome(`inv-${label}`);
  homes.push(created);
  return created;
};
/** game_sim spawned paused (the target), resumed and READY: the session set-up of investigations 2, 3, 6 and 7. */
const GAME_SETUP = [
  { tool: "resume_process", role: "setup" },
  { tool: "wait", input: { until: "output", output_contains: "READY", timeout_ms: 15_000 }, role: "sync" },
] as const;
const run = (
  name: string,
  scenario: Parameters<typeof runScenario>[1],
  extra: Partial<Parameters<typeof runScenario>[2]> = {},
) => home(name).then((h) => runScenario(name, scenario, { home: h, ledger, keepRun: true, ...extra }));

beforeAll(async () => {
  if (skip !== false) return;
  const loaded = await loadFixtures();
  if ("unavailable" in loaded) throw new Error(loaded.unavailable);
  manifest = loaded;
  game = artifact("game_sim");
  ledger = new OwnedPidLedger(fixtureArtifact(manifest, "pidcheck")?.path ?? null);
});

afterAll(async () => {
  if (skip !== false) return;
  try {
    await ledger.assertClean();
  } finally {
    for (const h of homes) await h.cleanup();
    for (const dir of scratch) await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
}, 60_000);

const investigation1 = async (): Promise<void> => {
  const result = await run("inv1-variable", {
    // S6 §1.1 calls 1–2 (list_processes + attach_process) become spawn (target) + resume: the session set-up
    target: { spawn: { program: game.path, args: ["--speed", "20", "--throttle", "0.125", "--ramp-at-ms", "1000"] } },
    countsSession: true,
    steps: [
      { tool: "resume_process", role: "analysis" },
      { tool: "wait", input: { until: "output", output_contains: "READY", timeout_ms: 15_000 }, role: "sync" },
      // 3: the HUD value (20 m/s) as an f32 range
      {
        tool: "scan_memory",
        input: { value_type: "f32", compare: "between", value: 19.9, value2: 20.1, wait_ms: 30_000 },
        save_as: "speed",
        role: "analysis",
      },
      // the frame after RAMP has run at full throttle once FRAME 120 is printed (RAMP is at 1 s, frame ≤ 64)
      { tool: "wait", input: { until: "output", output_contains: "FRAME 120", timeout_ms: 15_000 }, role: "sync" },
      // 4: "after the user accelerates" (game_sim holds full throttle from RAMP on)
      { tool: "scan_next", input: { scan_id: "${speed.scan_id}", compare: "increased" }, role: "analysis" },
      { tool: "wait", input: { until: "output", output_contains: "FRAME 240", timeout_ms: 15_000 }, role: "sync" },
      // 5: the HUD now reads well above 21 m/s; the slowly warming tyres (~20.0, also "increased") drop out
      {
        tool: "scan_next",
        input: { scan_id: "${speed.scan_id}", compare: "between", value: 21, value2: 81 },
        role: "analysis",
      },
      // 6
      { tool: "scan_results", input: { scan_id: "${speed.scan_id}", limit: 20 }, save_as: "hits", role: "analysis" },
      // 7: watch the first candidate: writer instruction, struct base and displacement
      {
        tool: "watch_memory",
        input: { address: "${hits.rows[0].va}", size: 4, access: "write", duration_ms: 2000, wait_ms: 3000 },
        save_as: "watch",
        role: "analysis",
      },
      // 8: static pointers to the struct base
      {
        tool: "scan_memory",
        input: {
          value_type: "ptr",
          compare: "pointer_to",
          value: "${watch.instrument.summary.writers[0].struct_bases[0].base}",
          kind: "image",
        },
        save_as: "pointers",
        role: "analysis",
      },
      // 9
      { tool: "scan_results", input: { scan_id: "${pointers.scan_id}" }, save_as: "statics", role: "analysis" },
      // 10: the validated chain [static]+8
      {
        tool: "read_memory",
        input: { address: "${statics.rows[0].at}", deref: [8], view: "f32", size: 4 },
        save_as: "chain",
        role: "analysis",
      },
      // ground truth for the assertions (not an analysis call): the speed through the fixture's documented chain
      {
        tool: "read_memory",
        input: { address: "game_sim.exe!g_world", deref: [8], view: "ptr", size: 8 },
        save_as: "car",
        role: "oracle",
      },
    ],
  });
  expectScenarioPassed(result);
  expect(result.analysisCalls).toBe(11); // S6 §1.8: 11 calls (11 = 2 set-up + 8 analysis + close)
  const hits = result.saved("hits")["rows"] as Obj[];
  const car = BigInt(String((result.saved("car")["values"] as unknown[])[0]));
  // the speed field is among the narrowed hits, and the watched candidate is it
  expect(hits.map((h) => BigInt(String(h["va"])))).toContain(car + 8n);
  expect(BigInt(String(hits[0]?.["va"]))).toBe(car + 8n);
  const writers = (result.saved("watch")["instrument"] as { summary: { writers: Obj[] } }).summary.writers;
  const speedWriter = (game.expectations["speedWriters"] as { rva: number }[])[0];
  expect(writers).toHaveLength(1);
  expect(writers[0]).toMatchObject({
    insn: { at: at(speedWriter?.rva ?? -1) },
    access: "w",
    struct_bases: [{ base: hex(car), disp: "0x8" }],
  });
  // a static pointer to the car inside game_sim.exe's image, read back as the live speed (> 20: accelerating)
  const statics = result.saved("statics")["rows"] as Obj[];
  expect(statics.length).toBeGreaterThanOrEqual(1);
  expect(String(statics[0]?.["at"])).toMatch(/^game_sim\.exe\+0x[0-9a-f]+$/u);
  expect(String(statics[0]?.["static"])).toMatch(/^game_sim\.exe:0x14[0-9a-f]+$/u);
  expect(statics[0]?.["value"]).toBe(hex(car));
  const chain = result.saved("chain");
  const speed = Number((chain["values"] as unknown[])[0]);
  expect(speed).toBeGreaterThan(20);
  expect(speed).toBeLessThanOrEqual(80.5);
};

const investigation2 = async (): Promise<void> => {
  const ghidraVa = 0x140000000 + rvaOf("physics_step") + 0x10; // inside physics_step, not its start
  const result = await run("inv2-rebase-hook", {
    target: { spawn: { program: game.path, args: ["--speed", "20", "--throttle", "0.125"] } },
    countsSession: false,
    steps: [
      ...GAME_SETUP,
      {
        tool: "map_address",
        input: {
          addresses: [`game_sim.exe:${hex(ghidraVa)}`],
          verify_bytes: 16,
          expected_image_sha256: game.artifactSha256,
        },
        save_as: "mapped",
        role: "analysis",
      },
      {
        tool: "hook_function",
        input: {
          address: "${mapped.rows[0].func.start}",
          capture: [
            { name: "car", arg: 0, type: "ptr" },
            { name: "dt", arg: 1, type: "f32" },
            { name: "speed_in", arg: 0, type: "f32", deref: [8], when: "both" },
          ],
          returns: "f32",
          duration_ms: 2000,
          wait_ms: 3500,
        },
        save_as: "hook",
        role: "analysis",
      },
      {
        tool: "query_events",
        input: { recording_id: "${hook.instrument.recording_id}", view: "group", group_by: ["dt", "ret"], limit: 20 },
        save_as: "groups",
        role: "analysis",
      },
    ],
  });
  expectScenarioPassed(result);
  expect(result.analysisCalls).toBe(3); // S6 §1.8
  const row = (result.saved("mapped")["rows"] as Obj[])[0];
  expect(row).toMatchObject({
    status: "mapped",
    func: { start: at(rvaOf("physics_step")), is_start: false, name: "physics_step" },
    image_check: "match",
    verify: { status: "match" },
  });
  const hook = result.saved("hook")["instrument"] as { state: string; events: number; summary: Obj };
  expect(hook.state).toBe("finished");
  expect(hook.events).toBeGreaterThan(30); // one call per frame for 2 s (60 Hz, or ~32 Hz at a 15.6 ms timer)
  // S6 §1.2 "caller game.exe+0x75c0d2": the one caller is main() in game_sim.exe, pointer-free
  const callers = hook.summary["callers"] as { at: string; static: string | null; calls: number }[];
  expect(callers).toHaveLength(1);
  expect(callers[0]?.at).toMatch(/^game_sim\.exe\+0x[0-9a-f]+$/u);
  expect(callers[0]?.calls).toBe(hook.events);
  // review fix UX-10: and its pasteable static form (game_sim.exe's preferred base 0x140000000 + rva)
  const callerRva = BigInt((callers[0]?.at ?? "").split("+")[1] ?? "0");
  expect(callers[0]?.static).toBe(`game_sim.exe:0x${(0x140000000n + callerRva).toString(16)}`);
  // the f32 1/60 every frame; the equilibrium returns exactly 20.0 (ret == speed@leave)
  const groups = result.saved("groups");
  const columns = groups["columns"] as string[];
  const rows = (groups["rows"] as unknown[][]).map((cells) => Object.fromEntries(columns.map((c, i) => [c, cells[i]])));
  expect(rows).toHaveLength(1);
  expect(rows[0]).toMatchObject({ count: hook.events });
  expect(Math.fround(Number(rows[0]?.["dt"]))).toBe(Math.fround(1 / 60));
  expect(Number(rows[0]?.["ret"])).toBe(20);
};

const investigation3 = async (): Promise<void> => {
  const python = realPython();
  const n = 64;
  const dts = Array.from({ length: n }, (_, i) =>
    i === n - 1 ? "0x7fc00000" : i === n - 2 ? "0x80000000" : ([1 / 60, 1 / 120, 0.001, 0.25, 1][i % 5] ?? 0),
  );
  const signature = {
    args: [
      { type: "buffer_ptr", buffer: "car" },
      { type: "f32", name: "dt" },
    ],
    returns: "f32",
  };
  // the struct base found by investigation 1, copied ONCE per call (A.4 #1, CI-I2); the tyres array is a buffer
  // of each leg (a ptr_to field), so neither leg writes the game's own heap
  const buffers = [
    {
      name: "car",
      size: 128,
      init_from: "${car.values[0]}",
      out: true,
      fields: [{ name: "tyres", offset: 0x40, type: "ptr_to", buffer: "tyres" }],
    },
    { name: "tyres", size: 64 },
  ];
  const result = await run(
    "inv3-oracle-diff",
    {
      target: { spawn: { program: game.path, args: ["--no-threads", "--speed", "20", "--throttle", "0.125"] } },
      countsSession: false,
      steps: [
        ...GAME_SETUP,
        {
          tool: "read_memory",
          input: { address: "game_sim.exe!g_world", deref: [8], view: "ptr", size: 8 },
          save_as: "car",
          role: "oracle",
        },
        {
          tool: "call_function",
          input: {
            address: "game_sim.exe!physics_step",
            signature,
            buffers,
            vectors: { columns: { dt: [1 / 60, 1 / 120, "0x7fc00000"] } },
          },
          save_as: "oracle",
          role: "analysis",
        },
        {
          tool: "emu_open",
          input: {
            live_session_id: "${target.session_id}",
            capture_regions: [{ address: "${car.values[0]}", size: 128 }],
          },
          save_as: "emu",
          role: "analysis",
        },
        {
          tool: "diff_function",
          input: {
            live_session_id: "${target.session_id}",
            emu_session_id: "${emu.session_id}",
            address: "game_sim.exe!physics_step",
            signature,
            buffers,
            vectors: { columns: { dt: dts } },
          },
          save_as: "diff",
          role: "analysis",
        },
      ],
    },
    python === null ? {} : { env: { BEA_PYTHON: python } },
  );
  expectScenarioPassed(result);
  expect(result.analysisCalls).toBe(3); // S6 §1.8
  // the live oracle: the equilibrium car returns exactly 20.0 for finite dt, NaN in → NaN out (a result, not a fault)
  const batch = result.saved("oracle")["batch"] as { columns: Record<string, { bits: string[] }> };
  expect(batch.columns["ret"]?.bits.slice(0, 2)).toEqual([f32Bits(20), f32Bits(20)]);
  expect(batch.columns["ret"]?.bits[2]).toMatch(/^0x(7f|ff)[c-f][0-9a-f]{5}$/u);
  expect(result.saved("oracle")["effects_applied"]).toHaveLength(1); // the live call taints the instance
  const emu = result.saved("emu");
  expect(emu).toMatchObject({ source: "dump", primary: { name: "game_sim.exe", sha256: game.artifactSha256 } });
  const diff = result.saved("diff");
  expect(diff["verdict"]).toBe("equivalent-on-tested-inputs");
  const pair = (diff["pairs"] as { verdict: string; columns: { compared: number; exact_equal: number }[] }[])[0];
  expect(pair?.verdict).toBe("equivalent-on-tested-inputs");
  for (const column of pair?.columns ?? []) expect(column.exact_equal).toBe(column.compared);
};

const investigation4 = async (): Promise<void> => {
  const behavior = artifact("behavior");
  const mathlib = artifact("mathlib");
  const outDir = await mkdtemp(join(tmpdir(), "bea-inv4-"));
  scratch.push(outDir);
  const regKey = `inv4-${randomBytes(4).toString("hex")}`;
  const result = await run("inv4-behavior", {
    target: { spawn: { program: behavior.path, args: ["--out-dir", outDir, "--reg-key", regKey] } },
    countsSession: true,
    steps: [
      {
        tool: "trace_api",
        input: {
          profiles: ["file", "registry", "network", "process", "module_load", "memory_protection"],
          duration_ms: 30_000,
        },
        save_as: "api",
        role: "analysis",
      },
      { tool: "resume_process", input: { wait_ms: 35_000 }, save_as: "resumed", role: "analysis" },
      // ground truth: the fixture's own NET port / CHILD pid lines and the job's children
      { tool: "session_status", save_as: "status", role: "oracle" },
    ],
  });
  expectScenarioPassed(result);
  expect(result.analysisCalls).toBe(4); // S6 §1.8: spawn, trace_api, resume_process, close_session
  expect(result.saved("api")["hooks_installed"] as number).toBeGreaterThan(40);
  const resumed = result.saved("resumed");
  expect(resumed).toMatchObject({ state: "exited", exit: { code: 0 } });
  const api = (resumed["instruments"] as { kind: string; state: string; summary: Obj }[]).find((i) => i.kind === "api");
  expect(api?.state).toBe("finished");
  const status = result.saved("status");
  const stdout = String(status["output_tail"] ?? "");
  for (const step of ["file", "registry", "network", "process", "module", "memory"])
    expect(stdout).toContain(`STEP ${step} ok`);
  const children = (status["containment"] as { children_seen: number[] }).children_seen;
  expect(children).toHaveLength(1);
  expect(Number(/CHILD pid=(\d+)/u.exec(stdout)?.[1])).toBe(children[0]);
  ledger.recordOwned(children[0] ?? 0, null, "inv4 behavior.exe --child");
  expectBehaviorTable(api?.summary ?? {}, {
    outDir,
    regKey,
    netPort: Number(/NET port=(\d+)/u.exec(stdout)?.[1]),
    childPid: children[0] ?? 0,
    exePath: behavior.path,
    mathlibPath: mathlib.path,
  });
  // the fixture cleaned its registry key again
  expect(spawnSync(REG_EXE, ["query", `HKCU\\Software\\BEA-Fixture\\${regKey}`], { windowsHide: true }).status).toBe(1);
};

const investigation5 = async (): Promise<void> => {
  const crashy = artifact("crashy");
  const expectations = crashy.expectations as {
    crashWrite: { rva: number; text: string };
    returnSites: { level1: number; level2: number };
  };
  const result = await run("inv5-crash", {
    target: { spawn: { program: crashy.path, args: ["av-write"] } },
    countsSession: true,
    steps: [{ tool: "resume_process", input: { wait_ms: 60_000, until: "exit" }, save_as: "crash", role: "analysis" }],
  });
  expectScenarioPassed(result);
  expect(result.analysisCalls).toBe(3); // S6 §1.8: 2–3 (spawn, resume, close)
  const resumed = result.saved("crash");
  expect(resumed).toMatchObject({
    state: "exited",
    exit: { code_hex: "0xc0000005", name: "STATUS_ACCESS_VIOLATION" },
  });
  const crash = resumed["crash"] as {
    type: string;
    pc: { at: string; sym: string | null; static: string | null };
    insn: string | null;
    memory: { op: string; address: string };
    registers: Record<string, string>;
    backtrace: { at: string | null }[];
  };
  expect(crash.type).toBe("access-violation");
  expect(crash.pc.at).toBe(`crashy.exe+${hex(expectations.crashWrite.rva)}`);
  expect(crash.pc.sym).toMatch(/^crash_write/u); // A.4 #32: crashy exports its crash functions
  expect(crash.pc.static).toBe(`crashy.exe:${hex(BigInt(crashy.pe.imageBase) + BigInt(expectations.crashWrite.rva))}`);
  expect(crash.insn?.replaceAll(/\s+/gu, " ")).toMatch(/mov dword ptr \[rcx\], 0x2a/iu);
  expect(crash.memory).toMatchObject({ op: "write", address: "0x0" });
  expect(Object.keys(crash.registers)).toEqual(expect.arrayContaining(["rip", "rsp", "rcx"]));
  const frames = crash.backtrace.map((f) => f.at);
  expect(frames).toEqual(
    expect.arrayContaining([
      `crashy.exe+${hex(expectations.returnSites.level1)}`,
      `crashy.exe+${hex(expectations.returnSites.level2)}`,
    ]),
  );
};

const investigation6 = async (): Promise<void> => {
  const extent = game.pe.pdata["physics_step"];
  if (extent === undefined) throw new Error("no .pdata extent for physics_step");
  const result = await run("inv6-coverage", {
    target: { spawn: { program: game.path, args: ["--speed", "20", "--throttle", "0.125"] } },
    countsSession: false,
    steps: [
      ...GAME_SETUP,
      {
        tool: "trace_execution",
        input: { on_call: "game_sim.exe!physics_step", invocations: 1, mode: "coverage", wait_ms: 5000 },
        save_as: "trace",
        role: "analysis",
      },
      {
        tool: "export_coverage",
        input: { recording_id: "${trace.instrument.recording_id}" },
        save_as: "drcov",
        role: "analysis",
      },
    ],
  });
  expectScenarioPassed(result);
  expect(result.analysisCalls).toBe(2); // S6 §1.8
  const exported = result.saved("drcov");
  const bytes = new Uint8Array(await readFile(String(exported["path"])));
  const drcov = parseDrcov(bytes);
  const module = drcov.modules.find((m) => m.path.toLowerCase().endsWith("game_sim.exe"));
  expect(module?.path.toLowerCase()).toBe(game.path.toLowerCase());
  const blocks = drcov.blocks.filter((b) => b.moduleId === module?.id);
  expect(blocks.length).toBeGreaterThanOrEqual(2);
  // one call of a leaf function: every block lies inside physics_step's .pdata extent
  for (const block of blocks) {
    expect(block.start).toBeGreaterThanOrEqual(extent.rva);
    expect(block.start + block.size).toBeLessThanOrEqual(extent.rva + extent.size);
  }
  expect(blocks.map((b) => b.start)).toContain(extent.rva);
};

const investigation7 = async (): Promise<void> => {
  const result = await run("inv7-dump", {
    target: { spawn: { program: game.path, args: ["--speed", "20", "--throttle", "0.125"] } },
    countsSession: false,
    steps: [
      ...GAME_SETUP,
      {
        tool: "dump_memory",
        input: { format: "pe", module: "game_sim.exe", layout: "pe_realigned", rebase_to: "preferred" },
        save_as: "dump",
        role: "analysis",
      },
    ],
  });
  expectScenarioPassed(result);
  expect(result.analysisCalls).toBe(1); // S6 §1.8
  const dump = result.saved("dump");
  const onDisk = new Uint8Array(await readFile(game.path));
  const facts = fileFacts(onDisk);
  expect(dump).toMatchObject({
    format: "pe",
    layout: "pe_realigned",
    image_base_in_file: hex(facts.preferredBase),
    module: { name: "game_sim.exe", rebased_to: "preferred" },
  });
  const dumped = await readFile(String(dump["path"]));
  const pe = parsePe(dumped);
  expect(pe.imageBase).toBe(hex(facts.preferredBase));
  const text = facts.sections.find((s) => (s.characteristics & 0x20000000) !== 0);
  if (text === undefined) throw new Error("no code section");
  const disk = fileSectionBytes(onDisk, text.rva);
  expect(dumped.subarray(text.rva, text.rva + disk.length).equals(Buffer.from(disk))).toBe(true);
};

describe.skipIf(skip !== false)(`S6 §1 investigations as bea run scenarios${skipNote(skip)}`, () => {
  it(
    "1: the live speed variable, its writer instruction, the struct base and a validated static chain (11 calls)",
    investigation1,
    300_000,
  );
  it("2: rebase a Ghidra VA, hook float args and return for 2 s, summarize (3 calls)", investigation2, 300_000);
  it.skipIf(emuSkip() !== false)(
    `3: call in-process as an oracle, emulate the same vectors, diff (3 calls)${skipNote(emuSkip())}`,
    investigation3,
    300_000,
  );
  it(
    "4: what files, registry keys, endpoints and child processes behavior.exe touches (4 calls)",
    investigation4,
    300_000,
  );
  it("5: catch a crash — faulting instruction, module+RVA, registers, backtrace (3 calls)", investigation5, 300_000);
  it("6: coverage of one physics_step call, exported as drcov (2 calls)", investigation6, 300_000);
  it("7: dump game_sim.exe for REA/Ghidra — realigned PE at the preferred base (1 call)", investigation7, 300_000);
});
