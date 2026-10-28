import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { parsePe, type PeImage } from "../../../scripts/lib/peParse.mjs";
import {
  fixtureArtifact,
  fridaSkip,
  loadFixtures,
  skipNote,
  type FixtureArtifact,
} from "../../support/acceptance/fixtures.js";
import { pidStatus } from "../../support/process/ownedPidLedger.js";

/**
 * WP12 raw-agent acceptance (wave rule, CI-I1: raw agent RPCs only, no later-wave tools). The REAL feature files
 * src/agent/{memwrite,override}.ts and their pure helpers are bundled by frida.Compiler with a test entry that gives
 * them a stand-in core with WP3's service shapes (bound through the WP12 seam), loaded into a game_sim this test
 * spawns, and driven through rpc.exports exactly as the host would. Everything spawned here is killed in afterAll.
 */
const REPO = resolve(import.meta.dirname, "../../..");
const SKIP = fridaSkip();

/** The day-0 AgentCore shape (DESIGN §4) and error helpers: other WPs' in-progress core files never enter the bundle. */
const DAY0_STATE = `import { AGENT_LIMIT_DEFAULTS } from "../shared/agentLimits.js";
export function createCore(): any {
  return { t0Wall: Date.now(), jsTid: Process.getCurrentThreadId(), phase: "loaded", bootStage: "platform", features: [],
    early: { exception_handler: true, exit_hook: false, last_chance_hook: false, module_observer: false },
    gates: { write_memory: false, override_function: false, call_function: false }, limits: { ...AGENT_LIMIT_DEFAULTS } };
}
`;
const DAY0_ERRORS = `export const ok = (value: any): any => ({ ok: true, value });
export const fail = (error: any): any => ({ ok: false, error });
`;

/**
 * Test entry: a stand-in core with WP3's service SHAPES (S4 §5.1 as implemented in src/agent/{instruments,originals,
 * guards,stalkerCo}.ts and pure/coreEvents.ts): InstrumentRegistry.register(spec)/stop(inst, reason) with duration
 * timers and hit() → record | record-and-stop | ignore, StreamRegistry.open/emit/close, native.nextG/nowUs,
 * OriginalBytes.save(site, n, owner)/release/isPatched/markPatched (the S4 order of src/agent/originals.ts; review fix
 * AGENT-9), hooks.onDispose[] — so the WP12 seam's adapters are the code under test, not a WP12-specific fake.
 */
const HARNESS = `
import { createCore } from "./state.js";
import * as memwrite from "./memwrite.js";
import * as override from "./override.js";

const c: any = createCore();
const instruments = new Map<string, any>();
const ended: any[] = [];
const rows: any[] = [];
const scratch: NativePointer[] = [];
const saved = new Map<string, { site: NativePointer; owners: Set<string>; n: number; patched: boolean }>();
let seq = 0;
let g = 0;
c.native = { nextG: () => ++g, nowUs: () => (Date.now() - c.t0Wall) * 1000 };
c.streams = {
  open: (spec: any) => ({ id: "s" + String(++seq), spec }),
  emit: (s: any, row: any[]) => { rows.push([s.id, ...row]); return true; },
  close: () => {},
};
const stop = (inst: any, reason: string): Promise<any> => {
  if (inst.stopping !== null) return inst.stopping;
  inst.state = "stopping";
  clearTimeout(inst.timer);
  inst.stopping = (async () => {
    const out = await inst.spec.revert(inst, reason);
    inst.state = "ended";
    const summary = { id: inst.id, kind: inst.spec.kind, end_reason: reason, reverted: out.reverted, verification: out.verification, hits: inst.counters.hits };
    ended.push({ id: inst.id, summary });
    return summary;
  })();
  return inst.stopping;
};
c.instruments = {
  register(spec: any) {
    const inst: any = {
      id: "o" + String(++seq), spec, state: "active", stopping: null, timer: null,
      counters: { hits: 0, recorded: 0, sampled_out: 0, filtered: 0, agent_calls_suppressed: 0, unreturned: 0, errors: 0, dropped: {}, bea_guard_suspended: 0 },
      get active() { return this.state === "active"; },
      hit() {
        if (this.state !== "active") return "ignore";
        this.counters.hits++;
        if (this.counters.hits < spec.lifetime.max_hits) return "record";
        this.state = "stopping";
        setImmediate(() => void stop(this, "max_hits"));
        return "record-and-stop";
      },
    };
    inst.timer = setTimeout(() => void stop(inst, "duration"), spec.lifetime.duration_ms);
    instruments.set(inst.id, inst);
    return inst;
  },
  stop,
};
c.originals = {
  save(site: NativePointer, n: number, owner: string) {
    const key = site.toString();
    const rec = saved.get(key) ?? { site, owners: new Set<string>(), n, patched: false };
    rec.owners.add(owner);
    saved.set(key, rec);
    return rec;
  },
  markPatched(site: NativePointer) { const rec = saved.get(site.toString()); if (rec) rec.patched = true; },
  release(site: NativePointer, owner: string) {
    const rec = saved.get(site.toString());
    if (!rec) return null;
    rec.owners.delete(owner);
    if (rec.owners.size === 0) saved.delete(site.toString());
    return rec;
  },
  isPatched(address: NativePointer, size: number) {
    for (const rec of saved.values()) {
      const s = rec.site;
      if (s.compare(address.add(size)) < 0 && address.compare(s.add(rec.n)) < 0) return true;
    }
    return false;
  },
};
c.hooks = { onDispose: [] as (() => void)[] };
// WP3's CallLedger shape (src/agent/calls.ts): a BEA oracle call with overrides:"bypass" marks its thread.
const bypassing = new Set<number>();
c.calls = { bypassesOverrides: (tid: number) => bypassing.has(tid) };
c.phase = "ready";
c.gates = { write_memory: true, override_function: true, call_function: false };
memwrite.init(c);
override.init(c);
const exp = (n: string) => Process.mainModule.getExportByName(n);
const hex = (b: ArrayBuffer | null) => (b === null ? null : Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, "0")).join(""));
rpc.exports = {
  ...memwrite.rpc,
  ...override.rpc,
  car: () => { const w = exp("g_world").readPointer(); return w.isNull() ? null : w.add(8).readPointer().toString(); },
  readF32: (a: string) => ptr(a).readFloat(),
  readHex: (a: string, n: number) => hex(ptr(a).readByteArray(n)),
  protection: (a: string) => Memory.queryProtection(ptr(a)),
  base: () => Process.mainModule.base.toString(),
  telemetry: (car: string) => new NativeFunction(exp("telemetry_sample"), "float", ["pointer"])(ptr(car)),
  // a Car the game never touches (speed = the given f32 bits): telemetry_sample on it returns one fixed value
  scratchCar: (speedBits: number) => {
    const p = Memory.alloc(0x80);
    p.add(8).writeU32(speedBits);
    scratch.push(p);
    return p.toString();
  },
  tinyAdd: (a: number, b: number) => new NativeFunction(exp("tiny_add"), "int", ["int", "int"])(a, b),
  tinyAddBypass: (a: number, b: number) => {
    const tid = Process.getCurrentThreadId();
    bypassing.add(tid);
    try {
      return new NativeFunction(exp("tiny_add"), "int", ["int", "int"])(a, b);
    } finally {
      bypassing.delete(tid);
    }
  },
  jsTid: () => Process.getCurrentThreadId(),
  stop: (id: string) => stop(instruments.get(id), "requested"),
  rows: () => rows.splice(0),
  ended: () => ended.splice(0),
  originals: () => [...saved.values()].map((r) => ({ site: r.site.toString(), owners: [...r.owners], patched: r.patched })),
  disposeAll: () => { for (const fn of c.hooks.onDispose) fn(); },
};
`;

interface Rpc {
  [method: string]: (...args: unknown[]) => Promise<unknown>;
}
type AgentReply = { ok: true; value: Record<string, unknown> } | { ok: false; error: Record<string, unknown> };

/** One rpc.exports call of the loaded harness (throws for an unknown export instead of returning undefined). */
const r = async (method: string, ...args: unknown[]): Promise<unknown> => {
  const fn = rpc[method];
  if (fn === undefined) throw new Error(`no rpc export ${method}`);
  return fn(...args);
};

const f32Hex = (value: number): string => Buffer.from(new Float32Array([value]).buffer).toString("hex");

let stage = "";
let frida: typeof import("frida");
let dm: InstanceType<(typeof import("frida"))["DeviceManager"]> | undefined;
let device: Awaited<ReturnType<InstanceType<(typeof import("frida"))["DeviceManager"]>["getDeviceById"]>>;
let pidcheck: string | null = null;
let pid = 0;
let session: Awaited<ReturnType<typeof device.attach>> | null = null;
let rpc: Rpc;
let game: FixtureArtifact;
let pe: PeImage;
let base = 0n;
let car = 0n;
const va = (rva: number): string => `0x${(base + BigInt(rva)).toString(16)}`;
const call = async (method: string, ...args: unknown[]): Promise<AgentReply> =>
  (await r(method, ...args)) as AgentReply;
const value = async (method: string, ...args: unknown[]): Promise<Record<string, unknown>> => {
  const reply = await call(method, ...args);
  if (!reply.ok) throw new Error(`${method} failed: ${JSON.stringify(reply.error)}`);
  return reply.value;
};
const speed = async (): Promise<number> => (await r("readF32", `0x${(car + 8n).toString(16)}`)) as number;

beforeAll(async () => {
  if (SKIP !== false) return;
  const manifest = await loadFixtures();
  const artifact = fixtureArtifact(manifest, "game_sim");
  if (artifact === null) throw new Error(`fixtures unavailable: ${JSON.stringify(manifest)}`);
  game = artifact;
  pidcheck = fixtureArtifact(manifest, "pidcheck")?.path ?? null;
  pe = parsePe(await readFile(game.path));
  frida = (await import("frida")).default as unknown as typeof import("frida");
  stage = await mkdtemp(join(tmpdir(), "bea-wp12-agent-"));
  await cp(join(REPO, "src", "agent"), join(stage, "agent"), { recursive: true });
  await cp(join(REPO, "src", "shared"), join(stage, "shared"), { recursive: true });
  await writeFile(join(stage, "agent", "state.ts"), DAY0_STATE);
  await writeFile(join(stage, "agent", "errors.ts"), DAY0_ERRORS);
  await writeFile(join(stage, "agent", "wp12Harness.ts"), HARNESS);
  const compiler = new frida.Compiler();
  const bundle = await compiler.build(join(stage, "agent", "wp12Harness.ts"), {
    projectRoot: stage,
    bundleFormat: "esm",
    typeCheck: "none",
    sourceMaps: "omitted",
    compression: "none",
  });
  // An OWNED DeviceManager, never frida.getLocalDevice()'s process-wide one (never closed): Frida copies its agent
  // DLLs (~45 MB) into %TEMP%\frida-<id> and deletes them only at DeviceManager.close(), once no target maps them.
  dm = new frida.DeviceManager();
  device = await dm.getDeviceById("local", 5000);
  pid = await device.spawn([game.path, "--no-threads", "--speed", "20", "--throttle", "0.125"], {
    cwd: game.path.replace(/[\\/][^\\/]+$/u, ""),
    stdio: frida.Stdio.Pipe,
  });
  session = await device.attach(pid);
  const script = await session.createScript(bundle, { runtime: frida.ScriptRuntime.QJS });
  await script.load();
  rpc = script.exports as unknown as Rpc;
  await device.resume(pid);
  base = BigInt((await r("base")) as string);
  await vi.waitFor(
    async () => {
      const address = (await r("car")) as string | null;
      if (address === null) throw new Error("g_world not set yet");
      car = BigInt(address);
    },
    { timeout: 10_000, interval: 25 },
  );
}, 120_000);

afterAll(async () => {
  try {
    await session?.detach();
  } catch {
    // the process may already be gone
  }
  if (pid !== 0) {
    try {
      await device.kill(pid);
    } catch {
      // already exited
    }
    // fully terminated (process object signaled; process.kill(pid, 0) reports ESRCH ~10 ms early) before close()
    await vi.waitFor(() => expect(pidStatus(pidcheck, pid).alive).toBe(false), { interval: 25, timeout: 5000 });
  }
  await dm?.close();
  if (stage !== "") await rm(stage, { recursive: true, force: true });
});

describe.skipIf(SKIP !== false)(`raw agent: gated writes on game_sim${skipNote(SKIP)}`, () => {
  it("writes data directly with read-back, overrides args, and reverts both exactly", async () => {
    const throttle = `0x${(car + 0xcn).toString(16)}`;
    expect(await speed()).toBe(20); // exact f32 equilibrium (--speed 20 --throttle 0.125)
    const written = await value("writeMemory", {
      address: throttle,
      mode: "data",
      typed: { type: "f32", values: [1] },
      allow_protect_change: true,
    });
    expect(written).toMatchObject({
      write_id: "wr1",
      size: 4,
      before: f32Hex(0.125),
      after: f32Hex(1),
      verified: true,
      method: "direct",
      effect: { kind: "memory-written", reversible: true, before: [{ address: throttle, hex: f32Hex(0.125) }] },
    });
    await vi.waitFor(async () => expect(await speed()).toBeGreaterThan(20.5), { timeout: 5000, interval: 25 });

    // An overlapping write is refused while wr1 is live.
    const overlap = await call("writeMemory", {
      address: throttle,
      mode: "data",
      bytes: "00",
      allow_protect_change: true,
    });
    expect(overlap).toMatchObject({ ok: false, error: { _tag: "BadParams" } });

    // dt (float arg 1 → xmm1) forced to 0: speed freezes while the override is active.
    const physics = va(game.pe.exportRvas["physics_step"] ?? 0);
    const headBefore = (await r("readHex", physics, 32)) as string;
    expect(headBefore).toBe(pe.readRva(game.pe.exportRvas["physics_step"] ?? 0, 32).toString("hex"));
    const installed = await value("overrideInstall", {
      target: { va: physics },
      relocation: "auto",
      mode: "rewrite",
      rewrite: { args: [{ slot: 1, class: "float", type: "f32", value: { bits: "0x0" } }] },
      lifetime: { duration_ms: 60_000, max_hits: 1_000_000 },
      record: true,
    });
    expect(installed).toMatchObject({ mode: "rewrite", stream_id: expect.stringMatching(/^s\d+$/u) });
    expect((installed["effect"] as { before: { hex: string }[] }).before[0]?.hex).toBe(headBefore);
    const trail: unknown[][] = [];
    const drain = async (): Promise<number> => {
      trail.push(...((await r("rows")) as unknown[][]));
      return trail.length;
    };
    await vi.waitFor(async () => expect(await drain()).toBeGreaterThan(0), { timeout: 5000, interval: 25 });
    const frozen = await speed();
    await vi.waitFor(async () => expect(await drain()).toBeGreaterThan(5), { timeout: 5000, interval: 25 });
    expect(await speed()).toBe(frozen);
    expect(trail[0]?.slice(4, 6)).toEqual([installed["instrument_id"], "args"]);
    expect(trail[0]?.[6]).toEqual([`0x${(0x3c888889).toString(16)}`]); // the original dt = 1/60 as f32 bits

    const summary = (await r("stop", installed["instrument_id"])) as Record<string, unknown>;
    expect(summary).toMatchObject({ kind: "override", reverted: true, verification: { kind: "bytes", ok: true } });
    expect(await r("readHex", physics, 32)).toBe(headBefore);
    await vi.waitFor(async () => expect(await speed()).toBeGreaterThan(frozen), { timeout: 5000, interval: 25 });

    const reverted = await value("revertWrite", { write_id: "wr1", force: false });
    expect(reverted).toMatchObject({
      write_id: "wr1",
      reverted: true,
      current_before_revert: f32Hex(1),
      after: f32Hex(0.125),
    });
    expect(await r("readHex", throttle, 4)).toBe(f32Hex(0.125));
    expect(await call("revertWrite", { write_id: "wr1", force: false })).toMatchObject({
      ok: false,
      error: { _tag: "NotFound", what: "write" },
    });
  });
  it("patches code with patchCode (protection stays executable) and the revert restores the file bytes", async () => {
    const tiny = game.pe.pdata["tiny_add"];
    if (tiny === undefined) throw new Error("tiny_add .pdata missing from the manifest");
    const padRva = tiny.rva + tiny.size; // alignment padding after tiny_add's ret: never executed
    const pad = va(padRva);
    const fileByte = pe.readRva(padRva, 1).toString("hex");
    expect(fileByte).not.toBe("cc");
    const written = await value("writeMemory", {
      address: pad,
      mode: "code",
      bytes: "cc",
      allow_protect_change: false,
    });
    expect(written).toMatchObject({ method: "patchCode", verified: true, before: fileByte, after: "cc" });
    expect(String(written["protection_after"])).toContain("x");
    expect(await r("protection", pad)).toContain("x");
    expect(await r("readHex", pad, 1)).toBe("cc");
    const reverted = await value("revertWrite", { write_id: written["write_id"], force: false });
    expect(reverted).toMatchObject({ reverted: true, after: fileByte });
    expect(await r("readHex", pad, 1)).toBe(fileByte);
  });
  it("guards BEA patch sites through the originals registry and reverts everything on dispose", async () => {
    const physicsRva = game.pe.exportRvas["physics_step"] ?? 0;
    const physics = va(physicsRva);
    const head = pe.readRva(physicsRva, 16).toString("hex");
    const installed = await value("overrideInstall", {
      target: { va: physics },
      relocation: "auto",
      mode: "rewrite",
      rewrite: { ret: { type: "f32", value: 1 } },
      lifetime: { duration_ms: 60_000, max_hits: 1_000_000 },
      record: false,
    });
    expect(await r("originals")).toEqual([{ site: physics, owners: [`override@${physics}`], patched: true }]);
    const overPatch = await call("writeMemory", {
      address: physics,
      mode: "code",
      bytes: "90",
      allow_protect_change: false,
    });
    expect(overPatch).toMatchObject({ ok: false, error: { _tag: "BadParams", issues: [{ path: "address" }] } });
    const steer = `0x${(car + 0x10n).toString(16)}`;
    const steerBefore = (await r("readHex", steer, 4)) as string;
    await value("writeMemory", { address: steer, mode: "data", bytes: "0000803f", allow_protect_change: true });
    await r("disposeAll"); // rpc.exports.dispose path: synchronous disarm of every override and write
    expect(await r("readHex", physics, 16)).toBe(head);
    expect(await r("readHex", steer, 4)).toBe(steerBefore);
    expect(await r("originals")).toEqual([]);
    expect(String(installed["instrument_id"])).toMatch(/^o\d+$/u);
  });
});

describe.skipIf(SKIP !== false)(`raw agent: overrides on game_sim${skipNote(SKIP)}`, () => {
  it("replaces a tiny function with a constant, refuses a second override, and reverts", async () => {
    const tiny = va(game.pe.exportRvas["tiny_add"] ?? 0);
    expect(await r("tinyAdd", 1, 2)).toBe(3);
    const installed = await value("overrideInstall", {
      target: { va: tiny },
      relocation: "auto",
      mode: "replace",
      replace: { ret_type: "i32", arg_types: [], returns: 7 },
      lifetime: { duration_ms: 60_000, max_hits: 1_000_000 },
      record: false,
    });
    expect(installed).toMatchObject({ mode: "replace", stream_id: null });
    expect(await r("tinyAdd", 1, 2)).toBe(7);
    const second = await call("overrideInstall", {
      target: { va: tiny },
      relocation: "auto",
      mode: "replace",
      replace: { ret_type: "i32", arg_types: [], returns: 8 },
      lifetime: { duration_ms: 1000, max_hits: 1 },
      record: false,
    });
    expect(second).toMatchObject({ ok: false, error: { _tag: "HookConflict" } });
    const summary = (await r("stop", installed["instrument_id"])) as Record<string, unknown>;
    expect(summary).toMatchObject({ reverted: true, verification: { ok: true } });
    expect(await r("tinyAdd", 1, 2)).toBe(3);
    expect(await r("readHex", tiny, 4)).toBe(pe.readRva(game.pe.exportRvas["tiny_add"] ?? 0, 4).toString("hex"));
  });
  it("replace falls through to the original for a bypassing BEA call, a filtered call and after max_hits", async () => {
    // tiny_add (forced relocation): thread filter = the agent JS thread (the game's main thread is filtered and keeps
    // calling the original through the stub), every_n 2 alternates, a bypassing call always runs the original
    const tiny = va(game.pe.exportRvas["tiny_add"] ?? 0);
    const jsTid = (await r("jsTid")) as number;
    const filtered = await value("overrideInstall", {
      target: { va: tiny },
      relocation: "auto",
      mode: "replace",
      replace: { ret_type: "i32", arg_types: [], returns: -5 },
      when: { thread_ids: [jsTid], every_n: 2 },
      lifetime: { duration_ms: 60_000, max_hits: 1_000_000 },
      record: true,
    });
    const results = [];
    for (let i = 0; i < 4; i++) results.push(await r("tinyAdd", 40, i));
    expect(results).toEqual([-5, 41, -5, 43]);
    expect(await r("tinyAddBypass", 1, 2)).toBe(3);
    const id = String(filtered["instrument_id"]);
    expect(((await r("rows")) as unknown[][]).filter((row) => row[4] === id)).toHaveLength(2);
    const summary = (await r("stop", id)) as Record<string, unknown>;
    expect(summary).toMatchObject({ reverted: true, verification: { ok: true }, hits: 2 });
    expect(await r("readHex", tiny, 4)).toBe(pe.readRva(game.pe.exportRvas["tiny_add"] ?? 0, 4).toString("hex"));

    // telemetry_sample: a float constant in xmm0; once max_hits is reached the stub forwards the pointer argument to
    // the original and its float return comes back untouched (before and after the asynchronous revert). The car is
    // a scratch Car at exactly 20.0 m/s: the live car's speed drifts after the earlier tests' throttle write (WP18
    // saw two reads a frame apart differ: 74.5148 vs 74.5127), and the original's return must be one fixed value.
    const target = va(game.pe.exportRvas["telemetry_sample"] ?? 0);
    const carText = String(await r("scratchCar", 0x41a00000));
    const original = (await r("telemetry", carText)) as number;
    expect(original).toBe(Math.fround(20 * 3.6));
    const once = await value("overrideInstall", {
      target: { va: target },
      relocation: "auto",
      mode: "replace",
      replace: { ret_type: "f32", arg_types: [], returns: { bits: "0x42f60000" } }, // 123.0
      lifetime: { duration_ms: 60_000, max_hits: 1 },
      record: false,
    });
    expect(await r("telemetry", carText)).toBe(123);
    expect(await r("telemetry", carText)).toBe(original); // stopping: decide answers "original"
    await vi.waitFor(
      async () => {
        const ended = (await r("ended")) as { id: string; summary: Record<string, unknown> }[];
        const end = ended.find((e) => e.id === String(once["instrument_id"]))?.summary;
        expect(end).toMatchObject({ end_reason: "max_hits", reverted: true, verification: { ok: true } });
      },
      { timeout: 5000, interval: 25 },
    );
    expect(await r("telemetry", carText)).toBe(original);
    expect(await r("readHex", target, 16)).toBe(
      pe.readRva(game.pe.exportRvas["telemetry_sample"] ?? 0, 16).toString("hex"),
    );
  });
  it("rewrites a float return, counts max_hits and ends itself with an override/1 trail", async () => {
    const target = va(game.pe.exportRvas["telemetry_sample"] ?? 0);
    const carText = `0x${car.toString(16)}`;
    const original = (await r("telemetry", carText)) as number;
    const installed = await value("overrideInstall", {
      target: { va: target },
      relocation: "auto",
      mode: "rewrite",
      rewrite: { ret: { type: "f32", value: { bits: "0x42f60000" } } }, // 123.0
      lifetime: { duration_ms: 60_000, max_hits: 2 },
      record: true,
    });
    const id = String(installed["instrument_id"]);
    expect(await r("telemetry", carText)).toBe(123);
    expect(await r("telemetry", carText)).toBe(123);
    await vi.waitFor(
      async () => {
        const ended = (await r("ended")) as { id: string; summary: Record<string, unknown> }[];
        expect(ended.find((e) => e.id === id)?.summary).toMatchObject({ end_reason: "max_hits", reverted: true });
      },
      { timeout: 5000, interval: 25 },
    );
    const third = (await r("telemetry", carText)) as number;
    expect(third).not.toBe(123);
    expect(Math.abs(third - original)).toBeLessThan(1000);
    const rows = ((await r("rows")) as unknown[][]).filter((row) => row[4] === id);
    expect(rows).toHaveLength(2);
    expect(rows[0]?.[5]).toBe("ret");
    expect(rows[0]?.[6]).toHaveLength(1); // the original return value's bits
  });
  it("a short lifetime ends the override by duration", async () => {
    const target = va(game.pe.exportRvas["car_energy"] ?? 0);
    const installed = await value("overrideInstall", {
      target: { va: target },
      relocation: "auto",
      mode: "rewrite",
      rewrite: { ret: { type: "f32", value: 1 } },
      lifetime: { duration_ms: 150, max_hits: 1_000_000 },
      record: false,
    });
    const id = String(installed["instrument_id"]);
    await vi.waitFor(
      async () => {
        const ended = (await r("ended")) as { id: string; summary: Record<string, unknown> }[];
        expect(ended.find((e) => e.id === id)?.summary).toMatchObject({ end_reason: "duration", reverted: true });
      },
      { timeout: 5000, interval: 25 },
    );
    expect(await r("readHex", target, 16)).toBe(pe.readRva(game.pe.exportRvas["car_energy"] ?? 0, 16).toString("hex"));
  });
});
