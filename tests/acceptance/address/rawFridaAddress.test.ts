import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { AddressServiceImpl } from "../../../src/application/address/AddressService.js";
import type { HostPlatform } from "../../../src/domain/paths.js";
import { ok } from "../../../src/domain/result.js";
import type { AgentRpc } from "../../../src/ports/agentRpc.js";
import type { AddressSpace } from "../../../src/ports/address.js";
import type { LiveSession } from "../../../src/ports/sessions.js";
import { PersistentFileHashCache } from "../../../src/providers/pe/FileHashCache.js";
import { LruPeImageCache } from "../../../src/providers/pe/PeImageCache.js";
import {
  fixtureArtifact,
  fridaSkip,
  gccSkip,
  loadFixtures,
  skipNote,
  type FixtureArtifact,
} from "../../support/acceptance/fixtures.js";
import { pidStatus } from "../../support/process/ownedPidLedger.js";
import { createTempHome, type TempHome } from "../../support/workspace/tempHome.js";
import { fakeEvidence, moduleMapOf, testOp, type FakeEvidence } from "../../unit/address/support/fakes.js";

/**
 * WP5 acceptance through RAW Frida RPCs (DESIGN §8.4 wave rule: only earlier waves, raw agent RPCs or fakes): a
 * minimal in-target script stands in for the agent's readMemory / listModules / resolveTargets, the REAL
 * AddressService + PE reader do the work. Rows: `+0x<rva>` = Frida's findExportByName; the static form = the export;
 * verify_bytes `match` on .text; after a code write with BEA's originals registered, still `match` with
 * own_effects_restored > 0; the footprint scan finds ≥ 1 ntdll range (the agent's own patches); `.data` →
 * not-applicable; crashy's faulting pc → `at` = the manifest crash site and `sym` = the exported crash function.
 * Every process is spawned by this file and killed in afterAll.
 */
const SCRIPT = `
const toHex = (p) => p.toString();
const readPrefix = (address, size) => {
  try { return ptr(address).readByteArray(size); } catch (e) {}
  // the readable prefix, page by page
  const out = [];
  let at = ptr(address); let left = size;
  while (left > 0) {
    const step = Math.min(left, 0x1000 - (at.toUInt32() & 0xfff));
    try { out.push(new Uint8Array(at.readByteArray(step))); } catch (e) { break; }
    at = at.add(step); left -= step;
  }
  const total = out.reduce((n, a) => n + a.length, 0);
  const buf = new Uint8Array(total); let o = 0;
  for (const a of out) { buf.set(a, o); o += a.length; }
  return buf.buffer;
};
rpc.exports = {
  modules() { return Process.enumerateModules().map((m) => ({ name: m.name, path: m.path, base: toHex(m.base), size: m.size })); },
  read(address, size) { return readPrefix(address, size); },
  exportVa(module, name) { const p = Process.getModuleByName(module).findExportByName(name); return p === null ? null : toHex(p); },
  patch(address, hex) {
    const bytes = hex.match(/../g).map((b) => parseInt(b, 16));
    Memory.patchCode(ptr(address), bytes.length, (code) => code.writeByteArray(bytes));
    return true;
  },
};
Process.setExceptionHandler((d) => {
  send({ crash: { type: d.type, pc: toHex(d.context.pc) } });
  recv("ack", () => {}).wait();
  return false;
});
`;

const platform = process.platform as HostPlatform;
const skipReason = gccSkip() || fridaSkip();

interface Target {
  readonly pid: number;
  readonly session: LiveSession;
  readonly script: {
    exports: Record<string, (...args: unknown[]) => Promise<unknown>>;
    post(m: unknown): void;
    unload(): Promise<void>;
  };
  readonly crash: Promise<{ type: string; pc: string }>;
  readonly evidence: FakeEvidence;
}

type Frida = typeof import("frida");
let frida: Frida;
/** This file's own DeviceManager (never the singleton): closing it lets Frida delete its %TEMP% agent copies. */
let dm: InstanceType<Frida["DeviceManager"]> | undefined;
let device: Awaited<ReturnType<Frida["getLocalDevice"]>>;
let pidcheck: string | null = null;
let home: TempHome;
let game: FixtureArtifact;
let crashy: FixtureArtifact;
const spawned: number[] = [];
let images: LruPeImageCache;
let hashes: PersistentFileHashCache;

const start = async (artifact: FixtureArtifact, argv: readonly string[]): Promise<Target> => {
  const pid = await device.spawn([artifact.path, ...argv], { cwd: join(artifact.path, "..") });
  spawned.push(pid);
  const fridaSession = await device.attach(pid);
  const script = await fridaSession.createScript(SCRIPT, { runtime: frida.ScriptRuntime.QJS });
  let onCrash: (c: { type: string; pc: string }) => void = () => undefined;
  const crash = new Promise<{ type: string; pc: string }>((resolve) => (onCrash = resolve));
  script.message.connect((message) => {
    if (message.type === "send" && (message.payload as { crash?: unknown }).crash !== undefined)
      onCrash((message.payload as { crash: { type: string; pc: string } }).crash);
  });
  await script.load();
  const exports = script.exports as unknown as Target["script"]["exports"];
  const instance = `pi_${pid.toString(16).padStart(64, "0")}` as const;
  const evidence = fakeEvidence(instance);
  const modules = (await exports["modules"]?.()) as { name: string; path: string; base: string; size: number }[];
  evidence.map = moduleMapOf(
    instance,
    modules.map((m) => ({ name: m.name, path: m.path, base: BigInt(m.base), size: m.size })),
  );
  const agent: AgentRpc = {
    health: { state: "ok" },
    call: (async (method: string, params: Record<string, unknown>) => {
      if (method === "readMemory") {
        const data = Buffer.from((await exports["read"]?.(params["address"], params["size"])) as Buffer);
        const size = params["size"] as number;
        return ok({
          value: {
            address: params["address"],
            requested: size,
            returned: data.length,
            complete: data.length === size,
            stop: null,
            bea_guard_suspended: [],
          },
          data,
        });
      }
      if (method === "listModules")
        return ok({ module_map_epoch: 1, modules: (await exports["modules"]?.()) as unknown[] });
      if (method === "resolveTargets") {
        const [target] = params["targets"] as { module: string; export: string }[];
        const va = (await exports["exportVa"]?.(target?.module, target?.export)) as string | null;
        return ok({
          results: [
            va === null
              ? { ok: false, error: { code: "not_found" } }
              : {
                  ok: true,
                  target: {
                    va,
                    module: null,
                    module_base: null,
                    rva: null,
                    export: null,
                    function: null,
                    protection: null,
                  },
                },
          ],
        });
      }
      throw new Error(`raw agent: ${method}`);
    }) as AgentRpc["call"],
  };
  const session = {
    id: "3f2b8c1e-5d4a-4b6f-9a7e-1c2d3e4f5a6b",
    kind: "live",
    ownership: "owned",
    state: "paused",
    instanceId: instance,
    identity: {
      deviceId: "local",
      pid,
      startTime: { source: "frida-started", value: new Date().toISOString() },
      image: { path: artifact.path, sha256: null, size: null, machine: "x64", peTimestamp: null, preferredBase: null },
      parentPid: null,
      osSessionId: null,
      integrity: "medium",
      launchedByBea: true,
    },
    agent,
  } as unknown as LiveSession;
  return { pid, session, script: script as unknown as Target["script"], crash, evidence };
};

const service = (evidence: FakeEvidence) =>
  new AddressServiceImpl({
    evidence: evidence.runtime,
    pe: { images, hashes },
    emulator: () => {
      throw new Error("no emulator");
    },
    platform,
  });

beforeAll(async () => {
  home = await createTempHome("addr-frida");
  if (skipReason !== false) return;
  const manifest = await loadFixtures();
  const g = fixtureArtifact(manifest, "game_sim");
  const c = fixtureArtifact(manifest, "crashy");
  if (g === null || c === null) throw new Error("fixtures unavailable");
  game = g;
  crashy = c;
  pidcheck = fixtureArtifact(manifest, "pidcheck")?.path ?? null;
  frida = await import("frida");
  dm = new frida.DeviceManager();
  device = await dm.getDeviceById("local", 5000);
  images = new LruPeImageCache(platform);
  hashes = new PersistentFileHashCache(join(home.beaHome, "cache", "file-sha256.jsonl"), platform);
}, 600_000);

afterAll(async () => {
  for (const pid of spawned) await device?.kill(pid).catch(() => undefined);
  // DeviceManager.close() deletes Frida's %TEMP%\frida-<id> agent copies (~45 MB) only once no target maps them
  await vi.waitFor(() => expect(spawned.filter((pid) => pidStatus(pidcheck, pid).alive)).toEqual([]), {
    interval: 25,
    timeout: 5000,
  });
  await dm?.close();
  await home.cleanup();
});

describe.skipIf(skipReason !== false)(`map_address model against a real process${skipNote(skipReason)}`, () => {
  it("resolves +0xRVA and the static form to Frida's export address, verifies .text, skips .data", async () => {
    const target = await start(game, ["--no-threads"]);
    const svc = service(target.evidence);
    const space: AddressSpace = { kind: "live", session: target.session };
    const op = testOp();
    const physicsRva = game.pe.exportRvas["physics_step"] ?? 0;
    const fridaVa = BigInt((await target.script.exports["exportVa"]?.("game_sim.exe", "physics_step")) as string);
    const byRva = await svc.resolve(space, `+0x${physicsRva.toString(16)}`, op);
    expect(byRva.ok && byRva.value.va).toBe(fridaVa);
    const byStatic = await svc.resolve(space, `game_sim.exe:0x${(0x140000000 + physicsRva).toString(16)}`, op);
    expect(byStatic.ok && byStatic.value.va).toBe(fridaVa);
    expect(byStatic.ok && byStatic.value.ref.symbol?.name).toBe("physics_step");
    // relocated file bytes equal live code exactly [S2-lab E2]
    expect(await svc.verify(space, fridaVa, 64, op)).toMatchObject({
      ok: true,
      value: { status: "match", compared: 64, equal: 64 },
    });
    const data = game.pe.sections.find((s) => s.name === ".data");
    const base = fridaVa - BigInt(physicsRva);
    expect(await svc.verify(space, base + BigInt(data?.rva ?? 0), 16, op)).toMatchObject({
      ok: true,
      value: { status: "not-applicable", compared: 0 },
    });
    // a kernel32 export through the real module list (forwarders follow into ntdll / API sets through the "agent")
    const sleep = await svc.resolve(space, "kernel32.dll!Sleep", op);
    expect(sleep.ok && sleep.value.va).toBe(
      BigInt((await target.script.exports["exportVa"]?.("kernel32.dll", "Sleep")) as string),
    );
  });

  it("after a code write with BEA's originals registered, verification still matches (own_effects_restored > 0)", async () => {
    const target = await start(game, ["--no-threads"]);
    const svc = service(target.evidence);
    const space: AddressSpace = { kind: "live", session: target.session };
    const op = testOp();
    const va = BigInt((await target.script.exports["exportVa"]?.("game_sim.exe", "physics_step")) as string);
    const original = Buffer.from((await target.script.exports["read"]?.(`0x${va.toString(16)}`, 4)) as Buffer);
    await target.script.exports["patch"]?.(`0x${va.toString(16)}`, "cccccccc");
    const patched = await svc.verify(space, va, 16, op);
    expect(patched.ok && patched.value.status).toBe("mismatch");
    target.evidence.originals.set(va, new Uint8Array(original));
    expect(await svc.verify(space, va, 16, op)).toMatchObject({
      ok: true,
      value: { status: "match", own_effects_restored: 4 },
    });
  });

  it("the footprint scan finds the injected agent's own ntdll patches", async () => {
    const target = await start(game, ["--no-threads"]);
    const svc = service(target.evidence);
    const space: AddressSpace = { kind: "live", session: target.session };
    const op = testOp();
    const view = await svc.view(space, op);
    if (!view.ok) throw new Error("view");
    const ntdll = view.value.modules.find((m) => m.name.toLowerCase() === "ntdll.dll");
    if (ntdll === undefined) throw new Error("no ntdll");
    const image = await svc.imageOf(ntdll);
    if (image === null) throw new Error("ntdll image");
    const ranges = await svc.footprint.scan(target.session, ntdll, image, op);
    expect(ranges).not.toBeNull();
    expect(ranges?.length ?? 0).toBeGreaterThanOrEqual(1);
    // a verification over the first patched range is classified as the agent's/foreign patch, not unexplained
    const first = ranges?.[0];
    if (first === undefined) throw new Error("no range");
    const detail = await svc.verify(space, ntdll.base + BigInt(first.rva), Math.min(16, first.size + 4), op);
    expect(detail.ok && detail.value.status).toBe("mismatch");
    expect(detail.ok && detail.value.differences.every((d) => d.class === "foreign-or-agent-patch")).toBe(true);
  });

  it("crashy's faulting pc describes as the manifest crash site and the exported crash function", async () => {
    const target = await start(crashy, ["av-write"]);
    const svc = service(target.evidence);
    const space: AddressSpace = { kind: "live", session: target.session };
    await device.resume(target.pid);
    const crash = await Promise.race([
      target.crash,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("no crash within 15 s")), 15_000)),
    ]);
    expect(crash.type).toBe("access-violation");
    const site = (crashy.expectations["crashWrite"] as { rva: number }).rva;
    const loc = await svc.describeCode(space, BigInt(crash.pc));
    target.script.post({ type: "ack" });
    expect(loc.at).toBe(`crashy.exe+0x${site.toString(16)}`);
    expect(loc.func).toBe(`crashy.exe+0x${(crashy.pe.exportRvas["crash_write"] ?? 0).toString(16)}`);
    const offset = site - (crashy.pe.exportRvas["crash_write"] ?? 0);
    expect(loc.sym).toBe(offset === 0 ? "crash_write" : `crash_write+0x${offset.toString(16)}`);
    expect(loc.static).toBe(`crashy.exe:0x${(0x140000000 + site).toString(16)}`);
  });
});
