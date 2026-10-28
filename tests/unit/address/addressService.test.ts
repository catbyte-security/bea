import { copyFile } from "node:fs/promises";
import { join } from "node:path";

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { AddressServiceImpl } from "../../../src/application/address/AddressService.js";
import { runMapAddress } from "../../../src/application/address/MapAddress.js";
import { mapAddressInputSchema } from "../../../src/contracts/areas/address.js";
import { addressRefSchema, locSchema } from "../../../src/domain/address/addressRef.js";
import type { HostPlatform } from "../../../src/domain/paths.js";
import type { AddressSpace } from "../../../src/ports/address.js";
import type { PeImage } from "../../../src/ports/pe.js";
import { PersistentFileHashCache } from "../../../src/providers/pe/FileHashCache.js";
import { LruPeImageCache } from "../../../src/providers/pe/PeImageCache.js";
import { fixtureArtifact, gccSkip, loadFixtures, type FixtureArtifact } from "../../support/acceptance/fixtures.js";
import { createTempHome, type TempHome } from "../../support/workspace/tempHome.js";
import { fakeEmu, fakeEvidence, fakeProcess, testOp, type FakeEvidence, type FakeProcess } from "./support/fakes.js";

/**
 * AddressService over fakes (S2 §16.2–16.3, §18.3; S6 §2.1–2.2): every AddrExpr form against a modelled live
 * process built from the REAL fixture and system DLL files, the S2 §16.2 error table, compact Addr/Loc,
 * prepare/describe, byte verification (match, loader masks, own effects, foreign patch, writable section), and the
 * emulation and file spaces.
 */
const windows = process.platform === "win32";
const platform = process.platform as HostPlatform;
const SYS = join(process.env["SystemRoot"] ?? "C:\\Windows", "System32");
const GAME_BASE = 0x7ff6_a000_0000n;
const KERNEL32_BASE = 0x7ffa_1000_0000n;
const NTDLL_BASE = 0x7ffa_2000_0000n;
const KERNELBASE_BASE = 0x7ffa_3000_0000n;
const MATH_A = 0x7ffa_4000_0000n;
const MATH_B = 0x7ffa_5000_0000n;

const skip = !windows || gccSkip() !== false;

let home: TempHome;
let game: FixtureArtifact;
let mathlib: FixtureArtifact;
let mathCopy: string;
let images: LruPeImageCache;
let hashes: PersistentFileHashCache;
let ev: FakeEvidence;
let proc: FakeProcess;
let svc: AddressServiceImpl;
let space: AddressSpace;
const op = testOp();

beforeAll(async () => {
  home = await createTempHome("addr");
  if (skip) return;
  const manifest = await loadFixtures();
  const g = fixtureArtifact(manifest, "game_sim");
  const m = fixtureArtifact(manifest, "mathlib");
  if (g === null || m === null) throw new Error("fixtures unavailable");
  game = g;
  mathlib = m;
  // a second mathlib.dll (same basename, other directory) to exercise module_ambiguous
  mathCopy = join(home.work, "mathlib.dll");
  await copyFile(mathlib.path, mathCopy);
}, 600_000);
afterAll(async () => {
  await home.cleanup();
});

beforeEach(async () => {
  if (skip) return;
  images = new LruPeImageCache(platform);
  hashes = new PersistentFileHashCache(join(home.beaHome, "cache", "file-sha256.jsonl"), platform);
  ev = fakeEvidence();
  proc = await fakeProcess(
    images,
    [
      { path: game.path, base: GAME_BASE },
      { path: join(SYS, "kernel32.dll"), base: KERNEL32_BASE, name: "KERNEL32.DLL" },
      { path: join(SYS, "ntdll.dll"), base: NTDLL_BASE },
      { path: join(SYS, "KernelBase.dll"), base: KERNELBASE_BASE, name: "KERNELBASE.dll" },
      { path: mathlib.path, base: MATH_A },
      { path: mathCopy, base: MATH_B },
    ],
    ev,
  );
  svc = new AddressServiceImpl({
    evidence: ev.runtime,
    pe: { images, hashes },
    emulator: () => {
      throw new Error("emulator not composed");
    },
    platform,
  });
  space = { kind: "live", session: proc.session };
});

const rva = (name: string): number => {
  const value = game.pe.exportRvas[name];
  if (value === undefined) throw new Error(`no export ${name}`);
  return value;
};
const resolveOk = async (expr: string) => {
  const r = await svc.resolve(space, expr, op);
  if (!r.ok) throw new Error(`${expr}: ${JSON.stringify(r.error)}`);
  return r.value;
};
const resolveErr = async (expr: string) => {
  const r = await svc.resolve(space, expr, op);
  if (r.ok) throw new Error(`${expr} resolved to ${r.value.ref.va}`);
  return r.error;
};

describe.skipIf(skip)("AddressService.resolve (S2 §16.3)", () => {
  it("resolves +0xRVA, module+0xRVA, exports, ordinals and static forms to the same AddressRef", async () => {
    const physics = rva("physics_step");
    const main = await resolveOk(`+0x${physics.toString(16)}`);
    expect(main.va).toBe(GAME_BASE + BigInt(physics));
    expect(main.moduleMapId).toBe(ev.map?.module_map_id);
    expect(main.ref).toMatchObject({
      module: "game_sim.exe",
      rva: `0x${physics.toString(16)}`,
      static_va: `0x${(0x140000000 + physics).toString(16)}`,
      static_base: "0x140000000",
      static_base_source: "pe-header",
      image_sha256: game.artifactSha256,
      section: ".text",
      symbol: { name: "physics_step", kind: "export", offset: "0x0", source: "pe-export" },
    });
    expect(addressRefSchema.safeParse(main.ref).success).toBe(true);
    for (const expr of [
      `game_sim.exe+0x${physics.toString(16)}`,
      `GAME_SIM.EXE+0x${physics.toString(16)}`,
      "game_sim.exe!physics_step",
      `game_sim.exe:0x${(0x140000000 + physics).toString(16)}`,
      `$main:0x${(0x140000000 + physics).toString(16)}`,
      `game_sim:0x${(0x140000000 + physics).toString(16)}`,
      `0x${(GAME_BASE + BigInt(physics)).toString(16)}`,
      `"${game.path.replaceAll("\\", "\\\\")}"+0x${physics.toString(16)}`,
    ])
      expect((await resolveOk(expr)).va, expr).toBe(main.va);
    const pe = await images.open(game.path);
    if (!pe.ok) throw new Error("open");
    const ordinal = (await pe.value.exports()).find((e) => e.name === "physics_step")?.ordinal;
    expect((await resolveOk(`game_sim.exe!#${String(ordinal)}`)).va).toBe(main.va);
    const displaced = await resolveOk("game_sim.exe!physics_step+0x10");
    expect(displaced.va).toBe(main.va + 0x10n);
    expect(displaced.ref.symbol).toMatchObject({ name: "physics_step", offset: "0x10" });
  });

  it("uses a caller static base (/0xBASE) and an REA base, recording the source", async () => {
    const physics = rva("physics_step");
    const ghidra = await resolveOk(`game_sim.exe:0x${(0x150000000 + physics).toString(16)}/0x150000000`);
    expect(ghidra.va).toBe(GAME_BASE + BigInt(physics));
    expect(ghidra.ref).toMatchObject({ static_base: "0x150000000", static_base_source: "caller" });
    const view = await svc.view(space, op);
    if (!view.ok) throw new Error("view");
    const rea = await svc.resolveParsed(
      space,
      view.value,
      { form: "static", module: { kind: "main" }, static_va: 0x160000000n + BigInt(physics), static_base: null },
      op,
      { reaBase: 0x160000000n },
    );
    expect(rea.ok && rea.value.ref.static_base_source).toBe("rea-evidence");
    expect(rea.ok && rea.value.callerBaseDiffers).toBeNull();
    const caller = await svc.resolveParsed(
      space,
      view.value,
      {
        form: "static",
        module: { kind: "main" },
        static_va: 0x150000000n + BigInt(physics),
        static_base: 0x150000000n,
      },
      op,
      {},
    );
    expect(caller.ok && caller.value.callerBaseDiffers).toBe(0x140000000n);
  });

  it("follows export forwarders (kernel32 → ntdll) and API-set forwarders through the agent", async () => {
    const forwarded = await resolveOk("kernel32.dll!AcquireSRWLockExclusive");
    expect(forwarded.ref.module).toBe("ntdll.dll");
    expect(forwarded.ref.symbol).toMatchObject({
      name: "RtlAcquireSRWLockExclusive",
      kind: "export",
      forwarded_from: "KERNEL32.DLL!AcquireSRWLockExclusive",
    });
    const kernelbase = await images.open(join(SYS, "KernelBase.dll"));
    if (!kernelbase.ok) throw new Error("open");
    const target = (await kernelbase.value.exports()).find((e) => e.name === "AddDllDirectory")?.rva ?? 0;
    proc.exportsByName.set("kernel32.dll!AddDllDirectory", KERNELBASE_BASE + BigInt(target));
    const apiSet = await resolveOk("kernel32!AddDllDirectory");
    expect(apiSet.ref.module).toBe("KERNELBASE.dll");
    expect(apiSet.va).toBe(KERNELBASE_BASE + BigInt(target));
    expect(proc.calls.some((c) => c.method === "resolveTargets")).toBe(true);
    // an API-set forwarder the agent cannot resolve
    expect(await resolveErr("kernel32.dll!BuildIoRingCancelRequest")).toMatchObject({
      _tag: "AddressUnmapped",
      diagnostics: { reason: "forwarder_unresolved" },
    });
  });

  it("implements the S2 §16.2 error table", async () => {
    const missing = await resolveErr("game_sim2.exe+0x10");
    expect(missing).toMatchObject({
      _tag: "AddressUnmapped",
      diagnostics: { reason: "module_not_loaded", token: "game_sim2.exe", suggestions: ["game_sim.exe"] },
    });
    expect(proc.calls.filter((c) => c.method === "listModules").length).toBe(1); // one refresh before failing
    expect(await resolveErr("mathlib.dll+0x10")).toMatchObject({
      _tag: "InputError",
      diagnostics: { reason: "module_ambiguous" },
    });
    expect((await resolveOk(`mathlib.dll@0x${MATH_B.toString(16)}+0x10`)).va).toBe(MATH_B + 0x10n);
    expect((await resolveOk("kernel32+0x10")).ref.module).toBe("KERNEL32.DLL");
    const notFound = await resolveErr("kernel32.dll!Slep");
    expect(notFound).toMatchObject({ _tag: "InputError", diagnostics: { reason: "export_not_found" } });
    expect((notFound.diagnostics?.["similar"] as string[]).includes("Sleep")).toBe(true);
    expect(await resolveErr(`game_sim.exe+0x${game.pe.sizeOfImage.toString(16)}`)).toMatchObject({
      issues: [{ reason: "out_of_range" }],
      diagnostics: { reason: "rva_out_of_image", size_of_image: game.pe.sizeOfImage },
    });
    expect(await resolveErr("game_sim.exe:0x13fffffff")).toMatchObject({
      diagnostics: { reason: "static_out_of_image" },
    });
    expect(await resolveErr("1234")).toMatchObject({
      _tag: "InputError",
      issues: [{ path: "address", reason: "invalid_format" }],
    });
    const mismatch = await svc.resolve(space, "+0x1000", op, { expectedImageSha256: "0".repeat(64), path: "target" });
    expect(!mismatch.ok && mismatch.error).toMatchObject({
      issues: [{ path: "target" }],
      diagnostics: { reason: "image_mismatch" },
    });
    expect((await svc.resolve(space, "+0x1000", op, { expectedImageSha256: game.artifactSha256 })).ok).toBe(true);
  });

  it("returns a non-image AddressRef for a VA outside every module", async () => {
    const r = await resolveOk("0x10000010");
    expect(r.ref).toEqual({
      va: "0x10000010",
      module: null,
      rva: null,
      static_va: null,
      static_base: null,
      static_base_source: null,
      module_map_id: ev.map?.module_map_id,
    });
    expect(svc.validate("0x10").ok).toBe(true);
    expect(svc.validate("0x800000000000")).toMatchObject({ ok: false, error: { reason: "out_of_range" } });
  });
});

describe.skipIf(skip)("compact forms (S6 §2.2, CI-I10)", () => {
  it("describe() gives static only after prepare(); describeCode() names exact-export function starts only", async () => {
    const physics = rva("physics_step");
    const va = GAME_BASE + BigInt(physics) + 0x36n;
    const fresh = new AddressServiceImpl({
      evidence: ev.runtime,
      pe: { images, hashes },
      emulator: () => {
        throw new Error("late");
      },
      platform,
    });
    expect(fresh.describe(space, va)).toEqual({
      va: `0x${va.toString(16)}`,
      at: `game_sim.exe+0x${(physics + 0x36).toString(16)}`,
      static: null,
    });
    // UX-10: prepare() always includes the main image; recordings decode static frames from this cache
    expect(fresh.preferredBaseOf(game.path)).toBeNull();
    await fresh.prepare(space, [], op);
    expect(fresh.preferredBaseOf(game.path)).toBe(0x140000000n);
    await fresh.prepare(space, [va], op);
    expect(fresh.describe(space, va).static).toBe(`game_sim.exe:0x${(0x140000000 + physics + 0x36).toString(16)}`);
    const loc = await fresh.describeCode(space, va);
    expect(loc).toMatchObject({ func: `game_sim.exe+0x${physics.toString(16)}`, sym: "physics_step+0x36" });
    expect(locSchema.safeParse(loc).success).toBe(true);
    // DATA-7: caller-table names (map_address symbols) never replace or hide an export in a Loc
    const sha = await hashes.sha256(game.path);
    if (!sha.ok) throw new Error("hash");
    const engine = rva("engine_update");
    fresh.callerSymbols.register(sha.value, [
      { rva: physics, name: "analyst_guess", size: engine + 16 - physics, evidence_id: null },
    ]);
    expect((await fresh.describeCode(space, va)).sym).toBe("physics_step+0x36");
    expect((await fresh.describeCode(space, GAME_BASE + BigInt(engine))).sym).toBe("engine_update");
    // a duplicate basename carries @0xBASE so the text resolves back to the same module
    const dup = fresh.describe(space, MATH_B + 0x1000n);
    expect(dup.at).toBe(`mathlib.dll@0x${MATH_B.toString(16)}+0x1000`);
    expect((await resolveOk(dup.at ?? "")).va).toBe(MATH_B + 0x1000n);
    expect(fresh.describe(space, 0x10000000n)).toEqual({ va: "0x10000000", at: null, static: null });
    // an unexported static function: func set, sym null
    const pe = await images.open(game.path);
    if (!pe.ok) throw new Error("open");
    const exported = new Set(Object.values(game.pe.exportRvas));
    const hidden = [...(await pe.value.functions()).entries()].find(
      (e) => e.primary_begin === e.begin && !exported.has(e.begin),
    );
    if (hidden !== undefined) {
      const hiddenLoc = await fresh.describeCode(space, GAME_BASE + BigInt(hidden.begin) + 1n);
      expect(hiddenLoc.func).toBe(`game_sim.exe+0x${hidden.begin.toString(16)}`);
      expect(hiddenLoc.sym).toBeNull();
    }
    // agent backtrace frame text
    expect((await fresh.fromFrameRef(space, `game_sim.exe+0x${(physics + 4).toString(16)}`)).sym).toBe(
      "physics_step+0x4",
    );
    expect(await fresh.fromFrameRef(space, "gone.dll+0x10")).toMatchObject({ va: "0x0", at: "gone.dll+0x10" });
  });
});

describe.skipIf(skip)("byte verification (S2 §18.3)", () => {
  const image = async (path: string): Promise<PeImage> => {
    const r = await images.open(path);
    if (!r.ok) throw new Error("open");
    return r.value;
  };

  it("matches code after relocation, masks IAT slots and the rewritten header ImageBase", async () => {
    const physics = GAME_BASE + BigInt(rva("physics_step"));
    expect(await svc.verify(space, physics, 64, op)).toEqual({
      ok: true,
      value: { status: "match", compared: 64, equal: 64, excluded_loader: 0, own_effects_restored: 0, differences: [] },
    });
    // kernel32's IAT lives in .rdata: the loader-written slots are excluded, never compared
    const k32 = await image(join(SYS, "kernel32.dll"));
    const slot = (await k32.imports())[0]?.slot_rva ?? 0;
    const iat = await svc.verify(space, KERNEL32_BASE + BigInt(slot), 32, op);
    // every byte of the window is a loader-written slot: nothing compared, nothing claimed
    expect(iat.ok && iat.value).toMatchObject({ status: "skipped", compared: 0, excluded_loader: 32, differences: [] });
    const header = await svc.verify(space, GAME_BASE, 0x200, op);
    expect(header.ok && header.value).toMatchObject({ status: "match", excluded_loader: 8 });
  });

  it("restores BEA's own patches, classifies foreign code patches by the footprint scan, flags the rest", async () => {
    const physics = GAME_BASE + BigInt(rva("physics_step"));
    const original = await image(game.path).then((pe) => pe.imageBytes(rva("physics_step"), 6, GAME_BASE));
    proc.write(physics, Uint8Array.from([0xff, 0x25, 0, 0, 0, 0]));
    const unexplainedBefore = await svc.verify(space, physics, 16, op);
    expect(unexplainedBefore.ok && unexplainedBefore.value.status).toBe("mismatch");
    // DATA-2: a code patch in the main module is never the agent's: unexplained on its FIRST verification
    expect(unexplainedBefore.ok && unexplainedBefore.value.differences.map((d) => d.class)).toEqual(["unexplained"]);
    ev.originals.set(physics, new Uint8Array(original));
    const own = await svc.verify(space, physics, 16, op);
    expect(own.ok && own.value).toMatchObject({ status: "match", own_effects_restored: 6 });
    // a foreign patch in ntdll .text: the footprint scan of the module finds it
    const ntdll = await image(join(SYS, "ntdll.dll"));
    const exportRva = (await ntdll.exports()).find((e) => e.name === "LdrLoadDll")?.rva ?? 0;
    proc.write(NTDLL_BASE + BigInt(exportRva), Uint8Array.from([0xe9, 1, 2, 3, 4]));
    const foreign = await svc.verify(space, NTDLL_BASE + BigInt(exportRva), 16, op);
    expect(foreign.ok && foreign.value).toMatchObject({
      status: "mismatch",
      differences: [{ rva: `0x${exportRva.toString(16)}`, size: 5, class: "foreign-or-agent-patch" }],
    });
    // a difference in read-only data is outside the code footprint: unexplained
    const rdata = ntdll.sections.find((s) => s.name === ".rdata");
    if (rdata === undefined) throw new Error("no .rdata");
    const at = NTDLL_BASE + BigInt(rdata.rva + 0x100);
    proc.write(at, Uint8Array.from([0x5a]));
    const data = await svc.verify(space, at, 8, op);
    expect(data.ok && data.value.differences[0]?.class).toBe("unexplained");
  });

  it("does not compare writable sections, non-image addresses, emulation or file spaces", async () => {
    const dataSection = game.pe.sections.find((s) => s.name === ".data");
    if (dataSection === undefined) throw new Error("no .data");
    expect(await svc.verify(space, GAME_BASE + BigInt(dataSection.rva), 16, op)).toMatchObject({
      ok: true,
      value: { status: "not-applicable", compared: 0 },
    });
    expect(await svc.verify(space, 0x10000000n, 16, op)).toMatchObject({
      ok: true,
      value: { status: "not-applicable" },
    });
    expect(
      await svc.verify({ kind: "file", imagePath: game.path, runtimeBase: null }, 0x140001000n, 16, op),
    ).toMatchObject({ ok: true, value: { status: "skipped" } });
    // an unreadable tail is partial
    const physics = GAME_BASE + BigInt(rva("physics_step"));
    proc.unreadable(physics + 8n, 0x1000);
    expect(await svc.verify(space, physics, 16, op)).toMatchObject({
      ok: true,
      value: { status: "partial", compared: 8 },
    });
  });
});

describe.skipIf(skip)("emulation and file spaces", () => {
  it("resolves against the emulated images through the late-bound EmuPort (CI-B5)", async () => {
    let composed = false;
    const emu = fakeEmu("9b2b8c1e-5d4a-4b6f-9a7e-1c2d3e4f5a6b", [
      {
        name: "game_sim.exe",
        path: game.path,
        sha256: game.artifactSha256,
        base: "0x140000000",
        size: game.pe.sizeOfImage,
        preferredBase: "0x140000000",
        primary: true,
      },
    ]);
    const emuSvc = new AddressServiceImpl({
      evidence: ev.runtime,
      pe: { images, hashes },
      emulator: () => {
        if (!composed) throw new Error("emulator requested during construction");
        return emu;
      },
      platform,
    });
    composed = true;
    const emuSpace: AddressSpace = { kind: "emulation", sessionId: "9b2b8c1e-5d4a-4b6f-9a7e-1c2d3e4f5a6b" };
    const r = await emuSvc.resolve(emuSpace, "$main:0x140001000", op);
    expect(r.ok && r.value.ref).toMatchObject({
      va: "0x140001000",
      module: "game_sim.exe",
      static_base_source: "emulation",
      module_map_id: null,
      image_sha256: game.artifactSha256,
    });
    expect(emuSvc.describe(emuSpace, 0x140001000n)).toEqual({
      va: "0x140001000",
      at: "game_sim.exe+0x1000",
      static: "game_sim.exe:0x140001000",
    });
    const gone = await emuSvc.resolve(
      { kind: "emulation", sessionId: "00000000-0000-4000-8000-000000000000" },
      "+0x10",
      op,
    );
    expect(!gone.ok && gone.error._tag).toBe("SessionNotFound");
  });

  it("map_address in an emulation space without any readable image has nothing to derive from: module-file-unknown", async () => {
    const id = "9b2b8c1e-5d4a-4b6f-9a7e-1c2d3e4f5a6c";
    const emu = fakeEmu(id, [
      {
        name: "dumped.exe",
        path: null,
        sha256: game.artifactSha256,
        base: "0x140000000",
        size: game.pe.sizeOfImage,
        preferredBase: "0x140000000",
        primary: true,
      },
    ]);
    const emuSvc = new AddressServiceImpl({
      evidence: ev.runtime,
      pe: { images, hashes },
      emulator: () => emu,
      platform,
    });
    const input = mapAddressInputSchema.parse({ session_id: id, addresses: ["+0x10"] });
    const mapped = await runMapAddress(emuSvc, ev.runtime, { kind: "emulation", sessionId: id }, input, op);
    expect(!mapped.ok && mapped.error).toMatchObject({ _tag: "CapabilityUnavailable", reason: "module-file-unknown" });
  });

  it("resolves module-relative forms against a PE file; runtime VAs need runtime_base", async () => {
    const file: AddressSpace = { kind: "file", imagePath: game.path, runtimeBase: 0x7ff600000000n };
    expect(
      (await svc.resolve(file, "+0x1000", op)).ok && (await svc.resolve(file, "game_sim.exe:0x140001000", op)),
    ).toMatchObject({
      ok: true,
      value: { va: 0x7ff600001000n },
    });
    expect((await svc.resolve(file, "0x7ff600001000", op)).ok).toBe(true);
    const noBase: AddressSpace = { kind: "file", imagePath: game.path, runtimeBase: null };
    expect(await svc.resolve(noBase, "0x7ff600001000", op)).toMatchObject({
      ok: false,
      error: { diagnostics: { reason: "no_module_map" } },
    });
    expect((await svc.resolve(noBase, "+0x1000", op)).ok && (await svc.resolve(noBase, "+0x1000", op))).toMatchObject({
      value: { va: 0x140001000n },
    });
    expect(await svc.resolve(noBase, "other.dll+0x10", op)).toMatchObject({
      ok: false,
      error: { diagnostics: { reason: "no_module_map" } },
    });
  });
});
