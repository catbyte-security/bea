import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { fixtureToolchain } from "../../../scripts/lib/fixtures.mjs";
import { exportRvas, parsePe } from "../../../scripts/lib/peParse.mjs";
import { verifyDumpBundle } from "../../../src/application/dump/verifyDumpBundle.js";
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
import { fileFacts, fileSectionBytes, mapPe } from "../../unit/dump/peBuilder.js";

/**
 * WP13 acceptance through the BUILT server (run from a snapshot: BEA_DIST_DIR, docs/testing.md): S6 §10.8 dump_memory
 * row + the WP13 card. Wave rule (CI-I1): spawn_process/resume_process/wait (WP4, wave 3) are earlier-wave tools;
 * hook_function and read_memory are wave-4 tools of WP7/WP6 — the two assertions that chain them are marked and move
 * to WP18 `tests/acceptance/integration/` if those WPs are not merged when this runs. L-S6-6 (Ghidra/REA load) is a
 * manual receipt, not automated here.
 */
const SKIP = fridaSkip() || jobhostSkip();

/**
 * L-S6-6 (automated part): gcc's COFF symbol table (a file offset; it also names the long sections "/4" = .eh_frame,
 * "/14" = .debug_…) is carried as overlay after SizeOfImage byte for byte — a loader would otherwise read a string
 * table from unrelated bytes — and an independent loader (binutils objdump, part of this lane's gcc toolchain)
 * recognizes the realigned file and resolves the long section names.
 */
const expectCoffOverlayAndLoadable = (dumped: Buffer, fileOnDisk: Uint8Array, path: string): void => {
  const facts = fileFacts(fileOnDisk);
  const nt = dumped.readUInt32LE(0x3c);
  const diskTable = Buffer.from(fileOnDisk).readUInt32LE(nt + 12);
  expect(dumped.readUInt32LE(nt + 12)).toBe(facts.sizeOfImage);
  expect(dumped.length).toBe(facts.sizeOfImage + (fileOnDisk.length - diskTable));
  expect(dumped.subarray(facts.sizeOfImage).equals(Buffer.from(fileOnDisk.subarray(diskTable)))).toBe(true);
  const toolchain = fixtureToolchain();
  if ("unavailable" in toolchain) throw new Error(`fixture toolchain: ${toolchain.unavailable}`);
  const objdump = spawnSync(toolchain.objdump.path, ["-h", path], { encoding: "utf8" });
  expect(objdump.status, objdump.stderr).toBe(0);
  expect(objdump.stdout).toMatch(/\.eh_frame/u);
  expect(objdump.stdout).toMatch(/\.debug_info/u);
};

describe.skipIf(SKIP !== false)(`dump_memory on game_sim${skipNote(SKIP)}`, () => {
  let home: TempHome;
  let ledger: OwnedPidLedger;
  let bea: BeaConnection;
  let game: FixtureArtifact;
  let session = "";
  let base = 0n;
  const call = async (name: string, args: Record<string, unknown>) => expectToolSuccess(await bea.call(name, args));

  beforeAll(async () => {
    const manifest = await loadFixtures();
    const artifact = fixtureArtifact(manifest, "game_sim");
    if (artifact === null) throw new Error(`fixtures unavailable: ${JSON.stringify(manifest)}`);
    game = artifact;
    home = await createTempHome("wp13-dump");
    ledger = new OwnedPidLedger(fixtureArtifact(manifest, "pidcheck")?.path ?? null);
    bea = await connectBea({ home, ledger });
    const spawned = await call("spawn_process", { program: game.path, args: ["--speed", "20", "--throttle", "0.125"] });
    session = String(spawned["session_id"]);
    base = BigInt(String((spawned["main_module"] as Record<string, unknown>)["base"]));
    await call("resume_process", { session_id: session });
    await call("wait", { session_id: session, until: "output", output_contains: "READY", timeout_ms: 10_000 });
  }, 120_000);

  afterAll(async () => {
    if (session !== "") await bea.call("close_session", { session_id: session }).catch(() => undefined);
    await bea?.close();
    await ledger?.assertClean();
    await home?.cleanup();
  });

  it("pe_realigned + rebase_to preferred: the file parses as a PE at the preferred base and .text equals the on-disk .text", async () => {
    const out = await call("dump_memory", { session_id: session, module: "game_sim.exe", rebase_to: "preferred" });
    const fileOnDisk = new Uint8Array(await readFile(game.path));
    const facts = fileFacts(fileOnDisk);
    expect(out).toMatchObject({
      format: "pe",
      layout: "pe_realigned",
      image_base_in_file: `0x${facts.preferredBase.toString(16)}`,
      module: { name: "game_sim.exe", rebased_to: "preferred" },
      predicate_type: "bea.memory.dump",
    });
    const dumped = await readFile(String(out["path"]));
    expect(dumped.length).toBe(Number(out["bytes"]));
    const pe = parsePe(dumped);
    expect(pe.format).toBe("PE32+");
    expect(pe.imageBase).toBe(`0x${facts.preferredBase.toString(16)}`);
    for (const s of pe.sections) expect(s.rawOffset, s.name).toBe(s.rva);
    const text = facts.sections.find((s) => (s.characteristics & 0x20000000) !== 0)!;
    const disk = fileSectionBytes(fileOnDisk, text.rva);
    expect(dumped.subarray(text.rva, text.rva + disk.length).equals(Buffer.from(disk))).toBe(true);
    expectCoffOverlayAndLoadable(dumped, fileOnDisk, String(out["path"]));
    // an existing out_path is never overwritten
    const again = parseToolError(
      await bea.call("dump_memory", { session_id: session, module: "game_sim.exe", out_path: String(out["path"]) }),
    );
    expect(again.code).toBe("file_operation_failed");
  });

  it("refuses an out_path in a Startup folder or ending in .cmd with access_denied{policy}", async () => {
    for (const out_path of [
      join(home.home, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "g.bin"),
      join(home.beaHome, "runs", "x.cmd"),
    ]) {
      const error = parseToolError(
        await bea.call("dump_memory", { session_id: session, module: "game_sim.exe", out_path }),
      );
      expect(error.code).toBe("access_denied");
      expect(error.details).toMatchObject({ reason: "policy" });
    }
  });

  it("a bea.dump/1 bundle verifies and contains the TEB of the chosen thread, with real FPCW/MXCSR", async () => {
    const out = await call("dump_memory", { session_id: session, format: "bundle", bundle: { mode: "suspended" } });
    const verified = await verifyDumpBundle(String(out["path"]), { maxTotalBytes: 2048 * 1024 * 1024 });
    if (!verified.ok) throw new Error(JSON.stringify(verified.error));
    const m = verified.value.manifest;
    const primary = m.threads.find((t) => t.primary)!;
    const teb = BigInt(primary.teb);
    expect(m.regions.some((r) => BigInt(r.base) <= teb && teb < BigInt(r.base) + BigInt(r.size))).toBe(true);
    expect(primary.context).toMatchObject({ fpcw: "0x37f" });
    // the real MXCSR (S4 F14: 0x1FA0 on gcc/msvcrt targets), not the bridge default: all exceptions masked; the
    // sticky precision flag (0x20) depends on the thread's float history, so it is not pinned here
    const mxcsr = Number(primary.context.mxcsr ?? "-1");
    expect(mxcsr & 0xffc0).toBe(0x1f80);
    expect(m.modules.find((x) => x.name === "game_sim.exe")).toMatchObject({
      captured: expect.stringMatching(/full|partial/u),
    });
    expect(m.regions.some((r) => r.tag === "kuser_shared_data")).toBe(true);
    expect(m.memory_map.every((r) => r.protection.startsWith("r"))).toBe(true);
  });

  // chains hook_function (WP7, same wave): moves to WP18 integration if WP7 is not merged
  it("with physics_step hooked, the dump restores the original prologue (restored_patches lists the hook site); live_bytes keeps the jump", async () => {
    const physics = game.pe.exportRvas["physics_step"] ?? 0;
    await call("hook_function", { session_id: session, address: "game_sim.exe!physics_step", duration_ms: 60_000 });
    const fileOnDisk = new Uint8Array(await readFile(game.path));
    const relocated = mapPe(fileOnDisk, base);
    const restored = await call("dump_memory", { session_id: session, module: "game_sim.exe", layout: "mapped" });
    const restoredBytes = await readFile(String(restored["path"]));
    expect(
      restoredBytes.subarray(physics, physics + 16).equals(Buffer.from(relocated.subarray(physics, physics + 16))),
    ).toBe(true);
    expect(restored["restored_patches"]).toEqual(
      expect.arrayContaining([expect.objectContaining({ rva: `0x${physics.toString(16)}`, source: "bea-original" })]),
    );
    const live = await call("dump_memory", {
      session_id: session,
      module: "game_sim.exe",
      layout: "mapped",
      live_bytes: true,
    });
    const liveBytes = await readFile(String(live["path"]));
    expect(liveBytes.subarray(physics, physics + 5).equals(Buffer.from(relocated.subarray(physics, physics + 5)))).toBe(
      false,
    );
    expect(live["restored_patches"]).toEqual([]);
  });

  it("Frida's own ntdll patch (LdrLoadDll) is restored from the relocated file image", async () => {
    const out = await call("dump_memory", { session_id: session, module: "ntdll.dll", layout: "mapped" });
    const patches = out["restored_patches"] as { rva: string; source: string }[];
    expect(patches.some((p) => p.source === "file-image")).toBe(true);
    const ntdllPath = String((out["module"] as Record<string, unknown>)["path"]);
    const disk = new Uint8Array(await readFile(ntdllPath));
    // S4 F17: Frida's own module tracking leaves a jmp at the entry of ntdll!LdrLoadDll
    const ldrLoadDll = exportRvas(parsePe(Buffer.from(disk)))["LdrLoadDll"] as number;
    expect(patches.some((p) => p.source === "file-image" && Number(p.rva) === ldrLoadDll)).toBe(true);
    const relocated = mapPe(disk, BigInt(String(out["base"])));
    const dumped = await readFile(String(out["path"]));
    for (const p of patches.filter((x) => x.source === "file-image")) {
      const rva = Number(p.rva);
      expect(dumped.subarray(rva, rva + 8).equals(Buffer.from(relocated.subarray(rva, rva + 8))), p.rva).toBe(true);
    }
  });

  // chains read_memory (WP6, same wave)
  it("a raw dump of the car equals read_memory of the same range (stable fields)", async () => {
    const read = await call("read_memory", {
      session_id: session,
      address: "game_sim.exe!g_world",
      // [[[g_world]+8]+0]: [[g_world]+8] is &world->cars[0]; one more dereference reaches the Car itself
      deref: [8, 0],
      size: 0x80,
    });
    const address = String((read["address"] as Record<string, unknown>)["va"]);
    const raw = await call("dump_memory", { session_id: session, format: "raw", address, size: 0x80 });
    expect(raw).toMatchObject({ format: "raw", bytes: 0x80, base: address, gaps: [] });
    const dumped = await readFile(String(raw["path"]));
    const viaRead = Buffer.from(String(read["data"]), "hex");
    expect(dumped.readUInt32LE(0)).toBe(0x31524143); // 'CAR1': the range really is the Car
    // magic, id, speed and throttle (exact f32 equilibrium) and the never-written tunables mass/drag
    for (const [from, to] of [
      [0x00, 0x10],
      [0x48, 0x50],
    ] as const)
      expect(dumped.subarray(from, to).equals(viaRead.subarray(from, to)), `bytes 0x${from.toString(16)}..`).toBe(true);
  });
});
