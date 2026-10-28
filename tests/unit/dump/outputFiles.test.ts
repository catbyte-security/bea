import { mkdir, mkdtemp, readdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  checkOutPath,
  hashFile,
  outputPolicy,
  pathIsFree,
  prepareParent,
  publishDirectory,
  safeStem,
  writeNewFile,
} from "../../../src/application/dump/outputFiles.js";
import {
  beaRestoredPatches,
  reportPatches,
  restoreForeignPatches,
} from "../../../src/application/dump/patchRestore.js";
import { sha256Hex } from "../../../src/domain/canonical.js";
import { loadConfig } from "../../../src/domain/config.js";
import { ok } from "../../../src/domain/result.js";
import type { AddressService } from "../../../src/ports/address.js";
import type { PeImage } from "../../../src/ports/pe.js";
import { testOp } from "./dumpFakes.js";

let root: string;
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "bea-wp13-out-"));
});
afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

const winPolicy = {
  platform: "win32" as const,
  exportsDir: "C:\\bea\\runs\\run_1\\exports",
  allowedRoots: ["D:\\re"],
  systemRoots: ["C:\\Windows"],
};

describe("out_path policy (D-INT-42)", () => {
  it.each([
    ["C:\\Users\\me\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\x.bin", "startup-folder"],
    ["D:\\re\\dump.cmd", "refused-extension"],
    ["D:\\re\\dump.DLL", "refused-extension"],
    ["C:\\Windows\\Temp\\x.bin", "system-directory"],
    ["E:\\elsewhere\\x.bin", "outside-roots"],
    ["D:\\re\\..\\x.bin", "traversal"],
    ["D:\\re\\x.bin:ads", "alternate-stream"],
    ["re\\x.bin", "not-absolute"],
  ])("refuses %s (%s) as access_denied{policy}", (path, why) => {
    const res = checkOutPath("dump_memory", path, winPolicy);
    expect(res.ok ? null : res.error).toMatchObject({
      _tag: "AccessDenied",
      reason: "policy",
      diagnostics: { policy: why },
    });
  });

  it("accepts the exports dir and user-configured roots", () => {
    expect(checkOutPath("dump_memory", "C:\\bea\\runs\\run_1\\exports\\a.pe", winPolicy)).toEqual(
      ok("C:\\bea\\runs\\run_1\\exports\\a.pe"),
    );
    expect(checkOutPath("dump_memory", "d:/re/sub/a.pe", winPolicy).ok).toBe(true);
  });

  it("outputPolicy uses the run's exports dir, the config roots and %SystemRoot%", async () => {
    const loaded = await loadConfig({
      env: { BEA_HOME: "C:\\bea-home" },
      platform: "win32",
      accountHome: "C:\\Users\\t",
      readConfigFile: async () => JSON.stringify({ schema: "bea.config/1", exports: { allowed_roots: ["D:\\re"] } }),
    });
    if (!loaded.ok) throw new Error(JSON.stringify(loaded.error));
    const policy = outputPolicy(loaded.value, "run_1", { SystemRoot: "C:\\WINDOWS" });
    expect(policy).toEqual({
      platform: "win32",
      exportsDir: "C:\\bea-home\\runs\\run_1\\exports",
      allowedRoots: ["D:\\re"],
      systemRoots: ["C:\\WINDOWS", "C:\\Windows"],
    });
  });

  it("safeStem keeps module names file-safe", () => {
    expect(safeStem("game_sim.exe")).toBe("game_sim.exe");
    expect(safeStem("..\\evil name.dll")).toBe("evil_name.dll");
    expect(safeStem("...")).toBe("dump");
  });
});

describe("writers never overwrite", () => {
  it("writeNewFile creates, hashes, and refuses an existing path; prepareParent creates parents only under exports", async () => {
    const policy = {
      platform: (process.platform === "win32" ? "win32" : "linux") as "win32" | "linux",
      exportsDir: join(root, "exports"),
      allowedRoots: [join(root, "allowed")],
      systemRoots: [],
    };
    const target = join(policy.exportsDir, "deep", "a.bin");
    expect((await prepareParent("t", target, policy)).ok).toBe(true);
    const written = await writeNewFile("t", target, Uint8Array.from([1, 2, 3]));
    expect(written).toEqual(ok({ path: target, bytes: 3, sha256: sha256Hex(Uint8Array.from([1, 2, 3])) }));
    expect(await hashFile(target)).toEqual({ bytes: 3, sha256: sha256Hex(Uint8Array.from([1, 2, 3])) });
    const again = await writeNewFile("t", target, Uint8Array.from([9]));
    expect(again.ok ? null : again.error).toMatchObject({ _tag: "FileOperationFailed", reason: "exists" });
    expect(Array.from(await readFile(target))).toEqual([1, 2, 3]);
    const outside = await prepareParent("t", join(root, "allowed", "missing", "b.bin"), policy);
    expect(outside.ok ? null : outside.error).toMatchObject({ _tag: "FileOperationFailed", reason: "missing" });
    async function* chunks() {
      yield Uint8Array.from([4]);
      throw new Error("source failed");
    }
    const failed = await writeNewFile("t", join(policy.exportsDir, "c.bin"), chunks());
    expect(failed.ok).toBe(false);
    expect(await pathIsFree(join(policy.exportsDir, "c.bin"))).toBe(true);
  });

  it("publishDirectory renames a staged bundle into place and refuses an existing target", async () => {
    const staging = join(root, "s1");
    await mkdir(staging);
    await writeFile(join(staging, "f"), "1");
    expect((await publishDirectory("t", staging, join(root, "final"))).ok).toBe(true);
    const staging2 = join(root, "s2");
    await mkdir(staging2);
    const clash = await publishDirectory("t", staging2, join(root, "final"));
    expect(clash.ok ? null : clash.error).toMatchObject({ reason: "exists" });
    expect((await readdir(root)).sort()).toEqual(["final"]);
  });

  it("a dangling link is not a free path", async () => {
    // a directory junction needs no privilege on Windows; elsewhere a plain symlink
    await symlink(join(root, "nowhere"), join(root, "link"), process.platform === "win32" ? "junction" : undefined);
    expect(await pathIsFree(join(root, "link"))).toBe(false);
  });
});

describe("patch restore (D-INT-45)", () => {
  it("maps agent bea_patches_restored to RVAs; restores only foreign-or-agent-patch differences in non-writable sections", async () => {
    expect(
      beaRestoredPatches(
        {
          blob: "b1",
          kind: "module",
          base: "0x140001000",
          size: 0x1000,
          protection: "r-x",
          module: "m",
          holes: [],
          bea_patches_restored: [{ offset: 0x760, size: 5 }],
          sha256: null,
        },
        0x1_4000_0000n,
      ),
    ).toEqual([{ rva: 0x1760, size: 5, source: "bea-original" }]);
    const image = new Uint8Array(0x3000).fill(0xaa);
    const verified: number[] = [];
    const address = {
      verify: async (_s: unknown, va: bigint) => {
        verified.push(Number(va - 0x1000_0000n));
        return ok({
          status: "mismatch" as const,
          compared: 1,
          equal: 0,
          excluded_loader: 0,
          own_effects_restored: 0,
          differences: [
            { rva: "0x1010" as const, size: 2, class: "foreign-or-agent-patch" as const },
            { rva: "0x1020" as const, size: 2, class: "unexplained" as const },
          ],
        });
      },
    } as unknown as AddressService;
    const file = {
      imageBytes: async (_rva: number, len: number) => new Uint8Array(len).fill(0x11),
    } as unknown as PeImage;
    const res = await restoreForeignPatches({
      address,
      space: { kind: "file", imagePath: "x", runtimeBase: null },
      op: testOp(),
      moduleBase: 0x1000_0000n,
      image,
      sections: [
        {
          name: ".text",
          virtualAddress: 0x1000,
          virtualSize: 0x800,
          sizeOfRawData: 0x800,
          pointerToRawData: 0x400,
          characteristics: 0x60000020,
          headerOffset: 0,
        },
        {
          name: ".data",
          virtualAddress: 0x2000,
          virtualSize: 0x800,
          sizeOfRawData: 0x200,
          pointerToRawData: 0xc00,
          characteristics: 0xc0000040,
          headerOffset: 0,
        },
      ],
      file,
    });
    expect(res).toEqual(ok({ restored: [{ rva: 0x1010, size: 2, source: "file-image" }], unchecked: 0 }));
    expect(verified).toEqual([0x1000]);
    expect(Array.from(image.subarray(0x1010, 0x1014))).toEqual([0x11, 0x11, 0xaa, 0xaa]);
    expect(Array.from(image.subarray(0x1020, 0x1022))).toEqual([0xaa, 0xaa]);
    expect(
      reportPatches([
        { rva: 9, size: 1, source: "file-image" },
        { rva: 1, size: 1, source: "bea-original" },
      ]).map((p) => p.rva),
    ).toEqual([1, 9]);
  });
});
