import { spawnSync } from "node:child_process";
import { copyFile, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { LruPeImageCache } from "../../../src/providers/pe/PeImageCache.js";
import type { PeFile } from "../../../src/providers/pe/PeFile.js";
import {
  fixtureArtifact,
  gccSkip,
  loadFixtures,
  skipNote,
  type FixtureManifest,
  type FixturesUnavailable,
} from "../../support/acceptance/fixtures.js";
import { createTempHome, type TempHome } from "../../support/workspace/tempHome.js";

/**
 * S2 §22 "PE reader": gcc fixtures + system DLLs; section long names, exports with forwarders and NONAME, imports
 * and delay imports with slot RVAs, .pdata chains, relocations, CodeView, TLS; the pefile cross-check (named skip
 * without pefile) mirroring S2 lab E1; imageBytes; malformed-file fuzz (never a throw or hang).
 */
const ORACLE = fileURLToPath(new URL("./pefile_oracle.py", import.meta.url));
const SYSTEM = process.env["SystemRoot"] ?? "C:\\Windows";
const SYSTEM_DLLS = ["kernel32.dll", "KernelBase.dll", "ntdll.dll", "user32.dll", "d3d11.dll", "ws2_32.dll"].map((f) =>
  join(SYSTEM, "System32", f),
);
const windows = process.platform === "win32";

const python = process.env["BEA_PYTHON"] ?? "python";
const pefileSkip = ((): string | false => {
  const probe = spawnSync(python, ["-I", "-c", "import pefile"], {
    encoding: "utf8",
    windowsHide: true,
    timeout: 30_000,
  });
  return probe.status === 0 ? false : `PEFILE_SKIP: ${python} -I -c "import pefile" failed`;
})();

const oracle = (path: string): Record<string, unknown> => {
  const run = spawnSync(python, ["-I", ORACLE, path], {
    encoding: "utf8",
    windowsHide: true,
    timeout: 120_000,
    maxBuffer: 256 * 1024 * 1024,
  });
  if (run.status !== 0) throw new Error(`pefile oracle failed: ${run.stderr}`);
  return JSON.parse(run.stdout) as Record<string, unknown>;
};

const cache = new LruPeImageCache(process.platform === "win32" ? "win32" : "linux");
const open = async (path: string): Promise<PeFile> => {
  const result = await cache.open(path);
  if (!result.ok) throw new Error(`open ${path}: ${JSON.stringify(result.error)}`);
  return result.value;
};

let manifest: FixtureManifest | FixturesUnavailable;
let home: TempHome;
beforeAll(async () => {
  manifest = await loadFixtures();
  home = await createTempHome("pe");
}, 600_000);
afterAll(async () => {
  await home.cleanup();
});

const fixturePath = (id: Parameters<typeof fixtureArtifact>[1]): string => {
  const artifact = fixtureArtifact(manifest, id);
  if (artifact === null) throw new Error("fixtures unavailable");
  return artifact.path;
};

describe("PE reader on gcc fixtures", () => {
  it.skipIf(gccSkip() !== false)(
    `parses headers, long section names, exports, .pdata, TLS${skipNote(gccSkip())}`,
    async () => {
      const artifact = fixtureArtifact(manifest, "game_sim");
      if (artifact === null) throw new Error("no game_sim");
      const pe = await open(artifact.path);
      expect(pe.format).toBe("pe32+");
      expect(pe.machine).toBe("x64");
      expect(pe.image_base).toBe(artifact.pe.imageBase);
      expect(pe.size_of_image).toBe(artifact.pe.sizeOfImage);
      expect(pe.dll_characteristics.dynamic_base).toBe(artifact.pe.dynamicBase);
      // gcc long names are resolved through the COFF string table (Frida shows them as "/4")
      expect(pe.sections.some((s) => s.short_name.startsWith("/") && s.name.startsWith(".debug"))).toBe(true);
      expect(pe.sections.find((s) => s.name === ".text")?.perms).toBe("r-x");
      expect(pe.sections.find((s) => s.name === ".data")?.perms).toBe("rw-");
      const exports = await pe.exports();
      for (const [name, rva] of Object.entries(artifact.pe.exportRvas))
        expect(exports.find((e) => e.name === name)?.rva, name).toBe(rva);
      const functions = await pe.functions();
      for (const [name, extent] of Object.entries(artifact.pe.pdata)) {
        expect(functions.lookup(extent.rva), name).toMatchObject({
          begin: extent.rva,
          primary_begin: extent.rva,
          fragment: false,
        });
        expect(functions.lookup(extent.rva + extent.size - 1)?.end, name).toBe(extent.rva + extent.size);
      }
      expect(pe.tls_callbacks.length).toBeGreaterThanOrEqual(1);
      const imports = await pe.imports();
      expect(imports.some((i) => i.dll.toUpperCase() === "KERNEL32.DLL" && i.name === "Sleep")).toBe(true);
      const iat = await pe.loaderWritten();
      for (const i of imports)
        expect(iat.some((r) => r.rva <= i.slot_rva && i.slot_rva + 8 <= r.rva + r.size)).toBe(true);
      expect(pe.issues).toEqual([]);
    },
  );

  it.skipIf(gccSkip() !== false)(
    `imageBytes applies DIR64 relocations for another base${skipNote(gccSkip())}`,
    async () => {
      const pe = await open(fixturePath("game_sim"));
      const slots = await pe.relocations();
      expect(slots.length).toBeGreaterThan(0);
      const slot = slots[Math.floor(slots.length / 2)] ?? 0;
      const window = { rva: slot - 3, len: 24 };
      const preferred = BigInt(pe.image_base);
      const same = await pe.imageBytes(window.rva, window.len, preferred);
      const { bytes } = await pe.readRva(window.rva, window.len);
      expect(Buffer.from(same).equals(Buffer.from(bytes))).toBe(true);
      const delta = 0x7ff6_0000_0000n - preferred;
      const moved = await pe.imageBytes(window.rva, window.len, preferred + delta);
      const before = Buffer.from(bytes).readBigUInt64LE(3);
      expect(Buffer.from(moved).readBigUInt64LE(3)).toBe(BigInt.asUintN(64, before + delta));
      // a slot straddling the window start: only its in-window bytes, relocated
      const straddle = await pe.imageBytes(slot + 4, 4, preferred + delta);
      const full = Buffer.alloc(8);
      full.writeBigUInt64LE(BigInt.asUintN(64, before + delta));
      expect(Buffer.from(straddle).equals(full.subarray(4, 8))).toBe(true);
      // .bss is zero-fill: not file-backed
      const bss = pe.sections.find((s) => s.name === ".bss");
      if (bss !== undefined) expect([...(await pe.readRva(bss.rva, 4)).backed]).toEqual([0, 0, 0, 0]);
    },
  );

  it.skipIf(gccSkip() !== false || pefileSkip !== false)(
    `equals the pefile oracle on every fixture${skipNote(gccSkip() || pefileSkip)}`,
    async () => {
      if ("unavailable" in manifest) return;
      for (const artifact of Object.values(manifest.artifacts)) await compareWithOracle(artifact.path);
    },
    300_000,
  );
});

describe.skipIf(!windows)("PE reader on system DLLs", () => {
  it("parses forwarders, NONAME ordinals, delay imports, chained .pdata, CodeView and fothk", async () => {
    const kernel32 = await open(SYSTEM_DLLS[0] ?? "");
    const kexports = await kernel32.exports();
    const forwarded = kexports.filter((e) => e.forwarder !== null);
    expect(forwarded.length).toBeGreaterThan(10);
    expect(forwarded.every((e) => e.rva === null && /\./u.test(e.forwarder ?? ""))).toBe(true);
    expect(kexports.find((e) => e.name === "Sleep")?.rva).toBeGreaterThan(0);
    const user32 = await open(SYSTEM_DLLS[3] ?? "");
    expect((await user32.exports()).filter((e) => e.name === null).length).toBeGreaterThan(0);
    const kernelbase = await open(SYSTEM_DLLS[1] ?? "");
    const pdata = await kernelbase.functions();
    expect(pdata.chained).toBeGreaterThan(100);
    // every chained fragment resolves to a primary entry inside the table
    let checked = 0;
    for (const entry of pdata.entries()) {
      if (entry.primary_begin === entry.begin) continue;
      expect(pdata.lookup(entry.primary_begin)?.begin).toBe(entry.primary_begin);
      if (++checked > 500) break;
    }
    expect(kernel32.codeview?.guid).toMatch(/^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/u);
    const delay = [...(await kernelbase.imports()), ...(await user32.imports())].filter((i) => i.delay);
    expect(delay.length).toBeGreaterThan(0);
    const loader = await kernel32.loaderWritten();
    expect(loader.some((r) => r.class === "iat")).toBe(true);
    if (kernel32.sections.some((s) => s.name === "fothk"))
      expect(loader.some((r) => r.class === "loader-thunk")).toBe(true);
  });

  it.skipIf(pefileSkip !== false)(
    `equals the pefile oracle on six system DLLs${skipNote(pefileSkip)}`,
    async () => {
      for (const path of SYSTEM_DLLS) await compareWithOracle(path);
    },
    300_000,
  );
});

describe("PE reader errors and robustness", () => {
  it("maps PE32, non-PE and missing files to typed errors", async () => {
    const pe32 = await cache.open(fileURLToPath(new URL("../../../fixtures/golden/pe32-minimal.bin", import.meta.url)));
    expect(pe32.ok).toBe(false);
    if (!pe32.ok) expect(pe32.error).toMatchObject({ _tag: "UnsupportedTarget", reason: "wow64" });
    const text = join(home.root, "not-a-pe.txt");
    await writeFile(text, "MZ but not really a portable executable".repeat(4));
    const notPe = await cache.open(text);
    expect(!notPe.ok && notPe.error).toMatchObject({ _tag: "UnsupportedTarget", reason: "not-pe64" });
    const missing = await cache.open(join(home.root, "missing.dll"));
    expect(!missing.ok && missing.error).toMatchObject({ _tag: "FileOperationFailed", reason: "missing" });
  });

  it.skipIf(gccSkip() !== false)(
    `re-parses a file that changed on disk and fails stale reads${skipNote(gccSkip())}`,
    async () => {
      const copy = join(home.root, "mathlib-copy.dll");
      await copyFile(fixturePath("mathlib"), copy);
      const first = await open(copy);
      const bytes = await readFile(copy);
      await writeFile(copy, Buffer.concat([bytes, Buffer.from([0])]));
      await expect(first.readRva(0, 16)).rejects.toThrow(/changed on disk/u);
      const second = await open(copy);
      expect(second).not.toBe(first);
      expect((await second.readRva(0, 2)).bytes.toString("latin1")).toBe("MZ");
    },
  );

  it.skipIf(gccSkip() !== false)(
    `never throws or hangs on truncated or corrupted images (fuzz)${skipNote(gccSkip())}`,
    async () => {
      const original = await readFile(fixturePath("mathlib"));
      const pe = await open(fixturePath("mathlib"));
      const dirs = pe.headers.dirs.filter((d) => d.rva !== 0).map((d) => d.rva);
      let seed = 0x5eed;
      const random = (n: number): number => {
        seed = (seed * 1_103_515_245 + 12_345) & 0x7fffffff;
        return seed % n;
      };
      const fuzzCache = new LruPeImageCache(process.platform === "win32" ? "win32" : "linux", 2);
      const target = join(home.root, "fuzz.dll");
      let opened = 0;
      for (let round = 0; round < 120; round++) {
        let mutated: Buffer;
        if (round % 4 === 0) mutated = original.subarray(0, random(original.length));
        else {
          mutated = Buffer.from(original);
          const hot = [
            0x3c,
            0x80 + random(0x200),
            ...dirs
              .map((rva) => pe.headers.sections.find((s) => rva >= s.rva && rva < s.rva + s.virtual_size))
              .filter((s) => s !== undefined)
              .map((s) => s.raw_offset + random(Math.max(1, s.raw_size))),
          ];
          for (let k = 0; k < 8; k++) mutated[(hot[random(hot.length)] ?? 0) + random(64)] = random(256);
        }
        await writeFile(target, mutated);
        const result = await fuzzCache.open(target);
        if (!result.ok) {
          expect(["UnsupportedTarget", "FileOperationFailed"]).toContain(result.error._tag);
          continue;
        }
        opened++;
        const image = result.value;
        await Promise.all([
          image.exports(),
          image.imports(),
          image.functions(),
          image.relocations(),
          image.loaderWritten(),
        ]);
        await image.imageBytes(0x1000, 64, 0x7ff600000000n);
        expect(Array.isArray(image.issues)).toBe(true);
      }
      expect(opened).toBeGreaterThan(10);
      await rm(target, { force: true });
    },
    120_000,
  );
});

/** Field-by-field equality with pefile (S2 lab E1 method). */
const compareWithOracle = async (path: string): Promise<void> => {
  const pe = await open(path);
  const py = oracle(path);
  expect(pe.image_base, path).toBe(py["image_base"]);
  expect(pe.size_of_image, path).toBe(py["size_of_image"]);
  expect(pe.size_of_headers, path).toBe(py["size_of_headers"]);
  expect(pe.entry_rva ?? 0, path).toBe(py["entry_rva"]);
  expect(pe.time_date_stamp, path).toBe(py["time_date_stamp"]);
  expect(
    pe.sections.map((s) => s.short_name),
    path,
  ).toEqual(py["sections"]);
  const exportKey = (e: { ordinal: number; name: string | null; rva: number | null; forwarder: string | null }) =>
    `${String(e.ordinal)}|${String(e.name)}|${String(e.rva)}|${String(e.forwarder)}`;
  expect(new Set((await pe.exports()).map(exportKey)), `${path} exports`).toEqual(
    new Set((py["exports"] as Parameters<typeof exportKey>[0][]).map(exportKey)),
  );
  const importKey = (i: {
    dll: string;
    name: string | null;
    ordinal: number | null;
    slot_rva: number;
    delay: boolean;
  }) => `${i.dll.toLowerCase()}|${String(i.name)}|${String(i.ordinal)}|${String(i.slot_rva)}|${String(i.delay)}`;
  expect(new Set((await pe.imports()).map(importKey)), `${path} imports`).toEqual(
    new Set((py["imports"] as Parameters<typeof importKey>[0][]).map(importKey)),
  );
  const pdata = await pe.functions();
  expect(pdata.count, `${path} pdata`).toBe(py["pdata_count"]);
  expect(pdata.chained, `${path} chained`).toBe(py["pdata_chained"]);
  const slots = await pe.relocations();
  expect(slots.length, `${path} relocs`).toBe(py["relocs_dir64"]);
  const { createHash } = await import("node:crypto");
  expect(
    createHash("sha256")
      .update([...slots].join(","))
      .digest("hex"),
    `${path} reloc slots`,
  ).toBe(py["relocs_sha256"]);
  expect(await pe.relocationOtherTypes(), `${path} reloc other`).toBe(py["reloc_other"]);
  expect(pe.codeview, `${path} codeview`).toEqual(py["codeview"]);
  expect([...pe.tls_callbacks], `${path} tls`).toEqual(py["tls_callbacks"]);
};
