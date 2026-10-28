import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { describe, expect, it } from "vitest";

import { exportedFunctions, parsePe, PeFormatError } from "../../scripts/lib/peParse.mjs";
import { distLayoutAt, resolveDistLayout } from "../../src/application/distLayout.js";

/** WP0 runtime-layout and fixture-tooling helpers. */
const repo = resolve(import.meta.dirname, "..", "..");

describe("dist layout (src/application/distLayout.ts)", () => {
  it("resolves a build relative to its own dist root, ignoring BEA_DIST_DIR", () => {
    const built = pathToFileURL(
      join(repo, "build", "dist-snapshots", "x", "dist", "application", "distLayout.js"),
    ).href;
    const layout = resolveDistLayout({ BEA_DIST_DIR: "C:/elsewhere/dist" }, built);
    expect(layout.fromSource).toBe(false);
    expect(layout.distRoot).toBe(join(repo, "build", "dist-snapshots", "x", "dist"));
    expect(layout.dispatcher).toBe(join(repo, "build", "dist-snapshots", "x", "scripts", "bea.mjs"));
    expect(layout.agentBundle).toBe(join(layout.distRoot, "agent", "bea-agent.js"));
    expect(layout.jobhostExe).toBe(join(layout.distRoot, "native", "win32-x64", "bea-jobhost.exe"));
    expect(layout.bridgeScript).toBe(join(repo, "build", "dist-snapshots", "x", "bridge", "emu", "bea_emu_bridge.py"));
  });

  it("from sources uses BEA_DIST_DIR when set, else the repository dist/", () => {
    const source = pathToFileURL(join(repo, "src", "application", "distLayout.ts")).href;
    expect(resolveDistLayout({}, source)).toMatchObject({
      fromSource: true,
      distRoot: join(repo, "dist"),
      packageRoot: repo,
    });
    const snapshot = join(repo, "build", "dist-snapshots", "wp0", "dist");
    expect(resolveDistLayout({ BEA_DIST_DIR: snapshot }, source)).toMatchObject({
      distRoot: snapshot,
      packageRoot: dirnameOf(snapshot),
    });
    expect(distLayoutAt(snapshot).bridgeManifest).toBe(join(snapshot, "bridge-manifest.json"));
  });
});

const dirnameOf = (path: string): string => resolve(path, "..");

describe("PE reader for fixture manifests (scripts/lib/peParse.mjs)", () => {
  it("parses the committed PE32 golden header", () => {
    const pe = parsePe(readFileSync(join(repo, "fixtures", "golden", "pe32-minimal.bin")));
    expect(pe).toMatchObject({
      machine: "i386",
      format: "PE32",
      imageBase: "0x400000",
      isDll: false,
      entryRva: 0x1000,
      sizeOfImage: 0x2000,
    });
    expect(pe.sections.map((s) => s.name)).toEqual([".text"]);
    expect(pe.exports).toEqual([]);
    expect(exportedFunctions(pe)).toEqual({});
    expect([...pe.readRva(0x1000, 3)]).toEqual([0x31, 0xc0, 0xc3]);
  });

  it("refuses malformed images", () => {
    expect(() => parsePe(Buffer.from("not a pe"))).toThrow(PeFormatError);
    const truncated = readFileSync(join(repo, "fixtures", "golden", "pe32-minimal.bin")).subarray(0, 0x90);
    expect(() => parsePe(truncated)).toThrow(PeFormatError);
  });
});
