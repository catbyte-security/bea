import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";

import { inject } from "vitest";

import {
  buildFixtures,
  fixtureToolchain,
  type FixtureArtifact,
  type FixtureId,
  type FixtureManifest,
  type FixturesUnavailable,
} from "../../../scripts/lib/fixtures.mjs";
import { harnessLayout } from "../mcp/stdioSubprocess.js";

export type { FixtureArtifact, FixtureId, FixtureManifest, FixturesUnavailable };

/**
 * The fixture manifest: provided once per run by tests/globalSetup.ts in the acceptance project, built (or read from
 * the cache) directly in lanes without that globalSetup (process, emulation). Never RVAs from documents.
 */
export const loadFixtures = async (): Promise<FixtureManifest | FixturesUnavailable> =>
  inject("fixtures") ?? (await buildFixtures());

/** The artifact or a named-skip reason. */
export const fixtureArtifact = (
  manifest: FixtureManifest | FixturesUnavailable,
  id: FixtureId,
): FixtureArtifact | null => ("unavailable" in manifest ? null : manifest.artifacts[id]);

const once = <T>(compute: () => T): (() => T) => {
  let cached: { readonly value: T } | undefined;
  return () => (cached ??= { value: compute() }).value;
};

/**
 * Named skips (S6 §10.3, DESIGN §8.2): each is false when the toolchain is present, else the reason, computed once
 * per worker. Use: `it.skipIf(gccSkip() !== false)(\`builds fixtures${skipNote(gccSkip())}\`, …)`. A named skip is
 * only for a missing toolchain, never for a failing behavior.
 */
export const gccSkip = once((): string | false => {
  const toolchain = fixtureToolchain();
  return "unavailable" in toolchain ? `GCC_SKIP: ${toolchain.unavailable}` : false;
});

export const fridaSkip = once((): string | false => {
  if (process.platform !== "win32" || process.arch !== "x64")
    return `FRIDA_SKIP: real-Frida lanes need Windows x64 (host is ${process.platform}-${process.arch})`;
  let packageDir: string;
  try {
    // frida's "exports" map hides ./package.json: resolve the entry and walk up to the package directory.
    packageDir = dirname(createRequire(import.meta.url).resolve("frida"));
    while (!existsSync(join(packageDir, "package.json")) && dirname(packageDir) !== packageDir)
      packageDir = dirname(packageDir);
  } catch (cause) {
    return `FRIDA_SKIP: the frida package is not installed (${String(cause)})`;
  }
  const binding = join(packageDir, "build", "frida_binding.node");
  return existsSync(binding) ? false : `FRIDA_SKIP: the frida binding is missing (${binding}); run npm ci`;
});

/** The built jobhost of the harness's dist (BEA_DIST_DIR or dist/) answers `probe` with ok:true. */
export const jobhostSkip = once((): string | false => {
  if (process.platform !== "win32") return `JOBHOST_SKIP: bea-jobhost is Windows-only (host is ${process.platform})`;
  const exe = harnessLayout().jobhostExe;
  if (!existsSync(exe)) return `JOBHOST_SKIP: ${exe} is missing; run npm run build (and snapshot it)`;
  const probe = spawnSync(exe, ["probe"], { encoding: "utf8", windowsHide: true, timeout: 15_000 });
  return probe.status === 0 && /"ok"\s*:\s*true/u.test(probe.stdout)
    ? false
    : `JOBHOST_SKIP: ${exe} probe failed: ${probe.stdout}${probe.stderr}`;
});

/** A Python with unicorn 2.1.x for the emulator bridge: BEA_PYTHON, else python on PATH (run with -I). */
export const emuSkip = once((): string | false => {
  const python = process.env["BEA_PYTHON"] ?? "python";
  const probe = spawnSync(python, ["-I", "-c", "import unicorn, capstone, pefile; print(unicorn.__version__)"], {
    encoding: "utf8",
    windowsHide: true,
    timeout: 30_000,
  });
  if (probe.status !== 0)
    return `EMU_SKIP: no Python with unicorn/capstone/pefile (${python}: ${(probe.stderr || String(probe.error)).trim().slice(0, 200)})`;
  return probe.stdout.trim().startsWith("2.1.") ? false : `EMU_SKIP: unicorn ${probe.stdout.trim()} is not 2.1.x`;
});

/** Suffix for a test title: " [skipped: <reason>]" or "". */
export const skipNote = (reason: string | false): string => (reason === false ? "" : ` [skipped: ${reason}]`);
