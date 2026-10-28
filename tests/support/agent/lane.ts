// =================================================================================================
// tests/support/agent/lane.ts — shared setup of the WP3 raw-Frida acceptance files (tests/acceptance/agent/**):
// named skips (FRIDA_SKIP, GCC_SKIP for the fixtures, JOBHOST_SKIP for the job tests), the fixture manifest, the
// test-entry agent build (cached per sources digest), small probe scripts that look at a target from a SEPARATE
// script, and process helpers that only ever touch processes the test started.
// =================================================================================================
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { fixtureArtifact, fridaSkip, gccSkip, loadFixtures, type FixtureId } from "../acceptance/fixtures.js";
import { buildTestAgent } from "./coreAgent.js";
import { RawAgent } from "./rawAgent.js";
import { TEST_ENTRY_NAME, TEST_ENTRY_SOURCE } from "./testEntry.js";

export type LaneSkip = string | false;

/** FRIDA_SKIP / GCC_SKIP for the agent lane (a missing toolchain only). */
export const agentLaneSkip = (): LaneSkip => fridaSkip() || gccSkip();

export interface AgentLane {
  readonly fixtures: Readonly<Record<FixtureId, string>>;
  readonly fixtureDir: string;
  readonly bundle: string;
  readonly bundleBytes: number;
  readonly pidcheck: string;
}

/** Fixtures + the core agent with the test entry. Throws when the fixtures are unavailable (callers skip first). */
export const setupAgentLane = async (): Promise<AgentLane> => {
  const manifest = await loadFixtures();
  if ("unavailable" in manifest) throw new Error(`fixtures unavailable: ${manifest.unavailable}`);
  const paths = {} as Record<FixtureId, string>;
  for (const id of Object.keys(manifest.artifacts) as FixtureId[]) paths[id] = fixtureArtifact(manifest, id)!.path;
  const build = await buildTestAgent({ mode: "core", entry: { name: TEST_ENTRY_NAME, source: TEST_ENTRY_SOURCE } });
  RawAgent.useLivenessProbe(paths.pidcheck);
  return {
    fixtures: paths,
    fixtureDir: manifest.dir,
    bundle: build.bundle,
    bundleBytes: build.bytes,
    pidcheck: paths.pidcheck,
  };
};

/** Write a bundle to a fresh temp file (for a separate host process); returns the path and a cleanup. */
export const bundleFile = (bundle: string): { path: string; cleanup: () => void } => {
  const dir = mkdtempSync(join(tmpdir(), "bea-wp3-bundle-"));
  const path = join(dir, "bea-agent.js");
  writeFileSync(path, bundle);
  return { path, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
};

/** A user script (run_script-like) registering its own exception handler AFTER BEA's (F15, A-33). */
export const USER_HANDLER_SCRIPT = `
const counts = {};
Process.setExceptionHandler((d) => { counts[d.type] = (counts[d.type] || 0) + 1; return false; });
rpc.exports = { counts() { return counts; } };
`;

/** A probe script that reports the PAGE_* protection of an address (VirtualQuery). */
export const PROTECT_PROBE_SCRIPT = `
const vq = new NativeFunction(Process.getModuleByName("kernelbase.dll").getExportByName("VirtualQuery"),
  "size_t", ["pointer", "pointer", "size_t"], { scheduling: "exclusive" });
const mbi = Memory.alloc(48);
rpc.exports = {
  protect(address) { return vq(ptr(address), mbi, 48).toNumber() === 0 ? -1 : mbi.add(0x24).readU32(); },
};
`;

/** Kill a process the TEST started (taskkill /F /T); never used on anything else. */
export const killTestProcess = (pid: number): void => {
  spawnSync("taskkill", ["/F", "/T", "/PID", String(pid)], { stdio: "ignore", windowsHide: true });
};

export const isAlive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (cause) {
    return (cause as NodeJS.ErrnoException).code === "EPERM";
  }
};

export const PAGE_GUARD = 0x100;
