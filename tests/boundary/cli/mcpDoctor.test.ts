import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { runMcpDoctor } from "../../../src/cli/mcpDoctor.js";
import type { ToolContract } from "../../../src/contracts/toolContract.js";
import { harnessLayout, minimalEnv } from "../../support/mcp/stdioSubprocess.js";
import { createTempHome, type TempHome } from "../../support/workspace/tempHome.js";

/**
 * `bea mcp doctor` against the BUILT server (BEA_DIST_DIR snapshot, else dist/; docs/testing.md). The expected
 * inventory is the build's own TOOL_CONTRACTS, so concurrent catalog work in the sources cannot skew the comparison.
 */
const layout = harnessLayout();
const built = existsSync(layout.dispatcher) && existsSync(join(layout.distRoot, "main", "mcp.js"));
const builtCli = built && existsSync(join(layout.distRoot, "cli", "mcpDoctor.js"));

let home: TempHome;
beforeEach(async () => {
  home = await createTempHome("cli-mcp-doctor");
});
afterEach(async () => {
  await home.cleanup();
});

const builtContracts = async (): Promise<readonly ToolContract[]> =>
  (
    (await import(pathToFileURL(join(layout.distRoot, "contracts", "index.js")).href)) as {
      TOOL_CONTRACTS: readonly ToolContract[];
    }
  ).TOOL_CONTRACTS;

describe("bea mcp doctor (S1 §7.7)", () => {
  it.skipIf(!built)(
    "passes against the built server (requires npm run build)",
    async () => {
      const report = await runMcpDoctor({
        dispatcherPath: layout.dispatcher,
        execPath: process.execPath,
        env: minimalEnv(home),
        contracts: await builtContracts(),
      });
      expect(report.checks.filter((c) => !c.ok)).toEqual([]);
      expect(report.ok).toBe(true);
      expect(report.checks.map((c) => c.name)).toEqual([
        "spawn-initialize",
        "inventory",
        "annotations",
        "schema-dialect",
        "bea_status",
        "invalid-request",
        "shutdown",
      ]);
      expect(report.server).toMatchObject({ name: "bea" });
      expect(report.inventory.missing).toEqual([]);
      expect(report.stderr.truncated).toBe(false);
    },
    60_000,
  );
  it.skipIf(!built)(
    "reports inventory drift (an expected tool the server does not advertise)",
    async () => {
      const contracts = await builtContracts();
      const ghost = { ...contracts[0], name: "ghost_tool" } as ToolContract;
      const report = await runMcpDoctor({
        dispatcherPath: layout.dispatcher,
        execPath: process.execPath,
        env: minimalEnv(home),
        contracts: [...contracts, ghost],
      });
      expect(report.ok).toBe(false);
      expect(report.inventory.missing).toEqual(["ghost_tool"]);
      expect(report.checks.find((c) => c.name === "shutdown")).toMatchObject({ ok: true });
    },
    60_000,
  );
  it("a server that dies at startup fails spawn-initialize and skips the rest", async () => {
    const dead = join(home.work, "dead.mjs");
    await writeFile(dead, "process.stderr.write('boom\\n'); process.exit(3);\n");
    const report = await runMcpDoctor({
      dispatcherPath: dead,
      execPath: process.execPath,
      env: minimalEnv(home),
      contracts: [],
      deadlineMs: 10_000,
    });
    expect(report.ok).toBe(false);
    expect(report.checks[0]).toMatchObject({ name: "spawn-initialize", ok: false });
    expect(report.checks.find((c) => c.name === "inventory")?.detail).toContain("skipped");
    expect(report.stderr.text).toContain("boom");
  }, 30_000);
  it.skipIf(!builtCli)(
    "`node scripts/bea.mjs mcp doctor --json` exits 0 (requires a build with WP15)",
    () => {
      const result = spawnSync(process.execPath, [layout.dispatcher, "mcp", "doctor", "--json"], {
        env: minimalEnv(home),
        cwd: home.work,
        encoding: "utf8",
        timeout: 60_000,
      });
      expect(result.status, result.stdout + result.stderr).toBe(0);
      expect(JSON.parse(result.stdout)).toMatchObject({ schema: "bea.mcp-doctor/1", ok: true });
    },
    70_000,
  );
});
