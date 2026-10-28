import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Where BEA's build outputs are at run time (WP0; docs/testing.md). Every path derives from the dist root that holds the
 * running code (this module compiles to <dist>/application/distLayout.js) and the package root above it, never from
 * process.cwd() or a repository path, so a copied build (scripts/snapshot-dist.mjs, an installed package) is
 * self-contained. Code running from the TypeScript sources (vitest) has no dist of its own: it uses BEA_DIST_DIR when
 * set (a snapshot's dist), else the repository's dist/. Providers locate the agent bundle (WP-SESS), the jobhost
 * (WP-PROC), the emulator bridge (WP-EMU) and the skill (WP-CLI) through resolveDistLayout().
 */
export interface DistLayout {
  /** The dist root: <package>/dist. */
  readonly distRoot: string;
  /** The package root: package.json, scripts/bea.mjs, bridge/emu/. */
  readonly packageRoot: string;
  /** True when resolved for code running from src/*.ts (tests) rather than from a build. */
  readonly fromSource: boolean;
  /** <package>/scripts/bea.mjs, the bin dispatcher (imports ../dist/main/*.js). */
  readonly dispatcher: string;
  readonly agentBundle: string;
  readonly agentManifest: string;
  readonly jobhostExe: string;
  readonly jobhostManifest: string;
  readonly bridgeScript: string;
  readonly bridgeRequirements: string;
  readonly bridgeManifest: string;
  readonly skillsDir: string;
}

/** The layout of the build whose dist root is `distRoot`. */
export const distLayoutAt = (distRoot: string, fromSource = false): DistLayout => {
  const root = resolve(distRoot);
  const packageRoot = dirname(root);
  return {
    distRoot: root,
    packageRoot,
    fromSource,
    dispatcher: join(packageRoot, "scripts", "bea.mjs"),
    agentBundle: join(root, "agent", "bea-agent.js"),
    agentManifest: join(root, "agent", "bea-agent.json"),
    jobhostExe: join(root, "native", "win32-x64", "bea-jobhost.exe"),
    jobhostManifest: join(root, "native", "win32-x64", "bea-jobhost.json"),
    bridgeScript: join(packageRoot, "bridge", "emu", "bea_emu_bridge.py"),
    bridgeRequirements: join(packageRoot, "bridge", "emu", "requirements.lock"),
    bridgeManifest: join(root, "bridge-manifest.json"),
    skillsDir: join(root, "skills"),
  };
};

/**
 * The layout for the running code. `moduleUrl` is this module's URL (a parameter only so tests can exercise both
 * cases); `env` supplies BEA_DIST_DIR, which applies only when running from sources.
 */
export const resolveDistLayout = (
  env: Readonly<Record<string, string | undefined>> = process.env,
  moduleUrl: string = import.meta.url,
): DistLayout => {
  const here = fileURLToPath(moduleUrl);
  if (!here.endsWith(".ts")) return distLayoutAt(join(dirname(here), ".."), false);
  const override = env["BEA_DIST_DIR"];
  return distLayoutAt(
    override !== undefined && override !== "" ? override : join(dirname(here), "..", "..", "dist"),
    true,
  );
};
