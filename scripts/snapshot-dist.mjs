#!/usr/bin/env node
// scripts/snapshot-dist.mjs <name> (WP0; docs/testing.md "Testing built binaries in a shared tree").
//
// Copies the current build into build/dist-snapshots/<name>/ under the "build" lock, so a concurrent rebuild by
// another agent can never swap the server, agent bundle or jobhost under a running test. The snapshot mirrors the
// package layout the built runtime resolves against (its own dist root and the package root above it):
//   <snapshot>/dist/**            copy of dist/ (server JS, agent bundle, jobhost, manifests, skills)
//   <snapshot>/scripts/bea.mjs    the bin dispatcher (imports ../dist/main/*.js, reads ../package.json)
//   <snapshot>/package.json
//   <snapshot>/bridge/emu/**      the emulator bridge, when present
// Bare imports (zod, @modelcontextprotocol/*, frida) resolve upward to the repository's node_modules.
// The previous snapshot of the same name is replaced atomically. Prints ONE line on stdout: the absolute path to use
// as BEA_DIST_DIR (<snapshot>/dist).
import { cp, mkdir, stat } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { makeStagingDir, publishDir, removeStagingDir } from "./lib/atomic.mjs";
import { withBuildLock } from "./lib/lock.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const name = process.argv[2];
if (name === undefined || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u.test(name) || process.argv.length > 3) {
  process.stderr.write(
    "usage: node scripts/snapshot-dist.mjs <name>   (name: letters, digits, . _ -; e.g. your WP id)\n",
  );
  process.exit(2);
}
const exists = async (path) => {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
};
const skipTransient = (path) => !/\.(?:old|tmp)-\d+-[0-9a-f]+$/u.test(path);

const target = join(root, "build", "dist-snapshots", name);
await withBuildLock(async () => {
  if (!(await exists(join(root, "dist", "main", "mcp.js")))) {
    process.stderr.write("snapshot-dist: dist/ has no built server (dist/main/mcp.js). Run `npm run build` first.\n");
    process.exitCode = 1;
    return;
  }
  const staged = await makeStagingDir(`snapshot-${name}`, root);
  try {
    await cp(join(root, "dist"), join(staged, "dist"), { recursive: true, filter: skipTransient });
    await mkdir(join(staged, "scripts"), { recursive: true });
    await cp(join(root, "scripts", "bea.mjs"), join(staged, "scripts", "bea.mjs"));
    await cp(join(root, "package.json"), join(staged, "package.json"));
    if (await exists(join(root, "bridge", "emu")))
      await cp(join(root, "bridge", "emu"), join(staged, "bridge", "emu"), {
        recursive: true,
        filter: (p) => !p.includes("__pycache__"),
      });
    try {
      await publishDir(staged, target);
    } catch (cause) {
      process.stderr.write(
        `snapshot-dist: could not replace ${target} (${cause?.code ?? cause}); a process started from the previous ` +
          "snapshot is probably still running. Stop it, or snapshot under another name.\n",
      );
      process.exitCode = 1;
      return;
    }
    process.stdout.write(`${join(target, "dist")}\n`);
  } finally {
    await removeStagingDir(staged);
  }
});
