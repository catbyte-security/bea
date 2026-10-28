#!/usr/bin/env node
// scripts/clean.mjs (WP0; S1 §1.1): remove the build outputs dist/ and the staging area build/tmp/ under the "build"
// lock. Windows keeps a running .exe (a jobhost started from dist/ by a test that did not snapshot) undeletable; such a
// file is renamed aside instead and reported, so the build can continue.
import { readdir, rename, rm, rmdir, unlink } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { withBuildLock } from "./lib/lock.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const BUSY = new Set(["EBUSY", "EPERM", "EACCES", "ENOTEMPTY"]);

/** Bottom-up removal that survives busy files; returns the paths that could only be moved aside. */
async function removeTree(dir, busy) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch (cause) {
    if (cause?.code === "ENOENT") return;
    throw cause;
  }
  for (const entry of entries) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      await removeTree(path, busy);
      continue;
    }
    try {
      await unlink(path);
    } catch (cause) {
      if (cause?.code === "ENOENT") continue;
      if (!BUSY.has(cause?.code)) throw cause;
      if (/\.old-\d+-[0-9a-f]+$/u.test(entry.name)) {
        busy.push(path);
        continue;
      }
      const aside = `${path}.old-${process.pid}-${Date.now().toString(16)}`;
      await rename(path, aside).catch(() => undefined);
      busy.push(path);
    }
  }
  await rmdir(dir).catch(() => undefined);
}

async function clean(target, busy) {
  try {
    await rm(target, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  } catch (cause) {
    if (!BUSY.has(cause?.code)) throw cause;
    await removeTree(target, busy);
  }
}

await withBuildLock(async () => {
  const busy = [];
  await clean(join(root, "dist"), busy);
  await clean(join(root, "build", "tmp"), busy);
  for (const path of busy)
    process.stderr.write(
      `clean: ${relative(root, path)} is in use by a running process and was left in place (renamed aside). ` +
        "Tests that launch built binaries should run from a snapshot: node scripts/snapshot-dist.mjs <name>.\n",
    );
});
