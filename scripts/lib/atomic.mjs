// scripts/lib/atomic.mjs — staging directories and atomic publication of build outputs (WP0; docs/testing.md).
//
// Builders write into a unique staging directory and publish finished files with rename, so a reader never sees a
// half-written bundle, exe, manifest or fixture. On Windows a running .exe cannot be overwritten or deleted but can
// be renamed: publishFile moves a busy target aside first (the leftover *.old-* file is removed by clean.mjs later).
import { randomBytes } from "node:crypto";
import { mkdir, mkdtemp, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { REPO_ROOT } from "./lock.mjs";

const BUSY = new Set(["EPERM", "EACCES", "EBUSY", "EEXIST", "ENOTEMPTY"]);
const suffix = () => `${process.pid}-${randomBytes(4).toString("hex")}`;

/** A fresh directory under build/tmp/ (same volume as dist/ and .cache/, so publication is a rename). */
export async function makeStagingDir(label, root = REPO_ROOT) {
  const base = join(root, "build", "tmp");
  await mkdir(base, { recursive: true });
  return mkdtemp(join(base, `${label}-${process.pid}-`));
}

/** Best-effort removal of a staging directory (never fails the build). */
export async function removeStagingDir(dir) {
  await rm(dir, { recursive: true, force: true, maxRetries: 3 }).catch(() => undefined);
}

/** Replace the file `dest` with `staged` (same volume). */
export async function publishFile(staged, dest) {
  await mkdir(dirname(dest), { recursive: true });
  try {
    await rename(staged, dest);
    return;
  } catch (cause) {
    if (!BUSY.has(cause?.code)) throw cause;
  }
  const aside = `${dest}.old-${suffix()}`;
  await rename(dest, aside);
  await rename(staged, dest);
  await rm(aside, { force: true }).catch(() => undefined);
}

/** Replace the directory `dest` with `staged` (same volume); the previous content is removed afterwards. */
export async function publishDir(staged, dest) {
  await mkdir(dirname(dest), { recursive: true });
  const aside = `${dest}.old-${suffix()}`;
  let moved = false;
  try {
    await rename(dest, aside);
    moved = true;
  } catch (cause) {
    if (cause?.code !== "ENOENT") throw cause;
  }
  try {
    await rename(staged, dest);
  } catch (cause) {
    if (moved) await rename(aside, dest).catch(() => undefined);
    throw cause;
  }
  if (moved) await rm(aside, { recursive: true, force: true, maxRetries: 3 }).catch(() => undefined);
}

/** Write a file through a sibling temp file + rename. */
export async function writeFileAtomic(path, data) {
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.tmp-${suffix()}`;
  await writeFile(tmp, data);
  try {
    await publishFile(tmp, path);
  } catch (cause) {
    await rm(tmp, { force: true }).catch(() => undefined);
    throw cause;
  }
}
