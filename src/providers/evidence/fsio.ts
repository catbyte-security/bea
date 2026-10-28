import { randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open, rename, rm, type FileHandle } from "node:fs/promises";
import { dirname } from "node:path";

import { isErrno } from "./errors.js";

/** Small fs helpers for the run store (S2 §9.6 durability; A7 Windows rename behaviour). */
export const randomHex = (bytes = 8): string => randomBytes(bytes).toString("hex");

export const delay = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

export const pathExists = async (path: string): Promise<boolean> => {
  try {
    await lstat(path);
    return true;
  } catch (cause) {
    if (isErrno(cause, "ENOENT", "ENOTDIR")) return false;
    throw cause;
  }
};

/** A7: AV / Explorer handles make Windows renames fail transiently; retry 50/100/200/400 ms (≤ 2 s total). */
export const renameWithRetry = async (from: string, to: string): Promise<void> => {
  const backoff = [50, 100, 200, 400, 400, 400, 400];
  for (let attempt = 0; ; attempt++) {
    try {
      await rename(from, to);
      return;
    } catch (cause) {
      const wait = backoff[attempt];
      if (wait === undefined || !isErrno(cause, "EPERM", "EBUSY", "EACCES")) throw cause;
      await delay(wait);
    }
  }
};

/** fsync a file by path (opened r+ so Windows FlushFileBuffers is allowed). */
export const fsyncPath = async (path: string): Promise<void> => {
  const handle = await open(path, "r+");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
};

/** Directory fsync is unsupported on win32; best effort elsewhere (A7). */
export const fsyncDir = async (path: string): Promise<void> => {
  if (process.platform === "win32") return;
  try {
    const handle = await open(path, constants.O_RDONLY);
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
  } catch {
    // best effort
  }
};

/** Write a whole file through a temp sibling and rename it into place (run.json, descriptors). */
export const writeFileAtomic = async (path: string, data: string | Uint8Array, sync = false): Promise<void> => {
  const tmp = `${path}.tmp-${randomHex()}`;
  await mkdir(dirname(path), { recursive: true });
  let handle: FileHandle | undefined = await open(tmp, "wx");
  try {
    await handle.writeFile(data);
    if (sync) await handle.sync();
    await handle.close();
    handle = undefined;
    await renameWithRetry(tmp, path);
  } catch (cause) {
    if (handle !== undefined) await handle.close().catch(() => undefined);
    await rm(tmp, { force: true }).catch(() => undefined);
    throw cause;
  }
};

/** Write a new file that must not exist yet ('wx'). */
export const writeFileExclusive = async (path: string, data: string | Uint8Array): Promise<void> => {
  const handle = await open(path, "wx");
  try {
    await handle.writeFile(data);
  } finally {
    await handle.close();
  }
};

/** Is `pid` a live process? (signal 0; EPERM means it exists but belongs to someone else). */
export const pidAlive = (pid: number): boolean => {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (cause) {
    return isErrno(cause, "EPERM");
  }
};
