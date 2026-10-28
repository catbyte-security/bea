import { createHash } from "node:crypto";
import { createReadStream, realpath } from "node:fs";
import { readdir, stat } from "node:fs/promises";

import { isNetworkPath } from "../../application/localPaths.js";
import { dirname } from "node:path";

/**
 * Streaming sha256 of an image file (identity.image.sha256, expect_sha256, the per-image anti-cheat override). A
 * 100 MB game executable hashes in ~0.3 s; the caller's signal stops the read. A locked or unreadable file gives null
 * (the identity then carries IMAGE_HASH_UNAVAILABLE).
 */
export const sha256File = (
  path: string,
  signal?: AbortSignal,
): Promise<{ readonly sha256: string; readonly size: number } | null> =>
  new Promise((resolve) => {
    if (signal?.aborted === true) {
      resolve(null);
      return;
    }
    const hash = createHash("sha256");
    let size = 0;
    const stream = createReadStream(path, { highWaterMark: 1024 * 1024 });
    const onAbort = (): void => {
      stream.destroy();
      resolve(null);
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    stream.on("data", (chunk) => {
      const bytes = chunk as Buffer;
      size += bytes.length;
      hash.update(bytes);
    });
    stream.on("error", () => {
      signal?.removeEventListener("abort", onAbort);
      resolve(null);
    });
    stream.on("end", () => {
      signal?.removeEventListener("abort", onAbort);
      resolve({ sha256: hash.digest("hex"), size });
    });
  });

const LONG_PATH_PREFIX = "\\\\?\\";

/**
 * SEC-1: the file's final path (GetFinalPathNameByHandle through realpath.native: junctions, symlinks and 8.3 short
 * names resolved), or null when it cannot be resolved (an execution alias, a missing file).
 */
export const finalPathOf = async (path: string): Promise<string | null> => {
  try {
    const resolved = await new Promise<string>((resolve, reject) => {
      realpath.native(path, (error, value) => (error === null ? resolve(value) : reject(error)));
    });
    return resolved.startsWith(LONG_PATH_PREFIX) ? resolved.slice(LONG_PATH_PREFIX.length) : resolved;
  } catch {
    return null;
  }
};

/** SEC-2: a spawn cwd: an existing local directory, a network location (UNC, mapped drive, junction to a share), … */
export const inspectDirectory = async (
  path: string,
): Promise<"directory" | "network" | "missing" | "not-directory"> => {
  const final = await finalPathOf(path);
  if (final !== null && isNetworkPath(final)) return "network";
  try {
    return (await stat(path)).isDirectory() ? "directory" : "not-directory";
  } catch {
    return "missing";
  }
};

/** Ancestor levels listed above the image's own directory (review fix SEC-6). */
const NEIGHBOURHOOD_LEVELS = 3;

/**
 * Entry names of the image's directory and of up to NEIGHBOURHOOD_LEVELS ancestors (anti-cheat signal (a)); unreadable
 * directories are skipped, a volume root ends the walk. Review fix SEC-6: the standard Unreal Engine layout keeps the
 * shipping image in <root>\<Project>\Binaries\Win64\ while EasyAntiCheat\ and start_protected_game.exe sit in <root>:
 * the image directory and its parent alone never saw them.
 */
export const listImageNeighbourhood = async (imagePath: string): Promise<readonly string[]> => {
  const names: string[] = [];
  let dir = dirname(imagePath);
  for (let level = 0; level <= NEIGHBOURHOOD_LEVELS; level++) {
    try {
      names.push(...(await readdir(dir)).slice(0, 4096));
    } catch {
      // permission or race: no signal from this directory
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return names;
};
