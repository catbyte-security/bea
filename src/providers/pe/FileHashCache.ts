import { createHash } from "node:crypto";
import { appendFile, mkdir, open, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import type { BeaError } from "../../domain/errors/beaError.js";
import type { HostPlatform } from "../../domain/paths.js";
import type { FileKey } from "../../domain/process/instance.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { FileHashCache } from "../../ports/pe.js";
import { peFailure } from "./errors.js";
import { fileKeyString, sameFileKey, statFileKey } from "./fileAccess.js";
import { toBeaError } from "./PeImageCache.js";

/**
 * Persistent sha256 cache (S2 §17.6): append-only NDJSON `{path_key, size, mtime_ns, ctime_ns, ino, dev, sha256}` in
 * BEA_HOME/cache/file-sha256.jsonl, loaded lazily on first use (last line wins), compacted when lines exceed twice
 * the unique keys. Concurrent servers append single short lines (O_APPEND); a torn or corrupt line is a cache miss —
 * the cache is an optimization, never an authority. Hashing streams 1 MiB reads and honours the signal.
 */
const CHUNK = 1024 * 1024;
const SHA256 = /^[a-f0-9]{64}$/u;

interface Line extends FileKey {
  readonly sha256: string;
}

const isLine = (value: unknown): value is Line => {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    ["path_key", "size", "mtime_ns", "ctime_ns", "ino", "dev"].every((k) => typeof v[k] === "string") &&
    typeof v["sha256"] === "string" &&
    SHA256.test(v["sha256"])
  );
};

export class PersistentFileHashCache implements FileHashCache {
  #loaded: Promise<void> | null = null;
  readonly #byKey = new Map<string, Line>();
  readonly #inflight = new Map<string, Promise<string>>();
  #lines = 0;

  constructor(
    private readonly file: string,
    private readonly platform: HostPlatform,
  ) {}

  async sha256(path: string, signal?: AbortSignal): Promise<Result<string, BeaError>> {
    try {
      const key = await statFileKey(path, this.platform);
      await this.#load();
      const id = fileKeyString(key);
      const cached = this.#byKey.get(id);
      if (cached !== undefined) return ok(cached.sha256);
      let pending = this.#inflight.get(id);
      if (pending === undefined) {
        pending = this.#hashAndStore(path, key, id, signal).finally(() => this.#inflight.delete(id));
        this.#inflight.set(id, pending);
      }
      return ok(await pending);
    } catch (thrown) {
      return err(toBeaError("pe.sha256", path, thrown));
    }
  }

  async #hashAndStore(path: string, key: FileKey, id: string, signal: AbortSignal | undefined): Promise<string> {
    const digest = await hashFile(path, key, this.platform, signal);
    const line: Line = { ...key, sha256: digest };
    this.#byKey.set(id, line);
    try {
      await mkdir(dirname(this.file), { recursive: true });
      await appendFile(this.file, `${JSON.stringify(line)}\n`, { encoding: "utf8", flag: "a" });
      this.#lines++;
      if (this.#lines > 2 * this.#byKey.size && this.#lines > 64) await this.#compact();
    } catch {
      // the cache is an optimization: a failed append only costs a re-hash next run
    }
    return digest;
  }

  #load(): Promise<void> {
    this.#loaded ??= (async () => {
      let text: string;
      try {
        text = await readFile(this.file, "utf8");
      } catch {
        return;
      }
      for (const raw of text.split("\n")) {
        if (raw.length === 0) continue;
        this.#lines++;
        try {
          const value: unknown = JSON.parse(raw);
          if (isLine(value)) this.#byKey.set(fileKeyString(value), value);
        } catch {
          // torn line: a cache miss
        }
      }
    })();
    return this.#loaded;
  }

  async #compact(): Promise<void> {
    const temp = `${this.file}.${String(process.pid)}.${Date.now().toString(36)}.tmp`;
    const lines = [...this.#byKey.values()].map((line) =>
      JSON.stringify({
        path_key: line.path_key,
        size: line.size,
        mtime_ns: line.mtime_ns,
        ctime_ns: line.ctime_ns,
        ino: line.ino,
        dev: line.dev,
        sha256: line.sha256,
      }),
    );
    await writeFile(temp, `${lines.join("\n")}\n`, "utf8");
    await rename(temp, this.file);
    this.#lines = lines.length;
  }
}

/** Streaming sha256 of a file whose FileKey must still be `key` (a change during hashing is an io failure). */
const hashFile = async (path: string, key: FileKey, platform: HostPlatform, signal?: AbortSignal): Promise<string> => {
  const handle = await open(path, "r").catch((cause: unknown) => {
    throw peFailure("io", `The file could not be opened (${String((cause as { code?: string }).code ?? "io")}).`);
  });
  try {
    const hash = createHash("sha256");
    const buffer = Buffer.alloc(CHUNK);
    let position = 0;
    for (;;) {
      if (signal?.aborted === true) throw peFailure("io", "Hashing was cancelled.");
      const { bytesRead } = await handle.read(buffer, 0, CHUNK, position);
      if (bytesRead === 0) break;
      hash.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }
    const after = await statFileKey(path, platform);
    if (!sameFileKey(after, key)) throw peFailure("io", "The file changed on disk while it was hashed.");
    return hash.digest("hex");
  } finally {
    await handle.close().catch(() => undefined);
  }
};
