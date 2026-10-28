import { createHash } from "node:crypto";
import { appendFile, mkdir, readFile, stat, utimes, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type { HostPlatform } from "../../../src/domain/paths.js";
import { PersistentFileHashCache } from "../../../src/providers/pe/FileHashCache.js";
import { createPeServices } from "../../../src/providers/pe/createPeServices.js";
import type { BeaCore } from "../../../src/application/BeaApplication.js";
import { createTempHome, type TempHome } from "../../support/workspace/tempHome.js";

/** S2 §17.6: persistent sha256 cache keyed by FileKey (append-only NDJSON, last line wins, corrupt lines ignored). */
const platform = process.platform as HostPlatform;
const sha = (data: string | Buffer) => createHash("sha256").update(data).digest("hex");

let home: TempHome;
let file: string;
let cacheFile: string;
beforeEach(async () => {
  home = await createTempHome("hash");
  file = join(home.root, "image.bin");
  cacheFile = join(home.beaHome, "cache", "file-sha256.jsonl");
  await writeFile(file, "first content");
});
afterEach(async () => {
  await home.cleanup();
});

describe("FileHashCache", () => {
  it("hashes, persists one line, and serves the next run from the file", async () => {
    const first = new PersistentFileHashCache(cacheFile, platform);
    expect(await first.sha256(file)).toEqual({ ok: true, value: sha("first content") });
    const lines = (await readFile(cacheFile, "utf8")).trim().split("\n");
    expect(lines).toHaveLength(1);
    const line = JSON.parse(lines[0] ?? "{}") as Record<string, string>;
    expect(Object.keys(line).sort()).toEqual(["ctime_ns", "dev", "ino", "mtime_ns", "path_key", "sha256", "size"]);
    // a second instance trusts the cache: plant a different digest for the same key to prove it is read
    const planted = { ...line, sha256: "f".repeat(64) };
    await appendFile(cacheFile, `${JSON.stringify(planted)}\n`);
    const second = new PersistentFileHashCache(cacheFile, platform);
    expect(await second.sha256(file)).toEqual({ ok: true, value: "f".repeat(64) });
  });

  it("re-hashes when the content changes even if mtime is restored (ctime/size in the key)", async () => {
    const cache = new PersistentFileHashCache(cacheFile, platform);
    await cache.sha256(file);
    const before = await stat(file);
    await writeFile(file, "second content!");
    await utimes(file, before.atime, before.mtime);
    expect(await cache.sha256(file)).toEqual({ ok: true, value: sha("second content!") });
  });

  it("skips corrupt and torn lines and reports missing files as file_operation_failed", async () => {
    await mkdir(join(home.beaHome, "cache"), { recursive: true });
    await writeFile(cacheFile, '{"path_key":1}\nnot json\n{"truncat');
    const cache = new PersistentFileHashCache(cacheFile, platform);
    expect(await cache.sha256(file)).toEqual({ ok: true, value: sha("first content") });
    const missing = await cache.sha256(join(home.root, "nope.bin"));
    expect(!missing.ok && missing.error).toMatchObject({ _tag: "FileOperationFailed", reason: "missing" });
  });

  it("compacts when lines exceed twice the unique keys", async () => {
    await mkdir(join(home.beaHome, "cache"), { recursive: true });
    const cache = new PersistentFileHashCache(cacheFile, platform);
    // distinct sizes: rewrites within one file-time tick must still be distinct keys
    for (let i = 0; i < 70; i++) {
      await writeFile(file, "x".repeat(i + 1));
      await cache.sha256(file);
    }
    // 70 distinct keys: no compaction (lines == keys); then duplicate lines from a second writer
    const lines = (await readFile(cacheFile, "utf8")).trim().split("\n");
    expect(lines.length).toBe(70);
    await appendFile(cacheFile, `${lines.join("\n")}\n${lines.join("\n")}\n`);
    const reloaded = new PersistentFileHashCache(cacheFile, platform);
    await writeFile(file, "fresh");
    await reloaded.sha256(file);
    expect((await readFile(cacheFile, "utf8")).trim().split("\n").length).toBe(71);
  });

  it("is constructed without touching the disk (CI-M20)", async () => {
    const core = { config: { platform, layout: { cacheDir: join(home.beaHome, "cache") } } } as unknown as BeaCore;
    const services = createPeServices(core);
    await expect(stat(join(home.beaHome, "cache"))).rejects.toThrow();
    expect((await services.hashes.sha256(file)).ok).toBe(true);
    expect((await stat(join(home.beaHome, "cache"))).isDirectory()).toBe(true);
  });
});
