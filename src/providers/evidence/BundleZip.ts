import { createWriteStream } from "node:fs";
import { mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { pipeline } from "node:stream/promises";
import { Transform, type TransformCallback } from "node:stream";

import { ZipFile } from "yazl";
import { openPromise, type Entry } from "yauzl";

/**
 * Zip bundles (S2 §13.3–13.4): yazl writes sorted entries with a fixed 1980-01-01 mtime (deflate for .json/.jsonl,
 * store for blobs and chunks); yauzl reads with traversal, bomb and size guards. Entry names follow the bundle layout
 * grammar only; anything else rejects the archive before a byte is extracted.
 */
export const BUNDLE_ENTRY_RE =
  /^(?:bundle\.json|records\.jsonl|blobs\/[a-f0-9]{64}|streams\/st_[a-f0-9]{64}\/(?:descriptor\.json|chain\.jsonl|chunk-\d{6}\.bin))$/u;
const DIRECTORY_ENTRY_RE = /^(?:blobs\/|streams\/|streams\/st_[a-f0-9]{64}\/)$/u;
const FIXED_MTIME = new Date(1980, 0, 1, 0, 0, 0);
const BOMB_RATIO = 200;
/** below this an entry's ratio is not checked (small JSON compresses well); the archive-wide ratio still applies */
const BOMB_MIN_BYTES = 64 * 1024;

export class ZipGuardError extends Error {
  override readonly name = "ZipGuardError";
  constructor(
    readonly what: string,
    readonly entry: string,
  ) {
    super(`${what}: ${entry.slice(0, 120)}`);
  }
}

/** Write `files` (relative bundle names → absolute source paths) as a zip at `outPath`. Returns the zip size. */
export const writeZip = async (files: ReadonlyMap<string, string>, outPath: string): Promise<void> => {
  const zip = new ZipFile();
  for (const name of [...files.keys()].sort()) {
    const source = files.get(name);
    if (source === undefined) continue;
    const compress = name.endsWith(".json") || name.endsWith(".jsonl");
    zip.addFile(source, name, { mtime: FIXED_MTIME, mode: 0o100644, compress, forceDosTimestamp: true });
  }
  zip.end();
  await pipeline(zip.outputStream, createWriteStream(outPath, { flags: "wx" }));
};

/** Cuts a stream that grows past `limit` bytes (defence beside yauzl's own size validation). */
const capped = (limit: number, name: string): Transform => {
  let seen = 0;
  return new Transform({
    transform(chunk: Buffer, _encoding: BufferEncoding, callback: TransformCallback) {
      seen += chunk.length;
      if (seen > limit) callback(new ZipGuardError("entry exceeds its declared size", name));
      else callback(null, chunk);
    },
  });
};

export const isUnsafeName = (name: string): boolean =>
  name.length === 0 ||
  name.includes("\\") ||
  name.includes("\u0000") ||
  name.startsWith("/") ||
  /^[A-Za-z]:/u.test(name) ||
  name.split("/").some((segment) => segment === ".." || segment === ".");

/** Hard ceiling on archive entries, whatever the manifest declares. */
export const MAX_ZIP_ENTRIES = 250_000;

/**
 * What the importer allows, decided from the (already extracted) manifest. Review fix SEC-5: every entry is checked
 * BEFORE any entry other than bundle.json is written: `limit(name)` is its largest acceptable uncompressed size (0 =
 * not referenced by the manifest: the archive is rejected), and the sum of all entries must stay within `total()`
 * (the run's remaining quotas and the free space of the extraction volume).
 */
export interface ZipExtractPolicy {
  readonly manifestMaxBytes: number;
  /** called once per entry in archive order; may account `size` cumulatively (e.g. a stream's chunks) */
  readonly limit: (name: string, size: number) => number;
  readonly total: () => number;
}

const writeEntry = async (zip: Awaited<ReturnType<typeof openPromise>>, entry: Entry, dest: string, limit: number) => {
  const target = join(dest, ...entry.fileName.split("/"));
  await mkdir(dirname(target), { recursive: true });
  const stream = await zip.openReadStreamPromise(entry);
  await pipeline(stream, capped(limit, entry.fileName), createWriteStream(target, { flags: "wx" }));
};

/**
 * Extract a bundle zip into `dest` (a fresh directory): the central directory is checked first (names, layout,
 * duplicates, encryption, per-entry and archive-wide compression ratio, entry count), then bundle.json alone is
 * extracted, then every other entry is planned against the policy, and only then extracted.
 */
export const extractZip = async (
  zipPath: string,
  dest: string,
  policy: ZipExtractPolicy,
  signal?: AbortSignal,
): Promise<readonly string[]> => {
  const zip = await openPromise(zipPath, {
    autoClose: false,
    lazyEntries: true,
    strictFileNames: true,
    validateEntrySizes: true,
  });
  try {
    if (zip.entryCount > MAX_ZIP_ENTRIES) throw new ZipGuardError("too many entries", "bundle");
    const entries: Entry[] = [];
    const names = new Set<string>();
    let declaredTotal = 0;
    for await (const entry of zip.eachEntry()) {
      const name = entry.fileName;
      if (isUnsafeName(name.endsWith("/") ? name.slice(0, -1) : name))
        throw new ZipGuardError("unsafe entry name", name);
      if (names.has(name)) throw new ZipGuardError("duplicate entry", name);
      names.add(name);
      if (names.size > MAX_ZIP_ENTRIES) throw new ZipGuardError("too many entries", name);
      if (DIRECTORY_ENTRY_RE.test(name)) continue;
      if (!BUNDLE_ENTRY_RE.test(name)) throw new ZipGuardError("entry outside the bundle layout", name);
      if (entry.isEncrypted()) throw new ZipGuardError("encrypted entry", name);
      if (
        entry.uncompressedSize > BOMB_MIN_BYTES &&
        entry.uncompressedSize > BOMB_RATIO * Math.max(1, entry.compressedSize)
      )
        throw new ZipGuardError("compression ratio above 200:1", name);
      declaredTotal += entry.uncompressedSize;
      entries.push(entry);
    }
    const archiveBytes = Math.max(1, zip.fileSize);
    if (declaredTotal > BOMB_MIN_BYTES && declaredTotal > BOMB_RATIO * archiveBytes)
      throw new ZipGuardError("archive compression ratio above 200:1", "bundle");
    const manifest = entries.find((e) => e.fileName === "bundle.json");
    if (manifest === undefined) throw new ZipGuardError("bundle.json missing", "bundle.json");
    if (manifest.uncompressedSize > policy.manifestMaxBytes)
      throw new ZipGuardError("entry larger than declared", manifest.fileName);
    await writeEntry(zip, manifest, dest, policy.manifestMaxBytes);
    // plan every other entry against the manifest before writing any of them
    let planned = 0;
    const rest: { readonly entry: Entry; readonly limit: number }[] = [];
    for (const entry of entries) {
      if (entry === manifest) continue;
      const limit = policy.limit(entry.fileName, entry.uncompressedSize);
      if (limit <= 0) throw new ZipGuardError("entry not referenced by the manifest", entry.fileName);
      if (entry.uncompressedSize > limit) throw new ZipGuardError("entry larger than declared", entry.fileName);
      planned += entry.uncompressedSize;
      rest.push({ entry, limit });
    }
    if (planned > policy.total()) throw new ZipGuardError("bundle larger than the remaining quota or disk", "bundle");
    const out: string[] = [manifest.fileName];
    for (const { entry, limit } of rest) {
      if (signal?.aborted === true) throw new ZipGuardError("cancelled", entry.fileName);
      await writeEntry(zip, entry, dest, limit);
      out.push(entry.fileName);
    }
    return out;
  } finally {
    zip.close();
  }
};
