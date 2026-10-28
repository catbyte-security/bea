import { randomBytes } from "node:crypto";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { canonicalJson, sha256Hex } from "../../domain/canonical.js";
import {
  DUMP_MANIFEST_FILE,
  DUMP_PAGE_BYTES,
  DUMP_REGIONS_DIR,
  dumpManifestSchema,
  type DumpManifest,
  type DumpManifestRegion,
  type DumpRegionTag,
} from "../../domain/dumpBundle.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { internalError } from "../../domain/errors/constructors.js";
import { formatHex } from "../../domain/hex.js";
import type { JsonValue } from "../../domain/json.js";
import { err, ok, type Result } from "../../domain/result.js";
import { pathIsFree, publishDirectory } from "./outputFiles.js";

/**
 * bea.dump/1 writer (S5 §10.1 + R10; WP-DUMP). Regions captured by the agent (module images, TEB/PEB/stack/TLS pages,
 * ranges) are normalized into the bundle layout: whole 4 KiB pages, module images split at the protection runs of
 * the readable memory map (unmapped/unreadable parts dropped), overlapping captures merged (the first readable capture
 * of a page wins), every page that no capture read listed in `unreadable_pages` (zero-filled, never mapped by the
 * emulator). Region files are content-addressed (`regions/<sha256>.bin`, identical regions stored once); the
 * manifest is JCS (RFC 8785) and `bundle_id` = "dump_" + sha256(JCS(manifest without bundle_id)). The bundle is
 * staged in `<target>.staging-<rand>` and renamed into place; an existing target is never touched.
 */
const PAGE = BigInt(DUMP_PAGE_BYTES);

export interface CapturedRegion {
  readonly base: bigint;
  readonly size: number;
  readonly tag: DumpRegionTag;
  readonly protection: string;
  readonly module: string | null;
  /** unreadable byte ranges relative to base (zero-filled in the bytes) */
  readonly holes: readonly { readonly offset: number; readonly size: number }[];
  /** the captured bytes (exactly `size`), loaded once per region */
  readonly load: () => Promise<Result<Uint8Array, BeaError>>;
}
export interface MemoryMapRange {
  readonly base: bigint;
  readonly size: number;
  readonly protection: string;
  readonly module: string | null;
}
interface Part {
  readonly src: CapturedRegion;
  /** absolute start/end of the bytes this part copies */
  readonly start: bigint;
  readonly end: bigint;
}
export interface PlannedRegion {
  readonly base: bigint;
  readonly size: number;
  readonly tag: DumpRegionTag;
  readonly protection: string;
  readonly module: string | null;
  readonly parts: readonly Part[];
  readonly unreadable: readonly bigint[];
}

const alignDown = (v: bigint): bigint => v - (v % PAGE);
const alignUp = (v: bigint): bigint => (v % PAGE === 0n ? v : v + (PAGE - (v % PAGE)));
const min = (a: bigint, b: bigint): bigint => (a < b ? a : b);
const max = (a: bigint, b: bigint): bigint => (a > b ? a : b);
const protectionText = (p: string): string => (/^[r-][w-][x-]$/u.test(p) ? p : "r--");

/** Pages of [start, end) that the part's source read completely (inside the source and outside its holes). */
const readablePages = (part: Part): Set<bigint> => {
  const pages = new Set<bigint>();
  for (let page = alignDown(part.start); page < part.end; page += PAGE) {
    const lo = max(page, part.src.base);
    const hi = min(page + PAGE, part.src.base + BigInt(part.src.size));
    if (lo !== page || hi !== page + PAGE) continue;
    const off = Number(page - part.src.base);
    if (part.src.holes.some((h) => h.offset < off + DUMP_PAGE_BYTES && off < h.offset + h.size)) continue;
    pages.add(page);
  }
  return pages;
};

interface Piece {
  base: bigint;
  end: bigint;
  tag: DumpRegionTag;
  protection: string;
  module: string | null;
  parts: Part[];
}

const piecesOf = (region: CapturedRegion, map: readonly MemoryMapRange[]): Piece[] => {
  const start = alignDown(region.base);
  const end = alignUp(region.base + BigInt(region.size));
  if (end <= start) return [];
  const piece = (lo: bigint, hi: bigint, protection: string): Piece => ({
    base: lo,
    end: hi,
    tag: region.tag,
    protection: protectionText(protection),
    module: region.module,
    parts: [{ src: region, start: max(lo, region.base), end: min(hi, region.base + BigInt(region.size)) }],
  });
  // Review fix DATA-6: EVERY capture (module images and ranges alike) is split at the readable memory map's protection
  // runs and takes the map's protection there; a range's own protection is only its first page's. Pages the map does
  // not cover keep the capture's protection.
  const out: Piece[] = [];
  let cursor = start;
  for (const range of map) {
    const lo = max(start, alignDown(range.base));
    const hi = min(end, alignUp(range.base + BigInt(range.size)));
    if (hi <= lo) continue;
    // a module image's unmapped parts are dropped; a range keeps them (listed as unreadable pages)
    if (lo > cursor && region.tag !== "module") out.push(piece(cursor, lo, region.protection));
    out.push(piece(max(lo, cursor), hi, range.protection));
    cursor = max(cursor, hi);
  }
  // no readable-map knowledge for this capture (map unavailable): keep it whole
  if (out.length === 0) return [piece(start, end, region.protection)];
  if (cursor < end && region.tag !== "module") out.push(piece(cursor, end, region.protection));
  return out.filter((p) => p.end > p.base);
};

/** Module pieces first at equal bases, so the first readable capture of a page is deterministic. */
const pieceOrder = (a: Piece, b: Piece): number =>
  a.base < b.base ? -1 : a.base > b.base ? 1 : a.tag === b.tag ? 0 : a.tag === "module" ? -1 : 1;

const clipParts = (parts: readonly Part[], lo: bigint, hi: bigint): Part[] =>
  parts
    .map((part) => ({ ...part, start: max(part.start, lo), end: min(part.end, hi) }))
    .filter((part) => part.end > part.start);

/** Normalizes captured regions into the bundle layout (pure; bytes are composed later). */
export const planBundleRegions = (
  captured: readonly CapturedRegion[],
  memoryMap: readonly MemoryMapRange[],
): PlannedRegion[] => {
  const sortedMap = [...memoryMap].sort((a, b) => (a.base < b.base ? -1 : a.base > b.base ? 1 : 0));
  const pieces = captured.flatMap((r) => piecesOf(r, sortedMap)).sort(pieceOrder);
  const merged: Piece[] = [];
  for (const p of pieces) {
    const last = merged[merged.length - 1];
    if (last === undefined || p.base >= last.end) {
      merged.push({ ...p, parts: [...p.parts] });
      continue;
    }
    // DATA-6: overlapping captures share bytes (the first readable capture of a page wins), but a region never
    // absorbs pages of another protection: the part past `last` becomes its own region with its own protection
    last.parts.push(...clipParts(p.parts, p.base, min(p.end, last.end)));
    if (last.tag !== "module" && p.tag === "module") {
      last.tag = "module";
      last.module = p.module;
    }
    if (p.end <= last.end) continue;
    if (p.protection === last.protection) {
      last.parts.push(...clipParts(p.parts, last.end, p.end));
      last.end = p.end;
    } else merged.push({ ...p, base: last.end, parts: clipParts(p.parts, last.end, p.end) });
  }
  return merged.map((p) => {
    const readable = new Set<bigint>();
    for (const part of p.parts) for (const page of readablePages(part)) readable.add(page);
    const unreadable: bigint[] = [];
    for (let page = p.base; page < p.end; page += PAGE) if (!readable.has(page)) unreadable.push(page);
    return {
      base: p.base,
      size: Number(p.end - p.base),
      tag: p.tag,
      protection: p.protection,
      module: p.module,
      parts: p.parts,
      unreadable,
    };
  });
};

/** Bytes of one planned region: later parts first, so the first readable capture of a page wins. */
export const composeRegion = async (
  region: PlannedRegion,
  load: (src: CapturedRegion) => Promise<Result<Uint8Array, BeaError>>,
): Promise<Result<Uint8Array, BeaError>> => {
  const out = new Uint8Array(region.size);
  for (const part of [...region.parts].reverse()) {
    const bytes = await load(part.src);
    if (!bytes.ok) return bytes;
    const pages = readablePages(part);
    for (const page of pages) {
      if (page < region.base || page >= region.base + BigInt(region.size)) continue;
      const from = Number(page - part.src.base);
      out.set(bytes.value.subarray(from, from + DUMP_PAGE_BYTES), Number(page - region.base));
    }
  }
  return ok(out);
};

export type ManifestDraft = Omit<DumpManifest, "bundle_id" | "regions">;

export interface WrittenBundle {
  readonly path: string;
  readonly bundleId: `dump_${string}`;
  readonly manifest: DumpManifest;
  /** bytes of manifest.json + every distinct region file */
  readonly bytes: number;
  readonly manifestSha256: string;
}

const writeError = (operation: string, path: string, cause: unknown): BeaError => ({
  _tag: "FileOperationFailed",
  operation,
  file_operation: "write",
  path,
  reason: "io",
  cause,
});

/** bundle_id of a manifest draft with its regions (deterministic). */
export const bundleIdOf = (manifest: Omit<DumpManifest, "bundle_id">): `dump_${string}` =>
  `dump_${sha256Hex(canonicalJson(manifest as unknown as JsonValue))}`;

/**
 * Writes the bundle. `target` = the final directory, or a function of the bundle id (the default
 * <exports>/<bundle_id>). Region bytes are composed, hashed and written one region at a time.
 */
export const writeDumpBundle = async (
  operation: string,
  draft: ManifestDraft,
  regions: readonly PlannedRegion[],
  target: string | ((bundleId: string) => string),
  parentDir: string,
): Promise<Result<WrittenBundle, BeaError>> => {
  const staging = join(parentDir, `.bea-dump.staging-${randomBytes(6).toString("hex")}`);
  const cache = new Map<CapturedRegion, Promise<Result<Uint8Array, BeaError>>>();
  const load = (src: CapturedRegion) => {
    let pending = cache.get(src);
    if (pending === undefined) {
      pending = src.load();
      cache.set(src, pending);
    }
    return pending;
  };
  try {
    await mkdir(join(staging, DUMP_REGIONS_DIR), { recursive: true });
    const manifestRegions: DumpManifestRegion[] = [];
    const written = new Set<string>();
    let bytes = 0;
    for (const region of regions) {
      const composed = await composeRegion(region, load);
      if (!composed.ok) return composed;
      const sha256 = sha256Hex(composed.value);
      if (!written.has(sha256)) {
        await writeFile(join(staging, DUMP_REGIONS_DIR, `${sha256}.bin`), composed.value, { flag: "wx" });
        written.add(sha256);
        bytes += composed.value.length;
      }
      manifestRegions.push({
        base: formatHex(region.base),
        size: region.size,
        protection: region.protection,
        tag: region.tag,
        module: region.module,
        sha256,
        complete: region.unreadable.length === 0,
        unreadable_pages: region.unreadable.map((p) => formatHex(p)),
      });
    }
    cache.clear();
    const withoutId = { ...draft, regions: manifestRegions };
    const bundleId = bundleIdOf(withoutId);
    const manifest = { ...withoutId, bundle_id: bundleId };
    const parsed = dumpManifestSchema.safeParse(manifest);
    if (!parsed.success) return err(internalError(operation, parsed.error));
    const text = canonicalJson(manifest as unknown as JsonValue);
    await writeFile(join(staging, DUMP_MANIFEST_FILE), text, { encoding: "utf8", flag: "wx" });
    const path = typeof target === "string" ? target : target(bundleId);
    const published = await publishDirectory(operation, staging, path);
    if (!published.ok) return published;
    return ok({
      path,
      bundleId,
      manifest: parsed.data,
      bytes: bytes + Buffer.byteLength(text),
      manifestSha256: sha256Hex(text),
    });
  } catch (cause) {
    return err(writeError(operation, staging, cause));
  } finally {
    if (!(await pathIsFree(staging))) await rm(staging, { recursive: true, force: true }).catch(() => undefined);
  }
};
