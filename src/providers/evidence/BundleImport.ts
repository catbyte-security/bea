import { createHash } from "node:crypto";
import { readFileSync, statfsSync } from "node:fs";
import { copyFile, cp, lstat, mkdir, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { sha256Hex } from "../../domain/canonical.js";
import type { BeaError, BeaErrorOf } from "../../domain/errors/beaError.js";
import { cancelled } from "../../domain/errors/constructors.js";
import type { FxId, RunId, StId, UnkId } from "../../domain/ids.js";
import type { JsonObject } from "../../domain/json.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { BundleDeps } from "./Bundle.js";
import { BUNDLE_ENTRY_RE, extractZip, ZipGuardError, type ZipExtractPolicy } from "./BundleZip.js";
import {
  bundleDigestOf,
  bundleManifestSchema,
  deriveFromLines,
  orderKey,
  type BundleManifest,
} from "./bundleFormat.js";
import { fileError, ioError, quotaError } from "./errors.js";
import { pathExists, randomHex } from "./fsio.js";
import type { LineRef, Origin } from "./LedgerIndex.js";
import { decodeLine, encodeLine, isCanonicalLine, type ImportCounts, type LedgerLine } from "./LedgerLines.js";
import { mibOf } from "./Quotas.js";
import { indexLine } from "./reloadRun.js";
import type { StreamDescriptor } from "./StreamStore.js";
import { CHUNKS_ABSENT_MARKER, nextChain, parseForeignChainLine, type ChainLine } from "./streamFrames.js";

/** Import (S2 §13.4): validate EVERYTHING, then merge inside an import-begin … import-commit bracket. */
const OPERATION = "import_evidence";
const MANIFEST_MAX_BYTES = 4 * 1024 * 1024;

type Integrity = BeaErrorOf<"EvidenceIntegrity">;
const integrity = (reason: Integrity["reason"], what: string, ids: readonly string[] = []): Integrity => ({
  _tag: "EvidenceIntegrity",
  operation: OPERATION,
  reason,
  diagnostics: { what, ...(ids.length > 0 ? { ids: ids.slice(0, 10) } : {}) },
});

interface BundleLine {
  readonly text: string;
  readonly line: LedgerLine;
  readonly sha256: string;
}

interface Validated {
  readonly manifest: BundleManifest;
  readonly lines: readonly BundleLine[];
  readonly fresh: readonly BundleLine[];
  readonly duplicates: number;
  readonly root: string;
}

/** Every file of a bundle directory must belong to the layout grammar; symlinks are refused. */
const walk = async (root: string, rel = ""): Promise<string[]> => {
  const out: string[] = [];
  for (const entry of await readdir(join(root, rel), { withFileTypes: true })) {
    const name = rel === "" ? entry.name : `${rel}/${entry.name}`;
    const info = await lstat(join(root, name));
    if (info.isSymbolicLink()) throw new ZipGuardError("symbolic link in bundle", name);
    if (info.isDirectory()) out.push(...(await walk(root, name)));
    else if (!BUNDLE_ENTRY_RE.test(name)) throw new ZipGuardError("file outside the bundle layout", name);
    else out.push(name);
  }
  return out;
};

const readManifest = async (root: string): Promise<Result<BundleManifest, BeaError>> => {
  const path = join(root, "bundle.json");
  if (!(await pathExists(path))) return err(fileError(OPERATION, "read", path, undefined, "missing"));
  if ((await stat(path)).size > MANIFEST_MAX_BYTES) return err(integrity("schema", "bundle.json too large"));
  let raw: unknown;
  try {
    raw = JSON.parse(await readFile(path, "utf8"));
  } catch {
    return err(integrity("schema", "bundle.json is not JSON"));
  }
  const parsed = bundleManifestSchema.safeParse(raw);
  if (!parsed.success) return err(integrity("schema", "bundle.json does not match bea.bundle/1"));
  if (bundleDigestOf(parsed.data) !== parsed.data.bundle_digest) return err(integrity("id-mismatch", "bundle digest"));
  return ok(parsed.data);
};

const readRecords = async (root: string, m: BundleManifest): Promise<Result<BundleLine[], BeaError>> => {
  const buffer = await readFile(join(root, "records.jsonl"));
  if (buffer.length !== m.records.bytes || sha256Hex(buffer) !== m.records.sha256)
    return err(integrity("id-mismatch", "records.jsonl digest"));
  const texts = buffer.toString("utf8").split("\n");
  if (texts.at(-1) !== "") return err(integrity("non-canonical", "records.jsonl must end with a newline"));
  texts.pop();
  if (texts.length !== m.records.lines) return err(integrity("schema", "records.jsonl line count"));
  const lines: BundleLine[] = [];
  let previous = "";
  for (const text of texts) {
    if (!isCanonicalLine(text)) return err(integrity("non-canonical", "records.jsonl line"));
    const decoded = decodeLine(text, OPERATION);
    if (!decoded.ok) return decoded;
    const key = orderKey(decoded.value);
    if (key === null) return err(integrity("schema", `line kind ${decoded.value.t} is not allowed in a bundle`));
    if (key <= previous) return err(integrity("schema", "records.jsonl order or uniqueness"));
    previous = key;
    lines.push({ text, line: decoded.value, sha256: sha256Hex(text) });
  }
  return ok(lines);
};

const checkBlobs = async (
  root: string,
  m: BundleManifest,
  files: readonly string[],
  signal?: AbortSignal,
): Promise<Result<void, BeaError>> => {
  const present = new Set(files.filter((f) => f.startsWith("blobs/")).map((f) => f.slice(6)));
  const listed = new Set(m.blobs.map((b) => b.sha256));
  for (const sha of present)
    if (!listed.has(sha) || !m.blobs_included) return err(integrity("schema", "unlisted blob file", [sha]));
  if (!m.blobs_included) return ok(undefined);
  for (const blob of m.blobs) {
    if (signal?.aborted === true) return err(cancelled(OPERATION, "signal"));
    if (!present.has(blob.sha256)) return err(integrity("dangling-link", "listed blob missing", [blob.sha256]));
    const bytes = await readFile(join(root, "blobs", blob.sha256));
    if (bytes.length !== blob.bytes || sha256Hex(bytes) !== blob.sha256)
      return err(integrity("id-mismatch", "blob digest", [blob.sha256]));
  }
  return ok(undefined);
};

const checkStreams = async (
  root: string,
  m: BundleManifest,
  files: readonly string[],
  signal?: AbortSignal,
): Promise<Result<void, BeaError>> => {
  const dirs = new Set(files.filter((f) => f.startsWith("streams/")).map((f) => f.split("/")[1] ?? ""));
  const listed = new Set(m.streams.map((s) => s.stream_id as string));
  for (const dir of dirs) if (!listed.has(dir)) return err(integrity("schema", "unlisted stream directory", [dir]));
  for (const s of m.streams) {
    if (signal?.aborted === true) return err(cancelled(OPERATION, "signal"));
    const dir = join(root, "streams", s.stream_id);
    let descriptor: Buffer;
    let chainText: string;
    try {
      descriptor = await readFile(join(dir, "descriptor.json"));
      chainText = await readFile(join(dir, "chain.jsonl"), "utf8");
    } catch {
      return err(integrity("dangling-link", "stream files missing", [s.stream_id]));
    }
    if (sha256Hex(descriptor) !== s.descriptor_sha256)
      return err(integrity("id-mismatch", "stream descriptor", [s.stream_id]));
    // DATA-4: every chain line is schema-checked (its `file` is later used as a path), whatever `included` says
    const chain: ChainLine[] = [];
    for (const text of chainText.split("\n").filter((l) => l.length > 0)) {
      const line = parseForeignChainLine(text, chain.length);
      if (line === null) return err(integrity("schema", "stream chain line", [s.stream_id]));
      chain.push(line);
    }
    let head = s.descriptor_sha256;
    const chunkFiles = new Set(
      files.filter((f) => f.startsWith(`streams/${s.stream_id}/chunk-`)).map((f) => f.split("/")[2] ?? ""),
    );
    for (const c of chain) {
      head = nextChain(head, c.sha256);
      if (head !== c.chain) return err(integrity("id-mismatch", "stream chain", [s.stream_id]));
      if (s.included === "all") {
        if (!chunkFiles.has(c.file)) return err(integrity("dangling-link", "stream chunk missing", [s.stream_id]));
        const bytes = await readFile(join(dir, c.file));
        if (bytes.length !== c.bytes || sha256Hex(bytes) !== c.sha256)
          return err(integrity("id-mismatch", "stream chunk", [s.stream_id]));
        chunkFiles.delete(c.file);
      }
    }
    if (chunkFiles.size > 0) return err(integrity("schema", "unlisted stream chunk", [s.stream_id]));
    if (head !== s.head_chain || chain.length !== s.chunks || chain.reduce((a, c) => a + c.bytes, 0) !== s.bytes)
      return err(integrity("id-mismatch", "stream head chain", [s.stream_id]));
  }
  return ok(undefined);
};

const sameList = (a: readonly unknown[], b: readonly unknown[]): boolean => JSON.stringify(a) === JSON.stringify(b);

/** Derived equality (counts, blobs, streams, source runs) + references inside the bundle ∪ this ledger. */
const checkDerived = (deps: BundleDeps, m: BundleManifest, lines: readonly BundleLine[]): Result<void, BeaError> => {
  const derived = deriveFromLines(lines.map((l) => l.line));
  if (derived.blobConflicts.length > 0)
    return err(integrity("conflicting-record", "blob size disagreement", derived.blobConflicts));
  if (!sameList(Object.entries(derived.counts).sort(), Object.entries(m.counts).sort()))
    return err(integrity("schema", "manifest counts"));
  if (!sameList(derived.blobs, m.blobs)) return err(integrity("schema", "manifest blob list"));
  if (
    !sameList(
      derived.streams,
      m.streams.map((s) => s.stream_id),
    )
  )
    return err(integrity("schema", "manifest stream list"));
  if (derived.sourceRuns.length > 0 ? !sameList(derived.sourceRuns, m.source_runs) : m.source_runs.length !== 1)
    return err(integrity("schema", "manifest source runs"));
  const index = deps.index;
  const ev = new Set<string>(index.byId.keys());
  const pi = new Set<string>(index.instances.keys());
  const mm = new Set<string>(index.moduleMaps.keys());
  const fx = new Set<string>(index.effects.keys());
  for (const { line } of lines) {
    if (line.t === "ev") ev.add(line.record.evidence_id);
    if (line.t === "pi") pi.add(line.instance_id);
    if (line.t === "mm") mm.add(line.module_map.module_map_id);
    if (line.t === "fx") fx.add(line.effect.effect_id);
  }
  const dangling: string[] = [];
  const need = (set: Set<string>, id: string | null | undefined): void => {
    if (id !== null && id !== undefined && !set.has(id)) dangling.push(id);
  };
  const revisions = new Map<string, { revision: number; digest: string; previous: string | null }[]>();
  for (const { line } of lines)
    switch (line.t) {
      case "mm":
        need(pi, line.module_map.instance_id);
        break;
      case "fx":
        need(pi, line.effect.instance_id);
        need(mm, line.effect.target.address?.module_map_id);
        break;
      case "fxt":
        need(fx, line.transition.effect_id);
        break;
      case "ev": {
        const r = line.record;
        for (const link of r.evidence_links) need(ev, link);
        if (r.subject?.kind === "process-instance") need(pi, r.subject.instance_id);
        if (r.subject !== null && r.subject.kind !== "image") need(mm, r.subject.module_map_id);
        for (const l of r.locations) if (l.kind === "address") need(mm, l.module_map_id);
        for (const f of [...r.effects, ...r.perturbation.active_effect_ids, ...r.perturbation.tainted_by]) need(fx, f);
        break;
      }
      case "unk": {
        const u = line.revision;
        for (const id of [...u.supporting_evidence_ids, ...u.contradicting_evidence_ids, ...u.mutation_evidence_ids])
          need(ev, id);
        const list = revisions.get(u.unknown_id) ?? [];
        list.push({ revision: u.revision, digest: u.revision_digest, previous: u.previous_revision_digest });
        revisions.set(u.unknown_id, list);
        break;
      }
      default:
        break;
    }
  if (dangling.length > 0) return err(integrity("dangling-link", "unresolved reference", dangling));
  for (const [id, list] of revisions)
    for (let i = 0; i < list.length; i++) {
      const cur = list[i];
      const prev = list[i - 1];
      if (cur === undefined || cur.revision !== i + 1 || cur.previous !== (prev?.digest ?? null))
        return err(integrity("schema", "unknown revision chain is not gap-free and digest-linked", [id]));
    }
  return ok(undefined);
};

/** Conflicts with this run's ledger: same id + different bytes rejects the whole import. */
const classify = (
  deps: BundleDeps,
  lines: readonly BundleLine[],
): Result<{ fresh: BundleLine[]; duplicates: number }, BeaError> => {
  const index = deps.index;
  const fresh: BundleLine[] = [];
  let duplicates = 0;
  const conflicts: string[] = [];
  const fxtKey = (effect: string, run: string, seq: number): string => `${effect}|${run}|${String(seq)}`;
  const knownFxt = new Map<string, string>();
  for (const entry of index.effects.values())
    for (const t of entry.transitions)
      knownFxt.set(fxtKey(t.transition.effect_id, t.transition.at.run_id, t.transition.at.seq), t.ref.sha256);
  for (const item of lines) {
    const line = item.line;
    let existing: LineRef | undefined;
    let id = "";
    switch (line.t) {
      case "pi":
        existing = index.instances.get(line.instance_id)?.ref;
        id = line.instance_id;
        break;
      case "mm":
        existing = index.moduleMaps.get(line.module_map.module_map_id)?.ref;
        id = line.module_map.module_map_id;
        break;
      case "fx":
        existing = index.effects.get(line.effect.effect_id)?.ref;
        id = line.effect.effect_id;
        break;
      case "ev":
        existing = index.byId.get(line.record.evidence_id)?.ref;
        id = line.record.evidence_id;
        break;
      case "fxt": {
        const sha = knownFxt.get(fxtKey(line.transition.effect_id, line.transition.at.run_id, line.transition.at.seq));
        id = line.transition.effect_id;
        if (sha !== undefined) existing = { offset: 0, length: 0, sha256: sha };
        else if (index.effects.get(line.transition.effect_id as FxId)?.origin.kind === "local")
          return err(
            integrity("conflicting-record", "an imported transition would change a live effect of this run", [id]),
          );
        break;
      }
      case "unk": {
        const head = index.unknowns
          .get(line.revision.unknown_id)
          ?.revisions.find((r) => r.revision.revision === line.revision.revision);
        if (head !== undefined && head.revision.revision_digest !== line.revision.revision_digest)
          return err({
            _tag: "RevisionConflict",
            operation: OPERATION,
            unknown_id: line.revision.unknown_id,
            expected_revision: line.revision.revision,
            actual_revision: index.unknownHead(line.revision.unknown_id as UnkId)?.revision ?? 0,
          });
        if (head !== undefined) existing = head.ref;
        id = line.revision.unknown_id;
        break;
      }
      default:
        break;
    }
    if (existing === undefined) fresh.push(item);
    else if (existing.sha256 === item.sha256) duplicates += 1;
    else conflicts.push(id);
  }
  if (conflicts.length > 0) return err(integrity("conflicting-record", "same id with different content", conflicts));
  return ok({ fresh, duplicates });
};

const validate = async (deps: BundleDeps, root: string, signal?: AbortSignal): Promise<Result<Validated, BeaError>> => {
  const files = await walk(root);
  const manifest = await readManifest(root);
  if (!manifest.ok) return manifest;
  const m = manifest.value;
  const lines = await readRecords(root, m);
  if (!lines.ok) return lines;
  const blobs = await checkBlobs(root, m, files, signal);
  if (!blobs.ok) return blobs;
  const streams = await checkStreams(root, m, files, signal);
  if (!streams.ok) return streams;
  const derived = checkDerived(deps, m, lines.value);
  if (!derived.ok) return derived;
  const classified = classify(deps, lines.value);
  if (!classified.ok) return classified;
  const remaining = deps.quotas.remaining();
  const ledgerBytes = classified.value.fresh.reduce((sum, l) => sum + l.text.length + 1, 0) + 1024;
  if (ledgerBytes > remaining.ledger)
    return err(quotaError(OPERATION, "ledger", mibOf(deps.quotas.limits.ledgerBytes)));
  const blobBytes = m.blobs_included
    ? m.blobs.filter((b) => !deps.index.blobs.has(b.sha256)).reduce((s, b) => s + b.bytes, 0)
    : 0;
  if (blobBytes > remaining.blobs) return err(quotaError(OPERATION, "blobs", mibOf(deps.quotas.limits.blobBytes)));
  const streamBytes = m.streams
    .filter((s) => s.included === "all" && !deps.index.streams.has(s.stream_id))
    .reduce((a, s) => a + s.bytes, 0);
  if (streamBytes > remaining.streams)
    return err(quotaError(OPERATION, "streams", mibOf(deps.quotas.limits.streamTotalBytes)));
  return ok({
    manifest: m,
    lines: lines.value,
    fresh: classified.value.fresh,
    duplicates: classified.value.duplicates,
    root,
  });
};

const merge = async (deps: BundleDeps, v: Validated): Promise<Result<number, BeaError>> => {
  const m = v.manifest;
  const origin: Origin = { kind: "import", bundle_digest: m.bundle_digest };
  if (m.blobs_included)
    for (const blob of m.blobs) {
      if (deps.index.blobs.has(blob.sha256)) continue;
      try {
        await copyFile(join(v.root, "blobs", blob.sha256), deps.blobs.pathOf(blob.sha256));
      } catch (cause) {
        if ((cause as { code?: string }).code !== "EEXIST")
          return err(ioError(OPERATION, "write", deps.blobs.pathOf(blob.sha256), cause));
      }
      if (deps.quotas.reserveBlob(blob.bytes)) await deps.blobs.adopt(blob.sha256);
    }
  // DATA-5: only streams whose chunks were copied count against the run's stream quota (run-wide only: the per-stream
  // cap is a live writer's), reserved once before anything is copied
  const fresh = m.streams.filter((s) => !deps.index.streams.has(s.stream_id));
  const chunkBytes = fresh.filter((s) => s.included === "all").reduce((sum, s) => sum + s.bytes, 0);
  if (!deps.quotas.reserveImportedStreams(chunkBytes))
    return err(quotaError(OPERATION, "streams", mibOf(deps.quotas.limits.streamTotalBytes)));
  for (const s of fresh) {
    const target = deps.streams.dirOf(s.stream_id);
    await mkdir(target, { recursive: true });
    await cp(join(v.root, "streams", s.stream_id), target, { recursive: true, force: false, errorOnExist: false });
    // DATA-4: a stream without its chunks is marked, so verify/export never look for files that never came
    if (s.included === "manifests-only")
      await writeFile(
        join(target, CHUNKS_ABSENT_MARKER),
        `${JSON.stringify({ included: "manifests-only", bundle_digest: m.bundle_digest })}\n`,
      );
    const descriptor = JSON.parse(readFileSync(join(target, "descriptor.json"), "utf8")) as StreamDescriptor;
    deps.streams.adopt(s.stream_id as StId, s.descriptor_sha256, descriptor, origin);
  }
  const import_id = `imp_${randomHex()}`;
  const begin = await deps.ledger.append(
    { t: "import-begin", import_id, bundle_digest: m.bundle_digest, source_runs: m.source_runs as RunId[] },
    { operation: OPERATION },
  );
  if (!begin.ok) return begin;
  const appended: { line: LedgerLine; ref: LineRef }[] = [];
  const counts: { -readonly [K in keyof ImportCounts]: number } = {
    instances: 0,
    module_maps: 0,
    effects: 0,
    effect_transitions: 0,
    unknown_revisions: 0,
    evidence: 0,
  };
  for (const item of v.fresh) {
    if (createHash("sha256").update(encodeLine(item.line).slice(0, -1)).digest("hex") !== item.sha256)
      return err(integrity("non-canonical", "line does not re-encode identically"));
    const ref = await deps.ledger.append(item.line, { operation: OPERATION });
    if (!ref.ok) return ref;
    appended.push({ line: item.line, ref: ref.value });
    const key = (
      {
        pi: "instances",
        mm: "module_maps",
        fx: "effects",
        fxt: "effect_transitions",
        unk: "unknown_revisions",
        ev: "evidence",
      } as const
    )[item.line.t as "pi" | "mm" | "fx" | "fxt" | "unk" | "ev"];
    counts[key] += 1;
  }
  const commit = await deps.ledger.append({ t: "import-commit", import_id, counts }, { operation: OPERATION });
  if (!commit.ok) return commit;
  await deps.ledger.sync();
  // the index learns the lines only after the commit is on disk (an uncommitted bracket is ignored on reload)
  for (const { line, ref } of appended) indexLine(deps.index, line, ref, origin);
  return ok(appended.length);
};

const DESCRIPTOR_MAX_BYTES = 64 * 1024;
/** a chain.jsonl line ({index, file, bytes, sha256, chain}) is ~200 bytes */
const CHAIN_LINE_MAX_BYTES = 512;
/** free space the extraction must leave on the volume */
const DISK_RESERVE_BYTES = 256 * 1024 * 1024;

const freeBytes = (dir: string): number => {
  try {
    const fs = statfsSync(dir);
    return Number(fs.bavail) * Number(fs.bsize);
  } catch {
    return Number.MAX_SAFE_INTEGER;
  }
};

/**
 * Review fix SEC-5: what a zip may extract, from its schema-valid bundle.json (read once, after it alone was
 * extracted): only entries the manifest references, each within its declared size (descriptor and chain files within
 * tight bounds, a stream's chunks cumulatively within the stream's bytes, chunks only for `included:"all"` streams,
 * blobs only when `blobs_included`), and all of it within the run's remaining quotas and the free disk space.
 */
const extractionPolicy = (deps: BundleDeps, dest: string): ZipExtractPolicy => {
  let declared: BundleManifest | null | undefined;
  const manifest = (): BundleManifest | null => {
    if (declared === undefined)
      try {
        const parsed = bundleManifestSchema.safeParse(JSON.parse(readFileSync(join(dest, "bundle.json"), "utf8")));
        declared = parsed.success ? parsed.data : null;
      } catch {
        declared = null;
      }
    return declared;
  };
  const chunkBytes = new Map<string, number>();
  const sideFiles = new Set<string>();
  return {
    manifestMaxBytes: MANIFEST_MAX_BYTES,
    limit: (name, size) => {
      const m = manifest();
      if (m === null) return 0;
      if (name === "records.jsonl") return m.records.bytes;
      if (name.startsWith("blobs/"))
        return m.blobs_included ? (m.blobs.find((b) => `blobs/${b.sha256}` === name)?.bytes ?? 0) : 0;
      const [, streamId = "", file = ""] = name.split("/");
      const stream = m.streams.find((s) => s.stream_id === streamId);
      if (stream === undefined) return 0;
      if (file === "descriptor.json" || file === "chain.jsonl") {
        if (sideFiles.has(name)) return 0;
        sideFiles.add(name);
        return file === "descriptor.json" ? DESCRIPTOR_MAX_BYTES : (stream.chunks + 1) * CHAIN_LINE_MAX_BYTES;
      }
      const index = Number(/^chunk-(\d{6})\.bin$/u.exec(file)?.[1] ?? Number.NaN);
      if (stream.included !== "all" || !(index < stream.chunks)) return 0;
      const used = chunkBytes.get(streamId) ?? 0;
      chunkBytes.set(streamId, used + size);
      return Math.max(0, stream.bytes - used);
    },
    total: () => {
      const remaining = deps.quotas.remaining();
      const quota = Math.max(0, remaining.ledger) + Math.max(0, remaining.blobs) + Math.max(0, remaining.streams);
      const sideAllowance = (manifest()?.streams.length ?? 0) * (DESCRIPTOR_MAX_BYTES + 64 * 1024);
      return Math.min(quota + sideAllowance, freeBytes(dest) - DISK_RESERVE_BYTES);
    },
  };
};

export const importBundle = async (
  deps: BundleDeps,
  req: { readonly path: string; readonly validate_only: boolean },
  signal?: AbortSignal,
): Promise<Result<JsonObject, BeaError>> => {
  let info;
  try {
    info = await stat(req.path);
  } catch (cause) {
    return err(fileError(OPERATION, "read", req.path, cause));
  }
  const started = await deps.ensureStarted();
  if (!started.ok) return started;
  let root = req.path;
  let extracted: string | null = null;
  try {
    if (!info.isDirectory()) {
      extracted = join(deps.tmpDir, `import-${randomHex()}`);
      await mkdir(extracted);
      const dest = extracted;
      try {
        await extractZip(req.path, dest, extractionPolicy(deps, dest), signal);
      } catch (cause) {
        if (cause instanceof ZipGuardError) throw cause;
        if ((cause as { code?: string }).code === "ENOSPC") throw cause;
        return err(integrity("schema", "zip archive rejected"));
      }
      root = dest;
    }
    const validated = await validate(deps, root, signal);
    if (!validated.ok) return validated;
    const v = validated.value;
    if (req.validate_only)
      return ok({
        bundle_digest: v.manifest.bundle_digest,
        records: v.lines.length,
        added: 0,
        duplicates: v.duplicates,
        valid: true,
      });
    const merged = await merge(deps, v);
    if (!merged.ok) return merged;
    return ok({
      bundle_digest: v.manifest.bundle_digest,
      records: v.lines.length,
      added: merged.value,
      duplicates: v.duplicates,
      valid: true,
    });
  } catch (cause) {
    if (cause instanceof ZipGuardError) return err(integrity("schema", cause.what, [cause.entry]));
    return err(ioError(OPERATION, "read", req.path, cause));
  } finally {
    if (extracted !== null) await rm(extracted, { recursive: true, force: true }).catch(() => undefined);
  }
};
