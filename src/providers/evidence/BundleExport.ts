import { createHash } from "node:crypto";
import { copyFile, link, mkdir, rm, stat, unlink, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { canonicalJson } from "../../domain/canonical.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { cancelled } from "../../domain/errors/constructors.js";
import type { EvId, FxId, MmId, PiId, RunId, StId, UnkId } from "../../domain/ids.js";
import type { JsonObject, JsonValue } from "../../domain/json.js";
import { err, ok, type Result } from "../../domain/result.js";
import { writeZip } from "./BundleZip.js";
import type { BundleDeps } from "./Bundle.js";
import { bundleDigestOf, type BundleManifest } from "./bundleFormat.js";
import { fileError, ioError } from "./errors.js";
import { fsyncDir, fsyncPath, pathExists, randomHex, renameWithRetry } from "./fsio.js";
import type { LineRef } from "./LedgerIndex.js";
import { decodeLine } from "./LedgerLines.js";
import { readChainLines } from "./StreamStore.js";
import type { ChainLine } from "./streamFrames.js";

/** Export (S2 §13.2–13.3): snapshot → closure → re-authenticate → stage → fsync → publish (never overwrites). */
export interface ExportRequest {
  readonly instance_id: PiId | null;
  readonly out_path: string;
  readonly format: "directory" | "zip";
  readonly streams: "manifests" | "all";
  readonly blobs: boolean;
  /** create missing parents (only for paths under this run's exports directory) */
  readonly create_parent: boolean;
}

interface Selection {
  readonly ev: Set<EvId>;
  readonly pi: Set<PiId>;
  readonly mm: Set<MmId>;
  readonly fx: Set<FxId>;
  readonly unk: Set<UnkId>;
  readonly blobs: Map<string, number>;
  readonly streams: Set<StId>;
}

const OPERATION = "export_evidence";

/** Transitive closure over links, subjects, maps, effects, unknowns, blobs and streams (S2 §13.2). */
const closure = (deps: BundleDeps, instance: PiId | null): Selection => {
  const index = deps.index;
  const s: Selection = {
    ev: new Set(),
    pi: new Set(),
    mm: new Set(),
    fx: new Set(),
    unk: new Set(),
    blobs: new Map(),
    streams: new Set(),
  };
  const evQueue: EvId[] = [];
  const addEv = (id: EvId): void => {
    if (!s.ev.has(id) && index.byId.has(id)) {
      s.ev.add(id);
      evQueue.push(id);
    }
  };
  const addFx = (id: FxId): void => {
    const entry = index.effects.get(id);
    if (entry === undefined || s.fx.has(id)) return;
    s.fx.add(id);
    s.pi.add(entry.effect.instance_id);
    const mm = entry.effect.target.address?.module_map_id ?? null;
    if (mm !== null) s.mm.add(mm);
    for (const st of entry.effect.stream_ids) s.streams.add(st as StId);
    for (const bytes of [entry.effect.before, entry.effect.after])
      if (bytes?.blob != null) s.blobs.set(bytes.blob, bytes.bytes);
  };
  if (instance === null) {
    for (const row of index.rows) addEv(row.evidence_id);
    for (const id of index.effects.keys()) addFx(id);
    for (const id of index.instances.keys()) s.pi.add(id);
    for (const id of index.moduleMaps.keys()) s.mm.add(id);
    for (const id of index.unknowns.keys()) s.unk.add(id);
  } else {
    s.pi.add(instance);
    for (const row of index.byInstance.get(instance) ?? []) addEv(row.evidence_id);
    for (const [id, entry] of index.effects) if (entry.effect.instance_id === instance) addFx(id);
  }
  for (;;) {
    for (let id = evQueue.shift(); id !== undefined; id = evQueue.shift()) {
      const row = index.byId.get(id);
      if (row === undefined) continue;
      for (const link of row.links) addEv(link);
      if (row.instance_id !== null) s.pi.add(row.instance_id);
      for (const mm of row.module_map_ids) s.mm.add(mm);
      for (const fx of [...row.applied_effects, ...row.perturbation.active_effect_ids, ...row.perturbation.tainted_by])
        addFx(fx);
      for (const blob of row.blobs) s.blobs.set(blob.sha256, blob.bytes);
      if (row.stream_id !== null && row.predicate_type === "bea.stream.manifest") s.streams.add(row.stream_id);
    }
    let grew = false;
    for (const [id, entry] of index.unknowns) {
      if (s.unk.has(id)) continue;
      const cited = entry.revisions.flatMap((r) => [
        ...r.revision.supporting_evidence_ids,
        ...r.revision.contradicting_evidence_ids,
        ...r.revision.mutation_evidence_ids,
      ]);
      if (instance !== null && !cited.some((ev) => s.ev.has(ev as EvId))) continue;
      s.unk.add(id);
      for (const ev of cited) addEv(ev as EvId);
      grew = true;
    }
    if (instance === null)
      for (const id of s.unk)
        for (const r of index.unknowns.get(id)?.revisions ?? [])
          for (const ev of [
            ...r.revision.supporting_evidence_ids,
            ...r.revision.contradicting_evidence_ids,
            ...r.revision.mutation_evidence_ids,
          ])
            addEv(ev as EvId);
    if (!grew && evQueue.length === 0) break;
  }
  for (const id of s.mm) {
    const entry = index.moduleMaps.get(id);
    if (entry !== undefined) s.pi.add(entry.module_map.instance_id);
  }
  return s;
};

interface PlannedLine {
  readonly key: string;
  readonly ref: LineRef;
}

const pad = (n: number, width: number): string => String(n).padStart(width, "0");

const plan = (deps: BundleDeps, s: Selection): PlannedLine[] => {
  const index = deps.index;
  const lines: PlannedLine[] = [];
  for (const id of s.pi) {
    const entry = index.instances.get(id);
    if (entry !== undefined) lines.push({ key: `0|${id}`, ref: entry.ref });
  }
  for (const id of s.mm) {
    const entry = index.moduleMaps.get(id);
    if (entry !== undefined) lines.push({ key: `1|${id}`, ref: entry.ref });
  }
  for (const id of s.fx) {
    const entry = index.effects.get(id);
    if (entry === undefined) continue;
    lines.push({ key: `2|${id}`, ref: entry.ref });
    for (const t of entry.transitions)
      lines.push({ key: `3|${id}|${t.transition.at.run_id}|${pad(t.transition.at.seq, 16)}`, ref: t.ref });
  }
  for (const id of s.unk)
    for (const r of index.unknowns.get(id)?.revisions ?? [])
      lines.push({ key: `4|${id}|${pad(r.revision.revision, 6)}`, ref: r.ref });
  for (const id of s.ev) {
    const row = index.byId.get(id);
    if (row !== undefined) lines.push({ key: `5|${id}`, ref: row.ref });
  }
  return lines.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
};

/** Write records.jsonl: every line re-read from the ledger, sha-checked against the index and re-authenticated. */
const writeRecords = async (
  deps: BundleDeps,
  lines: readonly PlannedLine[],
  target: string,
  signal: AbortSignal | undefined,
): Promise<Result<{ readonly sha256: string; readonly bytes: number; readonly runs: Set<RunId> }, BeaError>> => {
  const hash = createHash("sha256");
  const parts: string[] = [];
  const runs = new Set<RunId>();
  for (const planned of lines) {
    if (signal?.aborted === true) return err(cancelled(OPERATION, "signal"));
    const text = await deps.ledger.readAt(planned.ref.offset, planned.ref.length, OPERATION);
    if (!text.ok) return text;
    if (createHash("sha256").update(text.value).digest("hex") !== planned.ref.sha256)
      return err({
        _tag: "EvidenceIntegrity",
        operation: OPERATION,
        reason: "id-mismatch",
        diagnostics: { what: "ledger line changed on disk" },
      });
    const decoded = decodeLine(text.value, OPERATION);
    if (!decoded.ok) return decoded;
    const line = decoded.value;
    if (line.t === "ev" && line.record.observed_at !== null) runs.add(line.record.observed_at.run_id as RunId);
    if (line.t === "fx") runs.add(line.effect.applied_at.run_id as RunId);
    if (line.t === "fxt") runs.add(line.transition.at.run_id as RunId);
    parts.push(`${text.value}\n`);
    hash.update(`${text.value}\n`);
  }
  const body = parts.join("");
  await writeFile(target, body, { flag: "wx" });
  return ok({ sha256: hash.digest("hex"), bytes: Buffer.byteLength(body, "utf8"), runs });
};

const copyStreams = async (
  deps: BundleDeps,
  ids: readonly StId[],
  root: string,
  mode: "manifests" | "all",
  signal: AbortSignal | undefined,
): Promise<Result<BundleManifest["streams"], BeaError>> => {
  const out: BundleManifest["streams"] = [];
  for (const id of ids) {
    const entry = deps.index.streams.get(id);
    if (entry === undefined)
      return err({
        _tag: "EvidenceIntegrity",
        operation: OPERATION,
        reason: "dangling-link",
        diagnostics: { stream_id: id },
      });
    const reader = deps.streams.reader(id);
    if (!reader.ok) return reader;
    const verified = await reader.value.verify(signal);
    if (!verified.ok) return verified;
    const source = deps.streams.dirOf(id);
    const chain: ChainLine[] = (await readChainLines(source)).slice(0, verified.value.chunks);
    const dir = join(root, "streams", id);
    await mkdir(dir, { recursive: true });
    await copyFile(join(source, "descriptor.json"), join(dir, "descriptor.json"));
    await writeFile(
      join(dir, "chain.jsonl"),
      chain.map((c) => `${canonicalJson(c as unknown as JsonValue)}\n`).join(""),
      { flag: "wx" },
    );
    // DATA-4: a stream imported without its chunks is exported manifests-only whatever the mode
    const withChunks = mode === "all" && verified.value.included !== "manifests-only";
    if (withChunks) for (const c of chain) await copyFile(join(source, c.file), join(dir, c.file));
    out.push({
      stream_id: id,
      descriptor_sha256: entry.descriptor_sha256,
      head_chain: verified.value.head_chain,
      chunks: chain.length,
      bytes: chain.reduce((sum, c) => sum + c.bytes, 0),
      included: withChunks ? "all" : "manifests-only",
    });
  }
  return ok(out);
};

const listFiles = (
  root: string,
  records: boolean,
  blobs: readonly string[],
  streams: BundleManifest["streams"],
  chains: Map<StId, ChainLine[]>,
): Map<string, string> => {
  const files = new Map<string, string>([["bundle.json", join(root, "bundle.json")]]);
  if (records) files.set("records.jsonl", join(root, "records.jsonl"));
  for (const sha of blobs) files.set(`blobs/${sha}`, join(root, "blobs", sha));
  for (const s of streams) {
    files.set(`streams/${s.stream_id}/descriptor.json`, join(root, "streams", s.stream_id, "descriptor.json"));
    files.set(`streams/${s.stream_id}/chain.jsonl`, join(root, "streams", s.stream_id, "chain.jsonl"));
    if (s.included === "all")
      for (const c of chains.get(s.stream_id) ?? [])
        files.set(`streams/${s.stream_id}/${c.file}`, join(root, "streams", s.stream_id, c.file));
  }
  return files;
};

/** Publish without overwriting: hard link + unlink for files (EEXIST is atomic), checked rename for directories. */
const publish = async (staging: string, dest: string, isFile: boolean): Promise<void> => {
  if (isFile) {
    try {
      await link(staging, dest);
      await unlink(staging);
      return;
    } catch (cause) {
      if ((cause as { code?: string }).code === "EEXIST") throw cause;
    }
  }
  if (await pathExists(dest)) throw Object.assign(new Error("destination exists"), { code: "EEXIST" });
  await renameWithRetry(staging, dest);
};

export const exportBundle = async (
  deps: BundleDeps,
  req: ExportRequest,
  signal?: AbortSignal,
): Promise<Result<JsonObject, BeaError>> => {
  const started = await deps.ensureStarted();
  if (!started.ok) return started;
  if (req.create_parent) await mkdir(dirname(req.out_path), { recursive: true }).catch(() => undefined);
  if (await pathExists(req.out_path)) return err(fileError(OPERATION, "write", req.out_path, undefined, "exists"));
  if (!(await pathExists(dirname(req.out_path))))
    return err(fileError(OPERATION, "write", dirname(req.out_path), undefined, "missing"));
  for (const writer of deps.streams.live())
    if (
      writer.spec.source.instance_id !== null &&
      (req.instance_id === null || writer.spec.source.instance_id === req.instance_id)
    ) {
      const checkpoint = await writer.checkpoint(signal);
      if (!checkpoint.ok)
        deps.logger.warn("export: stream checkpoint failed", { stream: writer.stream_id, code: checkpoint.error._tag });
    }
  await deps.ledger.sync();
  const selection = closure(deps, req.instance_id);
  const lines = plan(deps, selection);
  const hex = randomHex();
  const root = req.format === "zip" ? join(deps.tmpDir, `export-${hex}`) : `${req.out_path}.bea-staging-${hex}`;
  const zipStaging = `${req.out_path}.bea-staging-${hex}`;
  try {
    await mkdir(root, { recursive: false });
    const records = await writeRecords(deps, lines, join(root, "records.jsonl"), signal);
    if (!records.ok) return records;
    const blobList = [...selection.blobs.entries()].sort(([a], [b]) => (a < b ? -1 : 1));
    if (req.blobs && blobList.length > 0) await mkdir(join(root, "blobs"));
    if (req.blobs)
      for (const [sha] of blobList) {
        const verified = await deps.blobs.verify(sha, signal);
        if (!verified.ok) return verified;
        await copyFile(deps.blobs.pathOf(sha), join(root, "blobs", sha));
      }
    const streamIds = [...selection.streams].sort();
    const streams = await copyStreams(deps, streamIds, root, req.streams, signal);
    if (!streams.ok) return streams;
    const chains = new Map<StId, ChainLine[]>();
    for (const id of streamIds) chains.set(id, await readChainLines(join(root, "streams", id)));
    const counts = {
      instances: 0,
      module_maps: 0,
      effects: 0,
      effect_transitions: 0,
      unknown_revisions: 0,
      evidence: 0,
    };
    for (const l of lines) {
      const rank = l.key[0];
      if (rank === "0") counts.instances += 1;
      else if (rank === "1") counts.module_maps += 1;
      else if (rank === "2") counts.effects += 1;
      else if (rank === "3") counts.effect_transitions += 1;
      else if (rank === "4") counts.unknown_revisions += 1;
      else counts.evidence += 1;
    }
    const body: Omit<BundleManifest, "bundle_digest"> = {
      schema: "bea.bundle/1",
      producer: { name: "bea", version: deps.beaVersion },
      created_wall: deps.clock.wallIso(),
      source_runs: records.value.runs.size > 0 ? [...records.value.runs].sort() : [deps.runId],
      selection: { kind: req.instance_id === null ? "run" : "instance", instance_id: req.instance_id, roots: [] },
      records: { path: "records.jsonl", sha256: records.value.sha256, bytes: records.value.bytes, lines: lines.length },
      counts,
      blobs_included: req.blobs,
      blobs: blobList.map(([sha256, bytes]) => ({ sha256, bytes })),
      streams: streams.value,
    };
    const manifest: BundleManifest = { ...body, bundle_digest: bundleDigestOf(body) };
    await writeFile(join(root, "bundle.json"), `${canonicalJson(manifest as unknown as JsonValue)}\n`, { flag: "wx" });
    const files = listFiles(root, true, req.blobs ? blobList.map(([sha]) => sha) : [], streams.value, chains);
    let bytes = 0;
    if (req.format === "zip") {
      await writeZip(files, zipStaging);
      await fsyncPath(zipStaging);
      bytes = (await stat(zipStaging)).size;
      await publish(zipStaging, req.out_path, true);
    } else {
      for (const path of files.values()) {
        await fsyncPath(path);
        bytes += (await stat(path)).size;
      }
      await publish(root, req.out_path, false);
    }
    await fsyncDir(dirname(req.out_path));
    return ok({
      path: req.out_path,
      bytes,
      bundle_digest: manifest.bundle_digest,
      records: lines.length,
      blobs: req.blobs ? blobList.length : 0,
      streams: streams.value.length,
    });
  } catch (cause) {
    const code = (cause as { code?: string }).code;
    return err(
      code === "EEXIST"
        ? fileError(OPERATION, "rename", req.out_path, cause, "exists")
        : ioError(OPERATION, "write", req.out_path, cause),
    );
  } finally {
    await rm(root, { recursive: true, force: true }).catch(() => undefined);
    if (req.format === "zip") await rm(zipStaging, { force: true }).catch(() => undefined);
  }
};
