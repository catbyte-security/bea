import { canonicalDigest } from "../../domain/canonical.js";
import type { RunId, StId } from "../../domain/ids.js";
import type { JsonValue } from "../../domain/json.js";
import type { LedgerLine } from "./LedgerLines.js";
import type { BundleManifest } from "../../application/evidence/storeSchemas.js";

/** `bea.bundle/1` (S2 §13.1): canonical record order and the values import recomputes from the records. */
export { bundleManifestSchema, type BundleManifest } from "../../application/evidence/storeSchemas.js";

/** sha256(canonical(manifest − bundle_digest − created_wall)) */
export const bundleDigestOf = (m: Omit<BundleManifest, "bundle_digest"> | BundleManifest): string => {
  const { bundle_digest: _d, created_wall: _w, ...rest } = m as BundleManifest;
  return canonicalDigest(rest as unknown as JsonValue);
};

const pad = (n: number, width: number): string => String(n).padStart(width, "0");

/** Canonical order of records.jsonl (S2 §13.1): kind rank, then id / (effect, run, seq) / (unknown, revision). */
export const orderKey = (line: LedgerLine): string | null => {
  switch (line.t) {
    case "pi":
      return `0|${line.instance_id}`;
    case "mm":
      return `1|${line.module_map.module_map_id}`;
    case "fx":
      return `2|${line.effect.effect_id}`;
    case "fxt":
      return `3|${line.transition.effect_id}|${line.transition.at.run_id}|${pad(line.transition.at.seq, 16)}`;
    case "unk":
      return `4|${line.revision.unknown_id}|${pad(line.revision.revision, 6)}`;
    case "ev":
      return `5|${line.record.evidence_id}`;
    default:
      return null;
  }
};

export interface Derived {
  readonly counts: BundleManifest["counts"];
  readonly blobs: { sha256: string; bytes: number }[];
  readonly streams: StId[];
  readonly sourceRuns: RunId[];
  /** blob references whose declared sizes disagree */
  readonly blobConflicts: string[];
}

const STREAM_ID_RE = /^st_[a-f0-9]{64}$/u;

/** Recompute what the manifest declares from the records alone (REA derived-equality rule). */
export const deriveFromLines = (lines: readonly LedgerLine[]): Derived => {
  const counts = { instances: 0, module_maps: 0, effects: 0, effect_transitions: 0, unknown_revisions: 0, evidence: 0 };
  const blobs = new Map<string, number>();
  const conflicts: string[] = [];
  const streams = new Set<StId>();
  const runs = new Set<RunId>();
  const blob = (sha: string | null, bytes: number): void => {
    if (sha === null) return;
    const known = blobs.get(sha);
    if (known !== undefined && known !== bytes) conflicts.push(sha);
    blobs.set(sha, bytes);
  };
  for (const line of lines)
    switch (line.t) {
      case "pi":
        counts.instances += 1;
        break;
      case "mm":
        counts.module_maps += 1;
        break;
      case "fx":
        counts.effects += 1;
        runs.add(line.effect.applied_at.run_id as RunId);
        blob(line.effect.before?.blob ?? null, line.effect.before?.bytes ?? 0);
        blob(line.effect.after?.blob ?? null, line.effect.after?.bytes ?? 0);
        for (const id of line.effect.stream_ids) streams.add(id as StId);
        break;
      case "fxt":
        counts.effect_transitions += 1;
        runs.add(line.transition.at.run_id as RunId);
        break;
      case "unk":
        counts.unknown_revisions += 1;
        break;
      case "ev": {
        counts.evidence += 1;
        if (line.record.observed_at !== null) runs.add(line.record.observed_at.run_id as RunId);
        for (const b of line.record.blobs) blob(b.sha256, b.bytes);
        const result = line.record.result;
        if (
          line.record.predicate_type === "bea.stream.manifest" &&
          typeof result === "object" &&
          result !== null &&
          !Array.isArray(result)
        ) {
          const id = (result as { readonly [k: string]: JsonValue })["stream_id"];
          if (typeof id === "string" && STREAM_ID_RE.test(id)) streams.add(id as StId);
        }
        break;
      }
      default:
        break;
    }
  return {
    counts,
    blobs: [...blobs.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([sha256, bytes]) => ({ sha256, bytes })),
    streams: [...streams].sort(),
    sourceRuns: [...runs].sort(),
    blobConflicts: conflicts,
  };
};
