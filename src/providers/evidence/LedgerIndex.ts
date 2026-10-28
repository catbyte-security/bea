import type { Effect, EffectState, EffectStatus, EffectTransition } from "../../domain/effects/effect.js";
import type { Coverage } from "../../domain/evidence/coverage.js";
import type { Authority, BeaEvidence, Confidence, Perturbation } from "../../domain/evidence/record.js";
import type { EvId, FxId, MmId, PiId, StId, UnkId } from "../../domain/ids.js";
import type { JsonValue } from "../../domain/json.js";
import type { ModuleMap, ProcessIdentity } from "../../domain/process/instance.js";
import type { ResidualUnknown } from "../../domain/unknowns/unknown.js";
import type { StreamSourceKind } from "../../ports/evidence.js";

/**
 * In-memory indexes over the run's ledger (S2 §9.4). Rows hold everything summary queries filter on; full records are
 * read on demand (pread offset/length) and re-authenticated. Origin is an index attribute, never part of a record
 * (S2-17): imported lines keep their ids and authority.
 */
export type Origin = { readonly kind: "local" } | { readonly kind: "import"; readonly bundle_digest: string };
export const LOCAL: Origin = { kind: "local" };

export interface LineRef {
  readonly offset: number;
  readonly length: number;
  readonly sha256: string;
}

export interface LocationKey {
  readonly module_key: string | null;
  readonly image_sha256: string | null;
  readonly rva: bigint | null;
  readonly va: bigint;
  readonly module_map_id: MmId | null;
}

export interface EvidenceRow {
  readonly evidence_id: EvId;
  readonly n: number;
  readonly ref: LineRef;
  readonly origin: Origin;
  readonly predicate_type: string;
  readonly operation: string;
  readonly subject_kind: "process-instance" | "image" | "emulation" | null;
  readonly instance_id: PiId | null;
  readonly module_map_id: MmId | null;
  readonly image_sha256: string | null;
  readonly seq: number | null;
  readonly run_id: string | null;
  readonly confidence: Confidence;
  readonly authority: Authority;
  readonly coverage_status: Coverage["status"];
  readonly truncated: boolean;
  readonly limitation_count: number;
  readonly effect_count: number;
  readonly link_count: number;
  readonly blob_bytes: number;
  readonly applied_effects: readonly FxId[];
  readonly perturbation: Perturbation;
  readonly stream_id: StId | null;
  readonly links: readonly EvId[];
  readonly locations: readonly LocationKey[];
  readonly blobs: readonly { readonly sha256: string; readonly bytes: number }[];
  readonly module_map_ids: readonly MmId[];
}

export interface EffectEntry {
  readonly effect: Effect;
  readonly ref: LineRef;
  readonly origin: Origin;
  readonly transitions: { readonly transition: EffectTransition; readonly ref: LineRef; readonly origin: Origin }[];
}
export interface UnknownEntry {
  readonly revisions: { readonly revision: ResidualUnknown; readonly ref: LineRef; readonly origin: Origin }[];
}
export interface InstanceEntry {
  readonly instance_id: PiId;
  readonly identity: ProcessIdentity;
  readonly ownership: "owned" | "attached";
  readonly image_name: string | null;
  readonly ref: LineRef;
  readonly origin: Origin;
}
export interface ModuleMapEntry {
  readonly module_map: ModuleMap;
  readonly ref: LineRef;
  readonly origin: Origin;
}
export interface StreamEntry {
  readonly stream_id: StId;
  readonly source_kind: StreamSourceKind;
  readonly instance_id: PiId | null;
  readonly effect_id: FxId | null;
  readonly descriptor_sha256: string;
  readonly origin: Origin;
  /** manifest evidence ids, oldest first */
  readonly manifests: EvId[];
}

const hexToBig = (value: string | null): bigint | null => (value === null ? null : BigInt(value));

const objectOf = (value: JsonValue | undefined): { readonly [k: string]: JsonValue } | null =>
  typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as { readonly [k: string]: JsonValue })
    : null;

/**
 * The stream a record names: `result.stream_id` (diff, manifests, call batches), else the nested emu_call stream of
 * `result.batch` / `result.sweep` (S5 §11.3 host row streams), else `parameters.stream_id`. Indexing the producers of
 * host row streams lets query_events {stream_id} cite them (they have no bea.stream.manifest; integrator, WP14).
 */
const resultStreamId = (record: BeaEvidence): StId | null => {
  const result = objectOf(record.result);
  const candidates = [
    result?.["stream_id"],
    objectOf(result?.["batch"])?.["stream_id"],
    objectOf(result?.["sweep"])?.["stream_id"],
  ];
  const fromResult = candidates.find((value) => typeof value === "string");
  const value = fromResult ?? record.parameters["stream_id"];
  return typeof value === "string" && /^st_[a-f0-9]{64}$/u.test(value) ? (value as StId) : null;
};

export const rowOf = (record: BeaEvidence, n: number, ref: LineRef, origin: Origin): EvidenceRow => {
  const subject = record.subject;
  const instance_id = subject?.kind === "process-instance" ? subject.instance_id : null;
  const module_map_id = subject !== null && subject.kind !== "image" ? subject.module_map_id : null;
  const mmIds = new Set<MmId>();
  if (module_map_id !== null) mmIds.add(module_map_id);
  const locations: LocationKey[] = [];
  for (const location of record.locations)
    if (location.kind === "address") {
      if (location.module_map_id !== null) mmIds.add(location.module_map_id);
      locations.push({
        module_key: location.module_key,
        image_sha256: location.image_sha256,
        rva: hexToBig(location.rva),
        va: BigInt(location.va),
        module_map_id: location.module_map_id,
      });
    }
  return {
    evidence_id: record.evidence_id,
    n,
    ref,
    origin,
    predicate_type: record.predicate_type,
    operation: record.operation,
    subject_kind: subject?.kind ?? null,
    instance_id,
    module_map_id,
    image_sha256: subject !== null && subject.kind !== "process-instance" ? subject.image_sha256 : null,
    seq: record.observed_at?.seq ?? null,
    run_id: record.observed_at?.run_id ?? null,
    confidence: record.confidence,
    authority: record.authority,
    coverage_status: record.coverage.status,
    truncated: record.coverage.truncated,
    limitation_count: record.limitations.length,
    effect_count: record.effects.length,
    link_count: record.evidence_links.length,
    blob_bytes: record.blobs.reduce((sum, blob) => sum + blob.bytes, 0),
    applied_effects: record.effects,
    perturbation: record.perturbation,
    stream_id: resultStreamId(record),
    links: record.evidence_links,
    locations,
    blobs: record.blobs.map((blob) => ({ sha256: blob.sha256, bytes: blob.bytes })),
    module_map_ids: [...mmIds],
  };
};

export const foldEffect = (entry: Pick<EffectEntry, "effect" | "transitions">): EffectState => {
  const last = entry.transitions.at(-1)?.transition;
  const status: EffectStatus = last !== undefined ? last.to : entry.effect.reversible ? "active" : "permanent";
  return { effect: entry.effect, status, transitions: entry.transitions.map((t) => t.transition) };
};

export class LedgerIndex {
  readonly rows: EvidenceRow[] = [];
  readonly byId = new Map<EvId, EvidenceRow>();
  readonly byInstance = new Map<PiId, EvidenceRow[]>();
  readonly childrenOf = new Map<EvId, EvId[]>();
  readonly effects = new Map<FxId, EffectEntry>();
  readonly unknowns = new Map<UnkId, UnknownEntry>();
  readonly instances = new Map<PiId, InstanceEntry>();
  readonly moduleMaps = new Map<MmId, ModuleMapEntry>();
  readonly streams = new Map<StId, StreamEntry>();
  /** blob sha256 -> bytes for every blob this run holds (written or imported) */
  readonly blobs = new Map<string, number>();

  addEvidence(record: BeaEvidence, ref: LineRef, origin: Origin = LOCAL): EvidenceRow {
    const row = rowOf(record, this.rows.length + 1, ref, origin);
    this.rows.push(row);
    this.byId.set(row.evidence_id, row);
    if (row.instance_id !== null) {
      const list = this.byInstance.get(row.instance_id);
      if (list === undefined) this.byInstance.set(row.instance_id, [row]);
      else list.push(row);
    }
    for (const link of row.links) {
      const list = this.childrenOf.get(link);
      if (list === undefined) this.childrenOf.set(link, [row.evidence_id]);
      else list.push(row.evidence_id);
    }
    if (row.predicate_type === "bea.stream.manifest" && row.stream_id !== null)
      this.streams.get(row.stream_id)?.manifests.push(row.evidence_id);
    return row;
  }

  addEffect(effect: Effect, ref: LineRef, origin: Origin = LOCAL): EffectEntry {
    const entry: EffectEntry = { effect, ref, origin, transitions: [] };
    this.effects.set(effect.effect_id, entry);
    return entry;
  }

  addTransition(transition: EffectTransition, ref: LineRef, origin: Origin = LOCAL): EffectEntry | undefined {
    const entry = this.effects.get(transition.effect_id);
    entry?.transitions.push({ transition, ref, origin });
    return entry;
  }

  addUnknown(revision: ResidualUnknown, ref: LineRef, origin: Origin = LOCAL): void {
    const entry = this.unknowns.get(revision.unknown_id);
    if (entry === undefined) this.unknowns.set(revision.unknown_id, { revisions: [{ revision, ref, origin }] });
    else entry.revisions.push({ revision, ref, origin });
  }

  unknownHead(id: UnkId): ResidualUnknown | undefined {
    return this.unknowns.get(id)?.revisions.at(-1)?.revision;
  }

  addInstance(entry: InstanceEntry): void {
    if (!this.instances.has(entry.instance_id)) this.instances.set(entry.instance_id, entry);
  }

  addModuleMap(entry: ModuleMapEntry): void {
    if (!this.moduleMaps.has(entry.module_map.module_map_id))
      this.moduleMaps.set(entry.module_map.module_map_id, entry);
  }

  addStream(entry: StreamEntry): void {
    if (!this.streams.has(entry.stream_id)) this.streams.set(entry.stream_id, entry);
  }

  effectState(id: FxId): EffectState | undefined {
    const entry = this.effects.get(id);
    return entry === undefined ? undefined : foldEffect(entry);
  }
}
