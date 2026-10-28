import type { BeaError, ReferenceKind } from "../../domain/errors/beaError.js";
import { cancelled, inputError, referenceNotFound } from "../../domain/errors/constructors.js";
import type { EvId, FxId, MmId, PiId, StId, UnkId } from "../../domain/ids.js";
import type { JsonObject, JsonValue } from "../../domain/json.js";
import { pointerTokens } from "../../domain/redaction/redact.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { BeaEvidence } from "../../domain/evidence/record.js";
import type { EvidenceQuery, InstanceRegistry } from "../../ports/evidence.js";
import type { FileBlobStore } from "./BlobStore.js";
import type { Ledger } from "./Ledger.js";
import { foldEffect, type EvidenceRow, type LedgerIndex, type Origin } from "./LedgerIndex.js";
import { decodeLine } from "./LedgerLines.js";

/**
 * `get_evidence` reads (S2 §12): summary rows (exact filters, paging), one complete record by any ledger id
 * (re-authenticated on read), or a page of an array / NDJSON table / binary blob inside a retained record. Reads
 * never resolve an address and never touch a target.
 */
export const SLICE_MAX_ITEMS = 15;
export const SLICE_MAX_KIB = 64;
const QUESTION_ROW_CHARS = 240;

const MISSING =
  "The ID is not in this run's ledger; list with get_evidence summary, or import the bundle that holds it.";

/** The reference kind of a ledger id by its prefix (review fix UX-13). */
const kindOf = (id: string): ReferenceKind =>
  id.startsWith("ev_")
    ? "evidence"
    : id.startsWith("fx_")
      ? "effect"
      : id.startsWith("unk_")
        ? "unknown"
        : id.startsWith("pi_")
          ? "instance"
          : id.startsWith("mm_")
            ? "module_map"
            : "stream";

/**
 * Review fix UX-13: an id absent from this run is reference_not_found (as record_unknown, query_events and the scan
 * tools report it), not invalid_request with a fragment of the caller's id as `expected`.
 */
const missing = (operation: string, id: string): BeaError => ({
  ...referenceNotFound(operation, kindOf(id), id.slice(0, 80)),
  remediation: MISSING,
});

const originName = (origin: Origin): "local" | "imported" => (origin.kind === "local" ? "local" : "imported");

type Filters = Readonly<Record<string, JsonValue>>;

const str = (f: Filters, key: string): string | undefined =>
  typeof f[key] === "string" ? (f[key] as string) : undefined;
const num = (f: Filters, key: string): number | undefined =>
  typeof f[key] === "number" ? (f[key] as number) : undefined;
const big = (f: Filters, key: string): bigint | undefined => {
  const value = str(f, key);
  return value === undefined ? undefined : BigInt(value.toLowerCase());
};

const locationMatches = (row: EvidenceRow, f: Filters): boolean => {
  const module = str(f, "module")?.toLowerCase();
  const image = str(f, "image_sha256");
  const [rvaFrom, rvaTo, vaFrom, vaTo] = [big(f, "rva_from"), big(f, "rva_to"), big(f, "va_from"), big(f, "va_to")];
  if (
    module === undefined &&
    image === undefined &&
    rvaFrom === undefined &&
    rvaTo === undefined &&
    vaFrom === undefined &&
    vaTo === undefined
  )
    return true;
  if (
    image !== undefined &&
    module === undefined &&
    rvaFrom === undefined &&
    rvaTo === undefined &&
    row.image_sha256 === image
  )
    return true;
  return row.locations.some(
    (l) =>
      (module === undefined || l.module_key === module) &&
      (image === undefined || l.image_sha256 === image) &&
      (rvaFrom === undefined || (l.rva !== null && l.rva >= rvaFrom)) &&
      (rvaTo === undefined || (l.rva !== null && l.rva <= rvaTo)) &&
      (vaFrom === undefined || l.va >= vaFrom) &&
      (vaTo === undefined || l.va <= vaTo),
  );
};

const evidenceMatches = (row: EvidenceRow, f: Filters): boolean => {
  const eq = (key: string, value: string | null): boolean => str(f, key) === undefined || str(f, key) === value;
  if (!eq("evidence_id", row.evidence_id) || !eq("instance_id", row.instance_id)) return false;
  if (!eq("predicate_type", row.predicate_type) || !eq("operation", row.operation)) return false;
  if (!eq("confidence", row.confidence) || !eq("authority", row.authority)) return false;
  if (!eq("coverage_status", row.coverage_status) || !eq("stream_id", row.stream_id)) return false;
  if (!eq("origin", originName(row.origin))) return false;
  const applied = str(f, "applied_effect_id");
  if (applied !== undefined && !row.applied_effects.includes(applied as FxId)) return false;
  const under = str(f, "under_effect_id");
  if (under !== undefined && !row.perturbation.active_effect_ids.includes(under as FxId)) return false;
  const mm = str(f, "module_map_id");
  if (mm !== undefined && !row.module_map_ids.includes(mm as MmId)) return false;
  const linksTo = str(f, "links_to");
  if (linksTo !== undefined && !row.links.includes(linksTo as EvId)) return false;
  const [from, to] = [num(f, "seq_from"), num(f, "seq_to")];
  if (from !== undefined && (row.seq === null || row.seq < from)) return false;
  if (to !== undefined && (row.seq === null || row.seq > to)) return false;
  return locationMatches(row, f);
};

const page = (offset: number, limit: number, total: number) => ({
  offset,
  limit,
  total,
  next_offset: offset + limit < total ? offset + limit : null,
});

export interface QueryDeps {
  readonly index: LedgerIndex;
  readonly ledger: Ledger;
  readonly blobs: FileBlobStore;
  readonly instances: InstanceRegistry;
}

export class LedgerEvidenceQuery implements EvidenceQuery {
  readonly #lineOffsets = new Map<string, number[]>();

  constructor(private readonly deps: QueryDeps) {}

  summary(input: JsonObject): Result<JsonObject, BeaError> {
    const entity = typeof input["entity"] === "string" ? input["entity"] : "evidence";
    const filters = (
      typeof input["filters"] === "object" && input["filters"] !== null ? input["filters"] : {}
    ) as Filters;
    const offset = typeof input["offset"] === "number" ? input["offset"] : 0;
    const limit = typeof input["limit"] === "number" ? input["limit"] : 50;
    const { total, rows } = this.#rows(entity, filters);
    return ok({
      entity,
      total,
      matching: rows.length,
      rows: rows.slice(offset, offset + limit),
      page: page(offset, limit, rows.length),
    });
  }

  #rows(entity: string, f: Filters): { readonly total: number; readonly rows: JsonObject[] } {
    const index = this.deps.index;
    switch (entity) {
      case "effects": {
        const all = [...index.effects.values()];
        const rows = all
          .map((entry) => ({ entry, state: foldEffect(entry) }))
          .filter(
            ({ entry, state }) =>
              (str(f, "instance_id") === undefined || entry.effect.instance_id === str(f, "instance_id")) &&
              (str(f, "status") === undefined || state.status === str(f, "status")) &&
              (str(f, "applied_effect_id") === undefined || entry.effect.effect_id === str(f, "applied_effect_id")) &&
              (str(f, "origin") === undefined || originName(entry.origin) === str(f, "origin")),
          )
          .map(({ entry, state }): JsonObject => {
            const a = entry.effect.target.address;
            const ended = state.transitions.findLast((t) => t.to !== "revert-failed");
            return {
              kind: "effect",
              effect_id: entry.effect.effect_id,
              effect_kind: entry.effect.kind,
              class: entry.effect.class,
              instance_id: entry.effect.instance_id,
              status: state.status,
              applied_seq: entry.effect.applied_at.seq,
              ended_seq: ended?.at.seq ?? null,
              target: a === null ? null : a.module_key !== null && a.rva !== null ? `${a.module_key}+${a.rva}` : a.va,
              stream_ids: entry.effect.stream_ids.slice(0, 2),
              stream_count: entry.effect.stream_ids.length,
            };
          });
        return { total: all.length, rows };
      }
      case "unknowns": {
        const heads = [...index.unknowns.values()]
          .map((e) => e.revisions.at(-1)?.revision)
          .filter((r) => r !== undefined);
        const rows = heads
          .filter(
            (u) =>
              (str(f, "status") === undefined || u.status === str(f, "status")) &&
              (str(f, "severity") === undefined || u.severity === str(f, "severity")) &&
              (str(f, "domain") === undefined || u.domain === str(f, "domain")),
          )
          .map((u): JsonObject => ({
            kind: "unknown",
            unknown_id: u.unknown_id,
            revision: u.revision,
            status: u.status,
            severity: u.severity,
            domain: u.domain,
            question: u.question.slice(0, QUESTION_ROW_CHARS),
            question_truncated: u.question.length > QUESTION_ROW_CHARS,
            supporting_count: u.supporting_evidence_ids.length,
            contradicting_count: u.contradicting_evidence_ids.length,
          }));
        return { total: heads.length, rows };
      }
      case "instances": {
        const all = [...index.instances.values()];
        const rows = all
          .filter(
            (i) =>
              (str(f, "instance_id") === undefined || i.instance_id === str(f, "instance_id")) &&
              (str(f, "origin") === undefined || originName(i.origin) === str(f, "origin")),
          )
          .map((i): JsonObject => ({
            kind: "instance",
            instance_id: i.instance_id,
            pid: i.identity.pid,
            ownership: i.ownership,
            image_name: i.image_name,
            state:
              this.deps.instances.get(i.instance_id)?.state ?? (i.origin.kind === "import" ? "imported" : "unknown"),
            evidence_count: index.byInstance.get(i.instance_id)?.length ?? 0,
          }));
        return { total: all.length, rows };
      }
      default: {
        const rows = index.rows
          .filter((row) => evidenceMatches(row, f))
          .map((row): JsonObject => ({
            kind: "evidence",
            evidence_id: row.evidence_id,
            n: row.n,
            predicate_type: row.predicate_type,
            operation: row.operation,
            instance_id: row.instance_id,
            seq: row.seq,
            confidence: row.confidence,
            authority: row.authority,
            coverage_status: row.coverage_status,
            truncated: row.truncated,
            limitation_count: row.limitation_count,
            effect_count: row.effect_count,
            link_count: row.link_count,
            blob_bytes: row.blob_bytes,
            origin: originName(row.origin),
          }));
        return { total: index.rows.length, rows };
      }
    }
  }

  /** Read and re-authenticate one evidence record (evidence_integrity_mismatch when the stored line fails). */
  async readEvidence(
    id: EvId,
    operation: string,
  ): Promise<Result<{ readonly record: BeaEvidence; readonly row: EvidenceRow }, BeaError>> {
    const row = this.deps.index.byId.get(id);
    if (row === undefined) return err(missing(operation, id));
    const text = await this.deps.ledger.readAt(row.ref.offset, row.ref.length, operation);
    if (!text.ok) return text;
    const line = decodeLine(text.value, operation);
    if (!line.ok) return line;
    if (line.value.t !== "ev" || line.value.record.evidence_id !== id)
      return err({ _tag: "EvidenceIntegrity", operation, reason: "id-mismatch", diagnostics: { evidence_id: id } });
    return ok({ record: line.value.record, row });
  }

  async complete(id: string): Promise<Result<JsonObject, BeaError>> {
    const operation = "get_evidence";
    const index = this.deps.index;
    const as = (record_kind: string, origin: Origin, value: unknown): Result<JsonObject, BeaError> =>
      ok({ record_kind, origin: originName(origin), value: value as JsonObject });
    if (id.startsWith("ev_")) {
      const read = await this.readEvidence(id as EvId, operation);
      return read.ok ? as("evidence", read.value.row.origin, read.value.record) : read;
    }
    if (id.startsWith("fx_")) {
      const entry = index.effects.get(id as FxId);
      if (entry === undefined) return err(missing(operation, id));
      const state = foldEffect(entry);
      return as("effect", entry.origin, { ...entry.effect, status: state.status, transitions: state.transitions });
    }
    if (id.startsWith("unk_")) {
      const entry = index.unknowns.get(id as UnkId);
      const head = entry?.revisions.at(-1);
      if (entry === undefined || head === undefined) return err(missing(operation, id));
      return as("unknown", head.origin, {
        ...head.revision,
        history: entry.revisions.map((r) => ({
          revision: r.revision.revision,
          status: r.revision.status,
          revision_digest: r.revision.revision_digest,
          mutation_evidence_ids: r.revision.mutation_evidence_ids,
        })),
      });
    }
    if (id.startsWith("pi_")) {
      const entry = index.instances.get(id as PiId);
      if (entry === undefined) return err(missing(operation, id));
      const live = this.deps.instances.get(id as PiId);
      return as("instance", entry.origin, {
        instance_id: entry.instance_id,
        identity: entry.identity,
        ownership: entry.ownership,
        display: { image_name: entry.image_name },
        state: live?.state ?? null,
        exit: live?.exit ?? null,
        environment: live?.environment ?? null,
      });
    }
    if (id.startsWith("mm_")) {
      const entry = index.moduleMaps.get(id as MmId);
      return entry === undefined ? err(missing(operation, id)) : as("module_map", entry.origin, entry.module_map);
    }
    const stream = index.streams.get(id as StId);
    return stream === undefined ? err(missing(operation, id)) : as("stream", stream.origin, stream);
  }

  async slice(
    id: EvId,
    pointer: string,
    offset: number,
    limit: number,
    format: "hex" | "base64",
    signal?: AbortSignal,
  ): Promise<Result<JsonObject, BeaError>> {
    const operation = "get_evidence";
    const read = await this.readEvidence(id, operation);
    if (!read.ok) return read;
    const record = read.value.record;
    const badPointer = (message: string): Result<never, BeaError> =>
      err(inputError(operation, [{ path: "pointer", reason: "invalid_value", message }]));
    if (pointer.startsWith("#blob:")) {
      const role = pointer.slice("#blob:".length);
      const blob = record.blobs.find((b) => b.role === role);
      if (blob === undefined) return badPointer(`The record has no blob with role "${role.slice(0, 64)}".`);
      if (blob.media_type === "application/x-ndjson")
        return this.#ndjson(record.evidence_id, pointer, blob.sha256, offset, limit, signal);
      const bytes = Math.min(limit, SLICE_MAX_KIB) * 1024;
      const data = await this.deps.blobs.read(blob.sha256, offset, bytes);
      if (!data.ok) return data;
      const buffer = Buffer.from(data.value.buffer, data.value.byteOffset, data.value.byteLength);
      return ok({
        evidence_id: record.evidence_id,
        pointer,
        total: blob.bytes,
        data: format === "hex" ? buffer.toString("hex") : buffer.toString("base64"),
        format,
        page: page(offset, bytes, blob.bytes),
      });
    }
    const tokens = pointerTokens(pointer);
    if (tokens === null) return badPointer('pointer must be a JSON pointer ("/result/rows") or "#blob:<role>".');
    let node: unknown = record;
    for (const token of tokens) {
      if (node === null || typeof node !== "object" || !Object.hasOwn(node, token))
        return badPointer("pointer does not resolve inside the record.");
      node = (node as Record<string, unknown>)[token];
    }
    if (!Array.isArray(node))
      return badPointer("pointer must resolve to an array; read scalars and objects with detail complete.");
    const take = Math.min(limit, SLICE_MAX_ITEMS);
    return ok({
      evidence_id: record.evidence_id,
      pointer,
      total: node.length,
      items: node.slice(offset, offset + take) as JsonValue[],
      page: page(offset, take, node.length),
    });
  }

  async #ndjson(
    evidenceId: EvId,
    pointer: string,
    sha256: string,
    offset: number,
    limit: number,
    signal?: AbortSignal,
  ): Promise<Result<JsonObject, BeaError>> {
    let offsets = this.#lineOffsets.get(sha256);
    if (offsets === undefined) {
      const opened = await this.deps.blobs.open(sha256);
      if (!opened.ok) return opened;
      offsets = [0];
      let position = 0;
      try {
        for await (const chunk of opened.value.createReadStream({ autoClose: false })) {
          if (signal?.aborted === true) return err(cancelled("get_evidence", "signal"));
          const buffer = chunk as Buffer;
          for (let i = buffer.indexOf(10); i !== -1; i = buffer.indexOf(10, i + 1)) offsets.push(position + i + 1);
          position += buffer.length;
        }
      } finally {
        await opened.value.close().catch(() => undefined);
      }
      if (offsets.at(-1) === position) offsets.pop();
      this.#lineOffsets.set(sha256, offsets);
    }
    const total = offsets.length;
    const take = Math.min(limit, SLICE_MAX_ITEMS);
    const items: JsonValue[] = [];
    const end = Math.min(total, offset + take);
    if (offset < end) {
      const start = offsets[offset] ?? 0;
      const stop = offsets[end] ?? this.deps.blobs.size(sha256) ?? start;
      const data = await this.deps.blobs.read(sha256, start, stop - start);
      if (!data.ok) return data;
      for (const line of Buffer.from(data.value).toString("utf8").split("\n"))
        if (line.length > 0) items.push(JSON.parse(line) as JsonValue);
    }
    return ok({ evidence_id: evidenceId, pointer, total, items, page: page(offset, take, total) });
  }
}
