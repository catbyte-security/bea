import type { z } from "zod";

import type { listMemoryRangesInputSchema, listMemoryRangesOutputSchema } from "../../contracts/areas/inspect.js";
import { INSPECT_CAPS } from "../../contracts/areas/inspect.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { COMPLETE, type Coverage } from "../../domain/evidence/coverage.js";
import { LIMITATIONS } from "../../domain/evidence/limitations.js";
import { ok, type Result } from "../../domain/result.js";
import type { LiveSession, OperationContext } from "../../ports/sessions.js";
import type { ListRangesParams, RangeRow } from "../../shared/agentProtocol.js";
import type { BeaApplication } from "../BeaApplication.js";
import type { HandlerContext } from "../handlerContext.js";
import { liveOp } from "../sessionAccess.js";
import { clip, deliver, jsonInput, jsonResult, literalsOf, pageOf, recordLive, sliceOf } from "./common.js";

type Input = z.output<typeof listMemoryRangesInputSchema>;
type Output = z.output<typeof listMemoryRangesOutputSchema>;
type Row = Output["rows"][number];

/** Agent page size per listRanges call (≤ AgentLimits.list_page_max default 5000). */
const AGENT_PAGE = 5000;
/** Ranges kept per snapshot; beyond it the result is truncated (row_cap). */
export const MAX_RANGE_ROWS = 100_000;
/** Continuation pages (offset > 0) reuse the snapshot of the first page for this long (agent snapshot TTL 30 s). */
export const SNAPSHOT_TTL_MS = 25_000;

interface Snapshot {
  readonly key: string;
  readonly at: number;
  readonly rows: readonly Row[];
  readonly totalBytes: number;
  readonly capped: boolean;
}

/**
 * Per-application snapshot cache: page 0 always enumerates afresh; a later page with the same filters within the
 * TTL pages the same snapshot, so totals and rows stay consistent across one paging walk (S6 §4.10 "totals match the
 * paging sum").
 */
const caches = new WeakMap<BeaApplication, Map<string, Snapshot>>();
const cacheOf = (app: BeaApplication): Map<string, Snapshot> => {
  let cache = caches.get(app);
  if (cache === undefined) {
    cache = new Map();
    caches.set(app, cache);
  }
  return cache;
};

export const snapshotKey = (input: Input): string =>
  JSON.stringify([input.protection, input.module ?? null, input.kind, input.coalesce]);

/** Agent kinds → tool kinds: module images are `image`; Frida's malloc ranges are private heap. */
export const rangeKind = (kind: RangeRow["kind"]): Row["kind"] => (kind === "module" ? "image" : "private");
const AGENT_KIND: Readonly<Record<Input["kind"], ListRangesParams["kind"]>> = {
  all: "all",
  image: "module",
  private: "private",
};

const toRow = (r: RangeRow): Row => ({
  base: r.base,
  size: r.size,
  prot: r.protection.slice(0, 8),
  module: r.module === null ? null : clip(r.module, INSPECT_CAPS.moduleName),
  kind: rangeKind(r.kind),
});

/** Every agent page of one snapshot; an expired snapshot (reference_not_found) restarts once without it. */
const enumerate = async (
  session: LiveSession,
  op: OperationContext,
  input: Input,
): Promise<Result<Omit<Snapshot, "key" | "at">, BeaError>> => {
  for (let attempt = 0; ; attempt++) {
    const rows: Row[] = [];
    let totalBytes = 0;
    let snapshot: string | undefined;
    let offset: number | null = 0;
    let restart = false;
    while (offset !== null && rows.length < MAX_RANGE_ROWS) {
      const params: ListRangesParams = {
        protection: input.protection,
        coalesce: input.coalesce,
        kind: AGENT_KIND[input.kind],
        offset,
        limit: AGENT_PAGE,
        ...(input.module === undefined ? {} : { module: input.module }),
        ...(snapshot === undefined ? {} : { snapshot }),
      };
      const reply = await session.agent.call("listRanges", params, { op });
      if (!reply.ok) {
        const expired =
          reply.error._tag === "ReferenceNotFound" && reply.error.reference.kind === "snapshot" && attempt === 0;
        if (!expired) return reply;
        restart = true;
        break;
      }
      snapshot = reply.value.snapshot;
      for (const item of reply.value.items) {
        if (rows.length >= MAX_RANGE_ROWS) break;
        rows.push(toRow(item));
        totalBytes += item.size;
      }
      offset = reply.value.next_offset;
    }
    if (!restart) return ok({ rows, totalBytes, capped: offset !== null });
  }
};

export const listMemoryRanges = (
  app: BeaApplication,
  input: Input,
  ctx: HandlerContext,
): Promise<Result<Output, BeaError>> =>
  liveOp(app, ctx, input.session_id, { mode: "exclusive", need: "agent" }, async (session, op) => {
    const literals = literalsOf(app);
    if (!literals.ok) return literals;
    const cache = cacheOf(app);
    const now = performance.now();
    for (const [id, entry] of cache) if (now - entry.at > SNAPSHOT_TTL_MS) cache.delete(id);
    const key = snapshotKey(input);
    const cached = cache.get(session.id);
    let snap: Snapshot;
    if (input.offset > 0 && cached?.key === key) snap = cached;
    else {
      const fresh = await enumerate(session, op, input);
      if (!fresh.ok) return fresh;
      snap = { key, at: performance.now(), ...fresh.value };
      cache.set(session.id, snap);
    }
    const capture = app.services.evidence.instances.capture(session.instanceId);
    const coverage: Coverage = snap.capped ? { status: "partial", truncated: true, reasons: ["row_cap"] } : COMPLETE;
    const limitations: string[] = [LIMITATIONS.AGENT_CLOAKED, LIMITATIONS.RANGE_KIND_MAPPED_UNDISTINGUISHED];
    if (snap.capped) limitations.push(LIMITATIONS.CAP("range", MAX_RANGE_ROWS));
    const recorded = await recordLive({ app, ctx }, session, capture, {
      predicate: "bea.memory.ranges",
      input: jsonInput(input),
      result: jsonResult({
        total_bytes: snap.totalBytes,
        rows: sliceOf(snap.rows, input.offset, input.limit),
        page: pageOf(input.offset, input.limit, snap.rows.length),
      }),
      coverage,
      limitations,
      literals: literals.value,
    });
    if (!recorded.ok) return recorded;
    return ok(deliver(recorded.value) as unknown as Output);
  });
