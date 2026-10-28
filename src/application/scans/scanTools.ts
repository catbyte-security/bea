import type { z } from "zod";

import {
  SCAN_CAPS,
  type scanMemoryOutputSchema,
  type scanNextOutputSchema,
  type scanResultsInputSchema,
  type scanResultsOutputSchema,
  type ScanToolValueType,
} from "../../contracts/areas/scan.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { cancelled, inputError, referenceNotFound } from "../../domain/errors/constructors.js";
import { mergeCoverage } from "../../domain/evidence/coverage.js";
import { LIMITATIONS } from "../../domain/evidence/limitations.js";
import { SCAN_LIMITATIONS } from "../../domain/evidence/limitations/scan.js";
import type { PiId } from "../../domain/ids.js";
import type { JsonObject } from "../../domain/json.js";
import { err, ok, type Result } from "../../domain/result.js";
import { bytesContainLiteral, textContainsLiteral } from "../../domain/redaction/redact.js";
import type { AddressSpace } from "../../ports/address.js";
import type { SensitiveLiterals } from "../../ports/evidence.js";
import type { LiveSession, OperationContext } from "../../ports/sessions.js";
import type { Paged, ScanHit, TypedOut } from "../../shared/agentProtocol.js";
import type { BeaApplication } from "../BeaApplication.js";
import type { HandlerContext } from "../handlerContext.js";
import { agentStateError, liveOp } from "../sessionAccess.js";
import { HOST_STORE_MAX_HITS, type HitStore, type StoredHit } from "./scanHitStore.js";
import {
  cellOf,
  planScanMemory,
  planScanNext,
  withResolvedAddress,
  type ScanMemoryInput,
  type ScanNextInput,
} from "./scanInputs.js";
import { recordedEnvelope, scanCoverage, scanLimitations, scanResultBody, unrecordedEnvelope } from "./scanOutputs.js";
import type { ScanRecord, ScanService } from "./ScanService.js";

/**
 * WP10-SCAN tool flows (DESIGN §6.2 #15–17):
 * 1. validate + plan (no session);
 * 2. exclusive section: resolve an AddrExpr comparand, scanStart / scanNext (ScanService.begin / narrow);
 * 3. outside any section: wait up to wait_ms on the background job await (other session ops keep flowing);
 * 4. done → exclusive section: pull a small hit list into the host store, record `bea.scan.result`, return the
 *    recorded envelope; still running → a poll (evidence_id null) that names the scan to wait on.
 */
type ScanMemoryOutput = z.output<typeof scanMemoryOutputSchema>;
type ScanNextOutput = z.output<typeof scanNextOutputSchema>;
type ScanResultsInput = z.output<typeof scanResultsInputSchema>;
type ScanResultsOutput = z.output<typeof scanResultsOutputSchema>;

export interface ScanToolDeps {
  readonly app: BeaApplication;
  readonly service: ScanService;
  readonly store: HitStore;
}

const PROVIDER = { id: "frida", name: "frida-gum", version: null } as const;
const agentUsable = (session: LiveSession): boolean => session.state === "running" || session.state === "paused";

const missing = (operation: string, id: string): BeaError => referenceNotFound(operation, "scan", id);
const failureOf = (ctx: HandlerContext, rec: ScanRecord): BeaError =>
  rec.error === null
    ? { _tag: "ProviderFailure", operation: ctx.operation, provider: "agent" }
    : { ...rec.error, operation: ctx.operation };

/** Pulls the last iteration's hits into the host store when they are few (scan_results after exit). */
const pullHits = async (deps: ScanToolDeps, session: LiveSession, op: OperationContext, rec: ScanRecord) => {
  if (rec.mode !== "explicit" || rec.count > HOST_STORE_MAX_HITS || !agentUsable(session)) return;
  const hits: StoredHit[] = [];
  let offset: number | null = 0;
  while (offset !== null && offset < rec.count) {
    const page: Result<Paged<ScanHit>, BeaError> = await session.agent.call(
      "scanResults",
      { scan_id: rec.agentScanId, offset, limit: HOST_STORE_MAX_HITS, read_current: false },
      { op },
    );
    if (!page.ok) return; // the store is a convenience; the scan itself is fine
    for (const item of page.value.items) hits.push({ address: item.address, stored: item.stored });
    offset = page.value.next_offset;
  }
  await deps.store.save(rec.id, rec.iteration, hits);
};

/** Records `bea.scan.result` for a finished iteration and returns the envelope keys. */
const recordIteration = async (
  deps: ScanToolDeps,
  operation: string,
  input: JsonObject,
  rec: ScanRecord,
): Promise<Result<ReturnType<typeof recordedEnvelope>, BeaError>> => {
  const evidence = deps.app.services.evidence;
  const literals = evidence.literals(undefined);
  if (!literals.ok) return literals;
  const instance = rec.instanceId as PiId;
  const recorded = await evidence.recorder.record({
    predicate_type: "bea.scan.result",
    operation,
    input,
    identityExclude: ["wait_ms"],
    subject: { kind: "process-instance", instance_id: instance },
    capture: evidence.instances.capture(instance),
    provider: PROVIDER,
    result: scanResultBody(rec),
    coverage: scanCoverage(rec),
    limitations: scanLimitations(rec),
    literals: literals.value,
  });
  return recorded.ok ? ok(recordedEnvelope(recorded.value.record)) : recorded;
};

/** How long a cancelled call may spend telling the agent to stop the scan's job. */
const CANCEL_BUDGET_MS = 5_000;

/**
 * S6 §2.6: a client-cancelled scan_memory/scan_next stops the scan at its next slice and keeps the partial result
 * (the background await then marks the record done with coverage reason "cancelled"). The call's own signal is
 * already aborted, so the jobCancel RPC runs under a short budget of its own; a failure only leaves the job running.
 */
const cancelJob = async (deps: ScanToolDeps, ctx: HandlerContext, rec: ScanRecord): Promise<void> => {
  const jobId = rec.jobId;
  if (jobId === null || rec.state !== "running") return;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CANCEL_BUDGET_MS);
  timer.unref?.();
  const detached: HandlerContext = {
    ...ctx,
    signal: controller.signal,
    abortCause: () => null,
    remainingMs: () => CANCEL_BUDGET_MS,
  };
  try {
    const r = await liveOp(deps.app, detached, rec.sessionId, { mode: "concurrent", need: "agent" }, (session, op) =>
      session.agent.call("jobCancel", { job_id: jobId }, { op }),
    );
    if (!r.ok) ctx.log.debug("scan job cancel failed", { scan_id: rec.id, error: r.error._tag });
  } finally {
    clearTimeout(timer);
  }
};

/** Steps 3–4 shared by scan_memory and scan_next. `project` maps the record to the tool's result fields. */
const conclude = async <R extends object>(
  deps: ScanToolDeps,
  ctx: HandlerContext,
  rec: ScanRecord,
  input: { readonly wait_ms: number } & JsonObject,
  project: (rec: ScanRecord) => R,
): Promise<Result<R & (ReturnType<typeof recordedEnvelope> | ReturnType<typeof unrecordedEnvelope>), BeaError>> => {
  await deps.service.settle(rec, input.wait_ms, ctx.signal);
  if (ctx.abortCause()?.kind === "client") {
    await cancelJob(deps, ctx, rec);
    return err(cancelled(ctx.operation, "client"));
  }
  if (rec.state === "running") return ok({ ...project(rec), ...unrecordedEnvelope(rec) });
  return liveOp(deps.app, ctx, rec.sessionId, { mode: "exclusive", need: "host" }, async (session, op) => {
    if (rec.state === "released") return err(agentStateError(ctx.operation, session) ?? missing(ctx.operation, rec.id));
    if (rec.state === "failed" && rec.agentGone)
      return err(agentStateError(ctx.operation, session) ?? failureOf(ctx, rec));
    if (rec.state === "failed") {
      const failure = failureOf(ctx, rec);
      // a first scan that failed holds nothing worth keeping: free its slot
      if (rec.iteration === 0) await deps.service.release(rec, session, op);
      return err(failure);
    }
    await pullHits(deps, session, op, rec);
    const envelope = await recordIteration(deps, ctx.operation, input, rec);
    return envelope.ok ? ok({ ...project(rec), ...envelope.value }) : envelope;
  });
};

const memoryResult = (rec: ScanRecord) => ({
  scan_id: rec.id,
  state:
    rec.state === "running" ? ("running" as const) : rec.state === "failed" ? ("failed" as const) : ("done" as const),
  count: rec.count,
  scanned_bytes: rec.scannedBytes,
  ranges_failed: rec.rangesFailed,
  truncated: rec.truncated,
  elapsed_ms: rec.elapsedMs,
});

const nextResult = (rec: ScanRecord) => ({
  scan_id: rec.id,
  state:
    rec.state === "running" ? ("running" as const) : rec.state === "failed" ? ("failed" as const) : ("done" as const),
  count: rec.count,
  previous_count: rec.previousCount,
  iteration: rec.iteration,
});

export const scanMemory = async (
  deps: ScanToolDeps,
  input: ScanMemoryInput,
  ctx: HandlerContext,
): Promise<Result<ScanMemoryOutput, BeaError>> => {
  const plan = planScanMemory(input);
  if (!plan.ok) return err(inputError(ctx.operation, [plan.issue]));
  const { app, service } = deps;
  const started = await liveOp(
    app,
    ctx,
    input.session_id,
    { mode: "exclusive", need: "agent" },
    async (session, op) => {
      let params = plan.value.params;
      const resolve = plan.value.resolve;
      if (resolve !== null) {
        const resolved = await app.services.address.resolve({ kind: "live", session }, resolve.expr, op, {
          path: resolve.path,
        });
        if (!resolved.ok) return resolved;
        params = withResolvedAddress(plan.value, resolved.value.va);
      }
      return service.begin(session, op, params, {
        operation: ctx.operation,
        valueType: input.value_type,
        compare: input.compare,
        maxHits: input.max_hits,
      });
    },
  );
  if (!started.ok) return started;
  return conclude(deps, ctx, started.value, input as ScanMemoryInput & JsonObject, memoryResult);
};

export const scanNext = async (
  deps: ScanToolDeps,
  input: ScanNextInput,
  ctx: HandlerContext,
): Promise<Result<ScanNextOutput, BeaError>> => {
  const { app, service } = deps;
  const rec = service.get(input.scan_id);
  if (rec === undefined || rec.state === "released") return err(missing(ctx.operation, input.scan_id));
  const plan = planScanNext(rec.valueType, input);
  if (!plan.ok) return err(inputError(ctx.operation, [plan.issue]));
  const narrowed = await liveOp(app, ctx, rec.sessionId, { mode: "exclusive", need: "agent" }, async (session, op) => {
    const refreshed = await service.refresh(session, op, rec);
    if (!refreshed.ok) return refreshed;
    return service.narrow(session, op, rec, plan.value);
  });
  if (!narrowed.ok) return narrowed;
  return conclude(deps, ctx, narrowed.value, input as ScanNextInput & JsonObject, nextResult);
};

/** Row address texts are bounded by the contract (module names are at most 260 characters, so this never bites). */
const clipText = (text: string | null): string | null =>
  text === null || text.length <= SCAN_CAPS.addressText ? text : text.slice(0, SCAN_CAPS.addressText);

const SCALAR_BYTES: Partial<Record<ScanToolValueType, number>> = {
  i32: 4,
  u32: 4,
  f32: 4,
  i64: 8,
  u64: 8,
  f64: 8,
  ptr: 8,
};

/** Little-endian bytes of `size` from a bigint (two's complement). */
const leBytes = (value: bigint, size: number): Uint8Array => {
  const out = new Uint8Array(size);
  let v = BigInt.asUintN(size * 8, value);
  for (let i = 0; i < size; i++, v >>= 8n) out[i] = Number(v & 0xffn);
  return out;
};

/**
 * The target bytes behind a scan value: raw bytes of bytes/text hits, the bits of ≥ 4-byte scalars (a literal is at
 * least 4 bytes, so smaller scalars cannot hold one). Null when not derivable.
 */
const cellBytes = (t: ScanToolValueType, v: TypedOut): Uint8Array | null => {
  if (v.hex !== undefined) return new Uint8Array(Buffer.from(v.hex, "hex"));
  const size = SCALAR_BYTES[t];
  if (size === undefined) return null;
  try {
    if (v.bits !== undefined) return leBytes(BigInt(v.bits), size);
    if (typeof v.value === "number" && Number.isInteger(v.value)) return leBytes(BigInt(v.value), size);
    if (typeof v.value === "string" && /^(?:-?\d+|0x[0-9a-fA-F]+)$/u.test(v.value))
      return leBytes(BigInt(v.value), size);
  } catch {
    return null;
  }
  return null;
};

/**
 * Review fix SEC-3: scan_results cells never pass the Recorder (evidence_id null), so the server-level sensitive
 * literals are matched here: a hit whose bytes (or text) contain a literal is withheld (null cell) and counted.
 */
const sensitiveHit = (
  t: ScanToolValueType,
  v: TypedOut | { readonly error: unknown } | undefined,
  literals: SensitiveLiterals,
): boolean => {
  if (literals.count === 0 || v === undefined || "error" in v) return false;
  if (typeof v.value === "string" && textContainsLiteral(v.value, literals)) return true;
  const bytes = cellBytes(t, v);
  return bytes !== null && bytesContainLiteral(bytes, literals);
};

const describeRows = async (
  deps: ScanToolDeps,
  space: AddressSpace,
  op: OperationContext,
  t: ScanToolValueType,
  hits: readonly { readonly address: string; readonly stored: TypedOut; readonly current?: ScanHit["current"] }[],
  values: boolean,
) => {
  const address = deps.app.services.address;
  const literals = deps.app.services.evidence.literals(undefined);
  const sensitive: SensitiveLiterals = literals.ok ? literals.value : { count: 0, texts: [], spellings: [] };
  const vas = hits.map((h) => BigInt(h.address));
  await address.prepare(space, vas, op);
  let unreadable = 0;
  let withheld = 0;
  const cell = (v: TypedOut | { readonly error: unknown } | undefined) => {
    if (!sensitiveHit(t, v, sensitive)) return cellOf(t, v);
    withheld += 1;
    return null;
  };
  const rows = hits.map((h, i) => {
    const a = address.describe(space, vas[i] ?? 0n);
    if (values && (h.current === undefined || "error" in h.current)) unreadable += 1;
    return {
      va: a.va,
      at: clipText(a.at),
      static: clipText(a.static),
      value: values ? cell(h.current) : null,
      prev: cell(h.stored),
    };
  });
  return { rows, unreadable, withheld };
};

/** Coverage and limitations of a page whose cells were withheld (SEC-3). */
const withheldParts = (withheld: number) =>
  withheld === 0
    ? { coverage: null, limitations: [] as string[] }
    : {
        coverage: { status: "partial" as const, truncated: true, reasons: ["explicit_sensitive_value"] },
        limitations: [LIMITATIONS.REDACTED(withheld)],
      };

export const scanResults = async (
  deps: ScanToolDeps,
  input: ScanResultsInput,
  ctx: HandlerContext,
): Promise<Result<ScanResultsOutput, BeaError>> => {
  const { app, service, store } = deps;
  const rec = service.get(input.scan_id);
  if (rec === undefined || rec.state === "released") return err(missing(ctx.operation, input.scan_id));
  const stored = store.get(rec.id);
  const fromStore =
    !input.values && stored !== undefined && stored.iteration === rec.iteration && rec.state !== "running";
  const page = (total: number, nextOffset: number | null) => ({
    offset: input.offset,
    limit: input.limit,
    total,
    next_offset: nextOffset,
  });
  const envelopeOf = (extra: readonly string[], withheld = 0) => {
    const redacted = withheldParts(withheld);
    return {
      evidence_id: null,
      coverage: redacted.coverage === null ? scanCoverage(rec) : mergeCoverage(scanCoverage(rec), redacted.coverage),
      limitations: [...scanLimitations(rec), ...extra, ...redacted.limitations].slice(0, 64),
    };
  };
  if (fromStore) {
    return liveOp(app, ctx, rec.sessionId, { mode: "concurrent", need: "host" }, async (session, op) => {
      const hits = stored.hits.slice(input.offset, input.offset + input.limit);
      const { rows, withheld } = await describeRows(deps, { kind: "live", session }, op, rec.valueType, hits, false);
      const end = input.offset + hits.length;
      const extra = [
        SCAN_LIMITATIONS.SCAN_STORED_VALUES,
        ...(agentUsable(session) ? [] : [SCAN_LIMITATIONS.SCAN_HOST_STORE]),
      ];
      return ok({
        scan_id: rec.id,
        rows,
        page: page(stored.hits.length, end < stored.hits.length ? end : null),
        ...envelopeOf(extra, withheld),
      });
    });
  }
  return liveOp(app, ctx, rec.sessionId, { mode: "exclusive", need: "agent" }, async (session, op) => {
    const refreshed = await service.refresh(session, op, rec);
    if (!refreshed.ok) return refreshed;
    if (rec.state === "running")
      return err({
        _tag: "InvalidState",
        operation: ctx.operation,
        state: "running",
        expected: ["done"],
        remediation: `Wait for the scan with wait {"ids":["${rec.id}"]}.`,
      });
    if (rec.mode === "snapshot")
      return err(
        inputError(ctx.operation, [
          { path: "scan_id", reason: "invalid_value", message: SCAN_LIMITATIONS.SCAN_SNAPSHOT },
        ]),
      );
    const agentPage = await session.agent.call(
      "scanResults",
      { scan_id: rec.agentScanId, offset: input.offset, limit: input.limit, read_current: input.values },
      { op },
    );
    if (!agentPage.ok) return agentPage;
    const { rows, unreadable, withheld } = await describeRows(
      deps,
      { kind: "live", session },
      op,
      rec.valueType,
      agentPage.value.items,
      input.values,
    );
    const extra = [
      ...(input.values ? [] : [SCAN_LIMITATIONS.SCAN_STORED_VALUES]),
      ...(unreadable > 0 ? [SCAN_LIMITATIONS.SCAN_VALUE_UNREADABLE(unreadable)] : []),
    ];
    return ok({
      scan_id: rec.id,
      rows,
      page: page(agentPage.value.total, agentPage.value.next_offset),
      ...envelopeOf(extra, withheld),
    });
  });
};
