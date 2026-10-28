import type { AddressRef } from "../../domain/address/addressRef.js";
import { canonicalDigest } from "../../domain/canonical.js";
import { EMU_PROTOCOL } from "../../domain/emuProtocol.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { COMPLETE, type Coverage } from "../../domain/evidence/coverage.js";
import type { PredicateType } from "../../domain/evidence/predicates.js";
import type { AgentIdentity, Authority, Subject } from "../../domain/evidence/record.js";
import type { JsonObject, JsonValue } from "../../domain/json.js";
import type { Result } from "../../domain/result.js";
import type { EmuRequestOptions, EmuSessionHandle } from "../../ports/emu.js";
import type { AnchorCapture, RecordedEvidence, SensitiveLiterals } from "../../ports/evidence.js";
import type { LiveSession, OperationContext } from "../../ports/sessions.js";
import { formatHex, type Hex } from "../../shared/hex.js";
import type { BeaApplication } from "../BeaApplication.js";
import type { HandlerContext } from "../handlerContext.js";

/**
 * Shared plumbing of the inspect services (WP-INSPECT): evidence drafts, the spread envelope (S2 §8.1, built from
 * the RECORDED result so redactions reach the caller), paging, emulator request options and compact address text.
 */

export type Page = {
  readonly offset: number;
  readonly limit: number;
  readonly total: number;
  readonly next_offset: number | null;
};
/** Paging is never coverage (S2 §8.1): `page{offset, limit, total, next_offset}`. */
export const pageOf = (offset: number, limit: number, total: number): Page => ({
  offset,
  limit,
  total,
  next_offset: offset + limit < total ? offset + limit : null,
});
export const sliceOf = <T>(rows: readonly T[], offset: number, limit: number): T[] =>
  rows.slice(offset, offset + limit);

/** Recorded envelope keys (contracts/schemas/envelope.ts recordedEnvelopeShape) from a recorded evidence line. */
export const recordedEnvelope = (rec: RecordedEvidence<JsonValue>) => {
  const r = rec.record;
  const subject = r.subject;
  const live = subject?.kind === "process-instance";
  const moduleMapId = subject !== null && subject.kind !== "image" ? subject.module_map_id : null;
  return {
    evidence_id: r.evidence_id,
    predicate_type: r.predicate_type,
    confidence: r.confidence,
    authority: r.authority,
    coverage: r.coverage,
    limitations: [...r.limitations],
    ...(live ? { instance_id: subject.instance_id } : {}),
    ...(moduleMapId !== null ? { module_map_id: moduleMapId } : {}),
    ...(r.observed_at !== null
      ? {
          observed_at: {
            seq: r.observed_at.seq,
            effect_epoch: r.observed_at.effect_epoch,
            module_map_epoch: r.observed_at.module_map_epoch,
          },
        }
      : {}),
    ...(live
      ? {
          perturbation: {
            level: r.perturbation.level,
            active_effect_ids: [...r.perturbation.active_effect_ids],
            tainted: r.perturbation.tainted_by.length > 0,
          },
        }
      : {}),
    ...(r.effects.length > 0 ? { effects_applied: [...r.effects] } : {}),
    ...(r.redactions.length > 0 ? { redactions: r.redactions.length } : {}),
  };
};

/** The recorded result spread with its envelope (the caller's output schema validates the whole object). */
export const deliver = <R extends JsonValue>(
  rec: RecordedEvidence<R>,
): JsonObject & ReturnType<typeof recordedEnvelope> =>
  ({ ...(rec.record.result as JsonObject), ...recordedEnvelope(rec) }) as JsonObject &
    ReturnType<typeof recordedEnvelope>;

export const FRIDA_PROVIDER = { id: "frida", name: "frida", version: null } as const;
export const emulatorProvider = (app: BeaApplication) =>
  ({
    id: "unicorn",
    name: "unicorn",
    version: app.services.emulator.availability().versions?.unicorn ?? null,
  }) as const;

/** Server-level + per-call sensitive literals (S2 §15); a literal shorter than 4 UTF-8 bytes is invalid_request. */
export const literalsOf = (app: BeaApplication, perCall?: readonly string[]): Result<SensitiveLiterals, BeaError> =>
  app.services.evidence.literals(perCall);

/** One tool call of the area: the application and the handler context (MCP, CLI or scenario). */
export interface InspectCall {
  readonly app: BeaApplication;
  readonly ctx: HandlerContext;
}
/** A call with its validated input and its sensitive literals. */
export interface InspectRequest<I> extends InspectCall {
  readonly input: I;
  readonly literals: SensitiveLiterals;
}

export interface DraftParts<R extends JsonValue> {
  readonly predicate: PredicateType;
  readonly input: JsonObject;
  readonly result: R;
  readonly coverage?: Coverage;
  readonly limitations?: readonly string[];
  readonly literals: SensitiveLiterals;
  /** SEC-3: /result pointers withheld because the raw bytes behind them contained a literal */
  readonly pre_redactions?: readonly string[];
}

/** Record one live observation (anchored, process-instance subject). */
export const recordLive = <R extends JsonValue>(
  { app, ctx }: InspectCall,
  session: LiveSession,
  capture: AnchorCapture,
  parts: DraftParts<R>,
): Promise<Result<RecordedEvidence<R>, BeaError>> => {
  const evidence = app.services.evidence;
  const agent: AgentIdentity | null = evidence.instances.get(session.instanceId)?.agent ?? null;
  return evidence.recorder.record({
    predicate_type: parts.predicate,
    operation: ctx.operation,
    input: parts.input,
    subject: { kind: "process-instance", instance_id: session.instanceId },
    capture,
    provider: FRIDA_PROVIDER,
    agent,
    authority: "live-process",
    result: parts.result,
    coverage: parts.coverage ?? COMPLETE,
    limitations: parts.limitations ?? [],
    literals: parts.literals,
    ...(parts.pre_redactions === undefined ? {} : { pre_redactions: parts.pre_redactions }),
  });
};

/**
 * The emulation subject of a record made on an emulation session (S2 §7.2). The EmuPort exposes no subject of its
 * own (change request: `EmuPort.subject(h)`), so it is derived here from the session's primary module and engine
 * versions; the state basis is `chained` because the session may have run calls since its baseline. Null when the
 * primary image has no digest (the Recorder then adds SUBJECT_UNAVAILABLE).
 */
export const emulationSubject = (app: BeaApplication, handle: EmuSessionHandle): Subject | null => {
  const emulator = app.services.emulator;
  const primary = emulator.modules(handle).find((m) => m.primary);
  if (primary?.sha256 === null || primary?.sha256 === undefined || !/^[a-f0-9]{64}$/u.test(primary.sha256)) return null;
  const versions = emulator.availability().versions;
  return {
    kind: "emulation",
    image_sha256: primary.sha256,
    config_digest: canonicalDigest({
      t: "bea.inspect.emu-config/1",
      protocol: EMU_PROTOCOL,
      engines: versions === null ? null : { ...versions },
      image_sha256: primary.sha256,
      mapped_base: primary.base,
      preferred_base: primary.preferredBase,
    }),
    state: { basis: "chained" },
    module_map_id: null,
  };
};

/** Record one emulation observation (no anchor; authority emulation; S5 §11 / D-INT-19). */
export const recordEmulation = <R extends JsonValue>(
  { app, ctx }: InspectCall,
  handle: EmuSessionHandle,
  parts: DraftParts<R>,
): Promise<Result<RecordedEvidence<R>, BeaError>> => {
  const subject = emulationSubject(app, handle);
  const authority: Authority = "emulation";
  return app.services.evidence.recorder.record({
    predicate_type: parts.predicate,
    operation: ctx.operation,
    input: parts.input,
    subject,
    provider: emulatorProvider(app),
    agent: null,
    confidence: "observed",
    authority,
    result: parts.result,
    coverage: parts.coverage ?? COMPLETE,
    limitations: parts.limitations ?? [],
    literals: parts.literals,
    ...(parts.pre_redactions === undefined ? {} : { pre_redactions: parts.pre_redactions }),
  });
};

/** Bridge request options from an admitted operation. */
export const emuOptions = (op: OperationContext): EmuRequestOptions => ({
  signal: op.signal,
  deadlineAt: performance.now() + op.deadline.remaining(),
});

/** Validated tool input as the Recorder's `input` (zod drops absent optionals, so it is plain JSON). */
export const jsonInput = (input: object): JsonObject => input as unknown as JsonObject;
/** A result built from schema-typed rows as the Recorder's JSON result (the output schema re-validates it). */
export const jsonResult = (result: object): JsonObject => result as unknown as JsonObject;

/** "module+0xrva" / "module@0xbase+0xrva" → {module token, rva}; null for "0x…" or null text. */
export const splitAt = (at: string | null): { readonly module: string; readonly rva: Hex } | null => {
  if (at === null) return null;
  const plus = at.lastIndexOf("+0x");
  if (plus <= 0) return null;
  const rva = at.slice(plus + 1);
  return /^0x[0-9a-f]+$/u.test(rva) ? { module: at.slice(0, plus), rva: rva as Hex } : null;
};

/** Reference text of a code/data target: "at static", "at", or the bare VA outside images (S6 §4.13). */
export const refText = (addr: {
  readonly va: Hex;
  readonly at: string | null;
  readonly static: string | null;
}): string => [addr.at, addr.static].filter((part): part is string => part !== null).join(" ") || addr.va;

export const clip = (text: string, max: number): string => (text.length <= max ? text : text.slice(0, max));

/** A minimal AddressRef for a VA that resolution could not describe (heap/stack targets of a pointer chain). */
export const bareRef = (va: bigint): AddressRef => ({
  va: formatHex(va),
  module: null,
  rva: null,
  static_va: null,
  static_base: null,
  static_base_source: null,
  module_map_id: null,
});
