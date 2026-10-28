import { effectSchema, effectTransitionSchema, type Effect, type EffectTransition } from "../effects/effect.js";
import type { BeaErrorOf } from "../errors/beaError.js";
import { idOf, type EvId, type FxId } from "../ids.js";
import type { JsonObject, JsonValue } from "../json.js";
import { err, ok, type Result } from "../result.js";
import { evidenceInvariantIssues } from "./invariants.js";
import { beaEvidenceSchema, type BeaEvidence } from "./record.js";

/**
 * Identity rules (S2 §2.4, §7.8). What enters an `ev_` id: the whole record except `evidence_id` and
 * `observed_at.wall`. What enters an `fx_` id: the effect except `effect_id`, `applied_at.wall` and `display`.
 * Authentication = strict schema + invariants + recomputed id; records are frozen after a successful parse.
 */
export type EvidenceIntegrityReason = BeaErrorOf<"EvidenceIntegrity">["reason"];

export const evidenceIntegrity = (
  operation: string,
  reason: EvidenceIntegrityReason,
  diagnostics?: JsonObject,
): BeaErrorOf<"EvidenceIntegrity"> => ({
  _tag: "EvidenceIntegrity",
  operation,
  reason,
  ...(diagnostics === undefined ? {} : { diagnostics }),
});

const withoutWall = (anchor: object): JsonObject => {
  const { wall: _wall, ...rest } = anchor as { readonly wall?: unknown } & JsonObject;
  return rest as JsonObject;
};

export const evidenceProjection = (e: Omit<BeaEvidence, "evidence_id">): JsonValue => {
  const {
    evidence_id: _id,
    observed_at,
    ...rest
  } = e as Omit<BeaEvidence, "evidence_id"> & {
    readonly evidence_id?: unknown;
  };
  return { ...(rest as unknown as JsonObject), observed_at: observed_at === null ? null : withoutWall(observed_at) };
};

export const evidenceIdOf = (e: Omit<BeaEvidence, "evidence_id">): EvId => idOf("ev", evidenceProjection(e));

export const deepFreeze = <T>(value: T): T => {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const item of Object.values(value as object)) deepFreeze(item);
  }
  return value;
};

/** Schema + invariants + id (S2 §7.8). The input is untrusted (a ledger line, a bundle line). */
export const authenticateEvidence = (
  input: unknown,
  operation = "evidence.authenticate",
): Result<BeaEvidence, BeaErrorOf<"EvidenceIntegrity">> => {
  const parsed = beaEvidenceSchema.safeParse(input);
  if (!parsed.success) return err(evidenceIntegrity(operation, "schema", { issue_count: parsed.error.issues.length }));
  const record = parsed.data as BeaEvidence;
  const issues = evidenceInvariantIssues(record);
  if (issues.length > 0)
    return err(evidenceIntegrity(operation, "schema", { invariant: issues[0]?.slice(0, 200) ?? "" }));
  if (evidenceIdOf(record) !== record.evidence_id)
    return err(evidenceIntegrity(operation, "id-mismatch", { evidence_id: record.evidence_id }));
  return ok(deepFreeze(record));
};

export const effectProjection = (e: Omit<Effect, "effect_id">): JsonValue => {
  const {
    effect_id: _id,
    display: _display,
    applied_at,
    ...rest
  } = e as Omit<Effect, "effect_id"> & {
    readonly effect_id?: unknown;
  };
  return { ...(rest as unknown as JsonObject), applied_at: withoutWall(applied_at) };
};

export const effectIdOf = (e: Omit<Effect, "effect_id">): FxId => idOf("fx", effectProjection(e));

export const authenticateEffect = (
  input: unknown,
  operation = "effect.authenticate",
): Result<Effect, BeaErrorOf<"EvidenceIntegrity">> => {
  const parsed = effectSchema.safeParse(input);
  if (!parsed.success) return err(evidenceIntegrity(operation, "schema", { issue_count: parsed.error.issues.length }));
  if (effectIdOf(parsed.data) !== parsed.data.effect_id)
    return err(evidenceIntegrity(operation, "id-mismatch", { effect_id: parsed.data.effect_id }));
  return ok(deepFreeze(parsed.data));
};

export const authenticateTransition = (
  input: unknown,
  operation = "effect.authenticate",
): Result<EffectTransition, BeaErrorOf<"EvidenceIntegrity">> => {
  const parsed = effectTransitionSchema.safeParse(input);
  return parsed.success
    ? ok(deepFreeze(parsed.data))
    : err(evidenceIntegrity(operation, "schema", { issue_count: parsed.error.issues.length }));
};
