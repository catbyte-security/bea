import { z } from "zod";

import { coverageSchema } from "../../domain/evidence/coverage.js";
import { authoritySchema, confidenceSchema, perturbationSchema } from "../../domain/evidence/record.js";
import { evIdSchema, fxIdSchema, mmIdSchema, piIdSchema } from "../../domain/ids.js";
import { jsonObjectSchema } from "../../domain/json.js";
import { compactAnchorSchema } from "../../domain/time.js";

/**
 * The spread result envelope (S2 §8; DESIGN conflict C-02). structuredContent = the envelope; MCP text =
 * JSON.stringify(envelope). Result fields are spread at the top level and may not use these reserved keys
 * (defineTool throws). Errors never use the envelope (they use the error projection).
 */
export const ENVELOPE_RESERVED_KEYS = [
  "evidence_id",
  "predicate_type",
  "confidence",
  "authority",
  "coverage",
  "limitations",
  "instance_id",
  "module_map_id",
  "observed_at",
  "perturbation",
  "effects_applied",
  "redactions",
  "next",
] as const;

export const nextStepSchema = z.strictObject({
  tool: z.string().regex(/^[a-z][a-z0-9_]{1,63}$/u),
  /** must parse with the target tool's input schema (contract test) */
  arguments: jsonObjectSchema,
  /** BEA-authored, never target text */
  reason: z.string().min(1).max(200),
});
export type NextStep = z.infer<typeof nextStepSchema>;

/** Paging is never coverage: page{} sits beside coverage. */
export const pageSchema = z.strictObject({
  offset: z.number().int().min(0),
  limit: z.number().int().min(0),
  total: z.number().int().min(0),
  next_offset: z.number().int().min(0).nullable(),
});

export const recordedEnvelopeShape = {
  evidence_id: evIdSchema,
  predicate_type: z.string().max(64),
  confidence: confidenceSchema,
  authority: authoritySchema,
  coverage: coverageSchema,
  limitations: z.array(z.string()).max(64),
  instance_id: piIdSchema.exactOptional(),
  module_map_id: mmIdSchema.exactOptional(),
  observed_at: compactAnchorSchema.exactOptional(),
  perturbation: z
    .strictObject({
      level: perturbationSchema.shape.level,
      active_effect_ids: z.array(fxIdSchema).max(256),
      tainted: z.boolean(),
    })
    .exactOptional(),
  /** present iff non-empty */
  effects_applied: z.array(fxIdSchema).max(64).exactOptional(),
  /** count; present iff > 0 */
  redactions: z.number().int().min(1).exactOptional(),
  next: z.array(nextStepSchema).max(3).exactOptional(),
} as const;

export const pollEnvelopeShape = {
  evidence_id: z.null(),
  coverage: coverageSchema,
  limitations: z.array(z.string()).max(64),
  next: z.array(nextStepSchema).max(3).exactOptional(),
} as const;

/** A tool that records may still return a poll on some paths (e.g. session_status detail summary). */
export const maybeRecordedEnvelopeShape = {
  ...recordedEnvelopeShape,
  evidence_id: evIdSchema.nullable(),
  predicate_type: z.string().max(64).nullable(),
  confidence: confidenceSchema.nullable(),
  authority: authoritySchema.nullable(),
} as const;

export class ReservedKeyError extends Error {
  override readonly name = "ReservedKeyError";
}
const assertNoReservedKeys = (shape: z.ZodRawShape): void => {
  for (const key of ENVELOPE_RESERVED_KEYS)
    if (Object.hasOwn(shape, key)) throw new ReservedKeyError(`result field "${key}" is an envelope reserved key`);
};

export const recordedOutput = <S extends z.ZodRawShape>(result: S) => {
  assertNoReservedKeys(result);
  return z.strictObject({ ...result, ...recordedEnvelopeShape });
};
export const pollOutput = <S extends z.ZodRawShape>(result: S) => {
  assertNoReservedKeys(result);
  return z.strictObject({ ...result, ...pollEnvelopeShape });
};
export const maybeRecordedOutput = <S extends z.ZodRawShape>(result: S) => {
  assertNoReservedKeys(result);
  return z.strictObject({ ...result, ...maybeRecordedEnvelopeShape });
};

/** Envelope keys every output root must carry (defineTool check). */
export const REQUIRED_ENVELOPE_KEYS = ["evidence_id", "coverage", "limitations"] as const;
