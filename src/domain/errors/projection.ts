import { z } from "zod";

import { jsonObjectSchema, type JsonObject, type JsonValue } from "../json.js";
import type { BeaError } from "./beaError.js";
import {
  BEA_ERROR_CATEGORIES,
  BEA_ERROR_CODES,
  specFor,
  type BeaErrorCategory,
  type BeaErrorCode,
  type BeaErrorRecovery,
} from "./errorCatalog.js";

/** REA-compatible wire shape: {code, category, message, retryable, remediation:{action}, recovery?, details?}. */
export interface BeaErrorProjection {
  readonly code: BeaErrorCode;
  readonly category: BeaErrorCategory;
  readonly message: string;
  readonly retryable: boolean;
  readonly remediation: { readonly action: string };
  readonly recovery?: BeaErrorRecovery;
  /** BEA always sends details: effects_applied is never omitted (D6). */
  readonly details: JsonObject;
}

const CLEANUP_REMEDIATION =
  "BEA still owns resources it could not release (details.cleanup_resources). Retry close_session or stop_instrumentation; if the target is BEA-owned, closing its session kills it. Do not assume the target is unmodified.";

export const projectBeaError = (error: BeaError): BeaErrorProjection => {
  const spec = specFor(error);
  const cleanupIncomplete = error.cleanup?.status === "incomplete";
  const recovery = cleanupIncomplete ? undefined : spec.recovery?.(error);
  const details: Record<string, JsonValue> = {
    ...spec.details(error),
    effects_applied: [...(error.effects_applied ?? [])],
  };
  if (error.instance_id !== undefined) details["instance_id"] = error.instance_id;
  if (error.diagnostics !== undefined) details["diagnostics"] = error.diagnostics;
  if (error.partial !== undefined) details["partial_observation"] = { ...error.partial };
  if (cleanupIncomplete && error.cleanup !== undefined) {
    details["cleanup"] = "incomplete";
    details["cleanup_resources"] = [...error.cleanup.resources];
    details["cleanup_reason"] = error.cleanup.reason;
    details["execution_failure"] = spec.code;
  }
  return {
    code: cleanupIncomplete ? "cleanup_incomplete" : spec.code,
    category: cleanupIncomplete ? "execution_failure" : spec.category,
    message: error.message ?? spec.message(error),
    retryable: cleanupIncomplete ? false : spec.retryable(error),
    remediation: {
      action: cleanupIncomplete ? CLEANUP_REMEDIATION : (error.remediation ?? spec.remediation(error)),
    },
    ...(recovery === undefined ? {} : { recovery }),
    details,
  };
};

/** Strict schema of the projection: tests, `bea mcp doctor`, docs/error-contract.schema.json. */
export const beaErrorProjectionSchema = z.strictObject({
  code: z.enum(BEA_ERROR_CODES),
  category: z.enum(BEA_ERROR_CATEGORIES),
  message: z.string().min(1).max(2000),
  retryable: z.boolean(),
  remediation: z.strictObject({ action: z.string().min(1).max(2000) }),
  recovery: z
    .discriminatedUnion("kind", [
      z.strictObject({ kind: z.literal("inspect_input_contract"), operation: z.string() }),
      z.strictObject({
        kind: z.literal("inspect_timeout_state"),
        operation: z.string(),
        timeout_ms: z.number().int().min(0).max(3_600_000),
      }),
      z.strictObject({ kind: z.literal("reattach"), previous_instance_id: z.string() }),
      z.strictObject({ kind: z.literal("refresh_module_map"), instance_id: z.string().nullable() }),
      z.strictObject({ kind: z.literal("revert_effects"), effect_ids: z.array(z.string()) }),
    ])
    .optional(),
  details: jsonObjectSchema,
});

/** The MCP/CLI error envelope: `{"error": projection}`. */
export const beaErrorEnvelopeSchema = z.strictObject({ error: beaErrorProjectionSchema });
