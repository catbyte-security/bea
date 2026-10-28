import { z } from "zod";

import { hexSchema } from "../hex.js";
import { evIdSchema, fxIdSchema, mmIdSchema, piIdSchema, sha256Schema } from "../ids.js";
import { jsonObjectSchema, jsonValueSchema, type JsonValue } from "../json.js";
import { timeAnchorSchema } from "../time.js";
import { coverageSchema } from "./coverage.js";

// ---------------------------------------------------------------- perturbation (S2 §6.5)
export const perturbationSchema = z.strictObject({
  level: z.enum(["none", "agent-only", "passive", "intrusive"]),
  /** sorted; active ∪ revert-failed, excluding the session's own agent-injected effect */
  active_effect_ids: z.array(fxIdSchema).max(256),
  /** sorted; permanent taint effects + revert-failed modify effects */
  tainted_by: z.array(fxIdSchema).max(256),
});
export type Perturbation = z.infer<typeof perturbationSchema>;
export const NO_PERTURBATION: Perturbation = { level: "none", active_effect_ids: [], tainted_by: [] };

// ---------------------------------------------------------------- subjects (S2 §7.2)
export const subjectSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("process-instance"),
    instance_id: piIdSchema,
    module_map_id: mmIdSchema.nullable(),
  }),
  z.strictObject({
    kind: z.literal("image"),
    image_sha256: sha256Schema,
    format: z.enum(["pe32+", "pe32", "elf64", "unknown"]),
    machine: z.enum(["x64", "x86", "arm64", "unknown"]),
  }),
  z.strictObject({
    kind: z.literal("emulation"),
    image_sha256: sha256Schema,
    /** digestCanonical({protocol, bridge, engines, image_sha256, mapped_base, options}) from session.open provenance */
    config_digest: sha256Schema,
    state: z.discriminatedUnion("basis", [
      z.strictObject({ basis: z.literal("baseline") }),
      z.strictObject({ basis: z.literal("snapshot"), snapshot_digest: sha256Schema }),
      z.strictObject({ basis: z.literal("chained") }),
      z.strictObject({ basis: z.literal("dump"), dump_digest: sha256Schema }),
    ]),
    module_map_id: mmIdSchema.nullable(),
  }),
]);
export type Subject = z.infer<typeof subjectSchema>;

// ---------------------------------------------------------------- locations, refs, blobs (S2 §7.7)
export const locationSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("address"),
    va: hexSchema,
    size: z
      .number()
      .int()
      .min(1)
      .max(2 ** 32)
      .nullable(),
    module_map_id: mmIdSchema.nullable(),
    module_key: z.string().max(260).nullable(),
    rva: hexSchema.nullable(),
    image_sha256: sha256Schema.nullable(),
  }),
  z.strictObject({
    kind: z.literal("thread"),
    thread_id: z
      .number()
      .int()
      .min(0)
      .max(2 ** 32 - 1),
  }),
  z.strictObject({
    kind: z.literal("file"),
    image_sha256: sha256Schema,
    offset: hexSchema,
    size: z.number().int().min(1).nullable(),
  }),
]);
export type Location = z.infer<typeof locationSchema>;

export const blobRefSchema = z.strictObject({
  role: z.string().regex(/^[a-z][a-z0-9_.-]{0,63}$/u),
  sha256: sha256Schema,
  bytes: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
  media_type: z.string().min(1).max(100),
});
export type BlobRef = z.infer<typeof blobRefSchema>;

export const externalRefSchema = z.strictObject({
  system: z.enum(["rea", "ghidra", "ida", "binja", "other"]),
  id: z.string().min(1).max(256),
  image_sha256: sha256Schema.nullable(),
});
export type ExternalRef = z.infer<typeof externalRefSchema>;

export const redactionSchema = z.strictObject({
  pointer: z.string().max(512),
  reason: z.literal("explicit-sensitive-value"),
  scope: z.enum(["value", "property-name", "blob", "batch", "parameter"]),
});

// ---------------------------------------------------------------- the record (S2 §7.1)
export const confidenceSchema = z.enum(["observed", "derived", "inferred"]);
export type Confidence = z.infer<typeof confidenceSchema>;
export const authoritySchema = z.enum([
  "live-process",
  "emulation",
  "static-artifact",
  "imported",
  "analyst-inference",
]);
export type Authority = z.infer<typeof authoritySchema>;
export const CONFIDENCE_RANK = { inferred: 1, derived: 2, observed: 3 } as const;
/** strongest first; `weakest-parent` derivations take the weakest of their parents */
export const AUTHORITY_TRUST = [
  "live-process",
  "emulation",
  "static-artifact",
  "imported",
  "analyst-inference",
] as const;

export const providerSchema = z.strictObject({
  id: z.enum(["frida", "unicorn", "bea-pe", "bea"]),
  name: z.string().min(1).max(64),
  version: z.string().max(64).nullable(),
});
export const agentIdentitySchema = z.strictObject({
  bundle_sha256: sha256Schema,
  bea_version: z.string().max(32),
  runtime: z.enum(["qjs", "v8"]),
});
export type AgentIdentity = z.infer<typeof agentIdentitySchema>;

export const PREDICATE_TYPE_RE = /^bea(?:\.[a-z][a-z0-9-]*){1,4}$/u;

/**
 * Structural schema of `bea.evidence/1`. The cross-field invariants (S2 §7.1 items 1–9) live in
 * src/domain/evidence/invariants.ts (WP-EVID) and are applied by the Recorder and by authenticate().
 */
export const beaEvidenceSchema = z.strictObject({
  schema: z.literal("bea.evidence/1"),
  evidence_id: evIdSchema,
  predicate_type: z.string().regex(PREDICATE_TYPE_RE).max(64),
  operation: z.string().regex(/^[a-z][a-z0-9_]{1,63}$/u),
  parameters: jsonObjectSchema,
  subject: subjectSchema.nullable(),
  observed_at: timeAnchorSchema.nullable(),
  provider: providerSchema,
  agent: agentIdentitySchema.nullable(),
  confidence: confidenceSchema,
  authority: authoritySchema,
  perturbation: perturbationSchema,
  result: jsonValueSchema,
  raw_result: jsonValueSchema.nullable(),
  blobs: z.array(blobRefSchema).max(64),
  coverage: coverageSchema,
  limitations: z.array(z.string().min(1).max(1000)).max(64),
  locations: z.array(locationSchema).max(1024),
  evidence_links: z.array(evIdSchema).max(4096),
  external_refs: z.array(externalRefSchema).max(64),
  effects: z.array(fxIdSchema).max(64),
  redactions: z.array(redactionSchema).max(1024),
  untrusted: z.boolean(),
});
export type BeaEvidence<R extends JsonValue = JsonValue> = Omit<z.infer<typeof beaEvidenceSchema>, "result"> & {
  readonly result: R;
};
