import { z } from "zod";

import { hexSchema } from "../hex.js";
import { evIdSchema, fxIdSchema, mmIdSchema, piIdSchema, sha256Schema, stIdSchema } from "../ids.js";
import { jsonObjectSchema } from "../json.js";
import { timeAnchorSchema } from "../time.js";

/** S2 §6.1. `class` drives perturbation.level: lifecycle=agent-only, observe=passive, modify/execute=intrusive. */
export const EFFECT_KINDS = [
  "process-spawned",
  "process-suspended",
  "process-resumed",
  "process-killed",
  "agent-injected",
  "hook-installed",
  "watch-armed",
  "trace-following",
  "override-installed",
  "memory-written",
  "code-patched",
  "protection-changed",
  "memory-allocated",
  "thread-context-set",
  "function-called",
  "script-run",
] as const;
export type EffectKind = (typeof EFFECT_KINDS)[number];
export type EffectClass = "lifecycle" | "observe" | "modify" | "execute";
export type EffectStatus = "active" | "revert-failed" | "reverted" | "expired" | "implicit-end" | "permanent";

export const EFFECT_KIND_TABLE: {
  readonly [K in EffectKind]: {
    readonly class: EffectClass;
    readonly reversible: boolean | "if-before-retained";
    readonly taintsWhenPermanent: boolean;
  };
} = {
  "process-spawned": { class: "lifecycle", reversible: false, taintsWhenPermanent: false },
  "process-suspended": { class: "lifecycle", reversible: true, taintsWhenPermanent: false },
  "process-resumed": { class: "lifecycle", reversible: false, taintsWhenPermanent: false },
  "process-killed": { class: "lifecycle", reversible: false, taintsWhenPermanent: false },
  "agent-injected": { class: "lifecycle", reversible: true, taintsWhenPermanent: false },
  "hook-installed": { class: "observe", reversible: true, taintsWhenPermanent: false },
  "watch-armed": { class: "observe", reversible: true, taintsWhenPermanent: false },
  "trace-following": { class: "observe", reversible: true, taintsWhenPermanent: false },
  "override-installed": { class: "modify", reversible: true, taintsWhenPermanent: true },
  "memory-written": { class: "modify", reversible: "if-before-retained", taintsWhenPermanent: true },
  "code-patched": { class: "modify", reversible: "if-before-retained", taintsWhenPermanent: true },
  "protection-changed": { class: "modify", reversible: true, taintsWhenPermanent: true },
  "memory-allocated": { class: "modify", reversible: true, taintsWhenPermanent: false },
  "thread-context-set": { class: "modify", reversible: false, taintsWhenPermanent: true },
  "function-called": { class: "execute", reversible: false, taintsWhenPermanent: true },
  "script-run": { class: "execute", reversible: false, taintsWhenPermanent: true },
};

const byteStateSchema = z.strictObject({
  bytes: z
    .number()
    .int()
    .min(0)
    .max(2 ** 32),
  sha256: sha256Schema.nullable(),
  hex: z
    .string()
    .regex(/^(?:[0-9a-f]{2})*$/u)
    .max(8192)
    .nullable(), // inline when <= 4096 bytes
  blob: sha256Schema.nullable(), // blob when > 4096 bytes
  retained: z.boolean(), // false: not persisted (redacted); revert still uses the in-memory copy
});
export const effectTargetSchema = z.strictObject({
  address: z
    .strictObject({
      va: hexSchema,
      module_map_id: mmIdSchema.nullable(),
      module_key: z.string().max(260).nullable(),
      rva: hexSchema.nullable(),
    })
    .nullable(),
  size: z
    .number()
    .int()
    .min(0)
    .max(2 ** 32)
    .nullable(),
  threads: z.union([z.literal("all"), z.array(z.number().int().min(0)).max(4096)]).nullable(),
});

export const effectSchema = z.strictObject({
  schema: z.literal("bea.effect/1"),
  effect_id: fxIdSchema,
  instance_id: piIdSchema,
  kind: z.enum(EFFECT_KINDS),
  class: z.enum(["lifecycle", "observe", "modify", "execute"]),
  reversible: z.boolean(),
  target: effectTargetSchema,
  parameters: jsonObjectSchema,
  before: byteStateSchema.nullable(), // >= 32 B at hook sites (S3 requirement)
  after: byteStateSchema.nullable(),
  lifetime: z
    .strictObject({
      duration_ms: z.number().int().min(1).max(86_400_000).nullable(),
      max_hits: z.number().int().min(1).max(1e9).nullable(),
    })
    .nullable(),
  stream_ids: z.array(stIdSchema).max(16),
  applied_by: z.string().regex(/^[a-z][a-z0-9_]{1,63}$/u), // tool name, never an evidence id (no hash cycle)
  applied_at: timeAnchorSchema, // its effect_epoch is the epoch AFTER this creation
  display: z.strictObject({ target_text: z.string().max(600).nullable() }), // excluded from the id
});
export type Effect = z.infer<typeof effectSchema>;

export const EFFECT_TRANSITION_REASONS = [
  "stop-requested",
  "lifetime-duration",
  "lifetime-max-hits",
  "session-close",
  "process-exited",
  "detached",
  "agent-unloaded",
  "resumed",
  "revert-error",
  "server-shutdown",
] as const;
export const effectTransitionSchema = z.strictObject({
  schema: z.literal("bea.effect-transition/1"),
  effect_id: fxIdSchema,
  from: z.enum(["active", "revert-failed"]),
  to: z.enum(["revert-failed", "reverted", "expired", "implicit-end"]),
  at: timeAnchorSchema,
  reason: z.enum(EFFECT_TRANSITION_REASONS),
  verification: z
    .strictObject({
      method: z.enum(["read-back", "agent-confirmed", "thread-context", "none"]),
      ok: z.boolean(),
      evidence_id: evIdSchema.nullable(),
    })
    .nullable(),
  residue: z.array(z.string().max(300)).max(8),
});
export type EffectTransition = z.infer<typeof effectTransitionSchema>;

/** Legal edges (S2 §6.3). Status is a fold over the creation record plus its transitions. */
export const EFFECT_EDGES: { readonly [F in "active" | "revert-failed"]: readonly EffectTransition["to"][] } = {
  active: ["reverted", "expired", "revert-failed", "implicit-end"],
  "revert-failed": ["reverted", "implicit-end", "revert-failed"],
};

export interface EffectState {
  readonly effect: Effect;
  readonly status: EffectStatus;
  readonly transitions: readonly EffectTransition[];
}
