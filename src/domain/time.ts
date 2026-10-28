import { z } from "zod";

import { runIdSchema, type RunId } from "./ids.js";

/**
 * When an observation happened (S2 §3). run_id + seq enter every live id, so two live reads never merge, even
 * across runs. Only `wall` is excluded from ids. `seq` is run-global (SequenceAllocator in clock.ts).
 */
export interface TimeAnchor {
  readonly run_id: RunId;
  readonly seq: number;
  /** process.hrtime.bigint() at capture, decimal. */
  readonly mono_ns: string;
  /** ISO-8601 UTC; display only; excluded from every id. */
  readonly wall: string;
  /** Perturbation version of the subject instance (null: no live instance). */
  readonly effect_epoch: number | null;
  /** Agent module-map epoch mirrored by the host (null: no live instance). */
  readonly module_map_epoch: number | null;
}
export interface CompactAnchor {
  readonly seq: number;
  readonly effect_epoch: number | null;
  readonly module_map_epoch: number | null;
}

export const timeAnchorSchema = z
  .strictObject({
    run_id: runIdSchema,
    seq: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
    mono_ns: z.string().regex(/^\d{1,20}$/u),
    wall: z.iso.datetime(),
    effect_epoch: z
      .number()
      .int()
      .min(0)
      .max(2 ** 31)
      .nullable(),
    module_map_epoch: z
      .number()
      .int()
      .min(0)
      .max(2 ** 31)
      .nullable(),
  })
  .refine((a) => (a.effect_epoch === null) === (a.module_map_epoch === null), "epochs are both null or both set");

export const compactAnchorSchema = z.strictObject({
  seq: z.number().int().min(1),
  effect_epoch: z.number().int().min(0).nullable(),
  module_map_epoch: z.number().int().min(0).nullable(),
});

/** S3 TimeMark: host-side instant before S2 assigns seq/epochs. */
export interface TimeMark {
  readonly monoNs: string;
  readonly wall: string;
}

export const compactOf = (a: TimeAnchor): CompactAnchor => ({
  seq: a.seq,
  effect_epoch: a.effect_epoch,
  module_map_epoch: a.module_map_epoch,
});
