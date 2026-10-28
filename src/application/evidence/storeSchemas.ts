import { z } from "zod";

import { hexSchema } from "../../domain/hex.js";
import { evIdSchema, mmIdSchema, piIdSchema, runIdSchema, sha256Schema, stIdSchema } from "../../domain/ids.js";
import { processIdentitySchema } from "../../domain/process/instance.js";

/**
 * zod schemas of the evidence store's on-disk formats (WP-EVID): `bea.run/1` (run.json), the ledger line envelope
 * (S2 §9.3), module-map lines and `bea.bundle/1` (S2 §13.1). They live in the application layer because
 * src/providers/** may not import zod (module-boundary table, §4.1); the providers parse with them.
 */

// ---------------------------------------------------------------- run.json (S2 §9.2)
export const RUN_KINDS = ["mcp-stdio", "mcp-http", "cli"] as const;
export type RunKind = (typeof RUN_KINDS)[number];

export const runHeaderSchema = z.strictObject({
  schema: z.literal("bea.run/1"),
  run_id: runIdSchema,
  kind: z.enum(RUN_KINDS),
  bea_version: z.string().max(64),
  node: z.string().max(64),
  platform: z.enum(["win32", "linux", "darwin"]),
  pid: z.number().int().min(0),
  started_wall: z.iso.datetime(),
  ended_wall: z.iso.datetime().nullable(),
  status: z.enum(["open", "closed", "crashed"]),
  quotas: z.strictObject({
    ledger_bytes: z.number().int(),
    ledger_reserve_bytes: z.number().int(),
    stream_bytes: z.number().int(),
    stream_total_bytes: z.number().int(),
    blob_bytes: z.number().int(),
  }),
  final: z
    .strictObject({
      ledger_bytes: z.number().int(),
      /** null when the ledger was too large to hash inside the shutdown budget */
      ledger_sha256: sha256Schema.nullable(),
      lines: z.number().int(),
      evidence: z.number().int(),
      effects: z.number().int(),
      blobs: z.number().int(),
      blob_bytes: z.number().int(),
      streams: z.number().int(),
      /** CT-M6: appends refused after the finalize fence */
      late_appends: z.number().int(),
    })
    .nullable(),
});
export type RunHeader = z.infer<typeof runHeaderSchema>;
export type RunFinal = NonNullable<RunHeader["final"]>;

// ---------------------------------------------------------------- ledger lines (S2 §9.3)
export const moduleMapSchema = z.strictObject({
  module_map_id: mmIdSchema,
  instance_id: piIdSchema,
  completeness: z.enum(["complete", "partial"]),
  modules: z
    .array(
      z.strictObject({
        base: hexSchema,
        size: z
          .number()
          .int()
          .min(0)
          .max(2 ** 32),
        path_sha256: sha256Schema,
        display: z.strictObject({ name: z.string().max(260).nullable(), path: z.string().max(4096).nullable() }),
      }),
    )
    .max(65_536),
});

const countsSchema = z.strictObject({
  instances: z.number().int().min(0),
  module_maps: z.number().int().min(0),
  effects: z.number().int().min(0),
  effect_transitions: z.number().int().min(0),
  unknown_revisions: z.number().int().min(0),
  evidence: z.number().int().min(0),
});

export const ledgerLineEnvelopeSchema = z.discriminatedUnion("t", [
  z.strictObject({
    t: z.literal("run"),
    run_id: runIdSchema,
    bea_version: z.string().max(64),
    started_wall: z.string(),
  }),
  z.strictObject({
    t: z.literal("pi"),
    instance_id: piIdSchema,
    identity: processIdentitySchema,
    ownership: z.enum(["owned", "attached"]),
    display: z.strictObject({ image_name: z.string().max(260).nullable() }),
  }),
  z.strictObject({ t: z.literal("mm"), module_map: moduleMapSchema }),
  z.strictObject({ t: z.literal("fx"), effect: z.unknown() }),
  z.strictObject({ t: z.literal("fxt"), transition: z.unknown() }),
  z.strictObject({ t: z.literal("ev"), record: z.unknown() }),
  z.strictObject({ t: z.literal("unk"), revision: z.unknown() }),
  z.strictObject({
    t: z.literal("import-begin"),
    import_id: z.string().regex(/^imp_[0-9a-f]{16}$/u),
    bundle_digest: sha256Schema,
    source_runs: z.array(runIdSchema).max(1024),
  }),
  z.strictObject({
    t: z.literal("import-commit"),
    import_id: z.string().regex(/^imp_[0-9a-f]{16}$/u),
    counts: countsSchema,
  }),
  z.strictObject({ t: z.literal("end"), ended_wall: z.string(), counts: z.record(z.string(), z.number()) }),
]);

// ---------------------------------------------------------------- bundles (S2 §13.1)
export const bundleManifestSchema = z.strictObject({
  schema: z.literal("bea.bundle/1"),
  bundle_digest: sha256Schema,
  producer: z.strictObject({ name: z.literal("bea"), version: z.string().max(64) }),
  created_wall: z.iso.datetime(),
  source_runs: z.array(runIdSchema).min(1).max(1024),
  selection: z.strictObject({
    kind: z.enum(["run", "instance", "closure"]),
    instance_id: piIdSchema.nullable(),
    roots: z.array(evIdSchema).max(1024),
  }),
  records: z.strictObject({
    path: z.literal("records.jsonl"),
    sha256: sha256Schema,
    bytes: z.number().int().min(0),
    lines: z.number().int().min(0),
  }),
  counts: z.strictObject({
    instances: z.number().int().min(0),
    module_maps: z.number().int().min(0),
    effects: z.number().int().min(0),
    effect_transitions: z.number().int().min(0),
    unknown_revisions: z.number().int().min(0),
    evidence: z.number().int().min(0),
  }),
  blobs_included: z.boolean(),
  blobs: z.array(z.strictObject({ sha256: sha256Schema, bytes: z.number().int().min(0) })),
  streams: z.array(
    z.strictObject({
      stream_id: stIdSchema,
      descriptor_sha256: sha256Schema,
      head_chain: sha256Schema,
      chunks: z.number().int().min(0),
      bytes: z.number().int().min(0),
      included: z.enum(["all", "manifests-only"]),
    }),
  ),
});
export type BundleManifest = z.infer<typeof bundleManifestSchema>;
