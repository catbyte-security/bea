import { z } from "zod";

import { EFFECT_KINDS } from "../../domain/effects/effect.js";
import { authoritySchema, confidenceSchema } from "../../domain/evidence/record.js";
import { hexInputSchema } from "../../domain/hex.js";
import {
  ANY_LEDGER_ID_RE,
  evIdSchema,
  fxIdSchema,
  mmIdSchema,
  piIdSchema,
  sha256Schema,
  stIdSchema,
  unkIdSchema,
} from "../../domain/ids.js";
import { jsonObjectSchema } from "../../domain/json.js";
import { fx } from "../effects.js";
import { pageSchema, pollOutput, recordedOutput } from "../schemas/envelope.js";
import { sessionIdSchema } from "../schemas/primitives.js";
import { defineTool, type ToolContract } from "../toolContract.js";

/**
 * Area evidence (WP-EVID; DESIGN §6.2 L #34–#37, S2 §12–§14). get_evidence / export_evidence / import_evidence are
 * polls (they record nothing); record_unknown records bea.unknown.mutation.
 */
const SAMPLE_EV = `ev_${"a".repeat(64)}`;
const SAMPLE_UNK = `unk_${"b".repeat(64)}`;
/** S2 §12.2 slice page sizes: rows of a retained table per page; binary slices count KiB. */
export const SLICE_ITEMS_MAX = 15;
export const SLICE_KIB_MAX = 64;

const STATUSES = [
  "active",
  "revert-failed",
  "reverted",
  "expired",
  "implicit-end",
  "permanent",
  "open",
  "investigating",
  "blocked",
  "contradicted",
  "resolved",
] as const;

const seqSchema = z.number().int().min(1).max(Number.MAX_SAFE_INTEGER);

export const evidenceFiltersSchema = z.strictObject({
  evidence_id: evIdSchema.optional(),
  instance_id: piIdSchema.optional(),
  predicate_type: z.string().max(64).optional(),
  operation: z.string().max(64).optional(),
  applied_effect_id: fxIdSchema.optional(),
  under_effect_id: fxIdSchema.optional(),
  stream_id: stIdSchema.optional(),
  module_map_id: mmIdSchema.optional(),
  links_to: evIdSchema.optional(),
  seq_from: seqSchema.optional(),
  seq_to: seqSchema.optional(),
  confidence: confidenceSchema.optional(),
  authority: authoritySchema.optional(),
  coverage_status: z.enum(["complete", "partial", "unknown"]).optional(),
  origin: z.enum(["local", "imported"]).optional(),
  module: z.string().min(1).max(260).optional(),
  image_sha256: sha256Schema.optional(),
  rva_from: hexInputSchema.optional(),
  rva_to: hexInputSchema.optional(),
  va_from: hexInputSchema.optional(),
  va_to: hexInputSchema.optional(),
  status: z.enum(STATUSES).optional(),
  severity: z.enum(["low", "medium", "high", "critical"]).optional(),
  domain: z.string().max(64).optional(),
});

export const getEvidenceInputSchema = z
  .strictObject({
    detail: z.enum(["summary", "complete", "slice"]).default("summary"),
    entity: z.enum(["evidence", "effects", "unknowns", "instances"]).default("evidence"),
    id: z.string().regex(ANY_LEDGER_ID_RE).optional(),
    filters: evidenceFiltersSchema.optional(),
    pointer: z.string().min(1).max(256).optional(),
    offset: z.number().int().min(0).max(1_000_000_000).default(0),
    limit: z.number().int().min(1).max(500).default(50),
    format: z.enum(["hex", "base64"]).default("hex"),
  })
  .superRefine((v, ctx) => {
    if (v.detail !== "summary" && v.filters !== undefined)
      ctx.addIssue({ code: "custom", path: ["filters"], message: "filters are valid only with detail: summary" });
    if (v.detail !== "summary" && v.entity !== "evidence")
      ctx.addIssue({ code: "custom", path: ["entity"], message: "entity is valid only with detail: summary" });
    if (v.detail !== "summary" && v.id === undefined)
      ctx.addIssue({ code: "custom", path: ["id"], message: "id is required for detail complete and slice" });
    // review fix UX-6: an id with the default summary view was silently ignored (unrelated rows came back)
    if (v.detail === "summary" && v.id !== undefined)
      ctx.addIssue({
        code: "custom",
        path: ["id"],
        message:
          'id needs detail: "complete" (the record) or "slice" with a pointer. To filter summary rows use filters.evidence_id.',
      });
    if (v.detail === "slice" && (v.pointer === undefined || v.id?.startsWith("ev_") !== true))
      ctx.addIssue({
        code: "custom",
        path: ["pointer"],
        message: 'detail slice needs an ev_ id and a pointer ("/result/rows" or "#blob:<role>")',
      });
    if (v.detail !== "slice" && v.pointer !== undefined)
      ctx.addIssue({ code: "custom", path: ["pointer"], message: "pointer is valid only with detail: slice" });
  });

const count = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const evidenceRowSchema = z.strictObject({
  kind: z.literal("evidence"),
  evidence_id: evIdSchema,
  n: count,
  predicate_type: z.string().max(64),
  operation: z.string().max(64),
  instance_id: piIdSchema.nullable(),
  seq: count.nullable(),
  confidence: confidenceSchema,
  authority: authoritySchema,
  coverage_status: z.enum(["complete", "partial", "unknown"]),
  truncated: z.boolean(),
  limitation_count: count,
  effect_count: count,
  link_count: count,
  blob_bytes: count,
  origin: z.enum(["local", "imported"]),
});
const effectRowSchema = z.strictObject({
  kind: z.literal("effect"),
  effect_id: fxIdSchema,
  effect_kind: z.enum(EFFECT_KINDS),
  class: z.enum(["lifecycle", "observe", "modify", "execute"]),
  instance_id: piIdSchema,
  status: z.enum(["active", "revert-failed", "reverted", "expired", "implicit-end", "permanent"]),
  applied_seq: count,
  ended_seq: count.nullable(),
  target: z.string().max(300).nullable(),
  /** the first two fed streams (keeps 500-row pages inside the 2 MiB envelope bound); the full list via detail complete */
  stream_ids: z.array(stIdSchema).max(2),
  stream_count: count,
});
const unknownRowSchema = z.strictObject({
  kind: z.literal("unknown"),
  unknown_id: unkIdSchema,
  revision: count,
  status: z.enum(["open", "investigating", "blocked", "contradicted", "resolved"]),
  severity: z.enum(["low", "medium", "high", "critical"]),
  domain: z.string().max(64),
  question: z.string().max(240),
  question_truncated: z.boolean(),
  supporting_count: count,
  contradicting_count: count,
});
const instanceRowSchema = z.strictObject({
  kind: z.literal("instance"),
  instance_id: piIdSchema,
  pid: count,
  ownership: z.enum(["owned", "attached"]),
  image_name: z.string().max(260).nullable(),
  state: z.string().max(32),
  evidence_count: count,
});

export const getEvidenceOutputSchema = pollOutput({
  view: z.enum(["summary", "complete", "slice"]),
  summary: z
    .strictObject({
      entity: z.enum(["evidence", "effects", "unknowns", "instances"]),
      total: count,
      matching: count,
      rows: z
        .array(z.discriminatedUnion("kind", [evidenceRowSchema, effectRowSchema, unknownRowSchema, instanceRowSchema]))
        .max(500),
      page: pageSchema,
    })
    .exactOptional(),
  record: z
    .strictObject({
      record_kind: z.enum(["evidence", "effect", "unknown", "instance", "module_map", "stream"]),
      origin: z.enum(["local", "imported"]),
      value: jsonObjectSchema,
    })
    .exactOptional(),
  slice: z
    .strictObject({
      evidence_id: evIdSchema,
      pointer: z.string().max(256),
      total: count,
      /** JSON rows; typed `unknown` so the advertised bound stays one open value per item (worst case ≤ 2 MiB) */
      items: z.array(z.unknown()).max(SLICE_ITEMS_MAX).exactOptional(),
      data: z
        .string()
        .max(SLICE_KIB_MAX * 1024 * 2)
        .exactOptional(),
      format: z.enum(["hex", "base64"]).exactOptional(),
      page: pageSchema,
    })
    .exactOptional(),
});

export const exportEvidenceInputSchema = z.strictObject({
  session_id: sessionIdSchema.optional(),
  out_path: z.string().min(1).max(1024).optional(),
  format: z.enum(["directory", "zip"]).default("directory"),
  streams: z.enum(["manifests", "all"]).default("manifests"),
  blobs: z.boolean().default(true),
});

export const importEvidenceInputSchema = z.strictObject({
  path: z.string().min(1).max(1024),
  validate_only: z.boolean().default(false),
});

const probeSchema = z.string().min(1).max(300);
export const recordUnknownInputSchema = z
  .strictObject({
    unknown_id: unkIdSchema.optional(),
    expected_revision: z.number().int().min(1).max(10_000).optional(),
    question: z.string().min(8).max(500).optional(),
    session_id: sessionIdSchema.optional(),
    domain: z
      .string()
      .regex(/^[a-z][a-z0-9_-]{0,63}$/u)
      .default("runtime"),
    // no defaults below: an update keeps the head's value for every omitted field (create: open, medium, [])
    status: z.enum(["open", "investigating", "blocked", "contradicted", "resolved"]).optional(),
    severity: z.enum(["low", "medium", "high", "critical"]).optional(),
    supporting: z.array(evIdSchema).max(16).optional(),
    contradicting: z.array(evIdSchema).max(16).optional(),
    probes: z.array(probeSchema).max(8).optional(),
    resolution: z.string().min(1).max(1000).optional(),
  })
  .superRefine((v, ctx) => {
    if (v.unknown_id === undefined && v.question === undefined)
      ctx.addIssue({
        code: "custom",
        path: ["question"],
        message: "Creating an unknown needs a question (8..500 characters).",
      });
    if (v.unknown_id !== undefined && v.question !== undefined)
      ctx.addIssue({
        code: "custom",
        path: ["question"],
        message: "question is immutable; omit it when updating an unknown_id.",
      });
    if (v.unknown_id !== undefined && v.expected_revision === undefined)
      ctx.addIssue({
        code: "custom",
        path: ["expected_revision"],
        message: "Updating needs expected_revision (the revision you read with get_evidence).",
      });
    if (v.unknown_id === undefined && v.expected_revision !== undefined)
      ctx.addIssue({
        code: "custom",
        path: ["expected_revision"],
        message: "expected_revision is valid only with unknown_id.",
      });
    if (v.status === "resolved" && v.resolution === undefined && v.unknown_id === undefined)
      ctx.addIssue({ code: "custom", path: ["resolution"], message: "status resolved needs a resolution text." });
    if (v.status !== undefined && v.status !== "resolved" && v.resolution !== undefined)
      ctx.addIssue({ code: "custom", path: ["resolution"], message: "resolution is valid only with status resolved." });
  });

export const EVIDENCE_TOOLS = [
  defineTool({
    name: "get_evidence",
    area: "evidence",
    phase: "P1",
    description:
      "Read this run's evidence ledger: summary rows of evidence, effects, unknowns or process instances (exact filters: instance, predicate, operation, effect, stream, module+rva, seq window; paged), one complete record by any ledger id with detail: complete (ev_, fx_, unk_, pi_, mm_, st_; re-authenticated), or a slice page of an array or blob inside a record. Use it to cite ids and to find partial evidence after a cancelled call. Read-only.",
    inputSchema: getEvidenceInputSchema,
    outputSchema: getEvidenceOutputSchema,
    effects: fx(),
    cli: { tier: "oneshot", command: "evidence show", positional: [] },
    errors: ["evidence_integrity_mismatch", "reference_not_found"],
    examples: [
      { title: "Recent evidence rows", input: { limit: 20 } },
      { title: "Records of one predicate", input: { filters: { predicate_type: "bea.memory.read" } } },
      { title: "Open unknowns", input: { entity: "unknowns", filters: { status: "open" } } },
      { title: "One complete record", input: { detail: "complete", id: SAMPLE_EV } },
      { title: "Page a retained table", input: { detail: "slice", id: SAMPLE_EV, pointer: "/result/rows", limit: 25 } },
    ],
  }),
  defineTool({
    name: "export_evidence",
    area: "evidence",
    phase: "P1",
    description:
      "Atomically write the run's (or one session's) evidence as a bundle directory or zip: manifest with digests, records.jsonl, blobs, and stream chunks or stream manifests only. Never overwrites; default path is under BEA_HOME/runs. Use it to hand findings to REA, the user or another agent.",
    inputSchema: exportEvidenceInputSchema,
    outputSchema: pollOutput({
      path: z.string().max(4096),
      bytes: count,
      bundle_digest: sha256Schema,
      records: count,
      blobs: count,
      streams: count,
    }),
    effects: fx({ writesFilesystem: true, idempotent: false }),
    returnsTargetContent: false,
    sessionKinds: ["live", "none"],
    cli: { tier: "oneshot", command: "evidence export", positional: [] },
    errors: ["file_operation_failed", "access_denied", "evidence_integrity_mismatch"],
    maxBlockingMs: 120_000,
    examples: [
      { title: "Whole run, directory bundle", input: {} },
      { title: "Zip with every stream chunk", input: { format: "zip", streams: "all" } },
    ],
  }),
  defineTool({
    name: "import_evidence",
    area: "evidence",
    phase: "P3",
    description:
      "Validate a BEA evidence bundle (recomputed ids, digests and stream hash chains) and, unless validate_only, merge it atomically into this run's ledger; records keep their ids and authority and are marked origin imported. Rejects conflicting records. Imported live evidence can be cited but not re-observed. Data only: no process is touched.",
    inputSchema: importEvidenceInputSchema,
    outputSchema: pollOutput({
      bundle_digest: sha256Schema,
      records: count,
      added: count,
      duplicates: count,
      valid: z.boolean(),
    }),
    effects: fx({ mutatesSession: true }),
    returnsTargetContent: false,
    cli: { tier: "oneshot", command: "evidence verify", positional: ["path"] },
    errors: ["evidence_integrity_mismatch", "file_operation_failed", "revision_conflict"],
    maxBlockingMs: 120_000,
    examples: [{ title: "Verify a bundle", input: { path: "C:\\bundles\\bundle-1", validate_only: true } }],
  }),
  defineTool({
    name: "record_unknown",
    area: "evidence",
    phase: "P2",
    description:
      "Create or update (expected_revision compare-and-swap) a residual unknown: the open question, status, severity, supporting and contradicting evidence ids, recommended probes and resolution. Resolving a runtime question needs observed live-process evidence. Lives in this run's ledger: an image-scoped id is stable (the same question on the same image gets the same id), so after a restart export_evidence + import_evidence carries unknowns over. Ledger only.",
    inputSchema: recordUnknownInputSchema,
    outputSchema: recordedOutput({
      unknown_id: unkIdSchema,
      revision: z.number().int().min(1).max(10_000),
      status: z.enum(["open", "investigating", "blocked", "contradicted", "resolved"]),
    }),
    effects: fx({ mutatesSession: true, idempotent: false }),
    returnsTargetContent: false,
    sessionKinds: ["live", "emulation", "none"],
    cli: {
      tier: "mcp-only",
      reason:
        "interactive agent bookkeeping across calls; scenarios are planned ahead and cannot reason about outcomes",
    },
    evidence: { predicate: "bea.unknown.mutation", recorded: "always" },
    errors: ["reference_not_found", "revision_conflict"],
    examples: [
      {
        title: "Open a question",
        input: { question: "Which function writes Car.speed on the physics thread?", severity: "high" },
      },
      {
        title: "Resolve with live evidence",
        input: {
          unknown_id: SAMPLE_UNK,
          expected_revision: 1,
          status: "resolved",
          supporting: [SAMPLE_EV],
          resolution: "physics_step is the single writer.",
        },
      },
    ],
  }),
] as const satisfies readonly ToolContract[];
