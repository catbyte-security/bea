import { z } from "zod";

import { canonicalDigest } from "../canonical.js";
import { sortedSet } from "../evidence/invariants.js";
import {
  AUTHORITY_TRUST,
  CONFIDENCE_RANK,
  authoritySchema,
  confidenceSchema,
  type Authority,
  type Confidence,
} from "../evidence/record.js";
import { evIdSchema, idOf, runIdSchema, sha256Schema, unkIdSchema, type EvId, type RunId, type UnkId } from "../ids.js";
import type { JsonValue } from "../json.js";

/**
 * Residual unknowns (S2 §14, flattened per DESIGN §6.2 #37): REA's revision chain with an `expected_revision`
 * compare-and-swap, `accepted_authorities` as an explicit set, the scope as an image digest (survives restarts of the
 * same binary) or this run. Every revision is a `{t:"unk"}` ledger line; status is never mutated in place.
 */
export const UNKNOWN_STATUSES = ["open", "investigating", "blocked", "contradicted", "resolved"] as const;
export const UNKNOWN_SEVERITIES = ["low", "medium", "high", "critical"] as const;
export type UnknownStatus = (typeof UNKNOWN_STATUSES)[number];
export type UnknownSeverity = (typeof UNKNOWN_SEVERITIES)[number];

export const unknownScopeSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("image"), image_sha256: sha256Schema }),
  z.strictObject({ kind: z.literal("run"), run_id: runIdSchema }),
  z.strictObject({ kind: z.literal("global") }),
]);
export type UnknownScope = z.infer<typeof unknownScopeSchema>;

export const UNKNOWN_DOMAIN_RE = /^[a-z][a-z0-9_-]{0,63}$/u;
/** @public */
export const QUESTION_MIN_CHARS = 8;
/** @public */
export const QUESTION_MAX_CHARS = 500;

const probeTextSchema = z.string().min(1).max(300);

export const residualUnknownSchema = z
  .strictObject({
    schema: z.literal("bea.unknown/1"),
    unknown_id: unkIdSchema,
    revision: z.number().int().min(1).max(10_000),
    previous_revision_digest: sha256Schema.nullable(),
    revision_digest: sha256Schema,
    scope: unknownScopeSchema,
    domain: z.string().regex(UNKNOWN_DOMAIN_RE),
    question: z.string().min(1).max(2000),
    status: z.enum(UNKNOWN_STATUSES),
    severity: z.enum(UNKNOWN_SEVERITIES),
    supporting_evidence_ids: z.array(evIdSchema).max(256),
    contradicting_evidence_ids: z.array(evIdSchema).max(256),
    accepted_authorities: z.array(authoritySchema).min(1).max(5),
    required_confidence: confidenceSchema,
    recommended_probes: z.array(probeTextSchema).max(8),
    resolution: z.string().min(1).max(1000).nullable(),
    mutation_evidence_ids: z.array(evIdSchema).min(1).max(10_000),
  })
  .superRefine((u, ctx) => {
    for (const issue of unknownInvariantIssues(u)) ctx.addIssue({ code: "custom", message: issue });
  });
export type ResidualUnknown = z.infer<typeof residualUnknownSchema>;

const isSorted = (items: readonly string[]): boolean => items.every((x, i) => i === 0 || (items[i - 1] ?? "") < x);

/** REA invariants (S2 §14.1). */
export const unknownInvariantIssues = (u: Omit<ResidualUnknown, "revision_digest">): string[] => {
  const issues: string[] = [];
  if ((u.revision === 1) !== (u.previous_revision_digest === null))
    issues.push("revision 1 has no previous digest and every later revision has one");
  if ((u.status === "resolved") !== (u.resolution !== null)) issues.push("resolution is set exactly when resolved");
  if (u.status === "contradicted" && u.contradicting_evidence_ids.length === 0)
    issues.push("a contradicted unknown cites contradicting evidence");
  const supporting = new Set(u.supporting_evidence_ids);
  if (u.contradicting_evidence_ids.some((id) => supporting.has(id)))
    issues.push("an evidence id cannot both support and contradict");
  for (const [name, list] of [
    ["supporting_evidence_ids", u.supporting_evidence_ids],
    ["contradicting_evidence_ids", u.contradicting_evidence_ids],
    ["accepted_authorities", u.accepted_authorities],
    ["mutation_evidence_ids", u.mutation_evidence_ids],
  ] as const)
    if (!isSorted(list)) issues.push(`${name} is not sorted and unique`);
  return issues;
};

export const normalizeQuestion = (question: string): string => question.replace(/\s+/gu, " ").trim();

export const unknownIdOf = (domain: string, question: string, scope: UnknownScope): UnkId =>
  idOf("unk", {
    t: "bea.unk/1",
    domain,
    question: normalizeQuestion(question),
    scope_digest: canonicalDigest(scope),
  });

export const revisionDigestOf = (u: Omit<ResidualUnknown, "revision_digest">): string => {
  const { revision_digest: _ignored, ...rest } = u as ResidualUnknown;
  return canonicalDigest(rest as unknown as JsonValue);
};

/** Domain defaults (S2 §14.1 table; "runtime" is the §6.2 default domain). */
export const domainDefaults = (
  domain: string,
): { readonly accepted_authorities: readonly Authority[]; readonly required_confidence: Confidence } => {
  switch (domain) {
    case "runtime":
    case "runtime-behavior":
    case "struct-layout":
      return { accepted_authorities: ["live-process"], required_confidence: "observed" };
    case "function-semantics":
      return { accepted_authorities: ["emulation", "live-process"], required_confidence: "observed" };
    case "address-mapping":
      return { accepted_authorities: ["live-process", "static-artifact"], required_confidence: "derived" };
    case "emulation-fidelity":
      return { accepted_authorities: ["emulation", "live-process"], required_confidence: "derived" };
    default:
      return { accepted_authorities: [...AUTHORITY_TRUST].sort(), required_confidence: "inferred" };
  }
};

export interface UnknownFields {
  readonly scope: UnknownScope;
  readonly domain: string;
  readonly question: string;
  readonly status: UnknownStatus;
  readonly severity: UnknownSeverity;
  readonly supporting: readonly EvId[];
  readonly contradicting: readonly EvId[];
  readonly probes: readonly string[];
  readonly resolution: string | null;
}

/** Build a revision (create when `head` is undefined) and seal it with its digest. */
export const nextRevision = (
  head: ResidualUnknown | undefined,
  fields: UnknownFields,
  mutationEvidenceId: EvId,
): ResidualUnknown => {
  const defaults = domainDefaults(fields.domain);
  const body: Omit<ResidualUnknown, "revision_digest"> = {
    schema: "bea.unknown/1",
    unknown_id: head?.unknown_id ?? unknownIdOf(fields.domain, fields.question, fields.scope),
    revision: (head?.revision ?? 0) + 1,
    previous_revision_digest: head?.revision_digest ?? null,
    scope: head?.scope ?? fields.scope,
    domain: head?.domain ?? fields.domain,
    question: head?.question ?? normalizeQuestion(fields.question),
    status: fields.status,
    severity: fields.severity,
    supporting_evidence_ids: sortedSet(fields.supporting),
    contradicting_evidence_ids: sortedSet(fields.contradicting),
    accepted_authorities: head?.accepted_authorities ?? sortedSet(defaults.accepted_authorities),
    required_confidence: head?.required_confidence ?? defaults.required_confidence,
    recommended_probes: [...fields.probes],
    resolution: fields.status === "resolved" ? fields.resolution : null,
    mutation_evidence_ids: sortedSet([...(head?.mutation_evidence_ids ?? []), mutationEvidenceId]),
  };
  return { ...body, revision_digest: revisionDigestOf(body) };
};

/** What the verified-resolution rule needs to know about one cited record. */
export interface SupportFacts {
  readonly predicate_type: string;
  /** effective authority: bundle-imported records count as "imported" (S2 §7.4) */
  readonly authority: Authority;
  readonly confidence: Confidence;
  readonly coverage_status: "complete" | "partial" | "unknown";
}

/**
 * S2 §14.3: `resolved` needs at least one supporting, non-mutation record of an accepted (effective) authority, of
 * sufficient confidence and not of unknown coverage, and no contradicting evidence. Returns the failing criterion.
 */
export const verifiedResolutionIssue = (
  u: Pick<
    ResidualUnknown,
    "supporting_evidence_ids" | "contradicting_evidence_ids" | "accepted_authorities" | "required_confidence"
  >,
  facts: (id: EvId) => SupportFacts | undefined,
): string | null => {
  if (u.contradicting_evidence_ids.length > 0)
    return "A resolved unknown cannot cite contradicting evidence; clear it or set status contradicted.";
  if (u.supporting_evidence_ids.length === 0)
    return "Resolving needs supporting evidence ids (observations that answer the question).";
  const rank = CONFIDENCE_RANK[u.required_confidence];
  const qualifies = u.supporting_evidence_ids.some((id) => {
    const f = facts(id);
    return (
      f !== undefined &&
      f.predicate_type !== "bea.unknown.mutation" &&
      u.accepted_authorities.includes(f.authority) &&
      CONFIDENCE_RANK[f.confidence] >= rank &&
      f.coverage_status !== "unknown"
    );
  });
  return qualifies
    ? null
    : `Resolving needs at least one supporting record with authority ${u.accepted_authorities.join(" or ")}, confidence ${u.required_confidence} or stronger and known coverage (imported records count as authority imported).`;
};

export const scopeOf = (imageSha256: string | null, runId: RunId): UnknownScope =>
  imageSha256 === null ? { kind: "run", run_id: runId } : { kind: "image", image_sha256: imageSha256 };
