import { canonicalJson } from "../canonical.js";
import type { JsonValue } from "../json.js";
import { coverageSchema } from "./coverage.js";
import { CORE_LIMITATIONS } from "./limitations.js";
import { PREDICATES, isPredicateType, type PredicateSpec } from "./predicates.js";
import type { BeaEvidence } from "./record.js";

/**
 * Cross-field invariants of `bea.evidence/1` (S2 §7.1 items 1–9). beaEvidenceSchema (§4, WP0) is structural only;
 * the Recorder and authenticateEvidence() apply these after it. Each returns human-readable issue text (never
 * target content) so a violation can be logged and turned into an EvidenceIntegrity/Internal error.
 */

/** UTF-16 code-unit order of the canonical JSON form (S2 §2.5); strings compare as themselves. */
export const setKey = (value: JsonValue): string => (typeof value === "string" ? value : canonicalJson(value));

const compare = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/** Sort + dedupe a set-valued array (S2 §2.5). */
export const sortedSet = <T extends JsonValue>(items: readonly T[]): T[] => {
  const byKey = new Map<string, T>();
  for (const item of items) byKey.set(setKey(item), item);
  return [...byKey.entries()].sort(([a], [b]) => compare(a, b)).map(([, item]) => item);
};

export const isSortedSet = (items: readonly JsonValue[]): boolean => {
  for (let i = 1; i < items.length; i++) {
    const prev = items[i - 1];
    const cur = items[i];
    if (prev === undefined || cur === undefined) return false;
    if (compare(setKey(prev), setKey(cur)) >= 0) return false;
  }
  return true;
};

/** Blobs sort by role, then sha256 (S2 §2.5); redactions by pointer (then scope, for determinism). */
export const blobOrder = (a: { role: string; sha256: string }, b: { role: string; sha256: string }): number =>
  compare(a.role, b.role) || compare(a.sha256, b.sha256);
export const redactionOrder = (a: { pointer: string; scope: string }, b: { pointer: string; scope: string }): number =>
  compare(a.pointer, b.pointer) || compare(a.scope, b.scope);

const sortedBy = <T>(items: readonly T[], order: (a: T, b: T) => number, unique: boolean): boolean => {
  for (let i = 1; i < items.length; i++) {
    const prev = items[i - 1];
    const cur = items[i];
    if (prev === undefined || cur === undefined) return false;
    const c = order(prev, cur);
    if (c > 0 || (unique && c === 0)) return false;
  }
  return true;
};

const LEVEL_RANK = { none: 0, "agent-only": 1, passive: 2, intrusive: 3 } as const;
/** @public */
export const perturbationLevelRank = (level: keyof typeof LEVEL_RANK): number => LEVEL_RANK[level];

/** S2 §7.1 invariants; `[]` when the record is consistent. */
export const evidenceInvariantIssues = (e: BeaEvidence): string[] => {
  const issues: string[] = [];
  const spec: PredicateSpec | undefined = isPredicateType(e.predicate_type) ? PREDICATES[e.predicate_type] : undefined;
  if (spec === undefined) return [`predicate ${e.predicate_type} is not registered`];

  // 1. set-valued arrays sorted and unique
  const sets: readonly [string, readonly JsonValue[]][] = [
    ["limitations", e.limitations],
    ["evidence_links", e.evidence_links],
    ["effects", e.effects],
    ["perturbation.active_effect_ids", e.perturbation.active_effect_ids],
    ["perturbation.tainted_by", e.perturbation.tainted_by],
    ["coverage.reasons", e.coverage.reasons],
    ["locations", e.locations as unknown as JsonValue[]],
    ["external_refs", e.external_refs as unknown as JsonValue[]],
  ];
  for (const [name, items] of sets) if (!isSortedSet(items)) issues.push(`${name} is not sorted and unique`);
  if (!sortedBy(e.blobs, blobOrder, true)) issues.push("blobs are not sorted by (role, sha256) and unique");
  if (!sortedBy(e.redactions, redactionOrder, false)) issues.push("redactions are not sorted by pointer");

  // 2. subjectless records
  if (
    e.subject === null &&
    !spec.subjects.includes("none") &&
    !e.limitations.includes(CORE_LIMITATIONS.SUBJECT_UNAVAILABLE)
  )
    issues.push("a subjectless record needs a subjectless predicate or the SUBJECT_UNAVAILABLE limitation");
  if (e.subject !== null && !spec.subjects.includes(e.subject.kind))
    issues.push(`subject kind ${e.subject.kind} is not allowed for ${e.predicate_type}`);

  // 3. observed process records are anchored with epochs
  const live = e.subject?.kind === "process-instance";
  if (live && e.confidence === "observed" && (e.observed_at === null || e.observed_at.effect_epoch === null))
    issues.push("an observed process-instance record needs an anchor with epochs");

  // 4. epochs only for live subjects
  if (e.observed_at !== null && e.observed_at.effect_epoch !== null && !live)
    issues.push("anchor epochs require a process-instance subject");

  // 5. authority vs subject
  if (e.authority === "live-process" && !live)
    issues.push("live-process authority requires a process-instance subject");
  if (e.authority === "emulation" && e.subject?.kind !== "emulation" && e.confidence === "observed")
    issues.push("observed emulation authority requires an emulation subject");

  // 6. derived/inferred records link their parents
  if (e.confidence !== "observed" && e.evidence_links.length === 0 && spec.linkless !== true)
    issues.push(`${e.confidence} records need at least one evidence link`);

  // 7. perturbation level none exactly when nothing live is involved
  if (live && e.perturbation.level === "none") issues.push("a process-instance record cannot have perturbation none");
  if (
    e.perturbation.level === "none" &&
    (e.perturbation.active_effect_ids.length > 0 || e.perturbation.tainted_by.length > 0)
  )
    issues.push("perturbation none cannot list effects");

  // 8. coverage invariants (coverageSchema refinement)
  if (!coverageSchema.safeParse(e.coverage).success) issues.push("coverage violates its invariants");

  // 9. anchor rule
  if (spec.anchor === "required" && e.observed_at === null) issues.push(`${e.predicate_type} requires an anchor`);
  if (spec.anchor === "none" && e.observed_at !== null) issues.push(`${e.predicate_type} must not carry an anchor`);
  return issues;
};
