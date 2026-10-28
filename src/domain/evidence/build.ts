import { canonicalJson } from "../canonical.js";
import type { BeaError, BeaErrorOf } from "../errors/beaError.js";
import type { EvId, FxId, MmId, PiId } from "../ids.js";
import type { JsonObject, JsonValue } from "../json.js";
import type { SensitiveLiterals } from "../redaction/literals.js";
import { jsonContainsLiteral, redactJsonPayload, type Redaction } from "../redaction/redact.js";
import { err, ok, type Result } from "../result.js";
import type { TimeAnchor } from "../time.js";
import { mergeCoverage, REASONS, type Coverage } from "./coverage.js";
import { evidenceIdOf } from "./authenticate.js";
import { blobOrder, evidenceInvariantIssues, redactionOrder, sortedSet } from "./invariants.js";
import { LIMITATIONS } from "./limitations.js";
import { PREDICATES, isPredicateType, type PredicateSpec, type PredicateType } from "./predicates.js";
import {
  AUTHORITY_TRUST,
  CONFIDENCE_RANK,
  NO_PERTURBATION,
  type AgentIdentity,
  type Authority,
  type BeaEvidence,
  type BlobRef,
  type Confidence,
  type ExternalRef,
  type Location,
  type Perturbation,
  type Subject,
  beaEvidenceSchema,
} from "./record.js";

/**
 * The pure part of the record pipeline (S2 §7.9 steps 1–6). The Recorder (src/providers/evidence/Recorder.ts) adds
 * the I/O steps (module-map materialization, reference closure, append, index); fakeEvidence reuses this file so
 * area unit tests exercise the same validation. Structurally identical to the port's EvidenceDraft.
 */
export interface EvidenceBuildInput<R extends JsonValue> {
  readonly predicate_type: PredicateType;
  readonly operation: string;
  readonly input: JsonObject;
  readonly identityExclude?: readonly string[];
  readonly subject: { readonly kind: "process-instance"; readonly instance_id: PiId } | Subject | null;
  readonly capture?: {
    readonly anchor: TimeAnchor;
    readonly module_map_id: MmId;
    readonly perturbation: Perturbation;
    readonly tainted_count: number;
  };
  readonly provider: {
    readonly id: "frida" | "unicorn" | "bea-pe" | "bea";
    readonly name: string;
    readonly version: string | null;
  };
  readonly agent?: AgentIdentity | null;
  readonly confidence?: Confidence;
  readonly authority?: Authority;
  readonly result: R;
  readonly raw_result?: JsonValue | null;
  readonly blobs?: readonly BlobRef[];
  readonly coverage: Coverage;
  readonly limitations?: readonly string[];
  readonly locations?: readonly Location[];
  readonly evidence_links?: readonly EvId[];
  readonly external_refs?: readonly ExternalRef[];
  readonly effects?: readonly FxId[];
  readonly literals: SensitiveLiterals;
  /** SEC-3: /result pointers the producer withheld (see ports/evidence.ts EvidenceDraft.pre_redactions) */
  readonly pre_redactions?: readonly string[];
}

/** What the pipeline needs to know about a cited parent record (weakest-parent authority, perturbation union). */
export interface ParentFacts {
  readonly authority: Authority;
  readonly perturbation: Perturbation;
}

export interface BuildFacts {
  /** links the Recorder adds (the materialized bea.modules.map evidence) */
  readonly extraLinks?: readonly EvId[];
  readonly parent: (id: EvId) => ParentFacts | undefined;
}

/** Delivery/handle keys never enter evidence identity (S2 §7.9 step 2). */
export const DEFAULT_IDENTITY_EXCLUDE = [
  "session_id",
  "detail",
  "offset",
  "limit",
  "format",
  "next",
  "timeout_ms",
  "wait_ms",
  "overwrite",
  "sensitive_values",
  "redact_literals",
] as const;

export const MAX_RECORD_BYTES = 4 * 1024 * 1024;
export const MAX_JSON_DEPTH = 64;
export const MAX_PERTURBATION_IDS = 256;
const MAX_LIMITATIONS = 64;

export const PLACEHOLDER_EVIDENCE_ID: EvId = `ev_${"0".repeat(64)}`;

const internal = (operation: string, stage: string, detail: string): BeaErrorOf<"Internal"> => ({
  _tag: "Internal",
  operation,
  diagnostics: { stage, detail: detail.slice(0, 300) },
});

const jsonDepth = (value: JsonValue, limit: number): number => {
  let max = 0;
  const walk = (node: JsonValue, depth: number): void => {
    if (depth > max) max = depth;
    if (max > limit || node === null || typeof node !== "object") return;
    for (const item of Object.values(node as object) as JsonValue[]) walk(item, depth + 1);
  };
  walk(value, 0);
  return max;
};

/** Step 2: identity-relevant, sanitized parameters plus the parameter-scope redactions. */
export const sanitizeParameters = (
  input: JsonObject,
  identityExclude: readonly string[],
  literals: SensitiveLiterals,
): { readonly parameters: JsonObject; readonly redactions: readonly Redaction[] } => {
  const excluded = new Set<string>([...DEFAULT_IDENTITY_EXCLUDE, ...identityExclude]);
  const parameters: Record<string, JsonValue> = {};
  const redactions: Redaction[] = [];
  for (const [key, value] of Object.entries(input)) {
    if (excluded.has(key)) continue;
    if (jsonContainsLiteral(key, literals) || jsonContainsLiteral(value, literals)) {
      redactions.push({
        pointer: `/parameters/${key.replaceAll("~", "~0").replaceAll("/", "~1")}`,
        reason: "explicit-sensitive-value",
        scope: "parameter",
      });
      continue;
    }
    parameters[key] = value;
  }
  const count = (["sensitive_values", "redact_literals"] as const).reduce((n, key) => {
    const value = input[key];
    return n + (Array.isArray(value) ? value.length : 0);
  }, 0);
  if (count > 0) parameters["sensitive_value_count"] = count;
  return { parameters, redactions };
};

const LEVELS = ["none", "agent-only", "passive", "intrusive"] as const;

/** Union of parent perturbations (derived records), capped at 256 ids. */
export const unionPerturbation = (
  items: readonly Perturbation[],
): { readonly perturbation: Perturbation; readonly capped: boolean } => {
  let level = 0;
  const active = new Set<FxId>();
  const tainted = new Set<FxId>();
  for (const p of items) {
    level = Math.max(level, LEVELS.indexOf(p.level));
    for (const id of p.active_effect_ids) active.add(id);
    for (const id of p.tainted_by) tainted.add(id);
  }
  const cap = (set: Set<FxId>): FxId[] => [...set].sort().slice(0, MAX_PERTURBATION_IDS);
  return {
    perturbation: {
      level: LEVELS[level] ?? "none",
      active_effect_ids: cap(active),
      tainted_by: cap(tainted),
    },
    capped: active.size > MAX_PERTURBATION_IDS || tainted.size > MAX_PERTURBATION_IDS,
  };
};

const weakestAuthority = (items: readonly Authority[]): Authority | undefined =>
  items.reduce<Authority | undefined>(
    (weakest, a) =>
      weakest === undefined || AUTHORITY_TRUST.indexOf(a) > AUTHORITY_TRUST.indexOf(weakest) ? a : weakest,
    undefined,
  );

const resolveConfidence = (spec: PredicateSpec, requested: Confidence | undefined): Result<Confidence, string> => {
  if (spec.confidence === "per-call")
    return requested === undefined ? err("the predicate needs a per-call confidence") : ok(requested);
  // a producer may weaken a fixed confidence (e.g. a failed identity check), never strengthen it
  if (requested !== undefined && CONFIDENCE_RANK[requested] < CONFIDENCE_RANK[spec.confidence]) return ok(requested);
  return ok(spec.confidence);
};

const resolveAuthority = (
  spec: PredicateSpec,
  requested: Authority | undefined,
  parents: readonly ParentFacts[],
): Result<Authority, string> => {
  if (spec.authority === "per-call")
    return requested === undefined ? err("the predicate needs a per-call authority") : ok(requested);
  if (spec.authority === "weakest-parent") {
    const weakest = weakestAuthority([
      ...parents.map((p) => p.authority),
      ...(requested === undefined ? [] : [requested]),
    ]);
    return weakest === undefined ? err("weakest-parent authority needs parents or a supplied authority") : ok(weakest);
  }
  return ok(spec.authority);
};

/** Fixed limitation sentences implied by the record (S2 §7.9 step 4); templates stay the producer's job. */
const impliedLimitations = (coverage: Coverage): string[] => {
  const out: string[] = [];
  for (const reason of coverage.reasons) {
    const key = (REASONS as Readonly<Record<string, string>>)[reason];
    const sentence = key === undefined ? undefined : (LIMITATIONS as Readonly<Record<string, unknown>>)[key];
    if (typeof sentence === "string") out.push(sentence);
  }
  return out;
};

/** Strict schema (with a placeholder id) + invariants, then the real id. */
export const checkEvidenceBody = (body: Omit<BeaEvidence, "evidence_id">): Result<EvId, string> => {
  const parsed = beaEvidenceSchema.safeParse({ ...body, evidence_id: PLACEHOLDER_EVIDENCE_ID });
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    return err(`${issue?.path.join(".") ?? ""}: ${issue?.message ?? "invalid"}`);
  }
  const issues = evidenceInvariantIssues({ ...body, evidence_id: PLACEHOLDER_EVIDENCE_ID } as BeaEvidence);
  if (issues.length > 0) return err(issues.join("; "));
  return ok(evidenceIdOf(body));
};

export interface BuiltEvidence<R extends JsonValue> {
  readonly record: BeaEvidence<R>;
  /** canonical JSON of the whole record (the `record` member of the ledger line) */
  readonly canonical: string;
}

/** Steps 1–6 of the record pipeline. A failure is a producer bug (Internal), never a target condition. */
export const buildEvidence = <R extends JsonValue>(
  draft: EvidenceBuildInput<R>,
  facts: BuildFacts,
): Result<BuiltEvidence<R>, BeaError> => {
  const op = draft.operation;
  // 1. registry check
  if (!isPredicateType(draft.predicate_type)) return err(internal(op, "registry", "unregistered predicate"));
  const spec: PredicateSpec = PREDICATES[draft.predicate_type];
  const subjectKind = draft.subject?.kind ?? "none";
  if (!spec.subjects.includes(subjectKind) && draft.subject !== null)
    return err(internal(op, "registry", `subject ${subjectKind} not allowed for ${draft.predicate_type}`));
  if (spec.anchor === "required" && draft.capture === undefined)
    return err(internal(op, "registry", `${draft.predicate_type} needs an anchor capture`));

  // 2. parameters
  const sanitized = sanitizeParameters(draft.input, draft.identityExclude ?? [], draft.literals);

  // 3. subject
  let subject: Subject | null = null;
  if (draft.subject !== null)
    subject =
      draft.subject.kind === "process-instance" && !("module_map_id" in draft.subject)
        ? {
            kind: "process-instance",
            instance_id: draft.subject.instance_id,
            module_map_id: draft.capture?.module_map_id ?? null,
          }
        : (draft.subject as Subject);
  const live = subject?.kind === "process-instance";

  // 4. confidence, authority, perturbation, limitations
  const links = sortedSet<EvId>([...(draft.evidence_links ?? []), ...(facts.extraLinks ?? [])]);
  const parents = links.map((id) => facts.parent(id)).filter((p): p is ParentFacts => p !== undefined);
  const confidence = resolveConfidence(spec, draft.confidence);
  if (!confidence.ok) return err(internal(op, "confidence", confidence.error));
  const authority = resolveAuthority(spec, draft.authority, parents);
  if (!authority.ok) return err(internal(op, "authority", authority.error));
  const union = unionPerturbation([
    ...(draft.capture === undefined ? [] : [draft.capture.perturbation]),
    ...(draft.capture === undefined && (live || parents.length > 0) ? parents.map((p) => p.perturbation) : []),
  ]);
  let perturbation = union.perturbation;
  if (live && perturbation.level === "none") perturbation = { ...perturbation, level: "agent-only" };
  if (!live && parents.length === 0 && draft.capture === undefined) perturbation = NO_PERTURBATION;

  // 5. redaction of the result payloads
  const result = redactJsonPayload(draft.result, draft.literals, "/result", spec.byteFields);
  const raw =
    draft.raw_result === undefined || draft.raw_result === null
      ? { value: null, redactions: [] as const }
      : redactJsonPayload(draft.raw_result, draft.literals, "/raw_result", spec.byteFields);
  const withheld: Redaction[] = (draft.pre_redactions ?? []).map((pointer) => ({
    pointer,
    reason: "explicit-sensitive-value",
    scope: "value",
  }));
  const payloadRedactions = [...withheld, ...result.redactions, ...raw.redactions];
  let coverage = draft.coverage;
  if (payloadRedactions.length > 0)
    coverage = mergeCoverage(coverage, { status: "partial", truncated: true, reasons: ["explicit_sensitive_value"] });
  const redactions = [...sanitized.redactions, ...payloadRedactions].sort(redactionOrder);

  const limitations = [...(draft.limitations ?? []), ...impliedLimitations(coverage)];
  if (perturbation.tainted_by.length > 0)
    limitations.push(LIMITATIONS.TAINTED(perturbation.tainted_by.length, perturbation.tainted_by));
  if (union.capped) limitations.push(LIMITATIONS.PERTURBATION_CAPPED);
  if (subject === null && !spec.subjects.includes("none")) limitations.push(LIMITATIONS.SUBJECT_UNAVAILABLE);
  if (payloadRedactions.length > 0) limitations.push(LIMITATIONS.REDACTED(payloadRedactions.length));

  const body: Omit<BeaEvidence<R>, "evidence_id"> = {
    schema: "bea.evidence/1",
    predicate_type: draft.predicate_type,
    operation: draft.operation,
    parameters: sanitized.parameters,
    subject,
    observed_at: spec.anchor === "none" ? null : (draft.capture?.anchor ?? null),
    provider: { ...draft.provider },
    agent: draft.agent ?? null,
    confidence: confidence.value,
    authority: authority.value,
    perturbation,
    result: result.value as R,
    raw_result: raw.value,
    blobs: [...(draft.blobs ?? [])].sort(blobOrder),
    coverage: { ...coverage, reasons: sortedSet(coverage.reasons) },
    limitations: sortedSet(limitations).slice(0, MAX_LIMITATIONS),
    locations: sortedSet(draft.locations ?? []),
    evidence_links: links,
    external_refs: sortedSet(draft.external_refs ?? []),
    effects: sortedSet(draft.effects ?? []),
    redactions,
    untrusted: spec.untrusted,
  };

  // 6. bounds, schema, invariants, id
  if (jsonDepth(body.result, MAX_JSON_DEPTH) > MAX_JSON_DEPTH)
    return err(internal(op, "bounds", `result nests deeper than ${String(MAX_JSON_DEPTH)}`));
  const checked = checkEvidenceBody(body as Omit<BeaEvidence, "evidence_id">);
  if (!checked.ok) return err(internal(op, "schema", checked.error));
  const record = { ...body, evidence_id: checked.value } as BeaEvidence<R>;
  const canonical = canonicalJson(record as unknown as JsonValue);
  if (canonical.length > MAX_RECORD_BYTES)
    return err(internal(op, "bounds", `record exceeds ${String(MAX_RECORD_BYTES)} bytes`));
  return ok({ record, canonical });
};
