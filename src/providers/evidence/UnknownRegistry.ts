import type { BeaError } from "../../domain/errors/beaError.js";
import { inputError, referenceNotFound } from "../../domain/errors/constructors.js";
import { COMPLETE } from "../../domain/evidence/coverage.js";
import { LIMITATIONS } from "../../domain/evidence/limitations.js";
import type { EvId, RunId, UnkId } from "../../domain/ids.js";
import { redactExplicitText } from "../../domain/redaction/redact.js";
import { err, ok, type Result } from "../../domain/result.js";
import { sortedSet } from "../../domain/evidence/invariants.js";
import {
  domainDefaults,
  nextRevision,
  residualUnknownSchema,
  scopeOf,
  unknownIdOf,
  verifiedResolutionIssue,
  type ResidualUnknown,
  type SupportFacts,
  type UnknownFields,
} from "../../domain/unknowns/unknown.js";
import type { Recorder, SensitiveLiterals, UnknownInput, UnknownRegistry } from "../../ports/evidence.js";
import { internalError } from "./errors.js";
import type { Ledger } from "./Ledger.js";
import type { LedgerIndex } from "./LedgerIndex.js";

/**
 * Residual unknowns (S2 §14): create, CAS update (`expected_revision`), the verified-resolution rule. Every mutation
 * first records `bea.unknown.mutation` evidence (analyst intent, linking every cited id), then appends the {t:"unk"}
 * revision whose `mutation_evidence_ids` include that record.
 */
export interface UnknownDeps {
  readonly runId: RunId;
  readonly ledger: Ledger;
  readonly index: LedgerIndex;
  readonly recorder: () => Recorder;
  readonly serverLiterals: () => SensitiveLiterals;
}

const CHANGE_FIELDS = [
  ["status", "status"],
  ["severity", "severity"],
  ["supporting_evidence_ids", "supporting"],
  ["contradicting_evidence_ids", "contradicting"],
  ["recommended_probes", "probes"],
  ["resolution", "resolution"],
] as const;

export class LedgerUnknownRegistry implements UnknownRegistry {
  #chain: Promise<unknown> = Promise.resolve();

  constructor(private readonly deps: UnknownDeps) {}

  /** Effective facts for the verified rule: imported-origin records count as authority `imported` (S2 §7.4). */
  #support = (id: EvId): SupportFacts | undefined => {
    const row = this.deps.index.byId.get(id);
    if (row === undefined) return undefined;
    return {
      predicate_type: row.predicate_type,
      authority: row.origin.kind === "import" ? "imported" : row.authority,
      confidence: row.confidence,
      coverage_status: row.coverage_status,
    };
  };

  upsert(
    input: UnknownInput,
    operation: string,
  ): Promise<
    Result<
      { readonly unknown_id: UnkId; readonly revision: number; readonly status: string; readonly evidence_id: EvId },
      BeaError
    >
  > {
    // mutations are serialized: a CAS check and its append must not interleave with another mutation
    const task = this.#chain.catch(() => undefined).then(() => this.#upsert(input, operation));
    this.#chain = task;
    return task;
  }

  async #upsert(
    input: UnknownInput,
    operation: string,
  ): Promise<
    Result<
      { readonly unknown_id: UnkId; readonly revision: number; readonly status: string; readonly evidence_id: EvId },
      BeaError
    >
  > {
    for (const [path, ids] of [
      ["supporting", input.supporting],
      ["contradicting", input.contradicting],
    ] as const)
      for (const id of ids)
        if (!this.deps.index.byId.has(id))
          return err({ ...referenceNotFound(operation, "evidence", id), diagnostics: { field: path } });
    const literals = this.deps.serverLiterals();
    let head: ResidualUnknown | undefined;
    if (input.unknown_id !== undefined) {
      head = this.deps.index.unknownHead(input.unknown_id);
      if (head === undefined) return err(referenceNotFound(operation, "unknown", input.unknown_id));
      if (input.expected_revision !== head.revision)
        return err({
          _tag: "RevisionConflict",
          operation,
          unknown_id: head.unknown_id,
          expected_revision: input.expected_revision ?? 0,
          actual_revision: head.revision,
        });
    } else {
      const question = redactExplicitText(input.question ?? "", literals);
      const id = unknownIdOf(input.domain, question, scopeOf(input.scope_image_sha256, this.deps.runId));
      const existing = this.deps.index.unknownHead(id);
      if (existing !== undefined)
        return err(
          inputError(operation, [
            {
              path: "question",
              reason: "conflicting_arguments",
              message: `This question is already recorded as ${id} (revision ${String(existing.revision)}); update it with unknown_id and expected_revision.`,
            },
          ]),
        );
    }
    const fields: UnknownFields = {
      scope: head?.scope ?? scopeOf(input.scope_image_sha256, this.deps.runId),
      domain: head?.domain ?? input.domain,
      question: head?.question ?? redactExplicitText(input.question ?? "", literals),
      status: input.contradicting.length > 0 && input.status === "open" ? "contradicted" : input.status,
      severity: input.severity,
      supporting: input.supporting,
      contradicting: input.contradicting,
      probes: input.probes.map((p) => redactExplicitText(p, literals)).filter((p) => p.length > 0),
      resolution: input.resolution === null ? null : redactExplicitText(input.resolution, literals) || null,
    };
    if (fields.status === "resolved") {
      const issue = verifiedResolutionIssue(
        {
          supporting_evidence_ids: [...fields.supporting],
          contradicting_evidence_ids: [...fields.contradicting],
          accepted_authorities:
            head?.accepted_authorities ?? sortedSet(domainDefaults(fields.domain).accepted_authorities),
          required_confidence: head?.required_confidence ?? domainDefaults(fields.domain).required_confidence,
        },
        this.#support,
      );
      if (issue !== null)
        return err(inputError(operation, [{ path: "status", reason: "conflicting_arguments", message: issue }]));
      if (fields.resolution === null)
        return err(
          inputError(operation, [
            { path: "resolution", reason: "missing_argument", message: "A resolved unknown needs a resolution text." },
          ]),
        );
    } else if (input.resolution !== null)
      return err(
        inputError(operation, [
          {
            path: "resolution",
            reason: "conflicting_arguments",
            message: "resolution is valid only with status resolved.",
          },
        ]),
      );
    if (fields.status === "contradicted" && fields.contradicting.length === 0)
      return err(
        inputError(operation, [
          {
            path: "contradicting",
            reason: "missing_argument",
            message: "status contradicted needs contradicting evidence ids.",
          },
        ]),
      );
    if (fields.supporting.some((id) => fields.contradicting.includes(id)))
      return err(
        inputError(operation, [
          {
            path: "contradicting",
            reason: "conflicting_arguments",
            message: "An evidence id cannot both support and contradict.",
          },
        ]),
      );
    return this.#commit(head, fields, operation);
  }

  async #commit(
    head: ResidualUnknown | undefined,
    fields: UnknownFields,
    operation: string,
  ): Promise<
    Result<
      { readonly unknown_id: UnkId; readonly revision: number; readonly status: string; readonly evidence_id: EvId },
      BeaError
    >
  > {
    const draftRevision = nextRevision(head, fields, `ev_${"0".repeat(64)}`);
    const change =
      head === undefined
        ? ["created"]
        : CHANGE_FIELDS.filter(([key]) => JSON.stringify(head[key]) !== JSON.stringify(draftRevision[key])).map(
            ([, name]) => name,
          );
    const links = [...new Set([...fields.supporting, ...fields.contradicting])];
    const recorded = await this.deps.recorder().record({
      predicate_type: "bea.unknown.mutation",
      operation,
      input: {
        unknown_id: draftRevision.unknown_id,
        revision: draftRevision.revision,
        status: draftRevision.status,
        severity: draftRevision.severity,
      },
      subject: null,
      provider: { id: "bea", name: "bea", version: null },
      result: {
        unknown_id: draftRevision.unknown_id,
        revision: draftRevision.revision,
        status: draftRevision.status,
        change,
      },
      coverage: COMPLETE,
      limitations: [LIMITATIONS.UNKNOWN_MUTATION_INTENT],
      evidence_links: links,
      literals: this.deps.serverLiterals(),
    });
    if (!recorded.ok) return recorded;
    const evidence_id = recorded.value.record.evidence_id;
    const revision = nextRevision(head, fields, evidence_id);
    const parsed = residualUnknownSchema.safeParse(revision);
    if (!parsed.success)
      return err(internalError(operation, `unknown revision invalid: ${parsed.error.issues[0]?.message ?? ""}`));
    const appended = await this.deps.ledger.append({ t: "unk", revision }, { operation });
    if (!appended.ok) return appended;
    this.deps.index.addUnknown(revision, appended.value);
    return ok({ unknown_id: revision.unknown_id, revision: revision.revision, status: revision.status, evidence_id });
  }

  async autoRecord(
    input: Omit<UnknownInput, "unknown_id" | "expected_revision">,
    operation: string,
  ): Promise<Result<{ readonly unknown_id: UnkId; readonly revision: number }, BeaError>> {
    const question = redactExplicitText(input.question ?? "", this.deps.serverLiterals());
    const id = unknownIdOf(input.domain, question, scopeOf(input.scope_image_sha256, this.deps.runId));
    const existing = this.deps.index.unknownHead(id);
    if (existing !== undefined) return ok({ unknown_id: existing.unknown_id, revision: existing.revision });
    const created = await this.upsert(
      { ...input, status: input.status === "resolved" ? "open" : input.status, resolution: null },
      operation,
    );
    return created.ok ? ok({ unknown_id: created.value.unknown_id, revision: created.value.revision }) : created;
  }
}
