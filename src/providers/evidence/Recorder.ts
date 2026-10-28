import { sha256Hex } from "../../domain/canonical.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { withEffects } from "../../domain/errors/constructors.js";
import { evidenceIntegrity } from "../../domain/evidence/authenticate.js";
import { buildEvidence, type ParentFacts } from "../../domain/evidence/build.js";
import type { EvId, MmId, PiId } from "../../domain/ids.js";
import type { JsonValue } from "../../domain/json.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { EvidenceDraft, RecordedEvidence, Recorder } from "../../ports/evidence.js";
import type { Ledger } from "./Ledger.js";
import type { EvidenceRow, LedgerIndex } from "./LedgerIndex.js";

export interface RecorderDeps {
  readonly index: LedgerIndex;
  readonly ledger: Ledger;
  /** materialize-on-reference (S2 §5): the mm line + bea.modules.map evidence of one epoch */
  readonly ensureModuleMap: (
    instance: PiId,
    epoch: number,
    operation: string,
  ) => Promise<Result<{ readonly module_map_id: MmId; readonly evidence_id: EvId }, BeaError>>;
  /** extra parent facts (records indexed elsewhere are always in `index`) */
  readonly onRecorded?: (row: EvidenceRow) => void;
}

export const parentFactsOf =
  (index: LedgerIndex) =>
  (id: EvId): ParentFacts | undefined => {
    const row = index.byId.get(id);
    return row === undefined ? undefined : { authority: row.authority, perturbation: row.perturbation };
  };

/**
 * The record pipeline (S2 §7.9): buildEvidence (registry, parameters, subject, perturbation, limitations, redaction,
 * validation, id) → reference closure (module map materialized first; every evidence link must resolve) → append the
 * {t:"ev"} line and await it → index. Same id + identical bytes = "duplicate"; same id + different bytes =
 * evidence_integrity_mismatch. Every error carries the draft's effects (S2 §9.5: a success is never shown without
 * retention, and applied effects are never hidden).
 */
export class EvidenceRecorder implements Recorder {
  readonly #inFlight = new Map<EvId, Promise<unknown>>();

  constructor(private readonly deps: RecorderDeps) {}

  async record<R extends JsonValue>(
    draft: EvidenceDraft<R>,
    opts?: { readonly lifecycle?: boolean },
  ): Promise<Result<RecordedEvidence<R>, BeaError>> {
    const fail = (error: BeaError): Result<never, BeaError> => err(withEffects(error, draft.effects ?? []));
    const extraLinks: EvId[] = [];
    const subject = draft.subject;
    if (
      draft.capture !== undefined &&
      draft.predicate_type !== "bea.modules.map" &&
      subject?.kind === "process-instance" &&
      draft.capture.anchor.module_map_epoch !== null
    ) {
      const mm = await this.deps.ensureModuleMap(
        subject.instance_id,
        draft.capture.anchor.module_map_epoch,
        draft.operation,
      );
      if (!mm.ok) return fail(mm.error);
      if ((draft.locations ?? []).some((l) => l.kind === "address" && l.module_map_id !== null))
        extraLinks.push(mm.value.evidence_id);
    }
    const built = buildEvidence(draft, { extraLinks, parent: parentFactsOf(this.deps.index) });
    if (!built.ok) return fail(built.error);
    const record = built.value.record;
    for (const link of record.evidence_links)
      if (!this.deps.index.byId.has(link))
        return fail(evidenceIntegrity(draft.operation, "dangling-link", { evidence_id: link }));

    const id = record.evidence_id;
    const previous = this.#inFlight.get(id);
    if (previous !== undefined) await previous.catch(() => undefined);
    const task = this.#append(record, built.value.canonical, opts?.lifecycle === true, draft.operation);
    this.#inFlight.set(id, task);
    try {
      const outcome = await task;
      return outcome.ok
        ? ok({ record: record as RecordedEvidence<R>["record"], outcome: outcome.value })
        : fail(outcome.error);
    } finally {
      if (this.#inFlight.get(id) === task) this.#inFlight.delete(id);
    }
  }

  async #append(
    record: RecordedEvidence<JsonValue>["record"],
    canonical: string,
    lifecycle: boolean,
    operation: string,
  ): Promise<Result<"added" | "duplicate", BeaError>> {
    // canonicalJson({t:"ev", record}): keys sort as "record" < "t", so the record's own encoding is reused
    const text = `{"record":${canonical},"t":"ev"}`;
    const existing = this.deps.index.byId.get(record.evidence_id);
    if (existing !== undefined)
      return sha256Hex(text) === existing.ref.sha256
        ? ok("duplicate")
        : err(evidenceIntegrity(operation, "conflicting-record", { evidence_id: record.evidence_id }));
    const appended = await this.deps.ledger.appendText(
      `${text}
`,
      { operation, lifecycle },
    );
    if (!appended.ok) return appended;
    const row = this.deps.index.addEvidence(record, appended.value);
    this.deps.onRecorded?.(row);
    return ok("added");
  }
}
