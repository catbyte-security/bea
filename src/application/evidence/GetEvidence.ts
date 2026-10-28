import type { z } from "zod";

import type { getEvidenceInputSchema, getEvidenceOutputSchema } from "../../contracts/areas/evidence.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import type { EvId } from "../../domain/ids.js";
import type { JsonObject } from "../../domain/json.js";
import { ok, type Result } from "../../domain/result.js";
import type { EvidenceRuntime } from "../../ports/evidence.js";
import { pollEnvelope } from "./envelope.js";

type Input = z.output<typeof getEvidenceInputSchema>;
type Output = z.output<typeof getEvidenceOutputSchema>;

/**
 * get_evidence (S2 §12, DESIGN §6.2 #34): a poll over retained data. Slices return the SOURCE evidence id in
 * `slice.evidence_id`; nothing is recorded. Every result carries the untrusted marker (contract default).
 */
export const getEvidence = async (evidence: EvidenceRuntime, input: Input): Promise<Result<Output, BeaError>> => {
  if (input.detail === "summary") {
    const summary = evidence.query.summary({
      entity: input.entity,
      offset: input.offset,
      limit: input.limit,
      ...(input.filters === undefined ? {} : { filters: input.filters as JsonObject }),
    });
    if (!summary.ok) return summary;
    return ok({
      view: "summary",
      summary: summary.value as unknown as NonNullable<Output["summary"]>,
      ...pollEnvelope(),
    } as Output);
  }
  const id = input.id ?? "";
  if (input.detail === "complete") {
    const record = await evidence.query.complete(id);
    if (!record.ok) return record;
    return ok({
      view: "complete",
      record: record.value as unknown as NonNullable<Output["record"]>,
      ...pollEnvelope(),
    } as Output);
  }
  const slice = await evidence.query.slice(id as EvId, input.pointer ?? "", input.offset, input.limit, input.format);
  if (!slice.ok) return slice;
  return ok({
    view: "slice",
    slice: slice.value as unknown as NonNullable<Output["slice"]>,
    ...pollEnvelope(),
  } as Output);
};
