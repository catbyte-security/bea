import type { RecordingKindSpec } from "../../../ports/recordings.js";
import { API_EVENT_FIELDS, decodeApiRow, parseApiDecoders } from "../../behavior/apiEvents.js";
import { apiSummaryBuilder, type ApiSummaryState } from "../../behavior/ApiSummary.js";

/**
 * Recording kind "api" (trace_api; WP-BEHAVIOR). Rows: api/1 tuples (catalog + pseudo APIs, src/shared/apiProfiles.ts);
 * events: S6 §5.4 api fields plus `g`/`parent` (the agent's sequence and parent call, for nesting); summary: ApiSummary
 * (S6 §5.3). The recording's `decoders` carry ApiDecoders (catalog minor, include_failed, caller, user_sid).
 */
export const API_KIND: RecordingKindSpec<ApiSummaryState> = {
  kind: "api",
  rowKinds: ["api/1"],
  fields: API_EVENT_FIELDS,
  *decode(record, ctx) {
    const event = decodeApiRow(record.fields, {
      seq: record.seq,
      startedAtUs: ctx.startedAtUs,
      decoders: parseApiDecoders(ctx.decoders),
      frame: (va) => ctx.frame(va).at,
    });
    if (event !== null) yield event;
  },
  summary: apiSummaryBuilder,
};
