import type { RecordingKindSpec } from "../../../ports/recordings.js";
import { pollDecodersOf } from "../../watch/decoders.js";
import { decodePollRow, POLL_SUMMARY, type PollSummaryState } from "../../watch/events.js";

/**
 * Recording kind "poll" (WP9-WATCH): poll/1 8-byte change cells split into view elements (S6 §4.22 poll, §5.3
 * PollSummary; fields offset, type, old, new).
 */
export const POLL_KIND: RecordingKindSpec<PollSummaryState> = {
  kind: "poll",
  rowKinds: ["poll/1"],
  fields: [
    { name: "offset", type: "address" },
    { name: "type", type: "string" },
    { name: "old", type: "string" },
    { name: "new", type: "string" },
  ],
  decode: (record, ctx) => decodePollRow(record, ctx, pollDecodersOf(ctx.decoders)),
  summary: POLL_SUMMARY,
};
