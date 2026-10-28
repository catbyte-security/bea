import type { RecordingKindSpec } from "../../../ports/recordings.js";
import { watchDecodersOf } from "../../watch/decoders.js";
import { decodeWatchRow, WATCH_SUMMARY, type WatchSummaryState } from "../../watch/events.js";

/**
 * Recording kind "watch" (WP9-WATCH): watch/1 rows of debug-register and page-guard watches (S6 §4.22, §5.3, §5.4).
 * Field dictionary S6 §5.4 + method/insn_va/insn_static/operand/addr/before/after; marker events carry the agent's
 * page-guard counters and the rate-valve trip (src/application/watch/decoders.ts).
 */
export const WATCH_KIND: RecordingKindSpec<WatchSummaryState> = {
  kind: "watch",
  rowKinds: ["watch/1"],
  fields: [
    { name: "tid", type: "int" },
    { name: "method", type: "string" },
    { name: "access", type: "string" },
    { name: "insn", type: "address" },
    { name: "insn_va", type: "address" },
    { name: "insn_static", type: "string" },
    { name: "insn_text", type: "string" },
    { name: "insn_confidence", type: "string" },
    { name: "func", type: "address" },
    { name: "addr", type: "address" },
    { name: "operand", type: "object" },
    { name: "struct_base", type: "address" },
    { name: "disp", type: "string" },
    { name: "value", type: "string" },
    { name: "value_when", type: "string" },
    { name: "before", type: "string" },
    { name: "after", type: "string" },
    { name: "bt", type: "array" },
    { name: "marker", type: "string" },
  ],
  decode: (record, ctx) => decodeWatchRow(record, ctx, watchDecodersOf(ctx.decoders)),
  summary: WATCH_SUMMARY,
};
