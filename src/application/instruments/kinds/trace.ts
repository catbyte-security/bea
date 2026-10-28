import type { EventField, RecordingKindSpec } from "../../../ports/recordings.js";
import { traceDecodersOf } from "../../watch/decoders.js";
import { decodeTraceRecord, TRACE_SUMMARY, type TraceSummaryState } from "../../watch/events.js";

/** S6 §5.4 trace fields: blocks (block/size/hits), call edges and on_call invocations. A separate constant because
 *  scripts/verify-module-boundaries.mjs scans an `export … = {` statement up to the first quoted string after the
 *  word `from` and would read the edge field's name as an import specifier. */
const TRACE_FIELDS: readonly EventField[] = [
  { name: "block", type: "address" },
  { name: "va", type: "address" },
  { name: "size", type: "int" },
  { name: "hits", type: "int" },
  { name: "module", type: "string" },
  { name: "entry", type: "bool" },
  { name: "from", type: "address" },
  { name: "to", type: "address" },
  { name: "count", type: "int" },
  { name: "invocations", type: "int" },
];

/**
 * Recording kind "trace" (WP9-WATCH): block-span/1, block-count/1 and call-site-count/1 records of trace_execution
 * (S6 §4.23, §5.3 TraceSummary). Functions are attributed by trace_execution and export_coverage, which read the
 * image from disk.
 */
export const TRACE_KIND: RecordingKindSpec<TraceSummaryState> = {
  kind: "trace",
  rowKinds: ["block-span/1", "block-count/1", "call-site-count/1"],
  fields: TRACE_FIELDS,
  decode: (record, ctx) => decodeTraceRecord(record, ctx, traceDecodersOf(ctx.decoders)),
  summary: TRACE_SUMMARY,
};
