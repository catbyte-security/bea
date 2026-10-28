import type { JsonValue } from "../../../domain/json.js";
import type { EventRecord, RecordingKindSpec } from "../../../ports/recordings.js";

/**
 * Built-in recording "output" (WP-SESS; S6 §2.5, §5.3, §5.4): stdout/stderr of a piped owned target. Host-produced
 * NDJSON rows [t_ms, fd, text, invalid_utf8] with text ≤ 4 KiB per row (UTF-8 decoded with replacement; invalid input
 * is flagged). Summary: `{stdout_bytes, stderr_bytes, retained_bytes, truncated, tail}` with tail ≤ 2 KiB. The text
 * is target-controlled.
 */
export interface OutputSummaryState {
  stdoutBytes: number;
  stderrBytes: number;
  tail: string;
  invalid: boolean;
}

const TAIL_CHARS = 2048;

export const OUTPUT_KIND: RecordingKindSpec<OutputSummaryState> = {
  kind: "output",
  rowKinds: ["bytes"],
  fields: [
    { name: "fd", type: "int" },
    { name: "text", type: "string" },
    { name: "invalid_utf8", type: "bool" },
  ],
  *decode(record) {
    const row = record.fields;
    if (!Array.isArray(row) || row.length < 3) return;
    const [tMs, fd, text, invalid] = row as readonly JsonValue[];
    if ((fd !== 1 && fd !== 2) || typeof text !== "string") return;
    const event: EventRecord = {
      seq: record.seq,
      t_ms: typeof tMs === "number" ? tMs : 0,
      fd,
      text,
      invalid_utf8: invalid === 1 || invalid === true,
    };
    yield event;
  },
  summary: {
    init: () => ({ stdoutBytes: 0, stderrBytes: 0, tail: "", invalid: false }),
    add: (state, event) => {
      const text = typeof event["text"] === "string" ? event["text"] : "";
      const bytes = Buffer.byteLength(text, "utf8");
      if (event["fd"] === 2) state.stderrBytes += bytes;
      else state.stdoutBytes += bytes;
      state.tail = `${state.tail}${text}`.slice(-TAIL_CHARS);
      if (event["invalid_utf8"] === true) state.invalid = true;
    },
    finish: (state) => ({
      stdout_bytes: state.stdoutBytes,
      stderr_bytes: state.stderrBytes,
      retained_bytes: state.stdoutBytes + state.stderrBytes,
      truncated: false,
      tail: state.tail,
      invalid_utf8: state.invalid,
    }),
  },
};
