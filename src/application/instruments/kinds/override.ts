import type { JsonObject, JsonValue } from "../../../domain/json.js";
import type { EventField, EventRecord, RecordingKindSpec } from "../../../ports/recordings.js";

/**
 * Recording kind "override" (WP12-MODIFY; S4 §4.6 `override/1`, S6 §5.3/§5.4). One row per APPLIED call:
 * `[g, t, tid, override, applied: "args"|"ret"|"replace", detail: ValueCell[]]`, where `detail` holds the original
 * values the override replaced (args: the original argument cells in set_args order; ret: the original return;
 * replace: empty, the original never ran). Events: `seq, t_ms, tid, applied, original`.
 */
export const OVERRIDE_FIELDS: readonly EventField[] = [
  { name: "seq", type: "int" },
  { name: "t_ms", type: "float" },
  { name: "tid", type: "int" },
  { name: "applied", type: "string" },
  { name: "original", type: "array" },
];

const APPLIED = ["args", "ret", "replace"] as const;
type Applied = (typeof APPLIED)[number];

/** Strict tuple check: the agent shares the target's address space, so a malformed row is skipped, never trusted. */
export const parseOverrideRow = (
  fields: JsonValue,
): {
  readonly t: number;
  readonly tid: number;
  readonly applied: Applied;
  readonly detail: readonly JsonValue[];
} | null => {
  if (!Array.isArray(fields) || fields.length !== 6) return null;
  const [g, t, tid, , applied, detail] = fields as readonly JsonValue[];
  if (typeof g !== "number" || typeof t !== "number" || typeof tid !== "number") return null;
  if (!Number.isFinite(t) || !Number.isInteger(tid) || tid < 0) return null;
  if (typeof applied !== "string" || !(APPLIED as readonly string[]).includes(applied)) return null;
  if (!Array.isArray(detail)) return null;
  return { t, tid, applied: applied as Applied, detail };
};

/** Summary digest (S6 §5.3): bounded, every list capped with totals. */
const MAX_THREADS = 16;
interface OverrideSummaryState {
  applications: number;
  readonly byApplied: Record<Applied, number>;
  readonly threads: Map<number, number>;
  firstMs: number | null;
  lastMs: number | null;
}

export const OVERRIDE_KIND: RecordingKindSpec<OverrideSummaryState> = {
  kind: "override",
  rowKinds: ["override/1"],
  fields: OVERRIDE_FIELDS,
  *decode(record, ctx): Iterable<EventRecord> {
    const row = parseOverrideRow(record.fields);
    if (row === null) return;
    yield {
      seq: record.seq,
      t_ms: Math.max(0, (row.t - ctx.startedAtUs) / 1000),
      tid: row.tid,
      applied: row.applied,
      original: [...row.detail],
    };
  },
  summary: {
    init: () => ({
      applications: 0,
      byApplied: { args: 0, ret: 0, replace: 0 },
      threads: new Map(),
      firstMs: null,
      lastMs: null,
    }),
    add: (state, event) => {
      state.applications += 1;
      const applied = event["applied"];
      if (applied === "args" || applied === "ret" || applied === "replace") state.byApplied[applied] += 1;
      const tid = event["tid"];
      if (typeof tid === "number") state.threads.set(tid, (state.threads.get(tid) ?? 0) + 1);
      const t = event["t_ms"];
      if (typeof t === "number") {
        state.firstMs = state.firstMs === null ? t : Math.min(state.firstMs, t);
        state.lastMs = state.lastMs === null ? t : Math.max(state.lastMs, t);
      }
    },
    finish: (state): JsonObject => {
      const threads = [...state.threads.entries()]
        .sort((a, b) => b[1] - a[1] || a[0] - b[0])
        .slice(0, MAX_THREADS)
        .map(([tid, count]) => ({ tid, count }));
      return {
        applications: state.applications,
        by_applied: { ...state.byApplied },
        threads,
        threads_total: state.threads.size,
        first_t_ms: state.firstMs,
        last_t_ms: state.lastMs,
      };
    },
  },
};
