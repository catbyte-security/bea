import type { JsonValue } from "../../../domain/json.js";
import type { EventRecord, RecordingKindSpec } from "../../../ports/recordings.js";

/**
 * Built-in recording "modules" (WP-SESS; S6 §2.5, §5.3, §5.4): module loads and unloads from the agent's module
 * observer on `s:modules` (`module/1` rows: [g, t, ev "L"|"U", name, path, base, size, epoch]). These rows also drive
 * the host's module-map epochs (the agent owns the epoch counter; the host mirrors it). Summary:
 * `{loaded, unloaded, rows ≤ 50}`. Paths are target-controlled text.
 */
export interface ModulesSummaryState {
  loaded: number;
  unloaded: number;
  readonly rows: { readonly event: string; readonly path: string; readonly base: string }[];
  total: number;
}

const MAX_ROWS = 50;

export const MODULES_KIND: RecordingKindSpec<ModulesSummaryState> = {
  kind: "modules",
  rowKinds: ["module/1"],
  fields: [
    { name: "event", type: "string" },
    { name: "name", type: "string" },
    { name: "path", type: "string" },
    { name: "base", type: "address" },
    { name: "size", type: "int" },
    { name: "epoch", type: "int" },
  ],
  *decode(record, ctx) {
    const row = record.fields;
    if (!Array.isArray(row) || row.length < 8) return;
    const [, t, ev, name, path, base, size, epoch] = row as readonly JsonValue[];
    if (ev !== "L" && ev !== "U") return;
    const event: EventRecord = {
      seq: record.seq,
      t_ms: typeof t === "number" ? Math.max(0, Math.round((t - ctx.startedAtUs) / 1000)) : 0,
      event: ev === "L" ? "load" : "unload",
      name: typeof name === "string" ? name.slice(0, 260) : "",
      path: typeof path === "string" ? path.slice(0, 1024) : "",
      base: typeof base === "string" ? base : "0x0",
      size: typeof size === "number" ? size : 0,
      epoch: typeof epoch === "number" ? epoch : 0,
    };
    yield event;
  },
  summary: {
    init: () => ({ loaded: 0, unloaded: 0, rows: [], total: 0 }),
    add: (state, event) => {
      if (event["event"] === "load") state.loaded += 1;
      else state.unloaded += 1;
      state.total += 1;
      if (state.rows.length < MAX_ROWS)
        state.rows.push({
          event: String(event["event"]),
          path: typeof event["path"] === "string" ? event["path"] : "",
          base: typeof event["base"] === "string" ? event["base"] : "0x0",
        });
    },
    finish: (state) => ({
      loaded: state.loaded,
      unloaded: state.unloaded,
      rows: state.rows.map((row) => ({ ...row })),
      truncated: state.total > state.rows.length,
    }),
  },
};
