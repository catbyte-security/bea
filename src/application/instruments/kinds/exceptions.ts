import type { JsonObject, JsonValue } from "../../../domain/json.js";
import type { EventRecord, RecordingKindSpec } from "../../../ports/recordings.js";

/**
 * Built-in recording "exceptions" (WP-SESS; S6 §2.5, §5.3, §5.4): every first-chance exception the agent's single
 * dispatcher saw, from the `s:exceptions` stream (`exception/1` rows: [g, t, tid, type, address, mem_op, mem_addr,
 * disposition, repeat]). Rows raised inside a BEA oracle call carry disposition `in-call` (never a crash). Summary:
 * `{count, by_type, last}` (count includes repeats folded by the agent's rate cap).
 */
export interface ExceptionsSummaryState {
  count: number;
  readonly byType: Map<string, number>;
  last: JsonObject | null;
}

const isHex = (value: unknown): value is string => typeof value === "string" && /^0x[0-9a-f]{1,16}$/u.test(value);

export const EXCEPTIONS_KIND: RecordingKindSpec<ExceptionsSummaryState> = {
  kind: "exceptions",
  rowKinds: ["exception/1"],
  fields: [
    { name: "type", type: "string" },
    { name: "address", type: "address" },
    { name: "memory_op", type: "string" },
    { name: "memory_address", type: "address" },
    { name: "insn", type: "string" },
    { name: "disposition", type: "string" },
    { name: "repeat", type: "int" },
  ],
  *decode(record, ctx) {
    const row = record.fields;
    if (!Array.isArray(row) || row.length < 9) return;
    const [, t, tid, type, address, memOp, memAddr, disposition, repeat] = row as readonly JsonValue[];
    const at = isHex(address) ? (ctx.frame(address).at ?? address) : null;
    const event: EventRecord = {
      seq: record.seq,
      t_ms: typeof t === "number" ? Math.max(0, Math.round((t - ctx.startedAtUs) / 1000)) : 0,
      ...(typeof tid === "number" ? { tid } : {}),
      type: typeof type === "string" ? type : "unknown",
      address: at,
      memory_op: typeof memOp === "string" ? memOp : null,
      memory_address: isHex(memAddr) ? memAddr : null,
      insn: null,
      disposition: typeof disposition === "string" ? disposition : "passed",
      repeat: typeof repeat === "number" && repeat > 0 ? repeat : 1,
    };
    yield event;
  },
  summary: {
    init: () => ({ count: 0, byType: new Map(), last: null }),
    add: (state, event) => {
      const repeat = typeof event["repeat"] === "number" ? event["repeat"] : 1;
      const type = typeof event["type"] === "string" ? event["type"] : "unknown";
      state.count += repeat;
      state.byType.set(type, (state.byType.get(type) ?? 0) + repeat);
      state.last = {
        seq: event.seq,
        type,
        address: event["address"] ?? null,
        memory_op: event["memory_op"] ?? null,
        memory_address: event["memory_address"] ?? null,
        disposition: event["disposition"] ?? null,
      };
    },
    finish: (state) => ({
      count: state.count,
      by_type: Object.fromEntries([...state.byType.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))),
      last: state.last,
    }),
  },
};
