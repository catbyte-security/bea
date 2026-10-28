import type { InputIssue } from "../../domain/errors/beaError.js";
import type { JsonValue } from "../../domain/json.js";
import type { EventField, EventRecord } from "../../ports/recordings.js";
import { floatBitsOf } from "./kinds/hook.js";
import { FieldStatsAccumulator, compareNumeric, numericOf, type Scalar } from "./summaryUtil.js";

/**
 * query_events engine (S6 §4.26, CI-I6; WP7-HOOK). Runs `where` / projection / group / stats / paging over any
 * decoded event source: RecordingRegistry.events() for recordings, or the generic NDJSON rows of a host row stream.
 * Reading never consumes: `source()` is called once per pass (twice for `order:"desc"` rows: count, then page).
 *
 * Output pages are COLUMNAR (`columns` + one cell array per row). Cells are scalars; arrays and objects become compact
 * text; strings longer than `cellChars` are shortened with "…" and counted (`truncatedValues`).
 */
export type Cell = number | string | boolean | null;
export type QueryView = "rows" | "group" | "stats";

export interface WhereClause {
  readonly field: string;
  readonly op: "eq" | "ne" | "lt" | "le" | "gt" | "ge" | "contains" | "prefix";
  readonly value: number | string | boolean;
}
export interface QueryRequest {
  readonly view: QueryView;
  readonly where: readonly WhereClause[];
  readonly group_by?: readonly string[] | undefined;
  readonly fields?: readonly string[] | undefined;
  readonly order: "asc" | "desc";
  readonly offset: number;
  readonly limit: number;
}
export interface StatRow {
  readonly field: string;
  readonly type: string;
  readonly count: number;
  readonly min: Cell;
  readonly max: Cell;
  readonly mean: number | null;
  readonly distinct: number;
  readonly distinct_capped: boolean;
  readonly top: readonly { readonly value: Cell; readonly count: number }[];
}
export interface QueryPage {
  readonly columns: readonly string[];
  readonly rows: readonly (readonly Cell[])[];
  readonly total: number;
  readonly next_offset: number | null;
  readonly stats?: readonly StatRow[];
  /** events scanned (all passes count once) */
  readonly scanned: number;
  readonly truncatedValues: number;
  /** groups beyond GROUP_CAP were folded into the totals only */
  readonly groupsCapped: boolean;
}
export interface QueryOptions {
  readonly cellChars: number;
  readonly maxColumns: number;
  readonly signal?: AbortSignal;
}

/** Fields every event carries (S6 §5.4). */
export const BASE_FIELDS: readonly EventField[] = [
  { name: "seq", type: "int" },
  { name: "t_ms", type: "float" },
  { name: "tid", type: "int" },
];
export const GROUP_CAP = 10_000;
const BITS = ":bits";

/** Host row streams (CI-I6) carry only the stream-local seq besides their own columns. */
export const STREAM_BASE_FIELDS: readonly EventField[] = [{ name: "seq", type: "int" }];

/** Field list for the first page and validation: base fields first, duplicates removed, auxiliary keys excluded. */
export const availableFields = (
  extra: readonly EventField[],
  base: readonly EventField[] = BASE_FIELDS,
): readonly EventField[] => {
  const seen = new Set<string>();
  const out: EventField[] = [];
  for (const f of [...base, ...extra])
    if (!seen.has(f.name) && !f.name.includes(":")) {
      seen.add(f.name);
      out.push(f);
    }
  return out;
};

/** Field types inferred from one host row (generic NDJSON streams, CI-I6). */
export const fieldsOfRow = (row: Readonly<Record<string, JsonValue>>): readonly EventField[] =>
  Object.entries(row)
    .filter(([k]) => !k.includes(":"))
    .map(([name, v]) => ({
      name,
      type:
        typeof v === "number"
          ? Number.isInteger(v)
            ? "int"
            : "float"
          : typeof v === "boolean"
            ? "bool"
            : typeof v === "string"
              ? "string"
              : Array.isArray(v)
                ? "array"
                : "object",
    }));

/** invalid_request issues for unknown fields (the message lists what exists). */
export function validateQuery(req: QueryRequest, available: readonly EventField[]): InputIssue[] {
  const names = new Set(available.map((f) => f.name));
  const list = available.map((f) => f.name).join(", ");
  const listed = list.length > 700 ? `${list.slice(0, 700)}…` : list;
  const issues: InputIssue[] = [];
  const check = (name: string, path: string): void => {
    const base = name.endsWith(BITS) ? name.slice(0, -BITS.length) : name;
    if (!names.has(base))
      issues.push({
        path,
        reason: "invalid_value",
        message: `Unknown field "${name.slice(0, 80)}". Available fields: ${listed}. Append ":bits" to a float field for its raw bits.`,
        expected: "a field of this recording",
      });
  };
  req.where.forEach((w, i) => check(w.field, `where[${String(i)}].field`));
  req.group_by?.forEach((g, i) => check(g, `group_by[${String(i)}]`));
  req.fields?.forEach((f, i) => check(f, `fields[${String(i)}]`));
  return issues;
}

/** Value of a (possibly ":bits") field of an event. */
export const fieldValue = (
  e: EventRecord,
  name: string,
  types: ReadonlyMap<string, EventField["type"]>,
): JsonValue | undefined => {
  if (!name.endsWith(BITS)) return e[name];
  const base = name.slice(0, -BITS.length);
  const own = e[name];
  if (own !== undefined) return own;
  const v = e[base];
  if (v === undefined || types.get(base) !== "float") return v;
  return floatBitsOf(v, true);
};

const textOf = (v: JsonValue): string => (typeof v === "string" ? v : JSON.stringify(v));

/** where semantics: numeric comparison when both sides are numeric (64-bit strings exact), text otherwise. */
export function matches(v: JsonValue | undefined, w: WhereClause): boolean {
  if (v === undefined || v === null) return w.op === "ne";
  if (Array.isArray(v) && (w.op === "contains" || w.op === "prefix")) return v.some((x) => matches(x, w));
  if (w.op === "contains" || w.op === "prefix") {
    const hay = textOf(v).toLowerCase();
    const needle = String(w.value).toLowerCase();
    return w.op === "contains" ? hay.includes(needle) : hay.startsWith(needle);
  }
  const a = numericOf(v);
  const b = numericOf(w.value);
  let cmp: number;
  if (a !== null && b !== null) cmp = compareNumeric(a, b);
  else if (typeof v === "boolean" || typeof w.value === "boolean") {
    if (w.op !== "eq" && w.op !== "ne") return false;
    cmp = v === w.value ? 0 : 1;
  } else {
    const sa = textOf(v);
    const sb = String(w.value);
    cmp = sa < sb ? -1 : sa > sb ? 1 : 0;
  }
  switch (w.op) {
    case "eq":
      return cmp === 0;
    case "ne":
      return cmp !== 0;
    case "lt":
      return cmp < 0;
    case "le":
      return cmp <= 0;
    case "gt":
      return cmp > 0;
    case "ge":
      return cmp >= 0;
  }
}

class CellWriter {
  truncated = 0;
  constructor(private readonly chars: number) {}
  cell(v: JsonValue | undefined): Cell {
    if (v === undefined || v === null) return null;
    if (typeof v === "number" || typeof v === "boolean") return v;
    const s = Array.isArray(v) && v.every((x) => typeof x === "string") ? v.join(" < ") : textOf(v);
    if (s.length <= this.chars) return s;
    this.truncated++;
    return `${s.slice(0, this.chars - 1)}…`;
  }
}

const aborted = (signal: AbortSignal | undefined, n: number): boolean => (n & 4095) === 0 && signal?.aborted === true;

/** Run one query view. Throws only when the signal aborts (the caller maps that to cancelled/provider_timeout). */
export async function runQuery(
  source: () => AsyncIterable<EventRecord>,
  available: readonly EventField[],
  req: QueryRequest,
  opts: QueryOptions,
): Promise<QueryPage> {
  const types = new Map(available.map((f) => [f.name, f.type] as const));
  const keep = (e: EventRecord): boolean => req.where.every((w) => matches(fieldValue(e, w.field, types), w));
  const writer = new CellWriter(opts.cellChars);
  let scanned = 0;
  const pass = async (visit: (e: EventRecord) => void): Promise<void> => {
    for await (const e of source()) {
      if (aborted(opts.signal, ++scanned)) throw opts.signal?.reason ?? new Error("aborted");
      if (keep(e)) visit(e);
    }
  };

  if (req.view === "rows") {
    const projected =
      req.fields !== undefined && req.fields.length > 0
        ? req.fields.filter((f) => f !== "seq")
        : available.map((f) => f.name).filter((n) => n !== "seq");
    const columns = ["seq", ...projected].slice(0, opts.maxColumns);
    const row = (e: EventRecord): Cell[] => columns.map((c) => writer.cell(fieldValue(e, c, types)));
    const rows: Cell[][] = [];
    let total = 0;
    if (req.order === "asc") {
      await pass((e) => {
        if (total >= req.offset && rows.length < req.limit) rows.push(row(e));
        total++;
      });
    } else {
      await pass(() => {
        total++;
      });
      const hi = total - req.offset; // exclusive end (oldest-first index) of the newest-first page
      const lo = Math.max(0, hi - req.limit);
      let i = 0;
      const picked: Cell[][] = [];
      if (hi > 0)
        await pass((e) => {
          if (i >= lo && i < hi) picked.push(row(e));
          i++;
        });
      rows.push(...picked.reverse());
    }
    const next = req.offset + rows.length;
    return {
      columns,
      rows,
      total,
      next_offset: next < total ? next : null,
      scanned,
      truncatedValues: writer.truncated,
      groupsCapped: false,
    };
  }

  if (req.view === "group") {
    const by = (req.group_by ?? []).slice(0, 3);
    const groups = new Map<string, { values: JsonValue[]; count: number; first: number; last: number }>();
    let capped = false;
    await pass((e) => {
      const values = by.map((g) => fieldValue(e, g, types) ?? null);
      const key = JSON.stringify(values);
      const seq = typeof e.seq === "number" ? e.seq : 0;
      const g = groups.get(key);
      if (g !== undefined) {
        g.count++;
        g.last = seq;
      } else if (groups.size < GROUP_CAP) groups.set(key, { values, count: 1, first: seq, last: seq });
      else capped = true;
    });
    const sorted = [...groups.values()].sort((a, b) => b.count - a.count || a.first - b.first);
    const page = sorted.slice(req.offset, req.offset + req.limit);
    const next = req.offset + page.length;
    return {
      columns: [...by, "count", "first_seq", "last_seq"],
      rows: page.map((g) => [...g.values.map((v) => writer.cell(v)), g.count, g.first, g.last]),
      total: sorted.length,
      next_offset: next < sorted.length ? next : null,
      scanned,
      truncatedValues: writer.truncated,
      groupsCapped: capped,
    };
  }

  // stats
  const targets = (
    req.fields !== undefined && req.fields.length > 0
      ? [...req.fields]
      : available.map((f) => f.name).filter((n) => n !== "seq")
  ).slice(0, opts.maxColumns - 1);
  const accs = targets.map(
    (f) => new FieldStatsAccumulator(types.get(f.endsWith(BITS) ? f.slice(0, -BITS.length) : f) ?? "unknown"),
  );
  await pass((e) => targets.forEach((f, i) => accs[i]?.add(fieldValue(e, f, types))));
  const all: StatRow[] = targets.map((field, i) => {
    const r = (accs[i] ?? new FieldStatsAccumulator("unknown")).result(opts.cellChars);
    return {
      field,
      type: r.type,
      count: r.count,
      min: writer.cell(r.min),
      max: writer.cell(r.max),
      mean: r.mean,
      distinct: r.distinct,
      distinct_capped: r.distinct_capped,
      top: r.top.map((t) => ({ value: writer.cell(t.value as Scalar), count: t.count })),
    };
  });
  const page = all.slice(req.offset, req.offset + req.limit);
  const next = req.offset + page.length;
  return {
    columns: [],
    rows: [],
    stats: page,
    total: all.length,
    next_offset: next < all.length ? next : null,
    scanned,
    truncatedValues: writer.truncated,
    groupsCapped: false,
  };
}
