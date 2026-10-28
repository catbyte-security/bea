// =================================================================================================
// src/application/watch/events.ts — row decoders and bounded summaries of the watch, poll and trace recording kinds
// (S6 §5.3 WatchSummary/PollSummary/TraceSummary, §5.4 field dictionaries; WP9-WATCH). Rows come from the
// target-resident agent and are validated cell by cell: a malformed row decodes to nothing rather than failing the
// whole query. Function attribution (func/sym) needs the on-disk image, so summaries carry func:null and the
// installing tools enrich them (src/application/watch/locate.ts).
// =================================================================================================
import { formatHex, hexToBytes, type Hex } from "../../domain/hex.js";
import { isJsonObject, type JsonObject, type JsonValue } from "../../domain/json.js";
import type { DecodeContext, EventRecord } from "../../ports/recordings.js";
import type { StreamRecord } from "../../ports/evidence.js";
import type { WatchMemOperand } from "../../shared/agentProtocol.js";
import {
  compactOf,
  fieldOf,
  locate,
  toBig,
  WATCH_MARKER_FINAL,
  WATCH_MARKER_RATE_LIMIT,
  type PollDecoders,
  type TraceDecoders,
  type WatchDecoders,
} from "./decoders.js";
import {
  decodeElement,
  decodeWatched,
  insnConfidence,
  numericKey,
  pollElementWidth,
  structBaseOf,
  type ScalarOut,
  type WatchView,
} from "./values.js";

const HEX_RE = /^0x[0-9a-f]{1,16}$/u;
const BYTES_RE = /^(?:[0-9a-f]{2}){0,65536}$/u;
const hexCell = (v: JsonValue | undefined): Hex | null => (typeof v === "string" && HEX_RE.test(v) ? (v as Hex) : null);
const bytesCell = (v: JsonValue | undefined): string | null => (typeof v === "string" && BYTES_RE.test(v) ? v : null);
const intCell = (v: JsonValue | undefined): number | null =>
  typeof v === "number" && Number.isSafeInteger(v) && v >= 0 ? v : null;
const tMs = (t: number | null, ctx: DecodeContext): number | null =>
  t === null ? null : Math.max(0, Math.round(t - ctx.startedAtUs) / 1000);

// ---------------------------------------------------------------- watch/1

const memOf = (v: JsonValue | undefined): WatchMemOperand | null => {
  if (!isJsonObject(v)) return null;
  const scale = v["scale"];
  return {
    base: typeof v["base"] === "string" ? v["base"] : null,
    index: typeof v["index"] === "string" ? v["index"] : null,
    scale: scale === 1 || scale === 2 || scale === 4 || scale === 8 ? scale : 1,
    disp: typeof v["disp"] === "number" && Number.isSafeInteger(v["disp"]) ? v["disp"] : 0,
    size: typeof v["size"] === "number" ? v["size"] : 0,
    base_value: hexCell(v["base_value"]),
    base_written: v["base_written"] === true,
  };
};

const regsOf = (v: JsonValue | undefined, wanted: readonly string[], operand: WatchMemOperand | null): JsonObject => {
  if (!isJsonObject(v)) return {};
  const names = new Set(wanted);
  if (operand?.base !== null && operand?.base !== undefined) names.add(operand.base);
  if (operand?.index !== null && operand?.index !== undefined) names.add(operand.index);
  const out: Record<string, JsonValue> = {};
  for (const n of names) {
    const value = hexCell(v[n]);
    if (value !== null) out[n] = value;
  }
  return out;
};

const MARKERS: Readonly<Record<string, string>> = {
  [WATCH_MARKER_RATE_LIMIT]: "rate-limit",
  [WATCH_MARKER_FINAL]: "final",
};

/** A marker row: insn null, text "bea:<marker>", its counters (hex) in the regs slot. */
const markerEvent = (record: StreamRecord, ctx: DecodeContext, cells: readonly JsonValue[], marker: string) => {
  const counters = isJsonObject(cells[12]) ? cells[12] : {};
  const t = typeof cells[1] === "number" ? cells[1] : null;
  const out: Record<string, JsonValue> = { seq: record.seq, t_ms: tMs(t, ctx), tid: intCell(cells[2]), marker };
  for (const [k, v] of Object.entries(counters)) {
    const n = hexCell(v);
    if (n !== null && /^[a-z_]{1,32}$/u.test(k)) out[k] = Number(BigInt(n));
  }
  return out as EventRecord;
};

/** Backtrace frames in their compact form (at most 16; a frame the registry cannot place stays as is). */
const backtraceOf = (ctx: DecodeContext, cell: JsonValue | undefined): string[] | null => {
  if (!Array.isArray(cell)) return null;
  const frames = (cell as readonly JsonValue[]).filter((f): f is string => typeof f === "string").slice(0, 16);
  return frames.map((f) => {
    try {
      return ctx.frame(f).at ?? f;
    } catch {
      return f;
    }
  });
};

/** Debug registers trap after the access (value after); the page-guard engine reports the value before (S6 §10.8). */
const watchedValue = (
  d: WatchDecoders,
  access: string,
  before: string | null,
  after: string | null,
): { readonly value: ScalarOut; readonly valueWhen: "before" | "after" } => {
  if (access === "x") return { value: null, valueWhen: "after" };
  return d.method === "page_guard"
    ? { value: decodeWatched(before, d.view), valueWhen: "before" }
    : { value: decodeWatched(after, d.view), valueWhen: "after" };
};

/** One watch/1 row → one hit event, or one marker event. */
export function* decodeWatchRow(record: StreamRecord, ctx: DecodeContext, d: WatchDecoders): Iterable<EventRecord> {
  const row = record.fields;
  if (!Array.isArray(row) || row.length < 15) return;
  const cells = row as readonly JsonValue[];
  const text = typeof cells[8] === "string" ? cells[8] : null;
  const marker = text === null ? undefined : MARKERS[text];
  if (cells[5] === null && marker !== undefined) {
    yield markerEvent(record, ctx, cells, marker);
    return;
  }
  const t = typeof cells[1] === "number" ? cells[1] : null;
  const access = cells[4] === "w" || cells[4] === "x" ? cells[4] : "r";
  const insnVa = hexCell(cells[5]);
  const where = insnVa === null ? null : compactOf(ctx, d.modules, BigInt(insnVa));
  const mem = memOf(cells[14]);
  const base = structBaseOf(mem);
  const before = bytesCell(cells[10]);
  const after = bytesCell(cells[11]);
  const { value, valueWhen } = watchedValue(d, access, before, after);
  const event: Record<string, JsonValue> = {
    seq: record.seq,
    t_ms: tMs(t, ctx),
    tid: intCell(cells[2]),
    method: d.method,
    access,
    insn: where?.at ?? insnVa,
    insn_va: insnVa,
    insn_static: where?.static ?? null,
    insn_text: text,
    insn_confidence: insnConfidence(typeof cells[6] === "string" ? cells[6] : "unknown"),
    func: null,
    addr: hexCell(cells[9]),
    operand: base.operand === null ? null : { ...base.operand },
    struct_base: base.struct_base,
    disp: base.disp,
    value,
    value_when: valueWhen,
    before,
    after,
    ...regsOf(cells[12], d.registers, mem),
  };
  const bt = backtraceOf(ctx, cells[13]);
  if (bt !== null) event["bt"] = bt;
  yield event as EventRecord;
}

interface WriterAgg {
  readonly insn: JsonValue;
  readonly va: Hex | null;
  readonly static: JsonValue;
  readonly text: JsonValue;
  readonly access: string;
  count: number;
  readonly threads: number[];
  readonly bases: Map<string, { base: string; disp: string; count: number }>;
  first: ScalarOut;
  last: ScalarOut;
  readonly distinct: Set<string>;
  /** review fix UX-10: the worst insn_confidence of its hits (exact < recovered < ambiguous < unknown) */
  confidence: string;
}

const CONFIDENCE_RANK: Readonly<Record<string, number>> = { exact: 0, recovered: 1, ambiguous: 2, unknown: 3 };
const worse = (a: string, b: string): string => ((CONFIDENCE_RANK[b] ?? 3) > (CONFIDENCE_RANK[a] ?? 3) ? b : a);
export interface WatchSummaryState {
  hits: number;
  method: string | null;
  readonly writers: Map<string, WriterAgg>;
  rateLimit: RateLimited | null;
  final: { bea_guard_suspended: number; kernel_rearms: number; rearm_fails: number } | null;
}
/**
 * The CT-I4 valve's trip: `cause` "rate" (traps/s above limit_per_sec) or "busy" (handling the traps held the target
 * for busy_pct % of a window, above half; WP9 acceptance). An agent marker without busy counters is a rate trip.
 */
export interface RateLimited {
  readonly cause: "rate" | "busy";
  readonly limit_per_sec: number;
  readonly peak_per_sec: number;
  readonly busy_pct: number;
}
const DISTINCT_CAP = 1000;

const addMarker = (s: WatchSummaryState, e: EventRecord): void => {
  if (e["marker"] === "rate-limit")
    s.rateLimit = {
      cause: e["busy_trip"] === 1 ? "busy" : "rate",
      limit_per_sec: Number(e["limit_per_sec"] ?? 0),
      peak_per_sec: Number(e["peak_per_sec"] ?? 0),
      busy_pct: Number(e["busy_pct"] ?? 0),
    };
  else
    s.final = {
      bea_guard_suspended: Number(e["bea_guard_suspended"] ?? 0),
      kernel_rearms: Number(e["kernel_rearms"] ?? 0),
      rearm_fails: Number(e["rearm_fails"] ?? 0),
    };
};

/** The aggregate of one instruction and access kind (created on its first hit). */
const writerOf = (s: WatchSummaryState, e: EventRecord): WriterAgg => {
  const key = `${String(e["insn_va"])}|${String(e["access"])}`;
  const known = s.writers.get(key);
  if (known !== undefined) return known;
  const w: WriterAgg = {
    insn: e["insn"] ?? null,
    va: typeof e["insn_va"] === "string" ? (e["insn_va"] as Hex) : null,
    static: e["insn_static"] ?? null,
    text: e["insn_text"] ?? null,
    access: String(e["access"]),
    count: 0,
    threads: [],
    bases: new Map(),
    first: (e["value"] as ScalarOut) ?? null,
    last: null,
    distinct: new Set(),
    confidence: typeof e["insn_confidence"] === "string" ? e["insn_confidence"] : "unknown",
  };
  s.writers.set(key, w);
  return w;
};

const addStructBase = (w: WriterAgg, e: EventRecord): void => {
  const sb = e["struct_base"];
  if (typeof sb !== "string") return;
  const disp = typeof e["disp"] === "string" ? e["disp"] : "0x0";
  const k = `${sb}|${disp}`;
  const known = w.bases.get(k);
  if (known !== undefined) known.count += 1;
  else if (w.bases.size < 64) w.bases.set(k, { base: sb, disp, count: 1 });
};

/** WatchSummary (S6 §5.3); config-free: the method comes from the events. */
export const WATCH_SUMMARY = {
  init: (): WatchSummaryState => ({ hits: 0, method: null, writers: new Map(), rateLimit: null, final: null }),
  add: (s: WatchSummaryState, e: EventRecord): void => {
    if (typeof e["marker"] === "string") {
      addMarker(s, e);
      return;
    }
    s.hits += 1;
    if (s.method === null && typeof e["method"] === "string") s.method = e["method"];
    const w = writerOf(s, e);
    w.count += 1;
    if (typeof e["insn_confidence"] === "string") w.confidence = worse(w.confidence, e["insn_confidence"]);
    const tid = e["tid"];
    if (typeof tid === "number" && !w.threads.includes(tid) && w.threads.length < 8) w.threads.push(tid);
    addStructBase(w, e);
    const value = (e["value"] as ScalarOut) ?? null;
    w.last = value;
    if (w.distinct.size < DISTINCT_CAP) w.distinct.add(JSON.stringify(value));
  },
  finish: (s: WatchSummaryState): JsonObject => {
    const ranked = [...s.writers.values()].sort((a, b) => b.count - a.count);
    return {
      hits: s.hits,
      method: s.method ?? "unknown",
      writers: ranked.slice(0, 16).map((w) => ({
        insn: {
          va: w.va,
          at: typeof w.insn === "string" && w.insn !== w.va ? w.insn : null,
          static: w.static,
          func: null,
          sym: null,
          text: w.text,
        },
        insn_confidence: w.confidence,
        access: w.access,
        count: w.count,
        threads: [...w.threads],
        struct_bases: [...w.bases.values()].sort((a, b) => b.count - a.count).slice(0, 3),
        values: {
          first: w.first,
          last: w.last,
          distinct: w.distinct.size,
          ...(w.distinct.size >= DISTINCT_CAP ? { distinct_capped: true } : {}),
        },
      })),
      writers_total: s.writers.size,
      rate_limited: s.rateLimit === null ? null : { ...s.rateLimit },
      guard: s.final,
    };
  },
};

// ---------------------------------------------------------------- poll/1

/** One poll/1 row (an 8-byte change cell) → one event per changed view element inside it. */
export function* decodePollRow(record: StreamRecord, ctx: DecodeContext, d: PollDecoders): Iterable<EventRecord> {
  const row = record.fields;
  if (!Array.isArray(row) || row.length < 5) return;
  const cells = row as readonly JsonValue[];
  const offset = intCell(cells[2]);
  const oldHex = bytesCell(cells[3]);
  const newHex = bytesCell(cells[4]);
  if (offset === null || oldHex === null || newHex === null || oldHex.length !== newHex.length) return;
  const oldBytes = hexToBytes(oldHex);
  const newBytes = hexToBytes(newHex);
  const width = pollElementWidth(d.view, d.size);
  const t = typeof cells[1] === "number" ? cells[1] : null;
  for (let k = 0; k + width <= oldBytes.length; k += width) {
    const a = oldBytes.subarray(k, k + width);
    const b = newBytes.subarray(k, k + width);
    if (a.every((v, i) => v === b[i])) continue;
    yield {
      seq: record.seq,
      t_ms: tMs(t, ctx),
      offset: formatHex(offset + k),
      type: d.view,
      old: decodeElement(a, d.view),
      new: decodeElement(b, d.view),
    } as EventRecord;
  }
}

interface FieldAgg {
  readonly offset: string;
  readonly type: WatchView;
  changes: number;
  min: number | bigint | null;
  max: number | bigint | null;
  minOut: ScalarOut;
  maxOut: ScalarOut;
  readonly first: ScalarOut;
  last: ScalarOut;
}
export interface PollSummaryState {
  readonly samples: Set<number>;
  changes: number;
  readonly fields: Map<string, FieldAgg>;
}
const sampleKey = (e: EventRecord): number => (typeof e["t_ms"] === "number" ? e["t_ms"] : -1);

const VIEW_SET: ReadonlySet<string> = new Set([
  "hex",
  "i8",
  "u8",
  "i16",
  "u16",
  "i32",
  "u32",
  "i64",
  "u64",
  "f32",
  "f64",
]);
const track = (f: FieldAgg, value: ScalarOut): void => {
  const k = numericKey(value, f.type);
  if (k === null) return;
  if (f.min === null || k < f.min) {
    f.min = k;
    f.minOut = value;
  }
  if (f.max === null || k > f.max) {
    f.max = k;
    f.maxOut = value;
  }
};
/** PollSummary (S6 §5.3); config-free: each event names the view it was decoded with. */
export const POLL_SUMMARY = {
  init: (): PollSummaryState => ({ samples: new Set(), changes: 0, fields: new Map() }),
  add: (s: PollSummaryState, e: EventRecord): void => {
    if (s.samples.size < 1_000_000) s.samples.add(sampleKey(e));
    s.changes += 1;
    const offset = String(e["offset"]);
    const oldV = (e["old"] as ScalarOut) ?? null;
    const newV = (e["new"] as ScalarOut) ?? null;
    let f = s.fields.get(offset);
    if (f === undefined) {
      if (s.fields.size >= 4096) return;
      const type = typeof e["type"] === "string" && VIEW_SET.has(e["type"]) ? (e["type"] as WatchView) : "hex";
      f = { offset, type, changes: 0, min: null, max: null, minOut: null, maxOut: null, first: oldV, last: newV };
      track(f, oldV);
      s.fields.set(offset, f);
    }
    f.changes += 1;
    f.last = newV;
    track(f, newV);
  },
  finish: (s: PollSummaryState): JsonObject => ({
    samples: s.samples.size,
    changes: s.changes,
    fields: [...s.fields.values()]
      .sort((a, b) => b.changes - a.changes || (BigInt(a.offset) < BigInt(b.offset) ? -1 : 1))
      .slice(0, 64)
      .map((f) => ({
        offset: f.offset,
        type: f.type,
        changes: f.changes,
        min: f.minOut,
        max: f.maxOut,
        first: f.first,
        last: f.last,
      })),
    fields_total: s.fields.size,
  }),
};

// ---------------------------------------------------------------- block-span/1, block-count/1, call-site-count/1

/** A call-site-count/1 record: a call edge, or the on_call entry self edge that carries the invocation count. */
const callEdgeEvent = (record: StreamRecord, ctx: DecodeContext, d: TraceDecoders): EventRecord | null => {
  const f = record.fields;
  const site = toBig(fieldOf(f, "site", 0));
  const target = toBig(fieldOf(f, "target", 1));
  const count = toBig(fieldOf(f, "count", 2));
  if (site === null || target === null || count === null) return null;
  const from = compactOf(ctx, d.modules, site);
  if (d.on_call !== null && site === target && site === BigInt(d.on_call))
    return { seq: record.seq, invocations: Number(count), entry: from.at ?? from.va } as EventRecord;
  const to = target === 0n ? null : compactOf(ctx, d.modules, target);
  return {
    seq: record.seq,
    from: from.at ?? from.va,
    from_va: from.va,
    to: to === null ? null : (to.at ?? to.va),
    to_va: to?.va ?? null,
    count: Number(count),
  } as EventRecord;
};

/** One trace record → one event (block spans and counts, or a call edge). */
export function* decodeTraceRecord(record: StreamRecord, ctx: DecodeContext, d: TraceDecoders): Iterable<EventRecord> {
  const f = record.fields;
  if (d.layout === "call-site-count/1") {
    const edge = callEdgeEvent(record, ctx, d);
    if (edge !== null) yield edge;
    return;
  }
  if (d.layout !== "block-span/1" && d.layout !== "block-count/1") return;
  const start = toBig(fieldOf(f, "start", 0));
  const end = toBig(fieldOf(f, "end", 1));
  if (start === null || end === null || end < start) return;
  const at = compactOf(ctx, d.modules, start);
  const m = locate(d.modules, start);
  const event: Record<string, JsonValue> = {
    seq: record.seq,
    block: at.at ?? at.va,
    va: at.va,
    size: Number(end - start),
    module: m?.name ?? null,
  };
  if (d.layout === "block-count/1") {
    const count = toBig(fieldOf(f, "count", 2));
    event["hits"] = count === null ? 0 : Number(count);
    if (d.on_call !== null && start === BigInt(d.on_call)) event["entry"] = true;
  }
  yield event as EventRecord;
}

export interface TraceSummaryState {
  readonly blocks: Map<string, { readonly module: string | null; hits: number; readonly firstSeq: number }>;
  invocations: number;
  readonly calls: Map<string, { from: string; to: string | null; count: number }>;
  counted: boolean;
}
/**
 * TraceSummary (S6 §5.3); config-free: the mode is inferred from the records (call edges → calls, counted blocks →
 * block_counts, spans → coverage) and trace_execution overrides mode/threads with what it installed.
 */
export const TRACE_SUMMARY = {
  init: (): TraceSummaryState => ({ blocks: new Map(), invocations: 0, calls: new Map(), counted: false }),
  add: (s: TraceSummaryState, e: EventRecord): void => {
    if (typeof e["invocations"] === "number") {
      s.invocations = Math.max(s.invocations, e["invocations"]);
      return;
    }
    if (typeof e["from"] === "string") {
      const key = `${e["from"]}>${String(e["to"])}`;
      const known = s.calls.get(key);
      if (known !== undefined) known.count += Number(e["count"] ?? 0);
      else if (s.calls.size < 65_536)
        s.calls.set(key, {
          from: e["from"],
          to: typeof e["to"] === "string" ? e["to"] : null,
          count: Number(e["count"] ?? 0),
        });
      return;
    }
    const va = typeof e["va"] === "string" ? e["va"] : null;
    if (va === null) return;
    const hits = typeof e["hits"] === "number" ? e["hits"] : 0;
    if (typeof e["hits"] === "number") s.counted = true;
    if (e["entry"] === true) s.invocations = Math.max(s.invocations, hits);
    const known = s.blocks.get(va);
    if (known !== undefined) known.hits += hits;
    else if (s.blocks.size < 2_000_000)
      s.blocks.set(va, { module: typeof e["module"] === "string" ? e["module"] : null, hits, firstSeq: e.seq });
  },
  finish: (s: TraceSummaryState): JsonObject => {
    const perModule = new Map<string, number>();
    let executions = 0;
    for (const b of s.blocks.values()) {
      const name = b.module ?? "(unattributed)";
      perModule.set(name, (perModule.get(name) ?? 0) + 1);
      executions += b.hits;
    }
    const mode = s.calls.size > 0 ? "calls" : s.counted ? "block_counts" : "coverage";
    return {
      mode,
      invocations: s.invocations,
      threads: [],
      blocks: s.blocks.size,
      ...(s.counted ? { executions } : {}),
      modules: [...perModule.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 16)
        .map(([name, blocks]) => ({ name, blocks })),
      functions: [],
      ...(s.calls.size > 0
        ? {
            calls: [...s.calls.values()]
              .sort((a, b) => b.count - a.count)
              .slice(0, 50)
              .map((c) => ({ from: c.from, to: c.to, count: c.count })),
          }
        : {}),
    };
  },
};
