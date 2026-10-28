import { z } from "zod";

import type { JsonObject, JsonValue } from "../../../domain/json.js";
import type { StreamRecord } from "../../../ports/evidence.js";
import type {
  DecodeContext,
  EventField,
  EventRecord,
  RecordingKindSpec,
  SummaryBuilder,
} from "../../../ports/recordings.js";
import { BINARY_LAYOUTS } from "../../../shared/binaryLayouts.js";
import { FieldStatsAccumulator, QuantileSample, TopCounter, bitsOfFloat, floatOfBits } from "../summaryUtil.js";

/**
 * Recording kind "hook" (WP7-HOOK; S6 §5.3 HookSummary, §5.4 hook fields). Decodes agent rows of both tiers:
 * `hook/1` JSON tuples [g, t, tid, phase, depth, caller, args, ret, bt, regs] and `hook-native/1` fixed records.
 * The host writes the decoders (HookDecoders below) at install time; field names come from the capture specs.
 *
 * Event keys: seq, t_ms, tid, depth, caller (Loc `at` text), dur_us, bt (array of `at`), one key per capture field,
 * ret. Auxiliary keys contain ":" and are not listed as fields: `<name>:bits` (exact float bits), `<name>:err`
 * (capture read failure code), `caller:static`. query_events projects them only when asked (`fields:["dt:bits"]`).
 */

/** Tool-level value types of hook fields (S6 §5.1; "bool" = one byte). */
export const HOOK_FIELD_TYPES = [
  "i8",
  "u8",
  "i16",
  "u16",
  "i32",
  "u32",
  "i64",
  "u64",
  "ptr",
  "bool",
  "f32",
  "f64",
  "utf8",
  "utf16",
  "bytes",
] as const;
export type HookFieldType = (typeof HOOK_FIELD_TYPES)[number];
const fieldTypeSchema = z.enum(HOOK_FIELD_TYPES);

/** Native layout fields a capture may read (hook-native/1). */
export const NATIVE_SOURCES = [
  "rcx",
  "rdx",
  "r8",
  "r9",
  "xmm0",
  "xmm1",
  "xmm2",
  "xmm3",
  "s4",
  "s5",
  "s6",
  "s7",
] as const;

export const hookDecodersSchema = z.strictObject({
  v: z.literal(1),
  engine: z.enum(["js", "native"]),
  caller: z.boolean(),
  backtrace: z.number().int().min(0).max(64),
  sample_every: z.number().int().min(1).max(1_000_000),
  /** JS tier: one entry per HookRow.args cell, in order */
  cells: z.array(z.strictObject({ field: z.string().max(80), type: fieldTypeSchema })).max(32),
  /** native tier: one entry per captured layout field */
  native: z
    .array(z.strictObject({ field: z.string().max(80), type: fieldTypeSchema, source: z.enum(NATIVE_SOURCES) }))
    .max(16),
  ret: fieldTypeSchema.nullable(),
  ret_source: z.enum(["rax", "xmm0_ret"]).nullable(),
});
export type HookDecoders = z.infer<typeof hookDecodersSchema>;

const FLOAT = new Set<HookFieldType>(["f32", "f64"]);
const INT_BITS: Readonly<Partial<Record<HookFieldType, { bits: bigint; signed: boolean }>>> = {
  i8: { bits: 8n, signed: true },
  u8: { bits: 8n, signed: false },
  i16: { bits: 16n, signed: true },
  u16: { bits: 16n, signed: false },
  i32: { bits: 32n, signed: true },
  u32: { bits: 32n, signed: false },
  i64: { bits: 64n, signed: true },
  u64: { bits: 64n, signed: false },
};

export const eventFieldType = (t: HookFieldType): EventField["type"] =>
  FLOAT.has(t)
    ? "float"
    : t === "bool"
      ? "bool"
      : t === "ptr"
        ? "address"
        : t === "utf8" || t === "utf16" || t === "bytes"
          ? "string"
          : "int";

/** Fields of a hook recording: the fixed ones plus one per capture and `ret` (query_events validation). */
export const hookFieldsOf = (d: HookDecoders): readonly EventField[] => {
  const out: EventField[] = [{ name: "depth", type: "int" }];
  if (d.caller) out.push({ name: "caller", type: "address" });
  out.push({ name: "dur_us", type: "int" });
  if (d.backtrace > 0) out.push({ name: "bt", type: "array" });
  for (const c of d.engine === "js" ? d.cells : d.native) out.push({ name: c.field, type: eventFieldType(c.type) });
  if (d.ret !== null) out.push({ name: "ret", type: eventFieldType(d.ret) });
  return out;
};

// ---------------------------------------------------------------------------------------------- value decoding
/** Unsigned 64-bit raw value of a decoded binary field (number, decimal or "0x" string). */
export const rawU64 = (v: JsonValue | undefined): bigint => {
  if (typeof v === "number") return Number.isSafeInteger(v) && v >= 0 ? BigInt(v) : 0n;
  if (typeof v === "string" && v.length > 0) {
    try {
      return BigInt.asUintN(64, BigInt(v));
    } catch {
      return 0n;
    }
  }
  return 0n;
};

const intOut = (raw: bigint, spec: { bits: bigint; signed: boolean }): number | string => {
  const v = spec.signed ? BigInt.asIntN(Number(spec.bits), raw) : BigInt.asUintN(Number(spec.bits), raw);
  return spec.bits <= 32n ? Number(v) : v.toString();
};
const hexOut = (raw: bigint): string => `0x${BigInt.asUintN(64, raw).toString(16)}`;

/** One value of a raw 64-bit word (native tier, or a Hex cell) as the declared type. */
export const valueOfRaw = (type: HookFieldType, raw: bigint): { value: JsonValue; bits?: string } => {
  if (type === "f32") {
    const bits = `0x${BigInt.asUintN(32, raw).toString(16).padStart(8, "0")}`;
    return { value: floatOfBits("f32", bits), bits };
  }
  if (type === "f64") {
    const bits = `0x${BigInt.asUintN(64, raw).toString(16).padStart(16, "0")}`;
    return { value: floatOfBits("f64", bits), bits };
  }
  if (type === "bool") return { value: (raw & 0xffn) !== 0n };
  if (type === "ptr") return { value: hexOut(raw) };
  const spec = INT_BITS[type];
  return { value: spec === undefined ? hexOut(raw) : intOut(raw, spec) };
};

type Cell = JsonValue;
/** S4 ValueCell → event value(s) for the declared type (S6 §2.3 output encoding). */
export const valueOfCell = (
  type: HookFieldType,
  cell: Cell | undefined,
): { value: JsonValue; bits?: string; err?: string } => {
  if (cell === undefined || cell === null) return { value: null };
  if (Array.isArray(cell)) return { value: cell.map((c) => valueOfCell(type, c).value) };
  if (typeof cell === "number") {
    if (type === "bool") return { value: cell !== 0 };
    if (FLOAT.has(type)) return { value: cell };
    return { value: cell };
  }
  if (typeof cell === "string") return valueOfRaw(type, rawU64(cell));
  if (typeof cell === "boolean") return { value: cell };
  const o = cell as JsonObject;
  if (typeof o["e"] === "string") return { value: null, err: o["e"] };
  if (typeof o["s"] === "string") return { value: o["s"] };
  if (typeof o["x"] === "string") return { value: o["x"] };
  return { value: null, err: "unsupported" };
};

// ---------------------------------------------------------------------------------------------- decode
const decodersCache = new WeakMap<object, HookDecoders | null>();
/** Parse (and cache by identity) the decoders a recording was created with; null when malformed. */
export const parseHookDecoders = (raw: JsonValue): HookDecoders | null => {
  if (typeof raw !== "object" || raw === null) return null;
  const cached = decodersCache.get(raw);
  if (cached !== undefined) return cached;
  const parsed = hookDecodersSchema.safeParse(raw);
  const value = parsed.success ? parsed.data : null;
  decodersCache.set(raw, value);
  return value;
};

const NATIVE_FIELD_ORDER = BINARY_LAYOUTS["hook-native/1"].fields.map((f) => f.name);
/** A binary record's field by name, whether the decoder produced an object or a layout-ordered array. */
const nativeField = (fields: JsonValue, name: string): JsonValue | undefined => {
  if (Array.isArray(fields)) return fields[NATIVE_FIELD_ORDER.indexOf(name)];
  if (typeof fields === "object" && fields !== null) return (fields as JsonObject)[name];
  return undefined;
};

const tMs = (tUs: number, startedAtUs: number): number => Math.max(0, Math.round(tUs - startedAtUs)) / 1000;

const putValue = (
  out: Record<string, JsonValue>,
  field: string,
  v: { value: JsonValue; bits?: string; err?: string },
): void => {
  out[field] = v.value;
  if (v.bits !== undefined) out[`${field}:bits`] = v.bits;
  if (v.err !== undefined) out[`${field}:err`] = v.err;
};

const putCaller = (out: Record<string, JsonValue>, raw: string, ctx: DecodeContext): void => {
  const loc = ctx.frame(raw);
  out["caller"] = loc.at ?? raw;
  out["caller:static"] = loc.static;
};

function decodeJsonRow(row: readonly JsonValue[], seq: number, d: HookDecoders, ctx: DecodeContext): EventRecord {
  const [, t, tid, phase, depth, caller, args, ret, bt, regs] = row;
  const tUs = typeof t === "number" ? t : 0;
  const out: Record<string, JsonValue> = {
    seq,
    t_ms: tMs(tUs, ctx.startedAtUs),
    tid: typeof tid === "number" ? tid : null,
    depth: typeof depth === "number" ? depth : null,
  };
  if (d.caller && typeof caller === "string") putCaller(out, caller, ctx);
  const tLeave =
    phase === 2 && typeof regs === "object" && regs !== null && !Array.isArray(regs)
      ? (regs as JsonObject)["t_leave"]
      : undefined;
  out["dur_us"] = typeof tLeave === "string" ? Math.max(0, Number(rawU64(tLeave)) - Math.floor(tUs)) : null;
  if (d.backtrace > 0)
    out["bt"] = Array.isArray(bt) ? bt.map((f) => (typeof f === "string" ? (ctx.frame(f).at ?? f) : null)) : null;
  const cells = Array.isArray(args) ? args : [];
  d.cells.forEach((c, i) => {
    const cell = cells[i];
    // leave-only cells are null in the row until onLeave; a phase-1 row has no leave values
    if (cell === undefined || (cell === null && c.field.endsWith("@leave") && phase !== 2)) out[c.field] = null;
    else putValue(out, c.field, valueOfCell(c.type, cell));
  });
  if (d.ret !== null) putValue(out, "ret", phase === 2 ? valueOfCell(d.ret, ret ?? null) : { value: null });
  return out as EventRecord;
}

function decodeNative(fields: JsonValue, seq: number, d: HookDecoders, ctx: DecodeContext): EventRecord {
  const num = (name: string): bigint => rawU64(nativeField(fields, name));
  const t = Number(num("t"));
  const phase = Number(num("phase"));
  const out: Record<string, JsonValue> = {
    seq,
    t_ms: tMs(t, ctx.startedAtUs),
    tid: Number(num("tid")),
    depth: Number(num("depth")),
  };
  if (d.caller) putCaller(out, hexOut(num("ret_addr")), ctx);
  const leave = num("reserved");
  out["dur_us"] = phase === 2 && leave > 0n ? Math.max(0, Number(leave) - t) : null;
  for (const c of d.native) putValue(out, c.field, valueOfRaw(c.type, num(c.source)));
  if (d.ret !== null)
    putValue(
      out,
      "ret",
      phase === 2 ? valueOfRaw(d.ret, num(d.ret_source === "xmm0_ret" ? "xmm0_ret" : "rax")) : { value: null },
    );
  return out as EventRecord;
}

export function* decodeHookRecord(record: StreamRecord, ctx: DecodeContext): Iterable<EventRecord> {
  const d = parseHookDecoders(ctx.decoders);
  if (d === null) return;
  if (d.engine === "native") {
    yield decodeNative(record.fields, record.seq, d, ctx);
    return;
  }
  if (Array.isArray(record.fields)) yield decodeJsonRow(record.fields, record.seq, d, ctx);
}

// ---------------------------------------------------------------------------------------------- summary (S6 §5.3)
interface HookSummaryState {
  recorded: number;
  readFailures: number;
  readonly threads: TopCounter<number>;
  readonly callers: TopCounter<string>;
  readonly callerStatic: Map<string, string | null>;
  readonly durations: QuantileSample;
  readonly fields: Map<string, FieldStatsAccumulator>;
  readonly ret: FieldStatsAccumulator;
  hasRet: boolean;
}

const AUX = /:/u;
const BASE_KEYS = new Set(["seq", "t_ms", "tid", "depth", "caller", "dur_us", "bt", "ret"]);

export const hookSummary: SummaryBuilder<HookSummaryState> = {
  init: () => ({
    recorded: 0,
    readFailures: 0,
    threads: new TopCounter<number>(),
    callers: new TopCounter<string>(),
    callerStatic: new Map(),
    durations: new QuantileSample(),
    fields: new Map(),
    ret: new FieldStatsAccumulator("ret"),
    hasRet: false,
  }),
  add: (s, e) => {
    s.recorded++;
    const tid = e["tid"];
    if (typeof tid === "number") s.threads.add(tid);
    const caller = e["caller"];
    if (typeof caller === "string") {
      s.callers.add(caller);
      if (!s.callerStatic.has(caller) && s.callerStatic.size < 10_000) {
        const st = e["caller:static"];
        s.callerStatic.set(caller, typeof st === "string" ? st : null);
      }
    }
    const dur = e["dur_us"];
    if (typeof dur === "number") s.durations.add(dur);
    for (const [key, value] of Object.entries(e)) {
      if (key.endsWith(":err")) s.readFailures++;
      if (AUX.test(key) || BASE_KEYS.has(key)) continue;
      let acc = s.fields.get(key);
      if (acc === undefined) {
        if (s.fields.size >= 64) continue;
        acc = new FieldStatsAccumulator(typeOfValue(value));
        s.fields.set(key, acc);
      }
      acc.add(value);
    }
    if ("ret" in e) {
      s.hasRet = true;
      s.ret.add(e["ret"]);
    }
  },
  finish: (s) => {
    const fields: Record<string, JsonValue> = {};
    for (const [name, acc] of s.fields) fields[name] = acc.digest();
    return {
      // recorded calls; with sample_every > 1 the agent's hit counter (instrument counters) holds the full count
      calls: s.recorded,
      recorded: s.recorded,
      read_failures: s.readFailures,
      threads: s.threads.top(8).map(([tid, calls]) => ({ tid, calls })),
      callers: s.callers.top(8).map(([at, calls]) => ({ at, static: s.callerStatic.get(at) ?? null, calls })),
      duration_us: s.durations.summary(),
      fields,
      ...(s.hasRet ? { returns: s.ret.digest() } : {}),
    };
  },
};

const typeOfValue = (v: JsonValue): string =>
  typeof v === "number"
    ? "number"
    : typeof v === "boolean"
      ? "bool"
      : typeof v === "string"
        ? "string"
        : Array.isArray(v)
          ? "array"
          : "null";

/** Re-render a float field as raw bits when the event lacks `<field>:bits` (QueryEngine `:bits` projection). */
export const floatBitsOf = (value: JsonValue, wide: boolean): string | null =>
  typeof value === "number" || value === "NaN" || value === "Infinity" || value === "-Infinity"
    ? bitsOfFloat(wide ? "f64" : "f32", value as number | string)
    : null;

/** Recording kind "hook" (pre-wired in ./index.ts). */
export const HOOK_KIND: RecordingKindSpec<HookSummaryState> | null = {
  kind: "hook",
  rowKinds: ["hook/1", "hook-native/1"],
  fields: [
    { name: "depth", type: "int" },
    { name: "caller", type: "address" },
    { name: "dur_us", type: "int" },
    { name: "bt", type: "array" },
    { name: "ret", type: "float" },
  ],
  decode: decodeHookRecord,
  summary: hookSummary,
};
