import {
  decodeOutcome,
  returnType,
  STATUS_OF,
  typedField,
  typedValue,
  type OutLayout,
} from "../../domain/callModel/decode.js";
import { floatFromBits, isNaNBits, maskTo, SCALAR_WIDTH, signedOf } from "../../domain/callModel/floatBits.js";
import type { FieldType } from "../../domain/callModel/normalize.js";
import type { CallOutcomeColumns, CallPlan, CallScalarType, TypedValue } from "../../domain/callModel/types.js";
import type {
  BatchResult,
  CallResult,
  Deviation,
  RegionDesc,
  StopRecord,
  SweepResult,
} from "../../domain/emuProtocol.js";
import type { JsonObject, JsonValue } from "../../domain/json.js";
import type { EmuModuleView } from "../../ports/emu.js";
import type { Attribution, CallStatus, RawBatchColumns, StatusCode } from "../../shared/callPlan.js";
import { formatHex, type Hex } from "../../shared/hex.js";
import { deviationSentence, HARNESS_STATUSES } from "./deviations.js";

/**
 * Result shaping for emu_call (S5 §8.2.1–§8.2.4): bridge results -> decoded, typed, bounded views. Bits stay the
 * authority (display values never replace them); traces and stop records are capped; rows above the inline limit go to
 * an `emu-batch` / `emu-sweep` row stream (S5 §11.3). Everything here is pure.
 */
const STATUS_CODE_OF: { readonly [S in CallStatus]: StatusCode } = {
  returned: "ok",
  fault: "fault",
  cpu_exception: "cpu",
  invalid_instruction: "inv",
  unsupported_instruction: "unsup",
  unhandled_import: "imp",
  syscall: "sys",
  raised: "raised",
  terminated: "term",
  budget_exhausted: "budget",
  timeout: "timeout",
  cancelled: "cancel",
  engine_error: "eng",
};

const TRACE_INLINE = 200;
const BLOCK_SAMPLE = 64;
const STACK_SCAN_SUMMARY = 8;
const OUT_HEX_CHARS = 8192;
export const PREVIEW_ROWS = 8;
export const MAX_FAULTS = 32;

/** canonical 64-bit hex; tolerant of empty strings ("" = no value) */
export const hex64 = (text: string | undefined | null): Hex =>
  text === undefined || text === null || text === "" ? "0x0" : formatHex(BigInt.asUintN(64, BigInt(text)));
const hex128 = (text: string): string => `0x${BigInt.asUintN(128, BigInt(text === "" ? "0x0" : text)).toString(16)}`;

const attributionOf = (status: CallStatus): Attribution => (HARNESS_STATUSES.has(status) ? "harness" : "target");

/** Out-field types of the decoded columns ("buffer.field" -> declared type). */
export const fieldTypes = (layout: OutLayout): Map<string, FieldType> => {
  const out = new Map<string, FieldType>();
  for (const [buffer, fields] of layout) for (const field of fields) out.set(`${buffer}.${field.name}`, field.type);
  return out;
};

/**
 * The emulator leg's outcome columns: decodeOutcome over the bridge columns, with the bridge's own per-vector
 * attribution (S5 §3.13: a fault on uncaptured or synthetic memory is a HARNESS stop) and fault sites.
 */
export const emulatorOutcome = (plan: CallPlan, layout: OutLayout, batch: BatchResult): CallOutcomeColumns => {
  const completed = batch.summary.completed;
  const raw: RawBatchColumns = {
    completed,
    status: batch.columns.status.slice(0, completed),
    rax: batch.columns.rax.map((v) => hex64(v)),
    xmm0lo: batch.columns.xmm0lo.map((v) => hex64(v)),
    out: Object.fromEntries(
      Object.entries(batch.columns.out).map(([name, cells]) => [name, cells.map((c) => c.toLowerCase())]),
    ),
    mxcsrOut: [],
    fpcwOut: [],
  };
  const decoded = decodeOutcome(plan, raw, batch.summary.offset, layout);
  const offset = batch.summary.offset;
  const byIndex = new Map(batch.faults.map((f) => [f.index, f]));
  const columnAttr = batch.columns.attr;
  // EMU-9: the bridge lists fault details for the first 1000 non-returned vectors only. Past that, its per-vector
  // attribution column decides; with neither, a stop is never ASSUMED to be the target's (a harness fault on
  // uncaptured or synthetic memory has the same status): it is a harness stop without detail (inconclusive in diffs)
  const undetailed: number[] = [];
  const attribution = decoded.status.map((status, k): Attribution | null => {
    if (status === "returned") return null;
    const fault = byIndex.get(offset + k);
    if (fault !== undefined) return fault.attribution;
    const column = columnAttr?.[k];
    if (column === "t") return "target";
    if (column === "h") return "harness";
    const byStatus = attributionOf(status);
    if (byStatus === "harness") return byStatus;
    undetailed.push(offset + k);
    return "harness";
  });
  const listed = batch.faults
    .filter((f) => f.index >= offset && f.index < offset + completed)
    .map((f) => ({
      index: f.index,
      status: f.status,
      attribution: f.attribution,
      cause: f.cause,
      site: {
        module: f.detail?.pcFunction?.module ?? f.detail?.pcRegion.module ?? null,
        rva: f.pcRva === null ? null : hex64(f.pcRva),
      },
    }));
  const columnSites = decoded.status.flatMap((status, k) => {
    const index = offset + k;
    const at = columnAttr?.[k];
    if (status === "returned" || byIndex.has(index) || (at !== "t" && at !== "h")) return [];
    const pc = batch.columns.pcRva?.[k] ?? null;
    return [
      {
        index,
        status,
        attribution: at === "t" ? ("target" as const) : ("harness" as const),
        cause: status,
        site: { module: null, rva: pc === null ? null : hex64(pc) },
      },
    ];
  });
  const missing = undetailed.map((index) => ({
    index,
    status: decoded.status[index - offset] ?? ("fault" as const),
    attribution: "harness" as const,
    cause: "no_fault_detail",
    site: { module: null, rva: null },
  }));
  return { ...decoded, attribution, faults: [...listed, ...columnSites, ...missing] };
};

/** A single CallResult as one-vector outcome columns. */
export const singleOutcome = (plan: CallPlan, layout: OutLayout, call: CallResult, offset = 0): CallOutcomeColumns => {
  const raw: RawBatchColumns = {
    completed: 1,
    status: [STATUS_CODE_OF[call.status]],
    rax: [hex64(call.raw.rax)],
    xmm0lo: [hex64(call.raw.xmm0)],
    out: Object.fromEntries(Object.entries(call.out).map(([name, hex]) => [name, [hex.toLowerCase()]])),
    mxcsrOut: [hex64(call.raw.mxcsr)],
    fpcwOut: [hex64(call.raw.fpcw)],
  };
  const decoded = decodeOutcome(plan, raw, offset, layout);
  const stop = call.stop;
  return {
    ...decoded,
    attribution: [call.status === "returned" ? null : (call.attribution ?? attributionOf(call.status))],
    faults:
      stop === null
        ? []
        : [
            {
              index: offset,
              status: call.status,
              attribution: stop.attribution,
              cause: stop.cause,
              site: {
                module: stop.pcFunction?.module ?? stop.pcRegion.module ?? null,
                rva: stop.pcRegion.rva === undefined ? null : hex64(stop.pcRegion.rva),
              },
            },
          ],
  };
};

const regionView = (region: RegionDesc): JsonObject => ({
  region: region.region,
  kind: region.kind,
  ...(region.module === undefined ? {} : { module: region.module }),
  ...(region.rva === undefined ? {} : { rva: region.rva }),
  ...(region.capture === undefined ? {} : { capture: region.capture }),
  ...(region.hint === undefined ? {} : { hint: region.hint }),
  ...(region.remediation === undefined ? {} : { remediation: region.remediation }),
});

/** Compact stop record (S5 §3.13); registers, the full stack scan and last blocks with detail "complete" only. */
export const stopView = (stop: StopRecord, detail: "summary" | "complete"): JsonObject => {
  const complete = detail === "complete";
  const insn = stop.instruction[0];
  const view: Record<string, JsonValue> = {
    status: stop.status,
    attribution: stop.attribution,
    cause: stop.cause,
    pc: stop.pc,
    pc_region: regionView(stop.pcRegion),
    function:
      stop.pcFunction === null
        ? null
        : `${stop.pcFunction.module}+${stop.pcFunction.beginRva} (+${stop.pcFunction.offset})`,
    instruction: insn === undefined ? null : { text: insn.text, bytes: insn.bytes },
  };
  if (stop.fault !== undefined)
    view["fault"] = {
      access: stop.fault.access,
      kind: stop.fault.kind,
      address: stop.fault.address,
      size: stop.fault.size,
      value: stop.fault.value,
      region: regionView(stop.fault.addressRegion),
    };
  if (stop.exception !== undefined) view["exception"] = { vector: stop.exception.vector, name: stop.exception.name };
  if (stop.importCall !== undefined)
    view["import_call"] = {
      import: stop.importCall.import,
      caller_rva: stop.importCall.callerRva,
      args: [...stop.importCall.args],
    };
  if (stop.isa !== undefined)
    view["isa"] = { mnemonic: stop.isa.mnemonic, encoding: stop.isa.encoding, rva: stop.isa.rva };
  if (stop.syscall !== undefined) view["syscall"] = { number: stop.syscall.number };
  if (stop.terminate !== undefined) view["terminate"] = { via: stop.terminate.via, code: stop.terminate.code };
  if (stop.engineError !== undefined) view["engine_error"] = { errno: stop.engineError.errno };
  const scan = complete ? stop.stackScan : stop.stackScan.slice(0, STACK_SCAN_SUMMARY);
  view["stack_scan"] = scan.map((s) => ({
    va: s.va,
    module: s.module,
    rva: s.rva,
    ...(s.note === undefined ? {} : { note: s.note }),
  }));
  if (complete && stop.registers !== undefined) view["registers"] = { ...stop.registers };
  if (complete && stop.lastBlocks !== undefined) view["last_blocks"] = [...stop.lastBlocks];
  return view;
};

/** Bounded trace view of a single call (S5 §8.2.1). */
export const traceView = (
  trace: CallResult["trace"],
): { readonly view: JsonObject | null; readonly truncatedAt: number | null } => {
  if (trace === undefined) return { view: null, truncatedAt: null };
  const view: Record<string, JsonValue> = {};
  const truncated: Record<string, boolean> = { ...trace.truncated };
  let cut = false;
  if (trace.imports !== undefined) {
    view["imports"] = trace.imports.slice(0, TRACE_INLINE).map((e) => ({
      import: e.import,
      model: e.model,
      caller_rva: e.callerRva,
      args: [...e.args],
      ret: e.ret,
    }));
    if (trace.imports.length > TRACE_INLINE) truncated["imports_inline"] = cut = true;
  }
  if (trace.blocks !== undefined)
    view["blocks"] = {
      executed: trace.blocks.length,
      unique: new Set(trace.blocks).size,
      sample: trace.blocks.slice(0, BLOCK_SAMPLE),
    };
  if (trace.memory !== undefined) {
    view["memory"] = trace.memory.slice(0, TRACE_INLINE).map((m) => ({ ...m }));
    if (trace.memory.length > TRACE_INLINE) truncated["memory_inline"] = cut = true;
  }
  if (trace.instructions !== undefined) {
    view["instructions"] = trace.instructions.slice(0, TRACE_INLINE).map((i) => ({ ...i }));
    if (trace.instructions.length > TRACE_INLINE) truncated["instructions_inline"] = cut = true;
  }
  view["truncated"] = truncated;
  const engineCut = Object.values(trace.truncated).some(Boolean);
  return { view, truncatedAt: engineCut || cut ? TRACE_INLINE : null };
};

/** Heap events of a single call (≤ 16; S5 §8.2.1). */
export const eventsView = (
  events: CallResult["events"],
): { type: "heap"; kind: string; ptr: Hex | null; size: number | null }[] =>
  events.slice(0, 16).map((e) => ({
    type: "heap",
    kind: e.kind.slice(0, 32),
    ptr: e.ptr === undefined ? null : hex64(e.ptr),
    size: e.size ?? null,
  }));

export const deviationView = (deviations: readonly Deviation[]): { kind: string; note: string; count?: number }[] =>
  deviations.slice(0, 64).map((d) => ({
    kind: d.kind,
    note: (deviationSentence(d) ?? d.note).slice(0, 500),
    ...(d.count === undefined ? {} : { count: d.count }),
  }));

/** Typed outputs of out-buffer fields for vector k. */
/** Inline array elements per out field of a single call (the emu_call contract caps them at 256, like call_function). */
export const OUTPUT_ARRAY_INLINE_CAP = 256;

/**
 * The typed out fields of vector `k`. Review fix EMU-11: arrays are cut at OUTPUT_ARRAY_INLINE_CAP elements and
 * `notes.truncatedValues` is set (value_cap coverage): an out field of more than 256 elements broke the output
 * contract AFTER the run, its record and the lineage update landed ("BEA hit an internal error").
 */
export const outputsOf = (
  outcome: CallOutcomeColumns,
  types: ReadonlyMap<string, FieldType>,
  k: number,
  notes: { truncatedValues: boolean } = { truncatedValues: false },
): Record<string, TypedValue | TypedValue[]> => {
  const out: Record<string, TypedValue | TypedValue[]> = {};
  for (const [name, cells] of Object.entries(outcome.fields)) {
    const cell = cells[k];
    const type = types.get(name);
    if (cell === undefined || type === undefined) continue;
    const typed = typedField(type, cell);
    if (Array.isArray(typed) && typed.length > OUTPUT_ARRAY_INLINE_CAP) {
      notes.truncatedValues = true;
      out[name] = typed.slice(0, OUTPUT_ARRAY_INLINE_CAP);
    } else out[name] = typed;
  }
  return out;
};

export const retValue = (plan: CallPlan, outcome: CallOutcomeColumns, k: number): TypedValue | null => {
  const type = returnType(plan.returns);
  const bits = outcome.ret?.[k];
  if (type === null || bits === undefined || outcome.status[k] !== "returned") return null;
  return typedValue(type, BigInt(bits));
};

/** A preview row: the batch row without its out fields (bounded inline). */
export const previewRow = (
  outcome: CallOutcomeColumns,
  k: number,
  instructions: readonly number[] | undefined,
): JsonObject => {
  const { f: _fields, ...row } = batchRow(outcome, k, instructions) as Record<string, JsonValue>;
  return row;
};

/** A batch row (emu-batch stream): {i, s, a?, c?, r?, f?, n?} (S5 §11.3). */
export const batchRow = (
  outcome: CallOutcomeColumns,
  k: number,
  instructions: readonly number[] | undefined,
): JsonObject => {
  const status = outcome.status[k] ?? "returned";
  const row: Record<string, JsonValue> = { i: outcome.offset + k, s: STATUS_CODE_OF[status] };
  const attribution = outcome.attribution[k];
  if (attribution !== null && attribution !== undefined) row["a"] = attribution === "target" ? "t" : "h";
  if (status !== "returned") row["c"] = outcome.faults.find((f) => f.index === outcome.offset + k)?.cause ?? status;
  const ret = outcome.ret?.[k];
  if (status === "returned" && ret !== undefined) row["r"] = ret;
  const fields: Record<string, JsonValue> = {};
  for (const [name, cells] of Object.entries(outcome.fields)) {
    const cell = cells[k];
    if (cell !== undefined) fields[name] = typeof cell === "string" ? cell : [...cell];
  }
  if (Object.keys(fields).length > 0) row["f"] = fields;
  const n = instructions?.[k];
  if (n !== undefined) row["n"] = n;
  return row;
};

const numericKey = (type: CallScalarType, bits: bigint): number | bigint | null => {
  if (type === "f32" || type === "f64") return isNaNBits(type, bits) ? null : floatFromBits(type, bits);
  const width = SCALAR_WIDTH[type];
  return type.startsWith("i") ? signedOf(maskTo(bits, width), width) : maskTo(bits, width);
};

/** min/max (by value; NaN excluded), NaN and infinity counts, distinct bit patterns of the returned values. */
export const retStats = (
  plan: CallPlan,
  outcome: CallOutcomeColumns,
): { min_bits: Hex | null; max_bits: Hex | null; nan: number; inf: number; distinct_bits: number } | null => {
  const type = returnType(plan.returns);
  if (type === null || outcome.ret === null) return null;
  let min: { key: number | bigint; bits: Hex } | null = null;
  let max: { key: number | bigint; bits: Hex } | null = null;
  let nan = 0;
  let inf = 0;
  const distinct = new Set<string>();
  outcome.ret.forEach((bitsText, k) => {
    if (outcome.status[k] !== "returned") return;
    distinct.add(bitsText);
    const bits = BigInt(bitsText);
    const key = numericKey(type, bits);
    if (key === null) {
      nan += 1;
      return;
    }
    if (typeof key === "number" && !Number.isFinite(key)) inf += 1;
    if (min === null || key < min.key) min = { key, bits: bitsText };
    if (max === null || key > max.key) max = { key, bits: bitsText };
  });
  const lo = min as { key: number | bigint; bits: Hex } | null;
  const hi = max as { key: number | bigint; bits: Hex } | null;
  return { min_bits: lo?.bits ?? null, max_bits: hi?.bits ?? null, nan, inf, distinct_bits: distinct.size };
};

/** Inline batch columns: ret and every decoded out field as {bits, value}. */
export const inlineColumns = (
  plan: CallPlan,
  outcome: CallOutcomeColumns,
  types: ReadonlyMap<string, FieldType>,
): Record<string, { bits: (Hex | Hex[])[]; value: JsonValue[] }> => {
  const out: Record<string, { bits: (Hex | Hex[])[]; value: JsonValue[] }> = {};
  const type = returnType(plan.returns);
  if (type !== null && outcome.ret !== null)
    out["ret"] = {
      bits: [...outcome.ret],
      value: outcome.ret.map((bits, k) =>
        outcome.status[k] === "returned" ? typedValue(type, BigInt(bits)).value : null,
      ),
    };
  for (const [name, cells] of Object.entries(outcome.fields)) {
    const fieldType = types.get(name);
    if (fieldType === undefined) continue;
    out[name] = {
      bits: cells.map((cell) => (typeof cell === "string" ? cell : [...cell])),
      value: cells.map((cell) => {
        const typed = typedField(fieldType, cell);
        return Array.isArray(typed) ? typed.map((t) => t.value) : typed.value;
      }),
    };
  }
  return out;
};

export const byStatus = (statuses: readonly CallStatus[]): Partial<Record<CallStatus, number>> => {
  const out: Partial<Record<CallStatus, number>> = {};
  for (const s of statuses) out[s] = (out[s] ?? 0) + 1;
  return out;
};

/** The status map of a bridge batch summary (short codes) -> CallStatus keys. */
export const byStatusOfSummary = (summary: BatchResult["summary"]): Partial<Record<CallStatus, number>> => {
  const out: Partial<Record<CallStatus, number>> = {};
  for (const [code, n] of Object.entries(summary.byStatus)) {
    const status = STATUS_OF[code as StatusCode] as CallStatus | undefined;
    if (status !== undefined && n !== undefined) out[status] = (out[status] ?? 0) + n;
  }
  return out;
};

/** Out-buffer hex view of a single call (≤ 4 KiB of bytes inline). */
export const outBuffersView = (
  call: CallResult,
): Record<string, { address: Hex | null; bytes: number; hex: string; truncated: boolean }> => {
  const out: Record<string, { address: Hex | null; bytes: number; hex: string; truncated: boolean }> = {};
  for (const [name, hex] of Object.entries(call.out)) {
    const address = call.buffers[name];
    out[name] = {
      address: address === undefined ? null : hex64(address),
      bytes: hex.length / 2,
      hex: hex.slice(0, OUT_HEX_CHARS).toLowerCase(),
      truncated: hex.length > OUT_HEX_CHARS,
    };
  }
  return out;
};

export const rawView = (call: CallResult): { rax: Hex; xmm0: string; mxcsr: Hex; fpcw: Hex } => ({
  rax: hex64(call.raw.rax),
  xmm0: hex128(call.raw.xmm0),
  mxcsr: hex64(call.raw.mxcsr),
  fpcw: hex64(call.raw.fpcw),
});

/** Sweep rows -> matched functions (va from the swept module's base), ≤ 200. */
export const sweepMatches = (
  sweep: SweepResult,
  modules: readonly EmuModuleView[],
): { rva: Hex; va: Hex; matches: string[] }[] =>
  sweep.rows
    .filter((row) => row.matches.length > 0)
    .slice(0, 200)
    .map((row) => {
      const module = modules.find((m) => m.name.toLowerCase() === row.module.toLowerCase());
      const rva = BigInt(row.rva);
      return {
        rva: hex64(row.rva),
        va: formatHex((module === undefined ? 0n : BigInt(module.base)) + rva),
        matches: row.matches.slice(0, 8),
      };
    });

export const sweepRow = (row: SweepResult["rows"][number]): JsonObject => ({
  rva: row.rva,
  module: row.module,
  s: [...row.statuses],
  r: [...row.rax],
  x: [...row.xmm0lo],
  m: [...row.matches],
});
