import type { CallFunctionOutput } from "../../contracts/areas/call.js";
import type { Loc } from "../../domain/address/addressRef.js";
import { returnType, typedField, typedValue, type OutField } from "../../domain/callModel/decode.js";
import { fpHex } from "../../domain/callModel/fpEnv.js";
import type { CallOutcomeColumns, TypedValue } from "../../domain/callModel/types.js";
import type { CoverageBlobV1 } from "../../domain/artifacts.js";
import type { Coverage } from "../../domain/evidence/coverage.js";
import { LIMITATIONS } from "../../domain/evidence/limitations.js";
import type { BlobRef } from "../../domain/evidence/record.js";
import type { StId } from "../../domain/ids.js";
import { moduleAt } from "../../domain/process/instance.js";
import type { AddressService } from "../../ports/address.js";
import type { EvidenceRuntime, SensitiveLiterals } from "../../ports/evidence.js";
import type { LiveSession, OperationContext } from "../../ports/sessions.js";
import { AGENT_LIMIT_DEFAULTS } from "../../shared/agentLimits.js";
import type { FaultInfo } from "../../shared/agentProtocol.js";
import { formatHex, type Hex } from "../../shared/hex.js";
import type { CallBatchRow } from "./callBatchStream.js";
import type { OracleRawRun } from "./OracleService.js";
import { GENERATE_WINDOW, type PreparedCall } from "./prepareCall.js";

/**
 * Tool-result views of an oracle run (DESIGN §6.2 #26 output): one call in full detail, or a batch with inline
 * columns (≤ inline_limit vectors) or a preview + `call-batch` stream. Inline caps are 256 array elements per value
 * and 4 KiB of out-buffer hex; hitting one is reported as value_cap truncation.
 */
type CallView = NonNullable<CallFunctionOutput["call"]>;
type BatchView = NonNullable<CallFunctionOutput["batch"]>;
type FaultView = BatchView["faults"][number];

const ARRAY_INLINE_CAP = 256;
const OUT_HEX_CAP_BYTES = 4096;
const FAULTS_INLINE = 32;
const PREVIEW_ROWS = 8;
const FUNCTION_BLOCKS_DESCRIBED = 4096;

export interface ShapeNotes {
  /** inline value caps hit (arrays > 256 elements, out buffers > 4 KiB) */
  truncatedValues: boolean;
}

const capArray = <T>(values: readonly T[], notes: ShapeNotes): T[] => {
  if (values.length > ARRAY_INLINE_CAP) notes.truncatedValues = true;
  return values.slice(0, ARRAY_INLINE_CAP);
};

const fieldsOf = (layout: PreparedCall["layout"]): Map<string, OutField> => {
  const map = new Map<string, OutField>();
  for (const [buffer, fields] of layout) for (const field of fields) map.set(`${buffer}.${field.name}`, field);
  return map;
};

const outputValue = (field: OutField, cell: Hex | readonly Hex[], notes: ShapeNotes): TypedValue | TypedValue[] => {
  const typed = typedField(field.type, cell);
  return Array.isArray(typed) ? capArray(typed, notes) : (typed as TypedValue);
};

const faultView = async (address: AddressService, session: LiveSession, fault: FaultInfo): Promise<FaultView> => {
  const loc: Loc = await address.describeCode({ kind: "live", session }, BigInt(fault.address));
  return {
    index: fault.index,
    type: fault.type,
    code: fault.code,
    address: loc,
    memory: fault.memory === null ? null : { operation: fault.memory.operation, address: fault.memory.address },
    insn: null,
  };
};

export const singleView = async (
  ctx: { readonly address: AddressService; readonly session: LiveSession },
  prepared: PreparedCall,
  run: OracleRawRun,
  outcome: CallOutcomeColumns,
  notes: ShapeNotes,
): Promise<CallView> => {
  const fields = fieldsOf(prepared.layout);
  const outputs: Record<string, TypedValue | TypedValue[]> = {};
  for (const [name, cells] of Object.entries(outcome.fields)) {
    const field = fields.get(name);
    const cell = cells[0];
    if (field !== undefined && cell !== undefined) outputs[name] = outputValue(field, cell, notes);
  }
  const outBuffers: CallView["out_buffers"] = {};
  for (const buffer of prepared.plan.buffers) {
    if (!buffer.out) continue;
    const hex = run.raw.out[buffer.name]?.[0] ?? "";
    if (hex.length > OUT_HEX_CAP_BYTES * 2) notes.truncatedValues = true;
    outBuffers[buffer.name] = {
      address: run.bufferAddresses.get(buffer.name) ?? "0x0",
      bytes: buffer.size,
      hex: hex.slice(0, OUT_HEX_CAP_BYTES * 2),
      truncated: hex.length > OUT_HEX_CAP_BYTES * 2,
    };
  }
  const type = returnType(prepared.plan.returns);
  const retBits = outcome.ret?.[0];
  const status = outcome.status[0] ?? "fault";
  const fault = run.faults[0];
  const faultBody = fault === undefined ? null : await faultView(ctx.address, ctx.session, fault);
  return {
    status,
    ret: type === null || retBits === undefined || status !== "returned" ? null : typedValue(type, BigInt(retBits)),
    outputs,
    out_buffers: outBuffers,
    fault:
      faultBody === null
        ? null
        : {
            type: faultBody.type,
            code: faultBody.code,
            address: faultBody.address,
            memory: faultBody.memory,
            insn: faultBody.insn,
          },
    raw: {
      rax: (run.raw.rax[0] ?? "0x0") as Hex,
      xmm0: (run.raw.xmm0lo[0] ?? "0x0") as Hex,
      mxcsr: (run.raw.mxcsrOut[0] ?? "0x0") as Hex,
      fpcw: (run.raw.fpcwOut[0] ?? "0x0") as Hex,
    },
    wall_us: run.wallUs,
  };
};

const inlineColumns = (
  prepared: PreparedCall,
  outcome: CallOutcomeColumns,
  notes: ShapeNotes,
): BatchView["columns"] => {
  const columns: NonNullable<BatchView["columns"]> = {};
  const type = returnType(prepared.plan.returns);
  if (outcome.ret !== null && type !== null) {
    const bits = [...outcome.ret];
    columns["ret"] = {
      bits,
      value: bits.map((b, i) => (outcome.status[i] === "returned" ? typedValue(type, BigInt(b)).value : null)),
    };
  }
  const fields = fieldsOf(prepared.layout);
  for (const [name, cells] of Object.entries(outcome.fields)) {
    const field = fields.get(name);
    if (field === undefined) continue;
    const bits = cells.map((cell) => (typeof cell === "string" ? cell : capArray(cell, notes)));
    const value = bits.map((cell) => {
      const typed = typedField(field.type, cell);
      return Array.isArray(typed) ? typed.map((t) => t.value) : (typed as TypedValue).value;
    });
    columns[name] = { bits, value };
  }
  return columns;
};

export const batchView = async (
  ctx: { readonly address: AddressService; readonly session: LiveSession },
  prepared: PreparedCall,
  run: OracleRawRun,
  outcome: CallOutcomeColumns,
  delivery: {
    readonly inlineLimit: number;
    readonly rows: readonly CallBatchRow[] | null;
    readonly streamId: StId | null;
  },
  notes: ShapeNotes,
): Promise<BatchView> => {
  const inline = delivery.rows === null;
  const byStatus: BatchView["by_status"] = {};
  for (const s of outcome.status) byStatus[s] = (byStatus[s] ?? 0) + 1;
  const faults: FaultView[] = [];
  for (const fault of run.faults.slice(0, FAULTS_INLINE)) faults.push(await faultView(ctx.address, ctx.session, fault));
  const rows = delivery.rows ?? [];
  const continuation =
    run.next !== null
      ? { vector_offset: run.next }
      : prepared.windowCapped
        ? { vector_offset: prepared.offset + run.raw.completed }
        : null;
  return {
    offset: prepared.offset,
    vectors: prepared.total - prepared.offset,
    completed: run.raw.completed,
    returned: byStatus.returned ?? 0,
    by_status: byStatus,
    columns: inline ? inlineColumns(prepared, outcome, notes) : null,
    status: inline ? [...outcome.status] : null,
    preview: inline
      ? null
      : {
          first: rows.slice(0, PREVIEW_ROWS).map((r) => capRow(r, notes)),
          last: rows.slice(Math.max(PREVIEW_ROWS, rows.length - PREVIEW_ROWS)).map((r) => capRow(r, notes)),
        },
    faults,
    stream_id: inline ? null : delivery.streamId,
    continuation,
  };
};

type PreviewRow = NonNullable<BatchView["preview"]>["first"][number];
const capRow = (row: CallBatchRow, notes: ShapeNotes): PreviewRow => {
  const f: Record<string, Hex | Hex[]> = {};
  for (const [name, cell] of Object.entries(row.f)) f[name] = typeof cell === "string" ? cell : capArray(cell, notes);
  return { i: row.i, s: row.s, r: row.r, f, e: row.e };
};

/** FP environment as the output reports it (live calls never use a dump thread). */
export const fpView = (fp: PreparedCall["fp"]): CallFunctionOutput["fp"] => ({
  mxcsr: fpHex(fp.mxcsr) as Hex,
  fpcw: fpHex(fp.fpcw) as Hex,
  source: fp.source === "dump-thread" ? "thread" : fp.source,
});

/** bea.coverage/1 from per-vector Stalker blocks (S5 §11.4), stored as a blob; null when coverage was off. */
export const blockCoverage = async (
  deps: { readonly evidence: EvidenceRuntime; readonly address: AddressService },
  session: LiveSession,
  run: OracleRawRun,
  literals: SensitiveLiterals,
  op: OperationContext,
): Promise<{
  readonly view: CallFunctionOutput["block_coverage"];
  readonly blob: BlobRef | null;
  readonly truncated: boolean;
}> => {
  if (run.coverage === null) return { view: null, blob: null, truncated: false };
  const blocks = new Map<bigint, { size: number; vectors: Set<number> }>();
  let truncated = false;
  for (const vector of run.coverage) {
    truncated ||= vector.truncated;
    for (const [start, size] of vector.blocks) {
      const va = BigInt(start);
      const entry = blocks.get(va) ?? { size, vectors: new Set<number>() };
      entry.vectors.add(vector.index);
      blocks.set(va, entry);
    }
  }
  const map = deps.evidence.modules.current(session.instanceId)?.map() ?? null;
  const modules: CoverageBlobV1["modules"] = [];
  const moduleIds = new Map<string, number>();
  const rows: CoverageBlobV1["blocks"] = [];
  const unattributed: CoverageBlobV1["unattributed"] = [];
  for (const [va, entry] of [...blocks].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    const module = map === null ? null : moduleAt(map, va);
    if (module === null) {
      unattributed.push([formatHex(va), Math.min(entry.size, 65_535), entry.vectors.size]);
      continue;
    }
    let id = moduleIds.get(module.base);
    if (id === undefined) {
      id = modules.length;
      moduleIds.set(module.base, id);
      modules.push({
        id,
        name: module.display.name ?? `module_${module.base}`,
        path: module.display.path,
        base: module.base,
        size: module.size,
        file_sha256: null,
        preferred_base: null,
        entry_rva: null,
        timestamp: null,
      });
    }
    rows.push([id, Number(va - BigInt(module.base)), Math.min(entry.size, 65_535), entry.vectors.size]);
  }
  const executions = [...blocks.values()].reduce((sum, e) => sum + e.vectors.size, 0);
  const document: CoverageBlobV1 = {
    schema: "bea.coverage/1",
    source: {
      kind: "stalker",
      granularity: "stalker-block",
      session_id: session.id,
      evidence_id: null,
      thread_ids: [...run.threadIds],
    },
    address_space: "live",
    modules,
    blocks: rows,
    unattributed,
    totals: { distinct_blocks: blocks.size, executions, truncated },
  };
  const stored = await deps.evidence.blobs.put(new TextEncoder().encode(JSON.stringify(document)), {
    role: "coverage",
    media_type: "application/json",
    literals,
  });
  if (!stored.ok || "redacted" in stored.value) return { view: null, blob: null, truncated: true };
  const blob = stored.value;
  const space = { kind: "live" as const, session };
  const starts = [...blocks.keys()].sort((a, b) => (a < b ? -1 : 1)).slice(0, FUNCTION_BLOCKS_DESCRIBED);
  await deps.address.prepare(space, starts, op);
  const functions = new Map<string, { blocks: number; vectors: Set<number> }>();
  for (const start of starts) {
    const loc = await deps.address.describeCode(space, start);
    if (loc.func === null) continue;
    const entry = functions.get(loc.func) ?? { blocks: 0, vectors: new Set<number>() };
    entry.blocks += 1;
    for (const v of blocks.get(start)?.vectors ?? []) entry.vectors.add(v);
    functions.set(loc.func, entry);
  }
  return {
    view: {
      blocks: blocks.size,
      modules: modules.length,
      functions: [...functions]
        .sort((a, b) => b[1].blocks - a[1].blocks || (a[0] < b[0] ? -1 : 1))
        .slice(0, 50)
        .map(([func, e]) => ({ func: func.slice(0, 600), blocks: e.blocks, vectors: e.vectors.size })),
      blob_sha256: blob.sha256,
    },
    blob,
    truncated,
  };
};

/** Limitations and coverage parts this tool adds on top of the executor's (runCoverage). */
export const callNotes = (
  prepared: PreparedCall,
  run: OracleRawRun,
  session: LiveSession,
  flags: { readonly truncatedValues: boolean; readonly coverageTruncated: boolean },
): { readonly coverage: Coverage[]; readonly limitations: string[] } => {
  const coverage: Coverage[] = [];
  const limitations: string[] = [];
  if (prepared.fp.limitations.includes("CALL_FP_DEFAULT")) limitations.push(LIMITATIONS.CALL_FP_DEFAULT);
  if (session.paused) limitations.push(LIMITATIONS.CALLED_BEFORE_INIT);
  if (flags.truncatedValues) {
    coverage.push({ status: "partial", truncated: true, reasons: ["value_cap"] });
    limitations.push(LIMITATIONS.CAP("inline value", ARRAY_INLINE_CAP));
  }
  if (flags.coverageTruncated) {
    coverage.push({ status: "partial", truncated: true, reasons: ["row_cap"] });
    limitations.push(LIMITATIONS.CAP("coverage block", AGENT_LIMIT_DEFAULTS.call_coverage_blocks));
  }
  if (run.next === null && prepared.windowCapped) {
    coverage.push({ status: "partial", truncated: false, reasons: ["row_cap"] });
    limitations.push(LIMITATIONS.CAP("generated vectors per call", GENERATE_WINDOW));
  }
  return { coverage, limitations };
};
