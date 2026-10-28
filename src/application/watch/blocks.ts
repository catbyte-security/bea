// =================================================================================================
// src/application/watch/blocks.ts — the blocks of a trace recording and their function attribution, shared by
// trace_execution (TraceSummary.functions) and export_coverage (WP9-WATCH).
// =================================================================================================
import type { BeaError } from "../../domain/errors/beaError.js";
import { ok, type Result } from "../../domain/result.js";
import type { RecordingRegistry } from "../../ports/recordings.js";
import type { OperationContext } from "../../ports/sessions.js";
import type { RawBlock } from "./coverage.js";
import type { LegendEntry } from "./decoders.js";
import type { CodeLocator } from "./locate.js";

/** At most this many distinct blocks are read back for attribution and exports (stalker_max_blocks default). */
const MAX_BLOCKS = 1 << 20;

export interface TraceBlocks {
  readonly blocks: RawBlock[];
  /** seq of the first record of each block (TraceSummary.functions[].first_seq) */
  readonly firstSeq: Map<bigint, number>;
  readonly truncated: boolean;
}

/** Distinct blocks of a trace recording (counts summed by start; call edges ignored). */
export const readTraceBlocks = async (
  recordings: RecordingRegistry,
  id: string,
  op: OperationContext,
): Promise<Result<TraceBlocks, BeaError>> => {
  const merged = new Map<bigint, { size: number; hits: number }>();
  const firstSeq = new Map<bigint, number>();
  let truncated = false;
  for await (const e of recordings.events(id, {}, op)) {
    const va = typeof e["va"] === "string" ? BigInt(e["va"]) : null;
    const size = typeof e["size"] === "number" ? e["size"] : null;
    if (va === null || size === null) continue;
    const hits = typeof e["hits"] === "number" ? e["hits"] : 1;
    const known = merged.get(va);
    if (known !== undefined) {
      known.hits += hits;
      known.size = Math.max(known.size, size);
      continue;
    }
    if (merged.size >= MAX_BLOCKS) {
      truncated = true;
      continue;
    }
    merged.set(va, { size, hits });
    firstSeq.set(va, e.seq);
  }
  return ok({
    blocks: [...merged.entries()].map(([va, b]) => ({ va, size: b.size, hits: b.hits })),
    firstSeq,
    truncated,
  });
};

export interface FunctionBlocks {
  readonly func: string;
  readonly sym: string | null;
  readonly blocks: number;
  readonly first_seq: number;
}

/** The functions a summary or export lists (most blocks first). */
const FUNCTIONS_LISTED = 50;

/** Blocks per .pdata function, most blocks first; unattributed blocks are counted separately. */
export const attributeFunctions = async (
  locator: CodeLocator,
  legend: readonly LegendEntry[],
  blocks: readonly RawBlock[],
  firstSeq: ReadonlyMap<bigint, number>,
): Promise<{ readonly functions: FunctionBlocks[]; readonly unresolved: number }> => {
  const byFunc = new Map<string, { sym: string | null; blocks: number; first: number }>();
  let unresolved = 0;
  for (const b of blocks) {
    const fn = await locator.functionOf(legend, b.va).catch(() => null);
    if (fn === null) {
      unresolved += 1;
      continue;
    }
    const seq = firstSeq.get(b.va) ?? 0;
    const known = byFunc.get(fn.func);
    if (known === undefined) byFunc.set(fn.func, { sym: fn.sym, blocks: 1, first: seq });
    else {
      known.blocks += 1;
      known.first = Math.min(known.first, seq);
    }
  }
  const functions = [...byFunc.entries()]
    .map(([func, f]) => ({ func, sym: f.sym, blocks: f.blocks, first_seq: f.first }))
    .sort((a, b) => b.blocks - a.blocks || a.first_seq - b.first_seq)
    .slice(0, FUNCTIONS_LISTED);
  return { functions, unresolved };
};
