import type { CoverageBlobV1 } from "../../domain/artifacts.js";
import type { CoverageWire } from "../../domain/emuProtocol.js";
import type { EmuModuleView } from "../../ports/emu.js";
import { formatHex, type Hex } from "../../shared/hex.js";

/**
 * bea.coverage/1 builder for emulation runs (S5 §11.4): every translation block `(va, size, hits)` of the bridge's
 * coverage is attributed to the module containing it (rva = va − base; module-relative, so ASLR-independent and
 * comparable with live Stalker coverage of the same file by (file_sha256, rva)); blocks outside modules are
 * `unattributed`, except BEA's own synthetic window (HLE stubs, heap, scratch, stack, TEB), which is dropped.
 * `export_coverage` (WP-WATCH) turns the blob into drcov. Unicorn TBs are not CFG blocks; consumers map by overlap.
 */
export const COVERAGE_MEDIA_TYPE = "application/json";
export const COVERAGE_BLOB_ROLE = "coverage";
/** the synthetic window BEA maps at OpenResult.layout.syntheticBase (stubs, heap, scratch, stack, TEB) */
const SYNTHETIC_WINDOW_BYTES = 0x1_0000_0000n;
/** drcov bb_entry carries a u16 size */
const MAX_BLOCK_SIZE = 0xffff;

export interface CoverageBlobInput {
  readonly wire: CoverageWire;
  readonly modules: readonly EmuModuleView[];
  readonly addressSpace: "emulation-image" | "emulation-dump";
  readonly sessionId: string;
  readonly evidenceId: string | null;
  readonly vectors: number;
  /** OpenResult.layout.syntheticBase; null: nothing is excluded */
  readonly syntheticBase: Hex | null;
}

export const buildCoverageBlob = (input: CoverageBlobInput): CoverageBlobV1 => {
  const modules = [...input.modules]
    .map((m) => ({ view: m, base: BigInt(m.base), end: BigInt(m.base) + BigInt(m.size) }))
    .sort((a, b) => (a.base < b.base ? -1 : a.base > b.base ? 1 : 0));
  const findModule = (va: bigint): number => {
    let lo = 0;
    let hi = modules.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const m = modules[mid];
      if (m === undefined) return -1;
      if (va < m.base) hi = mid - 1;
      else if (va >= m.end) lo = mid + 1;
      else return mid;
    }
    return -1;
  };
  const synthetic = input.syntheticBase === null ? null : BigInt(input.syntheticBase);
  const blocks: [number, number, number, number][] = [];
  const unattributed: [Hex, number, number][] = [];
  let executions = 0;
  for (const [vaText, size, hits] of input.wire.blocks) {
    const va = BigInt(vaText);
    const id = findModule(va);
    if (id >= 0) {
      const module = modules[id];
      if (module === undefined) continue;
      blocks.push([id, Number(va - module.base), Math.min(size, MAX_BLOCK_SIZE), hits]);
      executions += hits;
      continue;
    }
    if (synthetic !== null && va >= synthetic && va < synthetic + SYNTHETIC_WINDOW_BYTES) continue;
    unattributed.push([formatHex(va), size, hits]);
    executions += hits;
  }
  blocks.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  unattributed.sort((a, b) => (BigInt(a[0]) < BigInt(b[0]) ? -1 : 1));
  return {
    schema: "bea.coverage/1",
    source: {
      kind: "emulation",
      engine: "unicorn",
      granularity: "translation-block",
      session_id: input.sessionId,
      evidence_id: input.evidenceId,
      vectors: input.vectors,
    },
    address_space: input.addressSpace,
    modules: modules.map((m, id) => ({
      id,
      name: m.view.name,
      path: m.view.path,
      base: formatHex(m.base),
      size: m.view.size,
      file_sha256: m.view.sha256,
      preferred_base: m.view.preferredBase,
      entry_rva: null,
      timestamp: null,
    })),
    blocks,
    unattributed,
    totals: { distinct_blocks: blocks.length + unattributed.length, executions, truncated: input.wire.truncated },
  };
};
