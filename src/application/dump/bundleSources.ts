import { KUSER_SHARED_DATA_VA, type DumpManifest, type DumpManifestThread } from "../../domain/dumpBundle.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { formatHex, type Hex } from "../../domain/hex.js";
import { pathKey } from "../../domain/process/instance.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { LiveSession, OperationContext } from "../../ports/sessions.js";
import type {
  DumpRegion,
  ImportRow,
  ModuleInfo,
  RangeRow,
  ThreadInfo,
  ThreadState,
} from "../../shared/agentProtocol.js";
import type { CapturedRegion } from "./DumpBundleWriter.js";
import { MAX_GAPS, type GapOut } from "./dumpMemory.js";
import { parseMappedPe } from "./PeDumpWriter.js";

/**
 * Inputs of the bea.dump/1 capture (S5 §10.2) that come from the agent's core RPCs and the captured bytes: the paged
 * readable memory map (R4) and resolved imports (R7), the primary-thread choice, the manifest thread context with the
 * real RFLAGS/MXCSR/FPCW (R5), static TLS blocks of captured modules (R6) and the gap list of a written manifest.
 */
const PAGE_SIZE = 50_000;
const MAX_MAP_ROWS = 262_144;
const MAX_IMPORT_ROWS = 262_144;

export const pageAlign = (va: bigint, size: number): { base: bigint; size: number } => {
  const base = va - (va % 4096n);
  const end = va + BigInt(size);
  const top = end % 4096n === 0n ? end : end + (4096n - (end % 4096n));
  return { base, size: Number(top - base) };
};

/** Every page of the agent's list RPCs (snapshot-consistent for listRanges). */
export const listAllRanges = async (
  session: LiveSession,
  op: OperationContext,
): Promise<Result<RangeRow[], BeaError>> => {
  const rows: RangeRow[] = [];
  let offset = 0;
  let snapshot: string | undefined;
  for (;;) {
    const page = await session.agent.call(
      "listRanges",
      {
        protection: "r--",
        coalesce: false,
        kind: "all",
        offset,
        limit: PAGE_SIZE,
        ...(snapshot !== undefined ? { snapshot } : {}),
      },
      { op },
    );
    if (!page.ok) return page;
    rows.push(...page.value.items);
    snapshot = page.value.snapshot;
    if (page.value.next_offset === null || rows.length >= MAX_MAP_ROWS) return ok(rows.slice(0, MAX_MAP_ROWS));
    offset = page.value.next_offset;
  }
};

export const listAllImports = async (
  session: LiveSession,
  module: string,
  op: OperationContext,
): Promise<Result<ImportRow[], BeaError>> => {
  const rows: ImportRow[] = [];
  let offset = 0;
  for (;;) {
    const page = await session.agent.call("listImports", { module, offset, limit: PAGE_SIZE }, { op });
    if (!page.ok) return page;
    rows.push(...page.value.items);
    if (page.value.next_offset === null || rows.length >= MAX_IMPORT_ROWS) return ok(rows);
    offset = page.value.next_offset;
  }
};

export const mainModuleOf = (modules: readonly ModuleInfo[], session: LiveSession): ModuleInfo | undefined => {
  const key = pathKey(session.identity.image.path, "win32");
  return modules.find((m) => pathKey(m.path, "win32") === key) ?? modules[0];
};

/** Primary thread: the requested one, else the thread that started in the main module, else the first. */
export const chooseThreads = (
  threads: readonly ThreadInfo[],
  main: ModuleInfo | undefined,
  requested: number | undefined,
): Result<{ primary: number; others: number[] }, string> => {
  const candidates = threads.filter((t) => t.bea_role === null);
  if (requested !== undefined) {
    if (!candidates.some((t) => t.id === requested)) return err("the thread is not running in the target");
    return ok({ primary: requested, others: candidates.map((t) => t.id).filter((id) => id !== requested) });
  }
  const inMain = (t: ThreadInfo) => {
    if (main === undefined || t.entry === null) return false;
    const entry = BigInt(t.entry);
    const base = BigInt(main.base);
    return entry >= base && entry < base + BigInt(main.size);
  };
  const primary = candidates.find(inMain) ?? candidates[0];
  if (primary === undefined) return err("the target has no threads to capture");
  return ok({ primary: primary.id, others: candidates.map((t) => t.id).filter((id) => id !== primary.id) });
};

export const tagOf = (region: DumpRegion): CapturedRegion["tag"] =>
  region.kind === "range" && BigInt(region.base) === KUSER_SHARED_DATA_VA ? "kuser_shared_data" : region.kind;

const GPRS = ["rip", "rsp", "rbp", "rax", "rbx", "rcx", "rdx", "rsi", "rdi"] as const;
export const contextOf = (state: ThreadState): DumpManifestThread["context"] => {
  const reg = (name: string): Hex => state.registers[name] ?? "0x0";
  return {
    ...Object.fromEntries(GPRS.map((name) => [name, reg(name)])),
    r8: reg("r8"),
    r9: reg("r9"),
    r10: reg("r10"),
    r11: reg("r11"),
    r12: reg("r12"),
    r13: reg("r13"),
    r14: reg("r14"),
    r15: reg("r15"),
    rflags: state.eflags,
    mxcsr: state.mxcsr,
    fpcw: state.fpcw,
    ...(state.xmm !== null ? { xmm: state.xmm.slice(0, 16) } : {}),
  } as DumpManifestThread["context"];
};

/** u64/u32 little-endian reads out of captured bytes by absolute VA. */
export interface CapturedBytes {
  readonly base: bigint;
  readonly bytes: Uint8Array;
}
const readAt = (captures: readonly CapturedBytes[], va: bigint, width: 4 | 8): bigint | null => {
  for (const c of captures) {
    const off = va - c.base;
    if (off >= 0n && off + BigInt(width) <= BigInt(c.bytes.length)) {
      const view = new DataView(c.bytes.buffer, c.bytes.byteOffset, c.bytes.byteLength);
      return width === 8 ? view.getBigUint64(Number(off), true) : BigInt(view.getUint32(Number(off), true));
    }
  }
  return null;
};

/** R6: static TLS blocks of the CAPTURED modules for one thread (index from the image, block from the slots array). */
export const staticTlsBlocks = (
  slotsArray: bigint | null,
  images: readonly { readonly name: string; readonly base: bigint; readonly bytes: Uint8Array }[],
  captures: readonly CapturedBytes[],
): DumpManifestThread["tls"]["static_blocks"] => {
  if (slotsArray === null) return [];
  const out: DumpManifestThread["tls"]["static_blocks"] = [];
  for (const image of images) {
    const pe = parseMappedPe(image.bytes);
    const dir = pe.ok ? pe.value.directories[9] : undefined;
    if (dir === undefined || dir.rva === 0 || dir.size < 0x28 || dir.rva + 0x28 > image.bytes.length) continue;
    const self = [{ base: image.base, bytes: image.bytes }];
    const start = readAt(self, image.base + BigInt(dir.rva), 8);
    const end = readAt(self, image.base + BigInt(dir.rva) + 8n, 8);
    const indexVa = readAt(self, image.base + BigInt(dir.rva) + 16n, 8);
    const zeroFill = readAt(self, image.base + BigInt(dir.rva) + 32n, 4);
    if (start === null || end === null || indexVa === null || zeroFill === null) continue;
    const index = readAt(self, indexVa, 4);
    if (index === null || index >= 64n) continue;
    const block = readAt(captures, slotsArray + 8n * index, 8);
    const size = Number(end > start ? end - start : 0n) + Number(zeroFill);
    if (block === null || block === 0n || size <= 0) continue;
    out.push({ module: image.name, index: Number(index), address: formatHex(block), size });
  }
  return out;
};

export const gapsOfManifest = (manifest: DumpManifest): { gaps: GapOut[]; total: number } => {
  const gaps: GapOut[] = [];
  let total = 0;
  for (const region of manifest.regions) {
    let run: { va: bigint; size: number } | null = null;
    for (const page of region.unreadable_pages.map((p) => BigInt(p))) {
      if (run !== null && run.va + BigInt(run.size) === page) run.size += 4096;
      else {
        if (run !== null) gaps.push({ va: formatHex(run.va), size: run.size });
        run = { va: page, size: 4096 };
        total++;
      }
    }
    if (run !== null) gaps.push({ va: formatHex(run.va), size: run.size });
  }
  return { gaps: gaps.slice(0, MAX_GAPS), total };
};
