// =================================================================================================
// src/application/watch/coverage.ts — block coverage as `bea.coverage/1` (S5 §11.4; DESIGN: WP9 produces it for
// traces, WP11/WP14 for calls and emulation) and its two export formats (S6 §4.27): drcov v2 (DynamoRIO module table
// version 2 + binary BB table {u32 start (module-relative), u16 size, u16 mod_id}; BELIEVED layout, L6) and modoff
// (one `module+0xRVA` line per block). Pure: no I/O.
// =================================================================================================
import { z } from "zod";

import type { CoverageBlobV1 } from "../../domain/artifacts.js";
import { formatHex, type Hex } from "../../domain/hex.js";

export interface CoverageModuleFacts {
  readonly name: string;
  readonly path: string | null;
  readonly base: bigint;
  readonly size: number;
  readonly fileSha256: string | null;
  readonly preferredBase: bigint | null;
  readonly entryRva: number | null;
  readonly timestamp: number | null;
}
export interface RawBlock {
  readonly va: bigint;
  readonly size: number;
  readonly hits: number;
}

/** bea.coverage/1 from live Stalker blocks: module-relative, sorted, duplicates (recompiled blocks) merged. */
export const buildStalkerCoverage = (
  source: { readonly sessionId: string; readonly evidenceId: string | null; readonly threads: readonly number[] },
  modules: readonly CoverageModuleFacts[],
  blocks: readonly RawBlock[],
  truncated: boolean,
): CoverageBlobV1 => {
  const sorted = [...modules].sort((a, b) => (a.base < b.base ? -1 : 1));
  const merged = new Map<string, { moduleId: number; rva: number; size: number; hits: number }>();
  const unattributed = new Map<bigint, { size: number; hits: number }>();
  let executions = 0;
  for (const b of blocks) {
    executions += b.hits;
    const id = sorted.findIndex((m) => b.va >= m.base && b.va < m.base + BigInt(m.size));
    if (id < 0) {
      const u = unattributed.get(b.va);
      if (u === undefined) unattributed.set(b.va, { size: b.size, hits: b.hits });
      else {
        u.hits += b.hits;
        u.size = Math.max(u.size, b.size);
      }
      continue;
    }
    const module = sorted[id] as CoverageModuleFacts;
    const rva = Number(b.va - module.base);
    const key = `${String(id)}:${String(rva)}`;
    const known = merged.get(key);
    if (known === undefined) merged.set(key, { moduleId: id, rva, size: Math.min(65_535, b.size), hits: b.hits });
    else {
      known.hits += b.hits;
      known.size = Math.max(known.size, Math.min(65_535, b.size));
    }
  }
  const rows = [...merged.values()].sort((a, b) => a.moduleId - b.moduleId || a.rva - b.rva);
  return {
    schema: "bea.coverage/1",
    source: {
      kind: "stalker",
      granularity: "stalker-block",
      session_id: source.sessionId,
      evidence_id: source.evidenceId,
      thread_ids: [...source.threads],
    },
    address_space: "live",
    modules: sorted.map((m, id) => ({
      id,
      name: m.name,
      path: m.path,
      base: formatHex(m.base),
      size: m.size,
      file_sha256: m.fileSha256,
      preferred_base: m.preferredBase === null ? null : formatHex(m.preferredBase),
      entry_rva: m.entryRva === null ? null : formatHex(m.entryRva),
      timestamp: m.timestamp,
    })),
    blocks: rows.map((r) => [r.moduleId, r.rva, r.size, r.hits] as [number, number, number, number]),
    unattributed: [...unattributed.entries()]
      .sort((a, b) => (a[0] < b[0] ? -1 : 1))
      .map(([va, u]) => [formatHex(va), u.size, u.hits] as [Hex, number, number]),
    totals: { distinct_blocks: rows.length, executions, truncated },
  };
};

const hexText = /^0x[0-9a-fA-F]{1,16}$/u;
/** Validation of a stored bea.coverage/1 blob (produced by any WP; extra fields tolerated). */
const coverageBlobSchema = z.object({
  schema: z.literal("bea.coverage/1"),
  source: z.object({ kind: z.enum(["emulation", "stalker"]) }).passthrough(),
  address_space: z.enum(["emulation-image", "emulation-dump", "live"]),
  modules: z
    .array(
      z.object({
        id: z.number().int().min(0).max(65_535),
        name: z.string().max(4096),
        path: z.string().max(4096).nullable(),
        base: z.string().regex(hexText),
        size: z.number().int().min(0),
        file_sha256: z.string().nullable().optional(),
        preferred_base: z.string().regex(hexText).nullable().optional(),
        entry_rva: z.string().regex(hexText).nullable().optional(),
        timestamp: z.number().int().nullable().optional(),
      }),
    )
    .max(65_536),
  blocks: z
    .array(
      z.tuple([z.number().int().min(0), z.number().int().min(0), z.number().int().min(0), z.number().int().min(0)]),
    )
    .max(50_000_000),
  unattributed: z.array(z.tuple([z.string(), z.number().int().min(0), z.number().int().min(0)])).default([]),
  totals: z.object({ truncated: z.boolean() }).passthrough(),
});
export const parseCoverageBlob = (value: unknown): CoverageBlobV1 | null => {
  const parsed = coverageBlobSchema.safeParse(value);
  return parsed.success ? (parsed.data as unknown as CoverageBlobV1) : null;
};

const hex16 = (v: bigint): string => `0x${v.toString(16).padStart(16, "0")}`;
const hex8 = (v: number): string => `0x${(v >>> 0).toString(16).padStart(8, "0")}`;

/**
 * drcov version 2 with the Windows module-table columns (id, base, end, entry, checksum, timestamp, path) as
 * DynamoRIO's drcov writes them and Lighthouse/Cartographer read them; blocks outside modules are not representable.
 */
export const drcovBytes = (blob: CoverageBlobV1): Uint8Array => {
  const lines = [
    "DRCOV VERSION: 2",
    "DRCOV FLAVOR: drcov",
    `Module Table: version 2, count ${String(blob.modules.length)}`,
    "Columns: id, base, end, entry, checksum, timestamp, path",
  ];
  for (const m of blob.modules) {
    const base = BigInt(m.base);
    const entry = m.entry_rva === null ? 0n : base + BigInt(m.entry_rva);
    lines.push(
      `${String(m.id).padStart(3)}, ${hex16(base)}, ${hex16(base + BigInt(m.size))}, ${hex16(entry)}, ${hex8(0)}, ${hex8(m.timestamp ?? 0)}, ${m.path ?? m.name}`,
    );
  }
  const blocks = blob.blocks.filter(([, rva]) => rva <= 0xffff_ffff);
  lines.push(`BB Table: ${String(blocks.length)} bbs`);
  const header = new TextEncoder().encode(`${lines.join("\n")}\n`);
  const out = new Uint8Array(header.length + blocks.length * 8);
  out.set(header, 0);
  const dv = new DataView(out.buffer, header.length);
  blocks.forEach(([moduleId, rva, size], i) => {
    dv.setUint32(i * 8, rva, true);
    dv.setUint16(i * 8 + 4, Math.min(65_535, size), true);
    dv.setUint16(i * 8 + 6, moduleId, true);
  });
  return out;
};

/** One `module+0xRVA` line per block, module-table order then RVA. */
export const modoffText = (blob: CoverageBlobV1): string => {
  const names = new Map(blob.modules.map((m) => [m.id, m.name]));
  const lines = blob.blocks.map(
    ([moduleId, rva]) => `${names.get(moduleId) ?? `module${String(moduleId)}`}+${formatHex(rva)}`,
  );
  return lines.length === 0 ? "" : `${lines.join("\n")}\n`;
};
