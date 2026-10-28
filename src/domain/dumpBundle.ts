import { z } from "zod";

import type { DumpManifestV1 } from "./artifacts.js";
import { hexSchema, type Hex } from "./hex.js";
import { evIdSchema, piIdSchema, sha256Schema } from "./ids.js";

/**
 * bea.dump/1 bundle manifest (S5 §10.1; DESIGN §6.2 #30; WP-DUMP). Pure zod schema + pure cross-field constraints;
 * the file-system half of verification (region files, sha256, JCS identity) is application/dump/verifyDumpBundle.ts
 * (CI-M18: fs access stays out of domain). Producer: dump_memory {format:"bundle"} / DumpCapturePort; consumer:
 * WP-EMU (emu_open {dump_path | live_session_id}) and the bridge, which re-checks the same constraints.
 *
 * WP-DUMP addition (additive, recorded as a change request against src/domain/artifacts.ts): a thread `context` may
 * carry `rflags`, `mxcsr` and `fpcw` next to the 17 GPRs, so the emulator takes the REAL FPCW/MXCSR of the captured
 * thread (S4 §15.1: the fixtures run with FPCW 0x37F / MXCSR 0x1FA0, not the bridge defaults).
 */
export const DUMP_BUNDLE_SCHEMA = "bea.dump/1" as const;
export const DUMP_PAGE_BYTES = 4096;
/** KUSER_SHARED_DATA (R3): the fixed user-mode mapping of the shared data page. */
export const KUSER_SHARED_DATA_VA = 0x7ffe0000n;
export const DUMP_MANIFEST_FILE = "manifest.json";
export const DUMP_REGIONS_DIR = "regions";

export const DUMP_GPRS = [
  "rip",
  "rsp",
  "rbp",
  "rax",
  "rbx",
  "rcx",
  "rdx",
  "rsi",
  "rdi",
  "r8",
  "r9",
  "r10",
  "r11",
  "r12",
  "r13",
  "r14",
  "r15",
] as const;
export type DumpGpr = (typeof DUMP_GPRS)[number];

export const DUMP_REGION_TAGS = ["module", "heap", "stack", "teb", "peb", "tls", "kuser_shared_data", "range"] as const;
export type DumpRegionTag = (typeof DUMP_REGION_TAGS)[number];

/** 128-bit register text (xmm): canonical lowercase hex up to 32 digits. */
const hex128Schema = z.string().regex(/^0x(?:0|[1-9a-f][0-9a-f]{0,31})$/u) as unknown as z.ZodType<Hex, string>;
const u32 = z
  .number()
  .int()
  .min(0)
  .max(2 ** 32 - 1);
/** Sizes inside the 47-bit user address space. */
const vaSize = z
  .number()
  .int()
  .min(0)
  .max(2 ** 47);
const protectionSchema = z.string().regex(/^[r-][w-][x-]$/u);
const shortText = z.string().max(260);
const pathText = z.string().max(4096);

const gprShape = Object.fromEntries(DUMP_GPRS.map((name) => [name, hexSchema])) as {
  readonly [K in DumpGpr]: typeof hexSchema;
};

export const dumpThreadContextSchema = z.strictObject({
  ...gprShape,
  xmm: z.array(hex128Schema).max(16).exactOptional(),
  rflags: hexSchema.exactOptional(),
  mxcsr: hexSchema.exactOptional(),
  fpcw: hexSchema.exactOptional(),
});

const triggerSchema = z.strictObject({
  kind: z.literal("hook"),
  target: z.strictObject({ va: hexSchema, module: shortText, rva: hexSchema }),
  thread_id: u32,
  call: z.strictObject({
    gpr: z.strictObject({ rcx: hexSchema, rdx: hexSchema, r8: hexSchema, r9: hexSchema }),
    xmm: z.tuple([hex128Schema, hex128Schema, hex128Schema, hex128Schema]),
    rsp: hexSchema,
    stack: z.array(hexSchema).max(28),
  }),
  ret: z.strictObject({ rax: hexSchema, xmm0: hex128Schema }).exactOptional(),
});

export const dumpManifestSchema = z.strictObject({
  schema: z.literal(DUMP_BUNDLE_SCHEMA),
  bundle_id: z.string().regex(/^dump_[0-9a-f]{64}$/u) as unknown as z.ZodType<`dump_${string}`, string>,
  created_at: z.iso.datetime(),
  producer: z.strictObject({
    tool: z.literal("bea"),
    version: z.string().min(1).max(32),
    operation: z.literal("dump_memory"),
    evidence_id: evIdSchema.nullable(),
    instance_id: piIdSchema.nullable(),
  }),
  process: z.strictObject({
    pid: u32,
    image_path: pathText,
    image_sha256: sha256Schema.nullable(),
    arch: z.literal("x64"),
    os: z.strictObject({ platform: z.literal("windows"), version: z.string().max(64) }),
  }),
  capture: z.strictObject({
    mode: z.enum(["running", "suspended", "at_hook"]),
    time_anchor: z
      .strictObject({
        seq: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
        effect_epoch: z
          .number()
          .int()
          .min(0)
          .max(2 ** 31),
        module_map_epoch: z
          .number()
          .int()
          .min(0)
          .max(2 ** 31),
      })
      .nullable(),
    duration_ms: z.number().int().min(0).max(86_400_000),
    trigger: triggerSchema.exactOptional(),
  }),
  modules: z
    .array(
      z.strictObject({
        name: shortText,
        path: pathText,
        base: hexSchema,
        size: vaSize,
        file_sha256: sha256Schema.nullable(),
        preferred_base: hexSchema.nullable(),
        timestamp: u32.nullable(),
        captured: z.enum(["full", "partial", "none"]),
      }),
    )
    .max(4096),
  regions: z
    .array(
      z.strictObject({
        base: hexSchema,
        size: vaSize,
        protection: protectionSchema,
        tag: z.enum(DUMP_REGION_TAGS),
        module: shortText.nullable(),
        sha256: sha256Schema,
        complete: z.boolean(),
        unreadable_pages: z.array(hexSchema).max(1_048_576),
      }),
    )
    .max(65_536),
  memory_map: z
    .array(
      z.strictObject({ base: hexSchema, size: vaSize, protection: protectionSchema, module: shortText.nullable() }),
    )
    .max(262_144),
  threads: z
    .array(
      z.strictObject({
        tid: u32,
        primary: z.boolean(),
        teb: hexSchema,
        context: dumpThreadContextSchema,
        stack: z.strictObject({ base: hexSchema, limit: hexSchema }).nullable(),
        tls: z.strictObject({
          slots_array: hexSchema.nullable(),
          static_blocks: z
            .array(z.strictObject({ module: shortText, index: u32, address: hexSchema, size: vaSize }))
            .max(1024),
        }),
      }),
    )
    .max(1024),
  peb: hexSchema.nullable(),
  imports: z
    .array(
      z.strictObject({
        importer: shortText,
        slot: hexSchema,
        name: z.string().max(1024).nullable(),
        ordinal: z.number().int().min(0).max(65_535).nullable(),
        dll: shortText,
        target: hexSchema,
      }),
    )
    .max(262_144),
  limitations: z.array(z.string().min(1).max(1000)).max(64),
});
export type DumpManifest = z.infer<typeof dumpManifestSchema>;
export type DumpManifestRegion = DumpManifest["regions"][number];
export type DumpManifestThread = DumpManifest["threads"][number];

/** Compile-time proof that every schema-valid manifest is a src/domain/artifacts.ts DumpManifestV1. */
export const asDumpManifestV1 = (manifest: DumpManifest): DumpManifestV1 => manifest;

export interface DumpConstraintOptions {
  /** emu.dump_max_mb in bytes (total region bytes) */
  readonly maxTotalBytes: number;
  /** optional emulator memory limit in bytes; total must stay below it minus 256 MiB of headroom */
  readonly memoryLimitBytes?: number;
  /** the thread whose TEB must be captured; default the primary thread */
  readonly threadId?: number;
}

export interface DumpConstraintIssue {
  /** JSON pointer-ish path inside the manifest */
  readonly path: string;
  readonly problem: string;
  readonly kind: "layout" | "size";
}

const HEADROOM_BYTES = 256 * 1024 * 1024;

/**
 * The S5 §10.1 constraints that need no file access: 4 KiB alignment, no overlap, unreadable pages inside their
 * region, a readable-only memory map, exactly one primary thread whose TEB lies inside a captured region, and the
 * total size bound. Returns every violation (empty = valid). BEA-authored problem text only.
 */
export const dumpManifestIssues = (manifest: DumpManifest, options: DumpConstraintOptions): DumpConstraintIssue[] => {
  const issues: DumpConstraintIssue[] = [];
  const page = BigInt(DUMP_PAGE_BYTES);
  const spans: { start: bigint; end: bigint; index: number }[] = [];
  let total = 0;
  manifest.regions.forEach((region, index) => {
    const base = BigInt(region.base);
    const path = `regions[${String(index)}]`;
    if (base % page !== 0n || region.size % DUMP_PAGE_BYTES !== 0 || region.size === 0)
      issues.push({ path, problem: "region is not a non-empty run of 4 KiB pages", kind: "layout" });
    const end = base + BigInt(region.size);
    for (const unreadable of region.unreadable_pages) {
      const at = BigInt(unreadable);
      if (at % page !== 0n || at < base || at >= end)
        issues.push({
          path: `${path}.unreadable_pages`,
          problem: "unreadable page outside its region",
          kind: "layout",
        });
    }
    spans.push({ start: base, end, index });
    total += region.size;
  });
  spans.sort((a, b) => (a.start < b.start ? -1 : a.start > b.start ? 1 : 0));
  for (let i = 1; i < spans.length; i++) {
    const prev = spans[i - 1];
    const cur = spans[i];
    if (prev !== undefined && cur !== undefined && cur.start < prev.end)
      issues.push({ path: `regions[${String(cur.index)}]`, problem: "region overlaps another region", kind: "layout" });
  }
  manifest.memory_map.forEach((range, index) => {
    if (!range.protection.startsWith("r"))
      issues.push({
        path: `memory_map[${String(index)}]`,
        problem: "memory_map lists only readable ranges",
        kind: "layout",
      });
  });
  const primaries = manifest.threads.filter((t) => t.primary);
  if (manifest.threads.length === 0 || primaries.length !== 1)
    issues.push({ path: "threads", problem: "exactly one primary thread is required", kind: "layout" });
  const chosen =
    options.threadId === undefined ? primaries[0] : manifest.threads.find((thread) => thread.tid === options.threadId);
  if (options.threadId !== undefined && chosen === undefined)
    issues.push({ path: "threads", problem: "the requested thread is not in the bundle", kind: "layout" });
  if (chosen !== undefined) {
    const teb = BigInt(chosen.teb);
    if (!spans.some((s) => s.start <= teb && teb < s.end))
      issues.push({
        path: "threads",
        problem: "the chosen thread's TEB is not inside a captured region",
        kind: "layout",
      });
  }
  if (total > options.maxTotalBytes)
    issues.push({ path: "regions", problem: "total region bytes exceed emu.dump_max_mb", kind: "size" });
  if (options.memoryLimitBytes !== undefined && total >= options.memoryLimitBytes - HEADROOM_BYTES)
    issues.push({
      path: "regions",
      problem: "total region bytes leave less than 256 MiB of the emulator memory limit",
      kind: "size",
    });
  return issues;
};

/** Total bytes of all regions. */
export const dumpTotalBytes = (manifest: DumpManifest): number =>
  manifest.regions.reduce((sum, region) => sum + region.size, 0);
