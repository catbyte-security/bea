import { z } from "zod";

import { hexSchema } from "../../domain/hex.js";
import { sha256Schema } from "../../domain/ids.js";
import { fx } from "../effects.js";
import { recordedOutput } from "../schemas/envelope.js";
import { localPathSchema, sessionIdSchema } from "../schemas/primitives.js";
import { defineTool, type ToolContract } from "../toolContract.js";

/**
 * Area dump (WP13-DUMP, DESIGN §6.2 #30): dump_memory. Description is S6 §4.15 verbatim; the input adds DESIGN's
 * format (pe | raw | bundle = bea.dump/1 for emu_open), bundle options and live_bytes (D-INT-45). Records
 * bea.memory.dump (pe/raw) or bea.dump.capture (bundle). out_path passes checkOutputPath (D-INT-42).
 */
const DUMP_MAX_RAW_BYTES = 2 ** 31 - 1;
const BUNDLE_MAX_MODULES = 16;
const BUNDLE_MAX_REGIONS = 64;
const BUNDLE_MAX_REGION_BYTES = 256 * 1024 * 1024;

const SAMPLE_SESSION = "3f2b8c1e-4d5a-4e6f-9a0b-1c2d3e4f5a6b";

const moduleTokenSchema = z.string().min(1).max(600);

export const dumpInputSchema = z
  .strictObject({
    session_id: sessionIdSchema,
    format: z
      .enum(["pe", "raw", "bundle"])
      .default("pe")
      .describe("pe image; raw address+size; bundle = bea.dump/1 dir for emu_open."),
    module: moduleTokenSchema.optional().describe("Module (pe): name, $main or name@0xBASE."),
    address: z.string().min(2).max(600).optional().describe("AddrExpr (raw)."),
    size: z.number().int().min(1).max(DUMP_MAX_RAW_BYTES).optional().describe("Bytes (raw)."),
    layout: z.enum(["pe_realigned", "mapped"]).default("pe_realigned"),
    rebase_to: z.enum(["runtime", "preferred"]).default("runtime"),
    bundle: z
      .strictObject({
        modules: z.array(moduleTokenSchema).min(1).max(BUNDLE_MAX_MODULES).default(["$main"]),
        regions: z
          .array(
            z.strictObject({
              address: z.string().min(2).max(600),
              size: z.number().int().min(1).max(BUNDLE_MAX_REGION_BYTES),
            }),
          )
          .max(BUNDLE_MAX_REGIONS)
          .default([])
          .describe("Extra AddrExpr ranges."),
        thread_id: z
          .number()
          .int()
          .min(1)
          .max(2 ** 32 - 1)
          .optional()
          .describe("Primary thread (default: main)."),
        mode: z
          .enum(["running", "suspended"])
          .default("running")
          .describe("suspended: other threads paused while state is copied."),
      })
      .optional(),
    live_bytes: z.boolean().default(false).describe("Keep hook patches instead of original bytes."),
    out_path: localPathSchema.optional().describe("New absolute path; default BEA_HOME/runs/<run>/exports."),
  })
  .superRefine((input, ctx) => {
    const issue = (path: string, message: string) => ctx.addIssue({ code: "custom", path: [path], message });
    if (input.format === "pe") {
      if (input.module === undefined) issue("module", 'format "pe" needs module. Example: {"module":"game.exe"}');
      if (input.address !== undefined || input.size !== undefined)
        issue("address", 'address/size are for format "raw". Example: {"format":"raw","address":"0x…","size":4096}');
    } else if (input.format === "raw") {
      if (input.address === undefined || input.size === undefined)
        issue("address", 'format "raw" needs address and size. Example: {"format":"raw","address":"0x…","size":4096}');
      if (input.module !== undefined) issue("module", 'module is for format "pe".');
    } else if (input.module !== undefined || input.address !== undefined || input.size !== undefined)
      issue(
        "format",
        'format "bundle" takes its modules and regions inside bundle. Example: {"format":"bundle","bundle":{"modules":["$main"]}}',
      );
    if (input.bundle !== undefined && input.format !== "bundle") issue("bundle", 'bundle is only for format "bundle".');
  });

const gapSchema = z.strictObject({ va: hexSchema, size: z.number().int().min(1) });
const restoredPatchSchema = z.strictObject({
  rva: hexSchema,
  size: z.number().int().min(1),
  source: z.enum(["bea-original", "file-image"]),
});

export const DUMP_TOOLS = [
  defineTool({
    name: "dump_memory",
    area: "dump",
    phase: "P2",
    description:
      "Write a module image or an address range from the live process to a new file for REA/Ghidra: layout pe_realigned (sections at virtual offsets, loads as a PE) or mapped (a raw memory image: load it as raw binary at base, it is not a PE file for loaders); rebase_to preferred un-applies relocations so pointers match the static project. Never overwrites; default path is under BEA_HOME/runs. Returns path, bytes, sha256, base and zero-filled unreadable gaps.",
    inputSchema: dumpInputSchema,
    outputSchema: recordedOutput({
      path: z.string().max(4096),
      bytes: z.number().int().min(0),
      sha256: sha256Schema,
      format: z.enum(["pe", "raw", "bundle"]),
      base: hexSchema.nullable(),
      layout: z.enum(["pe_realigned", "mapped"]).nullable(),
      image_base_in_file: hexSchema.nullable(),
      module: z
        .strictObject({
          name: z.string().max(260),
          path: z.string().max(4096),
          file_sha256: sha256Schema.nullable(),
          rebased_to: z.enum(["runtime", "preferred"]),
          relocations_reverted: z.number().int().min(0).nullable(),
        })
        .nullable(),
      gaps: z.array(gapSchema).max(256),
      restored_patches: z.array(restoredPatchSchema).max(256),
      bundle: z
        .strictObject({
          bundle_id: z.string().regex(/^dump_[0-9a-f]{64}$/u),
          regions: z.number().int().min(0),
          modules: z.number().int().min(0),
          threads: z.number().int().min(0),
        })
        .nullable(),
    }),
    effects: fx({ readsTargetMemory: true, writesFilesystem: true, mutatesSession: true, idempotent: false }),
    cli: { tier: "session-oneshot", command: "dump", positional: ["module"] },
    evidence: { predicate: "bea.memory.dump", recorded: "always" },
    errors: ["address_unmapped", "memory_access_failed", "file_operation_failed", "access_denied", "target_exited"],
    maxBlockingMs: 120_000,
    examples: [
      {
        title: "Realigned, rebased image for Ghidra/REA",
        input: { session_id: SAMPLE_SESSION, module: "game.exe", layout: "pe_realigned", rebase_to: "preferred" },
      },
      {
        title: "Raw range",
        input: { session_id: SAMPLE_SESSION, format: "raw", address: "0x1f2a3b4c000", size: 4096 },
      },
      {
        title: "bea.dump/1 bundle for emu_open",
        input: { session_id: SAMPLE_SESSION, format: "bundle", bundle: { modules: ["$main"], mode: "suspended" } },
      },
    ],
  }),
] as const satisfies readonly ToolContract[];
