import { z } from "zod";

import { hexSchema } from "../../domain/hex.js";
import { fx } from "../effects.js";
import { maybeRecordedOutput, pageSchema, pollOutput } from "../schemas/envelope.js";
import { offsetSchema, limitSchema, sessionIdSchema } from "../schemas/primitives.js";
import { scanIdSchema } from "../schemas/shared.js";
import { defineTool, type ToolContract } from "../toolContract.js";

/**
 * Area scan (WP10-SCAN; DESIGN §6.2 D, S6 §4.17–4.19): scan_memory, scan_next, scan_results. Descriptions are S6 §4
 * verbatim except scan_memory, whose unknown-value snapshot lives in the target (S4 §9.1, capped by the agent's
 * scan_snapshot_bytes), not on disk.
 */

/** Value types a scan accepts (the tool-level `bool` is one byte, CI-M13). */
const SCAN_VALUE_TYPES = [
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
  "bytes",
  "utf8",
  "utf16",
] as const;
export type ScanToolValueType = (typeof SCAN_VALUE_TYPES)[number];
const BYTE_STRING_TYPES: ReadonlySet<ScanToolValueType> = new Set(["bytes", "utf8", "utf16"]);
const FLOAT_TYPES: ReadonlySet<ScanToolValueType> = new Set(["f32", "f64"]);

/** Schema caps chosen so the worst-case scan_results envelope stays ≤ 2 MiB (S2 §8.2). */
export const SCAN_CAPS = {
  /** a scalar input: numbers, decimal/hex text, a match pattern of ≤ 256 bytes, text of ≤ 256 UTF-8 bytes */
  valueChars: 800,
  /** an output cell: text values and the hex of byte values (≤ 256 bytes → 512 hex characters) */
  cellChars: 1024,
  pageRows: 500,
  module: 260,
  /** compact address texts of a row ("module+0xrva", "module:0xstatic"; quoted names and @0xbase included) */
  addressText: 320,
} as const;

const scanScalarSchema = z.union([z.number(), z.string().min(1).max(SCAN_CAPS.valueChars), z.boolean()]);
const cellSchema = z.union([z.number(), z.string().max(SCAN_CAPS.cellChars), z.boolean(), z.null()]);
const count = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const waitMs = z.number().int().min(0).max(60_000).default(30_000);
const epsilon = z.number().min(0).max(1e9).optional();
const EXAMPLE_SESSION = "6f1c2a4e-8b3d-4e5f-9a7b-1c2d3e4f5a6b";

// ---------------------------------------------------------------- scan_memory (#15)
export const scanMemoryInputSchema = z
  .strictObject({
    session_id: sessionIdSchema,
    value_type: z.enum(SCAN_VALUE_TYPES),
    compare: z.enum(["exact", "between", "unknown", "pointer_to"]).default("exact"),
    value: scanScalarSchema
      .optional()
      .describe('bytes: pattern like "48 8b ?? 4?"; utf8/utf16: text; ptr, pointer_to: hex or AddrExpr.'),
    value2: scanScalarSchema.optional().describe("Upper bound (between)."),
    epsilon,
    protection: z.enum(["rw-", "r--", "r-x"]).default("rw-"),
    module: z.string().min(1).max(SCAN_CAPS.module).optional().describe("Only this module."),
    kind: z.enum(["all", "image", "private"]).default("all").describe("image: static pointer candidates."),
    aligned: z.boolean().default(true),
    max_hits: z.number().int().min(1).max(50_000_000).default(10_000_000),
    wait_ms: waitMs,
  })
  .superRefine((v, ctx) => {
    const issue = (path: string, message: string): void => void ctx.addIssue({ code: "custom", path: [path], message });
    if (v.compare !== "unknown" && v.value === undefined)
      issue("value", 'value is required unless compare is "unknown". Example: {"value_type":"f32","value":20}');
    if (v.compare === "unknown" && v.value !== undefined)
      issue("value", 'compare "unknown" takes no value; narrow later with scan_next.');
    if ((v.compare === "between") !== (v.value2 !== undefined))
      issue("value2", 'value2 is required with compare "between" and only then. Example: {"value":23.9,"value2":24.3}');
    if (v.compare === "pointer_to" && v.value_type !== "ptr")
      issue("value_type", 'compare "pointer_to" needs value_type "ptr".');
    if (BYTE_STRING_TYPES.has(v.value_type) && v.compare !== "exact")
      issue("compare", `${v.value_type} scans support compare "exact" only.`);
    if (v.epsilon !== undefined && !(FLOAT_TYPES.has(v.value_type) && v.compare === "exact"))
      issue("epsilon", 'epsilon applies to an f32/f64 compare "exact".');
    if (v.module !== undefined && v.kind === "private")
      issue("kind", 'module restricts the scan to an image; it cannot be combined with kind "private".');
  });
export const scanMemoryOutputSchema = maybeRecordedOutput({
  scan_id: scanIdSchema,
  state: z.enum(["running", "done", "failed"]),
  count,
  scanned_bytes: count,
  ranges_failed: count,
  truncated: z.boolean(),
  elapsed_ms: count,
});

// ---------------------------------------------------------------- scan_next (#16)
const SCAN_NEXT_COMPARES = [
  "exact",
  "between",
  "changed",
  "unchanged",
  "increased",
  "decreased",
  "increased_by",
  "decreased_by",
] as const;
export type ScanNextCompare = (typeof SCAN_NEXT_COMPARES)[number];
const VALUE_COMPARES: ReadonlySet<ScanNextCompare> = new Set(["exact", "between", "increased_by", "decreased_by"]);

export const scanNextInputSchema = z
  .strictObject({
    scan_id: scanIdSchema,
    compare: z.enum(SCAN_NEXT_COMPARES),
    value: scanScalarSchema.optional(),
    value2: scanScalarSchema.optional(),
    epsilon,
    wait_ms: waitMs,
  })
  .superRefine((v, ctx) => {
    const issue = (path: string, message: string): void => void ctx.addIssue({ code: "custom", path: [path], message });
    if (VALUE_COMPARES.has(v.compare) && v.value === undefined)
      issue("value", `compare "${v.compare}" needs a value. Example: {"compare":"increased_by","value":1.5}`);
    if (!VALUE_COMPARES.has(v.compare) && v.value !== undefined)
      issue("value", `compare "${v.compare}" compares with each hit's previous value and takes no value.`);
    if ((v.compare === "between") !== (v.value2 !== undefined))
      issue("value2", 'value2 is required with compare "between" and only then.');
  });
export const scanNextOutputSchema = maybeRecordedOutput({
  scan_id: scanIdSchema,
  state: z.enum(["running", "done", "failed"]),
  count,
  previous_count: count.nullable(),
  iteration: z.number().int().min(0).max(1_000_000),
});

// ---------------------------------------------------------------- scan_results (#17)
export const scanResultsInputSchema = z.strictObject({
  scan_id: scanIdSchema,
  offset: offsetSchema,
  limit: limitSchema(SCAN_CAPS.pageRows, 50),
  values: z.boolean().default(true).describe("false: stored values only."),
});
const scanRowSchema = z.strictObject({
  va: hexSchema,
  at: z.string().max(SCAN_CAPS.addressText).nullable(),
  static: z.string().max(SCAN_CAPS.addressText).nullable(),
  value: cellSchema,
  prev: cellSchema,
});
export const scanResultsOutputSchema = pollOutput({
  scan_id: scanIdSchema,
  rows: z.array(scanRowSchema).max(SCAN_CAPS.pageRows),
  page: pageSchema,
});

export const SCAN_TOOLS = [
  defineTool({
    name: "scan_memory",
    area: "scan",
    phase: "P2",
    description:
      "Start a Cheat-Engine-style scan handle over target memory: exact value (ints, f32/f64 with epsilon, byte pattern with ?? wildcards, utf8/utf16 text), between two values, unknown initial value (snapshot in the target), or pointers to an address. Returns only scan_id and hit count; page hits with scan_results and narrow with scan_next. Runs in the background; blocks up to wait_ms. Read-only; snapshots are capped in size.",
    inputSchema: scanMemoryInputSchema,
    outputSchema: scanMemoryOutputSchema,
    effects: fx({ readsTargetMemory: true, mutatesSession: true, idempotent: false }),
    cli: { tier: "scenario", reason: "Scan handles are session state; run scans from MCP or as steps of a scenario." },
    evidence: { predicate: "bea.scan.result", recorded: "when-done", identityExclude: ["wait_ms"] },
    errors: ["reference_not_found", "target_exited", "address_unmapped", "invalid_state"],
    maxBlockingMs: 90_000,
    examples: [
      {
        title: "Find a float speed shown as about 24 m/s",
        input: { session_id: EXAMPLE_SESSION, value_type: "f32", compare: "between", value: 23.9, value2: 24.3 },
      },
      {
        title: "Static pointers to a struct",
        input: {
          session_id: EXAMPLE_SESSION,
          value_type: "ptr",
          compare: "pointer_to",
          value: "0x1f3a5c40",
          kind: "image",
        },
      },
    ],
  }),
  defineTool({
    name: "scan_next",
    area: "scan",
    phase: "P2",
    description:
      "Narrow an existing scan by re-reading its hits: exact, between, changed, unchanged, increased, decreased, increased_by or decreased_by (epsilon for floats). Returns the remaining count. When hunting an unknown in-game value, ask the user to change it between calls. Read-only.",
    inputSchema: scanNextInputSchema,
    outputSchema: scanNextOutputSchema,
    effects: fx({ readsTargetMemory: true, mutatesSession: true, idempotent: false }),
    cli: { tier: "scenario", reason: "Scan handles are session state; run scans from MCP or as steps of a scenario." },
    sessionKinds: ["live"],
    evidence: { predicate: "bea.scan.result", recorded: "when-done", identityExclude: ["wait_ms"] },
    errors: ["reference_not_found", "target_exited", "invalid_state", "session_not_found"],
    maxBlockingMs: 90_000,
    examples: [{ title: "Keep hits whose value went up", input: { scan_id: "scan_0000000a", compare: "increased" } }],
  }),
  defineTool({
    name: "scan_results",
    area: "scan",
    phase: "P2",
    description:
      "Page a scan's hits with current and previous values and address forms; hits inside a module carry module+RVA and static VA (candidates for static pointers). Exhausting pages proves nothing about memory outside the scanned ranges. Read-only.",
    inputSchema: scanResultsInputSchema,
    outputSchema: scanResultsOutputSchema,
    effects: fx({ readsTargetMemory: true, mutatesSession: true }),
    cli: { tier: "scenario", reason: "Scan handles are session state; run scans from MCP or as steps of a scenario." },
    sessionKinds: ["live"],
    errors: ["reference_not_found", "target_exited", "invalid_state", "session_not_found"],
    examples: [{ title: "First page of hits", input: { scan_id: "scan_0000000a", limit: 20 } }],
  }),
] as const satisfies readonly ToolContract[];
