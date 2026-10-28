import { z } from "zod";

import { addressRefSchema, locSchema } from "../../domain/address/addressRef.js";
import { hexInputSchema, hexSchema } from "../../domain/hex.js";
import { sha256Schema } from "../../domain/ids.js";
import { fx } from "../effects.js";
import { addrExprSchema, exactlyOne } from "../schemas/address.js";
import { pageSchema, recordedOutput } from "../schemas/envelope.js";
import { localPathSchema, offsetSchema, sessionIdSchema } from "../schemas/primitives.js";
import { defineTool, type ToolContract } from "../toolContract.js";

/**
 * Area address (WP-ADDR; DESIGN §6.2 C, S6 §4.9 + §4.12, D-INT-32): map_address, list_module_symbols. Both run on
 * a live or emulation session (anySessionOp) or offline on a PE file (`pe_path`; CLI `--pe-path`, CI-I11).
 */
const EXAMPLE_SESSION = "3f2b8c1e-5d4a-4b6f-9a7e-1c2d3e4f5a6b";
const u32 = z.number().int().min(0).max(4_294_967_295);
const sizeSchema = z.number().int().min(1).max(4_294_967_295);
const sensitiveValuesSchema = z
  .array(z.string().min(1).max(1024))
  .max(64)
  .describe("Literals to redact from evidence (each >= 4 UTF-8 bytes).");

const SESSION_OR_FILE = exactlyOne(
  ["session_id", "pe_path"],
  '{"pe_path":"C:\\\\Games\\\\game.exe","addresses":["$main:0x140001000"]}',
);
const SYMBOL_RVA_OR_STATIC = exactlyOne(["rva", "static_va"], '{"rva":"0x1760","name":"physics_step"}');

// ---------------------------------------------------------------- map_address (#14)

const callerSymbolSchema = z
  .strictObject({
    rva: hexInputSchema.optional(),
    static_va: hexInputSchema.optional(),
    name: z.string().min(1).max(1024),
    size: sizeSchema.optional(),
  })
  .refine((v) => SYMBOL_RVA_OR_STATIC.check(v), { message: SYMBOL_RVA_OR_STATIC.message, path: ["rva"] });

export const mapAddressInputSchema = z
  .strictObject({
    session_id: sessionIdSchema.optional(),
    pe_path: localPathSchema.optional().describe("Offline: an absolute path to a PE64 file (no session)."),
    runtime_base: hexInputSchema.optional().describe("Offline only: the runtime base to map to."),
    addresses: z.array(addrExprSchema).min(1).max(64),
    verify_bytes: z
      .number()
      .int()
      .min(0)
      .max(64)
      .default(16)
      .describe("Compare N live bytes with the file bytes (live only); 0 disables."),
    expected_image_sha256: sha256Schema.optional().describe("Ghidra 'Executable SHA256' or the REA subject digest."),
    symbols: z
      .array(callerSymbolSchema)
      .max(4096)
      .optional()
      .describe("Caller names (Ghidra/REA) to register for symbols_module."),
    symbols_module: z.string().min(1).max(600).optional().describe("Module the symbols belong to (default $main)."),
    symbols_source: z.enum(["ghidra", "rea", "ida", "binja", "analyst", "other"]).optional(),
    external_ref: z
      .strictObject({
        system: z.enum(["rea", "ghidra", "other"]),
        id: z.string().min(1).max(256),
        image_sha256: sha256Schema.optional(),
        image_base: hexInputSchema.optional(),
      })
      .optional(),
    sensitive_values: sensitiveValuesSchema.optional(),
  })
  .superRefine((v, ctx) => {
    if (!SESSION_OR_FILE.check(v))
      ctx.addIssue({ code: "custom", path: ["session_id"], message: SESSION_OR_FILE.message });
    if (v.runtime_base !== undefined && v.pe_path === undefined)
      ctx.addIssue({
        code: "custom",
        path: ["runtime_base"],
        message: "runtime_base is only for offline mode with pe_path; a session already knows its module bases.",
      });
  });

const verifySchema = z.strictObject({
  status: z.enum(["match", "mismatch", "partial", "not-applicable", "skipped"]),
  compared: z.number().int().min(0).max(64),
  equal: z.number().int().min(0).max(64),
  excluded_loader: z.number().int().min(0).max(64),
  own_effects_restored: z.number().int().min(0).max(64),
  differences: z
    .array(
      z.strictObject({
        rva: hexSchema,
        size: z.number().int().min(1).max(64),
        class: z.enum(["unexplained", "foreign-or-agent-patch"]),
      }),
    )
    .max(8),
});

const mapRowSchema = z.strictObject({
  index: z.number().int().min(0).max(63),
  input: z.string().max(600),
  status: z.enum(["mapped", "non-image", "error"]),
  address: addressRefSchema.nullable(),
  func: z
    .strictObject({
      start: z.string().max(600),
      size: u32,
      name: z.string().max(1024).nullable(),
      is_start: z.boolean(),
    })
    .nullable(),
  region: z.string().max(300).nullable(),
  image_check: z.enum(["match", "mismatch", "unchecked"]).nullable(),
  verify: verifySchema.nullable(),
  issue: z.strictObject({ code: z.string().max(64), message: z.string().max(600) }).nullable(),
});

const mapModuleSchema = z.strictObject({
  name: z.string().max(260),
  path: z.string().max(4096).nullable(),
  sha256: sha256Schema.nullable(),
  preferred_base: hexSchema,
  runtime_base: hexSchema.nullable(),
  base_source: z.enum(["pe-header", "caller", "emulation"]),
  runtime_matches_file: z.boolean().nullable(),
});

export const mapAddressOutputSchema = recordedOutput({
  modules: z.array(mapModuleSchema).max(64),
  rows: z.array(mapRowSchema).max(64),
  symbols_registered: z.number().int().min(0).max(4096).exactOptional(),
});

// ---------------------------------------------------------------- list_module_symbols (#13)

export const listModuleSymbolsInputSchema = z
  .strictObject({
    session_id: sessionIdSchema.optional(),
    pe_path: localPathSchema.optional().describe("Offline: an absolute path to a PE64 file (no session)."),
    module: z
      .string()
      .min(1)
      .max(600)
      .default("$main")
      .describe("Module name, quoted path or $main; ignored with pe_path."),
    kind: z.enum(["exports", "imports", "functions"]).default("exports"),
    filter: z.string().min(1).max(256).optional().describe("Case-insensitive name substring."),
    offset: offsetSchema,
    limit: z.number().int().min(1).max(1000).default(200),
  })
  .superRefine((v, ctx) => {
    if (!SESSION_OR_FILE.check(v))
      ctx.addIssue({
        code: "custom",
        path: ["session_id"],
        message: "Provide exactly one of session_id (live module) or pe_path (file on disk).",
      });
  });

/**
 * Row string caps keep one 1000-row page within the 2 MiB worst-case envelope (S2 §8.2, envelope contract test):
 * longer names are cut at the cap (the PE itself is the full source). `resolved` is a Loc with tighter caps
 * (SYMBOL_ROW_CAPS); a text that does not fit is null rather than cut, so every `at`/`static` still parses.
 */
export const SYMBOL_ROW_CAPS = {
  exportName: 768,
  forwarder: 384,
  importModule: 128,
  importName: 400,
  functionName: 768,
  locText: 180,
  locSym: 256,
} as const;
const resolvedLocSchema = locSchema.extend({
  at: z.string().max(SYMBOL_ROW_CAPS.locText).nullable(),
  static: z.string().max(SYMBOL_ROW_CAPS.locText).nullable(),
  func: z.string().max(SYMBOL_ROW_CAPS.locText).nullable(),
  sym: z.string().max(SYMBOL_ROW_CAPS.locSym).nullable(),
});
const exportRowSchema = z.strictObject({
  name: z.string().max(SYMBOL_ROW_CAPS.exportName).nullable(),
  ordinal: z.number().int().min(0).max(4_294_967_295),
  rva: hexSchema.nullable(),
  kind: z.enum(["function", "data"]),
  va: hexSchema.nullable(),
  forwarder: z.string().max(SYMBOL_ROW_CAPS.forwarder).nullable(),
});
const importRowSchema = z.strictObject({
  module: z.string().max(SYMBOL_ROW_CAPS.importModule),
  name: z.string().max(SYMBOL_ROW_CAPS.importName).nullable(),
  ordinal: z.number().int().min(0).max(65_535).nullable(),
  slot_rva: hexSchema,
  slot_va: hexSchema.nullable(),
  resolved: resolvedLocSchema.nullable(),
});
const functionRowSchema = z.strictObject({
  rva: hexSchema,
  size: u32,
  name: z.string().max(SYMBOL_ROW_CAPS.functionName).nullable(),
});

export const listModuleSymbolsOutputSchema = recordedOutput({
  module: z.string().max(260),
  image_sha256: sha256Schema.nullable(),
  preferred_base: hexSchema,
  kind: z.enum(["exports", "imports", "functions"]),
  rows: z.array(z.union([exportRowSchema, importRowSchema, functionRowSchema])).max(1000),
  page: pageSchema,
});

export const ADDRESS_TOOLS = [
  defineTool({
    name: "list_module_symbols",
    area: "address",
    phase: "P1",
    description:
      "List one module's exports, imports (with IAT slot) or .pdata function ranges (exact start and size), from the live process or from a PE file on disk (pe_path; no session needed). Filter by name substring; paged with a total. Names come from the PE itself, never from DebugSymbol guesses; non-exported functions appear only as unnamed .pdata ranges.",
    inputSchema: listModuleSymbolsInputSchema,
    outputSchema: listModuleSymbolsOutputSchema,
    effects: fx({ readsTargetMemory: true, mutatesSession: true }),
    cli: { tier: "session-oneshot", command: "symbols", positional: ["module"], offlineField: "pe_path" },
    sessionKinds: ["live", "emulation", "none"],
    evidence: { predicate: "bea.symbols.module", recorded: "always" },
    errors: ["file_operation_failed", "unsupported_target", "address_unmapped", "target_exited"],
    examples: [
      {
        title: "Exports of a DLL on disk",
        input: { pe_path: "C:\\Windows\\System32\\kernel32.dll", kind: "exports", filter: "Sleep" },
      },
      { title: "Function ranges of the main module", input: { session_id: EXAMPLE_SESSION, kind: "functions" } },
      { title: "Imports with IAT slots", input: { session_id: EXAMPLE_SESSION, module: "game.exe", kind: "imports" } },
    ],
  }),
  defineTool({
    name: "map_address",
    area: "address",
    phase: "P1",
    description:
      "Convert up to 64 address expressions between runtime VA, module+RVA and static VA (module:0xVA[/0xBASE]; base defaults to the ImageBase in the on-disk PE). Reports the enclosing .pdata function, the region, and whether verify_bytes live bytes equal the file bytes, so a Ghidra/REA address can be trusted before hooking. With pe_path and runtime_base it is pure arithmetic and needs no session.",
    inputSchema: mapAddressInputSchema,
    outputSchema: mapAddressOutputSchema,
    effects: fx({ readsTargetMemory: true, mutatesSession: true }),
    cli: { tier: "session-oneshot", command: "map", positional: ["addresses"], offlineField: "pe_path" },
    sessionKinds: ["live", "emulation", "none"],
    evidence: { predicate: "bea.address.map", recorded: "always" },
    errors: ["file_operation_failed", "unsupported_target", "target_exited"],
    maxInputBytes: 8 * 1024 * 1024,
    examples: [
      {
        title: "Rebase a Ghidra VA and verify the bytes",
        input: { session_id: EXAMPLE_SESSION, addresses: ["game.exe:0x1401234ab"], verify_bytes: 16 },
      },
      {
        title: "Offline arithmetic against the file",
        input: {
          pe_path: "C:\\Games\\game.exe",
          runtime_base: "0x7ff6a1b20000",
          addresses: ["$main:0x1401234ab", "+0x1760"],
        },
      },
      {
        title: "Register Ghidra names while mapping",
        input: {
          session_id: EXAMPLE_SESSION,
          addresses: ["game.exe:0x140001760"],
          symbols: [{ static_va: "0x140001760", name: "physics_step", size: 192 }],
          symbols_module: "game.exe",
          symbols_source: "ghidra",
        },
      },
    ],
  }),
] as const satisfies readonly ToolContract[];
