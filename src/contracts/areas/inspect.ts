import { z } from "zod";

import { addressRefSchema } from "../../domain/address/addressRef.js";
import { hexSchema } from "../../domain/hex.js";
import { sha256Schema } from "../../domain/ids.js";
import { fx } from "../effects.js";
import { addrExprSchema } from "../schemas/address.js";
import { maybeRecordedOutput, pageSchema, recordedOutput } from "../schemas/envelope.js";
import { limitSchema, offsetSchema, sessionIdSchema } from "../schemas/primitives.js";
import { REGISTERS } from "../schemas/shared.js";
import { defineTool, type ToolContract } from "../toolContract.js";

/**
 * Area inspect (WP-INSPECT; DESIGN §6.2 B, S6 §4.8, §4.10, §4.11, §4.13, §4.14): list_modules, list_memory_ranges,
 * list_threads, read_memory, disassemble. Descriptions are S6 §4 verbatim except read_memory, whose field name
 * follows the integrated output (`returned`, not S6's `returned_bytes`).
 */

/** Read-only through the already-injected agent (RM MS Id; D-INT-18). */
const READ_EFFECTS = fx({ readsTargetMemory: true, mutatesSession: true });

/** Schema caps of target text and row cells, chosen so the worst-case envelope stays ≤ 2 MiB (S2 §8.2). */
export const INSPECT_CAPS = {
  moduleName: 260,
  /** module paths in list rows (Windows MAX_PATH 260; longer extended-length paths are clipped) */
  path: 768,
  disasmRows: 4096,
  /** x64 instructions are ≤ 15 bytes */
  insnHexChars: 30,
  insnText: 120,
  ref: 160,
  readValues: 16_384,
  readBytes: 65_536,
  scalarChars: 24,
  derefSteps: 8,
  sensitiveValues: 64,
} as const;

const EXAMPLE_SESSION = "6f1c2a4e-8b3d-4e5f-9a7b-1c2d3e4f5a6b";

// ---------------------------------------------------------------- list_modules (#8)
export const listModulesInputSchema = z.strictObject({
  session_id: sessionIdSchema,
  filter: z.string().min(1).max(256).optional().describe("Case-insensitive module-name substring."),
  hash: z.boolean().default(false).describe("sha256 of each listed module file (cached by path, size and mtime)."),
  offset: offsetSchema,
  limit: limitSchema(1000, 100),
});
export const moduleRowSchema = z.strictObject({
  name: z.string().max(INSPECT_CAPS.moduleName),
  base: hexSchema,
  size: z.number().int().min(0).max(4_294_967_295),
  /** null for emulation modules without a backing file */
  path: z.string().max(INSPECT_CAPS.path).nullable(),
  preferred_base: hexSchema.nullable(),
  timestamp: z.number().int().min(0).max(4_294_967_295).nullable(),
  sha256: sha256Schema.nullable(),
  main: z.boolean(),
});
export const listModulesOutputSchema = maybeRecordedOutput({
  /** agent module-map epoch (live) or emulation session generation */
  epoch: z
    .number()
    .int()
    .min(0)
    .max(2 ** 31),
  rows: z.array(moduleRowSchema).max(1000),
  page: pageSchema,
});

// ---------------------------------------------------------------- list_memory_ranges (#9)
export const PROTECTIONS = ["---", "r--", "rw-", "r-x", "rwx"] as const;
export const listMemoryRangesInputSchema = z.strictObject({
  session_id: sessionIdSchema,
  protection: z.enum(PROTECTIONS).default("r--").describe("Minimum protection (Frida semantics)."),
  module: z.string().min(1).max(INSPECT_CAPS.moduleName).optional().describe("Only ranges of this module."),
  kind: z.enum(["all", "image", "private"]).default("all"),
  coalesce: z.boolean().default(true),
  offset: offsetSchema,
  limit: limitSchema(1000, 200),
});
export const rangeRowSchema = z.strictObject({
  base: hexSchema,
  size: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
  prot: z.string().max(8),
  module: z.string().max(INSPECT_CAPS.moduleName).nullable(),
  kind: z.enum(["image", "private", "mapped"]),
});
export const listMemoryRangesOutputSchema = recordedOutput({
  total_bytes: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
  rows: z.array(rangeRowSchema).max(1000),
  page: pageSchema,
});

// ---------------------------------------------------------------- list_threads (#10)
/** General registers of list_threads rows (the GPR subset of REGISTERS). */
export const GPRS = [
  "rax",
  "rbx",
  "rcx",
  "rdx",
  "rsi",
  "rdi",
  "rbp",
  "rsp",
  "r8",
  "r9",
  "r10",
  "r11",
  "r12",
  "r13",
  "r14",
  "r15",
  "rip",
] as const satisfies readonly (typeof REGISTERS)[number][];
export const listThreadsInputSchema = z.strictObject({
  session_id: sessionIdSchema,
  registers: z.boolean().default(false).describe("Include general registers (rax..r15, rip)."),
  offset: offsetSchema,
  limit: limitSchema(1000, 100),
});
const locOutSchema = z.strictObject({
  va: hexSchema,
  at: z.string().max(INSPECT_CAPS.ref).nullable(),
  static: z.string().max(INSPECT_CAPS.ref).nullable(),
  func: z.string().max(INSPECT_CAPS.ref).nullable(),
  sym: z.string().max(INSPECT_CAPS.ref).nullable(),
});
export const threadRowSchema = z.strictObject({
  tid: z.number().int().min(0).max(4_294_967_295),
  main: z.boolean(),
  entry: locOutSchema.nullable(),
  registers: z
    .strictObject(
      Object.fromEntries(GPRS.map((r) => [r, hexSchema.exactOptional()])) as Record<
        (typeof GPRS)[number],
        z.ZodExactOptional<typeof hexSchema>
      >,
    )
    .exactOptional(),
});
export const listThreadsOutputSchema = recordedOutput({
  rows: z.array(threadRowSchema).max(1000),
  page: pageSchema,
});

// ---------------------------------------------------------------- read_memory (#11)
export const READ_VIEWS = [
  "hex",
  "base64",
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
  "utf8",
  "utf16",
] as const;
export type ReadView = (typeof READ_VIEWS)[number];
const DEREF_LIMIT = 16 * 1024 * 1024;
export const readMemoryInputSchema = z.strictObject({
  session_id: sessionIdSchema,
  address: addrExprSchema,
  deref: z
    .array(z.number().int().min(-DEREF_LIMIT).max(DEREF_LIMIT))
    .min(1)
    .max(INSPECT_CAPS.derefSteps)
    .optional()
    .describe("Pointer chain offsets: [[address]+d0]+d1… (Cheat Engine semantics)."),
  size: z.number().int().min(1).max(INSPECT_CAPS.readBytes).default(64),
  view: z.enum(READ_VIEWS).default("hex"),
  sensitive_values: z
    .array(z.string().min(1).max(256))
    .max(INSPECT_CAPS.sensitiveValues)
    .optional()
    .describe("Literals (≥ 4 bytes) whose matches are dropped from the result and evidence."),
});
/** Output scalar of a typed view (S6 §2.3): ≤ 32-bit ints and floats as numbers; 64-bit, ptr, float specials as text. */
const viewScalarSchema = z.union([z.number(), z.string().max(INSPECT_CAPS.scalarChars), z.boolean()]);
export const readMemoryOutputSchema = recordedOutput({
  address: addressRefSchema,
  chain: z
    .array(z.strictObject({ address: hexSchema, value: hexSchema }))
    .max(INSPECT_CAPS.derefSteps)
    .exactOptional(),
  requested: z.number().int().min(1).max(INSPECT_CAPS.readBytes),
  returned: z.number().int().min(0).max(INSPECT_CAPS.readBytes),
  complete: z.boolean(),
  /** data, values and text are null when the bytes contained a sensitive value (redacted; review fixes SEC-3/4) */
  data: z
    .string()
    .max(2 * INSPECT_CAPS.readBytes)
    .nullable()
    .exactOptional(),
  values: z.array(viewScalarSchema).max(INSPECT_CAPS.readValues).nullable().exactOptional(),
  text: z.string().max(INSPECT_CAPS.readBytes).nullable().exactOptional(),
  region: z
    .strictObject({
      base: hexSchema,
      size: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
      prot: z.string().max(8),
      module: z.string().max(INSPECT_CAPS.moduleName).nullable(),
    })
    .nullable(),
});

// ---------------------------------------------------------------- disassemble (#12)
export const disassembleInputSchema = z.strictObject({
  session_id: sessionIdSchema,
  address: addrExprSchema,
  count: z.number().int().min(1).max(512).default(32),
  function: z
    .boolean()
    .default(false)
    .describe("Disassemble the whole .pdata function containing address (≤ 4096 instructions)."),
});
export const disasmRowSchema = z.strictObject({
  rva: hexSchema.nullable(),
  va: hexSchema,
  /** instruction bytes, hex; null when they contained a sensitive value (redacted; review fix SEC-4) */
  b: z.string().max(INSPECT_CAPS.insnHexChars).nullable(),
  /** Intel syntax text */
  t: z.string().max(INSPECT_CAPS.insnText),
  /** resolved branch/call/RIP-relative target: "module+0xrva module:0xstatic", or "0x…" outside images */
  ref: z.string().max(INSPECT_CAPS.ref).nullable(),
});
export const disassembleOutputSchema = recordedOutput({
  module: z.string().max(INSPECT_CAPS.moduleName).nullable(),
  func: z.strictObject({ start: hexSchema, size: z.number().int().min(0).max(4_294_967_295) }).nullable(),
  rows: z.array(disasmRowSchema).max(INSPECT_CAPS.disasmRows),
  hooked_bytes_restored: z.boolean(),
});

export const INSPECT_TOOLS = [
  defineTool({
    name: "list_modules",
    area: "inspect",
    phase: "P1",
    title: "List Modules",
    description:
      "List loaded modules with base, size, path, preferred ImageBase read from the file on disk, PE timestamp and optional file sha256 (hash: true), plus the module-map id and epoch that address results cite. Filter by name substring; paged with a total. Reads through the already-injected agent; frida-agent.dll is hidden. To rebase a Ghidra/REA address, pass module:0xVA to any address field.",
    inputSchema: listModulesInputSchema,
    outputSchema: listModulesOutputSchema,
    effects: READ_EFFECTS,
    cli: { tier: "session-oneshot", command: "modules", positional: [] },
    sessionKinds: ["live", "emulation"],
    // emulation module tables are not recorded (the predicate is live-only; the bea.emu.session record holds them)
    evidence: { predicate: "bea.modules.list", recorded: "always" },
    errors: ["target_exited"],
    examples: [
      { title: "List modules", input: { session_id: EXAMPLE_SESSION } },
      { title: "Hash one module", input: { session_id: EXAMPLE_SESSION, filter: "game", hash: true } },
    ],
  }),
  defineTool({
    name: "list_memory_ranges",
    area: "inspect",
    phase: "P1",
    title: "List Memory Ranges",
    description:
      "List memory ranges with base, size, protection and owning module (BEA attributes ranges itself; Windows reports no file names), filtered by minimum protection, module or kind (image or private), optionally coalesced; paged with total count and bytes. Use it to choose scan and dump scopes. Read-only through the injected agent.",
    inputSchema: listMemoryRangesInputSchema,
    outputSchema: listMemoryRangesOutputSchema,
    effects: READ_EFFECTS,
    cli: { tier: "session-oneshot", command: "maps", positional: [] },
    sessionKinds: ["live"],
    evidence: { predicate: "bea.memory.ranges", recorded: "always" },
    errors: ["target_exited"],
    examples: [
      { title: "Writable ranges", input: { session_id: EXAMPLE_SESSION, protection: "rw-" } },
      { title: "Private heap ranges", input: { session_id: EXAMPLE_SESSION, kind: "private", limit: 50 } },
    ],
  }),
  defineTool({
    name: "list_threads",
    area: "inspect",
    phase: "P2",
    title: "List Threads",
    description:
      "List the target's threads (tid, entry routine as module+RVA, main flag) and optionally their general registers. Thread state and names are unreliable on Windows and are not reported. Use the tids for call_function thread_id, trace_execution thread_ids and hook thread filters. Read-only through the injected agent.",
    inputSchema: listThreadsInputSchema,
    outputSchema: listThreadsOutputSchema,
    effects: READ_EFFECTS,
    cli: { tier: "session-oneshot", command: "threads", positional: [] },
    sessionKinds: ["live"],
    evidence: { predicate: "bea.threads.list", recorded: "always" },
    errors: ["target_exited"],
    examples: [{ title: "Threads with registers", input: { session_id: EXAMPLE_SESSION, registers: true } }],
  }),
  defineTool({
    name: "read_memory",
    area: "inspect",
    phase: "P1",
    title: "Read Memory",
    description:
      "Read up to 64 KiB of target or emulator memory at an address expression, optionally following a pointer chain first (deref offsets, Cheat-Engine [[a]+o1]+o2 semantics), returned as hex or base64 or as a typed array view (f32, i32, ptr, utf16 ...). An unreadable page ends the read: check complete and returned. Bytes are untrusted target content. Read-only.",
    inputSchema: readMemoryInputSchema,
    outputSchema: readMemoryOutputSchema,
    effects: READ_EFFECTS,
    cli: { tier: "session-oneshot", command: "read", positional: ["address", "size"] },
    sessionKinds: ["live", "emulation"],
    // live: bea.memory.read; emulation sessions record bea.emu.memory.read
    evidence: { predicate: "bea.memory.read", recorded: "always" },
    errors: ["address_unmapped", "memory_access_failed", "target_exited"],
    examples: [
      { title: "Read 64 bytes at an export", input: { session_id: EXAMPLE_SESSION, address: "game.exe!g_marker" } },
      {
        title: "Follow a pointer chain to a float",
        input: { session_id: EXAMPLE_SESSION, address: "game.exe!g_world", deref: [8, 8], size: 4, view: "f32" },
      },
    ],
  }),
  defineTool({
    name: "disassemble",
    area: "inspect",
    phase: "P1",
    title: "Disassemble",
    description:
      "Disassemble count instructions, or the whole .pdata function containing the address, from a live or emulation session. Shows original bytes where BEA hooks are installed, and resolves branch, call and RIP-relative targets to address forms (module+RVA, static VA). Read-only.",
    inputSchema: disassembleInputSchema,
    outputSchema: disassembleOutputSchema,
    effects: READ_EFFECTS,
    cli: { tier: "session-oneshot", command: "disasm", positional: ["address"] },
    sessionKinds: ["live", "emulation"],
    evidence: { predicate: "bea.code.disassembly", recorded: "always" },
    errors: ["address_unmapped", "memory_access_failed", "target_exited"],
    examples: [
      {
        title: "Whole function",
        input: { session_id: EXAMPLE_SESSION, address: "game.exe!physics_step", function: true },
      },
      { title: "Sixteen instructions", input: { session_id: EXAMPLE_SESSION, address: "game.exe+0x1760", count: 16 } },
    ],
  }),
] as const satisfies readonly ToolContract[];
