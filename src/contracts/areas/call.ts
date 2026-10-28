import { z } from "zod";

import { addressRefSchema, locSchema } from "../../domain/address/addressRef.js";
import { hexSchema } from "../../domain/hex.js";
import { sha256Schema, stIdSchema } from "../../domain/ids.js";
import { fx } from "../effects.js";
import { addrExprSchema } from "../schemas/address.js";
import {
  bufferSchema,
  CALL_INPUT_LIMITS,
  callInputBudget,
  columnNameSchema,
  fpSchema,
  generateSchema,
  nullableScalarInputSchema,
  SCALAR_TYPES,
  scalarInputSchema,
  signatureSchema,
  vectorsSchema,
} from "../schemas/callModel.js";
import { recordedOutput } from "../schemas/envelope.js";
import { sessionIdSchema } from "../schemas/primitives.js";
import { scalarOutSchema } from "../schemas/shared.js";
import { defineTool, type ToolContract } from "../toolContract.js";

/**
 * Area call (WP11-CALL): call_function — the in-process oracle (DESIGN §6.2 #26, §5.3.1; D-INT-8/9/43).
 * Input = the shared flattened call model (§4 contracts/schemas/callModel.ts) + live execution controls; output =
 * single-call detail or batch columns (inline ≤ inline_limit vectors, else a `call-batch` row stream).
 */
const count = z.number().int().min(0).max(1_000_000);

/** S2 §15.1 per-call redaction literals (never persisted). */
const sensitiveValuesSchema = z.array(z.string().min(1).max(1024)).max(64);

export const CALL_STATUSES = [
  "returned",
  "fault",
  "cpu_exception",
  "invalid_instruction",
  "unsupported_instruction",
  "unhandled_import",
  "syscall",
  "raised",
  "terminated",
  "budget_exhausted",
  "timeout",
  "cancelled",
  "engine_error",
] as const;

export const callFunctionInputSchema = z
  .strictObject({
    session_id: sessionIdSchema,
    address: addrExprSchema,
    signature: signatureSchema,
    buffers: z.array(bufferSchema).max(64).default([]),
    args: z.array(nullableScalarInputSchema).max(32).optional(),
    fields: z.record(columnNameSchema, scalarInputSchema).optional(),
    vectors: vectorsSchema.optional(),
    generate: generateSchema.optional(),
    fp: fpSchema.optional(),
    thread_id: z.number().int().min(1).max(4_294_967_295).optional(),
    thread_at: addrExprSchema.optional(),
    coverage: z.boolean().default(false),
    hooks: z.enum(["suppress", "observe"]).default("suppress"),
    overrides: z.enum(["apply", "bypass"]).default("bypass"),
    vector_offset: z.number().int().min(0).max(1_000_000).default(0),
    inline_limit: z.number().int().min(0).max(256).default(64),
    timeout_ms: z.number().int().min(1000).max(110_000).default(30_000),
    sensitive_values: sensitiveValuesSchema.optional(),
  })
  .superRefine((input, ctx) => callInputBudget(input, ctx as unknown as Parameters<typeof callInputBudget>[1]))
  .refine(
    (x) =>
      [x.args !== undefined || x.fields !== undefined, x.vectors !== undefined, x.generate !== undefined].filter(
        Boolean,
      ).length <= 1,
    {
      message:
        'Use one mode: args/fields (single call), vectors or generate (batch). Example: {"vectors":{"columns":{"dt":[0.016,0.033]}}}',
    },
  )
  .refine((x) => x.hooks !== "observe" || x.thread_id !== undefined || x.thread_at !== undefined, {
    message: 'hooks "observe" needs thread_id or thread_at (BEA listeners drop the cloaked agent thread).',
    path: ["hooks"],
  });
export type CallFunctionInput = z.output<typeof callFunctionInputSchema>;

const callStatusSchema = z.enum(CALL_STATUSES);
const typedValueSchema = z.strictObject({ type: z.enum(SCALAR_TYPES), bits: hexSchema, value: scalarOutSchema });
const outputValueSchema = z.union([typedValueSchema, z.array(typedValueSchema).max(256)]);
const faultSchema = z.strictObject({
  index: count,
  type: z.string().max(32),
  code: hexSchema,
  address: locSchema,
  memory: z.strictObject({ operation: z.enum(["read", "write", "execute"]), address: hexSchema }).nullable(),
  insn: z.string().max(200).nullable(),
});
/** One vector as a `call-batch` stream row and in previews: index, status, return bits, out fields, fault cause. */
const batchRowSchema = z.strictObject({
  i: count,
  s: z.string().max(32),
  r: hexSchema.nullable(),
  f: z.record(z.string().max(130), z.union([hexSchema, z.array(hexSchema).max(65_536)])),
  e: z.string().max(32).nullable(),
});

const callFunctionOutputSchema = recordedOutput({
  target: addressRefSchema,
  mode: z.enum(["single", "batch"]),
  fp: z.strictObject({
    mxcsr: hexSchema,
    fpcw: hexSchema,
    source: z.enum(["explicit", "thread", "windows-default"]),
  }),
  exception_model: z.enum(["seh-frame", "steal"]),
  callee_exceptions: count,
  call: z
    .strictObject({
      status: callStatusSchema,
      ret: typedValueSchema.nullable(),
      outputs: z.record(z.string().max(130), outputValueSchema),
      out_buffers: z.record(
        z.string().max(64),
        z.strictObject({ address: hexSchema, bytes: count, hex: z.string().max(8192), truncated: z.boolean() }),
      ),
      fault: faultSchema.omit({ index: true }).nullable(),
      raw: z.strictObject({ rax: hexSchema, xmm0: hexSchema, mxcsr: hexSchema, fpcw: hexSchema }),
      wall_us: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
    })
    .exactOptional(),
  batch: z
    .strictObject({
      offset: count,
      vectors: count,
      completed: count,
      returned: count,
      by_status: z.record(z.string().max(32), count),
      columns: z
        .record(
          z.string().max(130),
          z.strictObject({
            bits: z.array(z.union([hexSchema, z.array(hexSchema).max(256)])).max(256),
            value: z.array(z.union([scalarOutSchema, z.array(scalarOutSchema).max(256)])).max(256),
          }),
        )
        .nullable(),
      status: z.array(callStatusSchema).max(256).nullable(),
      preview: z
        .strictObject({ first: z.array(batchRowSchema).max(8), last: z.array(batchRowSchema).max(8) })
        .nullable(),
      faults: z.array(faultSchema).max(32),
      stream_id: stIdSchema.nullable(),
      continuation: z.strictObject({ vector_offset: count }).nullable(),
    })
    .exactOptional(),
  block_coverage: z
    .strictObject({
      blocks: count,
      modules: count,
      functions: z.array(z.strictObject({ func: z.string().max(600), blocks: count, vectors: count })).max(50),
      blob_sha256: sha256Schema,
    })
    .nullable(),
});
export type CallFunctionOutput = z.output<typeof callFunctionOutputSchema>;

const SESSION = "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b";

export const callFunction = defineTool({
  name: "call_function",
  area: "call",
  phase: "P1",
  description:
    'Call a target function in-process as an oracle (Win64 ABI) with typed args: ints, f32/f64 (value or exact "0x…" bits), pointers, and buffers/struct scratch copies (from a live address via init_from, or hex) so real state is untouched. One call, or batches of vectors or seeded generators (vector_offset continues). Faults are per-vector results; the target survives and callee-handled exceptions are normal. Optional block coverage. Runs target code; taints the instance. Attached targets need the call_attached gate; there a call that never returns runs on, with the BEA agent, until process exit.',
  inputSchema: callFunctionInputSchema,
  outputSchema: callFunctionOutputSchema,
  effects: fx({
    readsTargetMemory: true,
    writesTargetMemory: true,
    executesTargetCode: true,
    mutatesSession: true,
    idempotent: false,
  }),
  gate: { id: "call_attached", scope: "attached-targets" },
  cli: { tier: "session-oneshot", command: "call", positional: ["address"] },
  sessionKinds: ["live"],
  evidence: { predicate: "bea.call.oracle", recorded: "always", identityExclude: ["inline_limit"] },
  errors: [
    "capability_unavailable",
    "address_unmapped",
    "memory_access_failed",
    "invalid_state",
    "target_exited",
    "instrumentation_failed",
  ],
  maxBlockingMs: 120_000,
  maxInputBytes: CALL_INPUT_LIMITS.maxInputBytes,
  examples: [
    {
      title: "physics_step on a scratch copy of the live car, three dt values",
      input: {
        session_id: SESSION,
        address: "game_sim.exe!physics_step",
        signature: {
          args: [
            { type: "buffer_ptr", buffer: "car" },
            { type: "f32", name: "dt" },
          ],
          returns: "f32",
        },
        buffers: [
          {
            name: "car",
            size: 128,
            init_from: "0x1f3a5c40",
            out: true,
            fields: [{ name: "speed", offset: 8, type: "f32" }],
          },
        ],
        vectors: { columns: { dt: [0.016667, 0.008333, "0x7fc00000"] } },
      },
    },
    {
      title: "four_floats with exact bits under flush-to-zero",
      input: {
        session_id: SESSION,
        address: "live_fixture.exe!four_floats",
        signature: { args: [{ type: "f32" }, { type: "f32" }, { type: "f32" }, { type: "f32" }], returns: "f32" },
        args: ["0x00000001", "0x00400000", "0x00000003", "0x00000005"],
        fp: { mxcsr: "0x9fc0" },
      },
    },
    {
      title: "mix_args on the main thread at a safe point (stack arguments)",
      input: {
        session_id: SESSION,
        address: "game_sim.exe!mix_args",
        signature: {
          args: [{ type: "i32" }, { type: "f32" }, { type: "f64" }, { type: "f32" }, { type: "i32" }, { type: "f64" }],
          returns: "f64",
        },
        args: [7, 1.5, 2.25, 3.125, 11, 0.5],
        thread_at: "game_sim.exe!physics_step",
      },
    },
  ],
});

export const CALL_TOOLS = [callFunction] as const satisfies readonly ToolContract[];
