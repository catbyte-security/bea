import { z } from "zod";

import { addrExprSchema } from "./address.js";

/**
 * Shared call model INPUT fragments (S5 §7.1) used by call_function, emu_call and diff_function — flattened
 * (DESIGN D-INT-9) so every tool input stays at depth ≤ 10 (REA metric):
 * - scalars are `number | string | boolean`; a "0x…" string is ALWAYS the raw bit pattern of the declared type
 *   (two's complement for signed ints, IEEE bits for floats); floats also take "NaN", "Infinity", "-Infinity", "-0";
 * - unions of objects became one object + refine; array cells and array defaults are comma-separated strings;
 * - buffer init is hex, a fill byte, or a one-shot copy from a live/emulated address (base64 and the `rows` vector
 *   shorthand are dropped, S5 trim order);
 * - doubles are plain z.number() (zod 4 rejects NaN/Infinity); the bound invariant applies to integers only (CI-B1).
 */
export const SCALAR_TYPES = [
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
] as const;
export const ARRAY_TYPES = [
  "i8[]",
  "u8[]",
  "i16[]",
  "u16[]",
  "i32[]",
  "u32[]",
  "i64[]",
  "u64[]",
  "f32[]",
  "f64[]",
] as const;
/** @public */
export type ScalarType = (typeof SCALAR_TYPES)[number];
/** @public */
export type ArrayType = (typeof ARRAY_TYPES)[number];

/**
 * CT-B3: aggregate bounds every call-model tool enforces with `callInputBudget` (root superRefine), so a schema-valid
 * request stays far below the stdio read buffer and the agent's materialization stays bounded. Larger batches go
 * through `generate`, `from_recording`, `vector_offset` continuation, or one CLI --input file per chunk.
 */
export const CALL_INPUT_LIMITS = {
  /** Σ cells over vectors.columns and expected.columns */
  maxVectorCells: 200_000,
  /** Σ init_hex characters over buffers (8 MiB of hex = 4 MiB of bytes) */
  maxInitHexChars: 8 * 1024 * 1024,
  /** Σ fields[].default characters over buffers */
  maxFieldDefaultChars: 1024 * 1024,
  /** ToolContract.maxInputBytes of call_function, emu_call and diff_function */
  maxInputBytes: 48 * 1024 * 1024,
} as const;

export const identSchema = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,63}$/u);
export const columnNameSchema = z
  .string()
  .regex(/^(?:arg[0-9]{1,2}|[A-Za-z_][A-Za-z0-9_]{0,63}(?:\.[A-Za-z_][A-Za-z0-9_]{0,63})?|ret)$/u);
export const scalarInputSchema = z.union([z.number(), z.string().max(300), z.boolean()]);
/** CI-B2: one anyOf level for every "(scalar|null)" position (args, expected columns) instead of .nullable() (−2 depth). */
export const nullableScalarInputSchema = z.union([z.number(), z.string().max(300), z.boolean(), z.null()]);
const hexBytes = z
  .string()
  .max(2 * 1024 * 1024)
  .regex(/^(?:[0-9a-fA-F]{2})*$/u);
const hex16 = z.string().regex(/^0x[0-9a-fA-F]{1,4}$/u);

export const argSlotSchema = z
  .strictObject({
    type: z.enum([...SCALAR_TYPES, "buffer_ptr", "buffer_byval"]),
    name: identSchema.optional(),
    default: scalarInputSchema.optional(),
    buffer: identSchema.optional(),
    offset: z
      .number()
      .int()
      .min(0)
      .max(16 * 1024 * 1024)
      .optional(),
  })
  .refine((s) => (s.type === "buffer_ptr" || s.type === "buffer_byval") === (s.buffer !== undefined), {
    message: "buffer_ptr and buffer_byval need buffer (a buffers[].name); scalar slots must not set it.",
    path: ["buffer"],
  });

export const returnSchema = z.union([
  z.enum(["void", ...SCALAR_TYPES]),
  z.strictObject({
    type: z.literal("struct"),
    size: z.number().int().min(1).max(4096),
    buffer: identSchema.optional(),
  }),
]);

export const fieldSchema = z
  .strictObject({
    name: identSchema,
    offset: z
      .number()
      .int()
      .min(0)
      .max(16 * 1024 * 1024 - 1),
    type: z.enum([...SCALAR_TYPES, ...ARRAY_TYPES, "ptr_to"]),
    count: z.number().int().min(1).max(65536).optional(), // arrays
    default: z.string().max(65536).optional(), // scalar literal, or comma-separated elements for arrays
    buffer: identSchema.optional(), // ptr_to
    plus: z
      .number()
      .int()
      .min(-(2 ** 31))
      .max(2 ** 31 - 1)
      .optional(), // ptr_to
    codec_kind: z.enum(["xor", "add", "mul"]).optional(), // stored = encode(logical); mul keys must be odd
    codec_key: z
      .string()
      .regex(/^0x[0-9a-fA-F]{1,16}$/u)
      .optional(),
  })
  .refine((f) => (f.type === "ptr_to") === (f.buffer !== undefined), {
    message: "ptr_to fields need buffer; others must not set it.",
    path: ["buffer"],
  })
  .refine((f) => f.type.endsWith("[]") === (f.count !== undefined), {
    message: "array fields need count; scalar fields must not set it.",
    path: ["count"],
  })
  .refine((f) => (f.codec_kind === undefined) === (f.codec_key === undefined), {
    message: "codec_kind and codec_key go together.",
    path: ["codec_key"],
  });

export const bufferSchema = z
  .strictObject({
    name: identSchema,
    size: z
      .number()
      .int()
      .min(1)
      .max(16 * 1024 * 1024),
    align: z.number().int().min(1).max(4096).default(16), // power of two (refine)
    placement: z.enum(["scratch", "heap"]).default("scratch"),
    init_hex: hexBytes.optional(),
    init_fill: z.number().int().min(0).max(255).optional(),
    /**
     * CI-I2 (restores S6 `from`): copy `size` bytes from this address ONCE per call (diff_function: once per diff,
     * from the live leg when present, else from the emulator) and use them as the template for every vector and leg;
     * the target's own object is never passed. Live sessions read through the agent (BEA guard pages suspended,
     * CT-I5); emulation sessions through mem.read.
     */
    init_from: addrExprSchema.optional(),
    fields: z.array(fieldSchema).max(256).default([]),
    out: z.boolean().default(false),
  })
  .refine((b) => (b.align & (b.align - 1)) === 0, {
    message: "align must be a power of two (1..4096).",
    path: ["align"],
  })
  .refine((b) => [b.init_hex, b.init_fill, b.init_from].filter((v) => v !== undefined).length <= 1, {
    message: "Give at most one of init_hex, init_fill or init_from.",
    path: ["init_from"],
  });

export const signatureSchema = z.strictObject({
  args: z.array(argSlotSchema).max(32),
  returns: returnSchema,
  variadic: z.boolean().default(false),
  convention: z
    .enum(["c", "msvc_method"])
    .default("c")
    .describe(
      "msvc_method: an MSVC/clang-cl C++ instance method: args[0] is `this` (RCX), a struct return comes back through a hidden pointer in RDX whatever its size. c (default): free functions and GCC/MinGW methods (hidden pointer first, `this` second).",
    ),
});

/** Column vectors: column name -> one cell per vector; array cells are comma-separated strings. */
export const vectorsSchema = z
  .strictObject({
    count: z.number().int().min(1).max(1_000_000).optional(),
    columns: z.record(columnNameSchema, z.array(scalarInputSchema).max(CALL_INPUT_LIMITS.maxVectorCells)).optional(),
  })
  .refine((v) => v.columns !== undefined || v.count !== undefined, "Give columns, or count (for all-default vectors).");

/** Seeded generators (S5 §7.6), flattened: dist + its parameters. */
export const distributionSchema = z
  .strictObject({
    dist: z.enum(["uniform", "log_uniform", "grid", "edge", "bits_uniform", "constant"]),
    min: z.number().optional(),
    max: z.number().optional(),
    signs: z.enum(["positive", "both"]).optional(),
    values: z.string().max(65536).optional(), // grid: comma-separated
    value: scalarInputSchema.optional(), // constant
  })
  .refine((d) => !["uniform", "log_uniform"].includes(d.dist) || (d.min !== undefined && d.max !== undefined), {
    message: "uniform/log_uniform need min and max.",
    path: ["min"],
  })
  .refine((d) => d.dist !== "grid" || d.values !== undefined, {
    message: "grid needs values (comma-separated).",
    path: ["values"],
  })
  .refine((d) => d.dist !== "constant" || d.value !== undefined, { message: "constant needs value.", path: ["value"] });

export const generateSchema = z.strictObject({
  seed: z.number().int().min(0).max(0xffffffff),
  count: z.number().int().min(1).max(1_000_000).optional(),
  columns: z.record(columnNameSchema, distributionSchema),
  grid: z.enum(["cartesian", "zip"]).default("cartesian"),
});

/**
 * CT-I9: the FP environment of a call. `auto` (default) = the environment of a KNOWN target thread — `thread_id`
 * below, else the call's thread_id, else the hook thread of from_recording, else the dump's primary thread — read
 * with captureThreadState (MXCSR status bits 0..5 cleared), and otherwise "windows-default" (MXCSR 0x1F80, FPCW
 * 0x027F). Explicit mxcsr/fpcw override field by field. diff_function resolves ONCE and uses the result for every
 * leg; outputs report `fp{mxcsr, fpcw, source}`.
 */
export const FP_SOURCES = ["auto", "thread", "windows-default"] as const;
export const fpSchema = z.strictObject({
  source: z.enum(FP_SOURCES).default("auto"),
  thread_id: z.number().int().min(1).max(0xffffffff).optional(),
  mxcsr: hex16.optional(),
  fpcw: hex16.optional(),
});

/** Structural view of a call-model input for the aggregate budget (CT-B3). */
export interface CallBudgetInput {
  readonly buffers?:
    | readonly {
        readonly init_hex?: string | undefined;
        readonly fields?: readonly { readonly default?: string | undefined }[] | undefined;
      }[]
    | undefined;
  readonly vectors?: { readonly columns?: Readonly<Record<string, readonly unknown[]>> | undefined } | undefined;
  readonly expected?: { readonly columns?: Readonly<Record<string, readonly unknown[]>> | undefined } | undefined;
}

/** Root superRefine of call_function, emu_call and diff_function (`.superRefine(callInputBudget)`). */
export const callInputBudget = (input: CallBudgetInput, ctx: z.core.$RefinementCtx<CallBudgetInput>): void => {
  const cells = (columns: Readonly<Record<string, readonly unknown[]>> | undefined): number =>
    Object.values(columns ?? {}).reduce((sum, column) => sum + column.length, 0);
  const vectorCells = cells(input.vectors?.columns) + cells(input.expected?.columns);
  if (vectorCells > CALL_INPUT_LIMITS.maxVectorCells)
    ctx.addIssue({
      code: "custom",
      path: ["vectors", "columns"],
      message: `At most ${String(CALL_INPUT_LIMITS.maxVectorCells)} vector cells per request (got ${String(vectorCells)}); continue with vector_offset or use generate.`,
    });
  const buffers = input.buffers ?? [];
  const hexChars = buffers.reduce((sum, buffer) => sum + (buffer.init_hex?.length ?? 0), 0);
  if (hexChars > CALL_INPUT_LIMITS.maxInitHexChars)
    ctx.addIssue({
      code: "custom",
      path: ["buffers"],
      message: `Σ init_hex is at most ${String(CALL_INPUT_LIMITS.maxInitHexChars)} hex characters (got ${String(hexChars)}); use init_from or init_fill.`,
    });
  const defaultChars = buffers.reduce(
    (sum, buffer) => sum + (buffer.fields ?? []).reduce((inner, field) => inner + (field.default?.length ?? 0), 0),
    0,
  );
  if (defaultChars > CALL_INPUT_LIMITS.maxFieldDefaultChars)
    ctx.addIssue({
      code: "custom",
      path: ["buffers"],
      message: `Σ fields[].default is at most ${String(CALL_INPUT_LIMITS.maxFieldDefaultChars)} characters (got ${String(defaultChars)}).`,
    });
};
