import { z } from "zod";

import { addressRefSchema } from "../../domain/address/addressRef.js";
import { hexInputSchema, hexSchema } from "../../domain/hex.js";
import { evIdSchema, sha256Schema, stIdSchema, unkIdSchema } from "../../domain/ids.js";
import { jsonObjectSchema } from "../../domain/json.js";
import { fx } from "../effects.js";
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
import { addrExprSchema } from "../schemas/address.js";
import { recordedOutput } from "../schemas/envelope.js";
import { localPathSchema, sessionIdSchema } from "../schemas/primitives.js";
import { recordingIdSchema, scalarOutSchema } from "../schemas/shared.js";
import { defineTool, type ToolContract } from "../toolContract.js";

/**
 * Area emulation (WP14-EMU; DESIGN §6.2 K, S5 §8–§9 flattened per D-INT-9/15/29/31): emu_open (image, bea.dump/1
 * bundle, or a capture of a live session), emu_call (single / batch / sweep over the shared call model) and
 * diff_function (live, emulation and expected legs, bit-exact). Faults, budgets, unhandled imports and unsupported
 * instructions are STATUSES of results, never errors. Budgets (D-INT-10): emu_open input ≤ 4 KiB, emu_call and
 * diff_function ≤ 12 KiB, depth ≤ 10 — nested address positions therefore use a bare bounded string (the AddrExpr
 * grammar is still applied by the handler), and only top-level `address` fields carry the grammar summary.
 */
const MiB = 1024 * 1024;
const uint32 = z.number().int().min(0).max(4_294_967_295);
const count = z.number().int().min(0).max(1_000_000_000);
/** AddrExpr in nested positions (no description: ~250 B per field saved) */
const addr = z.string().min(2).max(600);
const snapName = z.string().regex(/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/u);
const hexBytesInput = z
  .string()
  .max(2 * MiB)
  .regex(/^(?:[0-9a-fA-F]{2})+$/u);
const timeoutMs = z.number().int().min(1000).max(110_000).default(60_000);
const exactlyOne = (values: readonly unknown[]): boolean => values.filter((v) => v !== undefined).length === 1;
const valueRefine = (w: {
  readonly hex?: string | undefined;
  readonly type?: string | undefined;
  readonly value?: unknown;
}) =>
  w.hex !== undefined ? w.type === undefined && w.value === undefined : w.type !== undefined && w.value !== undefined;
const VALUE_MESSAGE = 'Give hex, or type + value. Example: {"address":"game.exe+0x1a2b30","type":"f32","value":1.5}';

// ================================================================ emu_open
export const emuOpenInputSchema = z
  .strictObject({
    image_path: localPathSchema.optional(),
    dump_path: localPathSchema.optional(),
    live_session_id: sessionIdSchema.optional(),
    capture_modules: z.array(z.string().min(1).max(300)).min(1).max(16).optional(),
    capture_regions: z
      .array(
        z.strictObject({
          address: addr,
          size: z
            .number()
            .int()
            .min(1)
            .max(256 * MiB),
        }),
      )
      .max(64)
      .optional(),
    capture_thread_id: z.number().int().min(1).max(4_294_967_295).optional(),
    image_base: hexInputSchema.optional(),
    thread_id: z.number().int().min(1).max(4_294_967_295).optional(),
    primary_module: z.string().min(1).max(260).optional(),
    imports: z
      .strictObject({
        builtin: z.boolean().default(true),
        unhandled: z.enum(["stop", "return_zero"]).default("stop"),
        dump_policy: z.enum(["auto", "hle_known", "lle", "stop_all"]).default("auto"),
        overrides: z
          .array(
            z.strictObject({
              import: z
                .string()
                .max(300)
                .regex(/^(?:[^!\s]{1,255}!)?[^!\s]{1,255}$/u),
              action: z.enum(["return", "stop", "model"]),
              returns_type: z.enum(["void", "i32", "u32", "i64", "u64", "ptr", "f32", "f64"]).optional(),
              returns_value: scalarInputSchema.optional(),
              model: z
                .string()
                .regex(/^[a-z0-9_]{1,64}$/u)
                .optional(),
            }),
          )
          .max(256)
          .default([]),
      })
      .optional(),
    patches: z
      .array(
        z.strictObject({
          address: z.string().min(2).max(300),
          hex: hexBytesInput.optional(),
          type: z.enum(SCALAR_TYPES).optional(),
          value: scalarInputSchema.optional(),
        }),
      )
      .max(256)
      .optional(),
    memory: z
      .strictObject({
        heap_mb: z.number().int().min(1).max(256).default(64),
        scratch_mb: z.number().int().min(1).max(256).default(16),
        stack_kb: z.number().int().min(64).max(16_384).default(1024),
      })
      .optional(),
    fp: fpSchema.optional(),
    isa_guard: z.enum(["stop", "off"]).default("stop"),
    protections: z.enum(["sections", "rwx"]).default("sections"),
    fault_policy: z.enum(["stop", "map_zero"]).default("stop"),
    snapshots: z.enum(["cow", "manual"]).default("cow"),
    timeout_ms: timeoutMs,
    label: z.string().max(64).optional(),
  })
  .refine((x) => exactlyOne([x.image_path, x.dump_path, x.live_session_id]), {
    message:
      'Give exactly one of image_path, dump_path or live_session_id. Example: {"image_path":"C:\\\\lab\\\\mathlib.dll"}',
  })
  .refine((x) => x.fault_policy !== "map_zero" || x.snapshots === "manual", {
    message:
      'fault_policy "map_zero" requires snapshots "manual" (copy-on-write snapshots need a frozen memory layout).',
    path: ["snapshots"],
  })
  .refine((x) => x.image_path === undefined || (x.thread_id === undefined && x.primary_module === undefined), {
    message: "thread_id and primary_module apply to dump_path and live_session_id only.",
    path: ["thread_id"],
  })
  .refine((x) => x.image_path !== undefined || x.image_base === undefined, {
    message: "image_base applies to image_path only.",
    path: ["image_base"],
  })
  .refine(
    (x) =>
      x.live_session_id !== undefined ||
      (x.capture_modules === undefined && x.capture_regions === undefined && x.capture_thread_id === undefined),
    {
      message: "capture_modules, capture_regions and capture_thread_id apply to live_session_id only.",
      path: ["capture_modules"],
    },
  )
  .refine((x) => (x.patches ?? []).every(valueRefine), { message: VALUE_MESSAGE, path: ["patches"] })
  .refine(
    (x) =>
      (x.imports?.overrides ?? []).every((o) =>
        o.action === "return"
          ? o.returns_type !== undefined && (o.returns_type === "void") === (o.returns_value === undefined)
          : o.action === "model"
            ? o.model !== undefined
            : true,
      ),
    {
      message: 'Override "return" needs returns_type (+ returns_value unless void); "model" needs model.',
      path: ["imports", "overrides"],
    },
  );
export type EmuOpenInput = z.output<typeof emuOpenInputSchema>;

const deviationOut = z.strictObject({
  kind: z.string().max(64),
  note: z.string().max(500),
  count: count.exactOptional(),
});
const fpOut = z.strictObject({
  mxcsr: hexSchema,
  fpcw: hexSchema,
  source: z.enum(["explicit", "thread", "dump-thread", "windows-default"]),
});
const countRecord = z.record(z.string().max(64), count);

export const emuOpenOutputSchema = recordedOutput({
  session_id: sessionIdSchema,
  kind: z.literal("emulation"),
  source: z.enum(["image", "dump"]),
  bundle_id: z.string().max(80).nullable(),
  primary: z.strictObject({
    name: z.string().max(260),
    path: z.string().max(4096).nullable(),
    sha256: sha256Schema.nullable(),
    preferred_base: hexSchema.nullable(),
    mapped_base: hexSchema,
    static_base: hexSchema.nullable(),
    static_base_source: z.enum(["pe-header", "emulation"]).nullable(),
    relocated: z.boolean(),
    size: count,
    sections: count,
    exports: count,
    pdata_functions: count,
    tls_callbacks: count,
    delay_imports: count,
  }),
  modules: z
    .array(
      z.strictObject({
        name: z.string().max(260),
        mapped_base: hexSchema,
        size: count,
        captured: z.enum(["image", "full", "partial", "none"]),
        sha256: sha256Schema.nullable(),
      }),
    )
    .max(64),
  thread: z.strictObject({ tid: uint32, teb: hexSchema }).nullable(),
  imports: z.strictObject({
    total: count,
    models: countRecord,
    unhandled_sample: z.array(z.string().max(300)).max(50),
  }),
  isa: z.strictObject({
    cache: z.enum(["hit", "miss", "off"]),
    scan_ms: count,
    sites: countRecord,
    guarded: z.strictObject({ int3: count, hooks: count, unguarded: count }),
    functions_with_vex_sample: z.array(hexSchema).max(20),
  }),
  fp: fpOut,
  snapshots: z.enum(["cow", "manual"]),
  memory: z.strictObject({
    heap_mb: count,
    scratch_mb: count,
    stack_kb: count,
    mapped_mb: count,
    synthetic_base: hexSchema,
    limit_mb: count,
  }),
  loader_deviations: z.array(deviationOut).max(64),
  bridge: z.strictObject({
    pid: uint32.nullable(),
    child_pid: uint32.nullable(),
    version: z.string().max(32),
    protocol: z.literal("bea-emu/0.1"),
    generation: count,
    engines: z.record(z.string().max(16), z.string().max(32)),
    python: z.strictObject({
      source: z.string().max(16),
      version: z.string().max(32),
      pin: z.enum(["exact", "compatible"]),
    }),
  }),
  capture: z
    .strictObject({
      bundle_path: z.string().max(4096),
      evidence_id: evIdSchema,
      regions: count,
      modules: count,
      threads: count,
    })
    .nullable(),
  baseline_state: z.string().max(80),
  timings_ms: z.strictObject({
    bridge_start: count,
    load: count,
    isa: count,
    bind: count,
    snapshot: count,
    total: count,
  }),
});
export type EmuOpenOutput = z.output<typeof emuOpenOutputSchema>;

// ================================================================ emu_call
/** (kept outside the export statement: the boundary verifier reads `from "…"` text as an import) */
const STATE_FROM_PATH = ["state", "from"];

export const emuCallInputSchema = z
  .strictObject({
    session_id: sessionIdSchema,
    address: addrExprSchema.optional(),
    signature: signatureSchema,
    buffers: z.array(bufferSchema).max(64).default([]),
    args: z.array(nullableScalarInputSchema).max(32).optional(),
    fields: z.record(columnNameSchema, scalarInputSchema).optional(),
    vectors: vectorsSchema.optional(),
    generate: generateSchema.optional(),
    sweep: z
      .strictObject({
        module: z.string().min(1).max(260).optional(),
        rva_start: hexInputSchema.optional(),
        rva_end: hexInputSchema.optional(),
        targets: z.array(addr).min(1).max(20_000).optional(),
        match: z
          .strictObject({
            returns: z.enum(["f32", "f64"]),
            args: z.array(columnNameSchema).min(1).max(2),
            known: z.enum(["unary", "binary", "all"]).default("all"),
            tolerance_ulp: z.number().int().min(0).max(64).default(1),
          })
          .optional(),
        offset: z.number().int().min(0).max(20_000).default(0),
        limit: z.number().int().min(1).max(20_000).default(5000),
      })
      .refine((s) => (s.targets !== undefined) !== (s.rva_start !== undefined && s.rva_end !== undefined), {
        message: "Give targets, or rva_start and rva_end.",
        path: ["targets"],
      })
      .optional(),
    state: z
      .strictObject({
        from: snapName.default("baseline"),
        writes: z
          .array(
            z
              .strictObject({
                address: addr,
                hex: hexBytesInput.optional(),
                type: z.enum(SCALAR_TYPES).optional(),
                value: scalarInputSchema.optional(),
              })
              .refine(valueRefine, VALUE_MESSAGE),
          )
          .max(256)
          .default([]),
        save_as: snapName.optional(),
        drop: z.array(snapName).max(16).default([]),
      })
      .optional(),
    isolation: z.enum(["snapshot", "chain"]).default("snapshot"),
    budget: z
      .strictObject({
        max_instructions: z.number().int().min(0).max(10_000_000_000).default(1_000_000),
        timeout_ms_per_call: z.number().int().min(0).max(110_000).default(0),
      })
      .optional(),
    fp: fpSchema.optional(),
    trace: z
      .strictObject({
        imports: z.enum(["off", "counts", "full"]).optional(),
        blocks: z.boolean().default(false),
        coverage: z.boolean().default(false),
        count_instructions: z.boolean().default(false),
        memory: z.enum(["off", "reads", "writes", "all"]).default("off"),
        instructions: z.boolean().default(false),
        disassemble: z.boolean().default(false),
        max_events: z.number().int().min(1).max(100_000).default(10_000),
      })
      .optional(),
    fault_policy: z.enum(["stop", "map_zero"]).optional(),
    stop_on_fault: z.boolean().default(false),
    vector_offset: z.number().int().min(0).max(1_000_000).default(0),
    inline_limit: z.number().int().min(0).max(256).default(64),
    detail: z.enum(["summary", "complete"]).default("summary"),
    timeout_ms: timeoutMs,
  })
  .superRefine((input, ctx) => callInputBudget(input, ctx as unknown as Parameters<typeof callInputBudget>[1]))
  .refine(
    (x) =>
      // in sweep mode `vectors` are the sweep's probe inputs, not a batch
      [
        x.args !== undefined || x.fields !== undefined,
        x.vectors !== undefined && x.sweep === undefined,
        x.generate !== undefined,
        x.sweep !== undefined,
      ].filter(Boolean).length <= 1,
    {
      message:
        "Use one mode: args/fields (single call), vectors or generate (batch), or sweep (vectors are then its probe inputs).",
    },
  )
  .refine((x) => x.sweep !== undefined || x.address !== undefined, {
    message: 'address is required except in sweep mode. Example: "mathlib.dll!mf_spring"',
    path: ["address"],
  })
  .refine(
    (x) => x.sweep === undefined || (x.vectors?.count ?? Object.values(x.vectors?.columns ?? {})[0]?.length ?? 1) <= 16,
    {
      message: "Sweep probe vectors are limited to 16.",
      path: ["vectors"],
    },
  )
  .refine((x) => x.isolation !== "chain" || x.vector_offset === 0 || x.state?.from === "current", {
    message: 'A chained continuation must start from the chain\'s end: set state.from to "current".',
    path: STATE_FROM_PATH,
  });
export type EmuCallInput = z.output<typeof emuCallInputSchema>;

const CALL_STATUSES = [
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
const callStatusSchema = z.enum(CALL_STATUSES);
const attributionSchema = z.enum(["target", "harness"]);
const typedValueSchema = z.strictObject({ type: z.enum(SCALAR_TYPES), bits: hexSchema, value: scalarOutSchema });
const cellBits = z.union([hexSchema, z.array(hexSchema).max(65_536)]);
/** inline rows show at most 16 elements of an array cell (the row stream keeps them all) */
const rowBits = z.union([hexSchema, z.array(hexSchema).max(16)]);
const wideHex = z.string().regex(/^0x[0-9a-f]{1,32}$/u);
/** a batch row without its out fields (previews; the emu-batch stream rows carry `f`) */
const previewRowSchema = z.strictObject({
  i: count,
  s: z.string().max(8),
  a: z.enum(["t", "h"]).exactOptional(),
  c: z.string().max(64).exactOptional(),
  r: hexSchema.exactOptional(),
  n: count.exactOptional(),
});
const heapEventSchema = z.strictObject({
  type: z.literal("heap"),
  kind: z.string().max(32),
  ptr: hexSchema.nullable(),
  size: count.nullable(),
});

export const emuCallOutputSchema = recordedOutput({
  mode: z.enum(["single", "batch", "sweep"]),
  target: addressRefSchema.nullable(),
  fp: fpOut,
  call: z
    .strictObject({
      status: callStatusSchema,
      attribution: attributionSchema.nullable(),
      ret: typedValueSchema.nullable(),
      outputs: z.record(z.string().max(130), z.union([typedValueSchema, z.array(typedValueSchema).max(256)])),
      out_buffers: z.record(
        z.string().max(64),
        z.strictObject({
          address: hexSchema.nullable(),
          bytes: count,
          hex: z.string().max(8192),
          truncated: z.boolean(),
        }),
      ),
      raw: z.strictObject({ rax: hexSchema, xmm0: wideHex, mxcsr: hexSchema, fpcw: hexSchema }),
      stop: jsonObjectSchema.nullable(),
      metrics: z.strictObject({ wall_us: count, instructions: count.nullable(), blocks: count.nullable() }),
      trace: jsonObjectSchema.nullable(),
      events: z.array(heapEventSchema).max(16),
      deviations: z.array(deviationOut).max(64),
      deterministic: z.boolean(),
    })
    .exactOptional(),
  batch: z
    .strictObject({
      offset: count,
      vectors: count,
      completed: count,
      returned: count,
      by_status: z.partialRecord(callStatusSchema, count),
      by_attribution: z.strictObject({ target: count, harness: count }),
      elapsed_ms: count,
      calls_per_second: z.number().nullable(),
      isolation: z.enum(["snapshot", "chain"]),
      path: z.enum(["fast", "medium", "full"]),
      deterministic: z.boolean(),
      deadline_reached: z.boolean(),
      cancelled: z.boolean(),
      continuation: z.strictObject({ vector_offset: count }).nullable(),
      columns: z
        .record(
          z.string().max(130),
          z.strictObject({
            bits: z.array(cellBits).max(256),
            value: z.array(z.union([scalarOutSchema, z.array(scalarOutSchema).max(65_536)])).max(256),
          }),
        )
        .nullable(),
      status: z.array(callStatusSchema).max(256).nullable(),
      /** first and last rows (≤ 8 each) when the rows went to the stream */
      preview: z.array(previewRowSchema).max(16).nullable(),
      ret_stats: z
        .strictObject({
          min_bits: hexSchema.nullable(),
          max_bits: hexSchema.nullable(),
          nan: count,
          inf: count,
          distinct_bits: count,
        })
        .nullable(),
      faults: z
        .array(
          z.strictObject({
            index: count,
            status: callStatusSchema,
            attribution: attributionSchema,
            cause: z.string().max(64),
            pc_rva: hexSchema.nullable(),
          }),
        )
        .max(32),
      /** full stop records of the first faults (S5 §3.14: the bridge details the first 8; 4 are delivered) */
      fault_details: z.array(jsonObjectSchema).max(4),
      stream_id: stIdSchema.nullable(),
      imports: z.record(z.string().max(300), z.strictObject({ calls: count, model: z.string().max(64) })),
      deviations: z
        .array(z.strictObject({ kind: z.string().max(64), vectors: count, note: z.string().max(500) }))
        .max(64),
    })
    .exactOptional(),
  sweep: z
    .strictObject({
      module: z.string().max(260),
      functions: count,
      completed: count,
      by_outcome_profile: countRecord,
      matched: z
        .array(z.strictObject({ rva: hexSchema, va: hexSchema, matches: z.array(z.string().max(32)).max(8) }))
        .max(200),
      next_offset: count.nullable(),
      deadline_reached: z.boolean(),
      stream_id: stIdSchema.nullable(),
    })
    .exactOptional(),
  state: z
    .strictObject({
      from: z.string().max(64),
      from_digest: z.string().max(80),
      after_digest: z.string().max(80),
      saved_as: z.string().max(64).nullable(),
    })
    .nullable(),
  coverage_blob: z.strictObject({ sha256: sha256Schema, bytes: count, blocks: count }).nullable(),
});
export type EmuCallOutput = z.output<typeof emuCallOutputSchema>;

// ================================================================ diff_function
const LEGS = ["live", "emulation", "expected"] as const;
export const diffFunctionInputSchema = z
  .strictObject({
    emu_session_id: sessionIdSchema.optional(),
    live_session_id: sessionIdSchema.optional(),
    address: addrExprSchema,
    signature: signatureSchema,
    buffers: z.array(bufferSchema).max(64).default([]),
    vectors: vectorsSchema.optional(),
    generate: generateSchema.optional(),
    from_recording: z
      .strictObject({
        recording_id: recordingIdSchema,
        args: z.array(z.string().min(1).max(64)).min(1).max(32),
        ret: z.string().min(1).max(64).optional(),
        max_events: z.number().int().min(1).max(100_000).default(10_000),
      })
      .describe(
        "Replay a hook recording's captured args as vectors. Scalar-only signatures: a buffer_ptr/buffer_byval slot is refused (a recording cannot reproduce pointed-to memory); for pointer functions give vectors with buffers.",
      )
      .optional(),
    expected: z
      .strictObject({
        columns: z.record(columnNameSchema, z.array(nullableScalarInputSchema).max(CALL_INPUT_LIMITS.maxVectorCells)),
      })
      .optional(),
    legs: z.array(z.enum(LEGS)).min(2).max(3).optional(),
    compare: z
      .strictObject({
        columns: z.array(columnNameSchema).max(64).optional(),
        nan: z.enum(["bits", "any_nan"]).default("bits"),
        tolerance_ulp: z
          .number()
          .int()
          .min(0)
          .max(2 ** 30)
          .optional(),
        tolerance_abs: z.number().min(0).optional(),
        tolerance_rel: z.number().min(0).optional(),
        inconclusive: z.enum(["count", "exclude"]).default("count"),
        compare_fault_sites: z.boolean().default(true),
      })
      .optional(),
    live: z
      .strictObject({
        thread_id: z.number().int().min(1).max(4_294_967_295).optional(),
        chunk: z.number().int().min(1).max(10_000).default(1000),
      })
      .optional(),
    emulation: z
      .strictObject({
        isolation: z.enum(["snapshot", "chain"]).default("snapshot"),
        state_from: snapName.default("baseline"),
        max_instructions: z.number().int().min(0).max(10_000_000_000).default(1_000_000),
      })
      .optional(),
    fp: fpSchema.optional(),
    allow_image_mismatch: z.boolean().default(false),
    record_unknown: z.boolean().default(true),
    vector_offset: z.number().int().min(0).max(1_000_000).default(0),
    inline_limit: z.number().int().min(0).max(256).default(64),
    timeout_ms: timeoutMs,
  })
  .superRefine((input, ctx) => callInputBudget(input, ctx as unknown as Parameters<typeof callInputBudget>[1]))
  .refine((x) => exactlyOne([x.vectors, x.generate, x.from_recording]), {
    message:
      'Give exactly one input source: vectors, generate or from_recording. Example: {"vectors":{"columns":{"arg0":[1,2]}}}',
  })
  .refine(
    (x) =>
      [
        x.live_session_id !== undefined,
        x.emu_session_id !== undefined,
        x.expected !== undefined || x.from_recording?.ret !== undefined,
      ].filter(Boolean).length >= 2,
    {
      message:
        "Need at least two legs: live_session_id (live), emu_session_id (emulation), expected or from_recording.ret (expected).",
    },
  );
export type DiffFunctionInput = z.output<typeof diffFunctionInputSchema>;

const VERDICTS = ["equivalent-on-tested-inputs", "differ", "unknown"] as const;
/** inline diff rows are capped here whatever inline_limit says (bounded results, S2 §8) */
export const DIFF_INLINE_ROWS = 64;
const columnBitsList = z.array(z.strictObject({ column: z.string().max(130), bits: rowBits })).max(16);
const legSchema = z.enum(LEGS);
const columnStatsSchema = z.strictObject({
  column: z.string().max(130),
  type: z.string().max(16),
  compared: count,
  exact_equal: count,
  differ: count,
  max_ulp: z.number().nullable(),
  p50_ulp: z.number().nullable(),
  p99_ulp: z.number().nullable(),
  max_abs: z.number().nullable(),
  max_rel: z.number().nullable(),
  nan_payload: count,
  nan_vs_number: count,
  signed_zero: count,
  inf_mismatch: count,
  int_max_delta: z.string().max(24).nullable(),
});

export const diffFunctionOutputSchema = recordedOutput({
  verdict: z.enum(VERDICTS),
  verdict_basis: z.literal("bit-exact"),
  fp: fpOut,
  target: z.partialRecord(z.enum(["live", "emulation"]), addressRefSchema),
  legs: z
    .array(
      z.strictObject({
        leg: legSchema,
        completed: count,
        by_status: z.partialRecord(callStatusSchema, count),
        evidence_id: evIdSchema.nullable(),
        effect_id: z.string().max(80).exactOptional(),
        lost_target: z.boolean().exactOptional(),
      }),
    )
    .max(3),
  vectors: z.strictObject({
    count,
    offset: count,
    digest: z.string().max(80),
    source: z.enum(["inline", "generated", "recording"]),
    continuation: z.strictObject({ vector_offset: count }).nullable(),
  }),
  pairs: z
    .array(
      z.strictObject({
        a: legSchema,
        b: legSchema,
        verdict: z.enum(VERDICTS),
        compared: count,
        equal: count,
        differ: count,
        inconclusive: count,
        inconclusive_reasons: countRecord,
        outcome_mismatches: count,
        columns: z.array(columnStatsSchema).max(64),
        tolerance: z.strictObject({ within: count, outside: count }).exactOptional(),
      }),
    )
    .max(3),
  worst: z
    .array(
      z.strictObject({
        index: count,
        column: z.string().max(130),
        reason: z.enum(["outcome_class", "fault_site", "value"]),
        inputs: columnBitsList,
        values: z
          .array(z.strictObject({ leg: legSchema, status: callStatusSchema.nullable(), bits: rowBits.nullable() }))
          .max(3),
        ulp: z.number().nullable(),
      }),
    )
    .max(10),
  hints: z.array(z.strictObject({ code: z.string().max(32), message: z.string().max(300) })).max(16),
  unknown_id: unkIdSchema.nullable(),
  /**
   * ≤ 64 compact rows, one per vector (its inputs are the request's own; worst[] repeats them for the interesting
   * vectors). More vectors, or a smaller inline_limit: a `diff` row stream with inputs and per-leg fields.
   */
  rows: z
    .array(
      z.strictObject({
        i: count,
        legs: z.array(z.strictObject({ leg: legSchema, s: callStatusSchema.nullable(), r: rowBits.nullable() })).max(3),
        pairs: z
          .array(
            z.strictObject({
              pair: z.enum(["live~emulation", "live~expected", "emulation~expected"]),
              r: z.enum(["eq", "df", "ic"]),
              u: z.number().nullable(),
              why: z.string().max(64).nullable(),
            }),
          )
          .max(3),
      }),
    )
    .max(DIFF_INLINE_ROWS)
    .nullable(),
  stream_id: stIdSchema.nullable(),
});
export type DiffFunctionOutput = z.output<typeof diffFunctionOutputSchema>;

// ================================================================ contracts
const EMU = "1b4e28ba-2fa1-41d2-883f-0016d3cca427";
const LIVE = "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b";

export const emuOpen = defineTool({
  name: "emu_open",
  area: "emulation",
  phase: "P2",
  title: "Open Emulator",
  description:
    "Open a Unicorn emulation session with no target effects: from a PE64 file on disk, a bea.dump/1 bundle (dump_memory), or a fresh capture of a live session (live_session_id: module images with runtime .data and restored original code, chosen regions, a thread's TEB). Runs the ISA guard (VEX/AVX stop, x87 flagged), binds HLE import models and takes the baseline. Returns session_id, image identity, unhandled imports and loader deviations. Needs the emulator Python (bea setup --emulator).",
  inputSchema: emuOpenInputSchema,
  outputSchema: emuOpenOutputSchema,
  effects: fx({ readsTargetMemory: true, mutatesSession: true, idempotent: false }),
  cli: { tier: "scenario-target", reason: "creates the session that scenario steps run in" },
  sessionKinds: ["none"],
  evidence: { predicate: "bea.emu.session", recorded: "always", identityExclude: ["label"] },
  errors: [
    "capability_unavailable",
    "unsupported_target",
    "file_operation_failed",
    "evidence_integrity_mismatch",
    "session_not_found",
    "target_exited",
    "configuration_invalid",
  ],
  maxBlockingMs: 120_000,
  maxInputBytes: 2 * MiB,
  examples: [
    { title: "a DLL on disk", input: { image_path: "C:\\lab\\mathlib.dll" } },
    {
      title: "the live game's state with the car object, CRT sqrtf exact",
      input: {
        live_session_id: LIVE,
        capture_regions: [{ address: "0x1f3a5c40", size: 4096 }],
        imports: { overrides: [{ import: "my_sqrtf", action: "model", model: "sqrtf" }] },
      },
    },
  ],
});

export const emuCall = defineTool({
  name: "emu_call",
  area: "emulation",
  phase: "P2",
  title: "Emulate Call",
  description:
    "Emulate a call in an emulation session with the same typed call model as call_function (signature, buffers, args or vector columns, seeded generators), singly, as a batch (vector_offset continuation), or as a sweep of functions against known math. Deterministic instruction budget, snapshot or chained state, named snapshots, opt-in traces and coverage. Faults, budget stops, unhandled imports and unsupported instructions are result statuses. Results are emulator observations with deviations, never observations of the real process.",
  inputSchema: emuCallInputSchema,
  outputSchema: emuCallOutputSchema,
  effects: fx({ mutatesSession: true, idempotent: false }),
  cli: { tier: "emu-oneshot", command: "emulate", positional: [] },
  sessionKinds: ["emulation"],
  evidence: { predicate: "bea.emu.run", recorded: "always", identityExclude: ["inline_limit"] },
  errors: ["capability_unavailable", "address_unmapped", "memory_access_failed", "session_not_found"],
  maxBlockingMs: 120_000,
  maxInputBytes: CALL_INPUT_LIMITS.maxInputBytes,
  examples: [
    {
      title: "one call of a float function",
      input: {
        session_id: EMU,
        address: "mathlib.dll!mf_spring",
        signature: { args: [{ type: "f32" }, { type: "f32" }, { type: "f32" }, { type: "f32" }], returns: "f32" },
        args: [0.25, -1.5, 40, 2],
      },
    },
    {
      title: "physics_step over generated dt values with coverage",
      input: {
        session_id: EMU,
        address: "game_sim.exe!physics_step",
        signature: {
          args: [
            { type: "buffer_ptr", buffer: "car" },
            { type: "f32", name: "dt" },
          ],
          returns: "f32",
        },
        buffers: [
          { name: "car", size: 128, out: true, fields: [{ name: "speed", offset: 8, type: "f32", default: "10" }] },
        ],
        generate: { seed: 7, count: 1000, columns: { dt: { dist: "uniform", min: 0.001, max: 0.05 } } },
        trace: { coverage: true },
      },
    },
  ],
});

export const diffFunction = defineTool({
  name: "diff_function",
  area: "emulation",
  phase: "P2",
  title: "Diff Function",
  description:
    "Run the same input vectors through the live in-process oracle, the emulator and/or caller-given expected values (or a hook recording), and compare returns and output buffers bit-exactly with ulp statistics. The verdict is only equivalent-on-tested-inputs, differ or unknown; a non-equivalence auto-records an unknown with probes. The live leg executes target code (owned targets; attached ones need the call_attached gate); omit live_session_id for a sandboxed comparison.",
  inputSchema: diffFunctionInputSchema,
  outputSchema: diffFunctionOutputSchema,
  effects: fx({
    readsTargetMemory: true,
    writesTargetMemory: true,
    executesTargetCode: true,
    mutatesSession: true,
    idempotent: false,
  }),
  gate: { id: "call_attached", scope: "attached-targets" },
  cli: {
    tier: "scenario",
    reason: "needs two sessions; a scenario creates both with session-creating steps (spawn_process, emu_open)",
  },
  sessionKinds: ["live", "emulation"],
  evidence: { predicate: "bea.diff", recorded: "always", identityExclude: ["inline_limit", "record_unknown"] },
  errors: ["capability_unavailable", "session_not_found", "target_exited", "address_unmapped", "memory_access_failed"],
  maxBlockingMs: 120_000,
  maxInputBytes: CALL_INPUT_LIMITS.maxInputBytes,
  examples: [
    {
      title: "live vs emulator on generated vectors",
      input: {
        live_session_id: LIVE,
        emu_session_id: EMU,
        address: "live_fixture.exe!four_floats",
        signature: { args: [{ type: "f32" }, { type: "f32" }, { type: "f32" }, { type: "f32" }], returns: "f32" },
        generate: {
          seed: 1,
          count: 256,
          columns: { arg0: { dist: "edge" }, arg1: { dist: "uniform", min: -2, max: 2 } },
        },
      },
    },
    {
      title: "emulator vs expected values",
      input: {
        emu_session_id: EMU,
        address: "mathlib.dll!mf_lerp",
        signature: { args: [{ type: "f32" }, { type: "f32" }, { type: "f32" }], returns: "f32" },
        vectors: { columns: { arg0: [0, 1], arg1: [10, 10], arg2: [0.5, 0.25] } },
        expected: { columns: { ret: [5, 3.25] } },
      },
    },
  ],
});

export const EMULATION_TOOLS = [emuOpen, emuCall, diffFunction] as const satisfies readonly ToolContract[];
