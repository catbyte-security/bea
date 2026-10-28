import { z } from "zod";

import { addressRefSchema, locSchema } from "../../domain/address/addressRef.js";
import { hexSchema } from "../../domain/hex.js";
import { jsonObjectSchema } from "../../domain/json.js";
import { addrExprSchema } from "./address.js";

/**
 * Cross-area tool fragments (S6 §5, integrated). WP0-owned so no area WP depends on another for them.
 * Output fragments are lean (descriptions stripped at advertisement anyway).
 */
const uint32 = z.number().int().min(0).max(4_294_967_295);

// ---------------------------------------------------------------- ids and handles (D-INT-4)
export const recordingIdSchema = z.string().regex(/^rec_[0-9a-f]{8}$/u);
export const scanIdSchema = z.string().regex(/^scan_[0-9a-f]{8}$/u);
/** stop_instrumentation / wait ids: rec_, scan_ or fx_ */
export const handleOrEffectSchema = z.string().regex(/^(?:rec_[0-9a-f]{8}|scan_[0-9a-f]{8}|fx_[0-9a-f]{64})$/u);

// ---------------------------------------------------------------- value encoding (S6 §2.3)
export const VALUE_TYPES = [
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
  "bytes",
] as const;
export const valueTypeSchema = z.enum(VALUE_TYPES);
export const RETURN_TYPES = [
  "void",
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
export const returnTypeSchema = z.enum(RETURN_TYPES);
/** output scalar: ints ≤ 32 bit numbers, 64-bit decimal strings, floats shortest round-trip numbers or "NaN"/"Infinity"/"-Infinity" */
export const scalarOutSchema = z.union([z.number(), z.string().max(4096), z.boolean(), z.null()]);

export const REGISTERS = [
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
  "xmm0",
  "xmm1",
  "xmm2",
  "xmm3",
  "xmm4",
  "xmm5",
  "xmm6",
  "xmm7",
  "xmm8",
  "xmm9",
  "xmm10",
  "xmm11",
  "xmm12",
  "xmm13",
  "xmm14",
  "xmm15",
] as const;
export const registerSchema = z.enum(REGISTERS);

// ---------------------------------------------------------------- hook capture (S6 §5.1)
export const captureSpecSchema = z
  .strictObject({
    name: z
      .string()
      .regex(/^[A-Za-z_][A-Za-z0-9_]{0,31}$/u)
      .optional(),
    arg: z.number().int().min(0).max(15).optional(),
    reg: registerSchema.optional(),
    type: valueTypeSchema,
    deref: z.array(z.number().int().min(-65_536).max(16_777_216)).max(4).optional(),
    count: z.number().int().min(1).max(4096).optional(),
    when: z.enum(["enter", "leave", "both"]).default("enter"),
  })
  .refine((c) => (c.arg === undefined) !== (c.reg === undefined), {
    message: 'Give arg (0..15) or reg (e.g. "xmm1"), not both. Example: {"arg":1,"type":"f32"}',
    path: ["arg"],
  });

// ---------------------------------------------------------------- query_events filters (S6 §4.26)
export const whereSchema = z.strictObject({
  field: z.string().min(1).max(64),
  op: z.enum(["eq", "ne", "lt", "le", "gt", "ge", "contains", "prefix"]),
  value: z.union([z.number(), z.string().max(1024), z.boolean()]),
});
/** CI-I6: query_events pages a recording (rec_) OR a host row stream (emu-batch, emu-sweep, diff, call-batch) by st_ id */
export const streamIdInputSchema = z.string().regex(/^st_[a-f0-9]{64}$/u);

// ---------------------------------------------------------------- identity, exit, crash (S6 §5.5 + S3)
export const identitySchema = z.strictObject({
  instance_id: z.string().max(80),
  pid: uint32,
  start_time: z.strictObject({
    value: z.string().max(64),
    source: z.enum(["os-creation-time", "frida-started", "first-observed"]),
  }),
  image: z.strictObject({
    path: z.string().max(4096),
    sha256: z.string().max(64).nullable(),
    size: z.number().int().min(0).nullable(),
  }),
  ownership: z.enum(["owned", "attached"]),
});
export const exitInfoSchema = z.strictObject({
  code: z.number().int().nullable(),
  code_hex: z.string().max(18).nullable(),
  name: z.string().max(64).nullable(),
  kind: z.enum(["normal", "ntstatus", "bea-kill", "unknown"]),
});
export const crashReportSchema = z.strictObject({
  type: z.string().max(64),
  ntstatus: z.string().max(64).nullable(),
  thread_id: uint32.nullable(),
  /** null when no exception reached user-mode handlers (fast fail, some stack overflows) */
  pc: locSchema.nullable(),
  insn: z.string().max(200).nullable(),
  memory: z.strictObject({ op: z.enum(["read", "write", "execute"]), address: hexSchema }).nullable(),
  registers: z.record(z.string().max(8), hexSchema),
  backtrace: z.array(locSchema).max(64),
  first_chance_count: z.number().int().min(0),
  evidence_id: z.string().max(80).nullable(),
});

// ---------------------------------------------------------------- recordings (S6 §5.3)
export const instrumentStateSchema = z.strictObject({
  recording_id: recordingIdSchema,
  kind: z.enum(["hook", "api", "watch", "poll", "trace", "override", "exceptions", "output", "modules"]),
  state: z.enum(["active", "finished", "failed"]),
  events: z.number().int().min(0),
  dropped: z.number().int().min(0),
  ends_in_ms: z.number().int().min(0).nullable(),
  end_reason: z
    .enum(["duration", "max_events", "invocations", "stopped", "target_exited", "detached", "quota", "rate-limit"])
    .nullable(),
  /**
   * bounded digest per kind (S6 §5.3); present when finished (installing calls, wait, stop_instrumentation). query_events
   * omits it here (review fix UX-2): view summary carries it once as the result's top-level `summary`
   */
  summary: jsonObjectSchema.exactOptional(),
});

/** Live session state as tools see it (S6 C10 projection). */
export const visibleStateSchema = z.enum([
  "paused",
  "running",
  "exited",
  "detached",
  "closing",
  "cleanup_pending",
  "closed",
  "ready",
  "lost",
]);

/** Lifetime inputs shared by instruments (S6 §2.5). */
export const lifetimeShape = {
  duration_ms: z.number().int().min(1).max(3_600_000).default(10_000),
  wait_ms: z.number().int().min(0).max(60_000).default(0),
} as const;

/** Single-address results (D-INT-16). */
export { addressRefSchema, addrExprSchema, locSchema };
