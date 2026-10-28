import { z } from "zod";

import { fx } from "../effects.js";
import { addrExprSchema, exactlyOne } from "../schemas/address.js";
import { recordedOutput } from "../schemas/envelope.js";
import { localPathSchema, sessionIdSchema } from "../schemas/primitives.js";
import { addressRefSchema, instrumentStateSchema, lifetimeShape, recordingIdSchema } from "../schemas/shared.js";
import { defineTool, SESSION_STATE_REASON, type ToolContract } from "../toolContract.js";

/**
 * Area watch (WP9-WATCH): watch_memory, trace_execution, export_coverage (DESIGN §6.2 G; S6 §4.22, §4.23, §4.27).
 * Descriptions are S6 §4 verbatim. Address inputs are AddrExpr strings (D-INT-15); size/alignment and page counts
 * that depend on the resolved address are checked by the handlers with corrective messages.
 */
const WATCH_VIEWS = ["hex", "i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "f32", "f64"] as const;
const VIEW_WIDTH: Readonly<Record<(typeof WATCH_VIEWS)[number], number>> = {
  hex: 1,
  i8: 1,
  u8: 1,
  i16: 2,
  u16: 2,
  i32: 4,
  u32: 4,
  i64: 8,
  u64: 8,
  f32: 4,
  f64: 8,
};
/** Operand registers are always captured; these are the extra ones a hit may carry (the agent captures GPRs only). */
const WATCH_REGISTERS = [
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
] as const;
const DR_SIZES = [1, 2, 4, 8];
const uint32 = z.number().int().min(0).max(4_294_967_295);
const evidenceIdInputSchema = z.string().regex(/^ev_[a-f0-9]{64}$/u);
const EXAMPLE_SESSION = "00000000-0000-4000-8000-000000000001";

const watchInputSchema = z
  .strictObject({
    session_id: sessionIdSchema,
    address: addrExprSchema,
    size: z
      .number()
      .int()
      .min(1)
      .max(65_536)
      .default(4)
      .describe("debug_register: 1/2/4/8 aligned; page_guard: ≤16 pages."),
    access: z.enum(["write", "read_write", "execute"]).default("write"),
    method: z
      .enum(["auto", "debug_register", "page_guard", "poll"])
      .default("auto")
      .describe("auto: debug_register if it fits, else page_guard."),
    rate_limit_per_sec: z
      .number()
      .int()
      .min(1000)
      .max(1_000_000)
      .default(20_000)
      .describe("page_guard disarms above this trap rate."),
    view: z.enum(WATCH_VIEWS).default("hex"),
    interval_ms: z.number().int().min(1).max(10_000).default(16).describe("poll interval"),
    registers: z.array(z.enum(WATCH_REGISTERS)).max(8).default([]),
    backtrace: z.number().int().min(0).max(16).default(0),
    ...lifetimeShape,
    max_events: z.number().int().min(1).max(1_000_000).default(10_000),
  })
  .superRefine((v, ctx) => {
    if (v.method === "debug_register" && v.access !== "execute" && !DR_SIZES.includes(v.size)) {
      const nearest = DR_SIZES.find((s) => s >= v.size);
      ctx.addIssue({
        code: "custom",
        path: ["size"],
        message:
          nearest === undefined
            ? `debug_register watches 1, 2, 4 or 8 bytes; for ${String(v.size)} bytes use method page_guard.`
            : `debug_register watches 1, 2, 4 or 8 bytes; use size ${String(nearest)} or method page_guard.`,
      });
    }
    if (v.method === "poll" && v.access === "execute")
      ctx.addIssue({
        code: "custom",
        path: ["access"],
        message: "poll samples values and cannot observe execution; use debug_register or page_guard for execute.",
      });
    if (v.method === "poll" && v.size % VIEW_WIDTH[v.view] !== 0)
      ctx.addIssue({
        code: "custom",
        path: ["size"],
        message: `poll with view ${v.view} needs a size that is a multiple of ${String(VIEW_WIDTH[v.view])}.`,
      });
  });

const traceInputSchema = z
  .strictObject({
    session_id: sessionIdSchema,
    mode: z.enum(["coverage", "block_counts", "calls"]).default("coverage"),
    thread_ids: z.array(uint32).min(1).max(16).optional(),
    on_call: addrExprSchema.optional(),
    invocations: z.number().int().min(1).max(1000).default(1).describe("on_call only"),
    modules: z
      .array(z.string().min(1).max(260))
      .min(1)
      .max(16)
      .default(["$main"])
      .describe("Recorded modules. Direct calls into other modules run natively; indirect calls are still followed."),
    ...lifetimeShape,
    max_events: z.number().int().min(1).max(50_000_000).default(1_000_000),
  })
  .refine(
    exactlyOne(["thread_ids", "on_call"], '{"on_call":"game.exe!physics_step","invocations":1}').check,
    "Provide exactly one of thread_ids (follow now) or on_call (follow N invocations of one function)",
  );

const exportInputSchema = z
  .strictObject({
    recording_id: recordingIdSchema.optional(),
    evidence_id: evidenceIdInputSchema.optional(),
    format: z.enum(["drcov", "modoff"]).default("drcov"),
    out_path: localPathSchema.optional().describe("New file; default under BEA_HOME/runs."),
  })
  .refine(exactlyOne(["recording_id", "evidence_id"], '{"recording_id":"rec_0000000a"}').check, {
    message: 'Provide exactly one of recording_id or evidence_id. Example: {"recording_id":"rec_0000000a"}',
  });

const nameBlocksSchema = z.strictObject({ name: z.string().max(260), blocks: z.number().int().min(0) });
const functionBlocksSchema = z.strictObject({
  func: z.string().max(600),
  sym: z.string().max(1100).nullable(),
  blocks: z.number().int().min(0),
});

export const WATCH_TOOLS = [
  defineTool({
    name: "watch_memory",
    area: "watch",
    phase: "P2",
    title: "Watch Memory",
    description:
      "Log what accesses an address without stopping the target. debug_register: 4 hardware slots, size 1/2/4/8 aligned, all threads including new ones; page_guard: any size, page-granular, exact instruction, and while armed the target's own system calls into the page fail (use debug_register for I/O buffers); poll: sample a range every interval_ms and record value changes (struct exploration). Hits give the accessing instruction (module+RVA, static VA, text), thread, value and the struct base derived from its base register. Bounded; blocks up to wait_ms.",
    inputSchema: watchInputSchema,
    outputSchema: recordedOutput({
      instrument: instrumentStateSchema,
      method: z.enum(["debug_register", "page_guard", "poll"]),
      target: addressRefSchema,
      slot: z.number().int().min(0).max(3).nullable(),
      threads_armed: z.number().int().min(0).max(1_000_000).nullable(),
    }),
    effects: fx({ instrumentsTarget: true, mutatesSession: true, idempotent: false }),
    cli: { tier: "instrument-oneshot", command: "watch", positional: ["address"] },
    evidence: { predicate: "bea.instrument.install", recorded: "always", identityExclude: ["wait_ms"] },
    errors: [
      "address_unmapped",
      "instrumentation_failed",
      "memory_access_failed",
      "target_exited",
      "unsupported_target",
    ],
    maxBlockingMs: 90_000,
    examples: [
      {
        title: "Who writes this float (debug register)",
        input: {
          session_id: EXAMPLE_SESSION,
          address: "0x1f3a5e04",
          size: 4,
          access: "write",
          view: "f32",
          duration_ms: 2000,
          wait_ms: 3000,
        },
      },
      {
        title: "Which fields of a struct change (poll)",
        input: {
          session_id: EXAMPLE_SESSION,
          address: "0x1f3a5c40",
          size: 512,
          method: "poll",
          view: "f32",
          interval_ms: 16,
          duration_ms: 3000,
          wait_ms: 4000,
        },
      },
    ],
  }),
  defineTool({
    name: "trace_execution",
    area: "watch",
    phase: "P2",
    title: "Trace Execution",
    description:
      "Record executed code with Stalker on chosen threads, or for the next N invocations of one function (on_call): coverage (unique blocks), block_counts (exact hits) or calls (call edges). Bounded by duration and events; queues are tuned and drops are counted, never silent. calls mode can slow call-heavy code ~90x. Summary gives per-module and per-function block counts; export with export_coverage.",
    inputSchema: traceInputSchema,
    outputSchema: recordedOutput({
      instrument: instrumentStateSchema,
      followed_threads: z.array(uint32).max(16),
    }),
    effects: fx({ instrumentsTarget: true, mutatesSession: true, idempotent: false }),
    cli: { tier: "instrument-oneshot", command: "trace", positional: [] },
    evidence: { predicate: "bea.instrument.install", recorded: "always", identityExclude: ["wait_ms"] },
    errors: [
      "address_unmapped",
      "instrumentation_failed",
      "resource_constraint",
      "target_exited",
      "unsupported_target",
    ],
    maxBlockingMs: 90_000,
    examples: [
      {
        title: "Coverage of one call",
        input: {
          session_id: EXAMPLE_SESSION,
          on_call: "game.exe!physics_step",
          invocations: 1,
          mode: "coverage",
          wait_ms: 5000,
        },
      },
      {
        title: "Block hit counts of one thread for 1 s",
        input: {
          session_id: EXAMPLE_SESSION,
          thread_ids: [4242],
          mode: "block_counts",
          duration_ms: 1000,
          wait_ms: 2000,
        },
      },
    ],
  }),
  defineTool({
    name: "export_coverage",
    area: "watch",
    phase: "P2",
    title: "Export Coverage",
    description:
      "Write block coverage from a trace_execution recording, a call_function result or an emu_call result (its evidence id) to a new drcov v2 file (module-relative, ASLR-independent; for Lighthouse or Cartographer) or a module+offset text list. Never overwrites; default path is under BEA_HOME/runs. Returns path, sha256, block and module counts and blocks per function.",
    inputSchema: exportInputSchema,
    outputSchema: recordedOutput({
      path: z.string().max(4096),
      bytes: z.number().int().min(0),
      sha256: z.string().regex(/^[a-f0-9]{64}$/u),
      format: z.enum(["drcov", "modoff"]),
      blocks: z.number().int().min(0),
      modules: z.array(nameBlocksSchema).max(64),
      functions: z.array(functionBlocksSchema).max(50),
    }),
    effects: fx({ writesFilesystem: true, mutatesSession: true, idempotent: false }),
    cli: { tier: "scenario", reason: SESSION_STATE_REASON },
    evidence: { predicate: "bea.coverage.export", recorded: "always", identityExclude: ["out_path"] },
    errors: ["reference_not_found", "file_operation_failed", "access_denied"],
    maxBlockingMs: 60_000,
    examples: [
      { title: "Export a trace as drcov", input: { recording_id: "rec_0000000a" } },
      {
        title: "Export call coverage as module+offset lines",
        input: {
          evidence_id: "ev_0000000000000000000000000000000000000000000000000000000000000001",
          format: "modoff",
        },
      },
    ],
  }),
] as const satisfies readonly ToolContract[];
