import { z } from "zod";

import { stIdSchema, evIdSchema } from "../../domain/ids.js";
import { jsonObjectSchema } from "../../domain/json.js";
import { fx } from "../effects.js";
import { pageSchema, pollOutput, recordedOutput } from "../schemas/envelope.js";
import { limitSchema, offsetSchema, sessionIdSchema } from "../schemas/primitives.js";
import {
  addressRefSchema,
  addrExprSchema,
  captureSpecSchema,
  crashReportSchema,
  exitInfoSchema,
  handleOrEffectSchema,
  instrumentStateSchema,
  lifetimeShape,
  recordingIdSchema,
  returnTypeSchema,
  streamIdInputSchema,
  visibleStateSchema,
  whereSchema,
} from "../schemas/shared.js";
import { defineTool, SESSION_STATE_REASON, type ToolContract } from "../toolContract.js";

/**
 * Area instrument (WP7-HOOK): hook_function, wait, stop_instrumentation, query_events (DESIGN §6.2 E, S6 §4.20,
 * §4.24–4.26, §5.1, §5.3–5.4). Rows of query_events are COLUMNAR (`columns` + one cell array per row): the envelope's
 * worst case (DESIGN §8.3, ≤ 2 MiB) cannot admit 500 open JSON objects, and columns also cost fewer tokens.
 */

/** Field names of hook events: capture names (default "arg<i>" / the register name), "@leave" for leave values. */
const NUMERIC_TYPES = new Set(["i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "ptr", "bool", "f32", "f64"]);
const NATIVE_REGS = new Set(["rcx", "rdx", "r8", "r9", "xmm0", "xmm1", "xmm2", "xmm3"]);
/** Agent arrays are bounded at 64 elements (S4 ArgCapture.count). */
export const MAX_NUMERIC_COUNT = 64;
export const captureFieldName = (c: {
  readonly name?: string | undefined;
  readonly arg?: number | undefined;
  readonly reg?: string | undefined;
}): string => c.name ?? (c.arg !== undefined ? `arg${String(c.arg)}` : (c.reg ?? "value"));

const uint32 = z.number().int().min(0).max(4_294_967_295);

// ---------------------------------------------------------------------------------------------- hook_function
const hookInput = z
  .strictObject({
    session_id: sessionIdSchema,
    address: addrExprSchema,
    probe: z.boolean().default(false),
    capture: z.array(captureSpecSchema).max(16).default([]),
    returns: returnTypeSchema.default("void"),
    caller: z.boolean().default(true),
    backtrace: z.number().int().min(0).max(32).default(0),
    thread_id: uint32.optional(),
    sample_every: z.number().int().min(1).max(1_000_000).default(1),
    engine: z.enum(["js", "native"]).default("js"),
    duration_ms: lifetimeShape.duration_ms,
    max_events: z.number().int().min(1).max(10_000_000).default(100_000),
    wait_ms: lifetimeShape.wait_ms,
  })
  .superRefine((v, ctx) => {
    const names = new Set<string>();
    v.capture.forEach((c, i) => {
      const at = (message: string, key: string): void =>
        ctx.addIssue({ code: "custom", message, path: ["capture", i, key] });
      const name = captureFieldName(c);
      for (const field of c.when === "both" ? [name, `${name}@leave`] : [c.when === "leave" ? `${name}@leave` : name]) {
        if (
          names.has(field) ||
          field === "ret" ||
          ["seq", "t_ms", "tid", "depth", "caller", "dur_us", "bt"].includes(field)
        )
          at(`capture[${String(i)}]: field "${field}" is already used; give the capture a distinct name`, "name");
        names.add(field);
      }
      if (v.probe && c.arg !== undefined)
        at(`capture[${String(i)}]: a probe captures registers only, e.g. {"reg":"rax","type":"ptr"}`, "arg");
      if (v.probe && c.when !== "enter") at(`capture[${String(i)}]: a probe has only "enter"`, "when");
      if (NUMERIC_TYPES.has(c.type) && c.count !== undefined && c.count > 1) {
        if (c.deref === undefined)
          at(`capture[${String(i)}]: an array (count > 1) is read through deref, e.g. "deref":[0]`, "count");
        if (c.count > MAX_NUMERIC_COUNT)
          at(`capture[${String(i)}]: count is at most ${String(MAX_NUMERIC_COUNT)} for numeric arrays`, "count");
      }
      if (v.engine === "native") {
        if (c.deref !== undefined || !NUMERIC_TYPES.has(c.type) || (c.count ?? 1) > 1 || c.when !== "enter")
          at(
            `capture[${String(i)}]: engine "native" records bare register/slot values at entry only (no deref, strings, bytes or leave)`,
            "type",
          );
        else if (c.arg !== undefined && c.arg > 7) at(`capture[${String(i)}]: engine "native" records arg 0..7`, "arg");
        else if (c.reg !== undefined && !NATIVE_REGS.has(c.reg))
          at(`capture[${String(i)}]: engine "native" records rcx, rdx, r8, r9 and xmm0..xmm3`, "reg");
      }
    });
    if (v.probe && v.returns !== "void")
      ctx.addIssue({ code: "custom", message: 'A probe has no return value; use "returns":"void"', path: ["returns"] });
    if (v.engine === "native" && v.backtrace > 0)
      ctx.addIssue({
        code: "custom",
        message: 'engine "native" records no backtrace; use "backtrace":0',
        path: ["backtrace"],
      });
    if (v.engine === "native" && v.probe)
      ctx.addIssue({
        code: "custom",
        message: 'engine "native" hooks function entries only (probe:false)',
        path: ["engine"],
      });
  });

const hookFunction = defineTool({
  name: "hook_function",
  area: "instrument",
  phase: "P1",
  description:
    "Install a bounded observation hook on a function entry (or any instruction with probe: true). Per call it captures typed Win64 values: integer args from registers or stack, f32/f64 args from xmm by position, any register, pointer-chain fields, before and/or after the call, the return (rax or xmm0), caller and backtrace as module+RVA. Records into a recording with duration and hit limits; target behavior is unchanged. Blocks up to wait_ms and then includes the summary.",
  inputSchema: hookInput,
  outputSchema: recordedOutput({
    instrument: instrumentStateSchema,
    target: addressRefSchema,
    function_start: z.boolean(),
    bytes_match_file: z.boolean().nullable(),
    relocation: z.enum(["default", "forced"]),
  }),
  effects: fx({ instrumentsTarget: true, mutatesSession: true, idempotent: false }),
  cli: { tier: "instrument-oneshot", command: "hook", positional: ["address"] },
  evidence: { predicate: "bea.instrument.install", recorded: "always" },
  errors: ["session_not_found", "address_unmapped", "memory_access_failed", "instrumentation_failed", "target_exited"],
  maxBlockingMs: 90_000,
  examples: [
    {
      title: "Hook physics_step: car pointer, dt, speed before and after, f32 return, 2 s",
      input: {
        session_id: "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b",
        address: "game_sim.exe!physics_step",
        capture: [
          { name: "car", arg: 0, type: "ptr" },
          { name: "dt", arg: 1, type: "f32" },
          { name: "speed", arg: 0, type: "f32", deref: [8], when: "both" },
        ],
        returns: "f32",
        duration_ms: 2000,
        wait_ms: 2500,
      },
    },
    {
      title: "Instruction probe capturing a register",
      input: {
        session_id: "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b",
        address: "game_sim.exe+0x1a2b",
        probe: true,
        capture: [{ reg: "rbx", type: "ptr" }],
        max_events: 50,
      },
    },
  ],
});

// ---------------------------------------------------------------------------------------------- wait
const waitIdSchema = z.string().regex(/^(?:rec_[0-9a-f]{8}|scan_[0-9a-f]{8})$/u);
const waitInput = z
  .strictObject({
    session_id: sessionIdSchema,
    until: z.enum(["done", "events", "exit", "output"]).default("done"),
    ids: z.array(waitIdSchema).min(1).max(16).optional(),
    min_events: z.number().int().min(1).max(100_000_000).optional(),
    output_contains: z.string().min(1).max(256).optional(),
    timeout_ms: z.number().int().min(1).max(60_000).default(10_000),
  })
  .superRefine((v, ctx) => {
    if (v.until === "events" && v.min_events === undefined)
      ctx.addIssue({
        code: "custom",
        message: 'until "events" needs min_events, e.g. "min_events":100',
        path: ["min_events"],
      });
    if (v.until === "output" && v.output_contains === undefined)
      ctx.addIssue({
        code: "custom",
        message: 'until "output" needs output_contains, e.g. "output_contains":"READY"',
        path: ["output_contains"],
      });
  });

const handleStateSchema = z.enum(["running", "ready", "active", "released", "reverted", "failed"]);
const wait = defineTool({
  name: "wait",
  area: "instrument",
  phase: "P1",
  description:
    "Block up to timeout_ms (max 60000) until a condition holds for a session: the listed (default all) instruments or scans finished, a minimum event count, target exit, or a literal appearing in target output. Running out of time is a normal poll result, not an error, and reading never consumes results, so repeat freely. Returns target state, exit and crash report, recording counts and finished summaries. Read-only.",
  inputSchema: waitInput,
  outputSchema: pollOutput({
    satisfied: z.boolean(),
    reason: z.enum(["condition", "timeout", "target_exited"]),
    waited_ms: z.number().int().min(0).max(120_000),
    target: z.strictObject({
      state: visibleStateSchema,
      exit: exitInfoSchema.nullable(),
      crash: crashReportSchema.nullable(),
    }),
    recordings: z.array(instrumentStateSchema).max(16),
    scans: z
      .array(
        z.strictObject({
          scan_id: z.string().max(16),
          state: handleStateSchema,
          count: z.number().int().min(0).nullable(),
        }),
      )
      .max(16)
      .exactOptional(),
  }),
  effects: fx({ mutatesSession: true }),
  cli: { tier: "scenario", reason: SESSION_STATE_REASON },
  errors: ["session_not_found", "reference_not_found"],
  maxBlockingMs: 65_000,
  examples: [
    { title: "Wait for every active instrument", input: { session_id: "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b" } },
    {
      title: "Wait for output",
      input: { session_id: "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b", until: "output", output_contains: "FRAME 60" },
    },
  ],
});

// ---------------------------------------------------------------------------------------------- stop_instrumentation
const stopInput = z
  .strictObject({
    session_id: sessionIdSchema,
    ids: z.array(handleOrEffectSchema).min(1).max(64).optional(),
    all: z.boolean().default(false),
  })
  .superRefine((v, ctx) => {
    if ((v.ids !== undefined) === v.all)
      ctx.addIssue({
        code: "custom",
        message: 'Provide exactly one of ids or all:true. Example: {"ids":["rec_0a1b2c3d"]}',
        path: ["ids"],
      });
  });

const stopInstrumentation = defineTool({
  name: "stop_instrumentation",
  area: "instrument",
  phase: "P1",
  description:
    "Stop instruments now (hook, trace_api, watch, trace, override recording ids), revert write effects (fx ids), release scans (scan ids), or all: true. Verifies each revert (hooks removed, hardware slots disarmed, bytes restored) and finalizes recording manifests; events stay queryable. A failed revert returns effect_unreverted and is retryable. Idempotent.",
  inputSchema: stopInput,
  outputSchema: recordedOutput({
    stopped: z
      .array(
        z.strictObject({
          id: z.string().max(80),
          kind: z.enum(["hook", "api", "watch", "poll", "trace", "override", "scan", "write"]),
          status: z.enum(["reverted", "already_ended", "released", "revert-failed"]),
          events: z.number().int().min(0).nullable(),
          dropped: z.number().int().min(0).nullable(),
          manifest_evidence_id: evIdSchema.nullable(),
        }),
      )
      .max(64),
    active_remaining: z.number().int().min(0).max(1024),
  }),
  effects: fx({ instrumentsTarget: true, mutatesSession: true }),
  returnsTargetContent: false,
  cli: { tier: "scenario", reason: SESSION_STATE_REASON },
  evidence: { predicate: "bea.instrument.stop", recorded: "always" },
  errors: ["session_not_found", "reference_not_found", "effect_unreverted"],
  maxBlockingMs: 30_000,
  examples: [
    { title: "Stop one hook", input: { session_id: "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b", ids: ["rec_0a1b2c3d"] } },
    { title: "Stop everything", input: { session_id: "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b", all: true } },
  ],
});

// ---------------------------------------------------------------------------------------------- query_events
/** Longest string cell in a page (worst-case envelope bound); longer values are shortened and flagged. */
export const QUERY_CELL_CHARS = 160;
/** Columns of a rows/group page: seq + ≤ 15 projected fields, or ≤ 3 group fields + count/first_seq/last_seq. */
export const QUERY_MAX_COLUMNS = 16;
export const QUERY_MAX_FIELDS = 15;
const cellSchema = z.union([z.number(), z.string().max(QUERY_CELL_CHARS), z.boolean(), z.null()]);
const statRowSchema = z.strictObject({
  field: z.string().max(80),
  type: z.string().max(16),
  count: z.number().int().min(0),
  min: cellSchema,
  max: cellSchema,
  mean: z.number().nullable(),
  distinct: z.number().int().min(0),
  distinct_capped: z.boolean(),
  top: z.array(z.strictObject({ value: cellSchema, count: z.number().int().min(0) })).max(5),
});
const fieldNameSchema = z.string().min(1).max(80);

const queryInput = z
  .strictObject({
    recording_id: recordingIdSchema.optional(),
    stream_id: streamIdInputSchema.optional(),
    view: z.enum(["summary", "rows", "group", "stats"]).default("summary"),
    where: z.array(whereSchema).max(8).default([]),
    group_by: z.array(fieldNameSchema).min(1).max(3).optional(),
    fields: z.array(fieldNameSchema).max(QUERY_MAX_FIELDS).optional(),
    order: z.enum(["asc", "desc"]).default("asc"),
    offset: offsetSchema,
    limit: limitSchema(500, 50),
  })
  .superRefine((v, ctx) => {
    if ((v.recording_id === undefined) === (v.stream_id === undefined))
      ctx.addIssue({
        code: "custom",
        message:
          'Provide exactly one of recording_id or stream_id. Example: {"recording_id":"rec_0a1b2c3d","view":"rows"}',
        path: ["recording_id"],
      });
    if (v.view === "group" && v.group_by === undefined)
      ctx.addIssue({
        code: "custom",
        message: 'view "group" needs group_by, e.g. "group_by":["dt"]',
        path: ["group_by"],
      });
  });

const queryEvents = defineTool({
  name: "query_events",
  area: "instrument",
  phase: "P1",
  description:
    "Query a recording without consuming it: summary (the instrument's bounded digest, e.g. behavior per API profile or writers of a watched address), rows (raw events filtered, projected, paged; as columns + one array per row), group (counts by up to 3 fields) or stats (min, max, distinct, top values per field). The first page lists the available fields. stream_id pages a host row stream (emu_call batch/sweep, diff, call batch) instead. Unobserved is not proof of absence. Read-only.",
  inputSchema: queryInput,
  outputSchema: recordedOutput({
    recording: instrumentStateSchema.nullable(),
    stream_id: stIdSchema.nullable(),
    view: z.enum(["summary", "rows", "group", "stats"]),
    columns: z.array(z.string().max(80)).max(QUERY_MAX_COLUMNS),
    rows: z.array(z.array(cellSchema).max(QUERY_MAX_COLUMNS)).max(500),
    page: pageSchema,
    fields: z
      .array(z.strictObject({ name: z.string().max(80), type: z.string().max(16) }))
      .max(64)
      .exactOptional(),
    stats: z.array(statRowSchema).max(QUERY_MAX_FIELDS).exactOptional(),
    summary: jsonObjectSchema.exactOptional(),
  }),
  effects: fx({ mutatesSession: true }),
  cli: { tier: "scenario", reason: SESSION_STATE_REASON },
  evidence: { predicate: "bea.events.query", recorded: "always" },
  errors: ["reference_not_found"],
  maxBlockingMs: 60_000,
  examples: [
    { title: "Summary of a recording", input: { recording_id: "rec_0a1b2c3d" } },
    {
      title: "Newest rows with chosen fields",
      input: {
        recording_id: "rec_0a1b2c3d",
        view: "rows",
        fields: ["dt", "speed@leave", "ret"],
        order: "desc",
        limit: 20,
      },
    },
    { title: "Count calls by dt", input: { recording_id: "rec_0a1b2c3d", view: "group", group_by: ["dt"] } },
  ],
});

export const INSTRUMENT_TOOLS = [
  hookFunction,
  wait,
  stopInstrumentation,
  queryEvents,
] as const satisfies readonly ToolContract[];
