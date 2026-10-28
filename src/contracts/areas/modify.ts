import { z } from "zod";

import { fxIdSchema } from "../../domain/ids.js";
import { jsonValueSchema } from "../../domain/json.js";
import { fx } from "../effects.js";
import { scalarInputSchema } from "../schemas/callModel.js";
import { recordedOutput } from "../schemas/envelope.js";
import { sessionIdSchema } from "../schemas/primitives.js";
import { addressRefSchema, addrExprSchema, instrumentStateSchema } from "../schemas/shared.js";
import { defineTool, SESSION_STATE_REASON, type ToolContract } from "../toolContract.js";

/**
 * Area modify (WP12-MODIFY, DESIGN §6.2 I): write_memory, override_function, run_script. All three are gated by a
 * server-level opt-in (scope "always": invokeTool refuses before the handler runs, so a closed gate never reaches
 * the agent) and annotated destructive. Descriptions are S6 §4.16 / §4.29 / §4.30 verbatim.
 */

/** Tool-level scalar types a write or an override takes (S6 §2.3; `bool` is one byte, CI-M13). */
export const MODIFY_VALUE_TYPES = [
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
export type ModifyValueType = (typeof MODIFY_VALUE_TYPES)[number];
const modifyValueTypeSchema = z.enum(MODIFY_VALUE_TYPES);
const overrideReturnTypeSchema = z.enum(["void", ...MODIFY_VALUE_TYPES]);

/** S6 §4.16: 2..8192 hex chars (≤ 4096 bytes); spaces are not accepted, either case is. */
export const WRITE_MAX_BYTES = 4096;
const writeHexSchema = z
  .string()
  .min(2)
  .max(WRITE_MAX_BYTES * 2)
  .regex(/^(?:[0-9a-fA-F]{2})+$/u)
  .describe("Bytes to write as even-length hex without spaces, e.g. 0000803f.");
/** S2 §15.1 per-call literal fragment (≥ 4 UTF-8 bytes each is checked by EvidenceRuntime.literals). */
const sensitiveValuesSchema = z.array(z.string().min(1).max(1024)).max(64);
const hexBytesOutSchema = z
  .string()
  .max(WRITE_MAX_BYTES * 2)
  .regex(/^(?:[0-9a-f]{2})*$/u);

/** run_script inline output bounds (the full capture goes to an evidence blob). */
export const SCRIPT_INLINE = { messages: 1000, messageChars: 1024, rpcResultChars: 65_536 } as const;

const SAMPLE_SESSION = "3f2b8c1e-4d5a-4e6f-9a0b-1c2d3e4f5a6b";

export const MODIFY_TOOLS = [
  defineTool({
    name: "write_memory",
    area: "modify",
    phase: "P3",
    description:
      "GATED: needs server opt-in write_memory. Write bytes or one typed value to target memory (code pages use a code-safe patch). Records a reversible effect holding the original bytes and reads back to verify. Taints later observations of this process. Revert with stop_instrumentation(effect id) or close_session (attached); owned targets are killed at close.",
    inputSchema: z
      .strictObject({
        session_id: sessionIdSchema,
        address: addrExprSchema,
        hex: writeHexSchema.optional(),
        type: modifyValueTypeSchema.optional().describe("Typed write (with value); bool is one byte."),
        value: scalarInputSchema
          .optional()
          .describe(
            'Number, decimal string, "0x…" raw bits of the type, NaN/Infinity/-Infinity; ptr takes an address.',
          ),
        sensitive_values: sensitiveValuesSchema.optional(),
      })
      .superRefine((input, ctx) => {
        const typed = input.type !== undefined || input.value !== undefined;
        if ((input.hex !== undefined) === typed)
          ctx.addIssue({
            code: "custom",
            path: ["hex"],
            message:
              'Provide exactly one of hex or type+value. Example: {"type":"f32","value":1.0} or {"hex":"0000803f"}',
          });
        else if (typed && (input.type === undefined || input.value === undefined))
          ctx.addIssue({
            code: "custom",
            path: [input.type === undefined ? "type" : "value"],
            message: 'type and value go together. Example: {"type":"i32","value":100}',
          });
      }),
    outputSchema: recordedOutput({
      effect_id: fxIdSchema,
      address: addressRefSchema,
      /** null when the bytes contained a sensitive value (redacted; review fix SEC-4) */
      before_hex: hexBytesOutSchema.nullable(),
      after_hex: hexBytesOutSchema.nullable(),
      /** read-back equals the intended bytes; never just "submitted" */
      verified: z.boolean(),
      method: z.enum(["direct", "protect-and-restore", "patchCode"]),
    }),
    effects: fx({ writesTargetMemory: true, mutatesSession: true, idempotent: false }),
    gate: { id: "write_memory", scope: "always" },
    cli: { tier: "scenario", reason: SESSION_STATE_REASON },
    evidence: { predicate: "bea.memory.write", recorded: "always" },
    errors: ["memory_access_failed", "address_unmapped", "target_exited"],
    examples: [
      {
        title: "Write one f32 into a struct field",
        input: { session_id: SAMPLE_SESSION, address: "0x1f2a3b4c00c", type: "f32", value: 1.0 },
      },
      { title: "Patch raw bytes", input: { session_id: SAMPLE_SESSION, address: "game_sim.exe+0x1650", hex: "9090" } },
    ],
  }),
  defineTool({
    name: "override_function",
    area: "modify",
    phase: "P3",
    description:
      "GATED: needs server opt-in override_function. For a bounded lifetime change a function's behavior: rewrite chosen args before it runs, replace its return after it runs, or skip it and return a constant. Every affected call is logged to a recording. A reversible effect, reverted by stop_instrumentation, expiry or close_session. Taints observations of this process.",
    inputSchema: z
      .strictObject({
        session_id: sessionIdSchema,
        address: addrExprSchema,
        mode: z
          .enum(["args", "return", "replace"])
          .describe("args: rewrite args before the original runs; return: replace its return; replace: skip it."),
        set_args: z
          .array(
            z.strictObject({
              arg: z.number().int().min(0).max(15),
              type: modifyValueTypeSchema,
              value: scalarInputSchema,
            }),
          )
          .max(8)
          .default([])
          .describe('Args to rewrite (mode args). Example: [{"arg":1,"type":"f32","value":0}]'),
        returns: overrideReturnTypeSchema.default("void"),
        return_value: scalarInputSchema.optional().describe("Value returned (modes return and replace)."),
        duration_ms: z.number().int().min(1).max(3_600_000).default(10_000),
        max_events: z.number().int().min(1).max(10_000_000).default(100_000),
        record: z.boolean().default(true).describe("Log every applied call to the recording (override/1 rows)."),
      })
      .superRefine((input, ctx) => {
        if (input.mode === "args") {
          if (input.set_args.length === 0)
            ctx.addIssue({
              code: "custom",
              path: ["set_args"],
              message:
                'mode args needs set_args. Example: {"mode":"args","set_args":[{"arg":1,"type":"f32","value":0}]}',
            });
          if (input.return_value !== undefined || input.returns !== "void")
            ctx.addIssue({
              code: "custom",
              path: ["return_value"],
              message: "mode args rewrites arguments only; use mode return to change the return value.",
            });
          const slots = input.set_args.map((a) => a.arg);
          if (new Set(slots).size !== slots.length)
            ctx.addIssue({ code: "custom", path: ["set_args"], message: "Each arg index may appear once." });
          return;
        }
        if (input.set_args.length > 0)
          ctx.addIssue({
            code: "custom",
            path: ["set_args"],
            message: `set_args is only used by mode args; mode ${input.mode} changes the return value.`,
          });
        if (input.returns === "void" || input.return_value === undefined)
          ctx.addIssue({
            code: "custom",
            path: [input.returns === "void" ? "returns" : "return_value"],
            message: `mode ${input.mode} needs returns (a non-void type) and return_value. Example: {"mode":"${input.mode}","returns":"f32","return_value":123}`,
          });
      }),
    outputSchema: recordedOutput({
      instrument: instrumentStateSchema,
      effect_id: fxIdSchema,
      target: addressRefSchema,
    }),
    effects: fx({ instrumentsTarget: true, writesTargetMemory: true, mutatesSession: true, idempotent: false }),
    gate: { id: "override_function", scope: "always" },
    cli: { tier: "scenario", reason: SESSION_STATE_REASON },
    evidence: { predicate: "bea.instrument.install", recorded: "always" },
    errors: ["instrumentation_failed", "address_unmapped", "target_exited"],
    examples: [
      {
        title: "Force a return value",
        input: {
          session_id: SAMPLE_SESSION,
          address: "game_sim.exe!telemetry_sample",
          mode: "return",
          returns: "f32",
          return_value: 123,
        },
      },
      {
        title: "Zero a float argument",
        input: {
          session_id: SAMPLE_SESSION,
          address: "game_sim.exe!physics_step",
          mode: "args",
          set_args: [{ arg: 1, type: "f32", value: 0 }],
          duration_ms: 2000,
        },
      },
    ],
  }),
  defineTool({
    name: "run_script",
    area: "modify",
    phase: "P3",
    description:
      "GATED: needs server opt-in run_script. Escape hatch: load caller-written Frida JavaScript (QJS or V8) into the target for at most duration_ms, capture its bounded send() messages and errors, optionally call one rpc export, then always unload it. Shares the agent's single JS thread. Runs arbitrary code in the target; prefer the structured tools.",
    inputSchema: z
      .strictObject({
        session_id: sessionIdSchema,
        source: z.string().min(1).max(262_144).describe("Frida JavaScript source."),
        runtime: z.enum(["qjs", "v8"]).default("qjs"),
        duration_ms: z.number().int().min(0).max(60_000).default(1000),
        max_messages: z.number().int().min(1).max(10_000).default(1000),
        rpc_method: z
          .string()
          .regex(/^[A-Za-z_$][A-Za-z0-9_$]{0,63}$/u)
          .optional()
          .describe("rpc.exports method to call once after load."),
        rpc_args: z.array(jsonValueSchema).max(32).default([]),
      })
      .refine((input) => input.rpc_args.length === 0 || input.rpc_method !== undefined, {
        message: 'rpc_args needs rpc_method. Example: {"rpc_method":"probe","rpc_args":[1]}',
        path: ["rpc_args"],
      }),
    outputSchema: recordedOutput({
      /**
       * send() payloads as compact JSON text, at most SCRIPT_INLINE.messages inline and SCRIPT_INLINE.messageChars
       * characters each (the 2 MiB worst-case envelope bound, DESIGN §8.3); the complete capture is the evidence blob
       * `script.messages` (NDJSON).
       */
      messages: z.array(z.string().max(SCRIPT_INLINE.messageChars)).max(SCRIPT_INLINE.messages),
      /** messages the capture holds (≤ max_messages) */
      messages_total: z.number().int().min(0).max(10_000),
      errors: z
        .array(
          z.strictObject({
            description: z.string().max(1000),
            line: z.number().int().min(0).max(100_000_000).nullable(),
          }),
        )
        .max(64),
      /** the rpc export's return value as compact JSON text */
      rpc_result: z.string().max(SCRIPT_INLINE.rpcResultChars).exactOptional(),
      truncated: z.boolean(),
      unloaded: z.boolean(),
      /** BEA's own instrumentation fingerprint differed before/after; null = could not be compared */
      interference: z.boolean().nullable(),
    }),
    effects: fx({
      injectsCode: true,
      instrumentsTarget: true,
      writesTargetMemory: true,
      executesTargetCode: true,
      mutatesSession: true,
      idempotent: false,
    }),
    gate: { id: "run_script", scope: "always" },
    cli: { tier: "session-oneshot", command: "script", positional: ["source"], fileFields: ["source"] },
    evidence: { predicate: "bea.script.run", recorded: "always" },
    errors: ["target_exited", "effect_unreverted"],
    maxBlockingMs: 90_000,
    maxInputBytes: 2 * 1024 * 1024,
    examples: [
      {
        title: "Send three messages",
        input: { session_id: SAMPLE_SESSION, source: "for (let i = 0; i < 3; i++) send({i});" },
      },
      {
        title: "Call one rpc export",
        input: {
          session_id: SAMPLE_SESSION,
          source: "rpc.exports = { pid: () => Process.id };",
          rpc_method: "pid",
          duration_ms: 0,
        },
      },
    ],
  }),
] as const satisfies readonly ToolContract[];
