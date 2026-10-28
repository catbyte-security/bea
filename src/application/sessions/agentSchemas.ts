import { z } from "zod";

import { AGENT_ERROR_MAP } from "../../domain/errors/agentErrorMap.js";
import type { AgentMethodName } from "../../shared/agentProtocol.js";

/**
 * Zod schemas for what the in-target agent sends the host (WP-SESS). The agent shares the target's address space, so
 * every message and RPC reply is untrusted input and is validated before the host acts on it (S3 §10–§11): the
 * agent → host messages (ready, crash, exit, job, instrument, fault, notice, fatal), the AgentResult reply envelope with
 * the closed AgentError tag set, value schemas for the replies the session layer depends on, and the
 * `bea.agent-build/1` bundle manifest. Kept in the application layer (providers may not depend on zod directly).
 */

// ---------------------------------------------------------------- bundle manifest (D-INT-25)
export const agentBuildManifestSchema = z.object({
  schema: z.literal("bea.agent-build/1"),
  file: z.string(),
  sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  bytes: z.number().int().min(1),
  runtime: z.literal("qjs"),
  frida_version: z.string(),
  protocol: z.string(),
  protocol_minor: z.number().int().min(0),
  agent_version: z.string().max(64),
  build_id: z.string().min(1).max(64),
});

// ---------------------------------------------------------------- RPC replies (S3 §11)
const AGENT_ERROR_TAGS: ReadonlySet<string> = new Set(Object.keys(AGENT_ERROR_MAP));

const agentErrorSchema = z
  .object({ _tag: z.string().refine((tag) => AGENT_ERROR_TAGS.has(tag)), message: z.string().max(65_536) })
  .passthrough();
export const agentReplySchema = z.union([
  z.object({ ok: z.literal(true), value: z.unknown() }),
  z.object({ ok: z.literal(false), error: agentErrorSchema }),
]);

/** Value schemas for the replies the session layer itself depends on; feature WPs validate their own fields. */
export const AGENT_VALUE_SCHEMAS: Partial<Record<AgentMethodName, z.ZodType>> = {
  ping: z.object({ t: z.number(), g: z.number(), phase: z.enum(["loaded", "ready", "shutting-down"]) }).passthrough(),
  flush: z.object({ batches: z.number().int().min(0), rows: z.number().int().min(0) }).passthrough(),
  hello: z
    .object({
      protocol: z.literal("bea-agent/1"),
      protocol_minor: z.number().int().min(0),
      agent_version: z.string().max(64),
      build_id: z.string().max(64),
      frida_version: z.string().max(32),
      runtime: z.enum(["QJS", "V8"]),
      process: z
        .object({
          pid: z.number().int(),
          arch: z.literal("x64"),
          main_module: z
            .object({ name: z.string(), path: z.string(), base: z.string(), size: z.number().int() })
            .passthrough(),
        })
        .passthrough(),
      limits: z.object({}).passthrough(),
      features: z.array(z.string()),
      system_streams: z
        .object({ exceptions: z.string().nullable(), modules: z.string(), threads: z.string().nullable() })
        .passthrough(),
      module_map_epoch: z.number().int().min(0),
    })
    .passthrough(),
  listModules: z
    .object({
      module_map_epoch: z.number().int().min(0),
      modules: z.array(
        z.object({ name: z.string(), path: z.string(), base: z.string(), size: z.number().int() }).passthrough(),
      ),
    })
    .passthrough(),
  shutdown: z
    .object({
      stopped: z.array(z.object({ id: z.string() }).passthrough()),
      unreverted: z.array(z.object({ id: z.string(), detail: z.string() }).passthrough()),
    })
    .passthrough(),
  jobStatus: z.object({ job_id: z.string(), kind: z.string(), state: z.string() }).passthrough(),
};

// ---------------------------------------------------------------- agent → host messages (S4 §4.7)
const hex = z.string().regex(/^0x[0-9a-f]{1,32}$/u);
export const agentReadySchema = z
  .object({
    bea: z.literal("ready"),
    protocol: z.string(),
    protocol_minor: z.number().int().min(0),
    agent_version: z.string().max(64),
    build_id: z.string().max(64),
    frida_version: z.string().max(32),
    runtime: z.enum(["QJS", "V8"]),
    pid: z.number().int().min(0),
    arch: z.string().max(16),
    platform: z.string().max(16),
    js_thread_id: z.number().int().min(0),
    t0_wall_ms: z.number(),
    features: z.array(z.string().max(32)).max(64),
    early: z.object({}).passthrough(),
  })
  .passthrough();
const crashReportSchema = z
  .object({
    report_id: z.string().max(64),
    phase: z.enum(["first-chance", "last-chance"]),
    g: z.number(),
    t: z.number(),
    tid: z.number().int().min(0),
    type: z.string().max(32),
    code: hex.nullable(),
    address: hex,
    memory: z.object({ operation: z.enum(["read", "write", "execute"]), address: hex }).nullable(),
    registers: z.record(z.string().max(8), hex),
    instruction: z.object({ address: hex, bytes: z.string().max(64), text: z.string().max(200) }).nullable(),
    backtrace: z.array(z.object({ va: hex, module: z.string().max(260).nullable(), rva: hex.nullable() })).max(128),
    module_map_epoch: z.number().int().min(0),
  })
  .passthrough();
export const agentCrashSchema = z.object({
  bea: z.literal("crash"),
  ack: z.string().max(64),
  report: crashReportSchema,
});
export const agentExitSchema = z
  .object({
    bea: z.literal("exit"),
    ack: z.string().max(64),
    via: z.enum(["RtlExitUserProcess", "NtTerminateProcess(self)"]),
    exit_code: z.number().int(),
    tid: z.number().int().min(0),
    g: z.number(),
    t: z.number(),
    flushed: z.object({ streams: z.number(), rows: z.number() }),
  })
  .passthrough();
export const agentJobSchema = z
  .object({
    bea: z.literal("job"),
    job: z.string().max(64),
    kind: z.enum(["scan-first", "scan-next", "dump"]),
    state: z.enum(["done", "failed", "cancelled"]),
    progress: z.object({ done: z.number(), total: z.number().nullable(), unit: z.enum(["bytes", "items"]) }),
  })
  .passthrough();
export const agentInstrumentSchema = z
  .object({
    bea: z.literal("instrument"),
    id: z.string().max(64),
    event: z.enum(["ended", "degraded", "lazy-installed"]),
    detail: z.object({}).passthrough(),
  })
  .passthrough();
export const agentFaultSchema = z
  .object({ bea: z.literal("fault"), where: z.string().max(128), error: z.object({ _tag: z.string() }).passthrough() })
  .passthrough();
export const agentNoticeSchema = z
  .object({
    bea: z.literal("notice"),
    code: z.enum([
      "flow-shedding-on",
      "flow-shedding-off",
      "instrument-interference",
      "hwbp-unreverted",
      "heap-soft-limit",
    ]),
    detail: z.object({}).passthrough(),
  })
  .passthrough();
export const agentFatalSchema = z
  .object({ bea: z.literal("fatal"), stage: z.string().max(32), error: z.object({ _tag: z.string() }).passthrough() })
  .passthrough();
