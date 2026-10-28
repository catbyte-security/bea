import { randomUUID } from "node:crypto";

import { z } from "zod";

import type { BeaApplication } from "../../../src/application/BeaApplication.js";
import type { HandlerContext } from "../../../src/application/handlerContext.js";
import { createSessionHandlers } from "../../../src/application/handlers/sessions.js";
import type { HandlerLookup } from "../../../src/application/invokeTool.js";
import { toolContract } from "../../../src/contracts/index.js";
import { fx } from "../../../src/contracts/effects.js";
import { pollOutput } from "../../../src/contracts/schemas/envelope.js";
import { defineTool, SESSION_STATE_REASON, type ToolContract } from "../../../src/contracts/toolContract.js";
import type { BeaError } from "../../../src/domain/errors/beaError.js";
import { COMPLETE } from "../../../src/domain/evidence/coverage.js";
import { ok, type Result } from "../../../src/domain/result.js";

/**
 * WP15 test catalog: small contracts named like the real tools (spawn_process, read_memory, hook_function, emu_open,
 * diff_function …) with the CLI tiers, positionals, offline and file fields of DESIGN §6, so the CLI runners can be
 * exercised before the area work packages land. Field sets are reduced to what the runners touch.
 */
const sessionId = z.uuid();
const env = { evidence_id: null, coverage: COMPLETE, limitations: [] as string[] };
const scenarioTarget = "Creates the session that scenario steps run in (scenario target or session-creating step).";

const contracts = {
  bea_status: toolContract("bea_status"),
  spawn_process: defineTool({
    name: "spawn_process",
    area: "sessions",
    phase: "P1",
    description: "Test double of spawn_process: creates a paused owned session for the program and its arguments.",
    inputSchema: z.strictObject({
      program: z.string().min(1).max(1024),
      args: z.array(z.string().max(8192)).max(256).default([]),
    }),
    outputSchema: pollOutput({ session_id: sessionId, state: z.literal("paused") }),
    effects: fx({
      launchesProcess: true,
      suspendsTarget: true,
      injectsCode: true,
      mutatesSession: true,
      idempotent: false,
    }),
    cli: { tier: "scenario-target", reason: scenarioTarget },
    examples: [],
  }),
  attach_process: defineTool({
    name: "attach_process",
    area: "sessions",
    phase: "P1",
    description: "Test double of attach_process: attaches to a pid or an image name and returns a live session.",
    inputSchema: z
      .strictObject({
        pid: z.number().int().min(1).max(4_294_967_295).optional(),
        name: z.string().min(1).max(260).optional(),
      })
      .refine((v) => (v.pid === undefined) !== (v.name === undefined), {
        message: "Provide exactly one of pid or name.",
      }),
    outputSchema: pollOutput({ session_id: sessionId, state: z.literal("running") }),
    effects: fx({ injectsCode: true, mutatesSession: true, idempotent: false }),
    cli: { tier: "scenario-target", reason: scenarioTarget },
    examples: [],
  }),
  resume_process: defineTool({
    name: "resume_process",
    area: "sessions",
    phase: "P1",
    description: "Test double of resume_process: resumes a paused owned target and reports its state.",
    inputSchema: z.strictObject({ session_id: sessionId, wait_ms: z.number().int().min(0).max(60_000).default(0) }),
    outputSchema: pollOutput({ state: z.enum(["running", "exited"]) }),
    effects: fx({ executesTargetCode: true, mutatesSession: true, idempotent: false }),
    cli: { tier: "scenario", reason: SESSION_STATE_REASON },
    examples: [],
  }),
  close_session: defineTool({
    name: "close_session",
    area: "sessions",
    phase: "P1",
    description: "Test double of close_session: kills an owned target, detaches an attached one, closes emulation.",
    inputSchema: z.strictObject({ session_id: sessionId, force: z.boolean().default(false) }),
    outputSchema: pollOutput({ session_id: sessionId, already_closed: z.boolean() }),
    effects: fx({ killsProcess: true, instrumentsTarget: true, mutatesSession: true }),
    cli: { tier: "scenario", reason: SESSION_STATE_REASON },
    examples: [],
  }),
  read_memory: defineTool({
    name: "read_memory",
    area: "inspect",
    phase: "P1",
    description: "Test double of read_memory: reads bytes or typed values at an address of a live session.",
    inputSchema: z.strictObject({
      session_id: sessionId,
      address: z.string().min(1).max(600),
      size: z.number().int().min(1).max(1_048_576).default(64),
      format: z.enum(["hex", "values"]).default("hex"),
      types: z
        .array(z.enum(["f32", "u32"]))
        .max(16)
        .optional(),
      follow_pointers: z.boolean().default(true),
    }),
    outputSchema: pollOutput({ echo: z.record(z.string(), z.unknown()) }),
    effects: fx({ readsTargetMemory: true, mutatesSession: true }),
    cli: { tier: "session-oneshot", command: "read", positional: ["pid", "address", "size"] },
    examples: [],
  }),
  map_address: defineTool({
    name: "map_address",
    area: "address",
    phase: "P1",
    description: "Test double of map_address: maps addresses live or offline against a PE file (pe_path).",
    inputSchema: z
      .strictObject({
        session_id: sessionId.optional(),
        pe_path: z.string().min(3).max(1024).optional(),
        addresses: z.array(z.string().min(1).max(600)).min(1).max(64),
      })
      .refine((v) => (v.session_id === undefined) !== (v.pe_path === undefined), {
        message: "Provide exactly one of session_id or pe_path.",
      }),
    outputSchema: pollOutput({ echo: z.record(z.string(), z.unknown()) }),
    effects: fx({ readsTargetMemory: true, mutatesSession: true }),
    cli: { tier: "session-oneshot", command: "map", positional: ["addresses"], offlineField: "pe_path" },
    examples: [],
  }),
  run_script: defineTool({
    name: "run_script",
    area: "modify",
    phase: "P3",
    description: "Test double of run_script: runs caller JavaScript in a separate script (gated by run_script).",
    inputSchema: z.strictObject({ session_id: sessionId, source: z.string().min(1).max(262_144) }),
    outputSchema: pollOutput({ echo: z.record(z.string(), z.unknown()) }),
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
    maxInputBytes: 2 * 1024 * 1024,
    examples: [],
  }),
  hook_function: defineTool({
    name: "hook_function",
    area: "instrument",
    phase: "P1",
    description: "Test double of hook_function: installs a hook recording with a duration and returns its instrument.",
    inputSchema: z.strictObject({
      session_id: sessionId,
      address: z.string().min(1).max(600),
      duration_ms: z.number().int().min(1).max(3_600_000).default(10_000),
      wait_ms: z.number().int().min(0).max(60_000).default(0),
    }),
    outputSchema: pollOutput({ instrument: z.strictObject({ recording_id: z.string(), kind: z.literal("hook") }) }),
    effects: fx({ instrumentsTarget: true, mutatesSession: true, idempotent: false }),
    cli: { tier: "instrument-oneshot", command: "hook", positional: ["address"] },
    examples: [],
  }),
  wait: defineTool({
    name: "wait",
    area: "instrument",
    phase: "P1",
    description: "Test double of wait: waits for recordings to finish, the target to exit, or the timeout.",
    inputSchema: z.strictObject({
      session_id: sessionId,
      until: z.enum(["done", "events", "exit", "output"]).default("done"),
      ids: z.array(z.string()).max(16).optional(),
      timeout_ms: z.number().int().min(1).max(60_000).default(10_000),
    }),
    outputSchema: pollOutput({ satisfied: z.boolean(), reason: z.enum(["condition", "timeout", "target_exited"]) }),
    effects: fx({ mutatesSession: true }),
    cli: { tier: "scenario", reason: SESSION_STATE_REASON },
    examples: [],
  }),
  query_events: defineTool({
    name: "query_events",
    area: "instrument",
    phase: "P1",
    description: "Test double of query_events: summarizes or pages the events of one recording.",
    inputSchema: z.strictObject({
      session_id: sessionId.optional(),
      recording_id: z.string().min(1).max(64),
      view: z.enum(["summary", "rows"]).default("summary"),
    }),
    outputSchema: pollOutput({ view: z.string(), recording_id: z.string() }),
    effects: fx({ mutatesSession: true }),
    cli: { tier: "scenario", reason: SESSION_STATE_REASON },
    examples: [],
  }),
  stop_instrumentation: defineTool({
    name: "stop_instrumentation",
    area: "instrument",
    phase: "P1",
    description: "Test double of stop_instrumentation: stops recordings by id and finalizes their manifests.",
    inputSchema: z.strictObject({ session_id: sessionId, ids: z.array(z.string()).max(64).optional() }),
    outputSchema: pollOutput({ stopped: z.array(z.string()) }),
    effects: fx({ instrumentsTarget: true, mutatesSession: true }),
    returnsTargetContent: false,
    cli: { tier: "scenario", reason: SESSION_STATE_REASON },
    examples: [],
  }),
  emu_open: defineTool({
    name: "emu_open",
    area: "emulation",
    phase: "P2",
    description: "Test double of emu_open: opens an emulation session on an image or a live session's capture.",
    inputSchema: z
      .strictObject({ image_path: z.string().min(3).max(1024).optional(), live_session_id: sessionId.optional() })
      .refine((v) => (v.image_path === undefined) !== (v.live_session_id === undefined), {
        message: "Provide exactly one of image_path or live_session_id.",
      }),
    outputSchema: pollOutput({ session_id: sessionId, kind: z.literal("emulation") }),
    effects: fx({ readsTargetMemory: true, mutatesSession: true, idempotent: false }),
    sessionKinds: ["none"],
    cli: { tier: "scenario-target", reason: scenarioTarget },
    examples: [],
  }),
  emu_call: defineTool({
    name: "emu_call",
    area: "emulation",
    phase: "P2",
    description: "Test double of emu_call: calls a function of the emulated image with vectors from --input.",
    inputSchema: z.strictObject({
      session_id: sessionId,
      address: z.string().min(1).max(600).optional(),
      signature: z.string().min(1).max(256).optional(),
      vectors: z
        .array(z.strictObject({ args: z.array(z.number()) }))
        .max(1000)
        .optional(),
    }),
    outputSchema: pollOutput({ echo: z.record(z.string(), z.unknown()) }),
    effects: fx({ mutatesSession: true, idempotent: false }),
    sessionKinds: ["emulation"],
    cli: { tier: "emu-oneshot", command: "emulate", positional: ["address"] },
    examples: [],
  }),
  diff_function: defineTool({
    name: "diff_function",
    area: "emulation",
    phase: "P2",
    description: "Test double of diff_function: compares a live session and an emulation session on vectors.",
    inputSchema: z.strictObject({
      live_session_id: sessionId.optional(),
      emu_session_id: sessionId.optional(),
      address: z.string().min(1).max(600),
    }),
    outputSchema: pollOutput({ verdict: z.string(), echo: z.record(z.string(), z.unknown()) }),
    effects: fx({
      readsTargetMemory: true,
      writesTargetMemory: true,
      executesTargetCode: true,
      mutatesSession: true,
      idempotent: false,
    }),
    gate: { id: "call_attached", scope: "attached-targets" },
    sessionKinds: ["live", "emulation"],
    cli: { tier: "scenario", reason: "Needs two sessions; a scenario creates both with session-creating steps." },
    examples: [],
  }),
  export_evidence: defineTool({
    name: "export_evidence",
    area: "evidence",
    phase: "P1",
    description: "Test double of export_evidence: writes an evidence bundle and returns its path and digest.",
    inputSchema: z.strictObject({ session_id: sessionId.optional(), out_path: z.string().min(3).max(1024).optional() }),
    outputSchema: pollOutput({ path: z.string(), bytes: z.number().int().min(0), bundle_digest: z.string() }),
    effects: fx({ writesFilesystem: true, idempotent: false }),
    returnsTargetContent: false,
    cli: { tier: "oneshot", command: "evidence export", positional: [] },
    examples: [],
  }),
  get_evidence: defineTool({
    name: "get_evidence",
    area: "evidence",
    phase: "P1",
    description: "Test double of get_evidence: shows ledger records by id or summary filters.",
    inputSchema: z.strictObject({
      id: z.string().max(80).optional(),
      limit: z.number().int().min(1).max(500).default(50),
    }),
    outputSchema: pollOutput({ echo: z.record(z.string(), z.unknown()) }),
    effects: fx(),
    cli: { tier: "oneshot", command: "evidence show", positional: ["id"] },
    examples: [],
  }),
  record_unknown: defineTool({
    name: "record_unknown",
    area: "evidence",
    phase: "P2",
    description: "Test double of record_unknown: records an open question; interactive bookkeeping only.",
    inputSchema: z.strictObject({ question: z.string().min(8).max(500).optional() }),
    outputSchema: pollOutput({ unknown_id: z.string() }),
    effects: fx({ mutatesSession: true, idempotent: false }),
    returnsTargetContent: false,
    cli: { tier: "mcp-only", reason: "Interactive agent bookkeeping across calls; scenarios are planned ahead." },
    examples: [],
  }),
} as const;

export type FakeToolName = keyof typeof contracts;
export const FAKE_CONTRACTS: readonly ToolContract[] = Object.values(contracts);

export interface FakeCall {
  readonly tool: string;
  readonly input: Readonly<Record<string, unknown>>;
  /** ctx.signal.aborted at entry */
  readonly aborted: boolean;
}

export type FakeHandler = (
  input: Readonly<Record<string, unknown>>,
  ctx: HandlerContext,
) => Promise<Result<Readonly<Record<string, unknown>>, BeaError>>;

export interface FakeBackend {
  readonly contracts: readonly ToolContract[];
  readonly calls: FakeCall[];
  /** sessions opened by spawn/attach/emu_open, in order */
  readonly sessions: { readonly id: string; readonly by: string }[];
  readonly closed: string[];
  readonly createHandlers: (app: BeaApplication) => HandlerLookup;
  /** tools called, in order */
  readonly tools: () => string[];
}

const echo = (input: Readonly<Record<string, unknown>>) => ok({ echo: { ...input }, ...env });

/**
 * Handlers that record every call. Override any tool: `createFakeBackend({ wait: async () => ok({...}) })`. The real
 * bea_status handler is used for bea_status (it needs only the core).
 */
export const createFakeBackend = (overrides: Partial<Record<FakeToolName, FakeHandler>> = {}): FakeBackend => {
  const calls: FakeCall[] = [];
  const sessions: { id: string; by: string }[] = [];
  const closed: string[] = [];
  const open = (by: string) => {
    const id = randomUUID();
    sessions.push({ id, by });
    return id;
  };
  const defaults: Partial<Record<FakeToolName, FakeHandler>> = {
    spawn_process: async () => ok({ session_id: open("spawn_process"), state: "paused", ...env }),
    attach_process: async () => ok({ session_id: open("attach_process"), state: "running", ...env }),
    emu_open: async () => ok({ session_id: open("emu_open"), kind: "emulation", ...env }),
    resume_process: async () => ok({ state: "running", ...env }),
    close_session: async (input) => {
      closed.push(String(input["session_id"]));
      return ok({ session_id: input["session_id"], already_closed: false, ...env });
    },
    read_memory: async (input) => echo(input),
    map_address: async (input) => echo(input),
    run_script: async (input) => echo(input),
    emu_call: async (input) => echo(input),
    get_evidence: async (input) => echo(input),
    diff_function: async (input) => ok({ verdict: "equivalent-on-tested-inputs", echo: { ...input }, ...env }),
    hook_function: async () => ok({ instrument: { recording_id: "rec_0000abcd", kind: "hook" }, ...env }),
    wait: async () => ok({ satisfied: true, reason: "condition", ...env }),
    query_events: async (input) =>
      ok({ view: String(input["view"]), recording_id: String(input["recording_id"]), ...env }),
    stop_instrumentation: async (input) => ok({ stopped: (input["ids"] as string[] | undefined) ?? [], ...env }),
    export_evidence: async (input) =>
      ok({
        path: String(input["out_path"] ?? "C:\\bea\\exports\\bundle-1"),
        bytes: 1234,
        bundle_digest: "a".repeat(64),
        ...env,
      }),
    record_unknown: async () => ok({ unknown_id: `unk_${"0".repeat(64)}`, ...env }),
  };
  const table: Record<string, FakeHandler> = { ...defaults, ...overrides };
  return {
    contracts: FAKE_CONTRACTS,
    calls,
    sessions,
    closed,
    tools: () => calls.map((call) => call.tool),
    createHandlers: (app) => {
      const status = createSessionHandlers(app).bea_status;
      return (name) => {
        const handler = name === "bea_status" ? (status as unknown as FakeHandler) : table[name];
        if (handler === undefined) return undefined;
        return async (input, ctx) => {
          calls.push({ tool: name, input: { ...(input as Record<string, unknown>) }, aborted: ctx.signal.aborted });
          return handler(input as Readonly<Record<string, unknown>>, ctx);
        };
      };
    },
  };
};
