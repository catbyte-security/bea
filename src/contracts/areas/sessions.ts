import { z } from "zod";

import { EFFECT_KINDS } from "../../domain/effects/effect.js";
import { hexSchema } from "../../domain/hex.js";
import { evIdSchema, fxIdSchema } from "../../domain/ids.js";
import { jsonObjectSchema } from "../../domain/json.js";
import { fx } from "../effects.js";
import { maybeRecordedOutput, pageSchema, pollOutput, recordedOutput } from "../schemas/envelope.js";
import { limitSchema, offsetSchema, sessionIdSchema } from "../schemas/primitives.js";
import {
  crashReportSchema,
  exitInfoSchema,
  identitySchema,
  instrumentStateSchema,
  scanIdSchema,
  visibleStateSchema,
} from "../schemas/shared.js";
import { statusOutputSchema } from "../schemas/status.js";
import { defineTool, SESSION_STATE_REASON, type ToolContract } from "../toolContract.js";

/**
 * Area: sessions (WP4-SESS, DESIGN §6.2 A). bea_status (S1 seed), list_processes, spawn_process, attach_process,
 * resume_process, session_status, close_session. Descriptions are S6 §4.1–§4.7 with the DESIGN edits: spawn_process
 * names the interpreter refusal (D-INT-42), close_session names `force`.
 */
const uint32 = z.number().int().min(0).max(4_294_967_295);
const sha256InputSchema = z
  .string()
  .regex(/^[0-9a-fA-F]{64}$/u)
  .describe("Expected sha256 of the image file (64 hex), e.g. from REA or Ghidra.");
const redactLiteralsSchema = z
  .array(z.string().min(4).max(256))
  .max(32)
  .default([])
  .describe("Session-wide sensitive strings (4..256 chars) redacted from evidence; only the count is kept.");

const SCENARIO_TARGET_REASON = "creates the session that scenario steps run in";
const SAMPLE_SESSION = "3f2b8c1e-4d5a-4e6f-9a0b-1c2d3e4f5a6b";

/** spawn/attach result (DESIGN §6.2 #3/#4). */
const startupOutput = recordedOutput({
  session_id: sessionIdSchema,
  identity: identitySchema,
  state: z.enum(["paused", "running"]),
  main_module: z.strictObject({
    name: z.string().max(260),
    base: hexSchema,
    preferred_base: hexSchema.nullable(),
    size: uint32,
  }),
  containment: z.strictObject({
    kind: z.enum(["win32-job", "posix-best-effort", "none"]),
    kill_on_close: z.boolean(),
    breakaway: z.literal(false),
    assigned_before_first_instruction: z.boolean(),
    helper_pid: uint32.nullable(),
    watch_helper_pid: uint32.nullable(),
  }),
  recordings: z.array(instrumentStateSchema.omit({ summary: true })).max(8),
  agent: z.strictObject({
    version: z.string().max(64),
    build_id: z.string().max(64),
    runtime: z.literal("qjs"),
    bundle_sha256: z.string().max(64),
  }),
  anti_cheat_signals: z.array(z.string().max(80)).max(32),
  environment: z
    .strictObject({
      mode: z.enum(["allowlist", "inherit"]),
      allowlist_version: z.literal(1),
      dropped_keys: uint32,
      caller_keys: uint32,
    })
    .nullable(),
});

const effectRowSchema = z.strictObject({
  effect: fxIdSchema,
  kind: z.enum(EFFECT_KINDS),
  target: z.string().max(600).nullable(),
  status: z.enum(["active", "revert-failed", "reverted", "expired", "implicit-end", "permanent"]),
  reversible: z.boolean(),
});

export const SESSION_TOOLS = [
  defineTool({
    name: "bea_status",
    area: "sessions",
    phase: "P1",
    title: "BEA Status",
    description:
      "Report BEA's own state without touching any target: server version and run id, which opt-in gates are enabled and how to enable them, fixed limits and quotas, backend availability (Frida binding and local device, jobhost, emulator bridge), and open sessions with their active instruments and effects. Call it first when a tool is unavailable.",
    inputSchema: z.strictObject({}),
    outputSchema: statusOutputSchema,
    effects: fx(),
    cli: { tier: "oneshot", command: "status", positional: [] },
    maxBlockingMs: 10_000,
    examples: [{ title: "Read server status", input: {} }],
  }),
  defineTool({
    name: "list_processes",
    area: "sessions",
    phase: "P1",
    description:
      "List local processes (pid, name, path, parent pid, start time, user) with an optional case-insensitive name filter, paged with a total. Host-side enumeration: never attaches or injects. Marks processes BEA already has a session on. Names and paths are target-controlled text. Only attach to a process the user named.",
    inputSchema: z.strictObject({
      filter: z.string().min(1).max(256).optional().describe("Case-insensitive substring of the name or path."),
      offset: offsetSchema,
      limit: limitSchema(500, 50),
    }),
    outputSchema: pollOutput({
      rows: z
        .array(
          z.strictObject({
            pid: uint32,
            name: z.string().max(260),
            path: z.string().max(1024).nullable(),
            ppid: uint32.nullable(),
            started: z.string().max(40).nullable(),
            user: z.string().max(256).nullable(),
            bea_session: sessionIdSchema.nullable(),
          }),
        )
        .max(500),
      page: pageSchema,
    }),
    effects: fx({ mutatesSession: true }),
    cli: { tier: "oneshot", command: "ps", positional: ["filter"] },
    maxBlockingMs: 15_000,
    examples: [
      { title: "List every process", input: {} },
      { title: "Find a process by name", input: { filter: "game_sim" } },
    ],
  }),
  defineTool({
    name: "spawn_process",
    area: "sessions",
    phase: "P1",
    description:
      "Launch a program as a BEA-owned target: created suspended inside a kill-on-close job (bea-jobhost), the BEA agent injected and ready-checked, then left PAUSED until resume_process so instruments can be installed before main runs. Returns session_id, identity (pid, start time, image sha256), main module and built-in recordings. close_session kills the whole job tree. Refuses 32-bit, protected and anti-cheat-guarded targets, and script interpreters or system tools unless the user allowed them. Max 4 live sessions, 3 capturing output.",
    inputSchema: z.strictObject({
      program: z.string().min(3).max(1024).describe("Absolute path of the .exe (not .bat/.cmd)."),
      args: z.array(z.string().max(8192)).max(256).default([]),
      cwd: z.string().min(3).max(1024).optional().describe("Working directory; default: the program's directory."),
      capture_output: z
        .boolean()
        .default(true)
        .describe("false: inherit the server's handles (no output recording, not counted in the 3-piped cap)."),
      env: z
        .array(
          z
            .string()
            .max(8192)
            .regex(/^[^=\s][^=]*=/u),
        )
        .max(64)
        .default([])
        .describe("KEY=VALUE entries added to the OS-allowlist environment; BEA_* keys are dropped."),
      expect_sha256: sha256InputSchema.optional(),
      redact_literals: redactLiteralsSchema,
    }),
    outputSchema: startupOutput,
    effects: fx({
      launchesProcess: true,
      suspendsTarget: true,
      injectsCode: true,
      mutatesSession: true,
      idempotent: false,
    }),
    cli: { tier: "scenario-target", reason: SCENARIO_TARGET_REASON },
    evidence: { predicate: "bea.process.instance", recorded: "always", identityExclude: ["env"] },
    errors: ["unsupported_target", "access_denied", "instance_mismatch", "file_operation_failed", "cleanup_incomplete"],
    maxBlockingMs: 60_000,
    examples: [
      { title: "Spawn a game paused", input: { program: "C:\\Games\\game_sim.exe" } },
      {
        title: "Spawn with arguments and no output capture",
        input: { program: "C:\\Tools\\app.exe", args: ["--frames", "600"], capture_output: false },
      },
    ],
  }),
  defineTool({
    name: "attach_process",
    area: "sessions",
    phase: "P1",
    description:
      "Attach to a running process the user named (pid or exact image name) and inject the BEA agent (frida-agent.dll plus ~24 system DLLs; 11 stay loaded after detach). Returns session_id and identity (pid, start time, image path and sha256). BEA never kills an attached target: close_session reverts BEA's instruments and detaches. Refuses system, protected, other-user, 32-bit and anti-cheat-guarded processes. Pass expect_sha256 when you know the static image hash.",
    inputSchema: z
      .strictObject({
        pid: z.number().int().min(1).max(4_294_967_295).optional(),
        name: z.string().min(1).max(260).optional().describe("Exact image file name, case-insensitive."),
        expect_sha256: sha256InputSchema.optional(),
        redact_literals: redactLiteralsSchema,
      })
      .superRefine((input, ctx) => {
        if ((input.pid === undefined) === (input.name === undefined))
          ctx.addIssue({
            code: "custom",
            path: ["pid"],
            message: 'Provide exactly one of pid or name. Example: {"pid":1234}',
          });
      }),
    outputSchema: startupOutput,
    effects: fx({ injectsCode: true, mutatesSession: true, idempotent: false }),
    cli: { tier: "scenario-target", reason: SCENARIO_TARGET_REASON },
    evidence: { predicate: "bea.process.instance", recorded: "always" },
    errors: ["unsupported_target", "access_denied", "instance_mismatch", "target_exited"],
    maxBlockingMs: 60_000,
    examples: [
      { title: "Attach by pid", input: { pid: 1234 } },
      { title: "Attach by image name", input: { name: "game_sim.exe" } },
    ],
  }),
  defineTool({
    name: "resume_process",
    area: "sessions",
    phase: "P1",
    description:
      "Resume a paused BEA-spawned target so its own code runs (main has not executed before this). Optionally block up to wait_ms until the process exits or every active instrument finishes; returns exit code, crash report and finished instrument summaries. Running out of wait_ms is not an error. Refused for attached targets (already running) and while instrument cleanup is pending.",
    inputSchema: z.strictObject({
      session_id: sessionIdSchema,
      wait_ms: z.number().int().min(0).max(60_000).default(0),
      until: z
        .enum(["any", "exit", "instruments_done"])
        .default("any")
        .describe("any: exit or every instrument active at call time finished; exit; instruments_done."),
    }),
    outputSchema: recordedOutput({
      state: z.enum(["running", "exited"]),
      waited_ms: z.number().int().min(0),
      exit: exitInfoSchema.nullable(),
      crash: crashReportSchema.nullable(),
      instruments: z.array(instrumentStateSchema).max(16),
    }),
    effects: fx({ executesTargetCode: true, mutatesSession: true, idempotent: false }),
    cli: { tier: "scenario", reason: SESSION_STATE_REASON },
    evidence: { predicate: "bea.process.instance", recorded: "always" },
    errors: ["target_exited", "invalid_state", "effect_unreverted"],
    maxBlockingMs: 75_000,
    examples: [
      { title: "Resume", input: { session_id: SAMPLE_SESSION } },
      { title: "Resume and wait for the exit", input: { session_id: SAMPLE_SESSION, wait_ms: 5000, until: "exit" } },
    ],
  }),
  defineTool({
    name: "session_status",
    area: "sessions",
    phase: "P1",
    description:
      "Report one session: liveness, ownership and containment, exit code with NTSTATUS name, crash report (faulting instruction, module+RVA, registers, backtrace) if the target died, active instruments and effects with remaining lifetime, recordings with event and drop counts, scans, output tail and module-map epoch. Also works on closed sessions (final state). Never changes the target.",
    inputSchema: z.strictObject({
      session_id: sessionIdSchema,
      detail: z
        .enum(["summary", "complete"])
        .default("summary")
        .describe("complete adds xmm registers to a crash and records bea.session.status evidence."),
    }),
    outputSchema: maybeRecordedOutput({
      session_id: sessionIdSchema,
      kind: z.enum(["live", "emulation"]),
      state: visibleStateSchema,
      identity: identitySchema.nullable(),
      exit: exitInfoSchema.nullable(),
      crash: crashReportSchema.nullable(),
      containment: z
        .strictObject({
          kind: z.enum(["win32-job", "posix-best-effort", "none"]),
          active_processes: uint32.nullable(),
          children_seen: z.array(uint32).max(64),
        })
        .exactOptional(),
      instruments: z.array(instrumentStateSchema.omit({ summary: true })).max(64),
      effects: z.array(effectRowSchema).max(64),
      scans: z
        .array(
          z.strictObject({
            scan_id: scanIdSchema,
            value_type: z.string().max(16),
            count: z.number().int().min(0),
            iteration: z.number().int().min(0),
            state: z.string().max(16),
          }),
        )
        .max(8),
      output_tail: z.string().max(2048).nullable(),
      module_map_epoch: z.number().int().min(0).nullable(),
      emulation: jsonObjectSchema.nullable(),
    }),
    effects: fx({ mutatesSession: true }),
    cli: { tier: "scenario", reason: SESSION_STATE_REASON },
    sessionKinds: ["live", "emulation"],
    evidence: { predicate: "bea.session.status", recorded: "detail-complete" },
    maxBlockingMs: 15_000,
    examples: [
      { title: "Session summary", input: { session_id: SAMPLE_SESSION } },
      { title: "Complete status with evidence", input: { session_id: SAMPLE_SESSION, detail: "complete" } },
    ],
  }),
  defineTool({
    name: "close_session",
    area: "sessions",
    phase: "P1",
    description:
      "End a session. Owned target: the whole job tree is killed first. Attached target: every BEA hook, watch, trace, override and write is reverted, the agent unloaded and the process detached and left running. Emulation: the emulator state is discarded. Recording manifests are finalized and evidence stays queryable. Reports per-effect revert status; a failed revert keeps the session for retry (effect_unreverted), and force:true detaches anyway. Closing a closed session returns its final state.",
    inputSchema: z.strictObject({
      session_id: sessionIdSchema,
      force: z
        .boolean()
        .default(false)
        .describe("Attached: continue past unreverted effects (reported revert-failed)."),
    }),
    outputSchema: maybeRecordedOutput({
      session_id: sessionIdSchema,
      already_closed: z.boolean(),
      target_state: z.enum(["killed", "detached-running", "exited", "unknown", "none"]),
      reverted: z
        .array(
          z.strictObject({
            effect: fxIdSchema,
            kind: z.enum(EFFECT_KINDS),
            status: z.enum(["reverted", "revert-failed", "implicit-end"]),
          }),
        )
        .max(256),
      exit: exitInfoSchema.nullable(),
      manifests: z.array(evIdSchema).max(64),
    }),
    effects: fx({ killsProcess: true, instrumentsTarget: true, mutatesSession: true }),
    cli: { tier: "scenario", reason: SESSION_STATE_REASON },
    sessionKinds: ["live", "emulation"],
    evidence: { predicate: "bea.process.exit", recorded: "always" },
    errors: ["effect_unreverted", "cleanup_incomplete"],
    maxBlockingMs: 30_000,
    examples: [
      { title: "Close a session", input: { session_id: SAMPLE_SESSION } },
      { title: "Detach despite unreverted effects", input: { session_id: SAMPLE_SESSION, force: true } },
    ],
  }),
] as const satisfies readonly ToolContract[];
