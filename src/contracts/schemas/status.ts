import { z } from "zod";

import { GATE_IDS } from "../../domain/gates.js";
import { pollOutput } from "./envelope.js";
import { sessionIdSchema } from "./primitives.js";

/** Owned by the sessions area; S1 seeds the shape bea_status needs. */
export const sessionSummarySchema = z.strictObject({
  session_id: sessionIdSchema,
  kind: z.enum(["live", "emulation"]),
  state: z.string().min(1).max(64),
  pid: z.number().int().min(0).max(4_294_967_295).nullable(),
  ownership: z.enum(["owned", "attached", "none"]),
  image: z.string().max(4096).nullable(),
  instance_id: z.string().max(80).nullable(),
  active_instruments: z.number().int().min(0).max(1_000_000),
  active_effects: z.number().int().min(0).max(1_000_000),
});

const gateStatusSchema = z.strictObject({
  enabled: z.boolean(),
  source: z.enum(["default", "config-file", "env"]),
  env: z.string(),
  enables: z.string(),
});

export const backendStatusSchema = z.strictObject({
  id: z.enum(["frida", "agent", "jobhost", "emulator"]),
  state: z.enum(["available", "not-loaded", "unavailable", "failed"]),
  version: z.string().max(64).nullable(),
  detail: z.string().max(512).nullable(),
});

/** CI-M17: EVID's contributor (usage of this run vs the quotas in limits.quotas_mb). */
export const storageStatusSchema = z.strictObject({
  run_dir: z.string().max(4096),
  usage_mb: z.strictObject({
    ledger: z.number().int().min(0),
    streams: z.number().int().min(0),
    blobs: z.number().int().min(0),
  }),
});

export const statusOutputSchema = pollOutput({
  server: z.strictObject({
    name: z.string(),
    version: z.string(),
    run_id: z.string(),
    pid: z.number().int().min(0).max(4_294_967_295),
    started_at: z.string(),
    transport: z.enum(["stdio", "http", "cli"]),
    platform: z.enum(["win32", "linux", "darwin"]),
    home: z.string(),
  }),
  gates: z.strictObject(
    Object.fromEntries(GATE_IDS.map((gate) => [gate, gateStatusSchema])) as {
      [G in (typeof GATE_IDS)[number]]: typeof gateStatusSchema;
    },
  ),
  limits: z.strictObject({
    max_wait_ms: z.number().int(),
    max_tool_call_ms: z.number().int(),
    recommended_client_tool_timeout_s: z.number().int(),
    max_response_bytes: z.number().int(),
    /** CT-B3: largest accepted serialized tool input (call-model tools); other tools accept less (tools/list) */
    max_tool_input_bytes: z.number().int(),
    max_live_sessions: z.number().int(),
    max_piped_targets: z.number().int(),
    max_emulation_sessions: z.number().int(),
    max_instruments_per_session: z.number().int(),
    debug_register_slots: z.number().int(),
    max_scans_per_session: z.number().int(),
    quotas_mb: z.strictObject({
      ledger: z.number().int(),
      ledger_reserve: z.number().int(),
      stream: z.number().int(),
      stream_total: z.number().int(),
      blobs: z.number().int(),
    }),
    anti_cheat_allowed: z.boolean(),
  }),
  backends: z.array(backendStatusSchema).max(16),
  sessions: z.array(sessionSummarySchema).max(64),
  /** null until the evidence runtime contributes (CI-M17) */
  storage: storageStatusSchema.nullable(),
  /**
   * BEA-authored notes from contributors, never target text (CT-I11: "A machine-wide anti-cheat service is running
   * (FACEITService); BEA refuses only targets that show anti-cheat signals themselves."; HTTP exposure; open gates).
   */
  notes: z.array(z.string().max(300)).max(16),
});
