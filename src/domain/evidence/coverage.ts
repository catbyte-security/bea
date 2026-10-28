import { z } from "zod";

import type { DropReason } from "../../shared/agentProtocol.js";

/** Reason codes are registry-checked by a contract test (every emitted code is in REASONS). */
export const reasonCodeSchema = z.string().regex(/^[a-z][a-z0-9_]{1,47}$/u);

/**
 * S2 §7.5. `truncated` = some observed data was NOT retained (cap, drop, quota, redaction).
 * Paging is never truncation; absent knowledge is `unknown`, never `complete`.
 */
export const coverageSchema = z
  .strictObject({
    status: z.enum(["complete", "partial", "unknown"]),
    truncated: z.boolean(),
    dropped: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).exactOptional(),
    reasons: z.array(reasonCodeSchema).max(32),
  })
  .superRefine((c, ctx) => {
    if (c.status === "complete" && (c.truncated || (c.dropped ?? 0) > 0))
      ctx.addIssue({ code: "custom", message: "complete coverage cannot be truncated" });
    if (c.status !== "complete" && c.reasons.length === 0)
      ctx.addIssue({ code: "custom", message: "partial/unknown coverage needs a reason" });
    if (c.truncated && c.reasons.length === 0) ctx.addIssue({ code: "custom", message: "truncation needs a reason" });
  });
export type Coverage = z.infer<typeof coverageSchema>;

export const COMPLETE: Coverage = { status: "complete", truncated: false, reasons: [] };

/** Initial registry (S2 §7.5 + S5 §11.5 + S6). Key = code, value = limitation key in LIMITATIONS. */
export const REASONS = {
  unreadable_memory: "UNREADABLE_MEMORY",
  unreadable_ranges: "UNREADABLE_RANGES",
  string_cap: "CAP",
  frame_cap: "CAP",
  value_cap: "CAP",
  row_cap: "CAP",
  agent_buffer_full: "STREAM_DROPPED",
  agent_rate_limit: "STREAM_DROPPED",
  agent_payload_cap: "STREAM_DROPPED",
  flow_control: "STREAM_DROPPED",
  seq_gap: "STREAM_DROPPED",
  host_queue_full: "STREAM_DROPPED",
  stream_quota: "QUOTA",
  stream_total_quota: "QUOTA",
  blob_quota: "QUOTA",
  ledger_quota: "QUOTA",
  explicit_sensitive_value: "REDACTED",
  tail_unconfirmed: "TAIL_UNCONFIRMED",
  recording_active: "RECORDING_ACTIVE",
  process_exited: "ENDED_EARLY",
  detached: "ENDED_EARLY",
  cancelled: "ENDED_EARLY",
  deadline: "ENDED_EARLY",
  malformed_pe_directory: "PE_TABLE",
  pe_table_cap: "PE_TABLE",
  module_map_partial: "MODULE_MAP_PARTIAL",
  hle_imports_used: "EMU_HLE_IMPORTS",
  emulation_deviation: "EMU_DEVIATION",
  isa_guard_stop: "EMU_ISA_GUARD",
  entry_errors: "BATCH_ERRORS",
  unknown_completeness: "COMPLETENESS_UNKNOWN",
  // CI-I5: every agent DropReason has a registered code
  agent_memory: "STREAM_DROPPED",
  ring_overrun: "STREAM_DROPPED",
  torn_record: "STREAM_DROPPED",
  decode_error: "STREAM_DROPPED",
  per_api_cap: "CAP",
  stopped_early: "ENDED_EARLY",
  // revision (DESIGN Appendix C): reasons whose sentences live in area limitation files seeded by WP0
  watch_rate_limit: "WATCH_RATE_LIMIT",
  guard_suspended: "WATCH_SUSPEND_WINDOWS",
  callee_handlers_not_honoured: "CALL_SEH_UNAVAILABLE",
} as const;
export type ReasonCode = keyof typeof REASONS;

/** CI-I5: agent drop counters (S4 DropReason) -> coverage reason codes (EventPump, WP-SESS). */
export const DROP_REASON_CODES: { readonly [R in DropReason]: ReasonCode } = {
  buffer_full: "agent_buffer_full",
  flow_control: "flow_control",
  rate_limit: "agent_rate_limit",
  instrument_cap: "row_cap",
  agent_memory: "agent_memory",
  ring_overrun: "ring_overrun",
  torn_record: "torn_record",
  decode_error: "decode_error",
  stopped: "stopped_early",
  per_api_cap: "per_api_cap",
};

const RANK = { complete: 0, partial: 1, unknown: 2 } as const;

/** Worst status wins (unknown > partial > complete); OR truncated; sum dropped; union of reasons (sorted). */
export const mergeCoverage = (...items: readonly Coverage[]): Coverage => {
  let status: Coverage["status"] = "complete";
  let truncated = false;
  let dropped: number | undefined;
  const reasons = new Set<string>();
  for (const c of items) {
    if (RANK[c.status] > RANK[status]) status = c.status;
    truncated ||= c.truncated;
    if (c.dropped !== undefined) dropped = (dropped ?? 0) + c.dropped;
    for (const r of c.reasons) reasons.add(r);
  }
  if (status === "complete" && (truncated || (dropped ?? 0) > 0)) status = "partial";
  return { status, truncated, ...(dropped !== undefined ? { dropped } : {}), reasons: [...reasons].sort() };
};
