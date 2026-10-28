// =================================================================================================
// src/shared/agentLimits.ts — agent-side bounds (S4 §17). Shared so host validation == agent clamps.
// The host may lower any default in hello.limits; it may raise one only up to the hard cap.
// =================================================================================================
import type { AgentLimits } from "./agentProtocol.js";

const KiB = 1024;
const MiB = 1024 * KiB;
const GiB = 1024 * MiB;

export const AGENT_LIMIT_DEFAULTS: AgentLimits = {
  rpc_slice_ms: 20,
  job_slice_ms: 8,
  flush_ms: 50,
  batch_max_rows: 2000,
  batch_max_bin_bytes: 1 * MiB,
  stream_max_pending_rows: 20_000,
  stream_max_pending_bytes: 4 * MiB,
  max_streams: 64,
  flow_high_water_bytes: 32 * MiB,
  flow_low_water_bytes: 8 * MiB,
  max_instruments: 128,
  max_js_hooks: 256,
  max_native_hooks: 32,
  native_ring_records: 32_768,
  max_profile_api_hooks: 128,
  profile_events_per_api: 10_000,
  handle_cache_entries: 65_536,
  max_capture_args: 16,
  max_deref_depth: 8,
  max_string_chars: 1024,
  max_capture_bytes: 4096,
  max_backtrace_depth: 16,
  backtrace_per_sec: 100,
  max_duration_ms: 3_600_000,
  max_hits_cap: 10_000_000,
  page_guard_max_pages: 64,
  hwbp_verify_threads: 64,
  stalker_max_threads: 4,
  stalker_queue_capacity: 1 << 21,
  stalker_drain_ms: 50,
  stalker_max_blocks: 1 << 20,
  stalker_settle_ms: 300,
  scan_max_concurrent: 8,
  scan_max_candidates: 4_194_304,
  scan_snapshot_bytes: 256 * MiB,
  scan_page_rows: 1000,
  call_max_vectors: 1024,
  call_max_wall_ms: 50,
  call_scratch_bytes: 16 * MiB,
  call_buffer_bytes: 1 * MiB,
  call_coverage_blocks: 100_000,
  run_on_thread_timeout_ms: 2000,
  read_max_bytes: 1 * MiB,
  typed_max_reads: 256,
  write_max_bytes: 64 * KiB,
  disasm_max_insns: 2048,
  disasm_max_bytes: 64 * KiB,
  dump_chunk_bytes: 4 * MiB,
  dump_max_bytes: 2 * GiB,
  dump_max_concurrent: 1,
  list_page_max: 5000,
  snapshot_ttl_ms: 30_000,
  max_snapshots: 4,
  max_jobs: 8,
  agent_heap_soft_bytes: 256 * MiB,
};

export const AGENT_LIMIT_HARD: AgentLimits = {
  rpc_slice_ms: 50,
  job_slice_ms: 20,
  flush_ms: 1000,
  batch_max_rows: 10_000,
  batch_max_bin_bytes: 4 * MiB,
  stream_max_pending_rows: 100_000,
  stream_max_pending_bytes: 16 * MiB,
  max_streams: 128,
  flow_high_water_bytes: 256 * MiB,
  flow_low_water_bytes: 128 * MiB,
  max_instruments: 512,
  max_js_hooks: 1024,
  max_native_hooks: 64,
  native_ring_records: 262_144,
  max_profile_api_hooks: 256,
  profile_events_per_api: 1_000_000,
  handle_cache_entries: 262_144,
  max_capture_args: 32,
  max_deref_depth: 16,
  max_string_chars: 4096,
  max_capture_bytes: 65_536,
  max_backtrace_depth: 64,
  backtrace_per_sec: 1000,
  max_duration_ms: 3_600_000,
  max_hits_cap: 100_000_000,
  page_guard_max_pages: 256,
  hwbp_verify_threads: 256,
  stalker_max_threads: 8,
  stalker_queue_capacity: 1 << 22,
  stalker_drain_ms: 250,
  stalker_max_blocks: 1 << 22,
  stalker_settle_ms: 2000,
  scan_max_concurrent: 16,
  scan_max_candidates: 16_777_216,
  scan_snapshot_bytes: 1 * GiB,
  scan_page_rows: 4096,
  call_max_vectors: 1024,
  call_max_wall_ms: 1000,
  call_scratch_bytes: 256 * MiB,
  call_buffer_bytes: 16 * MiB,
  call_coverage_blocks: 1_000_000,
  run_on_thread_timeout_ms: 30_000,
  read_max_bytes: 4 * MiB,
  typed_max_reads: 1024,
  write_max_bytes: 1 * MiB,
  disasm_max_insns: 8192,
  disasm_max_bytes: 256 * KiB,
  dump_chunk_bytes: 16 * MiB,
  dump_max_bytes: 4 * GiB,
  dump_max_concurrent: 2,
  list_page_max: 20_000,
  snapshot_ttl_ms: 300_000,
  max_snapshots: 16,
  max_jobs: 16,
  agent_heap_soft_bytes: 1 * GiB,
};

/** Clamp a host-proposed partial limit set into [1, hard]; unknown keys are ignored. Used by host and agent. */
export const clampAgentLimits = (proposed: Partial<AgentLimits> | undefined): AgentLimits => {
  const out: AgentLimits = { ...AGENT_LIMIT_DEFAULTS };
  if (proposed === undefined) return out;
  for (const key of Object.keys(AGENT_LIMIT_DEFAULTS) as (keyof AgentLimits)[]) {
    const v = proposed[key];
    if (typeof v === "number" && Number.isFinite(v))
      out[key] = Math.max(1, Math.min(Math.floor(v), AGENT_LIMIT_HARD[key]));
  }
  if (out.flow_low_water_bytes > out.flow_high_water_bytes / 2)
    out.flow_low_water_bytes = Math.floor(out.flow_high_water_bytes / 2);
  return out;
};
