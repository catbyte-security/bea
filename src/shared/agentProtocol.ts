// =================================================================================================
// src/shared/agentProtocol.ts — BEA host <-> in-target agent wire contract.  Protocol "bea-agent/1".
// Pure types + constants. Imported by the host (tsc) and staged into the agent (frida.Compiler).
// Additive changes bump AGENT_PROTOCOL_MINOR; incompatible changes bump the major ("bea-agent/2").
// Source: S4-agent §4 (type-checked), with the DESIGN.md integration amendments marked "INTEGRATION" and the
// critique amendments marked CT-<id> / CI-<id> (DESIGN Appendix C). v0.1 is unreleased: minor stays 0.
// =================================================================================================
import type { Hex, HexBytes } from "./hex.js";
import type { PlanWire, RawBatchColumns, VectorsWire } from "./callPlan.js";
export type { Hex, HexBytes } from "./hex.js";

export const AGENT_PROTOCOL = "bea-agent/1" as const;
export const AGENT_PROTOCOL_MINOR = 0 as const;
export type AgentProtocol = typeof AGENT_PROTOCOL;

/* ------------------------------------------------------------------------------------------------
 * 4.1 Scalar encodings and ids
 * ---------------------------------------------------------------------------------------------- */
/** Agent-global event sequence: 1-based, strictly increasing over ALL rows of ALL streams (JS and native). */
export type Gseq = number;
/** Agent monotonic microseconds since agent load (native g_get_monotonic_time() minus t0). */
export type TimeUs = number;
export type ThreadId = number;
export type InstrumentId = string; // "h<n>" hook | "p<n>" profile set | "w<n>" watch | "t<n>" trace | "o<n>" override
export type StreamId = string; // "s<n>" | "s:exceptions" | "s:modules" | "s:threads" | "s:memmap"
export type JobId = string; // "j<n>"
export type ScanId = string; // "sc<n>"
export type BlobId = string; // "b<n>"
export type SnapshotId = string; // "ss<n>"
export type WriteId = string; // "wr<n>"
export type AckToken = string; // "crash-<n>" | "exit-<n>"

export type ValueType =
  | "i8"
  | "u8"
  | "i16"
  | "u16"
  | "i32"
  | "u32"
  | "i64"
  | "u64"
  | "ptr"
  | "bool8"
  | "bool32"
  | "f32"
  | "f64"
  | "utf8"
  | "utf16"
  | "ansi"
  | "bytes";

/** Scalar input: integer JS number (|v| ≤ 2^53-1), decimal or Hex string (exact 64-bit), boolean, or exact float bits. */
export type ScalarInput = number | string | boolean | { bits: Hex };

/** One captured value in a JSON row. Its meaning comes from the capture spec that produced it. */
export type ValueCell =
  | null // not captured (e.g. leave-only capture on an enter-only row)
  | number // i8..i32, u8..u32, bool8/bool32 (0|1)
  | Hex // i64/u64/ptr two's-complement bits; f32 bits (≤8 digits); f64 bits (≤16)
  | { s: string; trunc?: true } // utf8 / utf16 / ansi text
  | { x: HexBytes; trunc?: true } // bytes
  | { e: CaptureErr; a?: Hex } // capture failed at address a
  | ValueCell[]; // count > 1
export type CaptureErr = "av" | "guard" | "null" | "too_deep" | "unsupported";

/** Typed output used by results (not rows). Floats always carry exact bits. */
export interface TypedOut {
  type: ValueType;
  value: number | string | boolean | null; // f32/f64: number or "NaN"|"Infinity"|"-Infinity"; 64-bit ints: decimal string
  bits?: Hex; // f32/f64 (and i64/u64 raw bits)
  hex?: HexBytes; // bytes, or raw bytes of strings
  trunc?: boolean;
}

export interface Paged<T> {
  total: number;
  offset: number;
  items: T[];
  next_offset: number | null;
}
/**
 * CI-I3: clock "resume" (sent by the host when the session is still paused) arms the duration timer at the host's
 * {type:"resumed"} post instead of at install, so an instrument installed before resume_process covers its full window.
 */
export interface Lifetime {
  duration_ms: number;
  max_hits: number;
  clock?: "install" | "resume";
}

/* ------------------------------------------------------------------------------------------------
 * 4.2 Results and errors (plain data, tagged)
 * ---------------------------------------------------------------------------------------------- */
export type AgentResult<T> = { ok: true; value: T } | { ok: false; error: AgentError };

export type GateName = "write_memory" | "override_function" | "call_function";
export type AgentResource =
  | "agent_memory"
  | "instruments"
  | "streams"
  | "native_hooks"
  | "rows"
  | "scan_candidates"
  | "scan_snapshot"
  | "scans"
  | "jobs"
  | "stalker_threads"
  | "page_guard_pages"
  | "call_vectors"
  | "scratch"
  | "blob_bytes"
  | "snapshots";

interface E<T extends string> {
  _tag: T;
  message: string;
}
export type AgentError =
  | (E<"BadParams"> & { issues: { path: string; problem: string }[] })
  | E<"NotReady">
  | (E<"ProtocolMismatch"> & { expected: string; got: string; agent_minor: number })
  | E<"ShuttingDown">
  | (E<"GateClosed"> & { gate: GateName })
  | (E<"AccessViolation"> & { address: Hex; operation: "read" | "write" | "execute" | null; partial_bytes?: number })
  | (E<"GuardPage"> & { address: Hex; owner: "bea" | "target" })
  | (E<"ModuleNotFound"> & { module: string })
  | (E<"ExportNotFound"> & { module: string; export: string })
  | (E<"NoFunctionRange"> & { address: Hex })
  | (E<"NotExecutable"> & { address: Hex; protection: string | null })
  | (E<"HookDenied"> & {
      address: Hex;
      api: string;
      reason: "deadlock-risk" | "agent-critical" | "caution-requires-force";
      alternatives: string[];
    })
  | (E<"HookInstallFailed"> & {
      address: Hex;
      attempts: ("default" | "forced")[];
      frida_message: string;
      alternatives: string[];
    })
  | (E<"HookConflict"> & { address: Hex; existing: InstrumentId; kind: "replace" | "override" })
  | (E<"NoFreeDebugRegister"> & {
      in_use: { slot: number; owner: InstrumentId | "quarantined"; kind: "watch" | "exec" }[];
    })
  | (E<"WatchInvalid"> & {
      reason: "slot" | "size" | "alignment" | "access" | "range" | "stack-page" | "module-code" | "agent-page";
    })
  /**
   * The thread is followed by `owner` (state "followed", retry_after_ms 0) or still settling after `owner` unfollowed it
   * (state "settling", retry after retry_after_ms). Owner "call" is reserved: per-call coverage follows the agent
   * thread without the coordinator, so the agent never reports it (review fix AGENT-12).
   */
  | (E<"StalkerBusy"> & {
      thread_id: ThreadId;
      owner: InstrumentId | "call";
      retry_after_ms: number;
      state?: "followed" | "settling";
    })
  /** CT-I1: callFunction {thread}: the sampled RIP is inside an ntdll syscall stub (runOnThread would run late) */
  | (E<"ThreadBusy"> & { thread_id: ThreadId; reason: "in-syscall" | "suspended" })
  | (E<"NotFound"> & { what: "instrument" | "scan" | "job" | "snapshot" | "write" | "thread" | "blob"; id: string })
  | (E<"WriteConflict"> & { write_id: WriteId; address: Hex; expected: HexBytes; actual: HexBytes })
  /**
   * started (callFunction thread/hook modes): true when the callee had already started on the thread when the timeout
   * expired: it is still running there and its effects may have happened (review fix AGENT-1); false when it never ran.
   */
  | (E<"Timeout"> & { timeout_ms: number; phase: string; started?: boolean })
  | (E<"Cancelled"> & { phase: string })
  | (E<"ResourceLimit"> & { resource: AgentResource; limit: number; observed?: number })
  | (E<"Unsupported"> & { feature: string; reason: string })
  | (E<"Internal"> & { where: string; frida_message?: string });
export type AgentErrorTag = AgentError["_tag"];

/* ------------------------------------------------------------------------------------------------
 * 4.3 Handshake and session configuration
 * ---------------------------------------------------------------------------------------------- */
export type AgentFeature =
  | "hooks.js"
  | "hooks.native"
  | "hooks.native.xmm"
  | "profiles"
  | "watch.debug-register"
  | "watch.page-guard"
  | "stalker"
  | "call"
  | "override"
  | "scan"
  | "dump"
  | "crash.first-chance"
  | "crash.last-chance"
  | "exit-flush";

export interface ReadyMessage {
  bea: "ready";
  protocol: AgentProtocol;
  protocol_minor: number;
  agent_version: string;
  build_id: string;
  frida_version: string;
  runtime: "QJS" | "V8";
  pid: number;
  arch: string;
  platform: string;
  js_thread_id: ThreadId;
  t0_wall_ms: number;
  features: AgentFeature[];
  early: { exception_handler: true; exit_hook: boolean; last_chance_hook: boolean; module_observer: boolean };
}
export interface FatalMessage {
  bea: "fatal";
  stage: "platform" | "cmodule" | "exception-handler" | "core-hooks" | "events" | "modules" | "features" | "rpc";
  error: AgentError;
}

export type ExceptionType =
  | "abort"
  | "access-violation"
  | "guard-page"
  | "illegal-instruction"
  | "stack-overflow"
  | "arithmetic"
  | "breakpoint"
  | "single-step"
  | "system";

export interface CrashPolicy {
  first_chance_rows: boolean; // record non-BEA exceptions on s:exceptions (default true)
  /**
   * Blocking report for crash_class at first chance (default false, opt-in: BEA-FEEDBACK #4). The report runs on the
   * faulting thread, which may hold the target's own locks (ASan's allocator commits shadow memory from its exception
   * handler; JITs and drivers probe memory under SEH), and waits for the host's ack. The last-chance (UEF) report is
   * always on.
   */
  first_chance_blocking: boolean;
  /**
   * default ["access-violation","illegal-instruction","stack-overflow","arithmetic","abort"]. "system" (every code
   * Frida does not map: C++ throws, OutputDebugString, thread naming, RPC errors) is not in the default (review fix
   * AGENT-11); an unhandled one is still reported at last chance with its NTSTATUS. Even when a host lists "system", a
   * first-chance exception raised through KERNELBASE!RaiseException (software, normally handled) is only a row.
   */
  crash_class: ExceptionType[];
  ack_timeout_ms: number; // first-chance blocking report wait (default 1000, max 5000)
  last_chance_ack_timeout_ms: number; // UEF + exit + self-terminate (default 2000, max 5000)
  max_blocking_per_10s: number; // rate limit for first-chance blocking reports (default 8, max 64)
  rows_per_sec: number; // first-chance row cap; excess folded into repeat counts (default 1000)
  stack_bytes: number; // stack window in reports (default 256, max 4096)
  backtrace_depth: number; // unwound frames (ntdll RtlVirtualUnwind, never dbghelp) (default 32, max 64)
  include_xmm: boolean; // xmm0..15 bits in reports (default false)
  /**
   * Module file-name patterns (case-insensitive, `*` = any run of characters; at most 32 of at most 128 characters,
   * no path separators) whose first-chance exceptions pass through: an exception whose pc lies in a matching module
   * returns false at once, with no row and no report (the agent counts it). ASan's runtime (`clang_rt.asan*.dll`) and
   * access violations inside ASan's shadow memory always pass through. Unhandled ones still reach the last-chance
   * report. Absent (older hosts) = [].
   */
  passthrough_modules?: string[];
}

export interface HelloParams {
  protocol: AgentProtocol;
  min_minor: number;
  host: { name: "bea"; version: string };
  session: { session_id: string; instance_id: string; owned: boolean };
  gates: Record<GateName, boolean>; // host-computed effective gates (call_function: owned || opt-in)
  limits?: Partial<AgentLimits>; // clamped by the agent to AGENT_LIMIT_HARD
  crash: CrashPolicy;
  streams: { flush_ms: number; exceptions: boolean; threads: boolean }; // s:modules is always on (address reconstruction)
  flow: { high_water_bytes: number; low_water_bytes: number };
}
export interface HelloResult {
  protocol: AgentProtocol;
  protocol_minor: number;
  agent_version: string;
  build_id: string;
  frida_version: string;
  runtime: "QJS" | "V8";
  process: ProcessInfo;
  limits: AgentLimits; // effective (after clamping)
  features: AgentFeature[];
  deny_list: { api: string; va: Hex; reason: "deadlock-risk" | "agent-critical" }[];
  caution_list: { api: string; va: Hex }[];
  system_streams: { exceptions: StreamId | null; modules: StreamId; threads: StreamId | null };
  module_map_epoch: number;
  boot: { t_us: number; early_rows: number }; // rows recorded before hello (e.g. module loads, early exceptions)
}

/* ------------------------------------------------------------------------------------------------
 * 4.4 Limits (values in agentLimits.ts, §17)
 * ---------------------------------------------------------------------------------------------- */
export interface AgentLimits {
  rpc_slice_ms: number;
  job_slice_ms: number;
  flush_ms: number;
  batch_max_rows: number;
  batch_max_bin_bytes: number;
  stream_max_pending_rows: number;
  stream_max_pending_bytes: number;
  max_streams: number;
  flow_high_water_bytes: number;
  flow_low_water_bytes: number;
  max_instruments: number;
  max_js_hooks: number;
  max_native_hooks: number;
  native_ring_records: number;
  max_profile_api_hooks: number;
  profile_events_per_api: number;
  handle_cache_entries: number;
  max_capture_args: number;
  max_deref_depth: number;
  max_string_chars: number;
  max_capture_bytes: number;
  max_backtrace_depth: number;
  backtrace_per_sec: number;
  max_duration_ms: number;
  max_hits_cap: number;
  page_guard_max_pages: number;
  hwbp_verify_threads: number;
  stalker_max_threads: number;
  stalker_queue_capacity: number;
  stalker_drain_ms: number;
  stalker_max_blocks: number;
  stalker_settle_ms: number;
  scan_max_concurrent: number;
  scan_max_candidates: number;
  scan_snapshot_bytes: number;
  scan_page_rows: number;
  call_max_vectors: number;
  call_max_wall_ms: number;
  call_scratch_bytes: number;
  call_buffer_bytes: number;
  call_coverage_blocks: number;
  run_on_thread_timeout_ms: number;
  read_max_bytes: number;
  typed_max_reads: number;
  write_max_bytes: number;
  disasm_max_insns: number;
  disasm_max_bytes: number;
  dump_chunk_bytes: number;
  dump_max_bytes: number;
  dump_max_concurrent: number;
  list_page_max: number;
  snapshot_ttl_ms: number;
  max_snapshots: number;
  max_jobs: number;
  agent_heap_soft_bytes: number;
}

/* ------------------------------------------------------------------------------------------------
 * 4.5 Shared descriptive types
 * ---------------------------------------------------------------------------------------------- */
export type TargetRef = { va: Hex } | { module: string; rva: Hex } | { module: string; export: string };

export interface FunctionRange {
  base: Hex;
  size: number;
  source: "pdata";
}
export interface ResolvedTarget {
  va: Hex;
  module: string | null;
  module_base: Hex | null;
  rva: Hex | null;
  export: string | null;
  function: FunctionRange | null;
  protection: string | null;
}
export interface PeFacts {
  machine: number;
  time_date_stamp: number;
  size_of_image: number;
  checksum: number;
  entry_rva: Hex;
  subsystem: number;
  dll_characteristics: number;
  mapped_image_base: Hex; // in-memory OptionalHeader.ImageBase (loader rewrites it = base) [ext-frida §3.14]
  section_count: number;
  codeview: { guid: string; age: number; pdb: string } | null; // RSDS from the in-memory debug directory
  tls_callbacks: Hex[]; // VAs from IMAGE_TLS_DIRECTORY64.AddressOfCallBacks
  pdata_entries: number;
}
export interface ModuleInfo {
  name: string;
  path: string;
  base: Hex;
  size: number;
  pe: PeFacts | null;
}
export interface ProcessInfo {
  pid: number;
  arch: "x64";
  platform: "windows" | "linux" /* CI-M16: Linux best effort */;
  page_size: number;
  pointer_size: 8;
  main_module: ModuleInfo;
  peb: Hex | null;
  current_dir: string;
  debugger_present: boolean;
  code_signing_policy: string;
  frida_heap_bytes: number;
  js_thread_id: ThreadId;
  module_map_epoch: number;
}
export interface EffectHint {
  kind:
    | "hook-installed"
    | "profile-installed"
    | "watchpoint-set"
    | "breakpoint-set"
    | "guard-page-set"
    | "stalker-followed"
    | "memory-written"
    | "override-installed"
    | "function-called";
  reversible: boolean;
  targets: { address: Hex | null; size: number | null }[];
  thread_ids: ThreadId[] | null;
  before: { address: Hex; hex: HexBytes }[]; // original bytes for patches/writes (≤ 64 B each, ≤ 64 entries)
}

export type DropReason =
  | "buffer_full"
  | "flow_control"
  | "rate_limit"
  | "instrument_cap"
  | "agent_memory"
  | "ring_overrun"
  | "torn_record"
  | "decode_error"
  | "stopped"
  | "per_api_cap";
export type DropCounters = Partial<Record<DropReason, number>>;
export type EndReason =
  | "requested"
  | "duration"
  | "max_hits"
  | "max_events"
  | "error"
  | "process-exit"
  | "module-unloaded"
  | "shutdown"
  | "thread-exit"
  | "rate-limit" // CT-I4: page-guard rate valve disarmed in the handler
  | "invocations"; // on_call trace: the requested invocations completed (review fix UX-11; was reported as max_hits)

/* ------------------------------------------------------------------------------------------------
 * 4.6 Event rows (JSON tuples) and binary layouts
 * ---------------------------------------------------------------------------------------------- */
export type RowKind =
  | "hook/1"
  | "api/1"
  | "watch/1"
  | "poll/1"
  | "exception/1"
  | "module/1"
  | "thread/1"
  | "override/1"
  | "memmap/1" // JSON
  | "hook-native/1"
  | "block-span/1"
  | "block-count/1"
  | "call-site-count/1"
  | "gum-event-x64/1"; // binary
export type LayoutId = "hook-native/1" | "block-span/1" | "block-count/1" | "call-site-count/1" | "gum-event-x64/1";
/** Backtrace frame as emitted in rows: "<module>+0x<rva>" when inside a module (ModuleMap at capture time), else the bare VA "0x…". */
export type FrameRef = string;

/** JS-tier hook call. phase: 1 = emitted at enter (emit:"enter"); 2 = full call emitted at leave (args + ret). Calls whose leave is never
 *  seen (longjmp/unwind past the frame) produce no row when emit:"leave"; they are counted in InstrumentCounters.unreturned.
 *  Phase-2 rows carry `regs.t_leave` (Hex µs since agent load; the call duration is t_leave - t) next to the GPR dump
 *  of registers:"gpr" (integrator note, implement stage: the duration the HookSummary reports). */
export type HookRow = [
  g: Gseq,
  t: TimeUs,
  tid: ThreadId,
  phase: 1 | 2,
  depth: number,
  caller: Hex,
  args: ValueCell[],
  ret: ValueCell | null,
  bt: FrameRef[] | null,
  regs: Record<string, Hex> | null,
];
/** API profile call (one row per completed call; noreturn APIs emit at enter). args keyed by ApiArgSpec.name. */
export type ApiRow = [
  g: Gseq,
  t: TimeUs,
  tid: ThreadId,
  depth: number,
  parent: Gseq /* 0 = none */,
  api: number /* ApiSpec.id */,
  args: Record<string, ValueCell>,
  ret: ValueCell,
  caller: Hex,
];
/** Watch hit. insn = the accessing instruction; insn_conf says how it was obtained. */
export type WatchRow = [
  g: Gseq,
  t: TimeUs,
  tid: ThreadId,
  watch: InstrumentId,
  access: "r" | "w" | "x",
  insn: Hex | null,
  insn_conf: "exact" | "swept" | "heuristic" | "unknown",
  pc_after: Hex | null,
  text: string | null,
  addr: Hex | null,
  before: HexBytes | null,
  after: HexBytes | null,
  regs: Record<string, Hex> | null,
  bt: FrameRef[] | null,
  mem: WatchMemOperand | null, // CI-M12: decoded with Instruction.parse; null when insn is unknown
];
/** CI-M12: the memory operand of the accessing instruction (struct_base = value(base) [+ value(index) * scale]). */
export interface WatchMemOperand {
  base: string | null;
  index: string | null;
  scale: 1 | 2 | 4 | 8;
  disp: number;
  size: number;
  base_value: Hex | null; // register value at the access (pre-instruction for exact hits)
  base_written: boolean; // the instruction also writes `base` (struct_base then comes from pc_after context)
}
export type ExceptionRow = [
  g: Gseq,
  t: TimeUs,
  tid: ThreadId,
  type: ExceptionType,
  address: Hex,
  mem_op: "read" | "write" | "execute" | null,
  mem_addr: Hex | null,
  /** CT-B1: "in-call" = raised inside a BEA oracle call on this thread; passed on to the callee's own handlers and,
   *  if none handles it, to the call thunk's SEH frame; never a blocking crash report */
  disposition: "passed" | "reported" | "in-call",
  repeat: number,
];
/** INTEGRATION: poll watch change row (one per changed element). */
export type PollRow = [g: Gseq, t: TimeUs, offset: number, old: HexBytes, now: HexBytes];
export type ModuleRow = [
  g: Gseq,
  t: TimeUs,
  ev: "L" | "U",
  name: string,
  path: string,
  base: Hex,
  size: number,
  epoch: number,
];
export type ThreadRow = [g: Gseq, t: TimeUs, ev: "S" | "E", tid: ThreadId, entry: Hex | null];
/** @public */
export type OverrideRow = [
  g: Gseq,
  t: TimeUs,
  tid: ThreadId,
  override: InstrumentId,
  applied: "args" | "ret" | "replace",
  detail: ValueCell[],
];
/** @public */
export type MemmapRow = [
  g: Gseq,
  t: TimeUs,
  ev: "new-exec" | "new-rwx" | "gone" | "prot-change",
  base: Hex,
  size: number,
  protection: string,
  module: string | null,
];

export interface BinaryField {
  name: string;
  offset: number;
  type: "u8" | "u16" | "u32" | "i32" | "u64";
}
export interface BinaryLayout {
  id: LayoutId;
  rec_bytes: number;
  endian: "le";
  fields: BinaryField[];
  notes: string;
}

/* ------------------------------------------------------------------------------------------------
 * 4.7 Agent -> host messages
 * ---------------------------------------------------------------------------------------------- */
/**
 * INTEGRATION (stream announcement rule): a stream created inside an RPC is flushable only after that RPC's reply
 * has been produced, so the host always learns a stream id (install result or HelloResult.system_streams) before its
 * first batch. The host still parks batches for unknown ids (≤ 256 KiB, ≤ 2 s) and then counts them as dropped.
 */
interface BatchBase {
  bea: "batch";
  stream: StreamId;
  instrument: InstrumentId | null;
  bseq: number;
  kind: RowKind;
  n: number;
  g0: Gseq;
  g1: Gseq;
  t0: TimeUs;
  t1: TimeUs;
  dropped: DropCounters; // delta since the previous batch of this stream
  final: boolean; // last batch of a stopped stream
}
export interface JsonBatchMessage extends BatchBase {
  enc: "json";
  rows: unknown[];
} // rows: RowOf<kind>[]
export interface BinBatchMessage extends BatchBase {
  enc: "bin";
  layout: LayoutId;
  rec_bytes: number;
} // + data = n*rec_bytes
export type BatchMessage = JsonBatchMessage | BinBatchMessage;

export interface BlobMessage {
  // + data (≤ dump_chunk_bytes)
  bea: "blob";
  blob: BlobId;
  job: JobId | null;
  part: number;
  offset: number;
  bytes: number;
  last: boolean;
  total: number | null;
  sha256?: Hex; // sha256 advisory, on the last part only (host recomputes)
}
export type JobKind = "scan-first" | "scan-next" | "dump";
export interface Progress {
  done: number;
  total: number | null;
  unit: "bytes" | "items";
}
export interface JobMessage {
  bea: "job";
  job: JobId;
  kind: JobKind;
  state: "done" | "failed" | "cancelled";
  progress: Progress;
  result?: ScanStatus | DumpManifest;
  error?: AgentError;
}
export interface InstrumentMessage {
  bea: "instrument";
  id: InstrumentId;
  event: "ended" | "degraded" | "lazy-installed";
  detail: InstrumentSummary | { apis: string[] } | { reason: string };
}
export interface CrashReport {
  report_id: string;
  phase: "first-chance" | "last-chance";
  g: Gseq;
  t: TimeUs;
  tid: ThreadId;
  type: ExceptionType;
  code: Hex | null; // NTSTATUS: last-chance only (first-chance details carry no code) [ext-frida §3.11]
  address: Hex; // faulting instruction (ExceptionAddress / details.address)
  memory: { operation: "read" | "write" | "execute"; address: Hex } | null;
  exception_information: Hex[]; // last-chance EXCEPTION_RECORD.ExceptionInformation[0..n)
  registers: Record<
    | "rax"
    | "rbx"
    | "rcx"
    | "rdx"
    | "rsi"
    | "rdi"
    | "rbp"
    | "rsp"
    | "r8"
    | "r9"
    | "r10"
    | "r11"
    | "r12"
    | "r13"
    | "r14"
    | "r15"
    | "rip",
    Hex
  >;
  eflags: Hex | null;
  mxcsr: Hex | null;
  fpcw: Hex | null;
  xmm: Hex[] | null; // 16 × 128-bit as 32-hex-digit Hex, when policy.include_xmm
  instruction: { address: Hex; bytes: HexBytes; text: string } | null;
  /** [faulting pc, ...return addresses] unwound from the exception's CONTEXT by ntdll's RtlVirtualUnwind (no dbghelp) */
  backtrace: { va: Hex; module: string | null; rva: Hex | null }[];
  /** "uef-context" (dbghelp from inside the UEF call) is no longer produced; kept for recorded evidence */
  backtrace_source: "exception-context" | "first-chance-cache" | "uef-context";
  stack: { address: Hex; hex: HexBytes } | null;
  module_map_epoch: number;
  flushed: { streams: number; rows: number };
}
export interface CrashMessage {
  bea: "crash";
  ack: AckToken;
  report: CrashReport;
}
export interface ExitMessage {
  bea: "exit";
  ack: AckToken;
  via: "RtlExitUserProcess" | "NtTerminateProcess(self)";
  exit_code: number;
  tid: ThreadId;
  g: Gseq;
  t: TimeUs;
  flushed: { streams: number; rows: number };
}
export interface FaultMessage {
  bea: "fault";
  where: string;
  error: AgentError;
  count: number;
} // rate-limited internal faults
export interface NoticeMessage {
  bea: "notice";
  code: "flow-shedding-on" | "flow-shedding-off" | "instrument-interference" | "hwbp-unreverted" | "heap-soft-limit";
  detail: Record<string, unknown>;
}
/** @public */
export type AgentMessage =
  | ReadyMessage
  | FatalMessage
  | BatchMessage
  | BlobMessage
  | JobMessage
  | InstrumentMessage
  | CrashMessage
  | ExitMessage
  | FaultMessage
  | NoticeMessage;

/* ------------------------------------------------------------------------------------------------
 * 4.8 Host -> agent posts (script.post)
 * ---------------------------------------------------------------------------------------------- */
export type HostPost =
  | { type: "ack"; token: AckToken } // releases a crash/exit waiter
  | { type: "flow"; received_bytes: number } // cumulative payload bytes durably received by the host
  | { type: "resumed" }; // CI-I3: posted by WP-SESS right after the target is resumed

/* ------------------------------------------------------------------------------------------------
 * 4.9 RPC params / results by area
 * ---------------------------------------------------------------------------------------------- */
// ---- core
export interface PingResult {
  t: TimeUs;
  g: Gseq;
  phase: "loaded" | "ready" | "shutting-down";
}
export interface StatusParams {
  detail: "summary" | "full";
}
export interface StreamInfo {
  id: StreamId;
  instrument: InstrumentId | null;
  kind: RowKind;
  enc: "json" | "bin";
  state: "open" | "closing" | "closed";
  recorded: number;
  sent_rows: number;
  batches: number;
  pending_rows: number;
  dropped: DropCounters;
}
export interface InstrumentCounters {
  hits: number;
  recorded: number;
  sampled_out: number;
  filtered: number;
  agent_calls_suppressed: number;
  unreturned: number;
  errors: number;
  dropped: DropCounters;
  /** CT-I5: page-guard watches: windows where BEA suspended its own guard for an agent access path (scan slice, read,
   *  capture deref, dump chunk, call vector) or re-armed after a stolen guard-page; accesses inside are unobserved */
  bea_guard_suspended: number;
}
export interface InstrumentInfo {
  id: InstrumentId;
  kind: "hook" | "profile" | "watch" | "trace" | "override";
  label: string | null;
  state: "active" | "stopping" | "ended";
  stream: StreamId | null;
  created_t: TimeUs;
  deadline_t: TimeUs | null;
  max_hits: number;
  counters: InstrumentCounters;
  targets: Hex[];
}
export interface InstrumentSummary extends InstrumentInfo {
  end_reason: EndReason | null;
  ended_t: TimeUs | null;
  reverted: boolean;
  verification: { kind: "bytes" | "dr7" | "protection"; ok: boolean; detail: string } | null;
}
export interface AgentStatus {
  phase: "loaded" | "ready" | "shutting-down";
  t: TimeUs;
  g: Gseq;
  module_map_epoch: number;
  instruments: InstrumentInfo[];
  streams: StreamInfo[];
  jobs: JobInfo[];
  scans: ScanStatus[];
  flow: { sent_bytes: number; received_bytes: number; inflight: number; shedding: boolean; shed_rows: number };
  exceptions: {
    by_type: Partial<Record<ExceptionType, number>>;
    blocking_reports: number;
    last_chance: number;
    bea_traps: number;
    in_call: number; // CT-B1: first-chance exceptions inside oracle calls
    /** CT-I4: leaked native VEH that swallows stray BEA DR/TF/guard traps after unload (attached sessions) */
    safety_net: "none" | "installed";
  };
  /** CT-I1: oracle-call bookkeeping (runOnThread closures can run after the host gave up) */
  calls: {
    active: { tid: ThreadId; token: number }[];
    expired_closures: number; // chunks whose thread closure had not run when the RPC timed out
    late_runs: number; // expired closures that ran later and returned without calling (no-op)
    quarantined_blocks: number; // CallBlock+scratch held until their closure ran or the session ends
  };
  memory: { frida_heap_bytes: number; native_bytes: number; scan_bytes: number; ring_bytes: number };
  rpc: { calls: number; slow: { method: string; us: number }[] }; // slow = slices over rpc_slice_ms (last 16)
  faults: number;
  debug_registers: { slot: number; owner: InstrumentId | "quarantined" | null }[];
}
export interface FlushParams {
  streams?: StreamId[];
}
export interface FlushResult {
  batches: number;
  rows: number;
}
export interface ShutdownParams {
  revert: boolean;
  timeout_ms: number;
}
export interface ShutdownResult {
  stopped: InstrumentSummary[];
  unreverted: { id: InstrumentId; detail: string }[];
  scans_freed: number;
  jobs_cancelled: number;
  final_batches: number;
}
export interface Fingerprint {
  t: TimeUs;
  patches: { owner: string; address: Hex; expected_head: HexBytes; actual_head: HexBytes; ok: boolean }[];
  debug_registers: { tid: ThreadId; dr7: Hex; ok: boolean }[]; // sampled ≤ hwbp_verify_threads
  guard_pages: { page: Hex; guarded: boolean; ok: boolean }[];
  stalker_threads: ThreadId[];
}

// ---- inspection
export interface ListModulesParams {
  name_glob?: string;
  with_pe: boolean;
}
export interface ListModulesResult {
  module_map_epoch: number;
  modules: ModuleInfo[];
}
export interface ListExportsParams {
  module: string;
  name_glob?: string;
  kind?: "function" | "variable";
  offset: number;
  limit: number;
}
export interface ExportRow {
  name: string;
  kind: "function" | "variable";
  va: Hex;
  rva: Hex;
}
export interface ListImportsParams {
  module: string;
  name_glob?: string;
  offset: number;
  limit: number;
}
export interface ImportRow {
  name: string | null;
  ordinal: number | null;
  from_module: string | null;
  kind: "function" | "variable" | null;
  slot: Hex | null;
  resolved: Hex | null;
  delay: boolean;
}
export interface ListSectionsParams {
  module: string;
}
export interface SectionRow {
  raw_name: string;
  va: Hex;
  rva: Hex;
  virtual_size: number;
  characteristics: number;
  protection: string | null;
}
export interface ListFunctionsParams {
  module: string;
  rva_min?: Hex;
  rva_max?: Hex;
  offset: number;
  limit: number;
}
export interface FunctionRow {
  begin_rva: Hex;
  end_rva: Hex;
  unwind_rva: Hex;
  chained: boolean;
}
export interface FindFunctionParams {
  address: Hex;
}
export interface ListRangesParams {
  protection: string;
  coalesce: boolean;
  module?: string;
  kind: "all" | "module" | "private" | "malloc";
  offset: number;
  limit: number;
  snapshot?: SnapshotId;
}
export interface RangeRow {
  base: Hex;
  size: number;
  protection: string;
  module: string | null;
  kind: "module" | "private" | "malloc";
}
export type ListRangesResult = Paged<RangeRow> & { snapshot: SnapshotId; taken_t: TimeUs };
export interface ListThreadsParams {
  registers: "none" | "gpr" | "all";
  teb: boolean;
  names: boolean;
}
export interface ThreadInfo {
  id: ThreadId;
  state: string /* unreliable [ext-frida §3.13] */;
  entry: Hex | null;
  teb: Hex | null;
  stack: { base: Hex; limit: Hex } | null;
  name: string | null;
  regs: Record<string, Hex> | null;
  bea_role: "agent" | null;
}
export interface ListThreadsResult {
  threads: ThreadInfo[];
}
export interface ResolveTargetsParams {
  targets: TargetRef[];
}
export interface ResolveTargetsResult {
  results: ({ ok: true; target: ResolvedTarget } | { ok: false; error: AgentError })[];
}
export interface DescribeAddressesParams {
  addresses: Hex[];
}
export interface AddressDescription {
  va: Hex;
  module: string | null;
  rva: Hex | null;
  function: FunctionRange | null;
  range: { base: Hex; size: number; protection: string } | null;
  export_hint: { name: string; va: Hex; distance: number } | null; // nearest preceding export — a HINT only
  bea_patched: boolean;
  bea_guarded: boolean;
}
export interface DescribeAddressesResult {
  results: AddressDescription[];
}

// ---- memory
export interface ReadMemoryParams {
  address: Hex;
  size: number;
}
export interface ReadMemoryMeta {
  address: Hex;
  requested: number;
  returned: number;
  complete: boolean;
  stop: null | { reason: "unmapped" | "protection" | "guard-page" | "access-violation"; at: Hex };
  bea_guard_suspended: Hex[]; // BEA guard pages temporarily unguarded for this read
}
export interface TypedRead {
  address: Hex;
  type: ValueType;
  count?: number;
  chain?: number[];
  max_len?: number;
}
export interface ReadTypedParams {
  reads: TypedRead[];
}
export interface ReadTypedResult {
  results: (
    | { ok: true; final_address: Hex; path: Hex[]; value: TypedOut | TypedOut[] }
    | { ok: false; error: AgentError; path: Hex[] }
  )[];
}
export interface WriteMemoryParams {
  address: Hex;
  mode: "data" | "code";
  bytes?: HexBytes;
  typed?: { type: ValueType; values: ScalarInput[] };
  expect_before?: HexBytes;
  allow_protect_change: boolean;
}
export interface WriteResult {
  write_id: WriteId;
  address: Hex;
  size: number;
  before: HexBytes;
  after: HexBytes;
  verified: boolean;
  method: "direct" | "protect-and-restore" | "patchCode";
  protection_before: string | null;
  protection_after: string | null;
  effect: EffectHint;
}
export interface RevertWriteParams {
  write_id: WriteId;
  force: boolean;
}
export interface RevertWriteResult {
  write_id: WriteId;
  reverted: boolean;
  current_before_revert: HexBytes;
  after: HexBytes;
}

// ---- disassembly
export interface DisassembleParams {
  address: Hex;
  mode: "count" | "function" | "range";
  count?: number;
  size?: number;
  original_bytes: boolean;
  operands: boolean;
  cfg: boolean;
}
export interface InsnRow {
  address: Hex;
  size: number;
  bytes: HexBytes;
  mnemonic: string;
  op_str: string;
  groups: string[];
  branch_target: Hex | null;
  mem_targets: Hex[];
  overlay: boolean;
  regs_read?: string[];
  regs_written?: string[];
}
export interface CfgBlock {
  start: Hex;
  end: Hex;
  successors: Hex[];
}
export interface DisassembleResult {
  start: Hex;
  function: FunctionRange | null;
  instructions: InsnRow[];
  truncated: boolean;
  overlay_used: boolean;
  stop: null | { reason: "decode-error" | "access-violation" | "limit"; at: Hex };
  blocks: CfgBlock[] | null;
}

// ---- scans
export type ScanValueType =
  | "i8"
  | "u8"
  | "i16"
  | "u16"
  | "i32"
  | "u32"
  | "i64"
  | "u64"
  | "f32"
  | "f64"
  | "ptr"
  | "bytes"
  | "utf8"
  | "utf16";
export interface RegionFilter {
  protection: string; // Frida protection filter, e.g. "rw-"
  modules?: string[];
  exclude_modules?: string[];
  private_only?: boolean;
  min?: Hex;
  max?: Hex;
  max_region_bytes?: number;
}
export interface ScanStartParams {
  kind: "value" | "pattern" | "unknown" | "pointers-to";
  value_type?: ScanValueType;
  compare?: {
    op: "eq" | "approx" | "range" | "gt" | "lt";
    value?: ScalarInput;
    min?: ScalarInput;
    max?: ScalarInput;
    eps?: number;
    text?: string;
    bytes?: HexBytes;
  };
  pattern?: string; // kind "pattern": exact, "??", nibble "4?", ": mask" forms; "/regex/" refused
  targets?: Hex[]; // kind "pointers-to" (≤ 16)
  regions: RegionFilter;
  align?: 1 | 2 | 4 | 8;
  max_candidates?: number;
  label?: string;
}
export type ScanNextOp =
  | "eq"
  | "ne"
  | "approx"
  | "gt"
  | "lt"
  | "range"
  | "changed"
  | "unchanged"
  | "increased"
  | "decreased"
  | "increased_by"
  | "decreased_by"
  | "same_as_first";
export interface ScanNextParams {
  scan_id: ScanId;
  op: ScanNextOp;
  value?: ScalarInput;
  min?: ScalarInput;
  max?: ScalarInput;
  eps?: number;
}
export interface ScanStartResult {
  scan_id: ScanId;
  job_id: JobId;
}
export interface ScanNextResult {
  scan_id: ScanId;
  job_id: JobId;
}
export interface ScanStatus {
  scan_id: ScanId;
  label: string | null;
  state: "running" | "ready" | "failed" | "closed";
  mode: "explicit" | "snapshot";
  value_type: ScanValueType;
  count: number;
  ops: { op: string; count_after: number; t: TimeUs }[];
  bytes_scanned: number;
  regions: number;
  unreadable_regions: number;
  faulted_candidates_dropped: number;
  job: JobId | null;
  memory_bytes: number;
  error: AgentError | null;
}
export interface ScanResultsParams {
  scan_id: ScanId;
  offset: number;
  limit: number;
  read_current: boolean;
}
export interface ScanHit {
  address: Hex;
  stored: TypedOut;
  current?: TypedOut | { error: AgentError };
}
export interface ScanCloseParams {
  scan_id: ScanId;
}

// ---- jobs
export interface JobInfo {
  job_id: JobId;
  kind: JobKind;
  state: "queued" | "running" | "done" | "failed" | "cancelled";
  progress: Progress;
  started_t: TimeUs;
  ended_t: TimeUs | null;
  error: AgentError | null;
}
export interface JobStatusParams {
  job_id: JobId;
}
export interface JobCancelParams {
  job_id: JobId;
}

// ---- hooks
export type CaptureRegister =
  | "rax"
  | "rbx"
  | "rcx"
  | "rdx"
  | "rsi"
  | "rdi"
  | "rbp"
  | "rsp"
  | "r8"
  | "r9"
  | "r10"
  | "r11"
  | "r12"
  | "r13"
  | "r14"
  | "r15"
  | "rip"
  | "xmm0"
  | "xmm1"
  | "xmm2"
  | "xmm3"
  | "xmm4"
  | "xmm5"
  | "xmm6"
  | "xmm7"
  | "xmm8"
  | "xmm9"
  | "xmm10"
  | "xmm11"
  | "xmm12"
  | "xmm13"
  | "xmm14"
  | "xmm15";
/** INTEGRATION: exactly one of {slot+class} or {reg} (S6 CaptureSpec arg|reg). */
export interface ArgCapture {
  name?: string; // ≤ 32 chars
  slot?: number; // Win64 positional parameter index 0..15 (after hidden_ret_ptr shift)
  class?: "int" | "float"; // slots 0..3: int → rcx/rdx/r8/r9, float → xmm0..3; ≥4: stack
  reg?: CaptureRegister; // any register (xmm viewed as `type`; bytes = 16 B)
  type: ValueType; // slot value type, or the final type after deref
  deref?: number[]; // pointer chain offsets (≤ max_deref_depth); last = field offset
  count?: number; // array length at the final address (≤ 64)
  max_len?: number; // strings (chars) / bytes
  at?: "enter" | "leave"; // default "enter"; "leave" reads out-params after the call
}
export interface RetCapture {
  type: ValueType;
  deref?: number[];
  count?: number;
  max_len?: number;
}
export interface HookInstallParams {
  target: TargetRef;
  engine: "js" | "native";
  relocation: "auto" | "forced";
  capture: {
    args: ArgCapture[];
    ret: RetCapture | null;
    backtrace: { depth: number; max_per_sec: number } | null; // js engine only; frames as FrameRef ("mod+0xrva")
    registers: "none" | "gpr"; // js engine only
  };
  emit: "enter" | "leave";
  /** INTEGRATION (S6 probe): instruction probe, onEnter only, register captures only. */
  probe: boolean;
  hidden_ret_ptr: boolean;
  filter?: { thread_ids?: ThreadId[]; caller_modules?: string[] };
  sample?: { every_n?: number; max_per_sec?: number };
  lifetime: Lifetime;
  observe_agent_calls: boolean;
  force_caution: boolean;
  label?: string;
}
export interface HookInstallResult {
  instrument_id: InstrumentId;
  stream_id: StreamId;
  row_kind: "hook/1" | "hook-native/1";
  layout: BinaryLayout | null;
  resolved: ResolvedTarget;
  thunk: { kind: "jmp-rip" | "jmp-rel"; to: Hex } | null;
  patched_at: Hex[];
  relocation: "default" | "forced";
  stalker_invalidated: ThreadId[];
  arg_map: { slot: number; source: string }[];
  effect: EffectHint;
}

// ---- API profiles (catalog in apiProfiles.ts)
/** INTEGRATION: tool-level profile names (S6 §6) are the wire names. */
export type ApiProfileName = "file" | "registry" | "network" | "process" | "module_load" | "memory_protection";
export interface ProfileOptions {
  thread_ids?: ThreadId[];
  per_api_max_events?: number; // default limits.profile_events_per_api
  dedupe_window_ms?: number; // 0 = off; identical (api, args, ret) within the window → repeat count
  file?: { io: boolean; capture_bytes: number; track_handles: boolean };
  registry?: { capture_value_bytes: number; query_key: boolean; enumerate: boolean };
  network?: { capture_payload_bytes: number; http: boolean; dns: boolean };
  process?: { cross_process_memory: boolean; apc_and_context: boolean };
  module_load?: { resolve_procedures: boolean };
  memory_protection?: { frees: boolean; sections: boolean; exec_region_scan_ms: number };
}
export interface ProfileInstallParams {
  profiles: ApiProfileName[];
  options: ProfileOptions;
  lifetime: Lifetime;
  label?: string;
}
export interface ProfileInstallResult {
  instrument_id: InstrumentId;
  stream_id: StreamId;
  row_kind: "api/1";
  catalog_minor: number;
  installed: { api_id: number; api: string; va: Hex }[];
  pending: { api: string; module: string }[]; // module not loaded yet; installed on load
  denied: { api: string; reason: string }[];
  failed: { api: string; error: AgentError }[];
  memmap_stream: StreamId | null;
  effect: EffectHint;
}

// ---- watches
export interface WatchInstallParams {
  method: "debug-register" | "page-guard" | "poll"; // INTEGRATION: "poll" = timer sampling (S6 R5), never auto-picked
  address: Hex;
  size: number; // debug-register: 1|2|4|8 (aligned); page-guard: 1..65536; poll: 1..65536
  interval_ms?: number; // poll only: 1..10000 (default 16)
  access: "write" | "read-write" | "execute"; // DR "r" ≡ "rw" in hardware [ext-frida §3.9]: no read-only option
  slot?: 0 | 1 | 2 | 3;
  threads: "all" | ThreadId[];
  capture: { registers: "none" | "gpr"; backtrace: number; values: boolean };
  engine?: "trap-flag" | "access-monitor"; // page-guard only: default trap-flag (§11.3); access-monitor = MemoryAccessMonitor fallback (§11.3.1)
  /** CT-I4 (page-guard only): when (hits + filtered) exceed max_per_sec over window_ms, the handler disarms (no re-arm)
   *  and the instrument ends with end_reason "rate-limit". Default {max_per_sec: 20000, window_ms: 100}. */
  rate_limit?: { max_per_sec: number; window_ms: number };
  lifetime: Lifetime;
  label?: string;
}
export interface WatchInstallResult {
  instrument_id: InstrumentId;
  stream_id: StreamId;
  method: "debug-register" | "page-guard" | "poll";
  slot: number | null;
  pages: Hex[] | null;
  armed_threads: number;
  arm_errors: { tid: ThreadId; message: string }[];
  verified: { threads_checked: number; ok: number } | null;
  initial_value: HexBytes | null;
  effect: EffectHint;
}
export interface DebugRegisterStateParams {
  thread_ids?: ThreadId[];
}
export interface DebugRegisterStateResult {
  threads: { tid: ThreadId; dr: [Hex, Hex, Hex, Hex]; dr7: Hex; error: string | null }[];
  slots: {
    slot: number;
    owner: InstrumentId | "quarantined" | null;
    kind: "watch" | "exec" | null;
    address: Hex | null;
  }[];
}

// ---- Stalker
export interface TraceStartParams {
  /** INTEGRATION: exactly one of threads / on_call. */
  threads?: ThreadId[]; // 1..stalker_max_threads; never the agent thread
  on_call?: { target: TargetRef; invocations: number }; // follow the calling thread entry→return, N invocations (S6 R12)
  mode: "coverage" | "block_counts" | "call_summary" | "call_events";
  modules: string[]; // blocks recorded/counted only inside these (default: [main module])
  exclude_modules: string[]; // Stalker.exclude for speed
  lifetime: Lifetime; // max_hits = max rows/events
  queue?: { capacity: number; drain_ms: number };
  label?: string;
}
export interface TraceStartResult {
  instrument_id: InstrumentId;
  stream_id: StreamId;
  row_kind: "block-span/1" | "block-count/1" | "call-site-count/1" | "gum-event-x64/1";
  layout: BinaryLayout;
  threads: ThreadId[];
  queue: { capacity: number; drain_ms: number };
  excluded: { module: string; base: Hex; size: number }[];
  effect: EffectHint;
}

// ---- overrides
export interface OverrideInstallParams {
  target: TargetRef;
  relocation: "auto" | "forced";
  mode: "rewrite" | "replace";
  rewrite?: {
    args?: { slot: number; class: "int" | "float"; type: ValueType; value: ScalarInput }[];
    ret?: { type: ValueType; value: ScalarInput };
  };
  replace?: { ret_type: ValueType | "void"; arg_types: ValueType[]; returns: ScalarInput | null };
  when?: { thread_ids?: ThreadId[]; every_n?: number };
  lifetime: Lifetime;
  record: boolean; // emit override/1 rows
  label?: string;
}
export interface OverrideInstallResult {
  instrument_id: InstrumentId;
  stream_id: StreamId | null;
  resolved: ResolvedTarget;
  mode: "rewrite" | "replace";
  relocation: "default" | "forced";
  stalker_invalidated: ThreadId[];
  effect: EffectHint;
}

// ---- instruments (generic stop/list)
export interface InstrumentStopParams {
  id: InstrumentId | "all";
  final_flush: boolean;
}
export interface InstrumentStopResult {
  stopped: InstrumentSummary[];
  not_found: string[];
  unreverted: { id: InstrumentId; detail: string }[];
}
export interface InstrumentListResult {
  instruments: InstrumentInfo[];
}

// ---- calls (INTEGRATION: S5 §9.4–9.5 exact-bits register-file thunk replaces NativeFunction marshalling;
//      CT-B1/B2: the thunk is a registered SEH frame called with exceptions:"propagate", DESIGN §5.3.1)
export interface CallFunctionParams {
  plan: PlanWire; // classified on the host (src/domain/callModel); target = live VA
  vectors: VectorsWire; // raw 64-bit bits per column; offset = continuation start
  fp: { mxcsr: number; fpcw: number }; // per call; status bits (0..5) of mxcsr already cleared by the host
  /**
   * agent: the agent JS thread. thread: Process.runOnThread(tid) per chunk; refused (BadParams) when the sampled RIP
   * is inside an ntdll syscall stub; a closure that has not run by timeout_ms is EXPIRED (CT-I1): it runs as a no-op
   * whenever it finally runs, and its CallBlock/scratch stay quarantined until then. hook (CT-I1 safe point): a
   * temporary Interceptor listener at `at`; the chunk runs inside onEnter on the first arriving thread (`tid` = only
   * that thread); timeout_ms bounds the wait; the listener is removed after the chunk or on timeout.
   */
  thread:
    | { kind: "agent" }
    | { kind: "thread"; tid: ThreadId; timeout_ms: number }
    | { kind: "hook"; at: Hex; tid: ThreadId | null; timeout_ms: number };
  chunk: number; // max vectors this RPC (≤ limits.call_max_vectors)
  max_wall_ms: number; // time slice; returns next_offset when exceeded
  coverage: { mode: "none" | "blocks"; modules: string[]; max_blocks: number };
  hooks: "suppress" | "observe"; // BEA hook/profile rows caused by this call
  overrides: "apply" | "bypass";
}
/** An exception that NO handler inside the callee resolved; caught by the thunk's SEH frame (CT-B1). */
export interface FaultInfo {
  index: number;
  type: ExceptionType;
  address: Hex;
  memory: { operation: "read" | "write" | "execute"; address: Hex } | null;
  code: Hex; // NTSTATUS from the EXCEPTION_RECORD (e.g. "0xc0000005")
  information: Hex[]; // ExceptionInformation[0..min(n,3))
  module: string | null;
  rva: Hex | null;
  /** full GPRs from the dispatcher's in-call record of the same exception; {rip, rsp} only when unavailable */
  registers: Record<string, Hex>;
}
export interface CallFunctionResult {
  raw: RawBatchColumns; // completed vectors only, starting at vectors.offset
  next_offset: number | null; // null when every vector of this chunk ran
  thread_id: ThreadId;
  faults: FaultInfo[];
  /**
   * Always false from the agent (review fix EMU-10): a target that exits inside the callee dies before this reply can
   * be sent, so the agent cannot report its own process's death. The host derives a lost target from the failed RPC
   * (target exited / script destroyed) and the session state, and sets its own lostTarget.
   */
  lost_target: boolean;
  /** CT-B1: "seh-frame" normally; "steal" only if RtlAddFunctionTable failed (limitation CALL_SEH_UNAVAILABLE) */
  exception_model: "seh-frame" | "steal";
  /** CT-B1: first-chance exceptions raised inside the callee and resolved by its own handlers (SEH, C++ EH) */
  callee_exceptions: number;
  /** CT-B2: BEA traps (DR hits, guard-page steps) handled by the dispatcher while vectors ran; the calls continued */
  bea_traps_during_call: number;
  coverage: { index: number; blocks: [Hex, number][]; truncated: boolean }[] | null; // per vector [start, size]
  resolved: ResolvedTarget;
  perturbation: { target_instruments: InstrumentId[]; overrides_bypassed: boolean; hooks_suppressed: number };
  effect: EffectHint;
}

// ---- dumps
export type DumpItem =
  | { kind: "module"; module: string }
  | { kind: "range"; base: Hex; size: number }
  | { kind: "ranges"; filter: RegionFilter; max_total_bytes: number }
  | { kind: "thread"; tid: ThreadId; stack_bytes: number; teb: boolean; tls: boolean; xmm: boolean };
export interface DumpStartParams {
  items: DumpItem[];
  suspend: "none" | "all";
  chunk_bytes?: number;
  max_total_bytes: number;
  /** CT-I6: splice the original bytes under BEA's own code patches into module images (default true); the host then
   *  restores foreign patches from the relocated on-disk image */
  original_bytes: boolean;
}
export interface DumpStartResult {
  job_id: JobId;
  planned_bytes: number;
  planned_blobs: number;
}
export interface DumpRegion {
  blob: BlobId;
  kind: "module" | "range" | "stack" | "teb" | "peb" | "tls";
  base: Hex;
  size: number;
  protection: string;
  module: string | null;
  holes: { offset: number; size: number; reason: "unreadable" | "guard-page" }[];
  /** CT-I6: ranges whose BEA patch bytes were replaced with the originals (offsets into this region) */
  bea_patches_restored: { offset: number; size: number }[];
  sha256: Hex | null;
}
export interface ThreadState {
  tid: ThreadId;
  registers: Record<string, Hex>;
  eflags: Hex;
  mxcsr: Hex;
  fpcw: Hex;
  xmm: Hex[] | null;
  teb: Hex | null;
  peb: Hex | null;
  stack: { base: Hex; limit: Hex } | null;
  tls: { static_tls_array: Hex | null; tls_slots: Hex[] } | null;
}
export interface DumpManifest {
  format: "bea-dump/1";
  pid: number;
  taken: { t0: TimeUs; t1: TimeUs; suspended: boolean };
  modules: { name: string; path: string; base: Hex; size: number; blob: BlobId | null }[];
  regions: DumpRegion[];
  threads: ThreadState[];
  module_map_epoch: number;
  truncated: boolean;
}
export interface CaptureThreadStateParams {
  tid: ThreadId;
  xmm: boolean;
  teb: boolean;
  tls: boolean;
}

/* ------------------------------------------------------------------------------------------------
 * 4.10 The RPC method map (single source of truth for both sides)
 * ---------------------------------------------------------------------------------------------- */
type NoParams = Record<string, never>;
export interface AgentRpcMethods {
  // core
  hello: { params: HelloParams; result: HelloResult };
  ping: { params: NoParams; result: PingResult };
  status: { params: StatusParams; result: AgentStatus };
  flush: { params: FlushParams; result: FlushResult };
  shutdown: { params: ShutdownParams; result: ShutdownResult };
  fingerprint: { params: NoParams; result: Fingerprint };
  // inspection
  processInfo: { params: NoParams; result: ProcessInfo };
  listModules: { params: ListModulesParams; result: ListModulesResult };
  listExports: { params: ListExportsParams; result: Paged<ExportRow> };
  listImports: { params: ListImportsParams; result: Paged<ImportRow> };
  listSections: { params: ListSectionsParams; result: { sections: SectionRow[] } };
  listFunctions: { params: ListFunctionsParams; result: Paged<FunctionRow> };
  findFunction: { params: FindFunctionParams; result: FunctionRange | null };
  listRanges: { params: ListRangesParams; result: ListRangesResult };
  listThreads: { params: ListThreadsParams; result: ListThreadsResult };
  resolveTargets: { params: ResolveTargetsParams; result: ResolveTargetsResult };
  describeAddresses: { params: DescribeAddressesParams; result: DescribeAddressesResult };
  // memory + code
  readMemory: { params: ReadMemoryParams; result: ReadMemoryMeta; binary: true };
  readTyped: { params: ReadTypedParams; result: ReadTypedResult };
  writeMemory: { params: WriteMemoryParams; result: WriteResult }; // gate write_memory
  revertWrite: { params: RevertWriteParams; result: RevertWriteResult };
  disassemble: { params: DisassembleParams; result: DisassembleResult };
  // scans + jobs
  scanStart: { params: ScanStartParams; result: ScanStartResult };
  scanNext: { params: ScanNextParams; result: ScanNextResult };
  scanStatus: { params: { scan_id: ScanId }; result: ScanStatus };
  scanResults: { params: ScanResultsParams; result: Paged<ScanHit> };
  scanClose: { params: ScanCloseParams; result: { closed: true; freed_bytes: number } };
  jobStatus: { params: JobStatusParams; result: JobInfo };
  jobCancel: { params: JobCancelParams; result: JobInfo };
  // instruments
  hookInstall: { params: HookInstallParams; result: HookInstallResult };
  profileInstall: { params: ProfileInstallParams; result: ProfileInstallResult };
  watchInstall: { params: WatchInstallParams; result: WatchInstallResult };
  traceStart: { params: TraceStartParams; result: TraceStartResult };
  overrideInstall: { params: OverrideInstallParams; result: OverrideInstallResult }; // gate override_function
  instrumentStop: { params: InstrumentStopParams; result: InstrumentStopResult };
  instrumentList: { params: NoParams; result: InstrumentListResult };
  debugRegisterState: { params: DebugRegisterStateParams; result: DebugRegisterStateResult };
  // execution + capture
  callFunction: { params: CallFunctionParams; result: CallFunctionResult }; // gate call_function
  dumpStart: { params: DumpStartParams; result: DumpStartResult };
  captureThreadState: { params: CaptureThreadStateParams; result: ThreadState };
}
export type AgentMethodName = keyof AgentRpcMethods;
export type AgentParams<K extends AgentMethodName> = AgentRpcMethods[K]["params"];
export type AgentValue<K extends AgentMethodName> = AgentRpcMethods[K]["result"];
export type IsBinary<K extends AgentMethodName> = AgentRpcMethods[K] extends { binary: true } ? true : false;
/** What the agent's rpc.exports[K] returns (sync or Promise). */
export type AgentReply<K extends AgentMethodName> =
  IsBinary<K> extends true
    ? [AgentResult<AgentValue<K>>, ArrayBuffer] | AgentResult<never>
    : AgentResult<AgentValue<K>>;
export type AgentRpcImpl = { [K in AgentMethodName]: (p: AgentParams<K>) => AgentReply<K> | Promise<AgentReply<K>> };
export const PRE_HELLO_METHODS: readonly AgentMethodName[] = ["hello", "ping", "processInfo"] as const;
export const GATED_METHODS: Readonly<Partial<Record<AgentMethodName, GateName>>> = {
  writeMemory: "write_memory",
  revertWrite: "write_memory",
  overrideInstall: "override_function",
  callFunction: "call_function",
};
