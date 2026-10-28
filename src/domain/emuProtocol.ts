// =================================================================================================
// src/domain/emuProtocol.ts — canonical bea-emu/0.1 wire types (S5 §4.4, frozen). bea_emu_bridge.py mirrors
// these exactly. INTEGRATION: Hex/HexBytes and the call-plan types come from src/shared (single definition).
// =================================================================================================
import type { Hex, HexBytes } from "../shared/hex.js";
import type { Attribution, CallStatus, PlanWire, StatusCode, VectorsWire } from "../shared/callPlan.js";
export type { Attribution, CallStatus, PlanWire, StatusCode, VectorsWire };
export type { Hex, HexBytes };
export const EMU_PROTOCOL = "bea-emu/0.1" as const;
export type RequestId = number; // positive integer, unique per bridge process

// ---------------------------------------------------------------- frames
export type HostFrame = { id: RequestId; method: EmuMethod; params: Record<string, unknown> };
/** @public */
export type BridgeFrame =
  | { event: ReadyEvent | FatalEvent } // unsolicited; no id
  | { id: RequestId; event: ProgressEvent } // zero or more before the final frame
  | { id: RequestId; result: unknown } // final (shape = EmuMethods[M]["result"])
  | { id: RequestId | null; error: BridgeErrorBody }; // final; id null only for parse_error

export interface EngineVersions {
  python: string;
  unicorn: string;
  unicornCore: string;
  capstone: string;
  pefile: string;
}
export interface MemoryLimitInfo {
  applied: boolean;
  bytes: number | null;
  mechanism: "win32-job" | "linux-rlimit-data" | "none";
  error?: string;
}
export interface ReadyEvent {
  type: "ready";
  protocol: typeof EMU_PROTOCOL;
  bridge: { version: string; sha256: string };
  pid: number;
  engines: EngineVersions;
  python: { version: string; executable: string; inVenv: boolean };
  memoryLimit: MemoryLimitInfo;
}
export interface FatalEvent {
  type: "fatal";
  code: "engine_unavailable" | "usage" | "internal_error";
  message: string;
  data?: { missing?: string[]; errors?: Record<string, string> };
}
export interface ProgressEvent {
  type: "progress";
  phase: "load" | "isa-scan" | "batch" | "sweep" | "snapshot";
  completed: number;
  total: number | null;
}

export type BridgeErrorCode =
  | "parse_error"
  | "frame_too_large"
  | "invalid_request"
  | "invalid_params"
  | "unknown_method"
  | "protocol_mismatch"
  | "unknown_session"
  | "session_poisoned"
  | "unknown_snapshot"
  | "unknown_symbol"
  | "image_unreadable"
  | "unsupported_image"
  | "relocation_unavailable"
  | "layout_conflict"
  | "dump_invalid"
  | "dump_incomplete"
  | "unmapped"
  | "resource_exhausted"
  | "unsupported_combination"
  | "cancelled"
  | "engine_crashed"
  | "internal_error";
export interface BridgeErrorBody {
  code: BridgeErrorCode;
  message: string;
  data?: Record<string, unknown>;
}

// ---------------------------------------------------------------- shared value shapes
export interface RegionDesc {
  region: string;
  kind: "image" | "module" | "runtime" | "stub" | "heap" | "scratch" | "stack" | "teb" | "captured" | "unmapped";
  module?: string;
  rva?: Hex;
  offset?: Hex;
  import?: string;
  hint?: string;
  nearest?: string;
  distance?: Hex;
  capture?: "captured" | "synthetic" | "not-captured-mapped-live" | "unmapped-live";
  liveProtection?: string;
  remediation?: string;
}
export interface Insn {
  va: Hex;
  rva: Hex | null;
  module: string | null;
  bytes: HexBytes;
  text: string;
}
export interface FunctionRange {
  module: string;
  beginRva: Hex;
  endRva: Hex;
  source: "pdata";
}
export interface RegionInfo {
  start: Hex;
  end: Hex;
  name: string;
  kind: RegionDesc["kind"];
  perms: string;
  module?: string;
  capture?: RegionDesc["capture"];
}
export type DeviationKind =
  // loader-level
  | "tls_callbacks_not_run"
  | "entry_point_not_run"
  | "imports_hle_bound"
  | "no_seh_dispatch"
  | "delay_imports_present"
  | "managed_image"
  | "isa_guard_off"
  | "isa_guard_incomplete"
  | "x87_tagging_incomplete"
  | "fp_status_tagging_incomplete"
  | "sse_tagging_incomplete"
  | "iat_rebound"
  | "teb_stack_bounds_rewritten"
  | "memory_patched"
  | "synthetic_teb"
  | "synthetic_kuser_shared_data"
  | "malformed_directory"
  | "engine_unvalidated"
  // call-level
  | "x87_transcendental_inexact"
  | "sse_approx_inexact"
  | "hle_heap_exhausted"
  | "inexact_import_model"
  | "unhandled_import_returned_zero"
  | "auto_mapped_zero_pages"
  | "fp_status_flags_unmodeled"
  | "cpuid_executed"
  | "virtualized_tsc"
  | "nondeterministic_tsc"
  | "nondeterministic_rng"
  | "dynamic_import_resolved"
  | "self_modifying_code"
  | "isa_overlay_overwritten"
  // host-added
  | "bridge_restarted_state_reset";
export interface Deviation {
  kind: DeviationKind;
  note: string;
  count?: number;
  detail?: Record<string, unknown>;
}

// ---------------------------------------------------------------- session.open
export interface OpenParams {
  source:
    | { kind: "image"; path: string; base?: Hex }
    | { kind: "dump"; bundlePath: string; thread?: number; primaryModule?: string };
  memory?: { heapBytes?: number; scratchBytes?: number; stackBytes?: number }; // ≤ 256 MiB, ≤ 256 MiB, ≤ 16 MiB
  protections?: "sections" | "rwx";
  imports?: {
    builtin?: boolean; // default true
    unhandled?: "stop" | "return_zero"; // default "stop"
    dumpPolicy?: "auto" | "hle_known" | "lle" | "stop_all"; // default "auto"
    overrides?: Array<
      | { key: string; action: "return"; returns: { kind: "int" | "f32" | "f64" | "void"; bits: Hex } }
      | { key: string; action: "stop" }
      | { key: string; action: "model"; model: string }
    >; // ≤ 256
  };
  patches?: Array<{ address: Hex | string; hex: HexBytes }>; // ≤ 256 entries, ≤ 1 MiB total; applied before the baseline.
  // address: "0x…" | "module+0xRVA" | "module!export". The bridge resolves the
  // symbolic forms (the only symbolic input in the protocol; TS cannot know a
  // dump's or relocated image's modules before the open)
  cpu?: { mxcsr: number; fpcw: number }; // session defaults; defaults 0x1F80 / 0x027F
  isaGuard?: "stop" | "off";
  snapshots?: "cow" | "manual";
  faultPolicy?: "stop" | "map_zero"; // map_zero requires snapshots "manual"
  cacheDir?: string | null;
  deadlineMs?: number;
}
export interface ModuleInfo {
  name: string;
  path: string | null;
  sha256: string | null; // file sha256 (image) or captured-bytes digest (dump module without file match)
  preferredBase: Hex | null;
  mappedBase: Hex;
  size: number;
  relocated: boolean;
  captured: "image" | "full" | "partial" | "none";
  sections: Array<{ name: string; rva: Hex; size: number; perms: string }>;
  exports: number;
  pdataFunctions: number;
  tlsCallbacks: Array<{ rva: Hex }>;
  tlsCallbacksExecuted: false;
  delayImports: number;
}
export interface IsaReport {
  scanSource: "pdata+gaps" | "sections";
  cache: "hit" | "miss" | "off";
  scanMs: number;
  instructionsScanned: number;
  sites: Record<"vex" | "evex" | "x87_inexact" | "fp_status" | "cpuid" | "syscall" | "tsc" | "rng", number>;
  guarded: { int3: number; hooks: number; unguarded: number };
  functionsWithVex: Hex[] /* ≤ 100 RVAs of the primary */;
  guard: "stop" | "off";
}
export interface OpenResult {
  session: string; // bridge-local id, e.g. "s1"
  primary: ModuleInfo;
  modules: ModuleInfo[];
  imports: {
    total: number;
    models: Record<"builtin" | "builtin-inexact" | "override" | "unhandled" | "lle" | "stop", number>;
    unhandled: string[];
  };
  isa: IsaReport;
  layout: { syntheticBase: Hex; regions: number; mappedBytes: number };
  cpu: { mxcsr: Hex; fpcw: Hex; model: string };
  snapshots: "cow" | "manual";
  thread: { tid: number; teb: Hex } | null; // dump sessions
  loaderDeviations: Deviation[];
  timings: { loadMs: number; isaMs: number; bindMs: number; snapshotMs: number; totalMs: number };
}
export interface SessionStateInfo {
  poisoned: boolean;
  named: Array<{ name: string; bytes: number }>;
  heapHigh: Hex;
  calls: number;
  vectors: number;
}

// ---------------------------------------------------------------- call plan (built by TS: callModel.planToWire)
export interface TraceOptions {
  imports: "off" | "counts" | "full";
  blocks: boolean;
  coverage: boolean;
  countInstructions: boolean;
  memory: "off" | "reads" | "writes" | "all";
  instructions: boolean;
  disassemble: boolean;
  maxEvents: number;
}
export interface RunOptions {
  maxInstructions: number;
  timeoutMs: number;
  mxcsr: number;
  fpcw: number;
  faultPolicy: "stop" | "map_zero";
  trace: TraceOptions;
}
export interface StateWire {
  from: "baseline" | "current" | string;
  writes: Array<{ address: Hex; hex: HexBytes }>;
  saveAs: string | null;
}
export interface CallParams {
  session: string;
  plan: PlanWire;
  vectors: VectorsWire /* count 1 */;
  state: StateWire;
  options: RunOptions;
}
export interface BatchParams {
  session: string;
  plan: PlanWire;
  vectors: VectorsWire;
  state: StateWire;
  options: RunOptions & { isolation: "snapshot" | "chain"; stopOnFault: boolean; deadlineMs: number };
}

// ---------------------------------------------------------------- outcomes
export interface StopRecord {
  status: Exclude<CallStatus, "returned">;
  attribution: Attribution;
  cause: string;
  pc: Hex;
  pcRegion: RegionDesc;
  pcFunction: (FunctionRange & { offset: Hex }) | null;
  instruction: Insn[];
  fault?: {
    access: "read" | "write" | "fetch";
    kind: "unmapped" | "protected";
    address: Hex;
    size: number;
    value: Hex | null;
    addressRegion: RegionDesc;
  };
  exception?: { vector: number; name: string };
  importCall?: {
    import: string;
    caller: Hex;
    callerRva: Hex | null;
    args: [Hex, Hex, Hex, Hex];
    xmm: [Hex, Hex, Hex, Hex];
  };
  isa?: { mnemonic: string; encoding: "vex" | "evex" | "engine"; rva: Hex | null; reason: string };
  syscall?: { number: Hex; args: [Hex, Hex, Hex, Hex] };
  terminate?: { via: string; code: Hex | null };
  engineError?: { errno: number; message: string };
  registers?: Record<string, Hex>; // rax…r15, rip, rflags, mxcsr, fpcw, fpsw, xmm0…xmm15 (128-bit)
  stackScan: Array<{
    stackOffset: Hex;
    va: Hex;
    module: string | null;
    rva: Hex | null;
    note?: "harness return sentinel";
  }>;
  lastBlocks?: Hex[];
}
export interface ImportEvent {
  import: string;
  model: string;
  callerRva: Hex | null;
  args: [Hex, Hex, Hex, Hex];
  ret: Hex | null;
}
export interface MemEvent {
  pc: Hex;
  access: "r" | "w";
  address: Hex;
  size: number;
  value: Hex;
}
export interface CoverageWire {
  granularity: "tb";
  blocks: Array<[Hex, number, number]>;
  distinct: number;
  truncated: boolean;
}
export interface Provenance {
  evidence: "emulation";
  engine: "unicorn";
  engines: EngineVersions;
  bridge: { version: string; sha256: string };
  protocol: typeof EMU_PROTOCOL;
  source: "image" | "dump";
  bundleId: string | null;
  primary: { name: string; sha256: string | null; mappedBase: Hex; preferredBase: Hex | null };
  target: { va: Hex; module: string | null; rva: Hex | null; export: string | null };
  abi: "win64";
  mxcsr: Hex;
  fpcw: Hex;
  isaGuard: "stop" | "off";
}
export interface CallResult {
  status: CallStatus;
  attribution: Attribution | null;
  raw: { rax: Hex; xmm0: Hex; mxcsr: Hex; fpcw: Hex; fpsw: Hex }; // xmm0 128-bit
  buffers: Record<string, Hex>;
  out: Record<string, HexBytes>;
  stop: StopRecord | null;
  metrics: { wallUs: number; instructions?: number; blocks?: number; tbFlushes: number };
  trace?: {
    imports?: ImportEvent[];
    blocks?: Hex[];
    coverage?: CoverageWire;
    memory?: MemEvent[];
    instructions?: Array<{ va: Hex; text?: string }>;
    truncated: Record<string, boolean>;
  };
  events: Array<{ type: "heap"; kind: string; ptr?: Hex; size?: number }>;
  deviations: Deviation[];
  deterministic: boolean;
  provenance: Provenance;
}
export interface BatchResult {
  summary: {
    offset: number;
    vectors: number;
    completed: number;
    returned: number;
    byStatus: Partial<Record<StatusCode, number>>;
    byAttribution: { target: number; harness: number };
    elapsedMs: number;
    callsPerSecond: number | null;
    isolation: "snapshot" | "chain";
    from: string;
    path: "fast" | "medium" | "full";
    deterministic: boolean;
    deadlineReached: boolean;
    cancelled: boolean;
    /**
     * Review fix EMU-6: a `chain` batch whose next vector's buffers could not be placed (data.resource "heap" or
     * "scratch") ends with the completed prefix; nothing of vector `index` ran and its allocations were rolled back.
     */
    stopped?: { code: string; message: string; index: number; data?: Record<string, unknown> };
  };
  columns: {
    status: StatusCode[];
    rax: Hex[];
    xmm0lo: Hex[];
    out: Record<string, HexBytes[]>;
    instructions?: number[];
    /**
     * Review fix EMU-9: per-vector attribution of every non-returned vector ("" returned, "t" target, "h" harness),
     * uncapped (the `faults` list stops at the first 1000). Optional: older bridges omit it.
     */
    attr?: string[];
    /** per-vector pc rva of every non-returned vector (null when outside an image / returned) */
    pcRva?: (Hex | null)[];
  };
  faults: Array<{
    index: number;
    status: CallStatus;
    attribution: Attribution;
    cause: string;
    pc: Hex;
    pcRva: Hex | null;
    faultAddress?: Hex;
    import?: string;
    mnemonic?: string;
    detail?: StopRecord /* first 8 only */;
  }>;
  aggregates: {
    imports: Record<string, { calls: number; model: string }>;
    deviations: Partial<Record<DeviationKind, { vectors: number; detail?: unknown }>>;
    coverage?: CoverageWire;
    cpuidLeaves?: Hex[];
  };
  provenance: Provenance;
}
export interface SweepParams {
  session: string;
  plan: PlanWire /* target ignored */;
  vectors: VectorsWire /* count ≤ 16 */;
  functions: { module: string; rvaStart: Hex; rvaEnd: Hex; offset: number; limit: number } | { targets: Hex[] };
  options: RunOptions & { deadlineMs: number };
  match: { returns: "f32" | "f64"; argsFrom: string[]; known: string[]; toleranceUlp: number } | null;
}
export interface SweepResult {
  summary: {
    functions: number;
    completed: number;
    byOutcomeProfile: Record<string, number>;
    matched: number;
    deadlineReached: boolean;
    cancelled: boolean;
    nextOffset: number | null;
  };
  rows: Array<{ rva: Hex; module: string; statuses: StatusCode[]; rax: Hex[]; xmm0lo: Hex[]; matches: string[] }>;
  provenance: Provenance;
}
export interface HelloResult {
  protocol: typeof EMU_PROTOCOL;
  bridge: { version: string; sha256: string };
  engines: EngineVersions;
  python: { version: string; executable: string; inVenv: boolean };
  memoryLimit: MemoryLimitInfo;
  capabilities: {
    arch: ["x86_64"];
    formats: ["pe64", "bea.dump/1"];
    abi: ["win64"];
    snapshots: ["cow", "manual"];
    trace: ["imports", "blocks", "coverage", "memory", "instructions"];
    hle: string[];
    insnHooks: { cpuid: boolean; syscall: boolean; rdtsc: boolean };
    sweepKnown: string[];
  };
  limits: {
    maxFrameBytes: 67108864;
    maxMemRead: 16777216;
    maxVectorsPerBatch: 1000000;
    maxSweepTargets: 20000;
    maxSweepVectors: 16;
    maxNamedSnapshots: 16;
    maxTraceEvents: 100000;
    maxPatches: 256;
    maxOverrides: 256;
  };
}
export interface MemReadResult {
  address: Hex;
  size: number;
  region: RegionDesc;
  data: string;
  encoding: "hex" | "base64";
  overlayRestored: number;
}

export interface EmuMethods {
  "bridge.hello": {
    params: { protocol: typeof EMU_PROTOCOL; client: { name: "bea"; version: string } };
    result: HelloResult;
  };
  "bridge.ping": { params: Record<string, never>; result: { pong: true; busy: RequestId | null; sessions: number } };
  "bridge.cancel": {
    params: { requestId: RequestId };
    result: { cancelled: boolean; state: "running" | "queued" | "unknown" };
  };
  "bridge.shutdown": { params: Record<string, never>; result: { shutdown: true } };
  "session.open": { params: OpenParams; result: OpenResult };
  "session.info": { params: { session: string }; result: OpenResult & { state: SessionStateInfo } };
  "session.close": { params: { session: string }; result: { closed: boolean } };
  "state.save": { params: { session: string; name: string }; result: { name: string; bytes: number } };
  "state.restore": { params: { session: string; name: string }; result: { restored: string } };
  "state.list": {
    params: { session: string };
    result: { snapshots: Array<{ name: string; bytes: number }>; totalBytes: number; limitBytes: number };
  };
  "state.drop": { params: { session: string; name: string }; result: { dropped: boolean } };
  "mem.read": {
    params: { session: string; address: Hex; size: number; encoding?: "hex" | "base64" };
    result: MemReadResult;
  };
  "mem.write": {
    params: { session: string; address: Hex; hex?: HexBytes; base64?: string };
    result: { written: number; region: RegionDesc; tbFlushed: boolean };
  };
  "mem.disassemble": {
    params: { session: string; address: Hex; count?: number; function?: boolean };
    result: { instructions: Insn[]; function: FunctionRange | null };
  };
  "mem.regions": { params: { session: string }; result: { regions: RegionInfo[]; syntheticBase: Hex } };
  "mem.functions": {
    params: { session: string; module: string; rvaStart?: Hex; rvaEnd?: Hex; offset?: number; limit?: number };
    result: { functions: FunctionRange[]; total: number; nextOffset: number | null };
  };
  "emu.call": { params: CallParams; result: CallResult };
  "emu.batch": { params: BatchParams; result: BatchResult };
  "emu.sweep": { params: SweepParams; result: SweepResult };
}
export type EmuMethod = keyof EmuMethods;
