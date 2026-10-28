import type {
  AgentResult,
  AgentRpcImpl,
  CallFunctionParams,
  CallFunctionResult,
  FaultInfo,
  Hex,
  ResolvedTarget,
} from "../shared/agentProtocol.js";
import type { StatusCode } from "../shared/callPlan.js";
import { CODE_OF_TYPE, disposeThunk, installThunk, type Thunk } from "./callThunk.js";
import { fail, ok } from "./errors.js";
import { CALL_BLOCK, exceptionTypeOf, memoryOperationOf, STATUS_CAUGHT, STATUS_RETURNED } from "./pure/callBlock.js";
import { hookInstallFailedAt } from "./pure/coreErrors.js";
import {
  bitsHex,
  buildBlock,
  bytesHex,
  checkPlan,
  layoutScratch,
  materializeBuffer,
  parseBlock,
  registerFile,
} from "./pure/callMaterialize.js";
import type { AgentCore } from "./state.js";

/**
 * Agent feature `call` (WP11-CALL; DESIGN §5.3 "Calls", §5.3.1; S4 §13; S5 §9.5 as amended). callFunction runs a
 * host-classified PlanWire over raw-bit VectorsWire through the registered SEH-frame thunk:
 * - per vector: buffers materialized in a per-chunk scratch arena (template -> column patches -> ptrFields), the
 *   CallBlock written (target, GPR/XMM/stack, nstack, MXCSR & 0xFFC0, FPCW), the thunk called, status/RAX/XMM0/
 *   MXCSR/FPCW and out buffers read back as hex; status 2 = an exception no callee frame handled (FaultInfo);
 * - chunks of ≤ `chunk` vectors and time slices of `max_wall_ms` (next_offset continues);
 * - thread modes (CT-I1): `thread` refuses a thread whose RIP sits in an ntdll syscall stub (ThreadBusy) and runs the
 *   chunk in Process.runOnThread; `hook` runs it inside onEnter of a temporary listener at `at`. A chunk that has not
 *   run when its timeout expires is EXPIRED: its closure later returns at once (late run) and its allocation stays
 *   quarantined until then. A chunk whose callee STARTED but had not returned when the timeout expired is still
 *   running on its thread: Timeout{started:true} says so (the function's effects may have happened), no further vector
 *   of that chunk starts, and dispose leaves the thunk page and its function table in place while any call may still
 *   be on a target thread (review fix AGENT-1: the callee returns into that page; freeing it killed the target).
 * - the temporary hook-mode listener follows the Stalker rule of every BEA attach/detach (S4 §12.1): flush, then
 *   invalidate the site for followed threads (review fix AGENT-7).
 * Core services (DESIGN §5.3 rev. 2, owned by WP3) are bound structurally at init (see bindCore): the calls registry
 * (`enter`/`exit`/`activeOn`, consulted by THE dispatcher's in-call branch) and the hook-suppression map.
 */

// ---------------------------------------------------------------- core binding (WP3 services, structural)

/**
 * The WP3 calls registry as call.ts uses it (src/agent/calls.ts CallRegistry). Bound structurally so this feature
 * compiles and runs against any core: without a registry it keeps local token/expiry counters (and maintains
 * core.agentCallTids when present) and reports callee_exceptions/bea_traps as 0.
 */
interface InCallFaultLike {
  readonly address?: unknown;
  readonly registers?: unknown;
}
interface CallRecordLike {
  readonly exceptions?: unknown;
  readonly beaTraps?: unknown;
  readonly faults?: readonly InCallFaultLike[];
}
interface CallsApi {
  enter(tid: number, token: number, options: { readonly observe: boolean; readonly bypassOverrides: boolean }): unknown;
  exit(tid: number): CallRecordLike | null;
  newToken?(): number;
  expire?(token: number): void;
  quarantine?(token: number, allocations: readonly NativePointer[]): void;
  beginRun?(token: number): boolean;
  release?(token: number): void;
  /** WP3 CallRegistry.status(): the threads currently inside a call */
  status?(): { readonly active: readonly unknown[] };
}
interface ExitStats {
  readonly inCall: number;
  readonly beaTraps: number;
  readonly faults: readonly InCallFaultLike[];
}
interface BoundCore {
  readonly calls: CallsApi | null;
  readonly agentCallTids: Map<number, unknown> | null;
  readonly listInstruments: (() => readonly { readonly id: string; readonly targets: readonly string[] }[]) | null;
  readonly onDispose: (() => void)[] | null;
  /** StalkerCoordinator.invalidateAll: re-compile followed threads' blocks at `sites` after an attach/detach */
  readonly invalidate: ((sites: readonly NativePointer[]) => void) | null;
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null;
const countOf = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) ? v : 0);

const bindCore = (c: AgentCore): BoundCore => {
  const raw = c as unknown as Record<string, unknown>;
  const calls = raw["calls"];
  const tids = raw["agentCallTids"];
  const instruments = raw["instruments"];
  const hooks = raw["hooks"];
  const stalkerCo = raw["stalkerCo"];
  const invalidateAll =
    isRecord(stalkerCo) && typeof stalkerCo["invalidateAll"] === "function"
      ? (stalkerCo["invalidateAll"] as (sites: readonly NativePointer[]) => unknown)
      : null;
  return {
    calls:
      isRecord(calls) && typeof calls["enter"] === "function" && typeof calls["exit"] === "function"
        ? (calls as unknown as CallsApi)
        : null,
    agentCallTids: tids instanceof Map ? (tids as Map<number, unknown>) : null,
    // active instruments incl. externally registered ones (InstrumentRegistry.infos), else the own list
    listInstruments:
      isRecord(instruments) && typeof instruments["infos"] === "function"
        ? () =>
            (instruments["infos"] as (ended: boolean) => readonly { id: string; targets: readonly string[] }[]).call(
              instruments,
              false,
            )
        : isRecord(instruments) && typeof instruments["list"] === "function"
          ? () => (instruments["list"] as () => readonly { id: string; targets: readonly string[] }[]).call(instruments)
          : null,
    onDispose: isRecord(hooks) && Array.isArray(hooks["onDispose"]) ? (hooks["onDispose"] as (() => void)[]) : null,
    invalidate: invalidateAll === null ? null : (sites) => void invalidateAll.call(stalkerCo, sites),
  };
};

const exitStatsOf = (record: CallRecordLike | null): ExitStats =>
  record === null
    ? { inCall: 0, beaTraps: 0, faults: [] }
    : { inCall: countOf(record.exceptions), beaTraps: countOf(record.beaTraps), faults: record.faults ?? [] };

// ---------------------------------------------------------------- module state (kept reachable: QJS frees eagerly)

let core: AgentCore | null = null;
let bound: BoundCore = {
  calls: null,
  agentCallTids: null,
  listInstruments: null,
  onDispose: null,
  invalidate: null,
};
let thunk: Thunk | null = null;
let nextToken = 1;
interface Allocation {
  readonly block: NativePointer;
  readonly scratch: NativePointer;
  readonly base: NativePointer;
  readonly offsets: ReadonlyMap<string, number>;
}
const running = new Set<Allocation>();
const quarantined = new Set<Allocation>();
/** CT-I1 counters (the core's status().calls reads them when it has no registry of its own). */
export const callCounters = { expiredClosures: 0, lateRuns: 0, quarantinedBlocks: (): number => quarantined.size };

/**
 * A call may still execute on a target thread: an RPC in flight (`running`), a thread/hook chunk past its timeout whose
 * closure has not finished (`quarantined`), or a thread the registry still has inside enter..exit. Such a callee
 * returns into the thunk page, and its exceptions are dispatched through the page's function table.
 */
const callsInFlight = (): boolean =>
  running.size > 0 || quarantined.size > 0 || (bound.calls?.status?.().active.length ?? 0) > 0;

export function init(c: AgentCore): void {
  core = c;
  bound = bindCore(c);
  try {
    thunk = installThunk();
    if (!c.features.includes("call")) c.features.push("call");
    // rule 1: RtlDeleteFunctionTable (and VirtualFree) on unload; quarantined allocations go with the script. Not while
    // a call may still be on a target thread (review fix AGENT-1): the page is VirtualAlloc'd so that it can be leaked
    // (4 KiB, its unwind data stays valid); freeing it under a running callee killed the target when it returned.
    bound.onDispose?.push(() => {
      if (callsInFlight()) return;
      disposeThunk();
      quarantined.clear();
    });
  } catch {
    thunk = null; // callFunction answers Unsupported; the agent keeps loading
  }
}

const newToken = (): number => bound.calls?.newToken?.() ?? nextToken++;

// ---------------------------------------------------------------- one chunk on the current thread

interface ChunkJob {
  readonly params: CallFunctionParams;
  readonly target: bigint;
  readonly alloc: Allocation;
  readonly token: number;
  /** expired: the RPC gave up (no further vector starts); began: the closure ran and started calling */
  readonly state: { expired: boolean; began: boolean };
}
interface ChunkOutput {
  readonly status: StatusCode[];
  readonly rax: Hex[];
  readonly xmm0lo: Hex[];
  readonly mxcsrOut: Hex[];
  readonly fpcwOut: Hex[];
  readonly out: Record<string, string[]>;
  readonly faults: FaultInfo[];
  readonly coverage: { index: number; events: ArrayBuffer[]; truncated: boolean }[];
  threadId: number;
  calleeExceptions: number;
  beaTraps: number;
  hooksSuppressed: number;
}

const ptrBits = (p: NativePointer): bigint => BigInt(p.toString());
const hexOfPtr = (p: NativePointer): Hex => bitsHex(ptrBits(p));

const moduleOf = (address: NativePointer): { module: string | null; rva: Hex | null } => {
  const m = Process.findModuleByAddress(address);
  return m === null ? { module: null, rva: null } : { module: m.name, rva: hexOfPtr(address.sub(m.base)) };
};

const enterCall = (tid: number, token: number, p: CallFunctionParams): void => {
  const options = { observe: p.hooks === "observe", bypassOverrides: p.overrides === "bypass" };
  if (bound.calls !== null) bound.calls.enter(tid, token, options);
  else if (bound.agentCallTids !== null && p.hooks === "suppress")
    bound.agentCallTids.set(tid, { tid, token, options });
};
const exitCall = (tid: number, p: CallFunctionParams): ExitStats => {
  if (bound.calls !== null) return exitStatsOf(bound.calls.exit(tid));
  if (bound.agentCallTids !== null && p.hooks === "suppress") bound.agentCallTids.delete(tid);
  return { inCall: 0, beaTraps: 0, faults: [] };
};

/** The dispatcher's GPRs of the in-call exception at the same address (DESIGN §5.3.1 rule 3), else {rip, rsp}. */
const registersOf = (stats: ExitStats, address: bigint, fallback: Record<string, Hex>): Record<string, Hex> => {
  for (let k = stats.faults.length - 1; k >= 0; k--) {
    const fault = stats.faults[k];
    if (fault === undefined || typeof fault.address !== "string" || !isRecord(fault.registers)) continue;
    if (BigInt(fault.address) === address) return fault.registers as Record<string, Hex>;
  }
  return fallback;
};

const faultFromBlock = (index: number, b: ReturnType<typeof parseBlock>, stats: ExitStats): FaultInfo => {
  const address = ptr(bitsHex(b.exceptionAddress));
  const type = exceptionTypeOf(b.code);
  const info = b.info.slice(0, Math.min(b.nparams, 3)).map(bitsHex);
  return {
    index,
    type,
    address: bitsHex(b.exceptionAddress),
    memory:
      type === "access-violation" && b.nparams >= 2
        ? { operation: memoryOperationOf(Number(b.info[0] ?? 0n)), address: bitsHex(b.info[1] ?? 0n) }
        : null,
    code: bitsHex(BigInt(b.code >>> 0)),
    information: info,
    ...moduleOf(address),
    registers: registersOf(stats, b.exceptionAddress, { rip: bitsHex(b.faultRip), rsp: bitsHex(b.faultRsp) }),
  };
};

/** Steal fallback (no registered frame): the stolen JS error carries type, address, memory and the context. */
const faultFromError = (index: number, e: unknown): FaultInfo => {
  const err = (isRecord(e) ? e : {}) as {
    type?: string;
    address?: NativePointer;
    memory?: { operation: string; address: NativePointer };
    context?: { pc: NativePointer; sp: NativePointer };
  };
  const type = (err.type ?? "system") as FaultInfo["type"];
  const address = err.address ?? NULL;
  return {
    index,
    type,
    address: hexOfPtr(address),
    memory:
      err.memory === undefined
        ? null
        : { operation: err.memory.operation as "read" | "write" | "execute", address: hexOfPtr(err.memory.address) },
    code: bitsHex(BigInt(CODE_OF_TYPE[type] ?? 0)),
    information: [],
    ...moduleOf(address),
    registers: err.context === undefined ? {} : { rip: hexOfPtr(err.context.pc), rsp: hexOfPtr(err.context.sp) },
  };
};

const followForCoverage = (tid: number, sink: ArrayBuffer[]): boolean => {
  try {
    Stalker.follow(tid, { events: { compile: true }, onReceive: (events) => void sink.push(events) });
    return true;
  } catch {
    return false;
  }
};

/** Runs the job's vectors on the calling thread until done, expired or out of its time slice. */
const runChunk = (job: ChunkJob, active: Thunk): ChunkOutput => {
  const p = job.params;
  const tid = Process.getCurrentThreadId();
  const out: ChunkOutput = {
    status: [],
    rax: [],
    xmm0lo: [],
    mxcsrOut: [],
    fpcwOut: [],
    out: {},
    faults: [],
    coverage: [],
    threadId: tid,
    calleeExceptions: 0,
    beaTraps: 0,
    hooksSuppressed: 0,
  };
  const addressOf = (name: string): bigint => ptrBits(job.alloc.base.add(job.alloc.offsets.get(name) ?? 0));
  const started = Date.now();
  for (let i = 0; i < p.vectors.count; i++) {
    if (job.state.expired || (i > 0 && Date.now() - started >= p.max_wall_ms)) break;
    // Coverage: ONE vector per RPC. Following the current thread again in the same JS turn after an unfollow wedges
    // Stalker and later the script unload (VERIFIED, WP11 lab); the RPC boundary yields to the event loop.
    if (i > 0 && p.coverage.mode === "blocks") break;
    const images = new Map<string, Uint8Array>();
    for (const buffer of p.plan.buffers) {
      const bytes = materializeBuffer(buffer, p.vectors, i, addressOf);
      images.set(buffer.name, bytes);
      job.alloc.base.add(job.alloc.offsets.get(buffer.name) ?? 0).writeByteArray(bytes.buffer as ArrayBuffer);
    }
    const regs = registerFile(p.plan, p.vectors, i, addressOf, (name) => images.get(name) ?? new Uint8Array(8));
    job.alloc.block.writeByteArray(buildBlock(job.target, regs, p.fp).buffer as ArrayBuffer);
    const events: ArrayBuffer[] = [];
    const traced = p.coverage.mode === "blocks" && followForCoverage(tid, events);
    enterCall(tid, job.token, p);
    let stolen: unknown = null;
    try {
      (traced ? active.callTraced : active.call)(job.alloc.block);
    } catch (e) {
      stolen = e;
    }
    const stats = exitCall(tid, p);
    if (traced) {
      Stalker.unfollow(); // the calling thread (S4 §13.5; the lab form)
      Stalker.flush();
    }
    if (stolen !== null) active.restoreEnv(job.alloc.block);
    const index = p.vectors.offset + i;
    const block = parseBlock(
      new Uint8Array(job.alloc.block.readByteArray(CALL_BLOCK.size) ?? new ArrayBuffer(CALL_BLOCK.size)),
    );
    let status: StatusCode;
    if (stolen !== null) {
      status = "fault";
      out.faults.push(faultFromError(index, stolen));
    } else if (block.status === STATUS_CAUGHT) {
      status = "fault";
      out.faults.push(faultFromBlock(index, block, stats));
    } else status = block.status === STATUS_RETURNED ? "ok" : "eng";
    out.calleeExceptions += Math.max(0, stats.inCall - (status === "fault" ? 1 : 0));
    out.beaTraps += stats.beaTraps;
    out.status.push(status);
    out.rax.push(bitsHex(block.rax));
    out.xmm0lo.push(bitsHex(block.xmm0lo));
    out.mxcsrOut.push(bitsHex(BigInt(block.mxcsrOut)));
    out.fpcwOut.push(bitsHex(BigInt(block.fpcwOut)));
    for (const buffer of p.plan.buffers) {
      if (!buffer.out) continue;
      const bytes = job.alloc.base.add(job.alloc.offsets.get(buffer.name) ?? 0).readByteArray(buffer.size);
      (out.out[buffer.name] ??= []).push(bytesHex(new Uint8Array(bytes ?? new ArrayBuffer(0))));
    }
    if (p.coverage.mode === "blocks") out.coverage.push({ index, events, truncated: !traced });
  }
  return out;
};

// ---------------------------------------------------------------- rpc

const allocate = (p: CallFunctionParams): Allocation => {
  const layout = layoutScratch(p.plan.buffers);
  const block = Memory.alloc(CALL_BLOCK.size);
  const scratch = Memory.alloc(layout.total + layout.maxAlign);
  const misalign = scratch.and(ptr(layout.maxAlign - 1)).toUInt32();
  return { block, scratch, base: scratch.add((layout.maxAlign - misalign) % layout.maxAlign), offsets: layout.offsets };
};

const resolvedTarget = (target: NativePointer): ResolvedTarget => {
  const m = Process.findModuleByAddress(target);
  const range = Process.findRangeByAddress(target);
  return {
    va: hexOfPtr(target),
    module: m?.name ?? null,
    module_base: m === null ? null : hexOfPtr(m.base),
    rva: m === null ? null : hexOfPtr(target.sub(m.base)),
    export: null,
    function: null,
    protection: range?.protection ?? null,
  };
};

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** Per-vector Stalker compile events -> unique [start, size] blocks outside the thunk page, module filter applied. */
const coverageOf = (
  output: ChunkOutput,
  p: CallFunctionParams,
  page: NativePointer,
): CallFunctionResult["coverage"] => {
  const modules = new Set(p.coverage.modules.map((m) => m.toLowerCase()));
  const pageEnd = page.add(Process.pageSize);
  return output.coverage.map((vector) => {
    const seen = new Map<string, number>();
    let truncated = vector.truncated;
    for (const events of vector.events)
      for (const event of Stalker.parse(events, {
        annotate: false,
        stringify: false,
      }) as unknown as NativePointer[][]) {
        const [start, end] = event;
        if (start === undefined || end === undefined) continue;
        if (start.compare(page) >= 0 && start.compare(pageEnd) < 0) continue;
        if (modules.size > 0 && !modules.has((Process.findModuleByAddress(start)?.name ?? "").toLowerCase())) continue;
        if (seen.size >= p.coverage.max_blocks) {
          truncated = true;
          break;
        }
        seen.set(hexOfPtr(start), end.sub(start).toInt32());
      }
    return {
      index: vector.index,
      blocks: [...seen].map(([start, size]) => [start as Hex, size] as [Hex, number]),
      truncated,
    };
  });
};

const resultOf = (job: ChunkJob, output: ChunkOutput, active: Thunk): CallFunctionResult => {
  const p = job.params;
  const completed = output.status.length;
  const targetPtr = ptr(bitsHex(job.target));
  const targetHex = hexOfPtr(targetPtr);
  return {
    raw: {
      completed,
      status: output.status,
      rax: output.rax,
      xmm0lo: output.xmm0lo,
      out: output.out,
      mxcsrOut: output.mxcsrOut,
      fpcwOut: output.fpcwOut,
    },
    next_offset: completed < p.vectors.count ? p.vectors.offset + completed : null,
    thread_id: output.threadId,
    faults: output.faults,
    lost_target: false,
    exception_model: active.model,
    callee_exceptions: output.calleeExceptions,
    bea_traps_during_call: output.beaTraps,
    coverage: p.coverage.mode === "blocks" ? coverageOf(output, p, active.page) : null,
    resolved: resolvedTarget(targetPtr),
    perturbation: {
      target_instruments: (bound.listInstruments?.() ?? [])
        .filter((i) => i.targets.includes(targetHex))
        .map((i) => i.id),
      overrides_bypassed: p.overrides === "bypass",
      hooks_suppressed: output.hooksSuppressed,
    },
    // targets[0] = the function; targets[1..] = each plan buffer's scratch range (the host reports them per buffer)
    effect: {
      kind: "function-called",
      reversible: false,
      targets: [
        { address: targetHex, size: null },
        ...p.plan.buffers.map((b) => ({
          address: hexOfPtr(job.alloc.base.add(job.alloc.offsets.get(b.name) ?? 0)),
          size: b.size,
        })),
      ],
      thread_ids: [output.threadId],
      before: [],
    },
  };
};

/** CT-I1: a thread whose RIP is right after an ntdll `syscall` is blocked in the kernel; runOnThread would run late. */
const threadBusy = (tid: number): AgentResult<never> | null => {
  const thread = Process.enumerateThreads().find((t) => t.id === tid);
  if (thread === undefined)
    return fail({ _tag: "NotFound", message: "no such thread", what: "thread", id: String(tid) });
  const ntdll = Process.findModuleByName("ntdll.dll");
  const pc = thread.context.pc;
  try {
    if (
      ntdll !== null &&
      pc.compare(ntdll.base) >= 0 &&
      pc.compare(ntdll.base.add(ntdll.size)) < 0 &&
      pc.sub(2).readU16() === 0x050f
    )
      return fail({
        _tag: "ThreadBusy",
        message: "thread is inside a system call",
        thread_id: tid,
        reason: "in-syscall",
      });
  } catch {
    return null;
  }
  return null;
};

const TIMED_OUT = Symbol("timed-out");

/**
 * Races a thread chunk against its timeout. An expired job (CT-I1): the token is marked expired (its closure returns
 * at once whenever it runs: a late run) and the CallBlock + scratch stay quarantined until then; dispose drops the
 * rest. The registry (WP3) keeps the status().calls counters; the local ones back the core-less harness.
 */
const awaitThreadChunk = async (
  job: ChunkJob,
  started: Promise<ChunkOutput | null>,
  timeoutMs: number,
): Promise<ChunkOutput | typeof TIMED_OUT> => {
  let timer: ReturnType<typeof setTimeout> | null = null;
  const timeout = new Promise<typeof TIMED_OUT>((resolve) => {
    timer = setTimeout(() => resolve(TIMED_OUT), timeoutMs);
  });
  const winner = await Promise.race([started, timeout]);
  if (timer !== null) clearTimeout(timer);
  if (winner === TIMED_OUT || winner === null) {
    job.state.expired = true;
    callCounters.expiredClosures += 1;
    bound.calls?.expire?.(job.token);
    bound.calls?.quarantine?.(job.token, [job.alloc.block, job.alloc.scratch]);
    running.delete(job.alloc);
    quarantined.add(job.alloc);
    const leave = (): void => {
      quarantined.delete(job.alloc);
    };
    void started.then(leave, leave);
    return TIMED_OUT;
  }
  bound.calls?.release?.(job.token);
  return winner;
};

/** First thing a chunk's closure does on its thread: false = expired (late run, return without calling). */
const beginRun = (job: ChunkJob): boolean => {
  const registryAllows = bound.calls?.beginRun?.(job.token) ?? true;
  if (!job.state.expired && registryAllows) {
    job.state.began = true;
    return true;
  }
  callCounters.lateRuns += 1;
  return false;
};

const runOnThread = (job: ChunkJob, active: Thunk, tid: number): Promise<ChunkOutput | null> =>
  Process.runOnThread(tid, () => (beginRun(job) ? runChunk(job, active) : null));

const runAtHook = (
  job: ChunkJob,
  active: Thunk,
  at: NativePointer,
  tid: number | null,
): { promise: Promise<ChunkOutput | null>; detach: () => void } => {
  let claimed = false;
  let settle: (value: ChunkOutput | null) => void = () => undefined;
  const promise = new Promise<ChunkOutput | null>((resolve) => {
    settle = resolve;
  });
  const listener = Interceptor.attach(at, {
    onEnter() {
      if (claimed || (tid !== null && this.threadId !== tid)) return;
      claimed = true;
      settle(beginRun(job) ? runChunk(job, active) : null);
    },
  });
  // S4 §12.1: a thread Stalker follows keeps running its old translation of `at` until the block is invalidated
  Interceptor.flush();
  bound.invalidate?.([at]);
  return {
    promise,
    detach: () => {
      listener.detach();
      Interceptor.flush();
      bound.invalidate?.([at]);
    },
  };
};

const callFunction = async (p: CallFunctionParams): Promise<AgentResult<CallFunctionResult>> => {
  const active = thunk;
  const c = core;
  if (active === null || c === null)
    return fail({
      _tag: "Unsupported",
      message: "the oracle thunk is not installed",
      feature: "call",
      reason: "thunk-install-failed",
    });
  const issues = checkPlan(p.plan, p.vectors, {
    scratchBytes: c.limits.call_scratch_bytes,
    bufferBytes: c.limits.call_buffer_bytes,
  });
  if (p.chunk < 1 || p.chunk > c.limits.call_max_vectors || p.vectors.count > p.chunk)
    issues.push({
      path: "chunk",
      problem: `chunk must be 1..${String(c.limits.call_max_vectors)} and cover vectors.count`,
    });
  if (issues.length > 0)
    return fail({ _tag: "BadParams", message: "invalid callFunction parameters", issues: issues.slice(0, 32) });
  const target = ptr(p.plan.target);
  const range = Process.findRangeByAddress(target);
  if (range === null || !range.protection.includes("x"))
    return fail({
      _tag: "NotExecutable",
      message: "the call target is not executable",
      address: p.plan.target,
      protection: range?.protection ?? null,
    });
  const params: CallFunctionParams = {
    ...p,
    max_wall_ms: Math.max(1, Math.min(p.max_wall_ms, c.limits.call_max_wall_ms)),
  };
  const job: ChunkJob = {
    params,
    target: BigInt(p.plan.target),
    alloc: allocate(params),
    token: newToken(),
    state: { expired: false, began: false },
  };
  running.add(job.alloc);
  try {
    return await execute(job, active, c);
  } finally {
    // a timed-out chunk already moved to `quarantined`; a throw (e.g. a thread_at hook that cannot be installed) must
    // not leave the allocation counted as in flight (dispose keeps the thunk page while one is: AGENT-1)
    running.delete(job.alloc);
  }
};

/** Runs the chunk on its thread (agent, runOnThread or a temporary hook) and builds the result. */
const execute = async (job: ChunkJob, active: Thunk, c: AgentCore): Promise<AgentResult<CallFunctionResult>> => {
  const p = job.params;
  let output: ChunkOutput;
  if (p.thread.kind === "agent") output = runChunk(job, active);
  else {
    if (p.thread.kind === "thread") {
      const busy = threadBusy(p.thread.tid);
      if (busy !== null) return busy;
    }
    let hooked: ReturnType<typeof runAtHook> | null = null;
    if (p.thread.kind === "hook")
      try {
        hooked = runAtHook(job, active, ptr(p.thread.at), p.thread.tid);
      } catch (e) {
        // review fix EMU-14: a thread_at site Frida cannot hook fails before any vector, naming the requested site
        return fail(hookInstallFailedAt(p.thread.at, e instanceof Error ? e.message : String(e)));
      }
    const started = hooked?.promise ?? runOnThread(job, active, p.thread.kind === "thread" ? p.thread.tid : 0);
    const winner = await awaitThreadChunk(job, started, p.thread.timeout_ms);
    hooked?.detach();
    if (winner === TIMED_OUT)
      return fail({
        _tag: "Timeout",
        // started: the callee ran (its effects may have happened) and is still running on the thread; it returns into
        // the thunk later (dispose keeps the page for it) and no further vector of this chunk starts
        message: job.state.began
          ? "the call started on the thread but did not return in time; it is still running"
          : "the thread did not run the call in time",
        timeout_ms: p.thread.timeout_ms,
        phase: p.thread.kind === "hook" ? "hook-arrival" : "run-on-thread",
        started: job.state.began,
      });
    output = winner;
  }
  if (p.coverage.mode === "blocks") {
    // trailing onReceive batches, then free the unfollowed thread's Stalker state at a safe point (script unload
    // otherwise waits on it)
    await sleep(2 * c.limits.stalker_drain_ms);
    Stalker.garbageCollect();
  }
  return ok(resultOf(job, output, active));
};

/** The installed thunk's exception model (null before init or when installation failed). @public */
export const exceptionModel = (): "seh-frame" | "steal" | null => thunk?.model ?? null;

export const rpc = {
  callFunction: (p: CallFunctionParams) => callFunction(p),
} satisfies Partial<AgentRpcImpl>;
