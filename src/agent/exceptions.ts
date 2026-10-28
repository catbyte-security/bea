// =================================================================================================
// src/agent/exceptions.ts — WP3-AGENT THE single exception dispatcher and the crash/exit capture layers (S4 §7,
// DESIGN §5.3 + Appendix A.4 #26, CT-B1/CT-B2/CT-I5).
//  Registration: Process.setExceptionHandler exactly once, at boot step 2, never again (a second call in the same
//  script replaces the first; handlers of later scripts run AFTER BEA's, F15).
//  Routing: BEA debug-register traps → BEA guard-page/TF steps (trap routers registered by WP9, then the core guard
//  fallback) → IN-CALL check (an exception inside a BEA oracle call: `in-call` row, GPRs stashed, never a blocking
//  report, return false so the callee's handlers or the thunk's SEH frame decide) → Cloak early return for agent and
//  Frida threads → a fault inside BEA's own crash report on this thread (passed) → PASS-THROUGH → first-chance row
//  (+ the opt-in, rate-limited blocking crash report). BEA returns true only for its own traps. The dispatcher sees
//  only exceptions raised outside Frida try-scopes [CT-lab E6–E9].
//  Pass-through and the opt-in first-chance report (BEA-FEEDBACK.md item 4): the dispatcher runs on the faulting
//  thread, which may hold the target's own locks. ASan's allocator commits its shadow memory from its own exception
//  handler while it holds its lock; a first-chance report that unwound with dbghelp (Thread.backtrace ACCURATE)
//  allocated through the CRT that ASan intercepts and deadlocked on that lock, and every other thread then queued on
//  the JS lock. Now (a) exceptions whose pc lies in ASan's runtime or a configured pass-through module, and access
//  violations inside ASan's shadow memory, return false at once with no row and no report (`passthrough` counts them);
//  (b) the blocking first-chance report is opt-in (pure/coreCrash.ts) and bounded by ack_timeout_ms; (c) crash
//  backtraces never use dbghelp: NtUnwinder runs ntdll's own unwinder, which allocates nothing in the target.
//  Last chance: a kernelbase!UnhandledExceptionFilter listener (F13), unwound from the exception's own CONTEXT record
//  (the dbghelp walk from inside the UEF call, "uef-context", listed the exception-dispatch frames first). Exit flush:
//  RtlExitUserProcess and NtTerminateProcess(self) listeners flush every stream and wait (bounded) for the host's ack
//  (F11/F12).
//  Software exceptions (review fix AGENT-11): an exception raised through KERNELBASE!RaiseException (C++ throws,
//  OutputDebugString, thread naming, RPC and CLR errors: Frida's type "system") has its address inside that function on
//  x64 (RtlRaiseException stores the caller's pc). At first chance it is only a row, never a blocking crash report, even
//  when the crash policy lists "system": such exceptions are normally handled, and an unhandled one is reported by the
//  last-chance layer with its NTSTATUS. They no longer use up the blocking-report budget either.
// =================================================================================================
import type { CrashReport, ExceptionRow, ExceptionType, ExitMessage, Hex, ThreadId } from "../shared/agentProtocol.js";
import { capturedGprs, readContextAt, stackWindow } from "./capture.js";
import { decodeAt } from "./disasm.js";
import { hex } from "./encode.js";
import type { GuardPageEntry } from "./guards.js";
import {
  ASAN_RUNTIME_PATTERNS,
  ASAN_SHADOW_EXPORT,
  asanShadowRange,
  isCallReturnSite,
  modulePatternMatcher,
} from "./pure/coreCrash.js";
import { ExceptionRowLimiter, LruMap, SlidingCount } from "./pure/coreRate.js";
import { hexOfBigint, hexOfU32, xmmHex } from "./pure/coreHex.js";
import {
  CTX,
  EXCEPTION_MAXIMUM_PARAMETERS,
  EXR,
  exceptionTypeOfStatus,
  isGuardProtect,
  isReadableProtect,
  MBI,
  MEM_COMMIT,
  memoryOperationOf,
} from "./pure/coreWin64.js";
import type { AgentCore } from "./state.js";

/** A BEA trap engine plugged into the dispatcher (WP9 hwbp/pageguard; the core guard fallback runs last). */
export interface TrapRouter {
  readonly name: string;
  /** lower runs first (hwbp 10, pageguard 20, core fallback 1000) */
  readonly order: number;
  /** a single-step on `tid`: true when it was BEA's (handled, the thread resumes) */
  readonly onSingleStep?: (d: ExceptionDetails, tid: ThreadId) => boolean;
  /** a guard-page trap on a BEA guard page (the OS already cleared that page's guard) */
  readonly onGuardPage?: (d: ExceptionDetails, tid: ThreadId, page: GuardPageEntry) => boolean;
}

interface CachedCrash {
  readonly address: string;
  readonly backtrace: CrashReport["backtrace"];
}

/** Modules whose first-chance exceptions pass through, and ASan's shadow (computed on the JS thread). */
interface PassthroughTable {
  readonly ranges: readonly { readonly start: NativePointer; readonly end: NativePointer }[];
  /** where the ASan runtime (or a static-runtime executable) publishes its shadow offset; null without ASan */
  readonly shadowVar: NativePointer | null;
  /** [lo, hi) of the shadow once the runtime has published a non-zero offset */
  shadow: { readonly lo: NativePointer; readonly hi: NativePointer } | null;
}

const NT_CURRENT_PROCESS = "0xffffffffffffffff";
const MEM_IMAGE = 0x1000000;
const UNW_FLAG_NHANDLER = 0;

/** ntdll!RtlVirtualUnwind(HandlerType, ImageBase, ControlPc, FunctionEntry, ContextRecord, …) */
type VirtualUnwindArgs = [
  handlerType: number,
  imageBase: NativePointer,
  controlPc: NativePointer,
  functionEntry: NativePointer,
  contextRecord: NativePointer,
  handlerData: NativePointer,
  establisherFrame: NativePointer,
  contextPointers: NativePointer,
];

/**
 * ASan's shadow range, read lazily from the published offset (the runtime sets it when it initializes, possibly after
 * BEA's hello) and cached in the table once non-zero; null without ASan or before it initialized.
 */
const publishedShadow = (table: PassthroughTable): PassthroughTable["shadow"] => {
  if (table.shadowVar === null) return null;
  try {
    const range = asanShadowRange(BigInt(table.shadowVar.readPointer().toString()));
    if (range === null) return null;
    table.shadow = { lo: ptr(hexOfBigint(range.lo)), hi: ptr(hexOfBigint(range.hi)) };
    return table.shadow;
  } catch {
    return null;
  }
};

/** KERNELBASE!RaiseException's function range from the unwind tables (Process.findFunctionRange), else null. */
const raiseExceptionRange = (): { readonly start: bigint; readonly end: bigint } | null => {
  try {
    const at = Process.findModuleByName("kernelbase.dll")?.findExportByName("RaiseException") ?? null;
    const range = at === null ? null : Process.findFunctionRange(at);
    if (range === null) return null;
    const start = BigInt(range.base.toString());
    return { start, end: start + BigInt(range.size) };
  } catch {
    return null;
  }
};

/**
 * Crash backtraces without dbghelp (BEA-FEEDBACK.md item 4): ntdll's x64 unwinder, RtlLookupFunctionEntry +
 * RtlVirtualUnwind over a private copy of the exception's CONTEXT (never the record itself, which is the state the
 * thread resumes with). RtlDispatchException runs the same unwinder on the same thread right after the vectored
 * handlers, so it adds no lock the dispatch would not take anyway, and it allocates nothing in the target. Bounded:
 * frames stop at the stack bounds (this thread's stack, else the committed readable run that holds rsp), at a return
 * address outside every mapped image (JIT code, whose unwind data could come from a callback into the target; Frida's
 * Interceptor return trampolines of a hooked function still on the stack), when rsp stops growing, or at a fault
 * (NativeFunction steals it into a JS error). A faulting pc outside every image (a call through a bad pointer, DEP) is
 * unwound with the leaf rule when [rsp] holds an address right after a call instruction. Every binding is resolved on
 * the JS thread, never in a handler.
 */
class NtUnwinder {
  readonly #ctx: NativePointer;
  /** [0] image base, [8] handler data, [16] establisher frame, [24] stack low, [32] stack high, [64] MBI */
  readonly #cells: NativePointer;
  readonly #lookup: (pc: NativePointer, imageBase: NativePointer, history: NativePointer) => NativePointer;
  readonly #unwind: (...args: VirtualUnwindArgs) => NativePointer;
  readonly #stackLimits: (lo: NativePointer, hi: NativePointer) => void;
  readonly #query: (addr: NativePointer, mbi: NativePointer, len: number) => UInt64;

  constructor(c: AgentCore) {
    const page = c.keep.pin(Memory.alloc(Process.pageSize)); // page-aligned: CONTEXT needs 16
    this.#ctx = page;
    this.#cells = page.add(0x500);
    this.#lookup = c.win.bind("ntdll.dll", "RtlLookupFunctionEntry", "pointer", ["pointer", "pointer", "pointer"]);
    this.#unwind = c.win.bind("ntdll.dll", "RtlVirtualUnwind", "pointer", [
      "uint32",
      "pointer",
      "pointer",
      "pointer",
      "pointer",
      "pointer",
      "pointer",
      "pointer",
    ]);
    this.#stackLimits = c.win.bind("kernelbase.dll", "GetCurrentThreadStackLimits", "void", ["pointer", "pointer"]);
    this.#query = c.win.VirtualQuery;
  }

  /** Return addresses above the frame a CONTEXT record describes (at most `depth`); on the thread that owns it. */
  frames(context: NativePointer, depth: number): NativePointer[] {
    const out: NativePointer[] = [];
    if (depth <= 0) return out;
    Memory.copy(this.#ctx, context, CTX.size);
    const rip = this.#ctx.add(CTX.Rip);
    const rsp = this.#ctx.add(CTX.Rsp);
    const bounds = this.#bounds(rsp.readPointer());
    if (bounds === null) return out;
    const [lo, hi] = bounds;
    try {
      while (out.length < depth) {
        const pc = rip.readPointer();
        const sp = rsp.readPointer();
        if (sp.compare(lo) < 0 || sp.add(8).compare(hi) > 0 || !sp.and(7).isNull()) break;
        const image = this.#inImage(pc);
        // outside every image only the faulting pc itself is unwound (a call through a bad pointer, a jump to data):
        // the leaf rule, when the value at [rsp] follows a call instruction
        if (!image && (out.length > 0 || !this.#followsCall(sp.readPointer()))) break;
        const entry = image ? this.#lookup(pc, this.#cells, NULL) : NULL;
        if (entry.isNull()) {
          // a leaf function (no unwind data): the return address is at [rsp]
          rip.writePointer(sp.readPointer());
          rsp.writePointer(sp.add(8));
        } else
          this.#unwind(
            UNW_FLAG_NHANDLER,
            this.#cells.readPointer(),
            pc,
            entry,
            this.#ctx,
            this.#cells.add(8),
            this.#cells.add(16),
            NULL,
          );
        const next = rip.readPointer();
        if (next.isNull() || rsp.readPointer().compare(sp) <= 0) break;
        out.push(next);
      }
    } catch {
      // a fault while unwinding (a corrupt stack): the frames so far
    }
    return out;
  }

  /** [lo, hi) to unwind in: this thread's stack, else (a fiber, a pivoted rsp) the committed readable run with rsp. */
  #bounds(sp: NativePointer): [NativePointer, NativePointer] | null {
    const cells = this.#cells;
    this.#stackLimits(cells.add(24), cells.add(32));
    const lo = cells.add(24).readPointer();
    const hi = cells.add(32).readPointer();
    if (sp.compare(lo) >= 0 && sp.compare(hi) < 0) return [lo, hi];
    const mbi = this.#mbi(sp);
    if (mbi === null || mbi.state !== MEM_COMMIT || !isReadableProtect(mbi.protect) || isGuardProtect(mbi.protect))
      return null;
    return [mbi.base, mbi.base.add(mbi.size)];
  }

  #inImage(pc: NativePointer): boolean {
    const mbi = this.#mbi(pc);
    return mbi !== null && mbi.state === MEM_COMMIT && mbi.type === MEM_IMAGE;
  }

  /** `ra` lies in an image and the bytes before it end with a call instruction. */
  #followsCall(ra: NativePointer): boolean {
    if (!this.#inImage(ra)) return false;
    const before = ra.sub(8).readByteArray(8);
    return before !== null && isCallReturnSite(new Uint8Array(before));
  }

  #mbi(p: NativePointer): { base: NativePointer; size: UInt64; state: number; protect: number; type: number } | null {
    const mbi = this.#cells.add(64);
    if (this.#query(p, mbi, MBI.size).toNumber() === 0) return null;
    return {
      base: mbi.add(MBI.BaseAddress).readPointer(),
      size: mbi.add(MBI.RegionSize).readU64(),
      state: mbi.add(MBI.State).readU32(),
      protect: mbi.add(MBI.Protect).readU32(),
      type: mbi.add(MBI.Type).readU32(),
    };
  }
}

export class ExceptionDispatcher {
  readonly #core: AgentCore;
  #installed = false;
  readonly #routers: TrapRouter[] = [];
  readonly byType: Partial<Record<ExceptionType, number>> = {};
  blockingReports = 0;
  lastChance = 0;
  beaTraps = 0;
  /** first-chance exceptions passed through with no row and no report (ASan runtime/shadow, pass-through modules) */
  passthrough = 0;
  #reportSeq = 0;
  #exitReported = false;
  readonly #crashLimiter = new SlidingCount(8, 10_000);
  readonly #rowLimiter = new ExceptionRowLimiter<{ row: ExceptionRow; bseq: number }>(1000);
  readonly #crashCache = new LruMap<ThreadId, CachedCrash>(64);
  /** [start, end) of KERNELBASE!RaiseException (resolved at boot step 3; null when unknown) */
  #raiseException: { readonly start: bigint; readonly end: bigint } | null = null;
  /** null until boot step 3, or when ntdll's unwinder could not be bound (backtraces are then [pc] only) */
  #unwinder: NtUnwinder | null = null;
  #passthroughTable: PassthroughTable = { ranges: [], shadowVar: null, shadow: null };
  /** threads producing a crash report right now: a fault inside the report is passed, never reported again */
  readonly #reporting = new Set<ThreadId>();

  constructor(core: AgentCore) {
    this.#core = core;
  }

  /** Boot step 2: THE single Process.setExceptionHandler (never re-registered). */
  install(): void {
    if (this.#installed) return;
    Process.setExceptionHandler((d) => this.dispatch(d));
    this.#installed = true;
    this.#core.early.exception_handler = true;
    this.#core.features.push("crash.first-chance");
  }

  /** WP9 (and tests) plug BEA trap engines in here; returns the unregister function. */
  registerTrapRouter(router: TrapRouter): () => void {
    this.#routers.push(router);
    this.#routers.sort((a, b) => a.order - b.order);
    return () => {
      const i = this.#routers.indexOf(router);
      if (i >= 0) this.#routers.splice(i, 1);
    };
  }

  /** Re-apply the crash policy after hello (JS thread). */
  configure(): void {
    const crash = this.#core.config.crash;
    this.#crashLimiter.setMax(crash.max_blocking_per_10s);
    this.#rowLimiter.setRate(crash.rows_per_sec);
    this.#refreshPassthrough();
  }

  dispatch(d: ExceptionDetails): boolean {
    const c = this.#core;
    const tid = Process.getCurrentThreadId();
    try {
      this.byType[d.type] = (this.byType[d.type] ?? 0) + 1;
      if (this.#routeBeaTrap(d, tid)) {
        this.beaTraps++;
        c.calls.noteTrap(tid);
        return true;
      }
      const call = c.calls.activeOn(tid);
      if (call !== null) {
        this.#inCall(d, tid);
        return false;
      }
      if (Cloak.hasCurrentThread() || this.#reporting.has(tid)) return false;
      if (this.#passesThrough(d)) {
        this.passthrough++;
        return false;
      }
      this.#firstChance(d, tid);
      return false;
    } catch (e) {
      c.fault("exception-dispatcher", e);
      return false;
    }
  }

  /** Install the last-chance and exit-flush listeners (boot step 3); failures are recorded, not fatal. */
  installCoreHooks(): void {
    const c = this.#core;
    this.#hook(
      "kernelbase.dll",
      "UnhandledExceptionFilter",
      (_self, args) => this.#onUnhandled(args),
      () => {
        c.early.last_chance_hook = true;
        c.features.push("crash.last-chance");
      },
    );
    this.#hook(
      "ntdll.dll",
      "RtlExitUserProcess",
      (_self, args) => this.#onExit("RtlExitUserProcess", args[0]!),
      () => {
        c.early.exit_hook = true;
        c.features.push("exit-flush");
      },
    );
    this.#hook("ntdll.dll", "NtTerminateProcess", (_self, args) => {
      if (args[0]!.toString() === NT_CURRENT_PROCESS) this.#onExit("NtTerminateProcess(self)", args[1]!);
    });
    this.#raiseException = raiseExceptionRange();
    try {
      this.#unwinder = new NtUnwinder(c);
    } catch (e) {
      c.fault("crash-unwinder", e);
    }
    this.#refreshPassthrough();
    c.modules.onChange(() => this.#refreshPassthrough());
    Interceptor.flush();
    for (const site of this.#hookSites) c.originals.markPatched(site);
  }

  readonly #hookSites: NativePointer[] = [];

  #hook(
    module: string,
    name: string,
    onEnter: (self: InvocationContext, args: InvocationArguments) => void,
    onInstalled?: () => void,
  ): void {
    try {
      const target = Process.getModuleByName(module).getExportByName(name);
      this.#core.originals.save(target, 32, "core");
      Interceptor.attach(target, {
        onEnter(args) {
          onEnter(this, args);
        },
      });
      this.#hookSites.push(target);
      onInstalled?.();
    } catch (e) {
      this.#core.fault(`core-hook:${name}`, e);
    }
  }

  #routeBeaTrap(d: ExceptionDetails, tid: ThreadId): boolean {
    const c = this.#core;
    if (d.type === "single-step") {
      let ours = false;
      for (const r of this.#routers) if (r.onSingleStep !== undefined && r.onSingleStep(d, tid)) ours = true;
      if (c.guards.hasPendingStep(tid) && c.guards.fallbackOnStep(d.nativeContext, tid)) ours = true;
      return ours;
    }
    if (d.type !== "guard-page" || d.memory === undefined) return false;
    const page = c.guards.find(d.memory.address);
    if (page === null) return false;
    c.guards.noteConsumed(page);
    for (const r of this.#routers) if (r.onGuardPage !== undefined && r.onGuardPage(d, tid, page)) return true;
    return c.guards.fallbackOnGuard(page, d.nativeContext, tid);
  }

  /**
   * Rebuild the pass-through table on the JS thread (boot, hello, every module load/unload batch): the ranges of ASan's
   * runtime and of the modules matching crash.passthrough_modules, and where ASan publishes its shadow offset. The
   * handler only compares pointers against this table (no loader or module-registry call on a faulting thread).
   */
  #refreshPassthrough(): void {
    const c = this.#core;
    try {
      const asan = modulePatternMatcher(ASAN_RUNTIME_PATTERNS);
      const extra = modulePatternMatcher(c.config.crash.passthrough_modules ?? []);
      const ranges: { start: NativePointer; end: NativePointer }[] = [];
      let shadowVar: NativePointer | null = null;
      for (const m of c.modules.list()) {
        const isAsan = asan?.(m.name) === true;
        if (isAsan || extra?.(m.name) === true) ranges.push({ start: m.base, end: m.base.add(m.size) });
        if (isAsan) shadowVar ??= m.findExportByName(ASAN_SHADOW_EXPORT);
      }
      // a static-runtime ASan executable carries the runtime (and the variable) itself
      shadowVar ??= Process.mainModule.findExportByName(ASAN_SHADOW_EXPORT);
      const previous = this.#passthroughTable;
      const same = shadowVar !== null && previous.shadowVar?.equals(shadowVar) === true;
      this.#passthroughTable = { ranges, shadowVar, shadow: same ? previous.shadow : null };
    } catch (e) {
      c.fault("crash-passthrough", e);
    }
  }

  /** The exception's pc is in a pass-through module, or it is an access violation inside ASan's shadow. */
  #passesThrough(d: ExceptionDetails): boolean {
    const table = this.#passthroughTable;
    for (const r of table.ranges) if (d.address.compare(r.start) >= 0 && d.address.compare(r.end) < 0) return true;
    if (d.type !== "access-violation" || d.memory === undefined) return false;
    const shadow = table.shadow ?? publishedShadow(table);
    if (shadow === null) return false;
    const a = d.memory.address;
    return a.compare(shadow.lo) >= 0 && a.compare(shadow.hi) < 0;
  }

  /** CT-B1: an exception inside a BEA oracle call on this thread. */
  #inCall(d: ExceptionDetails, tid: ThreadId): void {
    const c = this.#core;
    const g = c.native.nextG();
    const memory =
      d.memory === undefined ? null : { operation: d.memory.operation, address: hex(d.memory.address) as Hex };
    c.calls.noteException(tid, {
      g,
      type: d.type,
      address: hex(d.address),
      memory,
      registers: capturedGprs(d.context),
    });
    this.#row(d, tid, g, "in-call");
  }

  #firstChance(d: ExceptionDetails, tid: ThreadId): void {
    const c = this.#core;
    const crash = c.config.crash;
    const report =
      c.phase === "ready" &&
      crash.first_chance_blocking &&
      crash.crash_class.includes(d.type) &&
      !this.#softwareRaise(d) &&
      this.#crashLimiter.allow(Date.now());
    const g = c.native.nextG();
    if (crash.first_chance_rows) this.#row(d, tid, g, report ? "reported" : "passed");
    if (report) this.#reportFirstChance(d, tid, g);
  }

  /** A "system" exception raised by KERNELBASE!RaiseException (software, normally handled; AGENT-11). */
  #softwareRaise(d: ExceptionDetails): boolean {
    const r = this.#raiseException;
    if (d.type !== "system" || r === null) return false;
    const a = BigInt(d.address.toString());
    return a >= r.start && a < r.end;
  }

  /** One exception/1 row on s:exceptions, rate-limited with repeat folding (S4 §7.3). */
  #row(d: ExceptionDetails, tid: ThreadId, g: number, disposition: ExceptionRow[7]): void {
    const c = this.#core;
    const stream = c.systemStreams.exceptions;
    if (stream === null) return;
    const address = hex(d.address);
    const key = `${d.type}@${address}`;
    const decision = this.#rowLimiter.decide(key, Date.now(), (r) => r.bseq === stream.bseq);
    if (decision.kind === "repeat") {
      decision.row.row[8]++;
      return;
    }
    if (decision.kind === "drop") {
      c.streams.drop(stream, "rate_limit");
      return;
    }
    const mem = d.memory;
    const row: ExceptionRow = [
      g,
      c.native.nowUs(),
      tid,
      d.type,
      address,
      mem?.operation ?? null,
      mem === undefined ? null : hex(mem.address),
      disposition,
      1,
    ];
    if (c.streams.emit(stream, row, 160)) this.#rowLimiter.remember(key, { row, bseq: stream.bseq });
  }

  /** The opt-in blocking report: registers, instruction, stack window and ntdll backtrace; never dbghelp. */
  #reportFirstChance(d: ExceptionDetails, tid: ThreadId, g: number): void {
    const c = this.#core;
    this.#reporting.add(tid);
    try {
      const ctx = readContextAt(d.nativeContext);
      const backtrace = this.#backtrace(d.address, d.nativeContext);
      this.#crashCache.set(tid, { address: d.address.toString(), backtrace });
      const report = this.#baseReport("first-chance", g, tid, d.type, d.address, ctx);
      report.memory = d.memory === undefined ? null : { operation: d.memory.operation, address: hex(d.memory.address) };
      report.backtrace = backtrace;
      report.backtrace_source = "exception-context";
      this.#send(report, c.config.crash.ack_timeout_ms, false);
      this.blockingReports++;
    } finally {
      this.#reporting.delete(tid);
    }
  }

  #onUnhandled(args: InvocationArguments): void {
    const c = this.#core;
    const tid = Process.getCurrentThreadId();
    this.#reporting.add(tid);
    try {
      const ep = args[0]!;
      const er = ep.readPointer();
      const cr = ep.add(8).readPointer();
      const code = er.add(EXR.code).readU32();
      const address = er.add(EXR.address).readPointer();
      const n = Math.min(er.add(EXR.numberParameters).readU32(), EXCEPTION_MAXIMUM_PARAMETERS);
      const info: bigint[] = [];
      for (let i = 0; i < n; i++)
        info.push(
          BigInt(
            er
              .add(EXR.information + 8 * i)
              .readU64()
              .toString(),
          ),
        );
      const type = exceptionTypeOfStatus(code);
      const report = this.#baseReport("last-chance", c.native.nextG(), tid, type, address, readContextAt(cr));
      report.code = hexOfU32(code);
      report.exception_information = info.map(hexOfBigint);
      const op = type === "access-violation" && info.length >= 2 ? memoryOperationOf(info[0]!) : null;
      report.memory = op === null ? null : { operation: op, address: hexOfBigint(info[1]!) };
      const cached = this.#crashCache.get(tid);
      if (cached !== undefined && cached.address === address.toString()) {
        report.backtrace = cached.backtrace;
        report.backtrace_source = "first-chance-cache";
      } else {
        report.backtrace = this.#backtrace(address, cr);
        report.backtrace_source = "exception-context";
      }
      this.lastChance++;
      this.#send(report, c.config.crash.last_chance_ack_timeout_ms, false);
    } catch (e) {
      c.fault("last-chance-report", e);
    } finally {
      this.#reporting.delete(tid);
    }
  }

  #onExit(via: ExitMessage["via"], codeArg: NativePointer): void {
    const c = this.#core;
    if (this.#exitReported) return;
    this.#exitReported = true;
    try {
      const tid = Process.getCurrentThreadId();
      c.instruments.markProcessExit();
      const flushed = c.streams.flushAll({ final: true });
      const message: ExitMessage = {
        bea: "exit",
        ack: c.acks.token("exit"),
        via,
        exit_code: codeArg.toUInt32(),
        tid,
        g: c.native.nextG(),
        t: c.native.nowUs(),
        flushed: { streams: flushed.streams, rows: flushed.rows },
      };
      c.acks.sendAndAwaitAck(message, c.config.crash.last_chance_ack_timeout_ms);
    } catch (e) {
      c.fault("exit-flush", e);
    }
  }

  #baseReport(
    phase: CrashReport["phase"],
    g: number,
    tid: ThreadId,
    type: ExceptionType,
    address: NativePointer,
    ctx: ReturnType<typeof readContextAt>,
  ): CrashReport {
    const c = this.#core;
    const crash = c.config.crash;
    return {
      report_id: `${phase === "first-chance" ? "fc" : "lc"}-${++this.#reportSeq}`,
      phase,
      g,
      t: c.native.nowUs(),
      tid,
      type,
      code: null,
      address: hex(address),
      memory: null,
      exception_information: [],
      registers: ctx === null ? emptyRegisters(address) : ctx.registers,
      eflags: ctx === null ? null : hexOfU32(ctx.parsed.eflags),
      mxcsr: ctx === null ? null : hexOfU32(ctx.parsed.mxcsr),
      fpcw: ctx === null ? null : hexOfU32(ctx.parsed.fpcw),
      xmm: ctx !== null && crash.include_xmm ? ctx.parsed.xmm.map(xmmHex) : null,
      instruction: instructionAt(c, address),
      backtrace: [],
      backtrace_source: "exception-context",
      stack: ctx === null ? null : stackWindow(c, ctx.parsed.gpr.rsp, crash.stack_bytes),
      module_map_epoch: c.modules.epoch,
      flushed: { streams: 0, rows: 0 },
    };
  }

  /** [pc, ...return addresses] unwound from a CONTEXT record (the exception's own) with ntdll's unwinder. */
  #backtrace(pc: NativePointer, context: NativePointer): CrashReport["backtrace"] {
    const c = this.#core;
    const depth = Math.min(c.config.crash.backtrace_depth, c.limits.max_backtrace_depth);
    let frames: NativePointer[] = [];
    try {
      frames = this.#unwinder?.frames(context, depth) ?? [];
    } catch (e) {
      c.fault("crash-backtrace", e);
    }
    return [pc, ...frames].map((p) => c.modules.locate(p));
  }

  /** Flush every pending row first (a crash may be fatal), then send the report and wait for the host's ack. */
  #send(report: CrashReport, timeoutMs: number, final: boolean): void {
    const c = this.#core;
    const flushed = c.streams.flushAll({ final });
    report.flushed = { streams: flushed.streams, rows: flushed.rows };
    c.acks.sendAndAwaitAck({ bea: "crash", ack: c.acks.token("crash"), report }, timeoutMs);
  }
}

const emptyRegisters = (pc: NativePointer): CrashReport["registers"] => {
  const r = {} as CrashReport["registers"];
  for (const k of [
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "rbp",
    "rsp",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
  ] as const)
    r[k] = "0x0";
  r.rip = hex(pc);
  return r;
};

const instructionAt = (c: AgentCore, address: NativePointer): CrashReport["instruction"] => {
  try {
    const insn = decodeAt(c, address, true);
    return insn === null ? null : { address: hex(address), bytes: insn.bytes, text: insn.text };
  } catch {
    return null;
  }
};
