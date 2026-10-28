// =================================================================================================
// src/agent/exceptions.ts — WP3-AGENT THE single exception dispatcher and the crash/exit capture layers (S4 §7,
// DESIGN §5.3 + Appendix A.4 #26, CT-B1/CT-B2/CT-I5).
//  Registration: Process.setExceptionHandler exactly once, at boot step 2, never again (a second call in the same
//  script replaces the first; handlers of later scripts run AFTER BEA's, F15).
//  Routing: BEA debug-register traps → BEA guard-page/TF steps (trap routers registered by WP9, then the core guard
//  fallback) → IN-CALL check (an exception inside a BEA oracle call: `in-call` row, GPRs stashed, never a blocking
//  report, return false so the callee's handlers or the thunk's SEH frame decide) → Cloak early return for agent and
//  Frida threads → first-chance row (+ optional rate-limited blocking crash report). BEA returns true only for its own
//  traps. The dispatcher sees only exceptions raised outside Frida try-scopes [CT-lab E6–E9].
//  Last chance: a kernelbase!UnhandledExceptionFilter listener (F13). Exit flush: RtlExitUserProcess and
//  NtTerminateProcess(self) listeners flush every stream and wait (bounded) for the host's ack (F11/F12).
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
import { ExceptionRowLimiter, LruMap, SlidingCount } from "./pure/coreRate.js";
import { hexOfBigint, hexOfU32, xmmHex } from "./pure/coreHex.js";
import { EXCEPTION_MAXIMUM_PARAMETERS, EXR, exceptionTypeOfStatus, memoryOperationOf } from "./pure/coreWin64.js";
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

const NT_CURRENT_PROCESS = "0xffffffffffffffff";

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

export class ExceptionDispatcher {
  readonly #core: AgentCore;
  #installed = false;
  readonly #routers: TrapRouter[] = [];
  readonly byType: Partial<Record<ExceptionType, number>> = {};
  blockingReports = 0;
  lastChance = 0;
  beaTraps = 0;
  #reportSeq = 0;
  #exitReported = false;
  readonly #crashLimiter = new SlidingCount(8, 10_000);
  readonly #rowLimiter = new ExceptionRowLimiter<{ row: ExceptionRow; bseq: number }>(1000);
  readonly #crashCache = new LruMap<ThreadId, CachedCrash>(64);
  /** [start, end) of KERNELBASE!RaiseException (resolved at boot step 3; null when unknown) */
  #raiseException: { readonly start: bigint; readonly end: bigint } | null = null;

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

  /** Re-apply the crash policy after hello. */
  configure(): void {
    const crash = this.#core.config.crash;
    this.#crashLimiter.setMax(crash.max_blocking_per_10s);
    this.#rowLimiter.setRate(crash.rows_per_sec);
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
      if (Cloak.hasCurrentThread()) return false;
      this.#firstChance(d, tid);
      return false;
    } catch (e) {
      c.fault("exception-dispatcher", e);
      return false;
    }
  }

  /** Install the last-chance and exit-flush listeners (boot step 3); failures are recorded, not fatal. */
  installCoreHooks(): void {
    this.#hook(
      "kernelbase.dll",
      "UnhandledExceptionFilter",
      (self, args) => this.#onUnhandled(self, args),
      () => {
        this.#core.early.last_chance_hook = true;
        this.#core.features.push("crash.last-chance");
      },
    );
    this.#hook(
      "ntdll.dll",
      "RtlExitUserProcess",
      (_self, args) => this.#onExit("RtlExitUserProcess", args[0]!),
      () => {
        this.#core.early.exit_hook = true;
        this.#core.features.push("exit-flush");
      },
    );
    this.#hook("ntdll.dll", "NtTerminateProcess", (_self, args) => {
      if (args[0]!.toString() === NT_CURRENT_PROCESS) this.#onExit("NtTerminateProcess(self)", args[1]!);
    });
    this.#raiseException = raiseExceptionRange();
    Interceptor.flush();
    for (const site of this.#hookSites) this.#core.originals.markPatched(site);
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

  #reportFirstChance(d: ExceptionDetails, tid: ThreadId, g: number): void {
    const c = this.#core;
    const ctx = readContextAt(d.nativeContext);
    const backtrace = this.#backtrace(d.address, d.context);
    this.#crashCache.set(tid, { address: d.address.toString(), backtrace });
    const report = this.#baseReport("first-chance", g, tid, d.type, d.address, ctx);
    report.memory = d.memory === undefined ? null : { operation: d.memory.operation, address: hex(d.memory.address) };
    report.backtrace = backtrace;
    report.backtrace_source = "exception-context";
    this.#send(report, c.config.crash.ack_timeout_ms, false);
    this.blockingReports++;
  }

  #onUnhandled(self: InvocationContext, args: InvocationArguments): void {
    const c = this.#core;
    try {
      const ep = args[0]!;
      const er = ep.readPointer();
      const cr = ep.add(8).readPointer();
      const tid = Process.getCurrentThreadId();
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
        report.backtrace = this.#backtrace(address, self.context);
        report.backtrace_source = "uef-context";
      }
      this.lastChance++;
      this.#send(report, c.config.crash.last_chance_ack_timeout_ms, false);
    } catch (e) {
      c.fault("last-chance-report", e);
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

  #backtrace(pc: NativePointer, context: CpuContext): CrashReport["backtrace"] {
    const c = this.#core;
    const depth = Math.min(c.config.crash.backtrace_depth, c.limits.max_backtrace_depth);
    let frames: NativePointer[] = [];
    try {
      frames = Thread.backtrace(context, Backtracer.ACCURATE).slice(0, depth);
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
