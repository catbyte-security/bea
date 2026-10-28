// =================================================================================================
// src/agent/calls.ts — WP3-AGENT oracle-call registry (DESIGN §5.3 `calls`, §5.3.1 rules 3–5, CT-B1, CT-I1).
// WP11's call.ts brackets every vector with `core.calls.enter(tid, token, options)` / `exit(tid)`; THE dispatcher
// consults `activeOn(tid)` before its Cloak early return: an exception inside a BEA call becomes an `exception/1` row
// with disposition `in-call` (GPRs stashed for FaultInfo), never a blocking report, and is passed on to the callee's
// own handlers or the thunk's SEH frame. Hook/profile/override listeners skip threads in a call unless observing
// (S4 §13.4); JS listeners use `suppresses(tid)`, CModule listeners the native table (`bea_in_agent_call`).
// =================================================================================================
import type { AgentStatus, ThreadId } from "../shared/agentProtocol.js";
import { CallLedger, type ActiveCall, type CallOptions, type InCallFault } from "./pure/coreCalls.js";
import type { AgentCore } from "./state.js";

export type { ActiveCall, CallOptions, InCallFault };

/** What exit() returns: the record plus the summary fields call.ts reads (in-call count, traps, last fault GPRs). */
export interface ExitedCall extends ActiveCall {
  readonly inCall: number;
  readonly hooksSuppressed: number;
  /** GPRs of the last in-call exception (FaultInfo.registers of the exception the thunk frame caught), else null */
  readonly registers: Readonly<Record<string, string>> | null;
}

export class CallRegistry {
  readonly #core: AgentCore;
  readonly #ledger = new CallLedger<NativePointer>();

  constructor(core: AgentCore) {
    this.#core = core;
  }

  newToken(): number {
    return this.#ledger.newToken();
  }

  /** The calling thread enters a BEA oracle call (nested calls deepen the existing record). */
  enter(tid: ThreadId, token: number, options?: CallOptions): ActiveCall {
    const call = this.#ledger.enter(tid, token, options);
    if (call.depth === 1) {
      this.#core.agentCallTids.set(tid, call);
      if (!call.options.observe) this.#core.native.setCallTid(tid, true);
    }
    return call;
  }

  /** Leave the call; the record (with its exception/trap counters and stashed faults) when the outermost ended. */
  exit(tid: ThreadId): ExitedCall | null {
    const call = this.#ledger.exit(tid);
    if (call === null) return null;
    this.#core.agentCallTids.delete(tid);
    if (!call.options.observe) this.#core.native.setCallTid(tid, false);
    const last = call.faults[call.faults.length - 1];
    return Object.assign(call, {
      inCall: call.exceptions,
      hooksSuppressed: 0,
      registers: last === undefined ? null : { ...last.registers },
    });
  }

  /** THE dispatcher's in-call check (hot path). */
  activeOn(tid: ThreadId): ActiveCall | null {
    return this.#ledger.activeOn(tid);
  }

  /** Hook/profile listeners: skip recording on this thread (a BEA call without hooks:"observe"). */
  suppresses(tid: ThreadId): boolean {
    const call = this.#ledger.activeOn(tid);
    return call !== null && !call.options.observe;
  }

  /** Override listeners: skip the rewrite (overrides:"bypass"). */
  bypassesOverrides(tid: ThreadId): boolean {
    return this.#ledger.activeOn(tid)?.options.bypassOverrides === true;
  }

  noteException(tid: ThreadId, fault: InCallFault): boolean {
    return this.#ledger.noteException(tid, fault);
  }

  noteTrap(tid: ThreadId): void {
    this.#ledger.noteTrap(tid);
  }

  /** CT-I1 bookkeeping for thread/hook-mode chunks (see pure/coreCalls.ts). */
  quarantine(token: number, allocations: readonly NativePointer[]): void {
    this.#ledger.quarantine(token, allocations);
  }

  expire(token: number): void {
    this.#ledger.expire(token);
  }

  beginRun(token: number): boolean {
    return this.#ledger.beginRun(token);
  }

  release(token: number): void {
    this.#ledger.release(token);
  }

  get inCallExceptions(): number {
    return this.#ledger.inCallExceptions;
  }

  status(): AgentStatus["calls"] {
    return {
      active: this.#ledger.active(),
      expired_closures: this.#ledger.expiredClosures,
      late_runs: this.#ledger.lateRuns,
      quarantined_blocks: this.#ledger.quarantinedBlocks,
    };
  }

  /** dispose / session end: drop every quarantined allocation (the references are released for GC). */
  drain(): number {
    return this.#ledger.drain().length;
  }
}
