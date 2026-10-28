// =================================================================================================
// src/agent/pure/coreCalls.ts — WP3-AGENT pure core of the oracle-call registry (DESIGN §5.3.1, CT-B1/CT-I1, S4 §13.4).
//  - enter/exit/activeOn(tid): the dispatcher's in-call check (an exception inside a BEA call is an `in-call` row,
//    never a blocking report); per-call counters for callee exceptions and BEA traps; the last in-call faults with
//    their GPRs so call.ts can fill FaultInfo.registers for the exception the thunk frame caught.
//  - Tokens, expiry and quarantine for runOnThread/hook-mode chunks whose closure had not run when the RPC timed out:
//    expired closures run later as no-ops (late_runs) and release their allocation; dispose frees the rest.
// Generic over the allocation type so it stays free of GumJS types; calls.ts adds the native tid table.
// =================================================================================================
import type { ExceptionType, Hex, ThreadId } from "../../shared/agentProtocol.js";

export interface InCallFault {
  readonly g: number;
  readonly type: ExceptionType;
  readonly address: Hex;
  readonly memory: { readonly operation: "read" | "write" | "execute"; readonly address: Hex } | null;
  readonly registers: Readonly<Record<string, Hex>>;
}

export interface CallOptions {
  /** hook/profile listeners record calls on this thread (hooks:"observe") */
  readonly observe: boolean;
  /** override listeners skip their rewrite (overrides:"bypass") */
  readonly bypassOverrides: boolean;
}

export interface ActiveCall {
  /** the depth as the record's primitive value (seams that store depth numbers compare `entry > 0`) */
  valueOf(): number;
  readonly tid: ThreadId;
  readonly token: number;
  readonly options: CallOptions;
  /** S4 §13.4 record fields (agentCallTids value): hooks:"observe" and overrides:"bypass" of this call */
  readonly observe: boolean;
  readonly bypassOverrides: boolean;
  depth: number;
  /** first-chance exceptions the dispatcher saw on this thread during the call */
  exceptions: number;
  /** BEA traps (DR hits, guard/TF steps) handled during the call */
  beaTraps: number;
  /** last ≤ 8 in-call exceptions, newest last */
  readonly faults: InCallFault[];
}

const MAX_FAULTS = 8;
const DEFAULT_OPTIONS: CallOptions = { observe: false, bypassOverrides: false };

export class CallLedger<A> {
  readonly #active = new Map<ThreadId, ActiveCall>();
  readonly #quarantine = new Map<number, A[]>();
  readonly #expired = new Set<number>();
  #nextToken = 1;
  expiredClosures = 0;
  lateRuns = 0;
  inCallExceptions = 0;

  newToken(): number {
    return this.#nextToken++;
  }

  /** Mark `tid` as running a BEA call (nested calls on one thread increase the depth). */
  enter(tid: ThreadId, token: number, options: CallOptions = DEFAULT_OPTIONS): ActiveCall {
    const existing = this.#active.get(tid);
    if (existing !== undefined) {
      existing.depth++;
      return existing;
    }
    const call: ActiveCall = {
      tid,
      token,
      options,
      observe: options.observe,
      bypassOverrides: options.bypassOverrides,
      depth: 1,
      exceptions: 0,
      beaTraps: 0,
      faults: [],
      valueOf() {
        return this.depth;
      },
    };
    this.#active.set(tid, call);
    return call;
  }

  /** Leave the call; returns the record when the outermost call on the thread ended, else null. */
  exit(tid: ThreadId): ActiveCall | null {
    const call = this.#active.get(tid);
    if (call === undefined) return null;
    call.depth--;
    if (call.depth > 0) return null;
    this.#active.delete(tid);
    return call;
  }

  activeOn(tid: ThreadId): ActiveCall | null {
    return this.#active.get(tid) ?? null;
  }

  /** Dispatcher: an exception raised inside the call on `tid` (recorded, never reported). */
  noteException(tid: ThreadId, fault: InCallFault): boolean {
    const call = this.#active.get(tid);
    if (call === undefined) return false;
    call.exceptions++;
    this.inCallExceptions++;
    call.faults.push(fault);
    if (call.faults.length > MAX_FAULTS) call.faults.shift();
    return true;
  }

  /** Dispatcher: a BEA trap handled on `tid` while a call ran there. */
  noteTrap(tid: ThreadId): void {
    const call = this.#active.get(tid);
    if (call !== undefined) call.beaTraps++;
  }

  active(): { tid: ThreadId; token: number }[] {
    return [...this.#active.values()].map((c) => ({ tid: c.tid, token: c.token }));
  }

  /** Keep a chunk's allocations alive until its closure ran (or dispose). */
  quarantine(token: number, allocations: readonly A[]): void {
    const held = this.#quarantine.get(token) ?? [];
    held.push(...allocations);
    this.#quarantine.set(token, held);
  }

  /** The RPC gave up on the chunk: its closure becomes a no-op whenever it runs. */
  expire(token: number): void {
    if (this.#expired.has(token)) return;
    this.#expired.add(token);
    this.expiredClosures++;
  }

  isExpired(token: number): boolean {
    return this.#expired.has(token);
  }

  /**
   * Called first thing inside a chunk's closure: false when the token expired (the closure must return without
   * calling; the late run is counted and the quarantine released).
   */
  beginRun(token: number): boolean {
    if (!this.#expired.has(token)) return true;
    this.#expired.delete(token);
    this.lateRuns++;
    this.#quarantine.delete(token);
    return false;
  }

  /** The chunk finished normally: its allocations may be reused/freed. */
  release(token: number): void {
    this.#quarantine.delete(token);
  }

  get quarantinedBlocks(): number {
    let n = 0;
    for (const held of this.#quarantine.values()) n += held.length;
    return n;
  }

  /** dispose / session end: drop every quarantined allocation and forget expired tokens. */
  drain(): A[] {
    const all: A[] = [];
    for (const held of this.#quarantine.values()) all.push(...held);
    this.#quarantine.clear();
    this.#expired.clear();
    return all;
  }
}
