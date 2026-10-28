// =================================================================================================
// src/agent/stalkerCo.ts — WP3-AGENT StalkerCoordinator (S4 §12.1, D-INT-36). The followed-thread registry shared by
// trace sessions (WP9) and per-call coverage (WP11):
//  - queue settings raised before the FIRST follow (1<<21 / 50 ms: 64,000/64,000 events instead of 3–6 % loss
//    [ext-frida §3.8]); global, only ever raised;
//  - invalidateAll(addresses) after EVERY Interceptor attach/detach/replace/revert and code patch by BEA (a hook added
//    or removed while a thread is followed is otherwise invisible or crashes the target 1/4 [ext-frida §3.8]);
//  - claim(tid, owner) refuses a followed or still-settling thread with StalkerBusy{retry_after_ms};
//  - release(tid) marks the thread settling for stalker_settle_ms; CModules/NativeCallbacks used by Stalker stay
//    pinned in core.keep until after the settle (QJS freed an unreferenced CModule mid-follow: crash 2/2).
//  - StalkerBusy names the instrument that holds the thread, also while it settles after that instrument's unfollow
//    (state "settling"), never the reserved owner "call" (review fix AGENT-12: per-call coverage follows the agent
//    thread without the coordinator, so no call ever holds a thread here).
// =================================================================================================
import type { AgentError, InstrumentId, ThreadId, TimeUs } from "../shared/agentProtocol.js";
import type { AgentCore } from "./state.js";

/** "call" is reserved (see the header): no code path claims a thread for an oracle call. */
export type StalkerOwner = InstrumentId | "call";

/** The core members the coordinator reads (the agent core; a stand-in in the unit tests). */
type CoordinatorCore = Pick<AgentCore, "jsTid" | "limits" | "fault"> & { readonly native: { nowUs(): number } };

export class StalkerCoordinator {
  readonly #core: CoordinatorCore;
  readonly followed = new Map<ThreadId, { owner: StalkerOwner; since: TimeUs }>();
  /** tid → the owner that released it and the time (µs) when it may be followed again */
  readonly settling = new Map<ThreadId, { owner: StalkerOwner; freeAt: TimeUs }>();
  #queueCapacity = 0;
  #queueDrainMs = 0;

  constructor(core: CoordinatorCore) {
    this.#core = core;
  }

  /** Raise Stalker's global queue settings before a follow (never lowered while anything is followed). */
  ensureQueue(capacity?: number, drainMs?: number): { capacity: number; drain_ms: number } {
    const l = this.#core.limits;
    const cap = Math.max(this.#queueCapacity, Math.min(capacity ?? l.stalker_queue_capacity, l.stalker_queue_capacity));
    const drain = Math.min(drainMs ?? l.stalker_drain_ms, l.stalker_drain_ms);
    if (cap !== this.#queueCapacity) {
      Stalker.queueCapacity = cap;
      this.#queueCapacity = cap;
    }
    if (this.#queueDrainMs === 0 || (this.followed.size === 0 && drain !== this.#queueDrainMs)) {
      Stalker.queueDrainInterval = drain;
      this.#queueDrainMs = drain;
    }
    return { capacity: this.#queueCapacity, drain_ms: this.#queueDrainMs };
  }

  /** Reserve `tid` for `owner`; StalkerBusy while it is followed or settling. Never the agent JS thread. */
  claim(tid: ThreadId, owner: StalkerOwner): AgentError | null {
    const now = this.#core.native.nowUs();
    const busy = this.followed.get(tid);
    if (busy !== undefined)
      return {
        _tag: "StalkerBusy",
        message: "the thread is already followed",
        thread_id: tid,
        owner: busy.owner,
        retry_after_ms: 0,
        state: "followed",
      };
    const settle = this.settling.get(tid);
    if (settle !== undefined && settle.freeAt > now)
      return {
        _tag: "StalkerBusy",
        message: "the thread is settling after an unfollow",
        thread_id: tid,
        owner: settle.owner,
        retry_after_ms: Math.ceil((settle.freeAt - now) / 1000),
        state: "settling",
      };
    if (owner !== "call" && tid === this.#core.jsTid)
      return {
        _tag: "BadParams",
        message: "the agent thread cannot be traced",
        issues: [{ path: "threads", problem: "agent thread" }],
      };
    this.settling.delete(tid);
    this.followed.set(tid, { owner, since: now });
    return null;
  }

  /** The owner unfollowed `tid` (after Stalker.unfollow + flush): settle before the next follow. */
  release(tid: ThreadId): void {
    const held = this.followed.get(tid);
    if (held === undefined) return;
    this.followed.delete(tid);
    this.settling.set(tid, {
      owner: held.owner,
      freeAt: this.#core.native.nowUs() + this.#core.limits.stalker_settle_ms * 1000,
    });
  }

  /** A followed thread exited: forget it without settling. */
  forget(tid: ThreadId): void {
    this.followed.delete(tid);
    this.settling.delete(tid);
  }

  /** Stalker.invalidate(tid, addr) for every followed thread; returns the threads touched (HookInstallResult). */
  invalidateAll(addresses: readonly NativePointer[]): ThreadId[] {
    const touched: ThreadId[] = [];
    if (addresses.length === 0) return touched;
    for (const tid of this.followed.keys()) {
      let any = false;
      for (const a of addresses) {
        try {
          Stalker.invalidate(tid, a);
          any = true;
        } catch (e) {
          this.#core.fault("stalker-invalidate", e);
        }
      }
      if (any) touched.push(tid);
    }
    return touched;
  }

  threads(): ThreadId[] {
    return [...this.followed.keys()];
  }
}
