import type { OperationContext, SessionState, WaitCondition, WaitOutcome } from "../../ports/sessions.js";

/**
 * Wait conditions over host counters (S3 §6.6, re-expressed over agent stream ids). `waitFor` never takes the session
 * queue and reading never consumes ("a stop is read, not taken"). notify() is coalesced with setImmediate so a burst
 * of batches costs one evaluation. Running out of time is a poll result, an abort is `cancelled`, and a session that
 * closes ends every wait with satisfied:false.
 */
export interface ConditionFacts {
  readonly state: SessionState;
  readonly exited: boolean;
  readonly detached: boolean;
  readonly closed: boolean;
  streamReceived(agentStream: string): number;
  streamEnded(agentStream: string): boolean;
  jobDone(jobId: string): boolean;
  outputContains(text: string): boolean;
}

const evaluateCondition = (cond: WaitCondition, facts: ConditionFacts): boolean => {
  switch (cond.kind) {
    case "process-exit":
      return facts.exited;
    case "detach":
      return facts.detached;
    case "stream-events":
      return facts.streamReceived(cond.agentStream) >= cond.atLeast;
    case "stream-end":
      return facts.streamEnded(cond.agentStream);
    case "agent-job":
      return facts.jobDone(cond.jobId);
    case "output-contains":
      return facts.outputContains(cond.text);
    case "any":
      return cond.of.some((inner) => evaluateCondition(inner, facts));
    case "all":
      return cond.of.every((inner) => evaluateCondition(inner, facts));
  }
};

interface Waiter {
  readonly check: () => boolean;
}

export class ConditionHub {
  readonly #facts: ConditionFacts;
  readonly #now: () => number;
  readonly #waiters = new Set<Waiter>();
  #scheduled = false;

  constructor(facts: ConditionFacts, now: () => number) {
    this.#facts = facts;
    this.#now = now;
  }

  get waiting(): number {
    return this.#waiters.size;
  }

  /** Coalesced re-evaluation of every waiter. Safe from Frida callbacks (never throws). */
  notify(): void {
    if (this.#scheduled || this.#waiters.size === 0) return;
    this.#scheduled = true;
    setImmediate(() => {
      this.#scheduled = false;
      for (const waiter of [...this.#waiters]) waiter.check();
    });
  }

  /** Immediate re-evaluation (close and shutdown end every wait at once). */
  flushNow(): void {
    for (const waiter of [...this.#waiters]) waiter.check();
  }

  waitFor(cond: WaitCondition, op: Pick<OperationContext, "signal">, timeoutMs: number): Promise<WaitOutcome> {
    const started = this.#now();
    const outcome = (satisfied: boolean, timedOut: boolean, cancelled: boolean): WaitOutcome => ({
      satisfied,
      timedOut,
      cancelled,
      state: this.#facts.state,
      waitedMs: Math.max(0, Math.round(this.#now() - started)),
    });
    if (evaluateCondition(cond, this.#facts)) return Promise.resolve(outcome(true, false, false));
    if (this.#facts.closed) return Promise.resolve(outcome(false, false, false));
    if (op.signal.aborted) return Promise.resolve(outcome(false, false, true));
    if (timeoutMs <= 0) return Promise.resolve(outcome(false, true, false));
    return new Promise((resolve) => {
      let done = false;
      const finish = (result: WaitOutcome): void => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        op.signal.removeEventListener("abort", onAbort);
        this.#waiters.delete(waiter);
        resolve(result);
      };
      const waiter: Waiter = {
        check: () => {
          if (evaluateCondition(cond, this.#facts)) finish(outcome(true, false, false));
          else if (this.#facts.closed) finish(outcome(false, false, false));
          return done;
        },
      };
      const onAbort = (): void => finish(outcome(false, false, true));
      const timer = setTimeout(() => finish(outcome(false, true, false)), timeoutMs);
      timer.unref?.();
      op.signal.addEventListener("abort", onAbort, { once: true });
      this.#waiters.add(waiter);
    });
  }
}
