import type { Clock } from "../domain/clock.js";
import type { Logger } from "../domain/logger.js";

/**
 * Kill-first shutdown (D10; rea-testing §0.5; S3 §7.6 VERIFIED 67–72 ms for 3 owned + 1 attached).
 * Phases run in order; closers inside a phase run concurrently. Budgets sum to 1800 ms (SDK 2 s window; the
 * unref'd hard-exit safety timer fires at 1900 ms). DESIGN conflict C-07: S1's six sequential phases are merged
 * with S3's kill-first concurrent teardown: owned kills, attached reverts and emulator bridges all start at t0.
 */
export const SHUTDOWN_PHASES = ["stop-admission", "teardown-targets", "finalize-evidence", "release-frida"] as const;
export type ShutdownPhase = (typeof SHUTDOWN_PHASES)[number];

export const PHASE_BUDGET_MS: { readonly [P in ShutdownPhase]: number } = {
  /** refuse new work; abort every in-flight signal (no drain-first: S3 C4); the drain is best-effort (CT-I3) */
  "stop-admission": 50,
  /** SessionManager.closeAll (kill owned at t0 ∥ revert/unload/detach attached ∥ bridges) + bounded admission drain */
  "teardown-targets": 1300,
  /** EvidenceRuntime.finalize: end streams/effects, fsync ledger, run.json closed */
  "finalize-evidence": 200,
  /** FridaHost.close: disconnect every handler, await DeviceManager.close() */
  "release-frida": 250,
};

/** The sum of the phase budgets (1800 ms): the window inside the SDK client's 2 s escalation. */
export const TOTAL_SHUTDOWN_BUDGET_MS = Object.values(PHASE_BUDGET_MS).reduce((sum, ms) => sum + ms, 0);

export interface Closer {
  readonly name: string;
  readonly phase: ShutdownPhase;
  /**
   * CT-I3: a best-effort closer never fails its phase. When the phase budget elapses first it is reported in
   * `abandoned` (not `failed`), removed, and never retried. Used by the admission drain: an in-flight agent RPC takes
   * ~106 ms to reject after cancellation, longer than the 50 ms phase, and that alone must not turn exit 0 into 1.
   */
  readonly bestEffort?: boolean;
  /** Must honor `signal` (phase budget): e.g. jobhost closers fall back to TerminateProcess on the helper. */
  readonly close: (signal: AbortSignal) => Promise<void>;
}

export interface PhaseReport {
  readonly phase: ShutdownPhase;
  readonly elapsed_ms: number;
  readonly timed_out: boolean;
  readonly failed: readonly { readonly closer: string; readonly message: string }[];
  /** best-effort closers still running when the budget elapsed (informational; never affects `ok`) */
  readonly abandoned: readonly string[];
}

export interface CloseReport {
  readonly ok: boolean;
  readonly reason: string;
  readonly elapsed_ms: number;
  readonly phases: readonly PhaseReport[];
}

const messageOf = (cause: unknown): string =>
  cause instanceof Error ? cause.message.slice(0, 512) : String(cause).slice(0, 512);

/**
 * Owns shutdown ordering. Successful closers unregister; failed or timed-out
 * closers stay owned so a later closeAll retries exactly them (REA closeAll memo).
 */
export class Lifecycle {
  readonly #closers = new Set<Closer>();
  readonly #shutdown = new AbortController();
  #attempt: Promise<CloseReport> | undefined;

  constructor(
    private readonly clock: Clock,
    private readonly logger: Logger,
  ) {}

  /** Aborted when closeAll starts. Composed into every handler's ctx.signal. */
  get shutdownSignal(): AbortSignal {
    return this.#shutdown.signal;
  }

  get closing(): boolean {
    return this.#shutdown.signal.aborted;
  }

  register(closer: Closer): () => void {
    this.#closers.add(closer);
    return () => {
      this.#closers.delete(closer);
    };
  }

  /** Memoized while running; after a failed attempt the next call retries remaining closers. */
  closeAll(reason: string): Promise<CloseReport> {
    this.#attempt ??= this.#run(reason).then((report) => {
      if (!report.ok) this.#attempt = undefined;
      return report;
    });
    return this.#attempt;
  }

  async #run(reason: string): Promise<CloseReport> {
    if (!this.#shutdown.signal.aborted) this.#shutdown.abort({ kind: "shutdown", reason });
    const started = this.clock.monoMs();
    const phases: PhaseReport[] = [];
    for (const phase of SHUTDOWN_PHASES) {
      const closers = [...this.#closers].filter((closer) => closer.phase === phase);
      if (closers.length === 0) continue;
      const phaseStarted = this.clock.monoMs();
      const budget = new AbortController();
      // Review fix LIFE-3: the last phase (release-frida: DeviceManager.close, which also removes Frida's extracted
      // agent directory) gets whatever the earlier phases left of the total budget, never less than its own
      const budgetMs =
        phase === SHUTDOWN_PHASES.at(-1)
          ? Math.max(PHASE_BUDGET_MS[phase], TOTAL_SHUTDOWN_BUDGET_MS - Math.round(phaseStarted - started))
          : PHASE_BUDGET_MS[phase];
      const timer = setTimeout(() => budget.abort({ kind: "deadline", budget_ms: budgetMs }), budgetMs);
      const failed: { closer: string; message: string }[] = [];
      const abandoned: string[] = [];
      const pending = new Set(closers);
      const all = Promise.allSettled(
        closers.map(async (closer) => {
          try {
            await closer.close(budget.signal);
            this.#closers.delete(closer);
          } catch (cause: unknown) {
            if (closer.bestEffort === true) this.#closers.delete(closer);
            else failed.push({ closer: closer.name, message: messageOf(cause) });
          } finally {
            pending.delete(closer);
          }
        }),
      );
      const timedOut = await Promise.race([
        all.then(() => false),
        new Promise<boolean>((resolve) => budget.signal.addEventListener("abort", () => resolve(true), { once: true })),
      ]);
      clearTimeout(timer);
      if (timedOut)
        for (const closer of pending) {
          if (closer.bestEffort === true) {
            abandoned.push(closer.name);
            this.#closers.delete(closer);
          } else failed.push({ closer: closer.name, message: "phase budget elapsed" });
        }
      phases.push({
        phase,
        elapsed_ms: Math.round(this.clock.monoMs() - phaseStarted),
        timed_out: timedOut,
        failed,
        abandoned,
      });
      if (failed.length > 0)
        this.logger.warn("shutdown phase incomplete", { phase, failed: failed.map((f) => f.closer) });
    }
    const report: CloseReport = {
      ok: phases.every((phase) => phase.failed.length === 0),
      reason,
      elapsed_ms: Math.round(this.clock.monoMs() - started),
      phases,
    };
    this.logger.info("shutdown complete", { ok: report.ok, ms: report.elapsed_ms, reason });
    return report;
  }
}
