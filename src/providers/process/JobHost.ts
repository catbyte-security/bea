import type { Readable, Writable } from "node:stream";

import type { BeaError } from "../../domain/errors/beaError.js";
import { invalidState } from "../../domain/errors/constructors.js";
import type { JobHostEvent } from "../../domain/jobhostProtocol.js";
import type { Logger } from "../../domain/logger.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { JobHostPort, JobHostState, JobPolicy, JobSettlement, KillReason, RootExit } from "../../ports/jobhost.js";
import type { HelperSession, JobHostEventOf } from "./JobHostSession.js";

/**
 * The owned-target handle (S3 §5.7): one adopt/spawn helper whose job holds the target tree. Created by the factory
 * after the decisive event (`adopted`/`started`), but it subscribes to the session BEFORE that event so no status line
 * is missed. `settled` resolves (never rejects) once the helper has exited and its status channel and, in spawn mode,
 * the target's stdout/stderr have closed (each capped at 1 s). `kill` is memoized and escalates to TerminateProcess on
 * the helper: KILL_ON_JOB_CLOSE is kernel-enforced, so the tree still dies, but nothing observes it (VERIFIED G2).
 * Callers choose `escalateAfterMs`; the S3 §5.7 defaults are 900 ms for server shutdown and 2000 ms for close_session.
 */

/** After TerminateProcess(helper), how long kill() still waits for the helper's exit before synthesizing. */
const POST_ESCALATION_WAIT_MS = 500;

type Decisive = JobHostEventOf<"adopted"> | JobHostEventOf<"started">;

const TERMINAL: ReadonlySet<JobHostState> = new Set(["settled", "helper-lost", "failed"]);

/** `promise`, or "timeout" after `ms`; the timer is cleared either way so it never pins the event loop. */
export const raceTimeout = async <T>(promise: Promise<T>, ms: number): Promise<T | "timeout"> => {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<"timeout">((resolve) => {
        timer = setTimeout(() => resolve("timeout"), Math.max(0, ms));
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
};

export interface JobHostHandleDeps {
  readonly now: () => number;
  readonly logger: Logger;
}

export class JobHostHandle implements JobHostPort {
  readonly settled: Promise<JobSettlement>;
  readonly stdin: Writable | null;
  readonly stdout: Readable | null;
  readonly stderr: Readable | null;

  readonly #session: HelperSession;
  readonly #deps: JobHostHandleDeps;
  readonly #startedAt: number;
  readonly #listeners = new Set<(event: JobHostEvent) => void>();
  #decisive: Decisive | null = null;
  #state: JobHostState = "starting";
  #rootExit: RootExit | null = null;
  #lastActive: number | null = null;
  #killed: JobHostEventOf<"killed"> | null = null;
  #settledEvent: JobHostEventOf<"settled"> | null = null;
  #suspended = false;
  #killRequestedAt: number | null = null;
  #kill: Promise<JobSettlement> | null = null;
  #settlement: JobSettlement | null = null;

  constructor(session: HelperSession, deps: JobHostHandleDeps) {
    this.#session = session;
    this.#deps = deps;
    this.#startedAt = deps.now();
    const spawnMode = session.mode === "spawn";
    this.stdin = spawnMode ? ((session.stream(4) as Writable | null) ?? null) : null;
    this.stdout = spawnMode ? ((session.stream(1) as Readable | null) ?? null) : null;
    this.stderr = spawnMode ? ((session.stream(2) as Readable | null) ?? null) : null;
    session.subscribe((event) => this.#onEvent(event));
    session.onViolation((violation) => {
      this.#state = "failed";
      deps.logger.warn("jobhost protocol violation; helper terminated", { violation: violation.kind });
    });
    this.settled = this.#settle();
  }

  // ------------------------------------------------------------------ JobHostPort facts
  get helperPid(): number {
    return this.#session.helperPid;
  }
  get rootPid(): number {
    return this.#decisive?.pid ?? 0;
  }
  get creationTime100ns(): bigint {
    return BigInt(this.#decisive?.creationTime100ns ?? "0");
  }
  get imagePath(): string | null {
    return this.#decisive?.imagePath ?? null;
  }
  get policy(): JobPolicy {
    return (
      this.#decisive?.policy ?? {
        killOnClose: true,
        dieOnUnhandledException: true,
        breakawayAllowed: false,
        memLimitBytes: null,
      }
    );
  }
  get wasInJob(): boolean | null {
    return this.#decisive?.event === "adopted" ? this.#decisive.wasInJob : null;
  }
  get state(): JobHostState {
    return this.#state;
  }
  get rootExit(): RootExit | null {
    return this.#rootExit;
  }
  get lastActive(): number | null {
    return this.#lastActive;
  }
  /** spawn --suspended: true until `resumed` arrives. */
  get suspended(): boolean {
    return this.#suspended;
  }

  on(listener: (event: JobHostEvent) => void): () => void {
    this.#listeners.add(listener);
    return () => void this.#listeners.delete(listener);
  }

  resume(): Result<void, BeaError> {
    if (this.#session.mode !== "spawn" || !this.#suspended || TERMINAL.has(this.#state) || this.#state === "killing")
      return err(invalidState("jobhost.resume", this.#suspended ? this.#state : "not-suspended", ["suspended"]));
    if (!this.#session.sendControl("resume")) return err(invalidState("jobhost.resume", "helper-gone", ["suspended"]));
    return ok(undefined);
  }

  requestStatus(): void {
    if (!TERMINAL.has(this.#state)) this.#session.sendControl("status");
  }

  kill(reason: KillReason, escalateAfterMs: number): Promise<JobSettlement> {
    this.#kill ??= this.#runKill(reason, escalateAfterMs);
    return this.#kill;
  }

  /** Factory backstop (shutdown budget elapsed): TerminateProcess on the helper now. Idempotent. */
  forceTerminate(): void {
    if (this.#settlement !== null) return;
    this.#killRequestedAt ??= this.#deps.now();
    if (!TERMINAL.has(this.#state)) this.#state = "killing";
    this.#session.terminate();
  }

  // ------------------------------------------------------------------ internals
  /** Called by the factory once the decisive event resolved the start. */
  bindDecisive(event: Decisive): void {
    this.#decisive = event;
    this.#suspended = event.event === "started" && event.suspended;
    if (event.event === "adopted") this.#lastActive = event.active;
    if (this.#state === "starting") this.#state = this.#rootExit === null ? "contained" : "root-exited";
  }

  async #runKill(reason: KillReason, escalateAfterMs: number): Promise<JobSettlement> {
    if (this.#settlement !== null) return this.#settlement;
    this.#killRequestedAt = this.#deps.now();
    if (!TERMINAL.has(this.#state)) this.#state = "killing";
    this.#deps.logger.debug("jobhost kill", { reason, helper_pid: this.helperPid });
    this.#session.sendControl("kill");
    this.#session.endControl();
    if (escalateAfterMs > 0 && (await raceTimeout(this.settled, escalateAfterMs)) !== "timeout") return this.settled;
    if (this.#settlement !== null) return this.#settlement;
    this.#session.terminate();
    const final = await raceTimeout(this.settled, POST_ESCALATION_WAIT_MS);
    if (final !== "timeout") return final;
    return {
      method: "helper-terminated",
      observation: "kernel-enforced-unobserved",
      activeBefore: this.#killed?.activeBefore ?? null,
      active: null,
      peakJobMemoryBytes: null,
      helperExitCode: null,
      outputComplete: false,
      elapsedMs: Math.round(this.#deps.now() - this.#killRequestedAt),
    };
  }

  #onEvent(event: JobHostEvent): void {
    switch (event.event) {
      case "resumed":
        this.#suspended = false;
        break;
      case "root-exit":
        this.#rootExit = {
          code: event.code,
          codeHex: event.codeHex,
          byKill: event.byKill,
          activeAfterRoot: event.activeAfterRoot,
          at: this.#deps.now(),
        };
        this.#suspended = false;
        if (event.activeAfterRoot !== null) this.#lastActive = event.activeAfterRoot;
        if (this.#state === "contained") this.#state = "root-exited";
        break;
      case "killed":
        this.#killed = event;
        this.#lastActive = event.activeBefore;
        break;
      case "status":
        this.#lastActive = event.active;
        break;
      case "settled":
        this.#settledEvent = event;
        this.#lastActive = event.active;
        break;
      default:
        break;
    }
    for (const listener of this.#listeners) {
      try {
        listener(event);
      } catch {
        // listeners must be O(1) and never throw (S3 §16 rule 10)
      }
    }
  }

  async #settle(): Promise<JobSettlement> {
    const exit = await this.#session.finished;
    const outputComplete = await this.#session.outputClosed;
    const settledEvent = this.#settledEvent;
    const terminatedByBea = this.#session.terminated;
    let method: JobSettlement["method"];
    if (terminatedByBea || settledEvent === null) method = "helper-terminated";
    else if (this.#killed !== null)
      method =
        this.#killed.reason === "control" ? "control-kill" : this.#killed.reason === "eof" ? "eof" : "root-exit-policy";
    else method = "natural";
    if (this.#state !== "failed") {
      if (settledEvent === null && !terminatedByBea && this.#killRequestedAt === null) {
        this.#state = "helper-lost";
        this.#deps.logger.warn("jobhost helper exited without settling; the kernel terminated the job", {
          helper_pid: this.helperPid,
          helper_exit_code: exit.code,
        });
      } else this.#state = "settled";
    }
    this.#settlement = {
      method,
      observation:
        settledEvent === null
          ? "kernel-enforced-unobserved"
          : settledEvent.active === 0
            ? "observed-zero-active"
            : "timed-out-with-active",
      activeBefore: this.#killed?.activeBefore ?? null,
      active: settledEvent?.active ?? null,
      peakJobMemoryBytes: settledEvent?.peakJobMemoryBytes ?? null,
      helperExitCode: exit.code,
      outputComplete: this.#session.mode === "spawn" ? outputComplete : true,
      elapsedMs: Math.round(this.#deps.now() - (this.#killRequestedAt ?? this.#startedAt)),
    };
    return this.#settlement;
  }
}
