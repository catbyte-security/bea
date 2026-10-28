// =================================================================================================
// src/agent/pure/coreJobs.ts — WP3-AGENT sliced background jobs (S4 §5.8, A13). Scans and dumps run as jobs: at most
// limits.max_jobs at a time, one ≤ job_slice_ms slice per turn, round-robin, yielding to the event loop between
// slices (one JS thread serves every script and RPC in the target [ext-frida §1.7]). Cancellation is checked before
// each slice; the completion message is sent exactly once and never before the RPC that created the job replied
// (announcement rule, D-INT-7). Pure: jobs.ts injects the clock, the scheduler and send().
// =================================================================================================
import type {
  AgentError,
  DumpManifest,
  JobId,
  JobInfo,
  JobKind,
  JobMessage,
  Progress,
  ScanStatus,
} from "../../shared/agentProtocol.js";

export type JobResult = ScanStatus | DumpManifest;

/** What a feature hands to the runner. `step` does ≤ budgetMs of work and updates `job.progress`. */
export interface JobSpec {
  readonly kind: JobKind;
  readonly total: number | null;
  readonly unit: Progress["unit"];
  readonly step: (job: Job, budgetMs: number) => "more" | "done";
  /** runs once when the job leaves the running state (done, failed or cancelled) */
  readonly onEnd?: (job: Job) => void;
}

export interface Job {
  readonly id: JobId;
  readonly kind: JobKind;
  state: JobInfo["state"];
  readonly progress: Progress;
  result: JobResult | undefined;
  error: AgentError | null;
  cancelRequested: boolean;
  readonly startedT: number;
  endedT: number | null;
  announced: boolean;
  messageSent: boolean;
  readonly spec: JobSpec;
}

export interface JobRunnerDeps {
  readonly nowUs: () => number;
  readonly nowMs: () => number;
  /** run `fn` on a later turn (setImmediate in the agent) */
  readonly schedule: (fn: () => void) => void;
  readonly send: (message: JobMessage) => void;
  readonly mapError: (e: unknown, where: string) => AgentError;
  readonly limits: () => { readonly max_jobs: number; readonly job_slice_ms: number };
  /**
   * Announcement rule: when an RPC is in progress, register `fn` to run once its reply was produced and return true;
   * return false outside RPCs (the job is announced at once).
   */
  readonly afterReply?: (fn: () => void) => boolean;
}

const FINISHED_KEEP = 64;

export class JobRunner {
  readonly #deps: JobRunnerDeps;
  readonly #jobs = new Map<JobId, Job>();
  #next = 1;
  #cursor = 0;
  #scheduled = false;

  constructor(deps: JobRunnerDeps) {
    this.#deps = deps;
  }

  /**
   * Queue a job; ResourceLimit{jobs} when max_jobs are already queued or running. `announced` overrides the RPC-scope
   * rule (false: the caller announces with announce(id) once its RPC replied; true: the message may go out at once).
   */
  submit(spec: JobSpec, announced?: boolean): Job | AgentError {
    const live = [...this.#jobs.values()].filter((j) => j.state === "queued" || j.state === "running").length;
    const max = this.#deps.limits().max_jobs;
    if (live >= max)
      return { _tag: "ResourceLimit", message: "too many agent jobs", resource: "jobs", limit: max, observed: live };
    const job: Job = {
      id: `j${this.#next++}`,
      kind: spec.kind,
      state: "queued",
      progress: { done: 0, total: spec.total, unit: spec.unit },
      result: undefined,
      error: null,
      cancelRequested: false,
      startedT: this.#deps.nowUs(),
      endedT: null,
      announced: false,
      messageSent: false,
      spec,
    };
    this.#jobs.set(job.id, job);
    if (announced !== undefined) job.announced = announced;
    else if (this.#deps.afterReply?.(() => this.announce(job.id)) !== true) job.announced = true;
    this.#prune();
    this.#kick();
    return job;
  }

  get(id: JobId): Job | null {
    return this.#jobs.get(id) ?? null;
  }

  info(job: Job): JobInfo {
    return {
      job_id: job.id,
      kind: job.kind,
      state: job.state,
      progress: { ...job.progress },
      started_t: job.startedT,
      ended_t: job.endedT,
      error: job.error,
    };
  }

  list(): JobInfo[] {
    return [...this.#jobs.values()].map((j) => this.info(j));
  }

  /** Request cancellation (honoured before the next slice); queued jobs end at once. */
  cancel(id: JobId): Job | null {
    const job = this.#jobs.get(id);
    if (job === undefined) return null;
    if (job.state === "queued" || job.state === "running") {
      job.cancelRequested = true;
      if (job.state === "queued") this.#finish(job, "cancelled");
      else this.#kick();
    }
    return job;
  }

  /** shutdown: cancel every live job synchronously; returns how many were cancelled. */
  cancelAll(): number {
    let n = 0;
    for (const job of this.#jobs.values())
      if (job.state === "queued" || job.state === "running") {
        job.cancelRequested = true;
        this.#finish(job, "cancelled");
        n++;
      }
    return n;
  }

  /** The creating RPC replied: a finished job's message may go out now. */
  announce(id: JobId): void {
    const job = this.#jobs.get(id);
    if (job === undefined || job.announced) return;
    job.announced = true;
    this.#sendIfReady(job);
  }

  #kick(): void {
    if (this.#scheduled) return;
    this.#scheduled = true;
    this.#deps.schedule(() => {
      this.#scheduled = false;
      this.#turn();
    });
  }

  #turn(): void {
    const live = [...this.#jobs.values()].filter((j) => j.state === "queued" || j.state === "running");
    if (live.length === 0) return;
    const job = live[this.#cursor % live.length]!;
    this.#cursor = (this.#cursor + 1) % Math.max(1, live.length);
    this.#slice(job);
    if ([...this.#jobs.values()].some((j) => j.state === "queued" || j.state === "running")) this.#kick();
  }

  #slice(job: Job): void {
    if (job.cancelRequested) return this.#finish(job, "cancelled");
    job.state = "running";
    let outcome: "more" | "done";
    try {
      outcome = job.spec.step(job, this.#deps.limits().job_slice_ms);
    } catch (e) {
      job.error = this.#deps.mapError(e, `job:${job.kind}`);
      return this.#finish(job, "failed");
    }
    if (job.error !== null) return this.#finish(job, "failed");
    if (outcome === "done") this.#finish(job, "done");
  }

  #finish(job: Job, state: "done" | "failed" | "cancelled"): void {
    if (job.state === "done" || job.state === "failed" || job.state === "cancelled") return;
    job.state = state;
    job.endedT = this.#deps.nowUs();
    try {
      job.spec.onEnd?.(job);
    } catch (e) {
      job.error ??= this.#deps.mapError(e, `job:${job.kind}:end`);
    }
    this.#sendIfReady(job);
  }

  #sendIfReady(job: Job): void {
    if (job.messageSent || !job.announced) return;
    if (job.state !== "done" && job.state !== "failed" && job.state !== "cancelled") return;
    job.messageSent = true;
    const message: JobMessage = {
      bea: "job",
      job: job.id,
      kind: job.kind,
      state: job.state,
      progress: { ...job.progress },
      ...(job.result !== undefined ? { result: job.result } : {}),
      ...(job.error !== null ? { error: job.error } : {}),
    };
    this.#deps.send(message);
  }

  #prune(): void {
    const finished = [...this.#jobs.values()].filter((j) => j.messageSent);
    for (const job of finished.slice(0, Math.max(0, finished.length - FINISHED_KEEP))) this.#jobs.delete(job.id);
  }
}
