// =================================================================================================
// src/agent/jobs.ts — WP3-AGENT sliced background jobs (S4 §5.8): wiring of the pure runner (pure/coreJobs.ts) to the
// agent (setImmediate between slices, µs clock, send) and the jobStatus / jobCancel RPCs. Scans (WP10) and dumps
// (WP13) submit jobs through `core.jobs.submit(spec)`; a job created inside an RPC is announced when that RPC replied.
// =================================================================================================
import type { AgentRpcImpl, JobCancelParams, JobStatusParams } from "../shared/agentProtocol.js";
import { env } from "./env.js";
import { badParam, fail, mapThrown, notFound, ok } from "./errors.js";
import { JobRunner } from "./pure/coreJobs.js";
import type { AgentCore } from "./state.js";

export const createJobRunner = (core: AgentCore): JobRunner =>
  new JobRunner({
    nowUs: () => core.native.nowUs(),
    nowMs: () => Date.now(),
    schedule: (fn) => env.defer(fn),
    send: (message) => env.send(message),
    mapError: (e, where) => {
      core.guards.noteThrown(e);
      return mapThrown(e, where);
    },
    limits: () => core.limits,
    afterReply: (fn) => core.scope.afterReply(fn),
  });

let bound: AgentCore | null = null;
const boundCore = (): AgentCore => {
  if (bound === null) throw new Error("jobs.init() has not run");
  return bound;
};

/** Feature contract: index.ts calls init(core) before spreading `rpc`. */
export function init(c: AgentCore): void {
  bound = c;
}

const jobStatus = (p: JobStatusParams) => {
  if (typeof p?.job_id !== "string") return fail(badParam("job_id", "a job id"));
  const jobs = boundCore().jobs;
  const job = jobs.get(p.job_id);
  return job === null ? fail(notFound("job", p.job_id)) : ok(jobs.info(job));
};

const jobCancel = (p: JobCancelParams) => {
  if (typeof p?.job_id !== "string") return fail(badParam("job_id", "a job id"));
  const jobs = boundCore().jobs;
  const job = jobs.cancel(p.job_id);
  return job === null ? fail(notFound("job", p.job_id)) : ok(jobs.info(job));
};

export const rpc = { jobStatus, jobCancel } satisfies Partial<AgentRpcImpl>;
