import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ScanEngine, type ScanJobWork } from "../../../../../src/agent/pure/scanEngine.js";
import type { BeaServices } from "../../../../../src/application/services/index.js";
import { Deadline } from "../../../../../src/domain/deadline.js";
import { mapAgentError } from "../../../../../src/domain/errors/agentErrorMap.js";
import type { BeaError } from "../../../../../src/domain/errors/beaError.js";
import { cancelled, providerTimeout } from "../../../../../src/domain/errors/constructors.js";
import type { BeaEvidence } from "../../../../../src/domain/evidence/record.js";
import type { EvId, MmId, PiId } from "../../../../../src/domain/ids.js";
import type { JsonValue } from "../../../../../src/domain/json.js";
import { literalsOf } from "../../../../../src/domain/redaction/literals.js";
import { err, ok, type Result } from "../../../../../src/domain/result.js";
import type { AddressService, AddressSpace } from "../../../../../src/ports/address.js";
import type { EvidenceDraft, EvidenceRuntime } from "../../../../../src/ports/evidence.js";
import type {
  AgentJobOutcome,
  DynamicSessionPort,
  LiveSession,
  OperationContext,
  SessionEndedEvent,
  SessionState,
} from "../../../../../src/ports/sessions.js";
import type { AgentResult } from "../../../../../src/shared/agentProtocol.js";
import { createFakePlatform, FakeMemory, LIMITS, runToEnd } from "../../../../unit/scan/support/fakePlatform.js";

/**
 * WP10-SCAN boundary doubles: one live session whose agent is the REAL ScanEngine over a FakeMemory (jobs run when
 * the test says so, or at once with autoRun), a passive jobs.await, a recording fake evidence runtime and a fake
 * address service. Only the slots the scan tools use are implemented.
 */
export const SESSION_ID = "6f1c2a4e-8b3d-4e5f-9a7b-1c2d3e4f5a6b";
const INSTANCE_ID = `pi_${"1".repeat(64)}` as PiId;
export const IMAGE_BASE = 0x1_4000_0000;
export const IMAGE_NAME = "game_sim.exe";
const PREFERRED_BASE = 0x1_4000_0000 - 0x1000_0000;

interface Job {
  readonly id: string;
  readonly work: ScanJobWork;
  outcome: AgentJobOutcome | null;
  readonly waiters: ((o: AgentJobOutcome) => void)[];
}

class FakeScanTarget {
  readonly mem = new FakeMemory();
  readonly platform = createFakePlatform(this.mem);
  readonly engine = new ScanEngine(this.platform, () => this.limits);
  limits = { ...LIMITS };
  /** run jobs to completion right after the RPC that created them */
  autoRun = true;
  state: SessionState = "running";
  readonly calls: { method: string; params: unknown }[] = [];
  readonly #jobs = new Map<string, Job>();
  #seq = 0;

  finish(jobId: string): void {
    const job = this.#jobs.get(jobId);
    if (job === undefined || job.outcome !== null) return;
    runToEnd(job.work);
    const out = job.work.outcome();
    const outcome: AgentJobOutcome = {
      info: {
        job_id: job.id,
        kind: job.work.kind,
        state: out.state,
        progress: job.work.progress(),
        started_t: 0,
        ended_t: 1,
        error: out.error,
      },
      result: out.result,
      error: out.error,
      blobs: new Map(),
    };
    job.outcome = outcome;
    for (const w of job.waiters.splice(0)) w(outcome);
  }

  pendingJobs(): string[] {
    return [...this.#jobs.values()].filter((j) => j.outcome === null).map((j) => j.id);
  }

  readonly agent = {
    health: { state: "ok" } as const,
    call: async (
      method: string,
      params: unknown,
      opts: { readonly op: OperationContext },
    ): Promise<Result<unknown, BeaError>> => {
      this.calls.push({ method, params });
      const map = <T>(r: AgentResult<T>): Result<T, BeaError> =>
        r.ok ? ok(r.value) : err(mapAgentError(r.error, { operation: opts.op.name }));
      const p = params as never;
      switch (method) {
        case "scanStart":
        case "scanNext": {
          const r = method === "scanStart" ? this.engine.start(p) : this.engine.next(p);
          if (!r.ok) return map(r);
          this.#seq += 1;
          const id = `j${String(this.#seq)}`;
          this.engine.attachJob(r.value.scanId, id);
          this.#jobs.set(id, { id, work: r.value, outcome: null, waiters: [] });
          if (this.autoRun) queueMicrotask(() => this.finish(id));
          return ok({ scan_id: r.value.scanId, job_id: id });
        }
        case "scanStatus":
          return map(this.engine.status((params as { scan_id: string }).scan_id));
        case "scanResults":
          return map(this.engine.results(p));
        case "scanClose":
          return map(this.engine.close((params as { scan_id: string }).scan_id));
        case "jobCancel": {
          // the agent runner's cancel: the work stops at its next slice and the job ends with the partial result
          const id = (params as { job_id: string }).job_id;
          const job = this.#jobs.get(id);
          if (job === undefined)
            return err({ _tag: "ReferenceNotFound", operation: opts.op.name, reference: { kind: "job", id } });
          if (job.outcome === null) {
            job.work.cancel();
            this.finish(id);
          }
          return ok(job.outcome?.info ?? null);
        }
        default:
          return err({
            _tag: "CapabilityUnavailable",
            operation: method,
            capability: "agent",
            reason: "not-implemented",
            retryable: false,
          });
      }
    },
  };

  readonly jobs = {
    await: (jobId: string, op: OperationContext, timeoutMs: number): Promise<Result<AgentJobOutcome, BeaError>> => {
      const job = this.#jobs.get(jobId);
      if (job === undefined)
        return Promise.resolve(
          err({ _tag: "ReferenceNotFound", operation: op.name, reference: { kind: "job", id: jobId } }),
        );
      if (job.outcome !== null) return Promise.resolve(ok(job.outcome));
      return new Promise((resolve) => {
        const timer = setTimeout(() => resolve(err(providerTimeout(op.name, timeoutMs, "job"))), timeoutMs);
        timer.unref();
        op.signal.addEventListener("abort", () => resolve(err(cancelled(op.name, "signal"))), { once: true });
        job.waiters.push((o) => {
          clearTimeout(timer);
          resolve(ok(o));
        });
      });
    },
  };

  readonly session: LiveSession;

  constructor() {
    const self = this;
    this.session = {
      id: SESSION_ID,
      kind: "live",
      ownership: "owned",
      get state(): SessionState {
        return self.state;
      },
      instanceId: INSTANCE_ID,
      identity: {} as LiveSession["identity"],
      agent: this.agent as unknown as LiveSession["agent"],
      streams: {} as LiveSession["streams"],
      output: null,
      lastCrash: null,
      paused: false,
      jobs: this.jobs as unknown as LiveSession["jobs"],
      scripts: {} as LiveSession["scripts"],
      liveness: () =>
        self.state === "exited"
          ? { state: "exited", basis: "jobhost-root-exit", exit: null, tree: null }
          : { state: "alive", basis: "jobhost" },
      waitFor: async () => ({ satisfied: true, timedOut: false, cancelled: false, state: self.state, waitedMs: 0 }),
      crash: async () => ok(null),
    } as LiveSession;
  }
}

export interface FakeScanWorld {
  readonly target: FakeScanTarget;
  readonly services: Partial<BeaServices>;
  readonly records: EvidenceDraft<JsonValue>[];
  readonly endSession: (reason: SessionEndedEvent["reason"]) => void;
  readonly runDir: string;
  readonly cleanup: () => void;
  /** server-level sensitive literals (BEA_SENSITIVE_VALUES_FILE) the evidence runtime reports */
  readonly sensitive: string[];
}

export const createFakeScanWorld = (): FakeScanWorld => {
  const t = new FakeScanTarget();
  const listeners: ((e: SessionEndedEvent) => void)[] = [];
  let closed = false;
  let opSeq = 0;
  const sessions = {
    admit: async <T>(
      name: string,
      req: { signal?: AbortSignal; timeoutMs?: number },
      fn: (op: OperationContext) => Promise<Result<T, BeaError>>,
    ) => {
      opSeq += 1;
      return fn({
        opId: opSeq,
        name,
        signal: req.signal ?? new AbortController().signal,
        deadline: Deadline.after(req.timeoutMs ?? 30_000),
      });
    },
    kindOf: (id: string) => (id !== SESSION_ID ? null : closed ? "closed" : "live"),
    withSession: async <T>(
      _id: string,
      _op: OperationContext,
      _mode: string,
      fn: (s: LiveSession) => Promise<Result<T, BeaError>>,
    ) => fn(t.session),
    onSessionEnded: (listener: (e: SessionEndedEvent) => void) => {
      listeners.push(listener);
      return () => undefined;
    },
  } as unknown as DynamicSessionPort;

  const runDir = mkdtempSync(join(tmpdir(), "bea-scan-run-"));
  const sensitive: string[] = [];
  const records: EvidenceDraft<JsonValue>[] = [];
  let ev = 0;
  const evidence = {
    run: { id: "run_test", dir: runDir, kind: "mcp-stdio" },
    literals: () => ok(literalsOf(sensitive)),
    instances: {
      capture: () => ({
        anchor: {
          run_id: "run_test",
          seq: ev + 1,
          mono_ns: "1",
          wall: "2026-01-01T00:00:00.000Z",
          effect_epoch: 0,
          module_map_epoch: 1,
        },
        module_map_id: `mm_${"2".repeat(64)}` as MmId,
        perturbation: { level: "agent-only", active_effect_ids: [], tainted_by: [] },
        tainted_count: 0,
      }),
    },
    recorder: {
      record: async (draft: EvidenceDraft<JsonValue>) => {
        records.push(draft);
        ev += 1;
        const record = {
          schema: "bea.evidence/1",
          evidence_id: `ev_${ev.toString(16).padStart(64, "0")}` as EvId,
          predicate_type: draft.predicate_type,
          operation: draft.operation,
          parameters: draft.input,
          subject: { kind: "process-instance", instance_id: INSTANCE_ID, module_map_id: `mm_${"2".repeat(64)}` },
          observed_at: draft.capture?.anchor ?? null,
          provider: draft.provider,
          agent: null,
          confidence: "observed",
          authority: "live-process",
          perturbation: { level: "agent-only", active_effect_ids: [], tainted_by: [] },
          result: draft.result,
          raw_result: null,
          blobs: [],
          coverage: draft.coverage,
          limitations: [...(draft.limitations ?? [])],
          locations: [],
          evidence_links: [],
          external_refs: [],
          effects: [],
          redactions: [],
          untrusted: true,
        } as unknown as BeaEvidence<JsonValue>;
        return ok({ record, outcome: "added" as const });
      },
    },
  } as unknown as EvidenceRuntime;

  const inImage = (va: bigint): boolean => va >= BigInt(IMAGE_BASE) && va < BigInt(IMAGE_BASE + 0x10_0000);
  const address = {
    resolve: async (_space: AddressSpace, expr: string) =>
      expr === `${IMAGE_NAME}!g_world`
        ? ok({ ref: {} as never, moduleMapId: null, va: BigInt(IMAGE_BASE + 0x3000) })
        : err({ _tag: "AddressUnmapped", operation: "resolve", address: expr, module_map_id: null }),
    prepare: async () => undefined,
    describe: (_space: AddressSpace, va: bigint) => ({
      va: `0x${va.toString(16)}` as const,
      at: inImage(va) ? `${IMAGE_NAME}+0x${(va - BigInt(IMAGE_BASE)).toString(16)}` : null,
      static: inImage(va) ? `${IMAGE_NAME}:0x${(va - BigInt(IMAGE_BASE) + BigInt(PREFERRED_BASE)).toString(16)}` : null,
    }),
  } as unknown as AddressService;

  return {
    target: t,
    services: { sessions, evidence, address },
    records,
    runDir,
    sensitive,
    endSession: (reason) => {
      closed = reason === "closed" || reason === "shutdown";
      for (const l of listeners) l({ sessionId: SESSION_ID, kind: "live", reason });
    },
    cleanup: () => rmSync(runDir, { recursive: true, force: true }),
  };
};
