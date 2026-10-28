import type { BeaError } from "../../domain/errors/beaError.js";
import type { BlobRef } from "../../domain/evidence/record.js";
import type { Logger } from "../../domain/logger.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { BlobStore, SensitiveLiterals } from "../../ports/evidence.js";
import type { AgentJobOutcome, AgentJobsPort, OperationContext } from "../../ports/sessions.js";
import type { DumpManifest, JobInfo, JobMessage, ScanStatus } from "../../shared/agentProtocol.js";
import { classifyAbort } from "./aborts.js";
import type { FlowTracker } from "./flowTracker.js";

/**
 * CI-B3: agent jobs and their blobs (S4 §5.8, §15.1). `blob` parts are streamed in order into EvidenceRuntime.blobs as
 * they arrive (a 2 GiB dump never sits in host memory); the BlobStore recomputes the sha256 (the agent's is advisory).
 * `await(jobId)` resolves after the job's JobMessage AND every blob of the job settled (stored, redacted or failed).
 */
type BlobOutcome = BlobRef | { readonly redacted: true } | { readonly failed: string };

interface BlobAssembly {
  readonly id: string;
  readonly job: string | null;
  nextPart: number;
  nextOffset: number;
  readonly queue: PushQueue;
  readonly outcome: Promise<BlobOutcome>;
  done: boolean;
}

interface JobRecord {
  message: JobMessage | null;
  readonly blobs: Set<string>;
  readonly waiters: Set<() => void>;
}

export interface AgentJobsDeps {
  readonly blobs: BlobStore;
  readonly literals: () => SensitiveLiterals;
  readonly flow: FlowTracker;
  /** authoritative JobInfo after the job message (best effort; the agent may have dropped the job already) */
  readonly jobStatus: (jobId: string, op: OperationContext) => Promise<Result<JobInfo, BeaError>>;
  readonly notify: () => void;
  readonly logger: Logger;
}

/** A minimal single-consumer async queue of byte chunks. */
class PushQueue implements AsyncIterable<Uint8Array> {
  readonly #items: Uint8Array[] = [];
  #ended = false;
  #failed: Error | null = null;
  #wake: (() => void) | null = null;

  push(chunk: Uint8Array): void {
    this.#items.push(chunk);
    this.#wake?.();
  }

  end(): void {
    this.#ended = true;
    this.#wake?.();
  }

  fail(reason: string): void {
    this.#failed = new Error(reason);
    this.#wake?.();
  }

  async *[Symbol.asyncIterator](): AsyncIterator<Uint8Array> {
    for (;;) {
      if (this.#failed !== null) throw this.#failed;
      const item = this.#items.shift();
      if (item !== undefined) {
        yield item;
        continue;
      }
      if (this.#ended) return;
      await new Promise<void>((resolve) => {
        this.#wake = resolve;
      });
      this.#wake = null;
    }
  }
}

export class AgentJobs implements AgentJobsPort {
  readonly #deps: AgentJobsDeps;
  readonly #jobs = new Map<string, JobRecord>();
  readonly #blobs = new Map<string, BlobAssembly>();
  #closedReason: string | null = null;

  constructor(deps: AgentJobsDeps) {
    this.#deps = deps;
  }

  jobDone(jobId: string): boolean {
    return (this.#jobs.get(jobId)?.message ?? null) !== null;
  }

  onBlob(header: Record<string, unknown>, data: Buffer | null): void {
    const id = header["blob"];
    const part = header["part"];
    const offset = header["offset"];
    const bytes = header["bytes"];
    if (typeof id !== "string" || typeof part !== "number" || typeof offset !== "number" || data === null) return;
    const job = typeof header["job"] === "string" ? header["job"] : null;
    let assembly = this.#blobs.get(id);
    if (assembly === undefined) {
      if (part !== 0) return; // a blob whose first part was lost is reported failed by the job
      assembly = this.#startBlob(id, job);
    }
    if (assembly.done) return;
    this.#deps.flow.add(data.length);
    if (
      part !== assembly.nextPart ||
      offset !== assembly.nextOffset ||
      (typeof bytes === "number" && bytes !== data.length)
    ) {
      assembly.done = true;
      assembly.queue.fail("blob parts arrived out of order");
      return;
    }
    assembly.nextPart += 1;
    assembly.nextOffset += data.length;
    assembly.queue.push(Buffer.from(data));
    if (header["last"] === true) {
      assembly.done = true;
      assembly.queue.end();
    }
  }

  onJob(message: JobMessage): void {
    const record = this.#record(message.job);
    record.message = message;
    for (const blob of referencedBlobs(message.result)) record.blobs.add(blob);
    for (const waiter of [...record.waiters]) waiter();
    this.#deps.notify();
  }

  /** Session ended: pending blobs fail, waiters settle with the reason. */
  closeAll(reason: string): void {
    this.#closedReason = reason;
    for (const assembly of this.#blobs.values())
      if (!assembly.done) {
        assembly.done = true;
        assembly.queue.fail(reason);
      }
    for (const record of this.#jobs.values()) for (const waiter of [...record.waiters]) waiter();
  }

  async await(jobId: string, op: OperationContext, timeoutMs: number): Promise<Result<AgentJobOutcome, BeaError>> {
    const record = this.#record(jobId);
    if (record.message === null) {
      const settled = await this.#waitForMessage(record, op, timeoutMs);
      if (!settled.ok) return settled;
    }
    const message = record.message;
    if (message === null)
      return err({
        _tag: "CapabilityUnavailable",
        operation: op.name,
        capability: "agent",
        reason: "agent-gone",
        retryable: false,
        diagnostics: { detail: this.#closedReason ?? "session ended" },
      });
    const blobs = new Map<string, BlobOutcome>();
    for (const blobId of record.blobs) {
      const assembly = this.#blobs.get(blobId);
      if (assembly === undefined) {
        blobs.set(blobId, { failed: "not received" });
        continue;
      }
      if (!assembly.done) {
        // the job message precedes no further parts (the agent sends parts first); close what is open
        assembly.done = true;
        assembly.queue.fail("job finished before the blob's last part");
      }
      blobs.set(blobId, await assembly.outcome);
    }
    const status = await this.#deps.jobStatus(jobId, op);
    const info: JobInfo = status.ok
      ? status.value
      : {
          job_id: message.job,
          kind: message.kind,
          state: message.state,
          progress: message.progress,
          started_t: 0,
          ended_t: null,
          error: message.error ?? null,
        };
    return ok({
      info,
      result: (message.result ?? null) as ScanStatus | DumpManifest | null,
      error: message.error ?? null,
      blobs,
    });
  }

  #record(jobId: string): JobRecord {
    let record = this.#jobs.get(jobId);
    if (record === undefined) {
      record = { message: null, blobs: new Set(), waiters: new Set() };
      this.#jobs.set(jobId, record);
    }
    return record;
  }

  #startBlob(id: string, job: string | null): BlobAssembly {
    const queue = new PushQueue();
    const outcome = this.#deps.blobs
      .put(queue, { role: "agent-blob", media_type: "application/octet-stream", literals: this.#deps.literals() })
      .then(
        (result): BlobOutcome => (result.ok ? result.value : { failed: result.error._tag }),
        (cause: unknown): BlobOutcome => ({
          failed: cause instanceof Error ? cause.message.slice(0, 200) : "store failed",
        }),
      );
    const assembly: BlobAssembly = { id, job, nextPart: 0, nextOffset: 0, queue, outcome, done: false };
    this.#blobs.set(id, assembly);
    if (job !== null) this.#record(job).blobs.add(id);
    return assembly;
  }

  #waitForMessage(record: JobRecord, op: OperationContext, timeoutMs: number): Promise<Result<void, BeaError>> {
    if (this.#closedReason !== null) return Promise.resolve(ok(undefined));
    return new Promise((resolve) => {
      const finish = (result: Result<void, BeaError>): void => {
        clearTimeout(timer);
        op.signal.removeEventListener("abort", onAbort);
        record.waiters.delete(wake);
        resolve(result);
      };
      const wake = (): void => finish(ok(undefined));
      const onAbort = (): void => finish(err(classifyAbort(op.signal, op.name, { deadline: op.deadline })));
      const timer = setTimeout(
        () => finish(err({ _tag: "ProviderTimeout", operation: op.name, timeout_ms: timeoutMs, phase: "agent-job" })),
        Math.max(0, Math.min(timeoutMs, op.deadline.remaining())),
      );
      timer.unref?.();
      if (op.signal.aborted) {
        onAbort();
        return;
      }
      op.signal.addEventListener("abort", onAbort, { once: true });
      record.waiters.add(wake);
    });
  }
}

const referencedBlobs = (result: ScanStatus | DumpManifest | undefined): string[] => {
  if (result === undefined || !("format" in result) || result.format !== "bea-dump/1") return [];
  const ids = new Set<string>();
  for (const region of result.regions) ids.add(region.blob);
  for (const module of result.modules) if (module.blob !== null) ids.add(module.blob);
  return [...ids];
};
