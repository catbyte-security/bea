import type {
  AgentError,
  AgentResult,
  AgentRpcImpl,
  DumpManifest,
  JobId,
  JobKind,
  JobMessage,
  Progress,
  ScanStatus,
} from "../shared/agentProtocol.js";
import { fail, ok } from "./errors.js";
import { ScanEngine, type ScanJobWork } from "./pure/scanEngine.js";
import type { RawRange, ScanBuf, ScanPlatform } from "./pure/scanTypes.js";
import { createScanKernels, scanKernelCompileError } from "./scanKernels.js";
import type { AgentCore } from "./state.js";

/**
 * Agent feature file (WP10-SCAN; S4 §9 + DESIGN §5.3): scanStart, scanNext, scanStatus, scanResults, scanClose over
 * the pure ScanEngine (src/agent/pure/scanEngine.ts) bound to GumJS here.
 *
 * Core services (WP3-AGENT) are reached structurally, so this file compiles against the day-0 AgentCore and picks the
 * real services up once the core carries them (DESIGN §5.3):
 * - `core.guards.withBeaGuardsSuspended(ranges, fn)` (CT-I5) wraps every slice, kernel call and read;
 *   `core.guards.listingPages()` re-inserts BEA-guarded pages that Frida omits from enumerateRanges [CT-lab E16b].
 * - `core.jobs.submit(spec, announced)` / `announce(id)` run the sliced jobs (S4 §5.8: round-robin job_slice_ms
 *   slices, completion message once and never before the creating RPC replied, D-INT-7). Without a core runner a
 *   local runner with the same contract is used.
 * - `core.scanRegistry` is published for coreRpc (status().scans, memory.scan_bytes, shutdown scans_freed).
 */
interface GuardRange {
  readonly base: NativePointer;
  readonly size: number;
}
interface CoreGuardsSeam {
  withBeaGuardsSuspended?<T>(ranges: readonly GuardRange[], fn: () => T): T;
  listingPages?(): readonly { readonly base: bigint; readonly size: number; readonly protection: string }[];
}
/** The S4 §5.8 job record as the core runner (src/agent/pure/coreJobs.ts) hands it to a job's step. */
interface CoreJob {
  readonly id: JobId;
  readonly state: string;
  readonly progress: Progress;
  result: ScanStatus | DumpManifest | undefined;
  error: AgentError | null;
}
interface CoreJobSpec {
  readonly kind: JobKind;
  readonly total: number | null;
  readonly unit: Progress["unit"];
  readonly step: (job: CoreJob, budgetMs: number) => "more" | "done";
  readonly onEnd?: (job: CoreJob) => void;
}
interface CoreJobsSeam {
  submit?(spec: CoreJobSpec, announced?: boolean): CoreJob | AgentError;
  announce?(id: JobId): void;
}
interface ScanRegistryView {
  list(): ScanStatus[];
  closeAll(): number;
  memoryBytes(): number;
  /** why the TinyCC compare kernels are unavailable (the slow JS reference then runs); null when compiled */
  kernelError(): string | null;
}
type ScanCore = AgentCore & {
  guards?: CoreGuardsSeam;
  jobs?: CoreJobsSeam;
  scanRegistry?: ScanRegistryView;
};
type StartJob = (kind: JobKind, work: ScanJobWork) => JobId | AgentError;

/**
 * Local job runner, used only while the core has no `jobs.submit` (same S4 §5.8 contract: round-robin slices of
 * limits.job_slice_ms, setImmediate between slices so RPCs and flushes interleave; the first slice runs on a later
 * turn, so the completion message always follows the creating RPC's reply). Ids stay in the "j<n>" space but start
 * at 1,000,001 so they never collide with the core runner's.
 */
class LocalJobRunner {
  #seq = 1_000_000;
  readonly #queue: { readonly id: string; readonly kind: JobKind; readonly work: ScanJobWork }[] = [];
  #scheduled = false;
  readonly #sliceMs: () => number;

  constructor(sliceMs: () => number) {
    this.#sliceMs = sliceMs;
  }

  start(kind: JobKind, work: ScanJobWork): JobId {
    this.#seq += 1;
    const id = `j${String(this.#seq)}`;
    this.#queue.push({ id, kind, work });
    this.#schedule();
    return id;
  }

  #schedule(): void {
    if (this.#scheduled || this.#queue.length === 0) return;
    this.#scheduled = true;
    setImmediate(() => {
      this.#scheduled = false;
      this.#pump();
    });
  }

  #pump(): void {
    const job = this.#queue.shift();
    if (job === undefined) return;
    let finished: boolean;
    try {
      finished = job.work.step(this.#sliceMs()) === "done";
    } catch {
      // an unexpected throw ends the job; the engine keeps what it had (recorded as a cancellation)
      job.work.cancel();
      finished = job.work.step(0) === "done";
    }
    if (!finished) this.#queue.push(job);
    else {
      const out = job.work.outcome();
      const message: JobMessage = {
        bea: "job",
        job: job.id,
        kind: job.kind,
        state: out.state,
        progress: job.work.progress(),
        result: out.result,
        ...(out.error === null ? {} : { error: out.error }),
      };
      send(message);
    }
    this.#schedule();
  }
}

/** Runs a scan job on the core runner: progress, result and error flow into the core's job record. */
const submitToCore = (jobs: CoreJobsSeam, kind: JobKind, work: ScanJobWork): JobId | AgentError => {
  const submit = jobs.submit;
  if (submit === undefined) return { _tag: "Internal", message: "no job runner", where: "scan" };
  const p0 = work.progress();
  const settle = (job: CoreJob): void => {
    const out = work.outcome();
    job.result = out.result;
    if (out.state === "failed" && out.error !== null) job.error = out.error;
  };
  const spec: CoreJobSpec = {
    kind,
    total: p0.total,
    unit: p0.unit,
    step: (job, budgetMs) => {
      const r = work.step(budgetMs);
      Object.assign(job.progress, work.progress());
      if (r === "done") settle(job);
      return r;
    },
    onEnd: (job) => {
      if (job.state !== "cancelled") return;
      work.cancel();
      work.step(0); // the engine keeps its partial result and records the cancellation
      Object.assign(job.progress, work.progress());
      job.result = work.outcome().result;
    },
  };
  const job = submit.call(jobs, spec, false);
  if ("_tag" in job) return job;
  // announcement rule (D-INT-7): the completion message may go out once this RPC has replied
  setImmediate(() => jobs.announce?.call(jobs, job.id));
  return job.id;
};

const toNum = (p: NativePointer): number => Number(p.toString(10));

const createPlatform = (core: ScanCore): ScanPlatform => {
  const read = (va: number, len: number): Uint8Array | null => {
    try {
      const data = ptr(va).readByteArray(len);
      return data === null ? null : new Uint8Array(data);
    } catch {
      return null;
    }
  };
  const suspend = <T>(span: { readonly base: number; readonly size: number }, fn: () => T): T => {
    const guards = core.guards;
    return typeof guards?.withBeaGuardsSuspended === "function"
      ? guards.withBeaGuardsSuspended([{ base: ptr(span.base), size: span.size }], () => fn())
      : fn();
  };
  return {
    nowMs: () => Date.now(),
    nowUs: () => (Date.now() - core.t0Wall) * 1000,
    alloc: (bytes: number): ScanBuf | null => {
      const n = Math.max(8, bytes);
      try {
        const p = Memory.alloc(n);
        return { u8: new Uint8Array(ArrayBuffer.wrap(p, n)), bytes: n, native: p };
      } catch {
        return null;
      }
    },
    free: () => undefined, // released when the engine drops its last reference (QJS refcounting)
    ranges: (protection: string): readonly RawRange[] => {
      const map = new ModuleMap();
      const name = (base: NativePointer): string | null => map.find(base)?.name ?? null;
      const rows: RawRange[] = Process.enumerateRanges({
        protection: protection as PageProtection,
        coalesce: false,
      }).map((r) => ({ base: toNum(r.base), size: r.size, protection: r.protection, module: name(r.base) }));
      // Frida omits guarded pages from enumerateRanges; BEA's own guard pages are target data (CT-I5)
      for (const g of core.guards?.listingPages?.() ?? []) {
        const base = Number(g.base);
        const listed = rows.some((r) => r.base < base + g.size && base < r.base + r.size);
        const passes = [...protection].every((ch, i) => ch === "-" || g.protection[i] === ch);
        if (!listed && passes) rows.push({ base, size: g.size, protection: g.protection, module: name(ptr(base)) });
      }
      return rows;
    },
    scanPattern: (base: number, size: number, pattern: string): readonly number[] => {
      const at = ptr(base);
      return Memory.scanSync(at, size, pattern).map((m) => base + m.address.sub(at).toInt32());
    },
    findPointers: (base, size, targets) =>
      Memory.findPointers(
        { base: ptr(base), size },
        targets.map((t) => ptr(t)),
      ).map((m) => ({ address: toNum(m.address), value: toNum(m.value) })),
    read,
    copyIn: (dst, dstOff, va, len) => {
      try {
        Memory.copy((dst.native as NativePointer).add(dstOff), ptr(va), len);
        return true;
      } catch {
        return false;
      }
    },
    suspendGuards: suspend,
    kernels: createScanKernels(read),
  };
};

let engine: ScanEngine | null = null;
let startJob: StartJob | null = null;

const ready = (): { readonly engine: ScanEngine; readonly startJob: StartJob } => {
  if (engine === null || startJob === null) throw new Error("scan feature used before init");
  return { engine, startJob };
};

const launch = (work: AgentResult<ScanJobWork>): AgentResult<{ scan_id: string; job_id: JobId }> => {
  if (!work.ok) return work;
  const r = ready();
  const jobId = r.startJob(work.value.kind, work.value);
  if (typeof jobId !== "string") {
    // the runner refused (max_jobs): end the scan's job at once so the scan never stays "running"
    r.engine.abandon(work.value);
    return fail(jobId);
  }
  r.engine.attachJob(work.value.scanId, jobId);
  return ok({ scan_id: work.value.scanId, job_id: jobId });
};

export function init(core: AgentCore): void {
  const c = core as ScanCore;
  const e = new ScanEngine(createPlatform(c), () => c.limits);
  engine = e;
  const local = new LocalJobRunner(() => c.limits.job_slice_ms);
  startJob = (kind, work) => {
    const jobs = c.jobs; // read per call: the core may wire its runner after this feature's init
    return typeof jobs?.submit === "function" ? submitToCore(jobs, kind, work) : local.start(kind, work);
  };
  c.scanRegistry = {
    list: () => e.list(),
    closeAll: () => e.closeAll(),
    memoryBytes: () => e.memoryBytes(),
    kernelError: scanKernelCompileError,
  };
  if (!c.features.includes("scan")) c.features.push("scan");
}

export const rpc = {
  scanStart: (p) => launch(ready().engine.start(p)),
  scanNext: (p) => launch(ready().engine.next(p)),
  scanStatus: (p) => ready().engine.status(p.scan_id),
  scanResults: (p) => ready().engine.results(p),
  scanClose: (p) => ready().engine.close(p.scan_id),
} satisfies Partial<AgentRpcImpl>;
