// WP3-AGENT unit tests: runtime bookkeeping of the agent core — rate limiters (S4 §7.3–§7.4, §5.1), the sliced job
// runner (S4 §5.8; round-robin, cancellation, failures, max_jobs, exactly-once completion after the announcement), the
// oracle-call ledger (DESIGN §5.3.1 rules 3–5, CT-I1), instrument lifetimes and hit accounting (S4 §5.7, CI-I3) and
// the ack router (S4 §6.6).
import { describe, expect, it } from "vitest";

import { AckRouter } from "../../../../src/agent/pure/coreAck.js";
import { CallLedger } from "../../../../src/agent/pure/coreCalls.js";
import { hitOutcome, normalizeLifetime, reverseCreationOrder } from "../../../../src/agent/pure/coreInstruments.js";
import { JobRunner, type Job, type JobRunnerDeps } from "../../../../src/agent/pure/coreJobs.js";
import {
  ExceptionRowLimiter,
  FaultCoalescer,
  LruMap,
  SlidingCount,
  TokenBucket,
} from "../../../../src/agent/pure/coreRate.js";
import type { AgentError, JobMessage } from "../../../../src/shared/agentProtocol.js";

describe("rate limiters", () => {
  it("SlidingCount allows max events per trailing window", () => {
    const s = new SlidingCount(2, 10_000);
    expect([s.allow(0), s.allow(1), s.allow(2)]).toEqual([true, true, false]);
    expect(s.allow(10_000)).toBe(true);
    s.setMax(0);
    expect(s.allow(30_000)).toBe(false);
  });

  it("ExceptionRowLimiter folds repeats into pending rows above the per-second cap", () => {
    const l = new ExceptionRowLimiter<{ id: number; pending: boolean }>(2);
    const a = { id: 1, pending: true };
    expect(l.decide("av@1", 0, (r) => r.pending)).toEqual({ kind: "new" });
    l.remember("av@1", a);
    expect(l.decide("av@2", 1, (r) => r.pending)).toEqual({ kind: "new" });
    expect(l.decide("av@1", 2, (r) => r.pending)).toEqual({ kind: "repeat", row: a });
    a.pending = false; // the row was sent: it can no longer change
    expect(l.decide("av@1", 3, (r) => r.pending)).toEqual({ kind: "drop" });
    expect(l.decide("av@9", 4, (r) => r.pending)).toEqual({ kind: "drop" });
    expect(l.decide("av@9", 1000, (r) => r.pending)).toEqual({ kind: "new" }); // next second
  });

  it("FaultCoalescer sends ≤ N per second and carries suppressed occurrences forward", () => {
    const f = new FaultCoalescer(2);
    expect([f.note(0), f.note(1), f.note(2), f.note(3)]).toEqual([1, 1, null, null]);
    expect(f.suppressed).toBe(2);
    expect(f.note(1000)).toBe(3);
  });

  it("TokenBucket refills at the rate; LruMap evicts the least recently used", () => {
    const t = new TokenBucket(2, 2);
    expect([t.take(0), t.take(0), t.take(0)]).toEqual([true, true, false]);
    expect(t.take(500)).toBe(true);
    const m = new LruMap<string, number>(2);
    m.set("a", 1);
    m.set("b", 2);
    expect(m.get("a")).toBe(1);
    m.set("c", 3);
    expect(m.get("b")).toBeUndefined();
    expect(m.size).toBe(2);
  });
});

const runner = (limits = { max_jobs: 2, job_slice_ms: 8 }) => {
  const queue: (() => void)[] = [];
  const sent: JobMessage[] = [];
  let scope: (() => void)[] | null = null;
  const deps: JobRunnerDeps = {
    nowUs: () => 1,
    nowMs: () => 1,
    schedule: (fn) => queue.push(fn),
    send: (m) => sent.push(m),
    mapError: (e, where): AgentError => ({ _tag: "Internal", message: "x", where, frida_message: String(e) }),
    limits: () => limits,
    afterReply: (fn) => {
      if (scope === null) return false;
      scope.push(fn);
      return true;
    },
  };
  const r = new JobRunner(deps);
  const drain = (max = 100): void => {
    for (let i = 0; i < max && queue.length > 0; i++) queue.shift()!();
  };
  const rpc = (fn: () => void): void => {
    scope = [];
    fn();
    const after = scope;
    scope = null;
    for (const cb of after) cb();
  };
  return { r, sent, drain, rpc, queue };
};

const counting = (slices: number, log: string[], name: string) => ({
  kind: "scan-first" as const,
  total: slices,
  unit: "items" as const,
  step: (job: Job, budget: number): "more" | "done" => {
    expect(budget).toBe(8);
    log.push(name);
    job.progress.done++;
    return job.progress.done >= slices ? "done" : "more";
  },
});

describe("job runner", () => {
  it("slices jobs round-robin and sends each completion exactly once", () => {
    const { r, sent, drain } = runner();
    const log: string[] = [];
    const a = r.submit(counting(3, log, "a")) as Job;
    const b = r.submit(counting(2, log, "b")) as Job;
    drain();
    expect(log).toEqual(["a", "b", "a", "b", "a"]);
    expect(sent.map((m) => [m.job, m.state, m.progress.done])).toEqual([
      [b.id, "done", 2],
      [a.id, "done", 3],
    ]);
    expect(r.info(a)).toMatchObject({ state: "done", kind: "scan-first", ended_t: 1, error: null });
    drain();
    expect(sent).toHaveLength(2);
  });

  it("refuses beyond max_jobs; cancels queued and running jobs; maps a throwing slice to failed", () => {
    const { r, sent, drain } = runner({ max_jobs: 1, job_slice_ms: 8 });
    const log: string[] = [];
    const a = r.submit(counting(5, log, "a")) as Job;
    expect(r.submit(counting(1, log, "b"))).toMatchObject({ _tag: "ResourceLimit", resource: "jobs", limit: 1 });
    drain(1);
    r.cancel(a.id);
    drain();
    expect(sent.at(-1)).toMatchObject({ job: a.id, state: "cancelled" });
    const ended: string[] = [];
    const bad = r.submit({
      kind: "dump",
      total: null,
      unit: "bytes",
      step: () => {
        throw new Error("boom");
      },
      onEnd: (j) => ended.push(j.state),
    }) as Job;
    drain();
    expect(sent.at(-1)).toMatchObject({ job: bad.id, state: "failed", error: { _tag: "Internal", where: "job:dump" } });
    expect(ended).toEqual(["failed"]);
    expect(r.cancel("j999")).toBeNull();
    expect(r.cancelAll()).toBe(0);
  });

  it("holds the completion message until the creating RPC replied (announcement rule)", () => {
    const { r, sent, drain, rpc } = runner();
    let job: Job | null = null;
    rpc(() => {
      job = r.submit(counting(1, [], "a")) as Job;
      expect(job.announced).toBe(false);
    });
    expect(job!.announced).toBe(true);
    drain();
    expect(sent).toHaveLength(1);
    // explicit form (scan.ts seam): announced=false then announce(id) later
    const j2 = r.submit(counting(1, [], "b"), false) as Job;
    drain();
    expect(sent).toHaveLength(1);
    r.announce(j2.id);
    expect(sent).toHaveLength(2);
  });
});

describe("oracle-call ledger", () => {
  it("tracks the in-call thread, nesting, counters and the last faults", () => {
    const l = new CallLedger<string>();
    const t1 = l.newToken();
    const call = l.enter(7, t1, { observe: false, bypassOverrides: true });
    expect(l.activeOn(7)).toBe(call);
    expect(call.valueOf()).toBe(1);
    expect(call).toMatchObject({ depth: 1, observe: false, bypassOverrides: true }); // the S4 §13.4 record shape
    expect(Number(call) > 0).toBe(true); // seams that store depths compare the record numerically
    l.enter(7, l.newToken());
    expect(call.depth).toBe(2);
    for (let i = 0; i < 10; i++)
      l.noteException(7, { g: i, type: "access-violation", address: "0x1", memory: null, registers: { rip: "0x1" } });
    l.noteTrap(7);
    expect(l.noteException(8, { g: 0, type: "system", address: "0x1", memory: null, registers: {} })).toBe(false);
    expect(l.exit(7)).toBeNull();
    const done = l.exit(7)!;
    expect(done).toMatchObject({ tid: 7, token: t1, exceptions: 10, beaTraps: 1, options: { bypassOverrides: true } });
    expect(done.faults.map((f) => f.g)).toEqual([2, 3, 4, 5, 6, 7, 8, 9]);
    expect(l.activeOn(7)).toBeNull();
    expect(l.inCallExceptions).toBe(10);
    expect(l.active()).toEqual([]);
  });

  it("expires timed-out closures: a late run is a counted no-op that releases its quarantine", () => {
    const l = new CallLedger<string>();
    const t = l.newToken();
    l.quarantine(t, ["block", "scratch"]);
    expect(l.quarantinedBlocks).toBe(2);
    l.expire(t);
    l.expire(t);
    expect(l.expiredClosures).toBe(1);
    expect(l.isExpired(t)).toBe(true);
    expect(l.beginRun(t)).toBe(false);
    expect(l.lateRuns).toBe(1);
    expect(l.quarantinedBlocks).toBe(0);
    const t2 = l.newToken();
    expect(l.beginRun(t2)).toBe(true);
    l.quarantine(t2, ["b2"]);
    l.release(t2);
    l.quarantine(l.newToken(), ["b3"]);
    expect(l.drain()).toEqual(["b3"]);
  });
});

describe("instrument lifetimes", () => {
  const limits = { max_duration_ms: 3_600_000, max_hits_cap: 1000 };
  it("applies agent defaults only for zero fields and clamps to the limits", () => {
    expect(normalizeLifetime("hook", { duration_ms: 0, max_hits: 0 }, limits)).toEqual({
      durationMs: 30_000,
      maxHits: 1000,
      clock: "install",
    });
    expect(normalizeLifetime("watch", { duration_ms: 5000, max_hits: 0, clock: "resume" }, limits)).toEqual({
      durationMs: 5000,
      maxHits: 1000,
      clock: "resume",
    });
    expect(normalizeLifetime("trace", { duration_ms: 9e9, max_hits: 5 }, limits)).toEqual({
      durationMs: 3_600_000,
      maxHits: 5,
      clock: "install",
    });
    expect(normalizeLifetime("watch", undefined, { max_duration_ms: 10, max_hits_cap: 1e9 })).toMatchObject({
      maxHits: 1000,
    });
  });

  it("records the hit reaching max_hits and stops; later or inactive hits are ignored", () => {
    expect(hitOutcome(true, 0, 3)).toBe("record");
    expect(hitOutcome(true, 2, 3)).toBe("record-and-stop");
    expect(hitOutcome(true, 3, 3)).toBe("ignore");
    expect(hitOutcome(false, 0, 3)).toBe("ignore");
    expect(hitOutcome(true, 0, 1)).toBe("record-and-stop");
    expect(reverseCreationOrder([{ seq: 1 }, { seq: 3 }, { seq: 2 }]).map((x) => x.seq)).toEqual([3, 2, 1]);
  });
});

describe("ack router", () => {
  it("routes acks to waiters by token and remembers early acks briefly", () => {
    const r = new AckRouter<string>();
    const a = r.token("crash");
    const b = r.token("exit");
    expect([a, b]).toEqual(["crash-1", "exit-2"]);
    expect(r.add(a, "event-a")).toBe(false);
    expect(r.add(b, "event-b")).toBe(false);
    expect(r.route(b)).toBe("event-b");
    expect(r.route(a)).toBe("event-a");
    expect(r.route("crash-99")).toBeNull();
    expect(r.add("crash-99", "late")).toBe(true);
    r.remove(a);
    r.remove(b);
    r.remove("crash-99");
    expect(r.waiting).toBe(0);
  });
});
