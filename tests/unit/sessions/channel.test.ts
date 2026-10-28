import { describe, expect, it, vi } from "vitest";

import {
  buildDerivedCrash,
  deriveCrashVerdict,
  fallbackLoc,
  typeForExitCode,
} from "../../../src/application/sessions/crashDerivation.js";
import { Deadline } from "../../../src/domain/deadline.js";
import { LIMITATIONS } from "../../../src/domain/evidence/limitations.js";
import { silentLogger } from "../../../src/domain/logger.js";
import { AgentRpcClient } from "../../../src/providers/frida/AgentRpcClient.js";
import { CrashProtocol } from "../../../src/providers/frida/CrashProtocol.js";
import { estimateRowBytes, FlowTracker } from "../../../src/providers/frida/flowTracker.js";
import { BoundedOutputCapture } from "../../../src/providers/frida/outputCapture.js";
import { SerialQueue } from "../../../src/providers/frida/SerialQueue.js";
import { SessionStreamBinder } from "../../../src/providers/frida/StreamBinder.js";
import type { CrashReport } from "../../../src/shared/agentProtocol.js";
import { FakeCancellable, FakeFrida, FakeSession } from "../../support/frida/fakeFrida.js";
import { createGate } from "../../support/frida/gate.js";
import { FakeEvidence, NO_LITERALS } from "./support/fakeEvidence.js";

const batch = (stream: string, bseq: number, rows: unknown[], extra: Record<string, unknown> = {}) => ({
  bea: "batch",
  stream,
  instrument: null,
  bseq,
  kind: "hook/1",
  n: rows.length,
  g0: 1,
  g1: rows.length,
  t0: 0,
  t1: 1,
  dropped: {},
  final: false,
  enc: "json",
  rows,
  ...extra,
});

const binderWith = (options: { readonly now?: () => number } = {}) => {
  const evidence = new FakeEvidence();
  const posts: number[] = [];
  const flow = new FlowTracker({ post: (n) => posts.push(n), everyBytes: 100, everyMs: 10_000 });
  const quota: string[] = [];
  const rowsSeen: unknown[] = [];
  const binder = new SessionStreamBinder({
    streams: evidence.streams,
    flushAgent: async () => undefined,
    flow,
    moduleEpoch: () => 3,
    onRows: (_s, _k, rows) => rowsSeen.push(...rows),
    onQuota: (s) => quota.push(s),
    notify: () => undefined,
    logger: silentLogger,
    now: options.now ?? (() => 0),
    parking: { maxBytes: 4096, maxAgeMs: 2000 },
  });
  const spec = {
    source: { kind: "hook" as const, instance_id: null, effect_id: null, channel: "s1" },
    encoding: { kind: "json-rows" as const, row_kind: "hook/1" as const },
    decoders: null,
    literals: NO_LITERALS,
  };
  return { evidence, binder, posts, quota, rowsSeen, spec, flow };
};

describe("stream binder (D-INT-7, D-INT-23; case 8)", () => {
  it("maps batches to frames: first_seq = records + drops so far + dropped_before + 1, NDJSON payloads", async () => {
    const t = binderWith();
    const bound = await t.binder.bind("s1", t.spec);
    expect(bound.ok).toBe(true);
    t.binder.onBatch(batch("s1", 1, [[1], [2]]), null);
    t.binder.onBatch(batch("s1", 2, [[3]], { dropped: { buffer_full: 2 } }), null);
    const writer = t.evidence.writers[0];
    expect(
      writer?.frames.map((f) => [
        f.header.first_seq,
        f.header.count,
        f.header.dropped_before,
        f.header.module_map_epoch,
      ]),
    ).toEqual([
      [1, 2, 0, 3],
      [5, 1, 2, 3],
    ]);
    expect(writer?.rows()).toEqual([[1], [2], [3]]);
    expect(t.binder.counters("s1")).toMatchObject({ received: 3, batches: 2, agentDropped: 2 });
    expect(t.binder.dropReasons("s1")).toEqual(["agent_buffer_full"]);
  });

  it("counts bseq gaps, malformed batches, duplicates, queue-full and quota; quota calls the owner", async () => {
    const t = binderWith();
    await t.binder.bind("s1", t.spec);
    const writer = t.evidence.writers[0];
    t.binder.onBatch(batch("s1", 1, [[1]]), null);
    t.binder.onBatch(batch("s1", 4, [[2]]), null);
    t.binder.onBatch(batch("s1", 4, [[3]]), null);
    t.binder.onBatch({ ...batch("s1", 5, [[4], [5]]), n: 3 }, null);
    if (writer !== undefined) writer.nextOutcome = "queue-full";
    t.binder.onBatch(batch("s1", 6, [[6]]), null);
    if (writer !== undefined) writer.nextOutcome = "quota-exceeded";
    t.binder.onBatch(batch("s1", 7, [[7]]), null);
    writer?.triggerQuota();
    expect(t.binder.counters("s1")?.hostDropped).toEqual({
      bseqGap: 2,
      hostQueueFull: 1,
      quota: 1,
      malformed: 4,
      unbound: 0,
    });
    expect(writer?.drops).toEqual([
      { n: 2, reason: "seq_gap" },
      { n: 3, reason: "decode_error" },
    ]);
    expect(t.quota).toEqual(["s1"]);
    expect(t.binder.dropReasons("s1")).toEqual(["host_queue_full", "seq_gap", "stream_quota"]);
  });

  it("parks batches for a stream that is not bound yet and replays them at bind; stale ones count as unbound", async () => {
    let now = 0;
    const t = binderWith({ now: () => now });
    t.binder.onBatch(batch("s2", 1, [[1]]), null);
    now = 3000;
    t.binder.onBatch(batch("s9", 1, [[9]]), null);
    expect(t.binder.unboundBatches).toBe(1);
    t.binder.onBatch(batch("s3", 1, [[2]]), null);
    await t.binder.bind("s3", { ...t.spec, source: { ...t.spec.source, channel: "s3" } });
    expect(t.evidence.writerFor("s3")?.rows()).toEqual([[2]]);
  });

  it("validates binary batches against the layout and ends each writer once (later ends return the first manifest)", async () => {
    const t = binderWith();
    await t.binder.bind("b1", {
      ...t.spec,
      encoding: { kind: "fixed-records", row_kind: "block-span/1", record_bytes: 16, fields: [] },
    });
    t.binder.onBatch(
      {
        ...batch("b1", 1, []),
        enc: "bin",
        kind: "block-span/1",
        n: 2,
        layout: "block-span/1",
        rec_bytes: 16,
        rows: undefined,
      },
      Buffer.alloc(32),
    );
    t.binder.onBatch(
      { ...batch("b1", 2, []), enc: "bin", kind: "block-span/1", n: 2, rows: undefined },
      Buffer.alloc(31),
    );
    expect(t.binder.counters("b1")).toMatchObject({ received: 2, hostDropped: { malformed: 2 } });
    const first = await t.binder.endWith("b1", "process-killed");
    const second = await t.binder.end("b1", "stopped");
    expect(first.ok && second.ok && first.value.record.evidence_id === second.value.record.evidence_id).toBe(true);
    expect(t.evidence.writers[0]?.endCalls).toBe(1);
    expect(t.evidence.writers[0]?.endReason).toBe("process-killed");
    expect((await t.binder.end("nope", "stopped")).ok).toBe(false);
  });

  it("acks flow in the agent's estimate units (S4 §6.5)", async () => {
    const t = binderWith();
    await t.binder.bind("s1", t.spec);
    const row = [1, "0x7ff6a0001000", "abc", null, [true]];
    t.binder.onBatch(
      batch(
        "s1",
        1,
        Array.from({ length: 5 }, () => row),
      ),
      null,
    );
    expect(estimateRowBytes(row)).toBe(2 + (12 + 1) + (20 + 1) + (5 + 1) + (4 + 1) + (2 + 4 + 1 + 1));
    expect(t.posts).toEqual([estimateRowBytes(row) * 5]);
    t.flow.stop();
  });
});

describe("crash protocol (D-INT-27; case 7)", () => {
  const report = { report_id: "r1", type: "access-violation" } as unknown as CrashReport;

  it("records first, then posts exactly one ack per token", async () => {
    const posts: unknown[] = [];
    const gate = createGate();
    const order: string[] = [];
    const crash = new CrashProtocol({
      post: (m) => {
        order.push("ack");
        posts.push(m);
      },
      recordCrash: async () => {
        await gate.wait();
        order.push("recorded");
      },
      recordExit: async () => undefined,
      ackTimeoutMs: 5000,
      ringSize: 16,
      now: () => 0,
      logger: silentLogger,
      onReport: () => undefined,
    });
    crash.onCrash("crash-1", report);
    crash.onCrash("crash-1", report);
    await gate.entered;
    expect(posts).toEqual([]);
    gate.release();
    await new Promise((r) => setImmediate(r));
    expect(order).toEqual(["recorded", "ack"]);
    expect(posts).toEqual([{ type: "ack", token: "crash-1" }]);
    expect(crash.crashCount).toBe(1);
  });

  it("a sink stalled past 5 s still acks; ackAll releases pending waiters at close", async () => {
    vi.useFakeTimers();
    try {
      const posts: unknown[] = [];
      const crash = new CrashProtocol({
        post: (m) => posts.push(m),
        recordCrash: () => new Promise(() => undefined),
        recordExit: () => new Promise(() => undefined),
        ackTimeoutMs: 5000,
        ringSize: 16,
        now: () => Date.now(),
        logger: silentLogger,
        onReport: () => undefined,
      });
      crash.onCrash("crash-2", report);
      vi.advanceTimersByTime(4999);
      expect(posts).toEqual([]);
      vi.advanceTimersByTime(1);
      expect(posts).toEqual([{ type: "ack", token: "crash-2" }]);
      expect(crash.crashes[0]?.ackVia).toBe("timeout");
      crash.onExit("exit-1", {
        bea: "exit",
        ack: "exit-1",
        via: "RtlExitUserProcess",
        exit_code: 0,
        tid: 1,
        g: 1,
        t: 1,
        flushed: { streams: 0, rows: 0 },
      });
      crash.ackAll("closing");
      expect(posts).toEqual([
        { type: "ack", token: "crash-2" },
        { type: "ack", token: "exit-1" },
      ]);
      expect(crash.pendingAcks).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });
});

/** Crash derivation fixtures (CI-I9). */
const r = (phase: "first-chance" | "last-chance", type: string, at: number) => ({
  report: {
    report_id: `${phase}-${String(at)}`,
    phase,
    type,
    tid: 3,
    address: "0x7ff6a0001650",
    memory: { operation: "write", address: "0x0" },
    registers: { rax: "0x0", rip: "0x7ff6a0001650" },
    xmm: ["0x1"],
    instruction: { address: "0x7ff6a0001650", bytes: "", text: "mov [rax], 0" },
    backtrace: [{ va: "0x7ff6a0001650", module: "game.exe", rva: "0x1650" }],
  } as unknown as CrashReport,
  receivedAt: at,
});
const exit = (code: number, kind: "ntstatus" | "normal" | "bea-kill" = "ntstatus") =>
  ({
    code,
    code_hex: `0x${code.toString(16)}`,
    kind,
    name: code === 0xc0000005 ? "STATUS_ACCESS_VIOLATION" : null,
  }) as const;

describe("crash derivation (CI-I9)", () => {
  it("joins the last crash-class report within 2 s of an NTSTATUS exit", () => {
    const verdict = deriveCrashVerdict({
      exit: exit(0xc0000005),
      exitAt: 10_000,
      reports: [r("first-chance", "access-violation", 9_000)],
      windowMs: 2000,
      exceptionRows: 3,
    });
    expect(verdict).toMatchObject({
      kind: "crash",
      type: "access-violation",
      ntstatus: "STATUS_ACCESS_VIOLATION",
      firstChanceCount: 2,
      limitations: [],
    });
  });

  it("no report → pc null + CRASH_PC_UNKNOWN; a mismatching report → CRASH_EXIT_MISMATCH; old reports are ignored", () => {
    expect(
      deriveCrashVerdict({
        exit: exit(0xc0000409),
        exitAt: 10_000,
        reports: [r("first-chance", "access-violation", 1_000)],
        windowMs: 2000,
        exceptionRows: 0,
      }),
    ).toMatchObject({
      kind: "crash",
      report: null,
      type: "fast-fail",
      limitations: [LIMITATIONS.CRASH_PC_UNKNOWN],
    });
    expect(
      deriveCrashVerdict({
        exit: exit(0xc0000094),
        exitAt: 10,
        reports: [r("last-chance", "access-violation", 9)],
        windowMs: 2000,
        exceptionRows: 1,
      }),
    ).toMatchObject({
      limitations: [LIMITATIONS.CRASH_EXIT_MISMATCH],
    });
  });

  it("a BEA kill or a clean exit is no crash unless a last-chance report says so", () => {
    expect(
      deriveCrashVerdict({
        exit: exit(0xbea, "bea-kill"),
        exitAt: 10,
        reports: [r("last-chance", "access-violation", 9)],
        windowMs: 2000,
        exceptionRows: 0,
      }).kind,
    ).toBe("none");
    expect(
      deriveCrashVerdict({
        exit: exit(0, "normal"),
        exitAt: 10,
        reports: [r("first-chance", "access-violation", 9)],
        windowMs: 2000,
        exceptionRows: 0,
      }).kind,
    ).toBe("none");
    expect(
      deriveCrashVerdict({
        exit: exit(3, "normal"),
        exitAt: 10,
        reports: [r("last-chance", "abort", 9)],
        windowMs: 2000,
        exceptionRows: 0,
      }),
    ).toMatchObject({ kind: "crash", type: "abort" });
    expect(deriveCrashVerdict({ exit: null, exitAt: null, reports: [], windowMs: 2000, exceptionRows: 0 }).kind).toBe(
      "none",
    );
    expect(typeForExitCode(0xc00000fd)).toBe("stack-overflow");
  });

  it("builds the tool shape: GPRs, xmm only on request, Loc frames", async () => {
    const verdict = deriveCrashVerdict({
      exit: exit(0xc0000005),
      exitAt: 10,
      reports: [r("first-chance", "access-violation", 9)],
      windowMs: 2000,
      exceptionRows: 1,
    });
    if (verdict.kind !== "crash") throw new Error("expected a crash");
    const crash = await buildDerivedCrash(verdict, async (f) => fallbackLoc(f), null, false);
    expect(crash).toMatchObject({
      thread_id: 3,
      insn: "mov [rax], 0",
      memory: { op: "write", address: "0x0" },
      registers: { rax: "0x0", rip: "0x7ff6a0001650" },
    });
    expect(crash.pc).toEqual({ va: "0x7ff6a0001650", at: "game.exe+0x1650", static: null, func: null, sym: null });
    const withXmm = await buildDerivedCrash(verdict, async (f) => fallbackLoc(f), null, true);
    expect(withXmm.registers["xmm0"]).toBe("0x1");
    expect(fallbackLoc({ va: "0x1", module: "bad name;.exe", rva: "0x1" }).at).toBeNull();
  });
});

describe("crash derivation joins (review fix AGENT-11)", () => {
  it("joins only matching first-chance reports: a fast fail or another type gets pc null (AGENT-11)", () => {
    // a handled C++ throw (first-chance "system", no code) right before std::terminate's fast fail
    expect(
      deriveCrashVerdict({
        exit: exit(0xc0000409),
        exitAt: 10_000,
        reports: [r("first-chance", "system", 9_990)],
        windowMs: 2000,
        exceptionRows: 1,
      }),
    ).toMatchObject({ kind: "crash", report: null, type: "fast-fail", limitations: [LIMITATIONS.CRASH_PC_UNKNOWN] });
    // a first-chance AV (handled by the program) does not explain an integer-divide exit
    expect(
      deriveCrashVerdict({
        exit: exit(0xc0000094),
        exitAt: 10,
        reports: [r("first-chance", "access-violation", 9)],
        windowMs: 2000,
        exceptionRows: 1,
      }),
    ).toMatchObject({ kind: "crash", report: null, type: "arithmetic", limitations: [LIMITATIONS.CRASH_PC_UNKNOWN] });
    // an unknown error status never joins a code-less first-chance "system" report
    expect(
      deriveCrashVerdict({
        exit: exit(0xc0000374),
        exitAt: 10,
        reports: [r("first-chance", "system", 9)],
        windowMs: 2000,
        exceptionRows: 1,
      }),
    ).toMatchObject({ kind: "crash", report: null, limitations: [LIMITATIONS.CRASH_PC_UNKNOWN] });
    // a last-chance report wins over a later first-chance one
    const preferred = deriveCrashVerdict({
      exit: exit(0xc0000005),
      exitAt: 10,
      reports: [r("last-chance", "access-violation", 8), r("first-chance", "access-violation", 9)],
      windowMs: 2000,
      exceptionRows: 2,
    });
    expect(preferred).toMatchObject({ kind: "crash", type: "access-violation", limitations: [] });
    if (preferred.kind !== "crash") throw new Error("expected a crash");
    expect(preferred.report?.phase).toBe("last-chance");
  });
});

describe("serial queue (S3 §7.3; case 2)", () => {
  it("runs FIFO, refuses the 17th pending op with the exact message, and lets an aborted waiter leave the line", async () => {
    const queue = new SerialQueue(16);
    const gate = createGate();
    const order: number[] = [];
    const never = new AbortController().signal;
    const first = queue.run("op", never, async () => {
      await gate.wait();
      order.push(0);
      return { ok: true as const, value: 0 };
    });
    const aborted = new AbortController();
    const leaving = queue.run("leave", aborted.signal, async () => ({ ok: true as const, value: -1 }));
    const rest = Array.from({ length: 14 }, (_, i) =>
      queue.run("op", never, async () => {
        order.push(i + 1);
        return { ok: true as const, value: i + 1 };
      }),
    );
    const refused = await queue.run("op", never, async () => ({ ok: true as const, value: 99 }));
    expect(refused.ok).toBe(false);
    if (!refused.ok) {
      expect(refused.error._tag).toBe("ResourceConstraint");
      expect(refused.error.message).toBe(
        "This session already has 16 queued operations. Wait for some to finish. This release has no runtime override.",
      );
    }
    aborted.abort();
    const left = await leaving;
    expect(left.ok).toBe(false);
    gate.release();
    await Promise.all([first, ...rest]);
    expect(order).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
    expect(queue.pending).toBe(0);
  });
});

describe("agent RPC client (S3 §11; case 6)", () => {
  const setup = (
    terminal = {
      closing: false,
      exited: null as { exit: null } | null,
      detachReason: null as string | null,
      instanceId: "pi_x",
    },
  ) => {
    const fake = new FakeFrida();
    fake.addProcess({ pid: 900, name: "t.exe", path: "C:\\t.exe" });
    const session = new FakeSession(fake, 900);
    return { fake, session, terminal };
  };
  const op = (ms = 2000) => ({
    opId: 1,
    name: "read_memory",
    signal: new AbortController().signal,
    deadline: Deadline.after(ms),
  });

  it("validates replies: AgentError → mapped BeaError (no agent text), binary tuples, malformed → protocol violation", async () => {
    const t = setup();
    const script = await t.session.createScript("x", { name: "bea-agent", runtime: "qjs" });
    t.fake.defaultBehavior = {
      rpc: {
        ping: () => ({
          ok: false,
          error: { _tag: "AccessViolation", message: "target text 0xdead", address: "0x10", operation: "read" },
        }),
        flush: () => ({ nonsense: true }),
        readMemory: () => [
          {
            ok: true,
            value: { address: "0x10", requested: 2, returned: 2, complete: true, stop: null, bea_guard_suspended: [] },
          },
          Buffer.from("MZ"),
        ],
      },
    };
    const client = new AgentRpcClient({
      script,
      createCancellable: () => new FakeCancellable(),
      defaultTimeoutMs: 1000,
      pingTimeoutMs: 100,
      pingIntervalMs: 1000,
      instanceId: () => "pi_x",
      terminal: async () => t.terminal,
      logger: silentLogger,
      now: () => performance.now(),
    });
    const av = await client.call("ping", {}, { op: op() });
    expect(av.ok).toBe(false);
    if (!av.ok) {
      expect(av.error._tag).toBe("MemoryAccessFailed");
      expect(JSON.stringify(av.error)).not.toContain("target text");
    }
    const bad = await client.call("flush", {}, { op: op() });
    expect(!bad.ok && bad.error._tag).toBe("ProviderFailure");
    const bin = await client.call("readMemory", { address: "0x10", size: 2 }, { op: op() });
    expect(bin.ok && bin.value.data.toString()).toBe("MZ");
    const missing = await client.call("scanClose", { scan_id: "sc1" }, { op: op() });
    expect(!missing.ok && missing.error._tag === "CapabilityUnavailable" && missing.error.reason).toBe("protocol-skew");
  });

  it("a deadline → provider_timeout and health suspect → a failed ping → unresponsive (fail fast)", async () => {
    const t = setup();
    const script = await t.session.createScript("x", { name: "bea-agent", runtime: "qjs" });
    t.fake.hold("rpc:ping");
    t.fake.hold("rpc:flush");
    const client = new AgentRpcClient({
      script,
      createCancellable: () => new FakeCancellable(),
      defaultTimeoutMs: 30,
      pingTimeoutMs: 30,
      pingIntervalMs: 0,
      instanceId: () => "pi_x",
      terminal: async () => t.terminal,
      logger: silentLogger,
      now: () => performance.now(),
    });
    const slow = await client.call("flush", {}, { op: op() });
    expect(!slow.ok && slow.error._tag).toBe("ProviderTimeout");
    expect(client.health.state === "suspect" || client.health.state === "unresponsive").toBe(true);
    await vi.waitFor(() => expect(client.health.state).toBe("unresponsive"), { interval: 10, timeout: 1000 });
    const fast = await client.call("flush", {}, { op: op() });
    expect(!fast.ok && fast.error._tag === "ProviderTimeout" && fast.error.phase).toBe("agent-unresponsive");
  });

  it("Script is destroyed maps by the terminal view: exited → target_exited, otherwise agent-gone", async () => {
    const t = setup({ closing: false, exited: { exit: null }, detachReason: "process-terminated", instanceId: "pi_x" });
    const script = await t.session.createScript("x", { name: "bea-agent", runtime: "qjs" });
    t.fake.hold("rpc:ping");
    const client = new AgentRpcClient({
      script,
      createCancellable: () => new FakeCancellable(),
      defaultTimeoutMs: 1000,
      pingTimeoutMs: 100,
      pingIntervalMs: 1000,
      instanceId: () => "pi_x",
      terminal: async () => t.terminal,
      logger: silentLogger,
      now: () => performance.now(),
    });
    const pending = client.call("ping", {}, { op: op() });
    await new Promise((r) => setImmediate(r));
    t.session.markDetached("process-terminated");
    const result = await pending;
    expect(!result.ok && result.error._tag).toBe("TargetExited");
    expect(client.health.state).toBe("gone");
  });
});

describe("output capture (S3 §15)", () => {
  it("keeps head + tail, counts observed bytes, tracks EOF per fd and searches retained text", async () => {
    const chunks: [number, string][] = [];
    const capture = new BoundedOutputCapture({
      headBytes: 8,
      tailBytes: 8,
      onChunk: (fd, d) => chunks.push([fd, d.toString()]),
    });
    capture.push(1, Buffer.from("HEAD-123"));
    capture.push(1, Buffer.from("middle-dropped-"));
    capture.push(1, Buffer.from("TAIL-xyz"));
    capture.push(2, Buffer.from("err"));
    expect(capture.observedBytes).toEqual({ stdout: 31, stderr: 3 });
    expect(capture.truncated).toBe(true);
    expect(capture.tail(1, 8)).toBe("TAIL-xyz");
    expect(capture.contains("HEAD")).toBe(true);
    expect(capture.contains("TAIL-xyz")).toBe(true);
    expect(capture.contains("middle")).toBe(false);
    expect(capture.contains("-123TAIL")).toBe(false);
    const eof = capture.waitEof(1000);
    capture.push(1, Buffer.alloc(0));
    capture.push(2, Buffer.alloc(0));
    expect(await eof).toBe(true);
    expect(chunks).toHaveLength(4);
  });
});
