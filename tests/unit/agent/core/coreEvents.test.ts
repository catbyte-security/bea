// WP3-AGENT unit tests: the event pipeline (S4 §6, D-INT-7, D-INT-23) — row estimates (the unit the host's flow tracker
// mirrors), admission, per-reason drop deltas, the flow-control hysteresis, and the stream registry: nothing is sent
// before hello, the announcement rule inside an RPC scope, batch sizes, immediate flushes, final batches, binary
// chunks, drop-only batches and max_streams.
import { describe, expect, it } from "vitest";

import { StreamRegistry, Stream, type EventDeps } from "../../../../src/agent/pure/coreEvents.js";
import {
  admitRow,
  DROP_REASONS,
  DropLedger,
  estimateBytes,
  FlowControl,
  needsImmediateFlush,
} from "../../../../src/agent/pure/coreStreams.js";
import { AGENT_LIMIT_DEFAULTS } from "../../../../src/shared/agentLimits.js";
import type { AgentLimits, BatchMessage, NoticeMessage } from "../../../../src/shared/agentProtocol.js";

describe("row estimates, admission, drops, flow", () => {
  it("estimates rows with the shared rule (numbers 12, 0x… 20, strings 2+len, containers recursive)", () => {
    expect(estimateBytes(1)).toBe(12);
    expect(estimateBytes("0x7ff6")).toBe(20);
    expect(estimateBytes("abc")).toBe(5);
    expect(estimateBytes(null)).toBe(4);
    expect(estimateBytes([1, "0x1", null])).toBe(2 + 13 + 21 + 5);
    expect(estimateBytes({ a: 1 })).toBe(2 + 1 + 3 + 12);
  });

  it("admits rows in order: stopped, flow-control (non-system), buffer bounds", () => {
    const l = { stream_max_pending_rows: 2, stream_max_pending_bytes: 100 };
    const fill = { open: true, system: false, pendingRows: 0, pendingBytes: 0 };
    expect(admitRow(fill, false, l)).toBeNull();
    expect(admitRow({ ...fill, open: false }, false, l)).toBe("stopped");
    expect(admitRow(fill, true, l)).toBe("flow_control");
    expect(admitRow({ ...fill, system: true }, true, l)).toBeNull();
    expect(admitRow({ ...fill, pendingRows: 2 }, false, l)).toBe("buffer_full");
    expect(admitRow({ ...fill, pendingBytes: 100 }, false, l)).toBe("buffer_full");
    expect(needsImmediateFlush(2000, 0, { batch_max_rows: 2000 })).toBe(true);
    expect(needsImmediateFlush(1, 256 * 1024, { batch_max_rows: 2000 })).toBe(true);
    expect(needsImmediateFlush(1, 10, { batch_max_rows: 2000 })).toBe(false);
  });

  it("reports drop deltas per batch and cumulative snapshots", () => {
    const d = new DropLedger();
    expect(DROP_REASONS).toHaveLength(10);
    d.add("buffer_full", 3);
    d.add("rate_limit");
    expect(d.takeDelta()).toEqual({ buffer_full: 3, rate_limit: 1 });
    expect(d.hasPendingDelta()).toBe(false);
    d.add("buffer_full");
    expect(d.takeDelta()).toEqual({ buffer_full: 1 });
    expect(d.snapshot()).toEqual({ buffer_full: 4, rate_limit: 1 });
    expect(d.sum()).toBe(5);
  });

  it("sheds above high water and resumes below low water (hysteresis)", () => {
    const f = new FlowControl(100, 40);
    expect(f.onSent(80)).toBeNull();
    expect(f.onSent(30)).toBe("shedding-on");
    expect(f.shedding).toBe(true);
    expect(f.onReceived(50)).toBeNull(); // inflight 60 ≥ 40
    expect(f.onReceived(30)).toBeNull(); // cumulative never decreases
    expect(f.onReceived(80)).toBe("shedding-off"); // inflight 30 < 40
    expect(f.inflight).toBe(30);
    expect(f.configure(10, 50)).toBe("shedding-on"); // low clamped to high
  });
});

interface Harness {
  readonly reg: StreamRegistry;
  readonly sent: { m: BatchMessage | NoticeMessage; data?: ArrayBuffer }[];
  ready: boolean;
  now: number;
}

const harness = (limits: Partial<AgentLimits> = {}): Harness => {
  const h = { sent: [] as Harness["sent"], ready: true, now: 0 } as Harness & { reg: StreamRegistry };
  const deps: EventDeps = {
    send: (m, data) => h.sent.push(data === undefined ? { m } : { m, data }),
    nowMs: () => h.now,
    limits: () => ({ ...AGENT_LIMIT_DEFAULTS, ...limits }),
    canSend: () => h.ready,
  };
  (h as { reg: StreamRegistry }).reg = new StreamRegistry(deps);
  return h;
};

const open = (h: Harness, spec: Partial<Parameters<StreamRegistry["open"]>[0]> = {}): Stream => {
  const s = h.reg.open({ instrument: "h1", kind: "hook/1", enc: "json", ...spec });
  if (!(s instanceof Stream)) throw new Error(s.message);
  return s;
};
const batches = (h: Harness): BatchMessage[] =>
  h.sent.map((x) => x.m).filter((m): m is BatchMessage => m.bea === "batch");

describe("stream registry", () => {
  it("sends nothing before hello and batches with g/t ranges afterwards", () => {
    const h = harness();
    h.ready = false;
    const s = open(h, { id: "s:modules", instrument: null, kind: "module/1", system: true });
    h.reg.emit(s, [1, 10, "L", "a.dll"]);
    h.reg.emit(s, [2, 20, "L", "b.dll"]);
    expect(h.reg.flushAll()).toEqual({ batches: 0, rows: 0, streams: 0 });
    h.ready = true;
    expect(h.reg.flushAll()).toEqual({ batches: 1, rows: 2, streams: 1 });
    expect(batches(h)[0]).toMatchObject({
      stream: "s:modules",
      instrument: null,
      bseq: 1,
      n: 2,
      g0: 1,
      g1: 2,
      t0: 10,
      t1: 20,
      final: false,
      enc: "json",
    });
    expect(h.reg.info(s)).toMatchObject({ recorded: 2, sent_rows: 2, batches: 1, pending_rows: 0 });
  });

  it("keeps streams opened inside an RPC unannounced until the scope ends", () => {
    const h = harness();
    h.reg.beginScope();
    const s = open(h);
    h.reg.emit(s, [1, 1]);
    expect(h.reg.flushAll().batches).toBe(0);
    h.reg.endScope();
    expect(h.reg.flushAll().batches).toBe(1);
    expect(s.announced).toBe(true);
    expect(s.id).toBe("s1");
    // a stale scope is released explicitly by the agent's flush loop
    h.reg.beginScope();
    const late = open(h);
    expect(late.announced).toBe(false);
    h.reg.announcePending();
    expect(late.announced).toBe(true);
    h.reg.endScope();
  });

  it("splits batches at batch_max_rows and flushes from the producer at the threshold", () => {
    const h = harness({ batch_max_rows: 3 });
    const s = open(h);
    for (let i = 1; i <= 7; i++) h.reg.emit(s, [i, i]);
    // producer-side immediate flushes at 3 and 6 rows
    expect(batches(h).map((b) => b.n)).toEqual([3, 3]);
    h.reg.flushStream(s, false);
    expect(batches(h).map((b) => [b.bseq, b.n, b.g0, b.g1])).toEqual([
      [1, 3, 1, 3],
      [2, 3, 4, 6],
      [3, 1, 7, 7],
    ]);
  });

  it("counts drops and ships them as per-batch deltas; a closed stream sends one final batch", () => {
    const h = harness({ stream_max_pending_rows: 2 });
    const s = open(h);
    h.reg.emit(s, [1, 1]);
    h.reg.emit(s, [2, 2]);
    expect(h.reg.emit(s, [3, 3])).toBe(false);
    h.reg.drop(s, "rate_limit", 2);
    h.reg.close(s);
    expect(batches(h)).toEqual([
      expect.objectContaining({ n: 2, final: true, dropped: { buffer_full: 1, rate_limit: 2 } }),
    ]);
    expect(h.reg.emit(s, [4, 4])).toBe(false);
    expect(h.reg.info(s)).toMatchObject({ state: "closed", dropped: { buffer_full: 1, rate_limit: 2, stopped: 1 } });
    h.reg.close(s);
    h.reg.flushAll({ final: true });
    expect(batches(h)).toHaveLength(1);
  });

  it("sends drop-only batches at most once per second, and empty final batches", () => {
    const h = harness();
    h.now = 10_000;
    const s = open(h);
    h.reg.drop(s, "per_api_cap");
    h.reg.flushAll();
    expect(batches(h)).toHaveLength(1); // no batch yet on this stream → the drop-only batch is due at once
    h.reg.drop(s, "per_api_cap");
    h.now = 10_900;
    h.reg.flushAll();
    expect(batches(h)).toHaveLength(1);
    h.now = 11_000;
    h.reg.flushAll();
    expect(batches(h).map((b) => [b.n, b.dropped])).toEqual([
      [0, { per_api_cap: 1 }],
      [0, { per_api_cap: 1 }],
    ]);
    h.reg.flushAll({ final: true });
    expect(batches(h).at(-1)).toMatchObject({ n: 0, final: true, dropped: {} });
    expect(s.state).toBe("closed");
  });

  it("assembles binary batches from whole-record chunks", () => {
    const h = harness({ batch_max_bin_bytes: 64 });
    const s = open(h, { kind: "block-span/1", enc: "bin", layout: "block-span/1", recBytes: 16 });
    const chunk = (n: number, g: number) => ({ bytes: new Uint8Array(16 * n).fill(g), n, g0: g, g1: g, t0: g, t1: g });
    h.reg.emitBin(s, chunk(2, 1));
    h.reg.emitBin(s, chunk(1, 2));
    h.reg.flushStream(s, false);
    const b = h.sent[0]!;
    expect(b.m).toMatchObject({ enc: "bin", layout: "block-span/1", rec_bytes: 16, n: 3, g0: 1, g1: 2 });
    expect(b.data?.byteLength).toBe(48);
    h.reg.emitBin(s, chunk(4, 3)); // 64 bytes ≥ batch_max_bin_bytes → immediate
    expect(h.sent).toHaveLength(2);
    expect(h.reg.flow.sentBytes).toBe(48 + 64);
  });

  it("sheds non-system rows while the host lags, with notices on both transitions", () => {
    const h = harness({ flow_high_water_bytes: 100, flow_low_water_bytes: 10 });
    const s = open(h);
    const sys = open(h, { id: "s:exceptions", instrument: null, kind: "exception/1", system: true });
    for (let i = 0; i < 12; i++) h.reg.emit(s, [i, i, "0x1"]);
    h.reg.flushAll();
    expect(h.reg.flow.shedding).toBe(true);
    expect(h.sent.find((x) => x.m.bea === "notice")?.m).toMatchObject({ code: "flow-shedding-on" });
    expect(h.reg.emit(s, [99, 99])).toBe(false);
    expect(h.reg.emit(sys, [1, 1])).toBe(true);
    expect(h.reg.flow.shedRows).toBe(1);
    h.reg.onFlowPost(h.reg.flow.sentBytes);
    expect(h.reg.flow.shedding).toBe(false);
    expect(h.sent.filter((x) => x.m.bea === "notice").map((x) => (x.m as NoticeMessage).code)).toEqual([
      "flow-shedding-on",
      "flow-shedding-off",
    ]);
    // the flow unit is estimateBytes of every sent row (what the host's flowTracker mirrors)
    expect(h.reg.flow.sentBytes).toBe(12 * estimateBytes([0, 0, "0x1"]));
  });

  it("refuses streams beyond max_streams", () => {
    const h = harness({ max_streams: 2 });
    open(h);
    open(h);
    expect(h.reg.open({ instrument: "h3", kind: "hook/1", enc: "json" })).toMatchObject({
      _tag: "ResourceLimit",
      resource: "streams",
      limit: 2,
    });
  });
});
