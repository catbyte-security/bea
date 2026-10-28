import { describe, expect, it } from "vitest";

import { POLL_KIND } from "../../../src/application/instruments/kinds/poll.js";
import { TRACE_KIND } from "../../../src/application/instruments/kinds/trace.js";
import { WATCH_KIND } from "../../../src/application/instruments/kinds/watch.js";
import { compactOf, locate, type LegendEntry } from "../../../src/application/watch/decoders.js";
import type { JsonValue } from "../../../src/domain/json.js";
import type { StreamRecord } from "../../../src/ports/evidence.js";
import type { DecodeContext, EventRecord, RecordingKindSpec } from "../../../src/ports/recordings.js";

const LEGEND: LegendEntry[] = [
  ["game_sim.exe", "0x7ff700000000", 0x1e000, "C:\\fx\\game_sim.exe"],
  ["msvcrt.dll", "0x7ffa00000000", 0x100000, "C:\\Windows\\System32\\msvcrt.dll"],
];
/** The registry's frame(): module+0xrva → at/static (preferred base 0x140000000 for the main module). */
const ctx = (decoders: JsonValue): DecodeContext => ({
  sessionId: "00000000-0000-4000-8000-000000000001",
  decoders,
  startedAtUs: 1_000_000,
  frame: (ref) => {
    const m = /^game_sim\.exe\+0x([0-9a-f]+)$/u.exec(ref);
    return m === null
      ? { at: ref.startsWith("0x") ? null : ref, static: null }
      : { at: ref, static: `game_sim.exe:0x${(0x140000000n + BigInt(`0x${m[1]}`)).toString(16)}` };
  },
});
const rec = (seq: number, fields: JsonValue): StreamRecord => ({ seq, module_map_epoch: 1, fields });
const decodeAll = <S>(spec: RecordingKindSpec<S>, records: StreamRecord[], c: DecodeContext): EventRecord[] =>
  records.flatMap((r) => [...spec.decode(r, c)]);
const summarize = <S>(spec: RecordingKindSpec<S>, events: EventRecord[]) => {
  const s = spec.summary.init();
  for (const e of events) spec.summary.add(s, e);
  return spec.summary.finish(s);
};

const WATCH_DECODERS = {
  v: 1,
  kind: "watch",
  method: "debug_register",
  view: "f32",
  size: 4,
  address: "0x2a000008",
  registers: ["rbx"],
  modules: LEGEND.map((e) => [...e]),
};
/** watch/1 tuple: the manifest speed writer `movss [rax+0x8], xmm0` at game_sim+0x17fb, trap-after. */
const hit = (g: number, tid: number, after: string, baseValue = "0x2a000000"): JsonValue => [
  g,
  1_000_000 + g * 16_000,
  tid,
  "w1",
  "w",
  "0x7ff7000017fb",
  "swept",
  "0x7ff700001800",
  "movss dword ptr [rax + 8], xmm0",
  "0x2a000008",
  "0000a041",
  after,
  { rax: baseValue, rbx: "0x5", rcx: "0x6" },
  null,
  { base: "rax", index: null, scale: 1, disp: 8, size: 4, base_value: baseValue, base_written: false },
];

describe("module legend", () => {
  it("locates addresses and builds compact forms", () => {
    expect(locate(LEGEND, 0x7ff7000017fbn)?.rva).toBe(0x17fbn);
    expect(locate(LEGEND, 0x1000n)).toBeNull();
    expect(compactOf(ctx({}), LEGEND, 0x7ff7000017fbn)).toEqual({
      va: "0x7ff7000017fb",
      at: "game_sim.exe+0x17fb",
      static: "game_sim.exe:0x1400017fb",
    });
    expect(compactOf(ctx({}), LEGEND, 0x1234n)).toEqual({ va: "0x1234", at: null, static: null });
  });
});

describe("watch kind (S6 §5.4 watch fields, §5.3 WatchSummary)", () => {
  it("decodes a debug-register hit with struct base, operand, value after and the requested registers", () => {
    const [event] = decodeAll(WATCH_KIND, [rec(1, hit(1, 100, "0000a841"))], ctx(WATCH_DECODERS));
    expect(event).toMatchObject({
      seq: 1,
      tid: 100,
      method: "debug_register",
      access: "w",
      insn: "game_sim.exe+0x17fb",
      insn_va: "0x7ff7000017fb",
      insn_static: "game_sim.exe:0x1400017fb",
      insn_confidence: "exact",
      operand: { base: "rax", index: null, scale: 1, disp: 8 },
      struct_base: "0x2a000000",
      disp: "0x8",
      value: 21,
      value_when: "after",
      rax: "0x2a000000",
      rbx: "0x5",
    });
    expect(event).not.toHaveProperty("rcx");
    expect(event?.["t_ms"]).toBe(16);
  });

  it("reports page-guard hits with the value before", () => {
    const [event] = decodeAll(
      WATCH_KIND,
      [rec(1, hit(1, 100, "0000a841"))],
      ctx({ ...WATCH_DECODERS, method: "page_guard" }),
    );
    expect(event).toMatchObject({ value: 20, value_when: "before", before: "0000a041", after: "0000a841" });
  });

  it("summarizes writers by count with threads, struct bases and values", () => {
    const records = [
      rec(1, hit(1, 100, "0000a841")),
      rec(2, hit(2, 100, "0000b041")),
      rec(3, hit(3, 200, "0000b041", "0x2b000000")),
    ];
    const summary = summarize(WATCH_KIND, decodeAll(WATCH_KIND, records, ctx(WATCH_DECODERS)));
    expect(summary).toMatchObject({
      hits: 3,
      method: "debug_register",
      writers_total: 1,
      writers: [
        {
          insn: {
            va: "0x7ff7000017fb",
            at: "game_sim.exe+0x17fb",
            static: "game_sim.exe:0x1400017fb",
            func: null,
            sym: null,
          },
          insn_confidence: "exact", // UX-10: the writer summary carries it (R1 step 6 checks it there)
          access: "w",
          count: 3,
          threads: [100, 200],
          struct_bases: [
            { base: "0x2a000000", disp: "0x8", count: 2 },
            { base: "0x2b000000", disp: "0x8", count: 1 },
          ],
          values: { first: 21, last: 22, distinct: 2 },
        },
      ],
    });
  });

  it("decodes malformed rows to nothing", () => {
    expect(decodeAll(WATCH_KIND, [rec(1, [1, 2, 3]), rec(2, { not: "a row" })], ctx(WATCH_DECODERS))).toEqual([]);
  });
});

describe("watch kind markers (CT-I4 rate valve, guard counters)", () => {
  it("turns marker rows into marker events and folds them into the summary", () => {
    const rate: JsonValue = [
      9,
      0,
      7,
      "w1",
      "r",
      null,
      "unknown",
      null,
      "bea:rate-limit",
      "0x2a000000",
      null,
      null,
      { limit_per_sec: "0x4e20", peak_per_sec: "0x7530" },
      null,
      null,
    ];
    const final: JsonValue = [
      10,
      0,
      7,
      "w1",
      "r",
      null,
      "unknown",
      null,
      "bea:watch-final",
      "0x2a000000",
      null,
      null,
      { bea_guard_suspended: "0x3", kernel_rearms: "0x0", rearm_fails: "0x0" },
      null,
      null,
    ];
    const events = decodeAll(
      WATCH_KIND,
      [rec(1, hit(1, 100, "0000a841")), rec(2, rate), rec(3, final)],
      ctx(WATCH_DECODERS),
    );
    expect(events[1]).toEqual({
      seq: 2,
      t_ms: 0,
      tid: 7,
      marker: "rate-limit",
      limit_per_sec: 20_000,
      peak_per_sec: 30_000,
    });
    const summary = summarize(WATCH_KIND, events);
    expect(summary["hits"]).toBe(1);
    // a marker without busy counters is a rate trip
    expect(summary["rate_limited"]).toEqual({
      cause: "rate",
      limit_per_sec: 20_000,
      peak_per_sec: 30_000,
      busy_pct: 0,
    });
    expect(summary["guard"]).toEqual({ bea_guard_suspended: 3, kernel_rearms: 0, rearm_fails: 0 });
  });

  it("tells a busy trip of the valve from a rate trip (handling held the target, the rate stayed under the limit)", () => {
    const busy: JsonValue = [
      9,
      0,
      7,
      "w1",
      "r",
      null,
      "unknown",
      null,
      "bea:rate-limit",
      "0x2a000000",
      null,
      null,
      { limit_per_sec: "0x4e20", peak_per_sec: "0x4652", busy_pct: "0x5d", busy_limit_pct: "0x32", busy_trip: "0x1" },
      null,
      null,
    ];
    const events = decodeAll(WATCH_KIND, [rec(1, hit(1, 100, "0000a841")), rec(2, busy)], ctx(WATCH_DECODERS));
    expect(events[1]).toMatchObject({ marker: "rate-limit", busy_pct: 93, busy_limit_pct: 50, busy_trip: 1 });
    expect(summarize(WATCH_KIND, events)["rate_limited"]).toEqual({
      cause: "busy",
      limit_per_sec: 20_000,
      peak_per_sec: 18_002,
      busy_pct: 93,
    });
  });
});

describe("poll kind (S6 §4.22 poll, §5.3 PollSummary)", () => {
  const POLL = { v: 1, kind: "poll", view: "f32", size: 128, address: "0x2a000000", interval_ms: 16 };
  it("splits a changed 8-byte cell into the changed view elements", () => {
    // cell 8: speed (+0x8) 20 → 21, throttle (+0xc) unchanged
    const events = decodeAll(POLL_KIND, [rec(1, [5, 1_016_000, 8, "0000a0410000003e", "0000a8410000003e"])], ctx(POLL));
    expect(events).toEqual([{ seq: 1, t_ms: 16, offset: "0x8", type: "f32", old: 20, new: 21 }]);
  });

  it("ranks changed offsets and tracks first/last/min/max", () => {
    const records = [
      rec(1, [1, 1_016_000, 8, "0000a04100000000", "0000a84100000000"]),
      rec(2, [2, 1_032_000, 16, "000000000000c843", "000000000000c843".replace("c843", "fa43")]),
      rec(3, [3, 1_032_000, 8, "0000a84100000000", "0000b04100000000"]),
    ];
    const summary = summarize(POLL_KIND, decodeAll(POLL_KIND, records, ctx(POLL)));
    expect(summary["samples"]).toBe(2);
    expect(summary["changes"]).toBe(3);
    expect(summary["fields"]).toEqual([
      { offset: "0x8", type: "f32", changes: 2, min: 20, max: 22, first: 20, last: 22 },
      { offset: "0x14", type: "f32", changes: 1, min: 400, max: 500, first: 400, last: 500 },
    ]);
  });
});

describe("trace kind (S6 §5.4 trace fields, §5.3 TraceSummary)", () => {
  const TRACE = {
    v: 1,
    kind: "trace",
    mode: "coverage",
    layout: "block-count/1",
    on_call: "0x7ff7000017a0",
    invocations: 1,
    threads: [],
    modules: LEGEND.map((e) => [...e]),
    instance_id: null,
  };
  it("decodes counted blocks, flags the on_call entry and counts invocations", () => {
    const records = [
      rec(1, { start: "0x7ff7000017a0", end: "0x7ff7000017a5", count: "3" }),
      rec(2, { start: "0x7ff7000017a5", end: "0x7ff7000017be", count: "3" }),
      rec(3, { start: "0x7ffa00008d20", end: "0x7ffa00008d66", count: "6" }),
      rec(4, { start: "0x7ff7000017a5", end: "0x7ff7000017be", count: "1" }),
    ];
    const events = decodeAll(TRACE_KIND, records, ctx(TRACE));
    expect(events[0]).toEqual({
      seq: 1,
      block: "game_sim.exe+0x17a0",
      va: "0x7ff7000017a0",
      size: 5,
      module: "game_sim.exe",
      hits: 3,
      entry: true,
    });
    expect(events[2]?.["module"]).toBe("msvcrt.dll");
    const summary = summarize(TRACE_KIND, events);
    expect(summary).toMatchObject({
      mode: "block_counts",
      invocations: 3,
      blocks: 3,
      executions: 13,
      modules: [
        { name: "game_sim.exe", blocks: 2 },
        { name: "msvcrt.dll", blocks: 1 },
      ],
      functions: [],
    });
  });

  it("decodes call edges and the calls-mode invocation self edge", () => {
    const calls = { ...TRACE, mode: "calls", layout: "call-site-count/1" };
    const records = [
      rec(1, [0x7ff7000017a0, 0x7ff7000017a0, 2]),
      rec(2, { site: "0x7ff700001010", target: "0x7ff7000017a0", count: "2" }),
      rec(3, { site: "0x7ff700001010", target: "0", count: "1" }),
    ];
    const events = decodeAll(TRACE_KIND, records, ctx(calls));
    expect(events[0]).toEqual({ seq: 1, invocations: 2, entry: "game_sim.exe+0x17a0" });
    expect(events[1]).toMatchObject({ from: "game_sim.exe+0x1010", to: "game_sim.exe+0x17a0", count: 2 });
    expect(events[2]).toMatchObject({ to: null, to_va: null });
    const summary = summarize(TRACE_KIND, events);
    expect(summary).toMatchObject({
      mode: "calls",
      invocations: 2,
      calls: [
        { from: "game_sim.exe+0x1010", to: "game_sim.exe+0x17a0", count: 2 },
        { to: null, count: 1 },
      ],
    });
  });

  it("decodes plain spans as coverage", () => {
    const spans = { ...TRACE, layout: "block-span/1", on_call: null };
    const events = decodeAll(TRACE_KIND, [rec(1, { start: "140701010007200", end: "140701010007210" })], ctx(spans));
    expect(events[0]).toMatchObject({ size: 10 });
    expect(summarize(TRACE_KIND, events)).toMatchObject({ mode: "coverage", blocks: 1 });
  });
});
