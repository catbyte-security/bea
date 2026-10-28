import { afterEach, describe, expect, it } from "vitest";

import { LedgerRecordingRegistry } from "../../../src/application/instruments/RecordingRegistry.js";
import { manualClock } from "../../../src/domain/clock.js";
import { sequentialIdSource } from "../../../src/domain/canonical.js";
import { Deadline } from "../../../src/domain/deadline.js";
import type { JsonValue } from "../../../src/domain/json.js";
import { silentLogger } from "../../../src/domain/logger.js";
import { NO_LITERALS } from "../../../src/domain/redaction/literals.js";
import type { StreamWriter } from "../../../src/ports/evidence.js";
import type { EventRecord, RecordingCreate, RecordingKindSpec } from "../../../src/ports/recordings.js";
import type { OperationContext } from "../../../src/ports/sessions.js";
import { makeRuntime, observation, type RuntimeFixture } from "./support.js";

let fx: RuntimeFixture | undefined;
afterEach(async () => {
  await fx?.cleanup();
  fx = undefined;
});

/** Test kind: rows are [n] tuples; the summary sums n. */
const SUM_KIND: RecordingKindSpec<{ total: number; count: number }> = {
  kind: "hook",
  rowKinds: ["hook/1"],
  fields: [{ name: "n", type: "int" }],
  decode: (record, ctx) => [
    {
      seq: record.seq,
      n: (record.fields as number[])[0] ?? 0,
      frame: ctx.frame("game.exe+0x10").at ?? null,
    } as EventRecord,
  ],
  summary: {
    init: () => ({ total: 0, count: 0 }),
    add: (state, event) => {
      state.total += Number(event["n"]);
      state.count += 1;
    },
    finish: (state) => ({ total: state.total, count: state.count }),
  },
};

const op = (): OperationContext => ({
  opId: 1,
  name: "query_events",
  signal: new AbortController().signal,
  deadline: Deadline.after(10_000),
});

const setup = async (flush?: (s: AbortSignal) => Promise<void>) => {
  fx = await makeRuntime();
  const r = await fx.runtime.instances.register(await observation(fx.home));
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  const instance = r.value.instance.instance_id;
  const stream = await fx.runtime.streams.open({
    source: { kind: "hook", instance_id: instance, effect_id: null, channel: "s1" },
    encoding: { kind: "json-rows", row_kind: "hook/1" },
    decoders: null,
    literals: NO_LITERALS,
    ...(flush === undefined ? {} : { flush }),
  });
  if (!stream.ok) throw new Error("stream");
  const clock = manualClock();
  const registry = new LedgerRecordingRegistry({
    evidence: fx.runtime,
    ids: sequentialIdSource(),
    clock,
    logger: silentLogger,
    kinds: {
      hook: SUM_KIND as RecordingKindSpec,
      api: null,
      watch: null,
      poll: null,
      trace: null,
      override: null,
      exceptions: null,
      output: null,
      modules: null,
    },
  });
  return { registry, writer: stream.value, clock };
};

const create = (writer: StreamWriter, extra: Partial<RecordingCreate> = {}): RecordingCreate => ({
  sessionId: "00000000-0000-4000-8000-000000000001",
  kind: "hook",
  agentInstrumentId: "h1",
  agentStream: "s1",
  streamId: writer.stream_id,
  effectId: null,
  durationMs: 10_000,
  maxEvents: 100,
  startsAtResume: false,
  decoders: null,
  ...extra,
});

const rows = (values: readonly number[]): Uint8Array =>
  new TextEncoder().encode(values.map((v) => `${JSON.stringify([v])}\n`).join(""));

describe("recording registry (S6 §2.5, CI-I3, CI-I13)", () => {
  it("hands out rec_ handles and counts duration from install or from resume", async () => {
    const { registry, writer, clock } = await setup();
    const now = registry.create(create(writer));
    const paused = registry.create(create(writer, { startsAtResume: true }));
    expect(now.id).toMatch(/^rec_[0-9a-f]{8}$/u);
    expect(paused.id).not.toBe(now.id);
    clock.advanceMs(4000);
    expect(now.view().ends_in_ms).toBe(6000);
    expect(paused.view().ends_in_ms).toBe(10_000);
    registry.onResumed(create(writer).sessionId);
    clock.advanceMs(1000);
    expect(paused.view().ends_in_ms).toBe(9000);
    expect(registry.list(create(writer).sessionId).map((r) => r.id)).toEqual([now.id, paused.id]);
    expect(registry.get("rec_ffffffff")).toBeUndefined();
  });

  it("decodes events through the kind after the flush barrier and finalizes a summary on end", async () => {
    let flushes = 0;
    const { registry, writer } = await setup(async () => {
      flushes += 1;
    });
    const recording = registry.create(create(writer));
    writer.append({ first_seq: 1, count: 3, dropped_before: 0, module_map_epoch: 1 }, rows([1, 2, 3]));
    writer.append({ first_seq: 6, count: 1, dropped_before: 2, module_map_epoch: 1 }, rows([10]));
    const events: EventRecord[] = [];
    for await (const e of registry.events(recording.id, { from_seq: 2 }, op())) events.push(e);
    expect(events.map((e) => [e.seq, e["n"], e["frame"]])).toEqual([
      [2, 2, "game.exe+0x10"],
      [3, 3, "game.exe+0x10"],
      [6, 10, "game.exe+0x10"],
    ]);
    expect(flushes).toBe(1);
    const ended = await registry.end(recording.id, "stopped", op());
    if (!ended.ok) throw new Error("end");
    expect(ended.value).toMatchObject({
      state: "finished",
      end_reason: "stopped",
      events: 4,
      dropped: 2,
      ends_in_ms: null,
      summary: { total: 16, count: 4 },
    });
    const again = await registry.end(recording.id, "duration", op());
    expect(again.ok && again.value.end_reason).toBe("stopped");
    const summary = await registry.summary(recording.id, op());
    expect(summary.ok && (summary.value as Record<string, JsonValue>)["total"]).toBe(16);
  });

  it("places a bare VA frame (the hook row's raw caller) in the instance's module map, with the static form of prepared modules (UX-10)", async () => {
    const { writer } = await setup();
    const frames: { at: string | null; static: string | null }[] = [];
    const FRAME_KIND: RecordingKindSpec<null> = {
      ...(SUM_KIND as unknown as RecordingKindSpec<null>),
      decode: (record, ctx) => {
        for (const va of [
          "0x140001234",
          "0x7ffc00000010",
          "0x12345",
          "game.exe+0x10",
          "game_sim.exe+0x10",
          "game_sim.exe+0x30000",
        ])
          frames.push(ctx.frame(va));
        return [{ seq: record.seq } as EventRecord];
      },
      summary: { init: () => null, add: () => undefined, finish: () => ({}) },
    };
    const registry = new LedgerRecordingRegistry({
      evidence: (fx as RuntimeFixture).runtime,
      ids: sequentialIdSource(),
      clock: manualClock(),
      logger: silentLogger,
      kinds: {
        hook: FRAME_KIND as RecordingKindSpec,
        api: null,
        watch: null,
        poll: null,
        trace: null,
        override: null,
        exceptions: null,
        output: null,
        modules: null,
      },
      // the main image was prepared (preferred base 0x180000000); ntdll was not
      staticBase: (path) => (path.toLowerCase().endsWith("game_sim.exe") ? 0x180000000n : null),
    });
    const recording = registry.create(create(writer));
    writer.append({ first_seq: 1, count: 1, dropped_before: 0, module_map_epoch: 1 }, rows([1]));
    for await (const _ of registry.events(recording.id, {}, op())) void _;
    // observation(): game_sim.exe at 0x140000000 (0x20000 bytes) and ntdll.dll at 0x7ffc00000000
    expect(frames).toEqual([
      { at: "game_sim.exe+0x1234", static: "game_sim.exe:0x180001234" },
      { at: "ntdll.dll+0x10", static: null },
      { at: null, static: null },
      { at: "game.exe+0x10", static: null },
      { at: "game_sim.exe+0x10", static: "game_sim.exe:0x180000010" },
      { at: "game_sim.exe+0x30000", static: null },
    ]);
  });

  it("answers reference_not_found for unknown recordings", async () => {
    const { registry } = await setup();
    const summary = await registry.summary("rec_00000999", op());
    expect(summary.ok || summary.error._tag).toBe("ReferenceNotFound");
    await expect(async () => {
      for await (const e of registry.events("rec_00000999", {}, op())) void e;
    }).rejects.toMatchObject({ _tag: "ReferenceNotFound" });
  });
});
