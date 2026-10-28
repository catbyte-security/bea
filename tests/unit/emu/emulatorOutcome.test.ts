import { describe, expect, it } from "vitest";

import { emulatorOutcome, OUTPUT_ARRAY_INLINE_CAP, outputsOf } from "../../../src/application/emu/views.js";
import type { FieldType } from "../../../src/domain/callModel/normalize.js";
import { classifyWin64 } from "../../../src/domain/callModel/classify.js";
import type { BatchResult } from "../../../src/domain/emuProtocol.js";

/**
 * Review fix EMU-9: the bridge details only the first 1000 non-returned vectors of a batch. Vectors past that must
 * never be re-attributed to the TARGET by status alone (a harness fault on synthetic or uncaptured memory has status
 * "fault" too): that turned emulator capture gaps into outcome-class "differ" verdicts in diff_function.
 */
const plan = (() => {
  const r = classifyWin64({
    signature: { args: [{ type: "u32" }], returns: "u32", variadic: false },
    buffers: [],
    supplied: new Set(),
  });
  if (!r.ok) throw new Error("classify");
  return r.value.plan;
})();

const batchOf = (n: number, detailed: number, columns: Partial<BatchResult["columns"]> = {}): BatchResult =>
  ({
    summary: {
      offset: 0,
      vectors: n,
      completed: n,
      returned: 0,
      byStatus: { fault: n },
      byAttribution: { target: 0, harness: n },
      elapsedMs: 1,
      callsPerSecond: null,
      isolation: "snapshot",
      from: "baseline",
      path: "fast",
      deterministic: true,
      deadlineReached: false,
      cancelled: false,
    },
    columns: {
      status: Array.from({ length: n }, () => "fault"),
      rax: Array.from({ length: n }, () => "0x0"),
      xmm0lo: Array.from({ length: n }, () => "0x0"),
      out: {},
      ...columns,
    },
    faults: Array.from({ length: detailed }, (_, index) => ({
      index,
      status: "fault",
      attribution: "harness",
      cause: "synthetic_unmapped",
      pc: "0x180001010",
      pcRva: "0x1010",
    })),
    aggregates: { imports: {}, deviations: {} },
  }) as unknown as BatchResult;

describe("single-call outputs (EMU-11)", () => {
  it("caps array outputs at 256 elements and flags the truncation", () => {
    const cells = Array.from({ length: 2000 }, (): `0x${string}` => "0x3f800000");
    const outcome = {
      count: 1,
      offset: 0,
      status: ["returned"],
      attribution: [null],
      ret: null,
      fields: { "b.pad": [cells], "b.pos": [["0x0", "0x0", "0x0"]] },
      faults: [],
      fp_after: { mxcsr_control: [], fpcw: [] },
    } as unknown as Parameters<typeof outputsOf>[0];
    const types = new Map<string, FieldType>([
      ["b.pad", "f32[]"],
      ["b.pos", "f32[]"],
    ]);
    const notes = { truncatedValues: false };
    const out = outputsOf(outcome, types, 0, notes);
    expect((out["b.pad"] as unknown[]).length).toBe(OUTPUT_ARRAY_INLINE_CAP);
    expect((out["b.pos"] as unknown[]).length).toBe(3);
    expect(notes.truncatedValues).toBe(true);
    const small = { truncatedValues: false };
    outputsOf({ ...outcome, fields: { "b.pos": [["0x0"]] } }, types, 0, small);
    expect(small.truncatedValues).toBe(false);
  });
});

describe("emulatorOutcome beyond the bridge's fault-detail cap (EMU-9)", () => {
  it("never attributes an undetailed stop to the target", () => {
    const outcome = emulatorOutcome(plan, new Map(), batchOf(1200, 1000));
    expect(outcome.attribution.filter((a) => a === "target")).toHaveLength(0);
    expect(outcome.attribution.filter((a) => a === "harness")).toHaveLength(1200);
    const undetailed = outcome.faults.filter((f) => f.cause === "no_fault_detail");
    expect(undetailed).toHaveLength(200);
    expect(undetailed[0]).toMatchObject({ index: 1000, attribution: "harness", site: { rva: null } });
  });

  it("uses the bridge's per-vector attribution column when it has one", () => {
    const attr = Array.from({ length: 1200 }, (_, k) => (k % 2 === 0 ? "h" : "t"));
    const pcRva = Array.from({ length: 1200 }, () => "0x1010");
    const outcome = emulatorOutcome(plan, new Map(), batchOf(1200, 1000, { attr, pcRva } as never));
    const tail = outcome.attribution.slice(1000);
    expect(tail.filter((a) => a === "target")).toHaveLength(100);
    expect(outcome.faults.find((f) => f.index === 1001)).toMatchObject({
      attribution: "target",
      site: { rva: "0x1010" },
    });
  });
});
