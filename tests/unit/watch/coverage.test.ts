import { describe, expect, it } from "vitest";

import {
  buildStalkerCoverage,
  drcovBytes,
  modoffText,
  parseCoverageBlob,
  type CoverageModuleFacts,
} from "../../../src/application/watch/coverage.js";
import { envelopeOf } from "../../../src/application/watch/envelope.js";
import type { BeaEvidence } from "../../../src/domain/evidence/record.js";
import type { JsonValue } from "../../../src/domain/json.js";
import { parseDrcov } from "../../support/drcov.js";

const MODULES: CoverageModuleFacts[] = [
  {
    name: "msvcrt.dll",
    path: "C:\\Windows\\System32\\msvcrt.dll",
    base: 0x7ffa00000000n,
    size: 0x100000,
    fileSha256: null,
    preferredBase: null,
    entryRva: null,
    timestamp: null,
  },
  {
    name: "game_sim.exe",
    path: "C:\\fx\\game sim, v1\\game_sim.exe",
    base: 0x7ff700000000n,
    size: 0x1e000,
    fileSha256: "a".repeat(64),
    preferredBase: 0x140000000n,
    entryRva: 0x14e0,
    timestamp: 0x6543210f,
  },
];

const blob = () =>
  buildStalkerCoverage(
    { sessionId: "s", evidenceId: null, threads: [42] },
    MODULES,
    [
      { va: 0x7ff7000017a5n, size: 25, hits: 3 },
      { va: 0x7ff7000017a0n, size: 5, hits: 3 },
      { va: 0x7ffa00008d20n, size: 70, hits: 6 },
      { va: 0x7ff7000017a5n, size: 30, hits: 1 },
      { va: 0x1000n, size: 4, hits: 1 },
    ],
    false,
  );

describe("bea.coverage/1 for Stalker traces (S5 §11.4)", () => {
  it("is module-relative, sorted by base and rva, merges recompiled blocks and keeps the rest unattributed", () => {
    const b = blob();
    expect(b.modules.map((m) => [m.id, m.name, m.base])).toEqual([
      [0, "game_sim.exe", "0x7ff700000000"],
      [1, "msvcrt.dll", "0x7ffa00000000"],
    ]);
    expect(b.modules[0]).toMatchObject({ preferred_base: "0x140000000", entry_rva: "0x14e0", timestamp: 0x6543210f });
    expect(b.blocks).toEqual([
      [0, 0x17a0, 5, 3],
      [0, 0x17a5, 30, 4],
      [1, 0x8d20, 70, 6],
    ]);
    expect(b.unattributed).toEqual([["0x1000", 4, 1]]);
    expect(b.totals).toEqual({ distinct_blocks: 3, executions: 14, truncated: false });
    expect(b.source).toEqual({
      kind: "stalker",
      granularity: "stalker-block",
      session_id: "s",
      evidence_id: null,
      thread_ids: [42],
    });
    expect(parseCoverageBlob(JSON.parse(JSON.stringify(b)))).not.toBeNull();
    expect(parseCoverageBlob({ schema: "bea.coverage/2" })).toBeNull();
  });
});

describe("drcov and modoff exports (S6 §4.27)", () => {
  it("writes drcov v2 that the independent reader parses back to the same blocks", () => {
    const b = blob();
    const parsed = parseDrcov(drcovBytes(b));
    expect(parsed.version).toBe(2);
    expect(parsed.flavor).toBe("drcov");
    expect(parsed.moduleTableVersion).toBe(2);
    expect(parsed.columns).toEqual(["id", "base", "end", "entry", "checksum", "timestamp", "path"]);
    expect(parsed.modules.map((m) => [m.id, m.base, m.end, m.entry, m.timestamp, m.path])).toEqual([
      [0, 0x7ff700000000n, 0x7ff70001e000n, 0x7ff7000014e0n, 0x6543210f, "C:\\fx\\game sim, v1\\game_sim.exe"],
      [1, 0x7ffa00000000n, 0x7ffa00100000n, 0n, 0, "C:\\Windows\\System32\\msvcrt.dll"],
    ]);
    expect(parsed.blocks).toEqual([
      { start: 0x17a0, size: 5, moduleId: 0 },
      { start: 0x17a5, size: 30, moduleId: 0 },
      { start: 0x8d20, size: 70, moduleId: 1 },
    ]);
  });

  it("writes one module+0xRVA line per block", () => {
    expect(modoffText(blob())).toBe("game_sim.exe+0x17a0\ngame_sim.exe+0x17a5\nmsvcrt.dll+0x8d20\n");
  });

  it("caps block sizes at the u16 drcov field", () => {
    const big = buildStalkerCoverage(
      { sessionId: "s", evidenceId: null, threads: [] },
      MODULES,
      [{ va: 0x7ff700001000n, size: 70_000, hits: 1 }],
      false,
    );
    expect(parseDrcov(drcovBytes(big)).blocks[0]?.size).toBe(65_535);
  });
});

describe("recorded envelope (S2 §8.1)", () => {
  const record = {
    schema: "bea.evidence/1",
    evidence_id: `ev_${"1".repeat(64)}`,
    predicate_type: "bea.instrument.install",
    operation: "watch_memory",
    parameters: {},
    subject: { kind: "process-instance", instance_id: `pi_${"2".repeat(64)}`, module_map_id: `mm_${"3".repeat(64)}` },
    observed_at: {
      run_id: "run_20260101T000000Z_0000000000000001",
      seq: 7,
      mono_ns: "1",
      wall: "2026-01-01T00:00:00.000Z",
      effect_epoch: 2,
      module_map_epoch: 1,
    },
    provider: { id: "frida", name: "bea-agent", version: null },
    agent: null,
    confidence: "observed",
    authority: "live-process",
    perturbation: { level: "passive", active_effect_ids: [`fx_${"4".repeat(64)}`], tainted_by: [] },
    result: {},
    raw_result: null,
    blobs: [],
    coverage: { status: "complete", truncated: false, reasons: [] },
    limitations: ["A"],
    locations: [],
    evidence_links: [],
    external_refs: [],
    effects: [`fx_${"4".repeat(64)}`],
    redactions: [],
    untrusted: true,
  } as unknown as BeaEvidence<JsonValue>;

  it("projects the record and merges delivery-time coverage and limitations", () => {
    const env = envelopeOf(
      { record, outcome: "added" },
      { coverage: [{ status: "partial", truncated: false, reasons: ["watch_rate_limit"] }], limitations: ["B", "A"] },
    );
    expect(env).toEqual({
      evidence_id: record.evidence_id,
      predicate_type: "bea.instrument.install",
      confidence: "observed",
      authority: "live-process",
      coverage: { status: "partial", truncated: false, reasons: ["watch_rate_limit"] },
      limitations: ["A", "B"],
      instance_id: `pi_${"2".repeat(64)}`,
      module_map_id: `mm_${"3".repeat(64)}`,
      observed_at: { seq: 7, effect_epoch: 2, module_map_epoch: 1 },
      perturbation: { level: "passive", active_effect_ids: [`fx_${"4".repeat(64)}`], tainted: false },
      effects_applied: [`fx_${"4".repeat(64)}`],
    });
    expect(envelopeOf({ record, outcome: "added" }).coverage.status).toBe("complete");
  });
});
