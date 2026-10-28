import { describe, expect, it } from "vitest";

import { buildCoverageBlob } from "../../../src/application/emu/coverageBlob.js";
import { assessEmulation, deviationSentence } from "../../../src/application/emu/deviations.js";
import { afterDigest, baselineDigest, LineageStore, queryId } from "../../../src/application/emu/lineage.js";
import type { DeviationKind } from "../../../src/domain/emuProtocol.js";
import { coverageSchema, REASONS } from "../../../src/domain/evidence/coverage.js";
import { CORE_LIMITATIONS, LIMITATIONS } from "../../../src/domain/evidence/limitations.js";
import { EMULATION_LIMITATIONS } from "../../../src/domain/evidence/limitations/emulation.js";

const KINDS: readonly DeviationKind[] = [
  "tls_callbacks_not_run",
  "entry_point_not_run",
  "imports_hle_bound",
  "no_seh_dispatch",
  "delay_imports_present",
  "managed_image",
  "isa_guard_off",
  "isa_guard_incomplete",
  "x87_tagging_incomplete",
  "fp_status_tagging_incomplete",
  "iat_rebound",
  "teb_stack_bounds_rewritten",
  "memory_patched",
  "synthetic_teb",
  "synthetic_kuser_shared_data",
  "malformed_directory",
  "engine_unvalidated",
  "x87_transcendental_inexact",
  "inexact_import_model",
  "unhandled_import_returned_zero",
  "auto_mapped_zero_pages",
  "fp_status_flags_unmodeled",
  "cpuid_executed",
  "virtualized_tsc",
  "nondeterministic_tsc",
  "nondeterministic_rng",
  "dynamic_import_resolved",
  "self_modifying_code",
  "isa_overlay_overwritten",
  "bridge_restarted_state_reset",
];

describe("emulation limitations and coverage (S5 §11.5)", () => {
  it("has a fixed sentence for every deviation kind, all registered", () => {
    const registered = new Set<unknown>(Object.values(LIMITATIONS).filter((v) => typeof v === "string"));
    for (const kind of KINDS) {
      const sentence = deviationSentence({ kind, count: 2, detail: { lost_snapshots: ["a", "b"] } });
      expect(sentence, kind).not.toBeNull();
      expect(sentence?.length ?? 0, kind).toBeGreaterThan(20);
      expect(sentence, kind).not.toContain("{");
    }
    expect(registered.has(EMULATION_LIMITATIONS.EMU_X87_INEXACT)).toBe(true);
    expect(
      deviationSentence({ kind: "bridge_restarted_state_reset", detail: { lost_snapshots: ["n1", "n2"] } }),
    ).toContain("2 named");
  });

  it("keeps exact HLE runs complete and marks substitutions partial", () => {
    const exact = assessEmulation({ deviations: [{ kind: "imports_hle_bound" }, { kind: "entry_point_not_run" }] });
    expect(exact.coverage).toEqual({ status: "complete", truncated: false, reasons: [] });
    expect(exact.limitations).toContain(CORE_LIMITATIONS.EMU_HLE_IMPORTS);
    expect(exact.limitations).toContain(CORE_LIMITATIONS.NOT_REAL_PROCESS);
    const inexact = assessEmulation({ deviations: [{ kind: "inexact_import_model", count: 3 }] });
    expect(inexact.coverage).toMatchObject({ status: "partial", reasons: ["hle_imports_used"] });
    expect(inexact.limitations.join(" ")).toContain("3 import(s)");
    const models = assessEmulation({ deviations: [], importModels: ["builtin", "override"] });
    expect(models.coverage.status).toBe("partial");
    const x87 = assessEmulation({ deviations: [{ kind: "x87_transcendental_inexact" }] });
    expect(x87.coverage.reasons).toEqual(["emulation_deviation"]);
  });

  it("marks harness stops, ISA-guard stops and early ends", () => {
    const run = assessEmulation({
      deviations: [],
      harnessStops: 3,
      isaStops: 1,
      endedEarly: "deadline",
      deterministic: false,
      traceTruncated: 200,
    });
    expect(run.coverage.status).toBe("partial");
    expect(run.coverage.truncated).toBe(true);
    expect([...run.coverage.reasons]).toEqual(["deadline", "emulation_deviation", "isa_guard_stop", "row_cap"]);
    for (const reason of run.coverage.reasons) expect(Object.keys(REASONS)).toContain(reason);
    expect(coverageSchema.safeParse(run.coverage).success).toBe(true);
    expect(run.limitations.join(" ")).toContain("3 vector(s) stopped");
    expect(run.limitations).toContain(CORE_LIMITATIONS.ENDED_EARLY("deadline"));
    expect(run.limitations).toContain(EMULATION_LIMITATIONS.EMU_NONDETERMINISTIC);
  });
});

describe("bea.coverage/1 builder (S5 §11.4)", () => {
  it("attributes translation blocks to modules, sorts, clamps sizes and drops the synthetic window", () => {
    const blob = buildCoverageBlob({
      wire: {
        granularity: "tb",
        blocks: [
          ["0x180001020", 8, 1],
          ["0x180001000", 70_000, 3],
          ["0x7ff000000100", 4, 2],
          ["0x1000", 4, 9],
          ["0x7ffa00001000", 12, 5],
        ],
        distinct: 5,
        truncated: false,
      },
      modules: [
        {
          name: "ntdll.dll",
          path: "C:\\Windows\\System32\\ntdll.dll",
          sha256: null,
          base: "0x7ffa00000000",
          size: 0x200000,
          preferredBase: "0x180000000",
          primary: false,
        },
        {
          name: "mathlib.dll",
          path: "C:\\lab\\mathlib.dll",
          sha256: "ab".repeat(32),
          base: "0x180000000",
          size: 0x10000,
          preferredBase: "0x180000000",
          primary: true,
        },
      ],
      addressSpace: "emulation-image",
      sessionId: "s",
      evidenceId: null,
      vectors: 2,
      syntheticBase: "0x7ff000000000",
    });
    expect(blob.modules.map((m) => m.name)).toEqual(["mathlib.dll", "ntdll.dll"]);
    expect(blob.blocks).toEqual([
      [0, 0x1000, 0xffff, 3],
      [0, 0x1020, 8, 1],
      [1, 0x1000, 12, 5],
    ]);
    expect(blob.unattributed).toEqual([["0x1000", 4, 9]]);
    expect(blob.totals).toEqual({ distinct_blocks: 4, executions: 18, truncated: false });
    expect(blob.source).toMatchObject({
      kind: "emulation",
      engine: "unicorn",
      granularity: "translation-block",
      vectors: 2,
    });
  });
});

describe("state lineage (S5 §11.2)", () => {
  const base = {
    source: { kind: "image" as const, sha256: "ab".repeat(32), mappedBase: "0x180000000" },
    open: { protections: "sections" },
    bridge: { protocol: "bea-emu/0.1", version: "0.1.0" },
    engines: { unicorn: "2.1.4", capstone: "5.0.9", pefile: "2024.8.26" },
  };
  const op = {
    method: "emu.batch" as const,
    planDigest: "p",
    vectorsDigest: "v",
    slice: { offset: 0, count: 2 },
    writesDigest: "w",
    optionsDigest: "o",
    isolation: "snapshot" as const,
  };

  it("derives deterministic digests (nonce only for non-deterministic runs)", () => {
    const baseline = baselineDigest(base);
    expect(baseline).toMatch(/^es_[a-f0-9]{64}$/u);
    expect(baselineDigest(base)).toBe(baseline);
    expect(baselineDigest({ ...base, open: { protections: "rwx" } })).not.toBe(baseline);
    expect(afterDigest(baseline, op, null)).toBe(afterDigest(baseline, op, null));
    expect(afterDigest(baseline, op, "n1")).not.toBe(afterDigest(baseline, op, "n2"));
    const id = queryId({
      initialState: baseline,
      imageSha256: "ab".repeat(32),
      rva: "0x1000",
      planDigest: "p",
      vectorsDigest: "v",
      optionsDigest: "o",
    });
    expect(id).toMatch(/^[a-f0-9]{64}$/u);
  });

  it("resets current and the named snapshots when the bridge generation changes", () => {
    const store = new LineageStore();
    const baseline = baselineDigest(base);
    const record = store.add(
      {
        sessionId: "s1",
        source: "image",
        imageSha256: "ab".repeat(32),
        configDigest: "cd".repeat(32),
        bundleId: null,
        producerInstance: null,
        sessionEvidence: null,
        fp: { mxcsr: 0x1f80, fpcw: 0x27f, source: "windows-default" },
        faultPolicy: "stop",
        syntheticBase: null,
        engineUnvalidated: false,
        baseline,
      },
      0,
    );
    record.current = afterDigest(baseline, op, null);
    record.currentIsBaseline = false;
    record.named.set("n", record.current);
    expect(store.get("s1", 0)?.named.size).toBe(1);
    const restarted = store.get("s1", 1);
    expect(restarted?.current).toBe(baseline);
    expect(restarted?.currentIsBaseline).toBe(true);
    expect(restarted?.named.size).toBe(0);
    store.prune(() => false);
    expect(store.size).toBe(0);
  });
});
