import { describe, expect, it } from "vitest";

import { WATCH_TOOLS } from "../../../src/contracts/areas/watch.js";
import { toolContract } from "../../../src/contracts/index.js";
import { WATCH_LIMITATIONS } from "../../../src/domain/evidence/limitations/watch.js";

const SESSION = "00000000-0000-4000-8000-000000000001";
const watch = toolContract("watch_memory");
const trace = toolContract("trace_execution");
const exportCov = toolContract("export_coverage");

const issues = (r: { success: boolean; error?: { issues: readonly { path: PropertyKey[]; message: string }[] } }) =>
  r.success ? [] : (r.error?.issues ?? []).map((i) => ({ path: i.path.join("."), message: i.message }));

describe("watch area contracts (DESIGN §6.2 G)", () => {
  it("registers the three tools with the catalog flags", () => {
    expect(WATCH_TOOLS.map((t) => t.name)).toEqual(["watch_memory", "trace_execution", "export_coverage"]);
    expect(watch.annotations).toEqual({
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    });
    expect(exportCov.effects.writesFilesystem).toBe(true);
    expect(exportCov.sessionKinds).toEqual(["none"]);
    expect(watch.evidence).toEqual({
      predicate: "bea.instrument.install",
      recorded: "always",
      identityExclude: ["wait_ms"],
    });
    expect(exportCov.evidence.predicate).toBe("bea.coverage.export");
    expect(watch.cli).toEqual({ tier: "instrument-oneshot", command: "watch", positional: ["address"] });
    expect(trace.cli).toEqual({ tier: "instrument-oneshot", command: "trace", positional: [] });
    expect(exportCov.cli.tier).toBe("scenario");
  });

  it("applies the S6 defaults", () => {
    expect(watch.inputSchema.parse({ session_id: SESSION, address: "0x10" })).toMatchObject({
      size: 4,
      access: "write",
      method: "auto",
      rate_limit_per_sec: 20_000,
      view: "hex",
      interval_ms: 16,
      registers: [],
      backtrace: 0,
      duration_ms: 10_000,
      max_events: 10_000,
      wait_ms: 0,
    });
    expect(trace.inputSchema.parse({ session_id: SESSION, thread_ids: [1] })).toMatchObject({
      mode: "coverage",
      invocations: 1,
      modules: ["$main"],
      max_events: 1_000_000,
    });
    expect(exportCov.inputSchema.parse({ recording_id: "rec_0000000a" })).toMatchObject({ format: "drcov" });
  });

  it("names the nearest valid debug-register size and refuses poll execute and misfit poll views", () => {
    const dr = watch.inputSchema.safeParse({ session_id: SESSION, address: "0x10", size: 3, method: "debug_register" });
    expect(issues(dr)).toEqual([
      { path: "size", message: "debug_register watches 1, 2, 4 or 8 bytes; use size 4 or method page_guard." },
    ]);
    const huge = watch.inputSchema.safeParse({
      session_id: SESSION,
      address: "0x10",
      size: 12,
      method: "debug_register",
    });
    expect(issues(huge)[0]?.message).toContain("use method page_guard");
    expect(
      watch.inputSchema.safeParse({
        session_id: SESSION,
        address: "0x10",
        size: 3,
        method: "debug_register",
        access: "execute",
      }).success,
    ).toBe(true);
    expect(
      issues(
        watch.inputSchema.safeParse({ session_id: SESSION, address: "0x10", method: "poll", access: "execute" }),
      )[0]?.path,
    ).toBe("access");
    expect(
      issues(
        watch.inputSchema.safeParse({ session_id: SESSION, address: "0x10", method: "poll", view: "f64", size: 12 }),
      )[0],
    ).toEqual({
      path: "size",
      message: "poll with view f64 needs a size that is a multiple of 8.",
    });
    expect(
      watch.inputSchema.safeParse({ session_id: SESSION, address: "0x10", method: "poll", view: "f32", size: 128 })
        .success,
    ).toBe(true);
  });

  it("requires exactly one trace target and exactly one export source", () => {
    expect(trace.inputSchema.safeParse({ session_id: SESSION }).success).toBe(false);
    expect(trace.inputSchema.safeParse({ session_id: SESSION, thread_ids: [1], on_call: "+0x10" }).success).toBe(false);
    expect(trace.inputSchema.safeParse({ session_id: SESSION, on_call: "game.exe!f" }).success).toBe(true);
    expect(exportCov.inputSchema.safeParse({}).success).toBe(false);
    expect(
      exportCov.inputSchema.safeParse({ recording_id: "rec_0000000a", evidence_id: `ev_${"0".repeat(64)}` }).success,
    ).toBe(false);
    expect(
      exportCov.inputSchema.safeParse({ evidence_id: `ev_${"0".repeat(64)}`, out_path: "relative.drcov" }).success,
    ).toBe(false);
  });

  it("keeps limitation keys WATCH_/TRACE_/COVERAGE_ and every template parameter BEA-controlled", () => {
    for (const [key, sentence] of Object.entries(WATCH_LIMITATIONS)) {
      expect(key).toMatch(/^(WATCH|TRACE|COVERAGE)_[A-Z0-9_]+$/u);
      const text = typeof sentence === "function" ? (sentence as (n: number) => string)(7) : sentence;
      expect(text.length).toBeGreaterThan(20);
      expect(text.length).toBeLessThan(300);
    }
  });
});
