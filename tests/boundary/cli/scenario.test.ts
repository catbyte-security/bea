import { EventEmitter } from "node:events";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { cancelled } from "../../../src/domain/errors/constructors.js";
import { err } from "../../../src/domain/result.js";
import { createFakeBackend, type FakeBackend } from "../../support/cli/fakeCatalog.js";
import { runCliInProcess, type CliRunResult } from "../../support/cli/harness.js";
import { createTempHome, type TempHome } from "../../support/workspace/tempHome.js";

let home: TempHome;
beforeEach(async () => {
  home = await createTempHome("cli-scenario");
});
afterEach(async () => {
  await home.cleanup();
});

const run = async (
  scenario: unknown,
  backend: FakeBackend,
  extra: {
    readonly argv?: readonly string[];
    readonly env?: Record<string, string>;
    readonly signals?: EventEmitter;
  } = {},
): Promise<CliRunResult> => {
  const file = join(home.work, "scenario.json");
  await writeFile(file, JSON.stringify(scenario));
  return runCliInProcess(["run", "scenario.json", "--json", ...(extra.argv ?? [])], {
    home,
    backend,
    ...(extra.env === undefined ? {} : { env: extra.env }),
    ...(extra.signals === undefined ? {} : { signals: extra.signals }),
  });
};

const spawnTarget = { spawn: { program: "C:/lab/behavior.exe", args: ["--out-dir", "C:/lab/out"] } };

describe("validation before any effect (S1 §7.5 step 2, D-INT-47)", () => {
  const cases: readonly [string, unknown, string][] = [
    ["unknown tool", { schema: "bea-scenario/1", steps: [{ tool: "no_such_tool" }] }, "scenario.steps[0].tool"],
    [
      "mcp-only tool",
      { schema: "bea-scenario/1", steps: [{ tool: "record_unknown", input: { question: "what is it?" } }] },
      "scenario.steps[0].tool",
    ],
    [
      "close_session is the teardown",
      { schema: "bea-scenario/1", target: spawnTarget, steps: [{ tool: "close_session" }] },
      "scenario.steps[0].tool",
    ],
    [
      "bad input without references",
      {
        schema: "bea-scenario/1",
        target: spawnTarget,
        steps: [{ tool: "read_memory", input: { address: "0x1", size: 0 } }],
      },
      "scenario.steps[0].input.size",
    ],
    [
      "reference to a later or unknown save_as",
      {
        schema: "bea-scenario/1",
        target: spawnTarget,
        steps: [
          { tool: "query_events", input: { recording_id: "${h.instrument.recording_id}" } },
          { tool: "hook_function", input: { address: "0x1" }, save_as: "h" },
        ],
      },
      "scenario.steps[0].input.recording_id",
    ],
    [
      "bad target input",
      { schema: "bea-scenario/1", target: { attach: { pid: 1, name: "x.exe" } }, steps: [{ tool: "resume_process" }] },
      "scenario.target.attach",
    ],
    [
      "save_as target is reserved",
      {
        schema: "bea-scenario/1",
        steps: [{ tool: "spawn_process", input: { program: "C:/a.exe" }, save_as: "target" }],
      },
      "scenario.steps[0].save_as",
    ],
    ["schema violation", { schema: "bea-scenario/2", steps: [] }, "scenario.schema"],
    [
      "session tool without a session",
      { schema: "bea-scenario/1", steps: [{ tool: "resume_process" }] },
      "scenario.steps[0].input.session_id",
    ],
  ];
  for (const [title, scenario, path] of cases)
    it(`${title} → exit 1, invalid_request, no handler ran`, async () => {
      const backend = createFakeBackend();
      const r = await run(scenario, backend);
      expect(r.code).toBe(1);
      const doc = r.doc() as { error: { code: string; details: { issues: { path: string }[] } } };
      expect(doc.error.code).toBe("invalid_request");
      expect(doc.error.details.issues.map((i) => i.path)).toContain(path);
      expect(backend.calls).toHaveLength(0);
    });
  it("a closed always gate → capability_unavailable before effects", async () => {
    await writeFile(join(home.work, "x.js"), "1");
    const backend = createFakeBackend();
    const r = await run(
      { schema: "bea-scenario/1", target: spawnTarget, steps: [{ tool: "run_script", input: { source: "send(1)" } }] },
      backend,
    );
    expect(r.code).toBe(1);
    expect(r.doc()).toMatchObject({ error: { code: "capability_unavailable", details: { gate: "run_script" } } });
    expect(backend.calls).toHaveLength(0);
    const open = await run(
      { schema: "bea-scenario/1", target: spawnTarget, steps: [{ tool: "run_script", input: { source: "send(1)" } }] },
      createFakeBackend(),
      { env: { BEA_ALLOW_RUN_SCRIPT: "1" } },
    );
    expect(open.code).toBe(0);
  });
});

describe("execution", () => {
  it("S6 §8.2 shape: target session injected, ${name.path} substituted, teardown closes the target", async () => {
    const backend = createFakeBackend();
    const r = await run(
      {
        schema: "bea-scenario/1",
        target: spawnTarget,
        steps: [
          { tool: "hook_function", input: { address: "behavior.exe+0x1000", duration_ms: 20000 }, save_as: "api" },
          { tool: "resume_process", input: { wait_ms: 250 } },
          { tool: "query_events", input: { recording_id: "${api.instrument.recording_id}", view: "summary" } },
        ],
        teardown: "close",
      },
      backend,
    );
    expect(r.code).toBe(0);
    const target = backend.sessions[0]?.id;
    expect(backend.tools()).toEqual([
      "spawn_process",
      "hook_function",
      "resume_process",
      "query_events",
      "close_session",
    ]);
    expect(backend.calls[3]?.input).toEqual({ recording_id: "rec_0000abcd", view: "summary", session_id: target });
    const doc = r.doc() as {
      ok: boolean;
      session_id: string;
      steps: { passed: boolean }[];
      teardown: { closed: { ok: boolean }[] };
    };
    expect(doc).toMatchObject({ schema: "bea-scenario-result/1", ok: true, session_id: target });
    expect(doc.steps.every((s) => s.passed)).toBe(true);
    expect(doc.teardown.closed).toHaveLength(1);
    expect(r.stderr).toContain('"bea_progress"');
  });
  it("session-creating steps: emu_open + diff_function; ids only via ${…}; teardown closes every created session (CI-B7)", async () => {
    const backend = createFakeBackend();
    const r = await run(
      {
        schema: "bea-scenario/1",
        steps: [
          { tool: "spawn_process", input: { program: "C:/lab/game_sim.exe" }, save_as: "live" },
          { tool: "resume_process", input: { session_id: "${live.session_id}" } },
          { tool: "emu_open", input: { live_session_id: "${live.session_id}" }, save_as: "emu" },
          {
            tool: "diff_function",
            input: {
              live_session_id: "${live.session_id}",
              emu_session_id: "${emu.session_id}",
              address: "game_sim.exe+0x1500",
            },
            save_as: "diff",
          },
        ],
      },
      backend,
    );
    expect(r.code).toBe(0);
    const [live, emu] = backend.sessions.map((s) => s.id);
    expect(backend.calls.find((c) => c.tool === "emu_open")?.input).toEqual({ live_session_id: live });
    expect(backend.calls.find((c) => c.tool === "diff_function")?.input).toEqual({
      live_session_id: live,
      emu_session_id: emu,
      address: "game_sim.exe+0x1500",
    });
    expect(backend.closed).toEqual([emu, live]);
    expect(r.doc()).toMatchObject({
      ok: true,
      session_id: null,
      sessions: [
        { session_id: live, created_by: 0 },
        { session_id: emu, created_by: 2 },
      ],
    });
  });
  it("with a target, an emu_open step references ${target.session_id}; diff gets no injected session_id", async () => {
    const backend = createFakeBackend();
    const r = await run(
      {
        schema: "bea-scenario/1",
        target: { attach: { name: "game_sim.exe" } },
        steps: [
          { tool: "emu_open", input: { live_session_id: "${target.session_id}" }, save_as: "emu" },
          {
            tool: "diff_function",
            input: { live_session_id: "${target.session_id}", emu_session_id: "${emu.session_id}", address: "x+0x1" },
          },
        ],
      },
      backend,
    );
    expect(r.code).toBe(0);
    const [target, emu] = backend.sessions.map((s) => s.id);
    expect(backend.calls.find((c) => c.tool === "diff_function")?.input).toEqual({
      live_session_id: target,
      emu_session_id: emu,
      address: "x+0x1",
    });
    expect(backend.closed).toEqual([emu, target]);
  });
});

describe("failures, signals and teardown", () => {
  it("teardown runs after a failed step; on_error stop skips the rest; exit 1", async () => {
    const backend = createFakeBackend({
      read_memory: async () =>
        err({ _tag: "AddressUnmapped", operation: "read_memory", address: "0x1", module_map_id: null }),
    });
    const r = await run(
      {
        schema: "bea-scenario/1",
        target: spawnTarget,
        steps: [{ tool: "read_memory", input: { address: "0x1" } }, { tool: "resume_process" }],
      },
      backend,
    );
    expect(r.code).toBe(1);
    expect(backend.tools()).toEqual(["spawn_process", "read_memory", "close_session"]);
    expect(r.doc()).toMatchObject({
      ok: false,
      steps: [{ ok: false, passed: false, error: { code: "address_unmapped" } }],
    });
  });
  it("expect error passes; on_error continue runs the remaining steps; a runtime reference miss fails its step", async () => {
    const backend = createFakeBackend({
      read_memory: async () =>
        err({ _tag: "AddressUnmapped", operation: "read_memory", address: "0x1", module_map_id: null }),
    });
    const r = await run(
      {
        schema: "bea-scenario/1",
        target: spawnTarget,
        on_error: "continue",
        steps: [
          { tool: "read_memory", input: { address: "0x1" }, expect: "error", save_as: "bad" },
          { tool: "query_events", input: { recording_id: "${bad.instrument.recording_id}" } },
          { tool: "resume_process" },
        ],
      },
      backend,
    );
    expect(r.code).toBe(1);
    const doc = r.doc() as { steps: { passed: boolean; error?: { code: string } }[] };
    expect(doc.steps.map((s) => s.passed)).toEqual([true, false, true]);
    expect(doc.steps[1]?.error?.code).toBe("invalid_request");
    expect(backend.tools()).toEqual(["spawn_process", "read_memory", "resume_process", "close_session"]);
  });
  it("a failed target runs no steps", async () => {
    const backend = createFakeBackend({
      spawn_process: async () => err({ _tag: "AccessDenied", operation: "spawn_process", reason: "policy" }),
    });
    const r = await run(
      { schema: "bea-scenario/1", target: spawnTarget, steps: [{ tool: "resume_process" }] },
      backend,
    );
    expect(r.code).toBe(1);
    expect(backend.tools()).toEqual(["spawn_process"]);
    expect(r.doc()).toMatchObject({ ok: false, target: { ok: false, error: { code: "access_denied" } }, steps: [] });
  });
  it("--evidence-out exports after the sessions closed", async () => {
    const backend = createFakeBackend();
    const r = await run(
      { schema: "bea-scenario/1", target: spawnTarget, steps: [{ tool: "resume_process" }] },
      backend,
      {
        argv: ["--evidence-out", "bundle"],
      },
    );
    expect(r.code, JSON.stringify(r.doc())).toBe(0);
    expect(backend.tools()).toEqual(["spawn_process", "resume_process", "close_session", "export_evidence"]);
    // UX-8: a relative name lands under THIS run's exports directory (the run id is unknowable before the run)
    const input = backend.calls[3]?.input as { out_path: string };
    expect(input.out_path.startsWith(join(home.beaHome, "runs", "run_"))).toBe(true);
    expect(input.out_path.endsWith(join("exports", "bundle"))).toBe(true);
    expect(r.doc()).toMatchObject({ evidence_bundle: { bytes: 1234 } });
  });
  it("--evidence-out outside exports.allowed_roots or with '..' fails validation before any effect (UX-8)", async () => {
    for (const value of [join(home.work, "elsewhere"), "../escape", "a/../b"]) {
      const backend = createFakeBackend();
      const r = await run(
        { schema: "bea-scenario/1", target: spawnTarget, steps: [{ tool: "resume_process" }] },
        backend,
        { argv: ["--evidence-out", value] },
      );
      expect(r.code, value).toBe(1);
      expect(backend.tools(), value).toEqual([]);
    }
  });
  it("SIGINT during a step: teardown still runs, exit 130", async () => {
    const signals = new EventEmitter();
    const backend = createFakeBackend({
      resume_process: async (_input, ctx) => {
        signals.emit("SIGINT");
        if (!ctx.signal.aborted)
          await new Promise((resolve) => ctx.signal.addEventListener("abort", resolve, { once: true }));
        return err(cancelled("resume_process", "client"));
      },
    });
    const r = await run(
      {
        schema: "bea-scenario/1",
        target: spawnTarget,
        steps: [{ tool: "resume_process" }, { tool: "resume_process" }],
      },
      backend,
      {
        signals,
      },
    );
    expect(r.code).toBe(130);
    expect(backend.tools()).toEqual(["spawn_process", "resume_process", "close_session"]);
    expect(r.doc()).toMatchObject({ ok: false, stopped: "signal" });
  });
  it("limits.total_ms aborts the running step and tears down", async () => {
    const backend = createFakeBackend({
      resume_process: async (_input, ctx) => {
        if (!ctx.signal.aborted)
          await new Promise((resolve) => ctx.signal.addEventListener("abort", resolve, { once: true }));
        return err(cancelled("resume_process", "client"));
      },
    });
    const r = await run(
      {
        schema: "bea-scenario/1",
        target: spawnTarget,
        steps: [{ tool: "resume_process" }],
        limits: { total_ms: 1000 },
      },
      backend,
    );
    expect(r.code).toBe(1);
    expect(r.doc()).toMatchObject({ ok: false, stopped: "time_limit" });
    expect(backend.closed).toHaveLength(1);
  });
});
