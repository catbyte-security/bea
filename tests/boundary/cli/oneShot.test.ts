import { EventEmitter } from "node:events";
import { mkdir, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type { BeaCore } from "../../../src/application/BeaApplication.js";
import { cancelled } from "../../../src/domain/errors/constructors.js";
import { COMPLETE } from "../../../src/domain/evidence/coverage.js";
import { err, ok } from "../../../src/domain/result.js";
import { createFakeBackend } from "../../support/cli/fakeCatalog.js";
import { fakeServices } from "../../support/fakes/fakeServices.js";
import { runCliInProcess } from "../../support/cli/harness.js";
import { createTempHome, type TempHome } from "../../support/workspace/tempHome.js";

const env = { evidence_id: null, coverage: COMPLETE, limitations: [] as string[] };

let home: TempHome;
beforeEach(async () => {
  home = await createTempHome("cli-oneshot");
});
afterEach(async () => {
  await home.cleanup();
});

describe("oneshot tier", () => {
  it("bea status runs bea_status with no session and prints TOON by default", async () => {
    const backend = createFakeBackend();
    const r = await runCliInProcess(["status"], { home, backend });
    expect(r.code).toBe(0);
    expect(backend.tools()).toEqual(["bea_status"]);
    expect(r.doc()).toMatchObject({ server: { name: "bea", transport: "cli" }, evidence_id: null });
    expect(r.stdout.trim().startsWith("{")).toBe(false);
  });
  it("a configuration error is a document and exit 1, before any tool runs", async () => {
    const backend = createFakeBackend();
    const r = await runCliInProcess(["status", "--json"], { home, backend, env: { BEA_LOG_LEVEL: "loud" } });
    expect(r.code).toBe(1);
    expect(r.doc()).toMatchObject({ error: { code: "configuration_invalid" } });
    expect(backend.calls).toHaveLength(0);
  });
});

describe("session-oneshot tier", () => {
  it("--spawn: spawn (paused) → resume → tool → close_session; the program path is resolved", async () => {
    const backend = createFakeBackend();
    const r = await runCliInProcess(
      ["read", "game.exe+0x10", "--size", "8", "--spawn", "game.exe", "--json", "--", "-x", "1"],
      {
        home,
        backend,
      },
    );
    expect(r.code).toBe(0);
    expect(backend.tools()).toEqual(["spawn_process", "resume_process", "read_memory", "close_session"]);
    const session = backend.sessions[0]?.id;
    expect(backend.calls[0]?.input).toEqual({ program: join(home.work, "game.exe"), args: ["-x", "1"] });
    expect(backend.calls[2]?.input).toMatchObject({ session_id: session, address: "game.exe+0x10", size: 8 });
    expect(backend.closed).toEqual([session]);
    expect(r.doc()).toMatchObject({ echo: { session_id: session, address: "game.exe+0x10" } });
  });
  it("--pid attaches without resuming and detaches at the end", async () => {
    const backend = createFakeBackend();
    const r = await runCliInProcess(["read", "77", "0x1000"], { home, backend });
    expect(r.code).toBe(0);
    expect(backend.tools()).toEqual(["attach_process", "read_memory", "close_session"]);
    expect(backend.calls[0]?.input).toEqual({ pid: 77 });
  });
  it("a failing tool prints the error, exits 1 and still closes the session", async () => {
    const backend = createFakeBackend({
      read_memory: async () =>
        err({ _tag: "AddressUnmapped", operation: "read_memory", address: "0x1", module_map_id: null }),
    });
    const r = await runCliInProcess(["read", "0x1", "--name", "game.exe", "--json"], { home, backend });
    expect(r.code).toBe(1);
    expect(r.doc()).toMatchObject({ error: { code: "address_unmapped" } });
    expect(backend.closed).toHaveLength(1);
  });
  it("a failed spawn closes nothing", async () => {
    const backend = createFakeBackend({
      spawn_process: async () =>
        err({
          _tag: "FileOperationFailed",
          operation: "spawn_process",
          file_operation: "stat",
          path: "x",
          reason: "missing",
        }),
    });
    const r = await runCliInProcess(["read", "0x1", "--spawn", "C:/missing.exe"], { home, backend });
    expect(r.code).toBe(1);
    expect(backend.tools()).toEqual(["spawn_process"]);
  });
  it("invalid tool input and closed gates are refused before the target is touched", async () => {
    const backend = createFakeBackend();
    const bad = await runCliInProcess(["read", "0x1", "--size", "0", "--pid", "5", "--json"], { home, backend });
    expect(bad.code).toBe(1);
    expect(bad.doc()).toMatchObject({ error: { code: "invalid_request" } });
    await writeFile(join(home.work, "hook.js"), "send(1);");
    const gated = await runCliInProcess(["script", "hook.js", "--pid", "5", "--json"], { home, backend });
    expect(gated.code).toBe(1);
    expect(gated.doc()).toMatchObject({ error: { code: "capability_unavailable", details: { gate: "run_script" } } });
    expect(backend.calls).toHaveLength(0);
  });
  it("offline: `bea map a b --pe-path X` runs map_address with no session (CI-I11)", async () => {
    const backend = createFakeBackend();
    const r = await runCliInProcess(["map", "0x140001000", "+0x2000", "--pe-path", "C:/lab/x.exe", "--json"], {
      home,
      backend,
    });
    expect(r.code).toBe(0);
    expect(backend.tools()).toEqual(["map_address"]);
    expect(backend.calls[0]?.input).toEqual({ addresses: ["0x140001000", "+0x2000"], pe_path: "C:/lab/x.exe" });
  });
  it("`bea script hook.js --pid N` reads the file into source; `-` reads stdin", async () => {
    await writeFile(join(home.work, "hook.js"), "\uFEFFconsole.log('hi');\n");
    const backend = createFakeBackend();
    const gates = { BEA_ALLOW_RUN_SCRIPT: "1" };
    const r = await runCliInProcess(["script", "hook.js", "--pid", "1234"], { home, backend, env: gates });
    expect(r.code).toBe(0);
    expect(backend.calls.find((c) => c.tool === "run_script")?.input["source"]).toBe("console.log('hi');\n");
    const piped = createFakeBackend();
    const s = await runCliInProcess(["script", "-", "--pid", "1234"], {
      home,
      backend: piped,
      env: gates,
      stdin: "send(2);",
    });
    expect(s.code).toBe(0);
    expect(piped.calls.find((c) => c.tool === "run_script")?.input["source"]).toBe("send(2);");
    const missing = await runCliInProcess(["script", "nope.js", "--pid", "1", "--json"], {
      home,
      backend: createFakeBackend(),
      env: gates,
    });
    expect(missing.code).toBe(1);
    expect(missing.doc()).toMatchObject({ error: { code: "file_operation_failed" } });
  });
  it("--input FILE merges under flags; two stdin readers conflict", async () => {
    await writeFile(join(home.work, "in.json"), JSON.stringify({ address: "from-file", size: 4, format: "values" }));
    const backend = createFakeBackend();
    const r = await runCliInProcess(["read", "--input", "in.json", "--size", "16", "--pid", "9"], { home, backend });
    expect(r.code).toBe(0);
    expect(backend.calls.find((c) => c.tool === "read_memory")?.input).toMatchObject({
      address: "from-file",
      size: 16,
      format: "values",
    });
    const both = await runCliInProcess(["script", "-", "--input", "-", "--pid", "1", "--json"], {
      home,
      backend: createFakeBackend(),
      env: { BEA_ALLOW_RUN_SCRIPT: "1" },
    });
    expect(both.code).toBe(1);
    expect(both.doc()).toMatchObject({ error: { code: "invalid_request" } });
  });
  it("SIGINT cancels the running tool, still closes the session (cleanup signal), and exits 130", async () => {
    const signals = new EventEmitter();
    const backend = createFakeBackend({
      read_memory: async (_input, ctx) => {
        signals.emit("SIGINT");
        if (!ctx.signal.aborted)
          await new Promise((resolve) => ctx.signal.addEventListener("abort", resolve, { once: true }));
        return err(cancelled("read_memory", "client"));
      },
    });
    const r = await runCliInProcess(["read", "0x1", "--spawn", "C:/lab/game.exe", "--json"], {
      home,
      backend,
      signals,
    });
    expect(r.code).toBe(130);
    expect(r.doc()).toMatchObject({ error: { code: "cancelled" } });
    const close = backend.calls.find((c) => c.tool === "close_session");
    expect(close?.aborted).toBe(false);
    expect(signals.listenerCount("SIGINT")).toBe(0);
  });
  it("--progress writes JSON-lines progress to stderr", async () => {
    const backend = createFakeBackend({
      read_memory: async (input, ctx) => {
        ctx.progress.report("reading", "8 bytes", true);
        return ok({ echo: { ...input }, ...env });
      },
    });
    const r = await runCliInProcess(["read", "0x1", "--pid", "3", "--progress"], { home, backend });
    expect(r.code).toBe(0);
    expect(JSON.parse(r.stderr.trim().split("\n").at(-1) ?? "{}")).toMatchObject({
      bea_progress: { tool: "read_memory", phase: "reading", message: "8 bytes" },
    });
  });
});

describe("emu-oneshot tier", () => {
  it("bea emulate --image PE --input request.json: emu_open → emu_call → close_session", async () => {
    await writeFile(
      join(home.work, "request.json"),
      JSON.stringify({ signature: "f32(f32)", vectors: [{ args: [1.5] }] }),
    );
    const backend = createFakeBackend();
    const r = await runCliInProcess(
      ["emulate", "bea_step", "--image", "fixture.dll", "--input", "request.json", "--json"],
      { home, backend },
    );
    expect(r.code).toBe(0);
    expect(backend.tools()).toEqual(["emu_open", "emu_call", "close_session"]);
    expect(backend.calls[0]?.input).toEqual({ image_path: join(home.work, "fixture.dll") });
    expect(backend.calls[1]?.input).toMatchObject({
      address: "bea_step",
      signature: "f32(f32)",
      vectors: [{ args: [1.5] }],
    });
    expect(backend.closed).toEqual([backend.sessions[0]?.id]);
  });
});

describe("instrument-oneshot tier", () => {
  it("install before resume, wait until done, summary, stop, close", async () => {
    const backend = createFakeBackend();
    const r = await runCliInProcess(
      ["hook", "game.exe+0x1000", "--spawn", "C:/lab/game.exe", "--duration-ms", "2000", "--json"],
      { home, backend },
    );
    expect(r.code).toBe(0);
    expect(backend.tools()).toEqual([
      "spawn_process",
      "hook_function",
      "resume_process",
      "wait",
      "query_events",
      "stop_instrumentation",
      "close_session",
    ]);
    expect(backend.calls[3]?.input).toMatchObject({ until: "done", ids: ["rec_0000abcd"] });
    expect((backend.calls[3]?.input["timeout_ms"] as number) <= 7000).toBe(true);
    expect(backend.calls[4]?.input).toMatchObject({ recording_id: "rec_0000abcd", view: "summary" });
    expect(r.doc()).toMatchObject({
      stop_reason: "finished",
      instrument: { instrument: { recording_id: "rec_0000abcd" } },
      summary: { view: "summary" },
      stopped: { stopped: ["rec_0000abcd"] },
    });
  });
  it("an attached target is not resumed; target exit ends the wait; a failed stop exits 1 with the document", async () => {
    const backend = createFakeBackend({
      wait: async () => ok({ satisfied: false, reason: "target_exited", ...env }),
      stop_instrumentation: async () =>
        err({ _tag: "EffectUnreverted", operation: "stop_instrumentation", effect_ids: [] }),
    });
    const r = await runCliInProcess(["hook", "0x1", "--pid", "42", "--json"], { home, backend });
    expect(r.code).toBe(1);
    expect(backend.tools()).not.toContain("resume_process");
    expect(r.doc()).toMatchObject({ stop_reason: "target_exited", stopped: { error: { code: "effect_unreverted" } } });
    expect(backend.closed).toHaveLength(1);
  });
});

describe("ephemeral CLI runs (S2 §9.2)", () => {
  /** Services that write the run directory the way the evidence runtime does on its first record. */
  const recordingServices = (dirs: string[]) => async (core: BeaCore) => {
    const dir = core.config.layout.runDir(core.run.runId);
    await mkdir(join(dir, "streams"), { recursive: true });
    await writeFile(join(dir, "run.json"), "{}");
    dirs.push(dir);
    return fakeServices()(core);
  };
  const runsIn = async (dir: string) => readdir(dir).catch(() => [] as string[]);

  it("a one-shot deletes its run directory at exit; --keep-run keeps it and says where", async () => {
    const dirs: string[] = [];
    const other = join(home.beaHome, "runs", "run_other");
    await mkdir(other, { recursive: true });
    const r = await runCliInProcess(["read", "game.exe+0x10", "--size", "8", "--pid", "42", "--json"], {
      home,
      backend: createFakeBackend(),
      services: recordingServices(dirs),
    });
    expect(r.code).toBe(0);
    expect(dirs).toHaveLength(1);
    await expect(stat(dirs[0] ?? "")).rejects.toThrow();
    // Only this command's run: another run next to it is untouched.
    expect(await runsIn(join(home.beaHome, "runs"))).toEqual(["run_other"]);

    const kept = await runCliInProcess(
      ["read", "game.exe+0x10", "--keep-run", "--size", "8", "--pid", "42", "--json"],
      { home, backend: createFakeBackend(), services: recordingServices(dirs) },
    );
    expect(kept.code).toBe(0);
    expect((await stat(dirs[1] ?? "")).isDirectory()).toBe(true);
    expect(kept.stderr).toContain(`evidence run kept: ${dirs[1] ?? ""}`);
  });
  it("--keep-run after -- belongs to the program, not to the runner", async () => {
    const dirs: string[] = [];
    const backend = createFakeBackend();
    const r = await runCliInProcess(
      ["read", "game.exe+0x10", "--size", "8", "--spawn", "game.exe", "--", "--keep-run"],
      {
        home,
        backend,
        services: recordingServices(dirs),
      },
    );
    expect(r.code).toBe(0);
    expect(backend.calls[0]?.input).toMatchObject({ args: ["--keep-run"] });
    await expect(stat(dirs[0] ?? "")).rejects.toThrow();
  });
  it("a failed cleanup keeps the run for diagnosis", async () => {
    const dirs: string[] = [];
    const failingCloser = async (core: BeaCore) => {
      core.lifecycle.register({
        name: "broken-closer",
        phase: "finalize-evidence",
        close: async () => {
          throw new Error("disk gone");
        },
      });
      return recordingServices(dirs)(core);
    };
    const r = await runCliInProcess(["status", "--json"], {
      home,
      backend: createFakeBackend(),
      services: failingCloser,
    });
    expect(r.code).toBe(1);
    expect((await stat(dirs[0] ?? "")).isDirectory()).toBe(true);
    expect(r.stderr).toContain("evidence run kept");
  });
  it("bea run deletes the run unless --keep-run or --evidence-out is given", async () => {
    await writeFile(
      join(home.work, "s.json"),
      JSON.stringify({
        schema: "bea-scenario/1",
        target: { attach: { pid: 42 } },
        steps: [{ tool: "read_memory", input: { address: "game.exe+0x10", size: 8 } }],
      }),
    );
    const dirs: string[] = [];
    const go = (extra: readonly string[]) =>
      runCliInProcess(["run", "s.json", "--json", ...extra], {
        home,
        backend: createFakeBackend(),
        services: recordingServices(dirs),
      });
    expect((await go([])).code).toBe(0);
    expect((await go(["--keep-run"])).code).toBe(0);
    expect((await go(["--evidence-out", "bundle"])).code).toBe(0);
    await expect(stat(dirs[0] ?? "")).rejects.toThrow();
    expect((await stat(dirs[1] ?? "")).isDirectory()).toBe(true);
    expect((await stat(dirs[2] ?? "")).isDirectory()).toBe(true);
  });
});
