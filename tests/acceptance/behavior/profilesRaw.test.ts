import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, describe, expect, it } from "vitest";

import { decodeApiRow, DEFAULT_API_DECODERS } from "../../../src/application/behavior/apiEvents.js";
import { apiSummaryBuilder } from "../../../src/application/behavior/ApiSummary.js";
import { TRACE_API_OPTIONS } from "../../../src/application/behavior/TraceApiService.js";
import type { JsonValue } from "../../../src/domain/json.js";
import type { EventRecord } from "../../../src/ports/recordings.js";
import type { ProfileInstallParams, ProfileInstallResult } from "../../../src/shared/agentProtocol.js";
import { fixtureArtifact, fridaSkip, gccSkip, loadFixtures, skipNote } from "../../support/acceptance/fixtures.js";
import { pidStatus } from "../../support/process/ownedPidLedger.js";
import { REG_EXE, expectBehaviorTable } from "./behaviorTable.js";

/**
 * WP8 raw-Frida acceptance (wave rule: raw agent RPCs only, DESIGN §8.4). The profile engine — src/agent/profiles.ts
 * with its pure helpers — is compiled by frida.Compiler into a small harness agent (no WP-AGENT core needed), injected
 * into a BEA-test-spawned behavior.exe, and the api/1 batches it sends are decoded and summarized by the host code
 * (apiEvents + ApiSummary). Asserts the S6 §10.1 behavior table (S6 §10.8 trace_api row), the absence of Frida's own
 * activity and that the fixture's registry key is gone afterwards. Every process started here is ended here.
 */
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const skip = fridaSkip() || gccSkip();

const ENTRY = `
import { AGENT_LIMIT_DEFAULTS } from "../shared/agentLimits.js";
import * as profiles from "./profiles.js";
import type { AgentCore } from "./state.js";
const core = {
  t0Wall: Date.now(), jsTid: Process.getCurrentThreadId(), phase: "ready", bootStage: "rpc", features: [],
  early: { exception_handler: false, exit_hook: false, last_chance_hook: false, module_observer: false },
  gates: { write_memory: false, override_function: false, call_function: false },
  limits: { ...AGENT_LIMIT_DEFAULTS },
} as unknown as AgentCore;
profiles.init(core);
rpc.exports = {
  profileInstall: (p: unknown) => profiles.rpc.profileInstall(p as never),
  stop: (id: string) => profiles.profileRuntime.stop(id, "requested"),
  flush: () => profiles.profileRuntime.flush(),
  modules: () => Process.enumerateModules().map((m) => ({ name: m.name, base: m.base.toString(), size: m.size })),
};
`;

interface FridaLike {
  Compiler: new () => {
    build(entry: string, options: Record<string, unknown>): Promise<string>;
    diagnostics: { connect(cb: (d: unknown) => void): void };
  };
  DeviceManager: new () => FridaDeviceManager;
}
interface FridaDeviceManager {
  getDeviceById(id: string, timeout: number): Promise<FridaDevice>;
  close(): Promise<void>;
}
interface FridaDevice {
  spawn(argv: string[], options: Record<string, unknown>): Promise<number>;
  resume(pid: number): Promise<void>;
  attach(pid: number): Promise<FridaSession>;
  output: { connect(cb: (pid: number, fd: number, data: Buffer) => void): void };
}
interface FridaSession {
  createScript(source: string): Promise<FridaScript>;
  detach(): Promise<void>;
}
interface FridaScript {
  load(): Promise<void>;
  unload(): Promise<void>;
  exports: Record<string, (...args: unknown[]) => Promise<unknown>>;
  message: { connect(cb: (message: { type: string; payload?: unknown; description?: string }) => void): void };
}

const buildHarness = async (frida: FridaLike): Promise<string> => {
  const tmpRoot = join(root, "build", "tmp");
  await mkdir(tmpRoot, { recursive: true });
  const stage = await mkdtemp(join(tmpRoot, "wp8-raw-"));
  try {
    await cp(join(root, "src", "agent"), join(stage, "agent"), {
      recursive: true,
      filter: (p) => !p.endsWith("tsconfig.json"),
    });
    await cp(join(root, "src", "shared"), join(stage, "shared"), { recursive: true });
    const tsconfig = JSON.parse(await readFile(join(root, "src", "agent", "tsconfig.json"), "utf8")) as Record<
      string,
      unknown
    >;
    tsconfig.include = ["agent/wp8RawEntry.ts"];
    await writeFile(join(stage, "tsconfig.json"), JSON.stringify(tsconfig));
    await writeFile(join(stage, "agent", "wp8RawEntry.ts"), ENTRY);
    const compiler = new frida.Compiler();
    return await compiler.build(join(stage, "agent", "wp8RawEntry.ts"), {
      projectRoot: stage,
      bundleFormat: "esm",
      typeCheck: "none",
      sourceMaps: "omitted",
      compression: "none",
    });
  } finally {
    await rm(stage, { recursive: true, force: true });
  }
};

const waitFor = async (cond: () => boolean, ms: number): Promise<boolean> => {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (cond()) return true;
    await new Promise((r) => setTimeout(r, 25));
  }
  return cond();
};

/**
 * One OWNED DeviceManager for this file (never frida.getLocalDevice()'s process-wide manager, which is never closed).
 * Frida copies its agent DLLs (~45 MB) into %TEMP%\frida-<id> and deletes them only at DeviceManager.close(), and only
 * once no process still maps them: every target is fully terminated before `shutdownFrida()` (afterAll).
 */
let owned: { readonly dm: FridaDeviceManager; readonly device: FridaDevice } | null = null;
const ownedDevice = async (frida: FridaLike): Promise<FridaDevice> => {
  if (owned === null) {
    const dm = new frida.DeviceManager();
    owned = { dm, device: await dm.getDeviceById("local", 2000) };
  }
  return owned.device;
};
const shutdownFrida = async (): Promise<void> => {
  const o = owned;
  owned = null;
  await Promise.race([o?.dm.close().catch(() => undefined), new Promise((r) => setTimeout(r, 10_000))]);
};

/** pidcheck.exe of the fixture manifest (null: process.kill fallback, which reports ESRCH ≈ 10 ms early). */
let pidcheckPath: string | null = null;
/** Alive until the process object is signaled (only then has the target unmapped frida-agent.dll). */
const pidAlive = (pid: number): boolean => pidStatus(pidcheckPath, pid).alive;

interface TraceRun {
  readonly stdout: string;
  readonly outDir: string;
  readonly regKey: string;
  readonly summary: Record<string, unknown>;
  readonly install: ProfileInstallResult;
}

const summaryOf = (rows: readonly JsonValue[], modules: readonly { name: string; base: string; size: number }[]) => {
  const frame = (va: string): string | null => {
    const v = BigInt(va);
    const m = modules.find((x) => v >= BigInt(x.base) && v < BigInt(x.base) + BigInt(x.size));
    return m === undefined ? null : `${m.name}+0x${(v - BigInt(m.base)).toString(16)}`;
  };
  const events = rows
    .map((row, i) => decodeApiRow(row, { seq: i + 1, startedAtUs: 0, decoders: DEFAULT_API_DECODERS, frame }))
    .filter((e): e is EventRecord => e !== null);
  const state = apiSummaryBuilder.init();
  for (const e of events) apiSummaryBuilder.add(state, e);
  return apiSummaryBuilder.finish(state) as Record<string, unknown>;
};

/**
 * One traced behavior.exe run. "spawn": Frida spawns it suspended, profiles go in before resume. "attach": the test
 * starts it with --delay-ms (a process this test owns), attaches after READY and installs while it sleeps.
 */
const traceBehavior = async (
  frida: FridaLike,
  bundle: string,
  exePath: string,
  mode: "spawn" | "attach",
  profiles: ProfileInstallParams["profiles"],
  started: number[],
  dirs: string[],
): Promise<TraceRun> => {
  const outDir = await mkdtemp(join(tmpdir(), "bea-wp8-out-"));
  dirs.push(outDir);
  const regKey = `wp8-${randomBytes(4).toString("hex")}`;
  const device = await ownedDevice(frida);
  let stdout = "";
  const args = ["--out-dir", outDir, "--reg-key", regKey, "--hold-ms", "4000"];
  let pid: number;
  if (mode === "spawn") {
    device.output.connect((outPid, fd, data) => {
      if (outPid === pid && fd === 1) stdout += data.toString("utf8");
    });
    pid = await device.spawn([exePath, ...args], { cwd: dirname(exePath), stdio: "pipe" });
    started.push(pid);
  } else {
    const child = spawn(exePath, [...args, "--delay-ms", "2000"], {
      cwd: dirname(exePath),
      stdio: ["ignore", "pipe", "ignore"],
      windowsHide: true,
    });
    if (child.pid === undefined) throw new Error("behavior.exe did not start");
    pid = child.pid;
    started.push(pid);
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString("utf8")));
    expect(await waitFor(() => stdout.includes("READY"), 10_000)).toBe(true);
  }
  const session = await device.attach(pid);
  const script = await session.createScript(bundle);
  const rows: JsonValue[] = [];
  const ended: unknown[] = [];
  const errors: string[] = [];
  script.message.connect((m) => {
    if (m.type === "error") errors.push(String(m.description));
    const p = m.payload as { bea?: string; rows?: JsonValue[]; event?: string } | undefined;
    if (p?.bea === "batch" && Array.isArray(p.rows)) rows.push(...p.rows);
    if (p?.bea === "instrument" && p.event === "ended") ended.push(p);
  });
  await script.load();
  const params: ProfileInstallParams = {
    profiles,
    options: TRACE_API_OPTIONS,
    lifetime: { duration_ms: 60_000, max_hits: 200_000, clock: "install" },
    label: "wp8-raw",
  };
  const reply = (await script.exports.profileInstall?.(params)) as {
    ok: boolean;
    value: ProfileInstallResult;
    error?: unknown;
  };
  expect(reply.ok, JSON.stringify(reply.error)).toBe(true);
  const install = reply.value;
  if (mode === "spawn") await device.resume(pid);
  expect(await waitFor(() => stdout.includes("DONE"), 30_000), stdout).toBe(true);
  const modules = (await script.exports.modules?.()) as { name: string; base: string; size: number }[];
  await script.exports.flush?.();
  await script.exports.stop?.(install.instrument_id);
  expect(await waitFor(() => ended.length === 1, 5_000)).toBe(true);
  await script.unload();
  await session.detach();
  expect(await waitFor(() => !pidAlive(pid), 15_000)).toBe(true);
  expect(errors).toEqual([]);
  return { stdout, outDir, regKey, summary: summaryOf(rows, modules), install };
};

type FileRows = {
  path: string;
  kind: string;
  ops: string[];
  ok: number;
  read_bytes?: number;
  write_bytes?: number;
  failed: number;
  first_status?: string;
}[];
const outDirRows = (run: TraceRun): FileRows =>
  (run.summary.file as { rows: FileRows }).rows
    .filter((r) => r.path.toLowerCase().startsWith(run.outDir.toLowerCase()))
    .map((r) => ({ ...r, path: r.path.slice(run.outDir.length) }));

describe.skipIf(skip !== false)(`trace_api profiles on behavior.exe (raw Frida)${skipNote(skip)}`, () => {
  const started: number[] = [];
  const dirs: string[] = [];
  let spawnedFileRows: FileRows | null = null;
  afterAll(async () => {
    for (const pid of started) if (pidAlive(pid)) process.kill(pid);
    for (const pid of started) await waitFor(() => !pidAlive(pid), 15_000);
    await shutdownFrida();
    for (const d of dirs) await rm(d, { recursive: true, force: true });
  });

  const fixtures = async () => {
    const manifest = await loadFixtures();
    const exe = fixtureArtifact(manifest, "behavior");
    const mathlib = fixtureArtifact(manifest, "mathlib");
    if (exe === null || mathlib === null) throw new Error(`fixtures unavailable: ${JSON.stringify(manifest)}`);
    pidcheckPath = fixtureArtifact(manifest, "pidcheck")?.path ?? null;
    const imported = (await import("frida")) as unknown as { default?: FridaLike } & FridaLike;
    const frida = imported.default ?? imported;
    return { exe, mathlib, frida, bundle: await buildHarness(frida) };
  };

  it(
    "spawned: the summary matches the behavior table; no Frida activity; registry key removed",
    { timeout: 120_000 },
    async () => {
      const { exe, mathlib, frida, bundle } = await fixtures();
      const run = await traceBehavior(
        frida,
        bundle,
        exe.path,
        "spawn",
        ["file", "registry", "network", "process", "module_load", "memory_protection"],
        started,
        dirs,
      );
      const { stdout, outDir, regKey, summary, install } = run;
      expect(install.installed.length).toBeGreaterThan(40);
      expect(install.failed.filter((f) => f.error._tag !== "ModuleNotFound")).toEqual([]);
      expect(stdout).toContain("DONE ok=1");
      const netPort = Number(/NET port=(\d+)/u.exec(stdout)?.[1]);
      // The parent's "CHILD pid=" and the child's "CHILDMODE pid=" lines (same pid) share the pipe and are written
      // unbuffered, so they can interleave character by character (seen once in 15 MCP runs). Either intact line
      // gives the pid; if both are torn, the summary's spawn row supplies it and the open_process row (and the
      // image/command line checks) still have to agree with it.
      const spawnRow = (summary.process as { rows: { op: string; pid?: number }[] }).rows.find((p) => p.op === "spawn");
      const childPid = Number(
        /CHILD pid=(\d+)/u.exec(stdout)?.[1] ?? /CHILDMODE pid=(\d+)/u.exec(stdout)?.[1] ?? spawnRow?.pid,
      );
      expectBehaviorTable(summary, { outDir, regKey, netPort, childPid, exePath: exe.path, mathlibPath: mathlib.path });
      spawnedFileRows = outDirRows(run);

      // ------------------------------------------------------------ the fixture's registry key is gone
      const reg = spawnSync(REG_EXE, ["query", `HKCU\\Software\\BEA-Fixture\\${regKey}`], { windowsHide: true });
      expect(reg.status).toBe(1);
    },
  );

  it("attached late (--delay-ms 2000): the same out-dir file rows", { timeout: 120_000 }, async () => {
    const { exe, frida, bundle } = await fixtures();
    const run = await traceBehavior(frida, bundle, exe.path, "attach", ["file"], started, dirs);
    expect(run.stdout).toContain("DONE ok=1");
    expect(spawnedFileRows).not.toBeNull();
    expect(outDirRows(run)).toEqual(spawnedFileRows);
  });
});
