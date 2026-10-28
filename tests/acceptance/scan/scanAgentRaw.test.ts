import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import type {
  AgentResult,
  JobMessage,
  Paged,
  ScanHit,
  ScanStartParams,
  ScanStatus,
} from "../../../src/shared/agentProtocol.js";
import { fixtureArtifact, fridaSkip, loadFixtures, skipNote } from "../../support/acceptance/fixtures.js";

/**
 * WP10-SCAN raw-agent acceptance (wave rule §8.4: raw agent RPCs only; no BEA tools, no WP3 core). The REAL agent
 * feature files (src/agent/scan.ts, scanKernels.ts, pure/scan*.ts) are compiled with frida.Compiler into a test agent
 * whose entry stands in for the core (limits, a test guard seam), injected into game_sim.exe:
 * - S6 §10.8 scan_memory rows on the f32 equilibrium: 20.0 hits include car+8; utf8/utf16 markers at their exports;
 *   pointers-to the World pointer restricted to images = game_sim.exe!g_world;
 * - scan_next "increased" after RAMP keeps car+8 and the count drops;
 * - a 1 GiB ballast scan keeps agent RPC latency ≤ 50 ms (sliced jobs);
 * - a value on a BEA-guarded page is found through withBeaGuardsSuspended and the guard stays armed (CT-I5);
 * - float specials inside the target's QJS: Frida 17.23.2's QJS on Windows has no infinities (±Infinity is the
 *   canonical NaN, and NaN === x is true), so decoding and the JS reference kernels classify specials from the bits;
 *   both kernels must agree with IEEE on +Inf/-Inf/NaN/±0 elements written into the target.
 * One owned DeviceManager, closed after every target is fully gone, so Frida can delete its %TEMP%\frida-<id> copy.
 */
const repo = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const skip = fridaSkip();

const STATE_STUB = `import type { AgentFeature, AgentLimits, FatalMessage, GateName, ReadyMessage, ThreadId } from "../shared/agentProtocol.js";
export type Phase = "loaded" | "ready" | "shutting-down";
export interface AgentCore { readonly t0Wall: number; readonly jsTid: ThreadId; phase: Phase; bootStage: FatalMessage["stage"]; features: AgentFeature[]; early: ReadyMessage["early"]; gates: Record<GateName, boolean>; limits: AgentLimits; }
`;
const ERRORS_STUB = `import type { AgentError, AgentResult } from "../shared/agentProtocol.js";
export const ok = <T>(value: T): AgentResult<T> => ({ ok: true, value });
export const fail = (error: AgentError): AgentResult<never> => ({ ok: false, error });
`;
/** Test entry: the scan feature over a stand-in core; a test guard seam on one VirtualAlloc'd page. */
const ENTRY = `import { AGENT_LIMIT_DEFAULTS } from "../shared/agentLimits.js";
import type { ScanStartParams, ScanNextParams, ScanResultsParams } from "../shared/agentProtocol.js";
import * as scan from "./scan.js";
import { createScanKernels, scanKernelCompileError } from "./scanKernels.js";
import { addrAt, createReferenceKernels } from "./pure/scanReference.js";
import type { KernelOp, ScanBuf, ScanKernels } from "./pure/scanTypes.js";
import { decodeValue, parseNumericOperand } from "./pure/scanValue.js";
import type { AgentCore } from "./state.js";

const core: AgentCore & { guards?: unknown } = {
  t0Wall: Date.now(), jsTid: Process.getCurrentThreadId(), phase: "ready", bootStage: "rpc", features: [],
  early: { exception_handler: true, exit_hook: false, last_chance_hook: false, module_observer: false },
  gates: { write_memory: false, override_function: false, call_function: false },
  limits: { ...AGENT_LIMIT_DEFAULTS },
};
scan.init(core);
const kb = Process.getModuleByName("kernelbase.dll");
const VirtualAlloc = new NativeFunction(kb.getExportByName("VirtualAlloc"), "pointer", ["pointer", "size_t", "uint32", "uint32"], { scheduling: "exclusive" });
const VirtualProtect = new NativeFunction(kb.getExportByName("VirtualProtect"), "int", ["pointer", "size_t", "uint32", "pointer"], { scheduling: "exclusive" });
const VirtualQuery = new NativeFunction(kb.getExportByName("VirtualQuery"), "size_t", ["pointer", "pointer", "size_t"], { scheduling: "exclusive" });
const old = Memory.alloc(8);
const mbi = Memory.alloc(0x30);
let page: NativePointer = NULL;
let windows = 0;
const protectOf = (p: NativePointer): number => { VirtualQuery(p, mbi, 0x30); return mbi.add(0x24).readU32(); };

// 20, +Inf, -Inf, NaN, 25, -0, +0 as f32 bits
const F32 = [0x41a00000, 0x7f800000, 0xff800000, 0x7fc00000, 0x41c80000, 0x80000000, 0];
const FLOAT_CASES: readonly (readonly [KernelOp, string | number, string | number])[] = [
  ["eq", "Infinity", 0], ["eq", "-Infinity", 0], ["eq", "NaN", 0], ["ne", "NaN", 0], ["eq", 20, 0], ["eq", 0, 0],
  ["gt", 21, 0], ["lt", 21, 0], ["range", "-Infinity", 21],
];
const nbuf = (n: number): ScanBuf => { const p = Memory.alloc(n); return { u8: new Uint8Array(ArrayBuffer.wrap(p, n)), bytes: n, native: p }; };
const readMem = (va: number, len: number): Uint8Array | null => {
  try { const d = ptr(va).readByteArray(len); return d === null ? null : new Uint8Array(d); } catch { return null; }
};
const bitsOfOperand = (v: string | number) => {
  const r = parseNumericOperand("f32", v);
  if (!r.ok) throw new Error(r.problem);
  return r.value.bits;
};
const floatMatches = (kernels: ScanKernels, data: NativePointer): number[][] => {
  const va = Number(data.toString());
  const n = F32.length;
  return FLOAT_CASES.map(([op, a, b]) => {
    const spec = { vt: 8, elem: 4, align: 4, op, a: bitsOfOperand(a), b: bitsOfOperand(b), eps: 0, operand: null };
    const out = { addrs: nbuf(n * 8), vals: nbuf(n * 4), firsts: null, cap: n };
    const r = kernels.cmp(spec, { va, len: n * 4, avail: n * 4, progress: 0, out, at: 0 });
    return Array.from({ length: r.at }, (_, i) => (addrAt(out.addrs, i) - va) / 4);
  });
};

rpc.exports = {
  scanStart: (p: ScanStartParams) => scan.rpc.scanStart(p),
  scanNext: (p: ScanNextParams) => scan.rpc.scanNext(p),
  scanStatus: (p: { scan_id: string }) => scan.rpc.scanStatus(p),
  scanResults: (p: ScanResultsParams) => scan.rpc.scanResults(p),
  scanClose: (p: { scan_id: string }) => scan.rpc.scanClose(p),
  ping: () => Date.now(),
  features: () => core.features,
  kernels: () => ({ native: createScanKernels(() => null).native, error: scanKernelCompileError() }),
  exportAddress: (name: string) => Process.getModuleByName(Process.mainModule.name).getExportByName(name).toString(),
  armGuard: (lo: number, hi: number) => {
    page = VirtualAlloc(NULL, 4096, 0x3000, 0x04);
    page.add(0x100).writeU32(lo).add(4).writeU32(hi);
    VirtualProtect(page, 4096, 0x104, old);
    core.guards = {
      withBeaGuardsSuspended: <T>(ranges: readonly { base: NativePointer; size: number }[], fn: () => T): T => {
        const hit = ranges.some((r) => page.compare(r.base.add(r.size)) < 0 && r.base.compare(page.add(4096)) < 0);
        if (!hit) return fn();
        windows += 1;
        VirtualProtect(page, 4096, 0x04, old);
        try { return fn(); } finally { VirtualProtect(page, 4096, 0x104, old); }
      },
      listingPages: () => [{ base: BigInt(page.toString()), size: 4096, protection: "rw-" }],
    };
    return page.toString();
  },
  guardState: () => ({ protect: protectOf(page), windows }),
  qjsFloats: () => {
    const data = Memory.alloc(F32.length * 4);
    F32.forEach((b, i) => data.add(i * 4).writeU32(b));
    const native = createScanKernels(readMem);
    return {
      decoded: F32.map((_, i) => decodeValue("f32", readMem(Number(data.add(i * 4).toString()), 4) ?? new Uint8Array(4)).value),
      words: ["Infinity", "-Infinity", "NaN"].map((w) => bitsOfOperand(w).lo.toString(16)),
      nativeUsed: native.native,
      native: floatMatches(native, data),
      reference: floatMatches(createReferenceKernels(readMem), data),
    };
  },
};
`;

interface FridaScript {
  readonly exports: Record<string, (...args: unknown[]) => Promise<unknown>>;
  readonly message: { connect(h: (message: { type: string; payload?: unknown }, data: Buffer | null) => void): void };
  load(): Promise<void>;
  unload(): Promise<void>;
}
interface Target {
  readonly pid: number;
  readonly script: FridaScript;
  readonly out: () => string;
  readonly jobs: Map<string, JobMessage>;
  readonly car: number;
  readonly world: number;
  readonly call: <T>(method: string, params?: unknown) => Promise<T>;
  readonly waitOutput: (re: RegExp, ms?: number) => Promise<RegExpExecArray>;
  readonly runJob: (method: "scanStart" | "scanNext", params: object) => Promise<ScanStatus>;
  readonly hits: (scanId: string) => Promise<number[]>;
}

let frida: typeof import("frida");
let manager: import("frida").DeviceManager | undefined;
let pidcheck: string | null = null;
let bundle = "";
let stage = "";
const owned = new Set<number>();
const until = async <T>(probe: () => T | null | undefined, ms: number, what: string): Promise<T> => {
  const end = Date.now() + ms;
  for (;;) {
    const v = probe();
    if (v !== null && v !== undefined) return v;
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 25));
  }
};

/** The test's own DeviceManager (closed in afterAll, once every target is gone). */
const localDevice = async (): Promise<import("frida").Device> => {
  manager ??= new frida.DeviceManager();
  return manager.getDeviceById("local", 5000);
};
/** pidcheck's signaled state (the process object), else process.kill(pid, 0); ESRCH alone comes ~10 ms early. */
const terminated = (pid: number): boolean => {
  if (pidcheck !== null) {
    const run = spawnSync(pidcheck, [String(pid)], { encoding: "utf8", windowsHide: true, timeout: 5000 });
    if (run.status === 0) return (JSON.parse(run.stdout) as { alive: boolean }).alive === false;
  }
  try {
    process.kill(pid, 0);
    return false;
  } catch (cause) {
    return (cause as NodeJS.ErrnoException).code !== "EPERM";
  }
};
const waitGone = async (pid: number): Promise<void> => {
  const end = Date.now() + 5000;
  while (Date.now() < end && !terminated(pid)) await new Promise((r) => setTimeout(r, 25));
};

const buildAgent = async (): Promise<string> => {
  stage = mkdtempSync(join(tmpdir(), "bea-scan-agent-"));
  const agent = join(stage, "agent");
  mkdirSync(join(agent, "pure"), { recursive: true });
  cpSync(join(repo, "src", "shared"), join(stage, "shared"), { recursive: true });
  for (const f of ["scan.ts", "scanKernels.ts"]) cpSync(join(repo, "src", "agent", f), join(agent, f));
  for (const f of readdirSync(join(repo, "src", "agent", "pure")).filter((n) => n.startsWith("scan")))
    cpSync(join(repo, "src", "agent", "pure", f), join(agent, "pure", f));
  writeFileSync(join(agent, "state.ts"), STATE_STUB);
  writeFileSync(join(agent, "errors.ts"), ERRORS_STUB);
  writeFileSync(join(agent, "entry.ts"), ENTRY);
  const tsconfig = JSON.parse(readFileSync(join(repo, "src", "agent", "tsconfig.json"), "utf8")) as Record<
    string,
    unknown
  >;
  delete tsconfig["include"];
  writeFileSync(join(stage, "tsconfig.json"), JSON.stringify({ ...tsconfig, files: ["agent/entry.ts"] }));
  const compiler = new frida.Compiler();
  const diagnostics: unknown[] = [];
  compiler.diagnostics.connect((d: unknown) => diagnostics.push(d));
  const out = await compiler.build(join(agent, "entry.ts"), {
    projectRoot: stage,
    bundleFormat: "esm",
    typeCheck: "full",
    sourceMaps: "omitted",
    compression: "none",
  } as never);
  expect(diagnostics, JSON.stringify(diagnostics).slice(0, 2000)).toEqual([]);
  return out;
};

const startTarget = async (gameSim: string, args: readonly string[]): Promise<Target> => {
  const device = await localDevice();
  let text = "";
  const pid = await device.spawn([gameSim, ...args], { cwd: dirname(gameSim), stdio: frida.Stdio.Pipe });
  owned.add(pid);
  device.output.connect((p, _fd, data) => {
    if (p === pid) text += data.toString("utf8");
  });
  const session = await device.attach(pid);
  const script = (await session.createScript(bundle, { runtime: frida.ScriptRuntime.QJS })) as unknown as FridaScript;
  const jobs = new Map<string, JobMessage>();
  script.message.connect((message) => {
    const payload = message.payload as { bea?: string; job?: string } | undefined;
    if (message.type === "send" && payload?.bea === "job" && payload.job !== undefined)
      jobs.set(payload.job, payload as JobMessage);
    if (message.type === "error") throw new Error(`agent error ${JSON.stringify(message)}`);
  });
  await script.load();
  await device.resume(pid);
  const waitOutput = (re: RegExp, ms = 15_000) => until(() => re.exec(text), ms, `output ${String(re)}`);
  const ready = await waitOutput(/READY pid=\d+ world=(?:0x)?([0-9a-fA-F]+) car=(?:0x)?([0-9a-fA-F]+)/u);
  const call = async <T>(method: string, params?: unknown): Promise<T> => {
    const r = (await script.exports[method]?.(params)) as AgentResult<T>;
    if (!r.ok) throw new Error(`${method}: ${JSON.stringify(r.error)}`);
    return r.value;
  };
  const runJob = async (method: "scanStart" | "scanNext", params: object): Promise<ScanStatus> => {
    const started = await call<{ scan_id: string; job_id: string }>(method, params);
    const done = await until(() => jobs.get(started.job_id), 60_000, `job ${started.job_id}`);
    return done.result as ScanStatus;
  };
  const hits = async (scanId: string): Promise<number[]> => {
    const page = await call<Paged<ScanHit>>("scanResults", {
      scan_id: scanId,
      offset: 0,
      limit: 1000,
      read_current: false,
    });
    return page.items.map((h) => Number(h.address));
  };
  return {
    pid,
    script,
    out: () => text,
    jobs,
    car: Number.parseInt(ready[2] ?? "0", 16),
    world: Number.parseInt(ready[1] ?? "0", 16),
    call,
    waitOutput,
    runJob,
    hits,
  };
};

const stopTarget = async (t: Target | undefined): Promise<void> => {
  if (t === undefined) return;
  const device = await localDevice();
  await t.script.unload().catch(() => undefined);
  await device.kill(t.pid).catch(() => undefined);
  await waitGone(t.pid);
  owned.delete(t.pid);
};

/** Float specials inside the target's QJS (see the file comment): decoding and both kernels against IEEE. */
const floatSpecialsCase = async (gameSim: string): Promise<void> => {
  const t = await startTarget(gameSim, ["--no-threads"]);
  try {
    const got = (await t.script.exports["qjsFloats"]?.()) as Record<string, unknown>;
    // elements: 0 = 20, 1 = +Inf, 2 = -Inf, 3 = NaN, 4 = 25, 5 = -0, 6 = +0
    const ieee = [[1], [2], [], [0, 1, 2, 3, 4, 5, 6], [0], [5, 6], [1, 4], [0, 2, 5, 6], [0, 2, 5, 6]];
    expect(got).toEqual({
      decoded: [20, "Infinity", "-Infinity", "NaN", 25, 0, 0],
      words: ["7f800000", "ff800000", "7fc00000"],
      nativeUsed: true,
      native: ieee,
      reference: ieee,
    });
  } finally {
    await stopTarget(t);
  }
};

/** CT-I5: a value on a BEA-guarded page is found through withBeaGuardsSuspended; the guard stays armed. */
const guardedPageCase = async (gameSim: string): Promise<void> => {
  const rw = { protection: "rw-" };
  const t = await startTarget(gameSim, ["--no-threads", "--speed", "20", "--throttle", "0.125"]);
  try {
    const page = Number(await t.script.exports["armGuard"]?.(0x1357_9bdf, 0x2468_ace0));
    const found = await t.runJob("scanStart", {
      kind: "value",
      value_type: "u64",
      compare: { op: "eq", value: "0x2468ace013579bdf" },
      regions: rw,
    });
    expect(await t.hits(found.scan_id)).toEqual([page + 0x100]);
    const next = await t.runJob("scanNext", { scan_id: found.scan_id, op: "unchanged" });
    expect(next.count).toBe(1);
    const state = (await t.script.exports["guardState"]?.()) as { protect: number; windows: number };
    expect(state.protect).toBe(0x104); // PAGE_READWRITE | PAGE_GUARD: still armed
    expect(state.windows).toBeGreaterThanOrEqual(2);
  } finally {
    await stopTarget(t);
  }
};

describe.skipIf(skip !== false)(`scan agent on game_sim (raw RPCs)${skipNote(skip)}`, () => {
  let gameSim = "";
  beforeAll(async () => {
    frida = await import("frida");
    const manifest = await loadFixtures();
    const artifact = fixtureArtifact(manifest, "game_sim");
    if (artifact === null) throw new Error(`fixtures unavailable: ${JSON.stringify(manifest)}`);
    gameSim = artifact.path;
    pidcheck = fixtureArtifact(manifest, "pidcheck")?.path ?? null;
    bundle = await buildAgent();
  }, 120_000);
  afterAll(async () => {
    if (manager !== undefined) {
      const device = await localDevice();
      for (const pid of owned) {
        await device.kill(pid).catch(() => undefined);
        await waitGone(pid);
      }
      await manager.close();
    }
    if (stage !== "") rmSync(stage, { recursive: true, force: true });
  });

  const rw = { protection: "rw-" };
  it("f32 equilibrium, markers and the static World pointer", async () => {
    const t = await startTarget(gameSim, ["--no-threads", "--speed", "20", "--throttle", "0.125"]);
    try {
      expect(await t.script.exports["features"]?.()).toContain("scan");
      // the TinyCC CModule kernels compiled (not the JS fallback)
      expect(await t.script.exports["kernels"]?.()).toEqual({ native: true, error: null });
      const speed = await t.runJob("scanStart", {
        kind: "value",
        value_type: "f32",
        compare: { op: "eq", value: 20 },
        regions: rw,
      } satisfies ScanStartParams);
      expect(speed.state).toBe("ready");
      expect(await t.hits(speed.scan_id)).toContain(t.car + 8);
      // the hit's stored and current values decode as 20 inside QJS (not "Infinity": see qjsFloats)
      const page = await t.call<Paged<ScanHit>>("scanResults", {
        scan_id: speed.scan_id,
        offset: 0,
        limit: 1000,
        read_current: true,
      });
      expect(page.items.find((h) => Number(h.address) === t.car + 8)).toMatchObject({
        stored: { type: "f32", value: 20, bits: "0x41a00000" },
        current: { type: "f32", value: 20, bits: "0x41a00000" },
      });
      const marker = Number(await t.script.exports["exportAddress"]?.("g_marker"));
      const wmarker = Number(await t.script.exports["exportAddress"]?.("g_wmarker"));
      const utf8 = await t.runJob("scanStart", {
        kind: "value",
        value_type: "utf8",
        compare: { op: "eq", text: "BEA_GAME_SIM_MARKER_v1" },
        regions: { protection: "r--" },
      });
      expect(await t.hits(utf8.scan_id)).toContain(marker);
      const utf16 = await t.runJob("scanStart", {
        kind: "value",
        value_type: "utf16",
        compare: { op: "eq", text: "BEA_GAME_SIM_WIDE_v1" },
        regions: { protection: "r--" },
      });
      expect(await t.hits(utf16.scan_id)).toContain(wmarker);
      const gWorld = Number(await t.script.exports["exportAddress"]?.("g_world"));
      const statics = await t.runJob("scanStart", {
        kind: "pointers-to",
        targets: [`0x${t.world.toString(16)}`],
        regions: { protection: "rw-", modules: ["*"] },
      });
      expect(await t.hits(statics.scan_id)).toEqual([gWorld]);
      for (const id of [speed, utf8, utf16, statics].map((s) => s.scan_id)) await t.call("scanClose", { scan_id: id });
    } finally {
      await stopTarget(t);
    }
  });

  it("scanNext increased after RAMP keeps car+8 and the count drops", async () => {
    const t = await startTarget(gameSim, [
      "--no-threads",
      "--speed",
      "20",
      "--throttle",
      "0.125",
      "--ramp-at-ms",
      "1500",
    ]);
    try {
      const first = await t.runJob("scanStart", {
        kind: "value",
        value_type: "f32",
        compare: { op: "eq", value: 20 },
        regions: rw,
      });
      await t.waitOutput(/RAMP frame=\d+/u);
      await t.waitOutput(/RAMP frame=\d+[\s\S]*FRAME \d+/u, 5_000);
      const up = await t.runJob("scanNext", { scan_id: first.scan_id, op: "increased" });
      expect(up.state).toBe("ready");
      expect(up.count).toBeLessThan(first.count);
      expect(await t.hits(first.scan_id)).toContain(t.car + 8);
    } finally {
      await stopTarget(t);
    }
  });

  it("a 1 GiB ballast scan keeps RPC latency ≤ 50 ms", async () => {
    const t = await startTarget(gameSim, [
      "--no-threads",
      "--speed",
      "20",
      "--throttle",
      "0.125",
      "--ballast-mb",
      "1024",
    ]);
    try {
      const started = await t.call<{ scan_id: string; job_id: string }>("scanStart", {
        kind: "value",
        value_type: "f32",
        compare: { op: "range", min: 19.99, max: 20.01 },
        regions: rw,
      });
      const rtts: number[] = [];
      while (!t.jobs.has(started.job_id)) {
        const t0 = performance.now();
        await t.script.exports["ping"]?.();
        rtts.push(performance.now() - t0);
        await new Promise((r) => setTimeout(r, 5));
      }
      const done = t.jobs.get(started.job_id)?.result as ScanStatus;
      expect(done.bytes_scanned).toBeGreaterThan(1024 * 1024 * 1024);
      expect(await t.hits(done.scan_id)).toContain(t.car + 8);
      rtts.sort((a, b) => a - b);
      if (process.env["BEA_TEST_VERBOSE"] === "1")
        process.stderr
          .write(`[scan latency] pings=${String(rtts.length)} p50=${String(rtts[rtts.length >> 1])} max=${String(rtts.at(-1))} bytes=${String(done.bytes_scanned)}
`);
      expect(rtts.length).toBeGreaterThan(10);
      expect(
        rtts.at(-1),
        `rtt max of ${String(rtts.length)} pings (p50 ${String(rtts[rtts.length >> 1])})`,
      ).toBeLessThanOrEqual(50);
    } finally {
      await stopTarget(t);
    }
  }, 120_000);

  it("float specials in the target's QJS: decoded from bits; native and reference kernels agree with IEEE", () =>
    floatSpecialsCase(gameSim));

  it("finds a value on a BEA-guarded page and leaves the guard armed (CT-I5)", () => guardedPageCase(gameSim));
});
