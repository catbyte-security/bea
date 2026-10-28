import { spawnSync } from "node:child_process";
import { cp, mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { decodeHookRecord, type HookDecoders } from "../../../../src/application/instruments/kinds/hook.js";
import type { JsonValue } from "../../../../src/domain/json.js";
import type { EventRecord } from "../../../../src/ports/recordings.js";
import { BINARY_LAYOUTS } from "../../../../src/shared/binaryLayouts.js";

/**
 * Raw-Frida harness for the WP7 hook engine (DESIGN §8.4 wave rule: raw agent RPCs, no BEA host). Stages ONLY the
 * hook engine's closure (src/agent/hooks.ts, hookNative.ts, pure/hook*.ts, src/shared/**) plus test-local copies of
 * the day-0 core files it imports (state.ts, errors.ts), so concurrent edits of other agent files cannot break it,
 * and compiles a test entry with frida.Compiler. The entry boots a minimal core without hookLink, so the engine runs
 * through its STANDALONE link (own clock CModule, own streams, `instruments.registerExternal`).
 */
const ROOT = resolve(import.meta.dirname, "../../../..");

const STATE_TS = `import type { AgentFeature, AgentLimits, FatalMessage, GateName, ReadyMessage, ThreadId } from "../shared/agentProtocol.js";
export type Phase = "loaded" | "ready" | "shutting-down";
export interface AgentCore {
  readonly t0Wall: number; readonly jsTid: ThreadId; phase: Phase; bootStage: FatalMessage["stage"];
  features: AgentFeature[]; early: ReadyMessage["early"]; gates: Record<GateName, boolean>; limits: AgentLimits;
}
`;
const ERRORS_TS = `import type { AgentError, AgentResult } from "../shared/agentProtocol.js";
export const ok = <T>(value: T): AgentResult<T> => ({ ok: true, value });
export const fail = (error: AgentError): AgentResult<never> => ({ ok: false, error });
`;
const ENTRY_TS = `import { AGENT_LIMIT_DEFAULTS } from "../shared/agentLimits.js";
import type { HookInstallParams } from "../shared/agentProtocol.js";
import * as hooks from "../agent/hooks.js";
import type { AgentCore } from "../agent/state.js";
interface Ext { readonly id: string; info(): unknown; stop(reason: "requested"): unknown }
const externals = new Map<string, Ext>();
const core = {
  t0Wall: Date.now(),
  jsTid: Process.getCurrentThreadId(),
  phase: "ready",
  bootStage: "rpc",
  features: [],
  early: { exception_handler: true, exit_hook: false, last_chance_hook: false, module_observer: false },
  gates: { write_memory: false, override_function: false, call_function: false },
  limits: { ...AGENT_LIMIT_DEFAULTS },
  instruments: { registerExternal: (e: Ext) => void externals.set(e.id, e) },
} as unknown as AgentCore;
hooks.init(core);
const bytesHex = (p: NativePointer, n: number): string => {
  const ab = p.readByteArray(n);
  return ab === null ? "" : Array.from(new Uint8Array(ab), (b) => (b + 0x100).toString(16).slice(1)).join("");
};
rpc.exports = {
  features: () => core.features,
  setLimits: (l: Record<string, number>) => { Object.assign(core.limits, l); return core.limits; },
  hookInstall: (p: HookInstallParams) => hooks.rpc.hookInstall(p),
  stop: (id: string) => externals.get(id)?.stop("requested") ?? null,
  info: (id: string) => externals.get(id)?.info() ?? null,
  exportVa: (mod: string, name: string) => Process.getModuleByName(mod).getExportByName(name).toString(),
  mainBase: () => Process.mainModule.base.toString(),
  read: (va: string, n: number) => bytesHex(ptr(va), n),
};
send({ bea: "test-ready" });
`;

const listHookFiles = async (dir: string): Promise<string[]> =>
  (await readdir(dir)).filter((f) => f.startsWith("hook") && f.endsWith(".ts"));

/** Stage + compile the test agent; returns the bundle source. */
export async function buildRawHookAgent(): Promise<string> {
  const fridaModule = (await import("frida")) as unknown as { default?: unknown };
  const frida = (fridaModule.default ?? fridaModule) as {
    Compiler: new () => {
      diagnostics: { connect(cb: (d: unknown) => void): void };
      build(entry: string, opts: Record<string, unknown>): Promise<string>;
    };
  };
  const stage = await mkdtemp(join(tmpdir(), "bea-wp7-agent-"));
  try {
    await mkdir(join(stage, "agent", "pure"), { recursive: true });
    await mkdir(join(stage, "test"), { recursive: true });
    for (const f of ["hooks.ts", "hookNative.ts"]) await cp(join(ROOT, "src", "agent", f), join(stage, "agent", f));
    for (const f of await listHookFiles(join(ROOT, "src", "agent", "pure")))
      await cp(join(ROOT, "src", "agent", "pure", f), join(stage, "agent", "pure", f));
    await cp(join(ROOT, "src", "shared"), join(stage, "shared"), { recursive: true });
    await writeFile(join(stage, "agent", "state.ts"), STATE_TS);
    await writeFile(join(stage, "agent", "errors.ts"), ERRORS_TS);
    await writeFile(join(stage, "test", "entry.ts"), ENTRY_TS);
    await writeFile(
      join(stage, "tsconfig.json"),
      JSON.stringify({
        compilerOptions: {
          strict: true,
          module: "ES2022",
          moduleResolution: "Bundler",
          target: "ES2022",
          lib: ["ES2022"],
          types: ["frida-gum"],
          verbatimModuleSyntax: true,
          exactOptionalPropertyTypes: true,
          noUncheckedIndexedAccess: true,
          skipLibCheck: true,
          noEmit: true,
        },
        include: ["agent/**/*.ts", "shared/**/*.ts", "test/**/*.ts"],
      }),
    );
    const compiler = new frida.Compiler();
    const diagnostics: unknown[] = [];
    compiler.diagnostics.connect((d) => diagnostics.push(d));
    const bundle = await compiler.build(join(stage, "test", "entry.ts"), {
      projectRoot: stage,
      bundleFormat: "esm",
      typeCheck: "full",
      sourceMaps: "omitted",
      compression: "none",
    });
    if (diagnostics.length > 0)
      throw new Error(
        `raw hook agent diagnostics: ${JSON.stringify(diagnostics, (_k, v: unknown) => (typeof v === "bigint" ? Number(v) : v)).slice(0, 4000)}`,
      );
    return bundle;
  } finally {
    await rm(stage, { recursive: true, force: true });
  }
}

// ------------------------------------------------------------------------------------------------ target session
export interface Batch {
  readonly stream: string;
  readonly instrument: string;
  readonly kind: string;
  readonly enc: "json" | "bin";
  readonly n: number;
  readonly bseq: number;
  readonly final: boolean;
  readonly dropped: Readonly<Record<string, number>>;
  readonly rows?: readonly JsonValue[][];
  readonly data?: Buffer;
}
export interface RawTarget {
  readonly pid: number;
  readonly stdout: () => string;
  readonly batches: Batch[];
  readonly ended: Map<string, Record<string, unknown>>;
  readonly rpc: (method: string, ...args: unknown[]) => Promise<unknown>;
  readonly resume: () => Promise<void>;
  readonly close: () => Promise<void>;
}

interface RawDevice {
  spawn(argv: readonly string[], o: Record<string, unknown>): Promise<number>;
  attach(pid: number): Promise<{
    createScript(
      src: string,
      o: Record<string, unknown>,
    ): Promise<{
      message: {
        connect(cb: (m: { type: string; payload?: unknown; description?: string }, data: Buffer | null) => void): void;
      };
      load(): Promise<void>;
      unload(): Promise<void>;
      exports: Record<string, (...a: unknown[]) => Promise<unknown>>;
    }>;
    detach(): Promise<void>;
  }>;
  resume(pid: number): Promise<void>;
  kill(pid: number): Promise<void>;
  output: { connect(cb: (pid: number, fd: number, data: Buffer) => void): void; disconnect(cb: unknown): void };
}
interface RawDeviceManager {
  getDeviceById(id: string, timeout: number): Promise<RawDevice>;
  close(): Promise<void>;
}

/**
 * One OWNED DeviceManager per test file (never frida.getLocalDevice()'s process-wide manager, which is never closed).
 * Frida copies its agent DLLs (~45 MB) into %TEMP%\frida-<id> and deletes them only at DeviceManager.close(), and
 * only once no process still maps them: every target is fully terminated before `shutdownRawFrida()` (afterAll).
 */
let shared: { readonly dm: RawDeviceManager; readonly device: RawDevice } | null = null;
const rawDevice = async (): Promise<RawDevice> => {
  if (shared === null) {
    const mod = (await import("frida")) as unknown as { default?: unknown };
    const frida = (mod.default ?? mod) as { DeviceManager: new () => RawDeviceManager };
    const dm = new frida.DeviceManager();
    shared = { dm, device: await dm.getDeviceById("local", 2000) };
  }
  return shared.device;
};

/** Close the file's DeviceManager (afterAll, after every target was closed): removes its %TEMP%\frida-<id> copy. */
export async function shutdownRawFrida(): Promise<void> {
  const s = shared;
  shared = null;
  await Promise.race([s?.dm.close().catch(() => undefined), new Promise((r) => setTimeout(r, 10_000))]);
}

/** pidcheck.exe of the fixture manifest: `alive:false` once the process object is signaled. */
let livenessProbe: string | null = null;
export const useLivenessProbe = (pidcheck: string | null): void => {
  livenessProbe = pidcheck;
};
/** Fully terminated: pidcheck's signaled state, else process.kill(pid, 0) → ESRCH (≈ 10 ms early, see S3 notes). */
const terminated = (pid: number): boolean => {
  if (livenessProbe !== null) {
    const run = spawnSync(livenessProbe, [String(pid)], { encoding: "utf8", windowsHide: true, timeout: 5000 });
    if (run.status === 0) return (JSON.parse(run.stdout) as { alive: boolean }).alive === false;
  }
  try {
    process.kill(pid, 0);
    return false;
  } catch (cause) {
    return (cause as NodeJS.ErrnoException).code !== "EPERM";
  }
};
/** Polls (25 ms) until `pid` is fully gone or `timeoutMs` passes (the target unmaps frida-agent.dll only then). */
const waitGone = async (pid: number, timeoutMs: number): Promise<void> => {
  const deadline = performance.now() + timeoutMs;
  while (performance.now() < deadline && !terminated(pid)) await new Promise((r) => setTimeout(r, 25));
};

/** Spawn `argv` (paused), inject the test agent, collect batches / ended messages; resume unless `paused`. */
export async function startRawTarget(
  bundle: string,
  argv: readonly string[],
  opts: { readonly paused?: boolean } = {},
): Promise<RawTarget> {
  const device = await rawDevice();
  const pid = await device.spawn([...argv], { stdio: "pipe" });
  let out = "";
  const onOutput = (p: number, fd: number, data: Buffer): void => {
    if (p === pid && fd === 1) out += data.toString("utf8");
  };
  device.output.connect(onOutput);
  const batches: Batch[] = [];
  const ended = new Map<string, Record<string, unknown>>();
  const errors: string[] = [];
  // Named aliases: `typeof session` right after `= null` is narrowed to null by TS 7, which made the script type never.
  type RawSession = Awaited<ReturnType<typeof device.attach>>;
  type RawScript = Awaited<ReturnType<RawSession["createScript"]>>;
  let session: RawSession | null = null;
  let script: RawScript | null = null;
  const bounded = (p: Promise<unknown> | undefined): Promise<unknown> =>
    Promise.race([p?.catch(() => undefined), new Promise((r) => setTimeout(r, 3000))]);
  /** kill first (owned fixture), then release the script and session; every step bounded */
  const close = async (): Promise<void> => {
    await bounded(device.kill(pid));
    await waitGone(pid, 3000);
    await bounded(script?.unload());
    await bounded(session?.detach());
    device.output.disconnect(onOutput);
  };
  try {
    session = await device.attach(pid);
    script = await session.createScript(bundle, { runtime: "qjs" });
    script.message.connect((m, data) => {
      if (m.type === "error") errors.push(m.description ?? "script error");
      if (m.type !== "send") return;
      const p = m.payload as Record<string, unknown>;
      if (p["bea"] === "batch") batches.push({ ...(p as unknown as Batch), ...(data !== null ? { data } : {}) });
      else if (p["bea"] === "instrument" && p["event"] === "ended")
        ended.set(String(p["id"]), p["detail"] as Record<string, unknown>);
    });
    await script.load();
    if (opts.paused !== true) await device.resume(pid);
  } catch (cause) {
    await close();
    throw cause;
  }
  const s = script;
  return {
    pid,
    stdout: () => out,
    batches,
    ended,
    rpc: async (method, ...args) => {
      if (errors.length > 0) throw new Error(`agent script error: ${errors.join("; ")}`);
      return s.exports[method]?.(...args);
    },
    resume: () => device.resume(pid),
    close,
  };
}

// ------------------------------------------------------------------------------------------------ decoding
const FIELDS = BINARY_LAYOUTS["hook-native/1"].fields;
/** Split a binary batch into hook-native/1 field objects (u64 as decimal strings, like a stream reader may). */
export const nativeRecords = (data: Buffer): Record<string, JsonValue>[] => {
  const out: Record<string, JsonValue>[] = [];
  for (let off = 0; off + 160 <= data.length; off += 160) {
    const rec: Record<string, JsonValue> = {};
    for (const f of FIELDS) {
      const at = off + f.offset;
      rec[f.name] =
        f.type === "u64"
          ? data.readBigUInt64LE(at).toString()
          : f.type === "u32"
            ? data.readUInt32LE(at)
            : f.type === "u16"
              ? data.readUInt16LE(at)
              : data.readUInt8(at);
    }
    out.push(rec);
  }
  return out;
};

/** Decode every batch of `stream` through the production hook kind decoder. */
export const decodeStream = (batches: readonly Batch[], stream: string, decoders: HookDecoders): EventRecord[] => {
  const events: EventRecord[] = [];
  let seq = 0;
  const ctx = {
    sessionId: "raw",
    decoders: decoders as unknown as JsonValue,
    startedAtUs: 0,
    frame: (f: string) => ({ at: f, static: null }),
  };
  for (const b of batches) {
    if (b.stream !== stream) continue;
    const rows: JsonValue[] =
      b.enc === "json" ? [...(b.rows ?? [])] : b.data !== undefined ? nativeRecords(b.data) : [];
    for (const row of rows) events.push(...decodeHookRecord({ seq: ++seq, module_map_epoch: null, fields: row }, ctx));
  }
  return events;
};

export const until = async (cond: () => boolean, timeoutMs: number, stepMs = 25): Promise<boolean> => {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    if (cond()) return true;
    await new Promise((r) => setTimeout(r, stepMs));
  }
  return cond();
};
