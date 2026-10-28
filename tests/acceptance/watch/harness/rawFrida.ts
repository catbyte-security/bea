/**
 * WP9 raw-Frida harness, host side (tests only): stages WP9's agent files + src/shared + the harness entry
 * (harness-agent.ts.txt) + two one-line stubs for the WP3 modules watch.ts imports (state.ts types, disasm.ts), compiles
 * them with frida.Compiler (typeCheck full), spawns or attaches to fixtures this test owns and drives the RPCs.
 * Every process it starts is recorded and killed in close(); nothing else is ever touched. One owned DeviceManager
 * per test file, closed by shutdownRawFrida() (no %TEMP%\frida-<id> left behind).
 */
import { spawnSync } from "node:child_process";
import { cp, mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { makeStagingDir, removeStagingDir } from "../../../../scripts/lib/atomic.mjs";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const WP9_AGENT = ["watch", "trace", "hwbp", "pageguard", "poll", "traceKernels", "watchSafetyNet"];
/** WP9's pure helpers: every src/agent/pure/{watch,trace,dr7}*.ts (the card's ownership pattern). */
const WP9_PURE = /^(?:watch|trace|dr7)[A-Za-z0-9]*\.ts$/u;
/** Diagnostics carry BigInts (frida.Compiler positions); keep them printable. */
const printable = (v: unknown): string =>
  JSON.stringify(v, (_k, x: unknown) => (typeof x === "bigint" ? x.toString() : x)).slice(0, 4000);

interface FridaScript {
  readonly exports: Record<string, (...args: unknown[]) => Promise<unknown>>;
  readonly message: {
    connect(fn: (m: { type: string; payload?: unknown; description?: string }, data: Buffer | null) => void): void;
  };
  logHandler: (level: string, text: string) => void;
  load(): Promise<void>;
  unload(): Promise<void>;
}
interface FridaSession {
  createScript(source: string, options: { runtime: "qjs" }): Promise<FridaScript>;
  detach(): Promise<void>;
  readonly detached: { connect(fn: (reason: string, crash: { summary: string; report: string } | null) => void): void };
}
interface FridaDevice {
  spawn(argv: string[], options: { stdio: "pipe"; cwd?: string }): Promise<number>;
  attach(pid: number): Promise<FridaSession>;
  resume(pid: number): Promise<void>;
  kill(pid: number): Promise<void>;
  readonly output: { connect(fn: (pid: number, fd: number, data: Buffer) => void): void };
}
interface FridaDeviceManager {
  getDeviceById(id: string, timeout: number): Promise<FridaDevice>;
  close(): Promise<void>;
}
interface FridaModule {
  readonly DeviceManager: new () => FridaDeviceManager;
  readonly Compiler: new () => {
    build(entry: string, options: Record<string, unknown>): Promise<string>;
    readonly diagnostics: { connect(fn: (batch: unknown) => void): void };
  };
}

export const loadFrida = async (): Promise<FridaModule> => {
  const mod = (await import("frida")) as unknown as { default?: FridaModule } & FridaModule;
  return mod.default ?? mod;
};

/**
 * One owned DeviceManager per test file (never frida.getLocalDevice(), whose manager is never closed): Frida copies
 * its agent DLLs (~45 MB) into %TEMP%\frida-<id> and deletes them only at DeviceManager.close(), and only once no
 * process maps them any more. Closed by shutdownRawFrida() in afterAll, after every target is gone.
 */
let shared: { readonly dm: FridaDeviceManager; readonly device: FridaDevice } | null = null;
const localDevice = async (frida: FridaModule): Promise<FridaDevice> => {
  if (shared === null) {
    const dm = new frida.DeviceManager();
    shared = { dm, device: await dm.getDeviceById("local", 2000) };
  }
  return shared.device;
};
export const shutdownRawFrida = async (): Promise<void> => {
  const s = shared;
  shared = null;
  await s?.dm.close();
};

/** pidcheck.exe of the fixture manifest: `alive:false` once the process object is signaled (the image unmapped). */
let livenessProbe: string | null = null;
export const useLivenessProbe = (pidcheck: string | null): void => {
  livenessProbe = pidcheck;
};
const terminated = (pid: number): boolean => {
  if (livenessProbe !== null) {
    const run = spawnSync(livenessProbe, [String(pid)], { encoding: "utf8", windowsHide: true, timeout: 5000 });
    if (run.status === 0) return (JSON.parse(run.stdout) as { alive: boolean }).alive === false;
  }
  try {
    process.kill(pid, 0); // reports ESRCH ~10 ms before the process object is signaled
    return false;
  } catch (cause) {
    return (cause as NodeJS.ErrnoException).code !== "EPERM";
  }
};
/** Polls (25 ms, at most `timeoutMs`) until `pid` has fully terminated, so its frida-agent.dll mapping is gone. */
export const waitGone = async (pid: number, timeoutMs: number): Promise<boolean> => {
  const deadline = performance.now() + timeoutMs;
  while (!terminated(pid)) {
    if (performance.now() >= deadline) return false;
    await new Promise<void>((r) => setTimeout(r, 25));
  }
  return true;
};

/** Compile the harness bundle; throws with the compiler diagnostics on any error. */
export const buildHarness = async (frida: FridaModule): Promise<string> => {
  const stage = await makeStagingDir("wp9-harness", repo);
  try {
    await mkdir(join(stage, "agent", "pure"), { recursive: true });
    for (const f of WP9_AGENT) await cp(join(repo, "src", "agent", `${f}.ts`), join(stage, "agent", `${f}.ts`));
    for (const f of (await readdir(join(repo, "src", "agent", "pure"))).filter((n) => WP9_PURE.test(n)))
      await cp(join(repo, "src", "agent", "pure", f), join(stage, "agent", "pure", f));
    await cp(join(repo, "src", "shared"), join(stage, "shared"), { recursive: true });
    await writeFile(join(stage, "agent", "state.ts"), "export interface AgentCore { readonly jsTid: number }\n");
    await writeFile(join(stage, "agent", "disasm.ts"), "export const findAccessInsn = undefined;\n");
    await cp(join(dirname(fileURLToPath(import.meta.url)), "harness-agent.ts.txt"), join(stage, "agent", "harness.ts"));
    const tsconfig = JSON.parse(await readFile(join(repo, "src", "agent", "tsconfig.json"), "utf8")) as Record<
      string,
      unknown
    >;
    tsconfig["include"] = ["agent/**/*.ts", "shared/**/*.ts"];
    await writeFile(join(stage, "tsconfig.json"), JSON.stringify(tsconfig, null, 2));
    const compiler = new frida.Compiler();
    const diagnostics: unknown[] = [];
    compiler.diagnostics.connect((batch) => diagnostics.push(batch));
    let bundle: string;
    try {
      bundle = await compiler.build(join(stage, "agent", "harness.ts"), {
        projectRoot: stage,
        bundleFormat: "esm",
        typeCheck: "full",
        sourceMaps: "omitted",
        compression: "none",
      });
    } catch (cause) {
      throw new Error(`harness build failed: ${String(cause)}\n${printable(diagnostics)}`);
    }
    if (diagnostics.length > 0) throw new Error(`harness diagnostics: ${printable(diagnostics)}`);
    return bundle;
  } finally {
    await removeStagingDir(stage);
  }
};

export interface HarnessMessage {
  readonly type: string;
  readonly [key: string]: unknown;
}
export interface Harnessed {
  readonly pid: number;
  readonly rpc: FridaScript["exports"];
  /** rpc[name](...args), bounded by `ms` */
  call(name: string, ms: number, ...args: unknown[]): Promise<unknown>;
  readonly messages: HarnessMessage[];
  readonly bins: { id: string; data: Buffer }[];
  /** session detach reasons (and the crash summary when Frida saw one) */
  readonly detaches: string[];
  output(): string;
  /** rows received for an instrument (JSON rows flushed every 50 ms by the shim) */
  rows(id: string): unknown[][];
  waitFor(pred: () => boolean, timeoutMs: number): Promise<boolean>;
  close(): Promise<void>;
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** Bounded await: a wedged target or script surfaces as an error naming the step, never a silent test timeout. */
const within = async <T>(ms: number, label: string, work: Promise<T>): Promise<T> => {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      work,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} did not finish within ${String(ms)} ms`)), ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
};

/** Spawn `exe` under Frida (suspended), load the harness, resume, wait for READY on stdout. */
export const spawnHarnessed = async (
  frida: FridaModule,
  bundle: string,
  exe: string,
  args: readonly string[],
): Promise<Harnessed> => {
  const device = await localDevice(frida);
  const pid = await device.spawn([exe, ...args], { stdio: "pipe", cwd: dirname(exe) });
  let out = "";
  device.output.connect((p, _fd, data) => {
    if (p === pid) out += data.toString("utf8");
  });
  const messages: HarnessMessage[] = [];
  const bins: { id: string; data: Buffer }[] = [];
  const detaches: string[] = [];
  let session: FridaSession | null = null;
  let script: FridaScript | null = null;
  /**
   * Kill first (the target is ours and disposable) and wait until it is fully gone, then let Frida tear down; every
   * step is bounded.
   */
  const close = async (): Promise<void> => {
    await within(5000, "kill", device.kill(pid)).catch(() => undefined);
    await waitGone(pid, 3000);
    await within(5000, "unload", script?.unload() ?? Promise.resolve()).catch(() => undefined);
    await within(5000, "detach", session?.detach() ?? Promise.resolve()).catch(() => undefined);
  };
  try {
    session = await device.attach(pid);
    session.detached.connect((reason, crash) =>
      detaches.push(crash === null ? reason : `${reason}: ${crash.summary} ${String(crash.report).slice(0, 2000)}`),
    );
    script = await session.createScript(bundle, { runtime: "qjs" });
    script.logHandler = () => undefined;
    script.message.connect((m, data) => {
      if (m.type !== "send") {
        messages.push({ type: "error", description: m.description ?? "" });
        return;
      }
      const payload = m.payload as HarnessMessage;
      if (payload.type === "bin" && data !== null) bins.push({ id: String(payload["id"]), data });
      else messages.push(payload);
    });
    await script.load();
    await device.resume(pid);
    const t0 = Date.now();
    while (!out.includes("READY") && Date.now() - t0 < 10_000) await sleep(25);
    if (!out.includes("READY")) throw new Error(`fixture did not print READY: ${out.slice(0, 400)}`);
  } catch (cause) {
    await close();
    throw cause;
  }
  const s = script;
  return {
    pid,
    rpc: s.exports,
    call: async (name, ms, ...args) => {
      const fn = s.exports[name];
      if (fn === undefined) throw new Error(`no rpc ${name}`);
      try {
        return await within(ms, `rpc ${name}`, fn(...args));
      } catch (cause) {
        // a destroyed script means the target died or detached: say how (Frida's crash summary when it saw one)
        await sleep(300);
        const errors = messages
          .filter((m) => m.type === "error" || m.type === "unclaimed" || m.type === "fault")
          .map((m) => (m.type === "error" ? String(m["description"]) : JSON.stringify(m)));
        throw new Error(
          `rpc ${name} failed: ${String(cause)}; detaches: ${detaches.join(" | ") || "none"}; ` +
            `script errors: ${errors.join(" | ").slice(0, 1000) || "none"}; fixture output tail: ${out.slice(-300)}`,
          { cause },
        );
      }
    },
    messages,
    bins,
    detaches,
    output: () => out,
    rows: (id) => messages.filter((m) => m.type === "rows" && m["id"] === id).flatMap((m) => m["rows"] as unknown[][]),
    waitFor: async (pred, timeoutMs) => {
      const t0 = Date.now();
      while (!pred() && Date.now() - t0 < timeoutMs) await sleep(25);
      return pred();
    },
    close,
  };
};
