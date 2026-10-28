// =================================================================================================
// tests/support/agent/rawAgent.ts — WP3-AGENT raw-Frida harness (no BEA host, S4 §19 acceptance lane). It plays the
// host's side of the agent protocol directly: spawn (or attach) → createScript(bundle, qjs) with the logHandler and
// message handler connected before load → wait for {bea:"ready"} → hello → resume. It acks crash/exit messages by
// token (record-before-ack is the host's job; here the message is simply kept), posts cumulative flow bytes in the
// agent's units every 100 ms (estimateBytes of JSON rows, binary lengths), collects batches per stream, captures the
// target's output, and can adopt the target into a bea-jobhost job (DIE_ON_UNHANDLED_EXCEPTION, kill-on-close).
// Only processes this harness spawned are ever killed.
// =================================================================================================
import { spawn, spawnSync, type ChildProcess } from "node:child_process";

import type { HelloParams, HelloResult } from "../../../src/shared/agentProtocol.js";
import { estimateBytes } from "../../../src/agent/pure/coreStreams.js";

interface Signal<H> {
  connect(handler: H): void;
  disconnect(handler: H): void;
}
type MessageHandler = (message: { type: string; payload?: unknown; description?: string }, data: Buffer | null) => void;
interface FridaScript {
  load(): Promise<void>;
  unload(): Promise<void>;
  post(message: unknown): void;
  logHandler: (level: string, text: string) => void;
  readonly message: Signal<MessageHandler>;
  readonly exports: Record<string, (...args: unknown[]) => Promise<unknown>>;
}
interface FridaSession {
  createScript(source: string, options: { name: string; runtime: "qjs" }): Promise<FridaScript>;
  detach(): Promise<void>;
  readonly detached: Signal<(reason: string) => void>;
}
interface FridaDevice {
  spawn(argv: string[], options: Record<string, unknown>): Promise<number>;
  attach(pid: number): Promise<FridaSession>;
  resume(pid: number): Promise<void>;
  kill(pid: number): Promise<void>;
  readonly output: Signal<(pid: number, fd: number, data: Buffer) => void>;
}
interface FridaDeviceManager {
  getDeviceById(id: string, timeout: number): Promise<FridaDevice>;
  close(): Promise<void>;
}

const loadFrida = async (): Promise<{ DeviceManager: new () => FridaDeviceManager }> => {
  const mod = (await import("frida")) as unknown as { default?: unknown };
  return (mod.default ?? mod) as { DeviceManager: new () => FridaDeviceManager };
};

/**
 * One DeviceManager per test process, like the host's FridaHost. Observed in this lane: with one manager per agent and
 * the agents kept open until afterAll, RPC round trips in a run slowed from ~1 ms to many seconds; with one shared
 * manager and every agent closed after its test they stay at ~1 ms. Closed by `RawAgent.shutdownFrida()` (afterAll).
 */
let shared: { dm: FridaDeviceManager; device: FridaDevice } | null = null;
const sharedDevice = async (): Promise<{ dm: FridaDeviceManager; device: FridaDevice }> => {
  if (shared === null) {
    const frida = await loadFrida();
    const dm = new frida.DeviceManager();
    shared = { dm, device: await dm.getDeviceById("local", 2000) };
  }
  return shared;
};

export interface AgentRecord {
  readonly at: number;
  readonly payload: Record<string, unknown>;
  readonly data: Buffer | null;
}

export interface JobhostEvent {
  readonly event: string;
  readonly [key: string]: unknown;
}

export const defaultHello = (overrides: Partial<HelloParams> = {}): HelloParams => ({
  protocol: "bea-agent/1",
  min_minor: 0,
  host: { name: "bea", version: "0.1.0-test" },
  session: { session_id: "00000000-0000-4000-8000-000000000003", instance_id: "pi_test", owned: true },
  gates: { write_memory: false, override_function: false, call_function: true },
  limits: { max_instruments: 16 },
  crash: {
    first_chance_rows: true,
    first_chance_blocking: true,
    crash_class: ["access-violation", "illegal-instruction", "stack-overflow", "arithmetic", "abort", "system"],
    ack_timeout_ms: 1000,
    last_chance_ack_timeout_ms: 2000,
    max_blocking_per_10s: 8,
    rows_per_sec: 1000,
    stack_bytes: 256,
    backtrace_depth: 32,
    include_xmm: false,
  },
  streams: { flush_ms: 50, exceptions: true, threads: false },
  flow: { high_water_bytes: 32 * 1024 * 1024, low_water_bytes: 8 * 1024 * 1024 },
  ...overrides,
});

export interface RawAgentOptions {
  readonly bundle: string;
  /** spawn this program (owned, suspended until resume()) … */
  readonly program?: string;
  readonly args?: readonly string[];
  readonly cwd?: string;
  /** … or attach to a running process the TEST started */
  readonly attachPid?: number;
  /** adopt the spawned target into a bea-jobhost job (path of bea-jobhost.exe) */
  readonly jobhost?: string;
  /** ack crash/exit messages (default true) */
  readonly ack?: boolean;
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** pidcheck.exe of the fixture manifest (set by setupAgentLane): `alive` = the process object is not yet signaled. */
let livenessProbe: string | null = null;

/** The process has fully terminated: pidcheck's signaled state, else (no probe) process.kill(pid, 0) → ESRCH. */
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

/**
 * Polls (25 ms) until `pid` has fully terminated or `timeoutMs` passes. The exit code is set at TerminateProcess,
 * but the address space (and frida-agent.dll's mapping) goes away only when the process object is signaled, ~10 ms
 * later; DeviceManager.close() cannot delete Frida's %TEMP%\frida-<id> agent copies (~45 MB) before that.
 */
const waitGone = async (pid: number, timeoutMs: number): Promise<void> => {
  const deadline = performance.now() + timeoutMs;
  while (performance.now() < deadline && !terminated(pid)) await sleep(25);
};

export class RawAgent {
  readonly records: AgentRecord[] = [];
  readonly errors: string[] = [];
  readonly logs: string[] = [];
  readonly detached: string[] = [];
  readonly jobhostEvents: JobhostEvent[] = [];
  readonly acked: string[] = [];
  #output = "";
  #received = 0;
  #flowTimer: ReturnType<typeof setInterval> | null = null;
  #jobhost: ChildProcess | null = null;
  #closed = false;
  readonly #t0 = performance.now();

  private constructor(
    readonly dm: FridaDeviceManager,
    readonly device: FridaDevice,
    readonly pid: number,
    readonly owned: boolean,
    readonly options: RawAgentOptions,
  ) {}

  script!: FridaScript;
  session!: FridaSession;

  /** Spawn/attach, adopt (optional), load the bundle and wait ≤ 5 s for ready (or fatal). Not resumed yet. */
  static async start(options: RawAgentOptions): Promise<RawAgent> {
    const { dm, device } = await sharedDevice();
    let pid: number;
    let owned = false;
    if (options.attachPid !== undefined) pid = options.attachPid;
    else if (options.program !== undefined) {
      pid = await device.spawn([options.program, ...(options.args ?? [])], {
        ...(options.cwd === undefined ? {} : { cwd: options.cwd }),
        stdio: "pipe",
      });
      owned = true;
    } else throw new Error("RawAgent: program or attachPid required");
    const agent = new RawAgent(dm, device, pid, owned, options);
    try {
      await agent.#init();
    } catch (cause) {
      await agent.close();
      throw cause;
    }
    return agent;
  }

  get ready(): Record<string, unknown> | null {
    return this.records.find((r) => r.payload["bea"] === "ready")?.payload ?? null;
  }

  output(): string {
    return this.#output;
  }

  elapsedMs(): number {
    return performance.now() - this.#t0;
  }

  /** Raw RPC (the AgentResult / binary tuple exactly as Frida delivers it). */
  rpc<T = unknown>(method: string, params: unknown = {}): Promise<T> {
    const fn = this.script.exports[method];
    if (fn === undefined) throw new Error(`no export ${method}`);
    return fn(params) as Promise<T>;
  }

  /** rpc() expecting {ok:true}; returns the value. */
  async ok<T = Record<string, unknown>>(method: string, params: unknown = {}): Promise<T> {
    const r = await this.rpc<{ ok: boolean; value?: T; error?: unknown }>(method, params);
    if (r === null || typeof r !== "object" || r.ok !== true) throw new Error(`${method} failed: ${JSON.stringify(r)}`);
    return r.value as T;
  }

  async hello(overrides: Partial<HelloParams> = {}): Promise<HelloResult> {
    return this.ok<HelloResult>("hello", defaultHello(overrides));
  }

  async resume(): Promise<void> {
    if (this.owned) await this.device.resume(this.pid);
  }

  /** A host post (script.post), e.g. {type:"resumed"}. */
  post(message: Record<string, unknown>): void {
    this.script.post(message);
  }

  /** Every message payload with bea === kind. */
  messages(kind: string): Record<string, unknown>[] {
    return this.records.filter((r) => r.payload["bea"] === kind).map((r) => r.payload);
  }

  /** JSON rows of a stream in batch order. */
  rows(stream: string): unknown[][] {
    const out: unknown[][] = [];
    for (const r of this.records)
      if (r.payload["bea"] === "batch" && r.payload["stream"] === stream && r.payload["enc"] === "json")
        out.push(...(r.payload["rows"] as unknown[][]));
    return out;
  }

  async waitFor<T>(probe: () => T | null | undefined | false, timeoutMs: number, stepMs = 25): Promise<T | null> {
    const deadline = performance.now() + timeoutMs;
    for (;;) {
      const v = probe();
      if (v !== null && v !== undefined && v !== false) return v;
      if (performance.now() > deadline) return null;
      await sleep(stepMs);
    }
  }

  /** The liveness probe close() waits with (pidcheck.exe; setupAgentLane sets it from the fixture manifest). */
  static useLivenessProbe(pidcheck: string | null): void {
    livenessProbe = pidcheck;
  }

  /** Close the shared DeviceManager (afterAll of a test file, after every agent was closed). */
  static async shutdownFrida(): Promise<void> {
    const s = shared;
    shared = null;
    await s?.dm.close();
  }

  /** Kill the owned target (never an attached one), detach, stop the jobhost. */
  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    if (this.#flowTimer !== null) clearInterval(this.#flowTimer);
    this.device.output.disconnect(this.#onOutput);
    if (this.owned) {
      try {
        await this.device.kill(this.pid);
      } catch {
        // already gone
      }
      // Frida deletes its %TEMP%\frida-<id> agent copies (~45 MB) at DeviceManager.close(), and cannot while a
      // dying target still maps frida-agent.dll: wait for the process to be fully gone (≤ 3 s) before anyone closes it.
      await waitGone(this.pid, 3000);
    }
    try {
      await this.session?.detach();
    } catch {
      // detached already
    }
    const jobhost = this.#jobhost;
    if (jobhost !== null) {
      jobhost.stdin?.end();
      await new Promise<void>((resolve) => {
        if (jobhost.exitCode !== null) resolve();
        else jobhost.once("exit", () => resolve());
        setTimeout(resolve, 3000);
      });
    }
  }

  readonly #onOutput = (p: number, _fd: number, data: Buffer): void => {
    if (p === this.pid) this.#output += data.toString("utf8");
  };

  async #init(): Promise<void> {
    this.device.output.connect(this.#onOutput);
    if (this.owned && this.options.jobhost !== undefined) await this.#adopt(this.options.jobhost);
    this.session = await this.device.attach(this.pid);
    this.session.detached.connect((reason) => this.detached.push(reason));
    this.script = await this.session.createScript(this.options.bundle, { name: "bea-agent", runtime: "qjs" });
    this.script.logHandler = (level, text) => this.logs.push(`${level}: ${text}`);
    this.script.message.connect((m, data) => this.#onMessage(m, data));
    await this.script.load();
    const ready = await this.waitFor(
      () => this.ready ?? this.records.find((r) => r.payload["bea"] === "fatal") ?? this.errors.length > 0,
      5000,
    );
    if (ready === null) throw new Error("agent did not send ready within 5 s");
    if (this.errors.length > 0) throw new Error(`agent load error: ${this.errors.join("; ")}`);
    this.#flowTimer = setInterval(() => {
      try {
        this.script.post({ type: "flow", received_bytes: this.#received });
      } catch {
        // script gone
      }
    }, 100);
  }

  #onMessage(m: { type: string; payload?: unknown; description?: string }, data: Buffer | null): void {
    if (m.type !== "send") {
      this.errors.push(m.description ?? m.type);
      return;
    }
    const payload = (m.payload ?? {}) as Record<string, unknown>;
    this.records.push({ at: this.elapsedMs(), payload, data });
    if (payload["bea"] === "batch") {
      if (payload["enc"] === "json")
        for (const row of payload["rows"] as unknown[]) this.#received += estimateBytes(row);
      else this.#received += data?.length ?? 0;
    } else if (payload["bea"] === "blob") this.#received += data?.length ?? 0;
    if ((payload["bea"] === "crash" || payload["bea"] === "exit") && this.options.ack !== false) {
      const token = String(payload["ack"]);
      this.acked.push(token);
      this.script.post({ type: "ack", token });
    }
  }

  /** bea-jobhost inspect → adopt <pid> <creation100ns> (status lines on fd3). */
  async #adopt(jobhost: string): Promise<void> {
    const inspect = spawnSync(jobhost, ["inspect", String(this.pid)], {
      encoding: "utf8",
      windowsHide: true,
      timeout: 10_000,
    });
    const info = inspect.stdout
      .split(/\r?\n/u)
      .filter((l) => l.trim().startsWith("{"))
      .map((l) => JSON.parse(l) as JobhostEvent)
      .find((e) => e.event === "inspect");
    if (info === undefined || typeof info["creationTime100ns"] !== "string")
      throw new Error(`jobhost inspect failed: ${inspect.stdout}${inspect.stderr}`);
    const args = ["adopt", String(this.pid), info["creationTime100ns"], "--expect-parent", String(process.pid)];
    const child = spawn(jobhost, args, { stdio: ["pipe", "pipe", "pipe", "pipe"], windowsHide: true });
    this.#jobhost = child;
    let buf = "";
    (child.stdio[3] as NodeJS.ReadableStream).on("data", (d: Buffer) => {
      buf += d.toString("utf8");
      for (let i = buf.indexOf("\n"); i >= 0; i = buf.indexOf("\n")) {
        const line = buf.slice(0, i).trim();
        buf = buf.slice(i + 1);
        if (line.startsWith("{")) this.jobhostEvents.push(JSON.parse(line) as JobhostEvent);
      }
    });
    child.stdout?.resume();
    child.stderr?.resume();
    const adopted = await this.waitFor(
      () => this.jobhostEvents.find((e) => e.event === "adopted" || e.event === "error"),
      10_000,
    );
    if (adopted?.event !== "adopted")
      throw new Error(`jobhost adopt failed: ${JSON.stringify(adopted ?? this.jobhostEvents)}`);
  }
}
