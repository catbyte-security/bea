import { Buffer } from "node:buffer";

import type { BeaError } from "../../../src/domain/errors/beaError.js";
import type { JobHostEvent } from "../../../src/domain/jobhostProtocol.js";
import { err, ok, type Result } from "../../../src/domain/result.js";
import type {
  AdoptRequest,
  JobHostAvailability,
  JobHostFactory,
  JobHostPort,
  JobHostState,
  JobPolicy,
  JobSettlement,
  KillReason,
  ProcessInspection,
  ProcessWatcherPort,
  RootExit,
  WatchRequest,
} from "../../../src/ports/jobhost.js";
import type { DetachReason } from "../../../src/ports/sessions.js";
import type {
  CancellableLike,
  FridaDeviceLike,
  FridaDeviceManagerLike,
  FridaLogLevel,
  FridaMessage,
  FridaModuleLike,
  FridaProcessLike,
  FridaScriptLike,
  FridaSessionLike,
  FridaSpawnOptions,
  SignalLike,
} from "../../../src/providers/frida/fridaPorts.js";
import { AGENT_LIMIT_DEFAULTS } from "../../../src/shared/agentLimits.js";
import type { HelloResult, ReadyMessage } from "../../../src/shared/agentProtocol.js";
import { isoToFiletime100ns } from "../../../src/providers/frida/spawnSession.js";
import { createGate, type Gate } from "./gate.js";

/**
 * Fake Frida binding + fake bea-jobhost (WP4-SESS fast lane, S3 §21). Implements the narrow ports of
 * src/providers/frida/fridaPorts.ts and src/ports/jobhost.ts. Every native call can be held at a named gate
 * (`fake.hold("attach")`), failed (`fake.fail("load", error)`), and is appended to `fake.log` so ordering can be
 * asserted (kills before unloads, dm.close last). Every signal connect/disconnect is counted (`fake.signals`), so a test
 * can assert that every handler was disconnected. The scriptable agent answers the RPCs the session layer uses
 * (hello, listModules, ping, flush, shutdown, readMemory, jobStatus, instrumentStop) and can emit any agent message.
 */
export class FakeSignal<H extends (...args: never[]) => void> implements SignalLike<H> {
  readonly #handlers = new Set<H>();
  readonly #counters: { connected: number; disconnected: number };

  constructor(counters: { connected: number; disconnected: number }) {
    this.#counters = counters;
  }

  connect(handler: H): void {
    this.#counters.connected += 1;
    this.#handlers.add(handler);
  }

  disconnect(handler: H): void {
    if (this.#handlers.delete(handler)) this.#counters.disconnected += 1;
  }

  get size(): number {
    return this.#handlers.size;
  }

  emit(...args: Parameters<H>): void {
    for (const handler of [...this.#handlers]) handler(...args);
  }
}

export class FakeCancellable implements CancellableLike {
  #cancelled = false;
  readonly #listeners = new Set<() => void>();

  get isCancelled(): boolean {
    return this.#cancelled;
  }

  cancel(): void {
    if (this.#cancelled) return;
    this.#cancelled = true;
    for (const listener of [...this.#listeners]) listener();
  }

  onCancel(listener: () => void): () => void {
    if (this.#cancelled) listener();
    else this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }
}

const cancellableOf = (args: readonly unknown[]): FakeCancellable | null => {
  const last = args.at(-1);
  return last instanceof FakeCancellable ? last : null;
};

export interface FakeProcessSpec {
  readonly pid: number;
  readonly name: string;
  readonly path?: string | null;
  readonly ppid?: number | null;
  readonly started?: string | null;
  readonly user?: string | null;
}

interface FakeProcess {
  readonly spec: FakeProcessSpec;
  alive: boolean;
  suspended: boolean;
  readonly sessions: FakeSession[];
  readonly env: Readonly<Record<string, string>> | null;
}

export type FakeRpcHandler = (params: Record<string, unknown>, script: FakeScript) => unknown;

export interface FakeAgentBehavior {
  /** false: never send ready; an object: fields merged into the ready message */
  readonly ready?: Partial<ReadyMessage> | false;
  /** a load-time script error (sent before ready) */
  readonly loadError?: string;
  readonly rpc?: Readonly<Record<string, FakeRpcHandler>>;
}

export class FakeScript implements FridaScriptLike {
  readonly fake: FakeFrida;
  readonly session: FakeSession;
  readonly name: string;
  readonly source: string;
  readonly posts: unknown[] = [];
  readonly message: FakeSignal<(message: FridaMessage, data: Buffer | null) => void>;
  readonly destroyed: FakeSignal<() => void>;
  /** set when a log line reached the DEFAULT handler (would have gone to stdout) */
  defaultLogUsed = false;
  logHandler: (level: FridaLogLevel, text: string) => void = () => {
    this.defaultLogUsed = true;
  };
  #destroyed = false;
  readonly #pending = new Set<(cause: Error) => void>();

  constructor(fake: FakeFrida, session: FakeSession, name: string, source: string) {
    this.fake = fake;
    this.session = session;
    this.name = name;
    this.source = source;
    this.message = new FakeSignal(fake.signals);
    this.destroyed = new FakeSignal(fake.signals);
  }

  get isDestroyed(): boolean {
    return this.#destroyed;
  }

  get pid(): number {
    return this.session.pid;
  }

  readonly exports: Readonly<Record<string, (...args: unknown[]) => Promise<unknown>>> = new Proxy(
    {},
    {
      get: (_target, property) =>
        typeof property !== "string" || property === "then"
          ? undefined
          : (...args: unknown[]) => this.#rpc(property, args),
    },
  );

  async load(): Promise<void> {
    await this.fake.step("load", this.pid);
    if (this.name !== "bea-agent") return;
    const behavior = this.fake.agentFor(this.pid);
    setImmediate(() => {
      if (behavior.loadError !== undefined) {
        this.emit({ type: "error", description: behavior.loadError, lineNumber: 7 });
        return;
      }
      if (behavior.ready === false) return;
      this.emitPayload({ ...this.fake.readyMessage(this.pid), ...behavior.ready });
    });
  }

  async unload(): Promise<void> {
    await this.fake.step("unload", this.pid);
    this.destroy();
  }

  post(message: unknown): void {
    if (this.#destroyed) throw new Error("Script is destroyed");
    this.posts.push(message);
  }

  /** Test helpers: deliver a message as Frida would (synchronously, like a signal emission). */
  emit(message: FridaMessage, data: Buffer | null = null): void {
    if (!this.#destroyed) this.message.emit(message, data);
  }

  emitPayload(payload: unknown, data: Buffer | null = null): void {
    this.emit({ type: "send", payload }, data);
  }

  log(level: FridaLogLevel, text: string): void {
    this.logHandler(level, text);
  }

  destroy(): void {
    if (this.#destroyed) return;
    this.#destroyed = true;
    for (const reject of [...this.#pending]) reject(new Error("Script is destroyed"));
    this.destroyed.emit();
  }

  async #rpc(method: string, args: unknown[]): Promise<unknown> {
    if (this.#destroyed) throw new Error("Script is destroyed");
    const cancellable = cancellableOf(args);
    const params = (args[0] ?? {}) as Record<string, unknown>;
    this.fake.log.push(`rpc:${method}:${String(this.pid)}`);
    const handler = this.fake.agentFor(this.pid).rpc?.[method] ?? this.fake.defaultRpc[method];
    return new Promise((resolve, reject) => {
      let offCancel: (() => void) | undefined;
      let done = false;
      const settle = (fn: () => void): void => {
        if (done) return;
        done = true;
        this.#pending.delete(fail);
        offCancel?.();
        fn();
      };
      const fail = (cause: Error): void => settle(() => reject(cause));
      this.#pending.add(fail);
      offCancel = cancellable?.onCancel(() => fail(new Error("Operation was cancelled")));
      const gate = this.fake.gates.get(`rpc:${method}`);
      void (gate === undefined ? Promise.resolve() : gate.wait()).then(async () => {
        if (handler === undefined) {
          fail(new Error(`unable to find method '${method}'`));
          return;
        }
        try {
          const value = await handler(params, this);
          settle(() => resolve(value));
        } catch (cause) {
          fail(cause instanceof Error ? cause : new Error(String(cause)));
        }
      });
    });
  }
}

export class FakeSession implements FridaSessionLike {
  readonly fake: FakeFrida;
  readonly pid: number;
  readonly detached: FakeSignal<(reason: DetachReason, crash: unknown) => void>;
  readonly scripts: FakeScript[] = [];
  #detached = false;

  constructor(fake: FakeFrida, pid: number) {
    this.fake = fake;
    this.pid = pid;
    this.detached = new FakeSignal(fake.signals);
  }

  isDetached(): boolean {
    return this.#detached;
  }

  async detach(): Promise<void> {
    await this.fake.step("detach", this.pid);
    this.markDetached("application-requested");
  }

  async createScript(
    source: string,
    options: { readonly name: string; readonly runtime: "qjs" | "v8" },
  ): Promise<FridaScriptLike> {
    await this.fake.step("createScript", this.pid);
    if (this.#detached) throw new Error("session is gone");
    if (source.includes("SYNTAX_ERROR")) throw new Error("Script(line 3): SyntaxError: unexpected token");
    const script = new FakeScript(this.fake, this, options.name, source);
    this.scripts.push(script);
    return script;
  }

  markDetached(reason: DetachReason): void {
    if (this.#detached) return;
    this.#detached = true;
    for (const script of this.scripts) script.destroy();
    this.detached.emit(reason, null);
  }
}

export class FakeFrida {
  readonly log: string[] = [];
  readonly signals = { connected: 0, disconnected: 0 };
  /** every options object passed to device.enumerateProcesses (S3 §21 case 11: never a pid-filtered liveness probe) */
  readonly enumerateOptions: unknown[] = [];
  /** process.env.TEMP at each device.attach (LIFE-3: Frida extracts its agent into TEMP at the first injection) */
  readonly attachTemp: (string | undefined)[] = [];
  readonly gates = new Map<string, Gate>();
  readonly failures = new Map<string, Error>();
  readonly processes = new Map<number, FakeProcess>();
  readonly output: FakeSignal<(pid: number, fd: number, data: Buffer) => void>;
  readonly behaviors = new Map<number, FakeAgentBehavior>();
  defaultBehavior: FakeAgentBehavior = {};
  /** build id the fake agent reports (must match the bundle the host loaded) */
  buildId = "fake-build-0001";
  nextPid = 4000;
  /** spawn resolves only after this gate when set (guard-expiry tests) */
  dmClosed = false;
  readonly defaultRpc: Record<string, FakeRpcHandler>;

  constructor() {
    this.output = new FakeSignal(this.signals);
    this.defaultRpc = {
      hello: (_p, script) => ({ ok: true, value: this.helloResult(script.pid) }),
      ping: () => ({ ok: true, value: { t: 1, g: 1, phase: "ready" } }),
      flush: () => ({ ok: true, value: { batches: 0, rows: 0 } }),
      listModules: (_p, script) => ({
        ok: true,
        value: { module_map_epoch: 1, modules: [this.mainModule(script.pid)] },
      }),
      shutdown: () => ({
        ok: true,
        value: { stopped: [], unreverted: [], scans_freed: 0, jobs_cancelled: 0, final_batches: 0 },
      }),
      readMemory: (params) => [
        {
          ok: true,
          value: {
            address: params["address"],
            requested: 16,
            returned: 16,
            complete: true,
            stop: null,
            bea_guard_suspended: [],
          },
        },
        Buffer.from("MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00", "latin1"),
      ],
      jobStatus: (params) => ({
        ok: false,
        error: { _tag: "NotFound", message: "no such job", what: "job", id: String(params["job_id"]) },
      }),
      instrumentStop: () => ({ ok: true, value: { stopped: [], not_found: [], unreverted: [] } }),
    };
  }

  /** Hold every later call of `name` (e.g. "attach", "load", "rpc:hello") until the gate is released. */
  hold(name: string): Gate {
    const gate = createGate();
    this.gates.set(name, gate);
    return gate;
  }

  fail(name: string, cause: Error): void {
    this.failures.set(name, cause);
  }

  agentFor(pid: number): FakeAgentBehavior {
    return this.behaviors.get(pid) ?? this.defaultBehavior;
  }

  /** gate → injected failure → log */
  async step(name: string, pid: number | null): Promise<void> {
    const gate = this.gates.get(name);
    if (gate !== undefined) await gate.wait();
    const failure = this.failures.get(name);
    if (failure !== undefined) throw failure;
    this.log.push(pid === null ? name : `${name}:${String(pid)}`);
  }

  addProcess(spec: FakeProcessSpec): void {
    this.processes.set(spec.pid, { spec, alive: true, suspended: false, sessions: [], env: null });
  }

  process(pid: number): FakeProcess | undefined {
    return this.processes.get(pid);
  }

  /** The process ends: every session detaches with process-terminated (kill, exit and crash look alike). */
  terminate(pid: number): void {
    const process = this.processes.get(pid);
    if (process === undefined || !process.alive) return;
    process.alive = false;
    for (const session of process.sessions) session.markDetached("process-terminated");
  }

  sessionsOf(pid: number): readonly FakeSession[] {
    return this.processes.get(pid)?.sessions ?? [];
  }

  agentScript(pid: number): FakeScript | undefined {
    return this.sessionsOf(pid)
      .flatMap((s) => s.scripts)
      .find((script) => script.name === "bea-agent");
  }

  mainModule(pid: number): { name: string; path: string; base: `0x${string}`; size: number; pe: null } {
    const path = this.processes.get(pid)?.spec.path ?? `C:\\fake\\${String(pid)}.exe`;
    return { name: path.slice(path.lastIndexOf("\\") + 1), path, base: "0x7ff6a0000000", size: 0x40000, pe: null };
  }

  readyMessage(pid: number): ReadyMessage {
    return {
      bea: "ready",
      protocol: "bea-agent/1",
      protocol_minor: 0,
      agent_version: "0.1.0",
      build_id: this.buildId,
      frida_version: "17.23.2",
      runtime: "QJS",
      pid,
      arch: "x64",
      platform: "windows",
      js_thread_id: 7,
      t0_wall_ms: 1_700_000_000_000,
      features: ["crash.first-chance"],
      early: { exception_handler: true, exit_hook: true, last_chance_hook: true, module_observer: true },
    };
  }

  helloResult(pid: number): HelloResult {
    const main = this.mainModule(pid);
    return {
      protocol: "bea-agent/1",
      protocol_minor: 0,
      agent_version: "0.1.0",
      build_id: this.buildId,
      frida_version: "17.23.2",
      runtime: "QJS",
      process: {
        pid,
        arch: "x64",
        platform: "windows",
        page_size: 4096,
        pointer_size: 8,
        main_module: main,
        peb: "0x1000",
        current_dir: "C:\\fake",
        debugger_present: false,
        code_signing_policy: "optional",
        frida_heap_bytes: 1024,
        js_thread_id: 7,
        module_map_epoch: 1,
      },
      limits: { ...AGENT_LIMIT_DEFAULTS, max_instruments: 16 },
      features: ["crash.first-chance"],
      deny_list: [],
      caution_list: [],
      system_streams: { exceptions: "s:exceptions", modules: "s:modules", threads: "s:threads" },
      module_map_epoch: 1,
      boot: { t_us: 10, early_rows: 0 },
    };
  }

  module(version = "17.23.2"): FridaModuleLike {
    return {
      version,
      createDeviceManager: () => this.#deviceManager(),
      createCancellable: () => new FakeCancellable(),
    };
  }

  #deviceManager(): FridaDeviceManagerLike {
    return {
      getDeviceById: async () => {
        await this.step("getDevice", null);
        return this.device();
      },
      close: async () => {
        await this.step("dm.close", null);
        this.dmClosed = true;
      },
    };
  }

  device(): FridaDeviceLike {
    return {
      id: "local",
      spawn: async (argv: readonly string[], options: FridaSpawnOptions) => {
        await this.step("spawn", null);
        const pid = (this.nextPid += 4);
        this.processes.set(pid, {
          spec: {
            pid,
            name: (argv[0] ?? "").slice((argv[0] ?? "").lastIndexOf("\\") + 1),
            path: argv[0] ?? null,
            ppid: process.pid,
            started: "2026-10-28T10:00:00.123456Z",
          },
          alive: true,
          suspended: true,
          sessions: [],
          env: options.envp,
        });
        this.log.push(`spawned:${String(pid)}`);
        return pid;
      },
      resume: async (pid: number) => {
        await this.step("resume", pid);
        const p = this.processes.get(pid);
        if (p === undefined || !p.alive) throw new Error("process not found");
        p.suspended = false;
      },
      kill: async (pid: number) => {
        await this.step("frida.kill", pid);
        this.terminate(pid);
      },
      attach: async (pid: number, cancellable?: CancellableLike | null) => {
        void cancellable;
        this.attachTemp.push(process.env["TEMP"]);
        await this.step("attach", pid);
        const p = this.processes.get(pid);
        if (p === undefined || !p.alive) throw new Error("unable to find process with pid");
        const session = new FakeSession(this, pid);
        p.sessions.push(session);
        return session;
      },
      enumerateProcesses: async (options?: unknown) => {
        this.enumerateOptions.push(options ?? null);
        await this.step("enumerate", null);
        return [...this.processes.values()]
          .filter((p) => p.alive)
          .map((p): FridaProcessLike => ({
            pid: p.spec.pid,
            name: p.spec.name,
            parameters: {
              ...(p.spec.path === undefined || p.spec.path === null ? {} : { path: p.spec.path }),
              ...(p.spec.ppid === undefined || p.spec.ppid === null ? {} : { ppid: BigInt(p.spec.ppid) }),
              ...(p.spec.started === undefined || p.spec.started === null ? {} : { started: p.spec.started }),
              ...(p.spec.user === undefined || p.spec.user === null ? {} : { user: p.spec.user }),
            },
          }));
      },
      querySystemParameters: async () => ({
        os: { id: "windows", version: "10.0.26200" },
        arch: "x64",
        access: "full",
      }),
      output: this.output,
    };
  }
}

// ---------------------------------------------------------------- fake bea-jobhost (S3 §21 "FakeJobHost")
const POLICY: JobPolicy = {
  killOnClose: true,
  dieOnUnhandledException: true,
  breakawayAllowed: false,
  memLimitBytes: null,
};

class Listeners {
  readonly #set = new Set<(e: JobHostEvent) => void>();
  on(listener: (e: JobHostEvent) => void): () => void {
    this.#set.add(listener);
    return () => this.#set.delete(listener);
  }
  emit(event: JobHostEvent): void {
    for (const listener of [...this.#set]) listener(event);
  }
  get size(): number {
    return this.#set.size;
  }
}

export class FakeJobHost implements JobHostPort {
  readonly helperPid: number;
  readonly rootPid: number;
  readonly creationTime100ns: bigint;
  readonly imagePath: string | null;
  readonly policy = POLICY;
  readonly wasInJob = false;
  state: JobHostState = "contained";
  rootExit: RootExit | null = null;
  lastActive: number | null = 1;
  readonly settled: Promise<JobSettlement>;
  readonly listeners = new Listeners();
  readonly stdin = null;
  readonly stdout = null;
  readonly stderr = null;
  killReasons: KillReason[] = [];
  /** the kill never settles (escalation tests) */
  stuck = false;
  #resolveSettled: (s: JobSettlement) => void = () => undefined;
  #kill: Promise<JobSettlement> | null = null;
  readonly #fake: FakeFrida;

  constructor(fake: FakeFrida, req: AdoptRequest, helperPid: number, skew100ns = 0n) {
    this.#fake = fake;
    this.helperPid = helperPid;
    this.rootPid = req.pid;
    // like the real helper: the creation time READ from the adopted process (its Frida `started`), else the request's
    const started = isoToFiletime100ns(fake.process(req.pid)?.spec.started)?.value;
    this.creationTime100ns =
      skew100ns + (started ?? (req.creationTime100ns === 0n ? 133_000_000_000_000_000n : req.creationTime100ns));
    this.imagePath = req.expectImage;
    this.settled = new Promise((resolve) => {
      this.#resolveSettled = resolve;
    });
  }

  on(listener: (e: JobHostEvent) => void): () => void {
    return this.listeners.on(listener);
  }

  resume(): Result<void, BeaError> {
    return ok(undefined);
  }

  requestStatus(): void {
    this.listeners.emit({
      event: "status",
      rootAlive: this.rootExit === null,
      active: this.lastActive ?? 0,
      elapsedMs: 1,
    });
  }

  /** The root exits on its own (natural exit or crash) with `code`; `stragglers` stay in the job. */
  exitRoot(code: number, stragglers = 0): void {
    if (this.rootExit !== null) return;
    this.rootExit = {
      code,
      codeHex: `0x${code.toString(16).toUpperCase()}`,
      byKill: false,
      activeAfterRoot: stragglers,
      at: 0,
    };
    this.state = "root-exited";
    this.lastActive = stragglers;
    this.#fake.terminate(this.rootPid);
    this.listeners.emit({
      event: "root-exit",
      pid: this.rootPid,
      code,
      codeHex: this.rootExit.codeHex,
      activeAfterRoot: stragglers,
      byKill: false,
    });
  }

  procStart(pid: number): void {
    this.listeners.emit({ event: "proc-start", pid });
  }

  kill(reason: KillReason, escalateAfterMs: number): Promise<JobSettlement> {
    this.killReasons.push(reason);
    this.#kill ??= (async () => {
      this.#fake.log.push(`jobhost.kill:${String(this.rootPid)}`);
      this.state = "killing";
      const activeBefore = this.lastActive;
      if (this.stuck) {
        await new Promise((resolve) => setTimeout(resolve, escalateAfterMs));
        const settlement: JobSettlement = {
          method: "helper-terminated",
          observation: "timed-out-with-active",
          activeBefore,
          active: activeBefore,
          peakJobMemoryBytes: null,
          helperExitCode: null,
          outputComplete: true,
          elapsedMs: escalateAfterMs,
        };
        this.#kill = null; // a stuck kill is retried by the next caller (closeAll retry)
        return settlement;
      }
      if (this.rootExit === null) {
        this.rootExit = { code: 0xbea, codeHex: "0xBEA", byKill: true, activeAfterRoot: 0, at: 0 };
        this.listeners.emit({
          event: "killed",
          reason: "control",
          activeBefore: activeBefore ?? 0,
          ok: true,
          win32: 0,
        });
        this.#fake.terminate(this.rootPid);
        this.listeners.emit({
          event: "root-exit",
          pid: this.rootPid,
          code: 0xbea,
          codeHex: "0xBEA",
          activeAfterRoot: 0,
          byKill: true,
        });
      }
      this.state = "settled";
      this.lastActive = 0;
      this.listeners.emit({ event: "settled", active: 0, timedOut: false, peakJobMemoryBytes: 0, elapsedMs: 3 });
      const settlement: JobSettlement = {
        method: "control-kill",
        observation: "observed-zero-active",
        activeBefore,
        active: 0,
        peakJobMemoryBytes: 0,
        helperExitCode: 0xbea,
        outputComplete: true,
        elapsedMs: 3,
      };
      this.#resolveSettled(settlement);
      return settlement;
    })();
    return this.#kill;
  }
}

export class FakeWatcher implements ProcessWatcherPort {
  readonly helperPid: number;
  readonly pid: number;
  readonly creationTime100ns: bigint;
  readonly imagePath: string | null;
  rootExit: RootExit | null = null;
  readonly exited: Promise<RootExit | null>;
  readonly listeners = new Listeners();
  stopped = false;
  #resolve: (r: RootExit | null) => void = () => undefined;
  readonly #fake: FakeFrida;

  constructor(fake: FakeFrida, req: WatchRequest, helperPid: number, imagePath: string | null) {
    this.#fake = fake;
    this.helperPid = helperPid;
    this.pid = req.pid;
    this.creationTime100ns = req.creationTime100ns;
    this.imagePath = imagePath;
    this.exited = new Promise((resolve) => {
      this.#resolve = resolve;
    });
  }

  on(listener: (e: JobHostEvent) => void): () => void {
    return this.listeners.on(listener);
  }

  async stop(): Promise<void> {
    this.#fake.log.push(`watcher.stop:${String(this.pid)}`);
    this.stopped = true;
    this.#resolve(null);
  }

  exitRoot(code: number): void {
    this.rootExit = { code, codeHex: `0x${code.toString(16)}`, byKill: false, activeAfterRoot: null, at: 0 };
    this.#fake.terminate(this.pid);
    this.listeners.emit({
      event: "root-exit",
      pid: this.pid,
      code,
      codeHex: this.rootExit.codeHex,
      activeAfterRoot: null,
      byKill: false,
    });
    this.#resolve(this.rootExit);
  }
}

export class FakeJobHostFactory implements JobHostFactory {
  readonly hosts: FakeJobHost[] = [];
  readonly watchers: FakeWatcher[] = [];
  readonly inspections = new Map<number, Partial<ProcessInspection>>();
  adoptError: BeaError | null = null;
  adoptRequests: AdoptRequest[] = [];
  /** added to the creation time the helper reports (a pid-reuse identity mismatch) */
  creationSkew100ns = 0n;
  #helper = 9000;
  readonly #fake: FakeFrida;

  constructor(fake: FakeFrida) {
    this.#fake = fake;
  }

  availability(): JobHostAvailability {
    return { state: "available", sha256: "0".repeat(64), reason: null, probe: null };
  }

  hostOf(pid: number): FakeJobHost | undefined {
    return this.hosts.find((h) => h.rootPid === pid);
  }

  watcherOf(pid: number): FakeWatcher | undefined {
    return this.watchers.find((w) => w.pid === pid);
  }

  async adopt(req: AdoptRequest): Promise<Result<JobHostPort, BeaError>> {
    this.adoptRequests.push(req);
    await this.#fake.step("adopt", req.pid);
    if (this.adoptError !== null) return err(this.adoptError);
    const host = new FakeJobHost(this.#fake, req, (this.#helper += 1), this.creationSkew100ns);
    this.hosts.push(host);
    return ok(host);
  }

  async spawn(): Promise<Result<JobHostPort, BeaError>> {
    return err({
      _tag: "CapabilityUnavailable",
      operation: "jobhost.spawn",
      capability: "jobhost",
      reason: "not-faked",
      retryable: false,
    });
  }

  async watch(req: WatchRequest): Promise<Result<ProcessWatcherPort, BeaError>> {
    await this.#fake.step("watch", req.pid);
    const watcher = new FakeWatcher(
      this.#fake,
      req,
      (this.#helper += 1),
      this.#fake.process(req.pid)?.spec.path ?? null,
    );
    this.watchers.push(watcher);
    return ok(watcher);
  }

  async inspect(pid: number): Promise<Result<ProcessInspection, BeaError>> {
    await this.#fake.step("inspect", pid);
    const known = this.#fake.process(pid);
    return ok({
      pid,
      access: "limited+synchronize",
      exited: known === undefined ? null : !known.alive,
      exitCode: null,
      creationTime100ns: 133_000_000_000_000_000n + BigInt(pid),
      imagePath: known?.spec.path ?? null,
      parentPid: known?.spec.ppid ?? null,
      osSessionId: 1,
      critical: false,
      protectionLevel: 0xffff_fffe,
      protected: false,
      wow64: false,
      processMachine: 0,
      nativeMachine: 0x8664,
      inJob: false,
      elevated: false,
      integrityRid: 0x2000,
      sameUser: true,
      ...this.inspections.get(pid),
    });
  }

  async probe(): Promise<Result<never, BeaError>> {
    return err({
      _tag: "CapabilityUnavailable",
      operation: "jobhost.probe",
      capability: "jobhost",
      reason: "not-faked",
      retryable: false,
    });
  }
}
