import { spawn as nodeSpawn, type ChildProcess, type SpawnOptions } from "node:child_process";
import { mkdir } from "node:fs/promises";

import {
  EMU_PROTOCOL,
  type BridgeErrorBody,
  type EmuMethod,
  type EmuMethods,
  type FatalEvent,
  type HelloResult,
  type ProgressEvent,
  type ReadyEvent,
  type RequestId,
} from "../../domain/emuProtocol.js";
import type { Logger } from "../../domain/logger.js";
import { err, ok, type Result } from "../../domain/result.js";
import { encodeFrame, FrameTooLarge, NdjsonSplitter } from "./framing.js";

/**
 * One bridge process and its bea-emu/0.1 client (S5 §5.2, CT-M9). Spawned NON-detached (libuv's job kills the
 * direct child; launchers kill the interpreter, VERIFIED S5-E2/E2b), never through jobhost (D-INT-11). Lifetime:
 * `bridge.shutdown` -> stdin EOF -> `child.kill()` at 900 ms, inside the 1,300 ms teardown-targets budget.
 * Requests are matched by id; queued methods answer in order, `bridge.cancel`/`bridge.ping` out of band. A request
 * whose signal aborts or whose deadline (+1 s backstop) passes is cancelled; a bridge that ignores the cancel for
 * `cancelGraceMs` is killed and every pending request resolves `bridge_lost`. Outcomes (faults, stops) are results;
 * an `error` frame means the request could not be attempted.
 */
export type SpawnFn = (command: string, args: readonly string[], options: SpawnOptions) => ChildProcess;

export interface PythonCommand {
  readonly command: string;
  /** e.g. ["-3"] for `py`; the bridge flags `-I -X utf8 <bridge>` always follow */
  readonly prefixArgs: readonly string[];
}
export interface BridgeArtifact {
  /** absolute path of bea_emu_bridge.py */
  readonly path: string;
  /** expected sha256 of the bridge file (dist/bridge-manifest.json) */
  readonly sha256: string;
  /** expected bridge version (= package version) */
  readonly version: string;
}

export interface EmuBridgeOptions {
  readonly python: PythonCommand;
  readonly bridge: BridgeArtifact;
  readonly memoryLimitBytes: number;
  readonly cacheDir: string | null;
  /** BEA-owned working directory (<BEA_HOME>/emu), created before spawning */
  readonly cwd: string;
  readonly clientVersion: string;
  readonly startupTimeoutMs?: number;
  /** shutdown -> EOF -> kill escalation (CT-M9: 900 ms) */
  readonly killAfterMs?: number;
  readonly cancelGraceMs?: number;
  /** a request's own deadline is enforced by the bridge; this backstop cancels it from the host */
  readonly deadlineBackstopMs?: number;
  readonly stderrHeadBytes?: number;
  readonly stderrTailBytes?: number;
}
export interface EmuBridgeDeps {
  readonly spawn?: SpawnFn;
  /** monotonic milliseconds (performance.now based, like EmuRequestOptions.deadlineAt) */
  readonly now: () => number;
  readonly logger: Logger;
  readonly env?: Readonly<Record<string, string | undefined>>;
}

export type BridgeExitReason = "shutdown" | "eof" | "killed" | "crashed" | "protocol_violation" | "startup_failed";
export interface BridgeExit {
  readonly code: number | null;
  readonly signal: string | null;
  readonly reason: BridgeExitReason;
  /** bridge stderr tail (debug logs only; never projected into errors) */
  readonly stderrTail: string;
}
export type EmuStartError =
  | { readonly kind: "spawn_failed"; readonly message: string }
  | { readonly kind: "engine_unavailable"; readonly missing: readonly string[] | null }
  | { readonly kind: "exited"; readonly exit: BridgeExit }
  | { readonly kind: "timeout"; readonly afterMs: number }
  | {
      readonly kind: "version_mismatch";
      readonly field: "protocol" | "sha256" | "version";
      readonly expected: string;
      readonly actual: string | null;
    }
  | { readonly kind: "cancelled" };
export type EmuRequestFailure =
  | { readonly kind: "bridge_error"; readonly error: BridgeErrorBody }
  | { readonly kind: "bridge_lost"; readonly exit: BridgeExit }
  /** the final frame that arrived after the auto-cancel, if any (partial batch results are preserved) */
  | { readonly kind: "deadline"; readonly partial: unknown }
  | { readonly kind: "cancelled"; readonly partial: unknown }
  /** the host could not encode the frame (non-finite number, > 64 MiB): a host bug */
  | { readonly kind: "local"; readonly reason: string };
export interface BridgeRequestOptions {
  readonly signal?: AbortSignal;
  /** monotonic ms; the host cancels the request at deadlineAt + deadlineBackstopMs */
  readonly deadlineAt?: number;
  readonly onProgress?: (event: ProgressEvent) => void;
}

const DEFAULTS = {
  startupTimeoutMs: 15_000,
  killAfterMs: 900,
  cancelGraceMs: 2_000,
  deadlineBackstopMs: 1_000,
  stderrHeadBytes: 16_384,
  stderrTailBytes: 49_152,
} as const;
/** after the kill: how long close() waits for the exit event before reporting it synthetically */
const POST_KILL_WAIT_MS = 300;

interface Pending {
  readonly method: EmuMethod;
  readonly resolve: (outcome: Result<unknown, EmuRequestFailure>) => void;
  readonly onProgress: ((event: ProgressEvent) => void) | undefined;
  why: "deadline" | "cancelled" | null;
  readonly timers: ReturnType<typeof setTimeout>[];
  detach: () => void;
}

/** Head + tail bounded capture that always drains (S3 §15 pattern). */
class StderrCapture {
  #head = "";
  #tail = "";
  #dropped = 0;
  constructor(
    private readonly headBytes: number,
    private readonly tailBytes: number,
  ) {}
  push(text: string): void {
    if (this.#head.length < this.headBytes) {
      const room = this.headBytes - this.#head.length;
      this.#head += text.slice(0, room);
      text = text.slice(room);
    }
    if (text.length === 0) return;
    this.#tail += text;
    if (this.#tail.length > this.tailBytes) {
      this.#dropped += this.#tail.length - this.tailBytes;
      this.#tail = this.#tail.slice(-this.tailBytes);
    }
  }
  tail(maxBytes: number): string {
    const all = this.#dropped > 0 ? `${this.#head}\n…\n${this.#tail}` : this.#head + this.#tail;
    return all.length > maxBytes ? all.slice(-maxBytes) : all;
  }
}

/** Copy of the environment without PYTHON* keys (defence in depth; `-I` already ignores them). */
const bridgeEnv = (env: Readonly<Record<string, string | undefined>>): Record<string, string> => {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) if (value !== undefined && !/^PYTHON/iu.test(key)) out[key] = value;
  return out;
};

/** argv after the command: prefix args, the isolation flags, the bridge, its memory cap and cache dir (S5 §3.1). */
const bridgeArgs = (options: EmuBridgeOptions): string[] => [
  ...options.python.prefixArgs,
  "-I",
  "-X",
  "utf8",
  options.bridge.path,
  "--mem-limit",
  String(options.memoryLimitBytes),
  ...(options.cacheDir === null ? [] : ["--cache-dir", options.cacheDir]),
];

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null;

export class EmuBridge {
  readonly #options: EmuBridgeOptions;
  readonly #deps: EmuBridgeDeps;
  readonly #config: typeof DEFAULTS;
  readonly #splitter = new NdjsonSplitter();
  readonly #stderr: StderrCapture;
  readonly #pending = new Map<RequestId, Pending>();
  /** ids of fire-and-forget control frames whose replies are swallowed (bridge.cancel, bridge.shutdown) */
  readonly #control = new Set<RequestId>();
  readonly #exitListeners = new Set<(exit: BridgeExit) => void>();
  #child: ChildProcess | null = null;
  #nextId = 0;
  #state: "starting" | "ready" | "closing" | "exited" = "starting";
  #exit: BridgeExit | null = null;
  #exitWaiters: ((exit: BridgeExit) => void)[] = [];
  #killedByHost = false;
  #protocolViolation = false;
  #shutdownSent = false;
  #closing: Promise<BridgeExit> | null = null;
  #onFirstFrame: ((frame: Record<string, unknown> | null, cause?: EmuStartError) => void) | null = null;
  #hello: HelloResult | null = null;
  #ready: ReadyEvent | null = null;

  private constructor(options: EmuBridgeOptions, deps: EmuBridgeDeps) {
    this.#options = options;
    this.#deps = deps;
    this.#config = {
      startupTimeoutMs: options.startupTimeoutMs ?? DEFAULTS.startupTimeoutMs,
      killAfterMs: options.killAfterMs ?? DEFAULTS.killAfterMs,
      cancelGraceMs: options.cancelGraceMs ?? DEFAULTS.cancelGraceMs,
      deadlineBackstopMs: options.deadlineBackstopMs ?? DEFAULTS.deadlineBackstopMs,
      stderrHeadBytes: options.stderrHeadBytes ?? DEFAULTS.stderrHeadBytes,
      stderrTailBytes: options.stderrTailBytes ?? DEFAULTS.stderrTailBytes,
    } as typeof DEFAULTS;
    this.#stderr = new StderrCapture(this.#config.stderrHeadBytes, this.#config.stderrTailBytes);
  }

  /** Spawn, wait for `ready`, check protocol/sha256/version, `bridge.hello` (S5 §4.2). */
  static async start(
    options: EmuBridgeOptions,
    deps: EmuBridgeDeps,
    signal?: AbortSignal,
  ): Promise<Result<EmuBridge, EmuStartError>> {
    try {
      await mkdir(options.cwd, { recursive: true });
    } catch (cause) {
      return err({ kind: "spawn_failed", message: `cannot create the bridge working directory (${String(cause)})` });
    }
    const bridge = new EmuBridge(options, deps);
    return bridge.#start(signal);
  }

  /** launcher (spawned) vs interpreter (ready.pid) [S5-E2] */
  get pids(): { readonly child: number | null; readonly bridge: number | null } {
    return { child: this.#child?.pid ?? null, bridge: this.#ready?.pid ?? null };
  }
  get hello(): HelloResult {
    if (this.#hello === null) throw new Error("bridge not started");
    return this.#hello;
  }
  get readyEvent(): ReadyEvent {
    if (this.#ready === null) throw new Error("bridge not started");
    return this.#ready;
  }
  state(): "starting" | "ready" | "closing" | "exited" {
    return this.#state;
  }
  get lastExit(): BridgeExit | null {
    return this.#exit;
  }
  stderrTail(maxBytes = 4096): string {
    return this.#stderr.tail(maxBytes);
  }
  onExit(listener: (exit: BridgeExit) => void): () => void {
    this.#exitListeners.add(listener);
    return () => {
      this.#exitListeners.delete(listener);
    };
  }

  async #start(signal: AbortSignal | undefined): Promise<Result<EmuBridge, EmuStartError>> {
    if (signal?.aborted === true) return err({ kind: "cancelled" });
    const spawn = this.#deps.spawn ?? (nodeSpawn as SpawnFn);
    const startedAt = this.#deps.now();
    let child: ChildProcess;
    try {
      child = spawn(this.#options.python.command, bridgeArgs(this.#options), {
        stdio: ["pipe", "pipe", "pipe"],
        windowsHide: true,
        detached: false,
        cwd: this.#options.cwd,
        env: bridgeEnv(this.#deps.env ?? process.env),
      });
    } catch (cause) {
      return err({ kind: "spawn_failed", message: String(cause) });
    }
    this.#child = child;
    const first = new Promise<{ frame: Record<string, unknown> | null; cause?: EmuStartError }>((resolve) => {
      this.#onFirstFrame = (frame, cause) => {
        this.#onFirstFrame = null;
        resolve(cause === undefined ? { frame } : { frame, cause });
      };
    });
    child.once("error", (cause: NodeJS.ErrnoException) => {
      // ENOENT / EACCES before the process existed: no exit event follows
      if (this.#state === "starting" && child.pid === undefined) {
        this.#onFirstFrame?.(null, { kind: "spawn_failed", message: cause.code ?? cause.message });
        this.#markExited(null, null, "startup_failed");
      } else this.#deps.logger.debug("emulator bridge process error", { cause });
    });
    child.stdout?.on("data", (chunk: Buffer) => this.#onStdout(chunk));
    child.stderr?.setEncoding("utf8");
    child.stderr?.on("data", (text: string) => this.#stderr.push(text));
    child.stdin?.on("error", (cause) => this.#deps.logger.debug("emulator bridge stdin error", { cause }));
    child.once("exit", (code, sig) => this.#onChildExit(code, sig));

    const timer = setTimeout(
      () => this.#onFirstFrame?.(null, { kind: "timeout", afterMs: this.#deps.now() - startedAt }),
      this.#config.startupTimeoutMs,
    );
    const onAbort = (): void => this.#onFirstFrame?.(null, { kind: "cancelled" });
    signal?.addEventListener("abort", onAbort, { once: true });
    const firstFrame = await first;
    clearTimeout(timer);
    signal?.removeEventListener("abort", onAbort);

    const failStart = async (cause: EmuStartError): Promise<Result<EmuBridge, EmuStartError>> => {
      await this.#killAndWait();
      return err(cause);
    };
    if (firstFrame.cause !== undefined) {
      if (firstFrame.cause.kind === "spawn_failed") return err(firstFrame.cause);
      return failStart(firstFrame.cause);
    }
    const event = isObject(firstFrame.frame) ? firstFrame.frame["event"] : undefined;
    if (!isObject(event) || firstFrame.frame?.["id"] !== undefined) {
      this.#protocolViolation = true;
      return failStart({ kind: "exited", exit: this.#synthExit("protocol_violation") });
    }
    if (event["type"] === "fatal") {
      const data = (event as unknown as FatalEvent).data;
      const missing = Array.isArray(data?.missing)
        ? data.missing.filter((m): m is string => typeof m === "string")
        : null;
      return failStart({ kind: "engine_unavailable", missing });
    }
    if (event["type"] !== "ready") {
      this.#protocolViolation = true;
      return failStart({ kind: "exited", exit: this.#synthExit("protocol_violation") });
    }
    const ready = event as unknown as ReadyEvent;
    const mismatch = this.#versionMismatch(ready);
    if (mismatch !== null) return failStart(mismatch);
    this.#ready = ready;
    this.#state = "ready";
    const hello = await this.request(
      "bridge.hello",
      { protocol: EMU_PROTOCOL, client: { name: "bea", version: this.#options.clientVersion } },
      {
        deadlineAt: startedAt + this.#config.startupTimeoutMs,
        ...(signal === undefined ? {} : { signal }),
      },
    );
    if (!hello.ok) {
      const failure = hello.error;
      if (failure.kind === "bridge_error" && failure.error.code === "protocol_mismatch")
        return failStart({ kind: "version_mismatch", field: "protocol", expected: EMU_PROTOCOL, actual: null });
      if (failure.kind === "cancelled") return failStart({ kind: "cancelled" });
      if (failure.kind === "bridge_lost") return err({ kind: "exited", exit: failure.exit });
      if (failure.kind === "deadline") return failStart({ kind: "timeout", afterMs: this.#deps.now() - startedAt });
      return failStart({ kind: "exited", exit: this.#synthExit("protocol_violation") });
    }
    this.#hello = hello.value;
    return ok(this);
  }

  #versionMismatch(ready: ReadyEvent): EmuStartError | null {
    const expected = this.#options.bridge;
    if (ready.protocol !== EMU_PROTOCOL)
      return { kind: "version_mismatch", field: "protocol", expected: EMU_PROTOCOL, actual: String(ready.protocol) };
    if (!isObject(ready.bridge) || ready.bridge.sha256 !== expected.sha256)
      return {
        kind: "version_mismatch",
        field: "sha256",
        expected: expected.sha256,
        actual: isObject(ready.bridge) ? String(ready.bridge.sha256) : null,
      };
    if (ready.bridge.version !== expected.version)
      return {
        kind: "version_mismatch",
        field: "version",
        expected: expected.version,
        actual: String(ready.bridge.version),
      };
    return null;
  }

  #onStdout(chunk: Buffer): void {
    let frames: Buffer[];
    try {
      frames = this.#splitter.push(chunk);
    } catch (cause) {
      if (cause instanceof FrameTooLarge) this.#violation("frame_too_large");
      else throw cause;
      return;
    }
    for (const bytes of frames) {
      let frame: unknown;
      try {
        frame = JSON.parse(bytes.toString("utf8"));
      } catch {
        this.#violation("invalid_json");
        return;
      }
      if (!isObject(frame)) {
        this.#violation("non_object_frame");
        return;
      }
      this.#dispatch(frame);
    }
  }

  #violation(kind: string): void {
    this.#deps.logger.warn("emulator bridge protocol violation", { kind });
    this.#protocolViolation = true;
    if (this.#onFirstFrame !== null)
      this.#onFirstFrame(null, { kind: "exited", exit: this.#synthExit("protocol_violation") });
    this.#kill();
  }

  #dispatch(frame: Record<string, unknown>): void {
    if (this.#onFirstFrame !== null) {
      this.#onFirstFrame(frame);
      return;
    }
    const id = frame["id"];
    if (id === null) {
      // parse_error answers an unparseable host line: a host bug, never fatal
      this.#deps.logger.error("emulator bridge could not parse a host frame", {
        code: isObject(frame["error"]) ? String(frame["error"]["code"]) : "unknown",
      });
      return;
    }
    if (typeof id !== "number") {
      this.#deps.logger.debug("unsolicited emulator bridge frame ignored");
      return;
    }
    if (this.#control.has(id)) {
      if (!("event" in frame)) this.#control.delete(id);
      return;
    }
    const pending = this.#pending.get(id);
    if (pending === undefined) {
      this.#deps.logger.debug("late emulator bridge frame for an unknown request", { id });
      return;
    }
    if ("event" in frame) {
      const event = frame["event"];
      if (isObject(event) && event["type"] === "progress") pending.onProgress?.(event as unknown as ProgressEvent);
      return;
    }
    this.#finish(id, pending);
    if ("result" in frame) {
      pending.resolve(
        pending.why === null ? ok(frame["result"]) : err({ kind: pending.why, partial: frame["result"] }),
      );
      return;
    }
    const body = frame["error"];
    if (pending.why !== null) pending.resolve(err({ kind: pending.why, partial: null }));
    else if (isObject(body) && typeof body["code"] === "string")
      pending.resolve(err({ kind: "bridge_error", error: body as unknown as BridgeErrorBody }));
    else
      pending.resolve(
        err({ kind: "bridge_error", error: { code: "internal_error", message: "malformed error frame" } }),
      );
  }

  #finish(id: RequestId, pending: Pending): void {
    this.#pending.delete(id);
    for (const timer of pending.timers) clearTimeout(timer);
    pending.detach();
  }

  #write(bytes: Buffer): void {
    const stdin = this.#child?.stdin;
    if (stdin === null || stdin === undefined || stdin.destroyed || stdin.writableEnded) return;
    // stdin buffers writes in order; frames are bounded (64 MiB) and requests per session are serialized above
    stdin.write(bytes);
  }

  /** Fire-and-forget control frame; its reply is swallowed. */
  #sendControl(method: "bridge.cancel" | "bridge.shutdown", params: Record<string, unknown>): void {
    this.#nextId += 1;
    const id = this.#nextId;
    const encoded = encodeFrame({ id, method, params });
    if (!encoded.ok) return;
    this.#control.add(id);
    this.#write(encoded.bytes);
  }

  request<M extends EmuMethod>(
    method: M,
    params: EmuMethods[M]["params"],
    options: BridgeRequestOptions = {},
  ): Promise<Result<EmuMethods[M]["result"], EmuRequestFailure>> {
    return this.#send(method, params, options, null);
  }

  /**
   * `quietTimeoutMs` (ping only): on expiry the request is forgotten without bridge.cancel, so a liveness probe can
   * never escalate into a kill; otherwise signal/deadline cancel through #cancel.
   */
  #send<M extends EmuMethod>(
    method: M,
    params: EmuMethods[M]["params"],
    options: BridgeRequestOptions,
    quietTimeoutMs: number | null,
  ): Promise<Result<EmuMethods[M]["result"], EmuRequestFailure>> {
    if (this.#state !== "ready")
      return Promise.resolve(err({ kind: "bridge_lost", exit: this.#exit ?? this.#synthExit("crashed") }));
    if (options.signal?.aborted === true) return Promise.resolve(err({ kind: "cancelled", partial: null }));
    this.#nextId += 1;
    const id = this.#nextId;
    const encoded = encodeFrame({ id, method, params: params as unknown as Record<string, unknown> });
    if (!encoded.ok) return Promise.resolve(err({ kind: "local", reason: encoded.reason }));
    return new Promise((resolve) => {
      const pending: Pending = {
        method,
        resolve: resolve as Pending["resolve"],
        onProgress: options.onProgress,
        why: null,
        timers: [],
        detach: () => undefined,
      };
      this.#pending.set(id, pending);
      if (quietTimeoutMs !== null)
        pending.timers.push(
          setTimeout(() => {
            if (!this.#pending.has(id)) return;
            this.#finish(id, pending);
            pending.resolve(err({ kind: "deadline", partial: null }));
          }, quietTimeoutMs),
        );
      const signal = options.signal;
      if (signal !== undefined) {
        const onAbort = (): void => this.#cancel(id, "cancelled");
        signal.addEventListener("abort", onAbort, { once: true });
        pending.detach = () => signal.removeEventListener("abort", onAbort);
      }
      if (options.deadlineAt !== undefined) {
        const delay = Math.max(0, options.deadlineAt - this.#deps.now()) + this.#config.deadlineBackstopMs;
        pending.timers.push(setTimeout(() => this.#cancel(id, "deadline"), delay));
      }
      this.#write(encoded.bytes);
    });
  }

  /** At most once per id: send bridge.cancel; a bridge that does not answer within cancelGraceMs is killed. */
  #cancel(id: RequestId, why: "deadline" | "cancelled"): void {
    const pending = this.#pending.get(id);
    if (pending === undefined || pending.why !== null) return;
    pending.why = why;
    this.#sendControl("bridge.cancel", { requestId: id });
    pending.timers.push(
      setTimeout(() => {
        if (!this.#pending.has(id)) return;
        this.#deps.logger.warn("emulator bridge ignored a cancel; killing it", { method: pending.method });
        this.#kill();
      }, this.#config.cancelGraceMs),
    );
  }

  /** Out-of-band liveness probe (answered by the bridge's reader thread even while busy). */
  async ping(timeoutMs = 1_000): Promise<{ readonly alive: boolean; readonly busy: number | null }> {
    if (this.#state !== "ready") return { alive: false, busy: null };
    const reply = await this.#send("bridge.ping", {}, {}, timeoutMs);
    return reply.ok ? { alive: true, busy: reply.value.busy } : { alive: false, busy: null };
  }

  /** shutdown -> EOF -> kill at killAfterMs (CT-M9). Idempotent; resolves with the exit. */
  close(): Promise<BridgeExit> {
    if (this.#exit !== null) return Promise.resolve(this.#exit);
    this.#closing ??= this.#close();
    return this.#closing;
  }

  async #close(): Promise<BridgeExit> {
    const started = this.#deps.now();
    if (this.#state === "ready" || this.#state === "starting") this.#state = "closing";
    if (!this.#shutdownSent && this.#ready !== null) {
      this.#shutdownSent = true;
      this.#sendControl("bridge.shutdown", {});
    }
    this.#child?.stdin?.end();
    const exited = await this.#waitExit(Math.max(0, this.#config.killAfterMs - (this.#deps.now() - started)));
    if (exited !== null) return exited;
    return this.#killAndWait();
  }

  async #killAndWait(): Promise<BridgeExit> {
    if (this.#exit !== null) return this.#exit;
    this.#kill();
    return (await this.#waitExit(POST_KILL_WAIT_MS)) ?? this.#markExited(null, null, "killed");
  }

  #kill(): void {
    if (this.#exit !== null) return;
    this.#killedByHost = true;
    try {
      this.#child?.kill();
    } catch (cause) {
      this.#deps.logger.debug("emulator bridge kill failed", { cause: cause instanceof Error ? cause : String(cause) });
    }
  }

  #waitExit(timeoutMs: number): Promise<BridgeExit | null> {
    if (this.#exit !== null) return Promise.resolve(this.#exit);
    return new Promise((resolve) => {
      const timer = setTimeout(() => resolve(null), timeoutMs);
      this.#exitWaiters.push((exit) => {
        clearTimeout(timer);
        resolve(exit);
      });
    });
  }

  #synthExit(reason: BridgeExitReason): BridgeExit {
    return { code: null, signal: null, reason, stderrTail: this.#stderr.tail(4096) };
  }

  #onChildExit(code: number | null, signal: NodeJS.Signals | null): void {
    const reason: BridgeExitReason = this.#protocolViolation
      ? "protocol_violation"
      : this.#ready === null
        ? "startup_failed"
        : this.#killedByHost
          ? "killed"
          : this.#state === "closing"
            ? this.#shutdownSent
              ? "shutdown"
              : "eof"
            : "crashed";
    this.#markExited(code, signal, reason);
  }

  #markExited(code: number | null, signal: string | null, reason: BridgeExitReason): BridgeExit {
    if (this.#exit !== null) return this.#exit;
    const exit: BridgeExit = { code, signal, reason, stderrTail: this.#stderr.tail(4096) };
    this.#exit = exit;
    this.#state = "exited";
    if (this.#onFirstFrame !== null) this.#onFirstFrame(null, { kind: "exited", exit });
    for (const [id, pending] of Array.from(this.#pending)) {
      this.#finish(id, pending);
      pending.resolve(err({ kind: "bridge_lost", exit }));
    }
    for (const waiter of this.#exitWaiters.splice(0)) waiter(exit);
    if (reason !== "shutdown" && reason !== "eof")
      this.#deps.logger.debug("emulator bridge exited", { code, reason, stderr_tail: exit.stderrTail.slice(-1024) });
    for (const listener of Array.from(this.#exitListeners)) {
      try {
        listener(exit);
      } catch (cause) {
        this.#deps.logger.warn("emulator bridge exit listener failed", { cause: String(cause) });
      }
    }
    return exit;
  }
}
