import type { DetachReason } from "../../ports/sessions.js";

/**
 * Narrow structural views of the frida 17.23.2 Node binding (S3 §4.1). The provider codes against these so the fast
 * lane runs on fakes (tests/support/frida/fakeFrida.ts); fridaAdapters.ts maps the real vendor objects onto them (all
 * enum casts live there) and tests/unit/sessions/fridaCompat.test.ts asserts at compile time that the vendor types fit.
 *
 * Deliberate omissions: `enumerateProcesses` takes no `pids` filter (a pid-filtered query is not a liveness probe,
 * VERIFIED zombie gotcha ext-frida §1.3; the type system keeps it out of reach), `attach` takes no SessionOptions
 * (`exceptor:"off"` turns every agent fault into a target kill, ext-frida §1.5), and `spawn`/`resume`/`kill` take no
 * cancellable (S3 §16 rule 3: a cancelled spawn could lose the pid of a suspended child).
 */
export interface CancellableLike {
  cancel(): void;
  readonly isCancelled: boolean;
}

export interface SignalLike<H extends (...args: never[]) => void> {
  connect(handler: H): void;
  disconnect(handler: H): void;
}

export type FridaMessage =
  | { readonly type: "send"; readonly payload: unknown }
  | {
      readonly type: "error";
      readonly description: string;
      readonly stack?: string;
      readonly fileName?: string;
      readonly lineNumber?: number;
      readonly columnNumber?: number;
    };

export type FridaLogLevel = "info" | "warning" | "error";

type ScriptMessageHandler = (message: FridaMessage, data: Buffer | null) => void;
type ScriptLogHandler = (level: FridaLogLevel, text: string) => void;

export interface FridaScriptLike {
  readonly isDestroyed: boolean;
  /** Must be replaced in the same tick createScript resolves: the default prints to stdout (the MCP channel). */
  logHandler: ScriptLogHandler;
  /** RPC proxy: a trailing Cancellable (the binding's own class) and a trailing Buffer are popped by frida.js. */
  readonly exports: Readonly<Record<string, (...args: unknown[]) => Promise<unknown>>>;
  readonly message: SignalLike<ScriptMessageHandler>;
  readonly destroyed: SignalLike<() => void>;
  load(cancellable?: CancellableLike | null): Promise<void>;
  unload(cancellable?: CancellableLike | null): Promise<void>;
  post(message: unknown, data?: Buffer | null): void;
}

type SessionDetachedHandler = (reason: DetachReason, crash: unknown) => void;

export interface FridaSessionLike {
  readonly pid: number;
  isDetached(): boolean;
  detach(cancellable?: CancellableLike | null): Promise<void>;
  createScript(
    source: string,
    options: { readonly name: string; readonly runtime: "qjs" | "v8" },
    cancellable?: CancellableLike | null,
  ): Promise<FridaScriptLike>;
  readonly detached: SignalLike<SessionDetachedHandler>;
}

export interface FridaProcessLike {
  readonly pid: number;
  readonly name: string;
  /** scope "metadata": path, user, ppid (a BigInt), started (ISO, µs precision); fields may be absent */
  readonly parameters: Readonly<Record<string, unknown>>;
}

export interface FridaSpawnOptions {
  /** replaces the whole environment (D-INT-41); Frida's `env` would merge into the server environment */
  readonly envp: Readonly<Record<string, string>>;
  readonly cwd: string;
  readonly stdio: "pipe" | "inherit";
}

export type OutputHandler = (pid: number, fd: number, data: Buffer) => void;

export interface FridaDeviceLike {
  readonly id: string;
  /** NEVER given a cancellable (S3 §16): awaited under a guard timer and compensated afterwards. */
  spawn(argv: readonly string[], options: FridaSpawnOptions): Promise<number>;
  resume(pid: number): Promise<void>;
  /** Owned, pre-adoption cleanup only (verify-module-boundaries pins the call sites). */
  kill(pid: number): Promise<void>;
  attach(pid: number, cancellable?: CancellableLike | null): Promise<FridaSessionLike>;
  enumerateProcesses(
    options: { readonly scope: "minimal" | "metadata" },
    cancellable?: CancellableLike | null,
  ): Promise<readonly FridaProcessLike[]>;
  querySystemParameters(cancellable?: CancellableLike | null): Promise<Readonly<Record<string, unknown>>>;
  readonly output: SignalLike<OutputHandler>;
}

export interface FridaDeviceManagerLike {
  getDeviceById(id: string, timeoutMs: number, cancellable?: CancellableLike | null): Promise<FridaDeviceLike>;
  close(cancellable?: CancellableLike | null): Promise<void>;
}

export interface FridaModuleLike {
  /** the binding's package version (pinned 17.23.2) */
  readonly version: string;
  createDeviceManager(): FridaDeviceManagerLike;
  createCancellable(): CancellableLike;
}
