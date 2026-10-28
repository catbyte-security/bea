import type { EmuMethod, EmuMethods, OpenParams, OpenResult, ProgressEvent } from "../../domain/emuProtocol.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { sessionNotFound } from "../../domain/errors/constructors.js";
import { canonicalJson } from "../../domain/canonical.js";
import type { JsonValue } from "../../domain/json.js";
import type { Logger } from "../../domain/logger.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { BridgeExit, EmuBridge } from "./EmuBridge.js";
import { crashLoopError, identityChangedError, requestFailureToBea, type BridgeErrorContext } from "./errors.js";

/**
 * One emulation session = one bridge process (S5-D3, §5.3–§5.4). Owns the bridge lifecycle, the generation counter,
 * the named-snapshot table and the restart policy:
 * - loss detection: the bridge exits outside a close, a protocol violation, or `engine_crashed`/`session_poisoned`
 *   (the poisoned bridge is closed proactively); the in-flight request fails `bridge_lost` (capability_unavailable,
 *   retryable) and no partial result exists;
 * - lazy re-open on the next request from the recorded open parameters, with an identity check (primary sha256 and
 *   mapped base, ISA site counts, import models) -> generation + 1, named snapshots reported lost, and a one-shot
 *   `bridge_restarted_state_reset` notice for the next result;
 * - crash loop: three losses within ten minutes -> `failed` (every later request: execution_failure).
 * Requests are serialized per session (FIFO), so the state lineage the application keeps advances in order.
 */
export type EmuRuntimeStatus = "opening" | "ready" | "lost" | "reopening" | "failed" | "closing" | "closed";

export interface RuntimeRequestOptions {
  readonly signal: AbortSignal;
  /** monotonic ms */
  readonly deadlineAt: number;
  readonly onProgress?: (event: ProgressEvent) => void;
}

export type RuntimeFailure =
  | { readonly kind: "error"; readonly error: BeaError }
  /** the bridge stopped the request at the host deadline or a cancel and answered with a partial result */
  | { readonly kind: "partial"; readonly reason: "deadline" | "cancelled"; readonly result: unknown };

export interface RestartNotice {
  readonly generation: number;
  readonly lostSnapshots: readonly string[];
}

export interface RuntimeDeps {
  /** starts a fresh bridge (errors already mapped to BEA errors) */
  readonly startBridge: (signal: AbortSignal) => Promise<Result<EmuBridge, BeaError>>;
  readonly now: () => number;
  readonly logger: Logger;
  readonly crashLoop?: { readonly losses: number; readonly windowMs: number };
}

const CRASH_LOOP = { losses: 3, windowMs: 10 * 60_000 } as const;
/** deadlineMs handed to the bridge for open: the host deadline minus this margin (S5 §5.5) */
const BRIDGE_DEADLINE_MARGIN_MS = 500;

type ParamsOf<M extends EmuMethod> = EmuMethods[M]["params"];
/** the methods addressed to one bridge-local session (distributive over the method union) */
export type SessionScoped<M extends EmuMethod> = M extends EmuMethod
  ? EmuMethods[M]["params"] extends { readonly session: string }
    ? M
    : never
  : never;

/** What a re-opened session must reproduce (S5 §5.4 step 3). */
const identityOf = (open: OpenResult): string =>
  canonicalJson({
    sha256: open.primary.sha256,
    mappedBase: open.primary.mappedBase,
    sites: open.isa.sites,
    models: open.imports.models,
  } as unknown as JsonValue);

export class EmuSessionRuntime {
  readonly kind = "emulation" as const;
  readonly id: string;
  readonly params: OpenParams;
  readonly #deps: RuntimeDeps;
  readonly #crashLoop: { readonly losses: number; readonly windowMs: number };
  #status: EmuRuntimeStatus = "opening";
  #generation = 0;
  #bridge: EmuBridge | null = null;
  #bridgeSession: string | null = null;
  #open: OpenResult | null = null;
  #identity: string | null = null;
  #named = new Map<string, number>();
  #lost: string[] = [];
  #losses: number[] = [];
  #notice: RestartNotice | null = null;
  #queue: Promise<unknown> = Promise.resolve();
  #closing: Promise<BridgeExit | null> | null = null;
  #unsubscribe: () => void = () => undefined;
  #calls = 0;
  #vectors = 0;

  constructor(id: string, params: OpenParams, deps: RuntimeDeps) {
    this.id = id;
    this.params = params;
    this.#deps = deps;
    this.#crashLoop = deps.crashLoop ?? CRASH_LOOP;
  }

  get status(): EmuRuntimeStatus {
    return this.#status;
  }
  get generation(): number {
    return this.#generation;
  }
  /** OpenResult of the first open (re-opens must reproduce its identity; modules stay valid across generations) */
  get openResult(): OpenResult | null {
    return this.#open;
  }
  get bridge(): EmuBridge | null {
    return this.#bridge;
  }
  get namedSnapshots(): readonly { readonly name: string; readonly bytes: number }[] {
    return [...this.#named].map(([name, bytes]) => ({ name, bytes }));
  }
  get lostSnapshots(): readonly string[] {
    return [...this.#lost];
  }
  get counters(): { readonly calls: number; readonly vectors: number } {
    return { calls: this.#calls, vectors: this.#vectors };
  }

  /** The one-shot restart notice (consumed by the next call/batch/sweep result). */
  takeRestartNotice(): RestartNotice | null {
    const notice = this.#notice;
    this.#notice = null;
    return notice;
  }

  noteSnapshot(change: { readonly saved: string; readonly bytes: number } | { readonly dropped: string }): void {
    if ("saved" in change) this.#named.set(change.saved, change.bytes);
    else this.#named.delete(change.dropped);
  }

  noteRun(vectors: number): void {
    this.#calls += 1;
    this.#vectors += vectors;
  }

  #serialize<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.#queue.then(fn, fn);
    this.#queue = run.catch(() => undefined);
    return run;
  }

  /** First open (generation 0). A failure leaves the runtime closed (no session was registered). */
  start(options: RuntimeRequestOptions): Promise<Result<OpenResult, BeaError>> {
    return this.#serialize(async () => {
      const opened = await this.#openBridge(options, "emu_open");
      if (!opened.ok) {
        this.#status = "closed";
        return opened;
      }
      this.#open = opened.value;
      this.#identity = identityOf(opened.value);
      this.#status = "ready";
      return ok(opened.value);
    });
  }

  async #openBridge(options: RuntimeRequestOptions, operation: string): Promise<Result<OpenResult, BeaError>> {
    const started = await this.#deps.startBridge(options.signal);
    if (!started.ok) return started;
    const bridge = started.value;
    const remaining = Math.max(1_000, Math.floor(options.deadlineAt - this.#deps.now() - BRIDGE_DEADLINE_MARGIN_MS));
    const opened = await bridge.request(
      "session.open",
      { ...this.params, deadlineMs: Math.min(this.params.deadlineMs ?? remaining, remaining) },
      {
        signal: options.signal,
        deadlineAt: options.deadlineAt,
        ...(options.onProgress === undefined ? {} : { onProgress: options.onProgress }),
      },
    );
    if (!opened.ok) {
      this.#logFailure("session.open", opened.error);
      await bridge.close();
      // patches are the only open input the bridge resolves itself (unknown_symbol); other refusals are host bugs
      const context: BridgeErrorContext = {
        imagePath: this.params.source.kind === "image" ? this.params.source.path : this.params.source.bundlePath,
        path: "patches",
      };
      return err(requestFailureToBea(operation, opened.error, { ...context, timeoutMs: remaining }));
    }
    this.#bridge = bridge;
    this.#bridgeSession = opened.value.session;
    this.#unsubscribe();
    this.#unsubscribe = bridge.onExit((exit) => {
      if (this.#closing === null) this.#markLost(bridge, exit, "exit");
    });
    return ok(opened.value);
  }

  /**
   * One loss per bridge: the exit listener and the failed request both report the same crash, so a bridge that is no
   * longer the current one (null `bridge`: a failed re-open, which has none) is counted once.
   */
  #markLost(bridge: EmuBridge | null, exit: BridgeExit | null, why: string): void {
    if (this.#status === "closed" || this.#status === "closing" || this.#status === "failed") return;
    if (bridge !== null && bridge !== this.#bridge) return;
    this.#deps.logger.warn("emulation bridge lost", {
      session: this.id,
      generation: this.#generation,
      why,
      code: exit?.code ?? null,
      reason: exit?.reason ?? null,
    });
    this.#bridge = null;
    this.#bridgeSession = null;
    const now = this.#deps.now();
    this.#losses = [...this.#losses.filter((t) => now - t < this.#crashLoop.windowMs), now];
    this.#status = this.#losses.length >= this.#crashLoop.losses ? "failed" : "lost";
  }

  async #reopen(options: RuntimeRequestOptions, operation: string): Promise<Result<void, BeaError>> {
    this.#status = "reopening";
    const opened = await this.#openBridge(options, operation);
    if (!opened.ok) {
      // a failed re-open counts as a loss (S5 §5.4 step 5); a cancel does not
      if (opened.error._tag === "Cancelled") this.#status = "lost";
      else this.#markLost(null, null, "reopen-failed");
      if (this.#status === "reopening") this.#status = "lost";
      return opened;
    }
    if (identityOf(opened.value) !== this.#identity) {
      const bridge = this.#bridge;
      this.#bridge = null;
      this.#status = "failed";
      await bridge?.close();
      return err(identityChangedError(operation));
    }
    this.#generation += 1;
    const lost = [...this.#named.keys()];
    this.#lost = [...new Set([...this.#lost, ...lost])];
    this.#named.clear();
    this.#notice = { generation: this.#generation, lostSnapshots: lost };
    this.#status = "ready";
    return ok(undefined);
  }

  /**
   * Review fix EMU-8: re-open a lost bridge NOW (not lazily inside the next request) and return the generation the next
   * request runs in, so callers resolve their state lineage against the generation that will really execute.
   */
  ensureReady(options: RuntimeRequestOptions, operation: string): Promise<Result<number, BeaError>> {
    return this.#serialize(async () => {
      if (this.#status === "closing" || this.#status === "closed") return err(sessionNotFound(operation, this.id));
      if (this.#status === "failed") return err(crashLoopError(operation));
      if (this.#status === "lost" || this.#bridge === null) {
        const reopened = await this.#reopen(options, operation);
        if (!reopened.ok) return reopened;
      }
      return ok(this.#generation);
    });
  }

  /**
   * One bridge request on this session (the bridge-local session id is filled in). A lost bridge is re-opened
   * first; `partial` carries a batch/sweep result the bridge produced after a host cancel or deadline.
   */
  request<M extends SessionScoped<EmuMethod>>(
    method: M,
    params: Omit<ParamsOf<M>, "session">,
    options: RuntimeRequestOptions,
    context: BridgeErrorContext & { readonly operation: string },
  ): Promise<Result<EmuMethods[M]["result"], RuntimeFailure>> {
    return this.#serialize(async () => {
      const operation = context.operation;
      if (this.#status === "closing" || this.#status === "closed")
        return err({ kind: "error", error: sessionNotFound(operation, this.id) });
      if (this.#status === "failed") return err({ kind: "error", error: crashLoopError(operation) });
      if (this.#status === "lost" || this.#bridge === null) {
        const reopened = await this.#reopen(options, operation);
        if (!reopened.ok) return err({ kind: "error", error: reopened.error });
      }
      const bridge = this.#bridge;
      const session = this.#bridgeSession;
      if (bridge === null || session === null)
        return err({ kind: "error", error: sessionNotFound(operation, this.id) });
      const reply = await bridge.request(method, { ...params, session } as unknown as ParamsOf<M>, {
        signal: options.signal,
        deadlineAt: options.deadlineAt,
        ...(options.onProgress === undefined ? {} : { onProgress: options.onProgress }),
      });
      if (reply.ok) return ok(reply.value);
      const failure = reply.error;
      this.#logFailure(method, failure);
      // the session may have been closed while the request was in flight (close never queues)
      if (this.#isClosing()) return err({ kind: "error", error: sessionNotFound(operation, this.id) });
      if ((failure.kind === "deadline" || failure.kind === "cancelled") && failure.partial !== null)
        return err({ kind: "partial", reason: failure.kind, result: failure.partial });
      if (failure.kind === "bridge_lost") this.#markLost(bridge, failure.exit, "request");
      if (
        failure.kind === "bridge_error" &&
        (failure.error.code === "engine_crashed" || failure.error.code === "session_poisoned")
      ) {
        // the process is poisoned: count the loss, close it proactively and re-open lazily
        this.#markLost(bridge, null, failure.error.code);
        await bridge.close();
      }
      const remaining = Math.max(0, Math.round(options.deadlineAt - this.#deps.now()));
      return err({
        kind: "error",
        error: requestFailureToBea(operation, failure, {
          ...context,
          generation: this.#generation,
          timeoutMs: remaining,
        }),
      });
    });
  }

  /** bridge error text stays in the debug log (never projected: it can quote target content) */
  #logFailure(
    method: string,
    failure: { readonly kind: string; readonly error?: { readonly code: string; readonly message: string } },
  ): void {
    this.#deps.logger.debug("emulator bridge request failed", {
      session: this.id,
      method,
      kind: failure.kind,
      code: failure.error?.code,
      message: failure.error?.message.slice(0, 500),
    });
  }

  #isClosing(): boolean {
    return this.#status === "closing" || this.#status === "closed";
  }

  /** Liveness without queueing behind a running request (bridge.ping is answered out of band). */
  async ping(): Promise<{ readonly alive: boolean; readonly busy: number | null }> {
    const bridge = this.#bridge;
    return bridge === null ? { alive: false, busy: null } : bridge.ping();
  }

  /**
   * shutdown -> EOF -> kill (900 ms). Never waits behind a running request: an in-flight request resolves
   * session_not_found once the bridge is gone. Idempotent.
   */
  close(): Promise<BridgeExit | null> {
    this.#closing ??= (async () => {
      this.#status = "closing";
      this.#unsubscribe();
      const bridge = this.#bridge;
      this.#bridge = null;
      this.#bridgeSession = null;
      const exit = bridge === null ? null : await bridge.close();
      this.#status = "closed";
      return exit;
    })();
    return this.#closing;
  }
}
