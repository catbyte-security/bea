import { join } from "node:path";

import { BEA_PACKAGE_VERSION } from "../../application/emu/packageVersion.js";
import type { BeaConfig } from "../../domain/config.js";
import type { Deadline } from "../../domain/deadline.js";
import type {
  BatchResult,
  CallResult,
  Deviation,
  EmuMethods,
  OpenParams,
  OpenResult,
  ProgressEvent,
  SweepResult,
} from "../../domain/emuProtocol.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { sessionNotFound } from "../../domain/errors/constructors.js";
import type { JsonObject, JsonValue } from "../../domain/json.js";
import type { Logger } from "../../domain/logger.js";
import { err, ok, type Result } from "../../domain/result.js";
import type {
  EmuModuleView,
  EmuPort,
  EmuRequestOptions,
  EmuSessionHandle,
  EmuSessionStatusView,
  PartialBatch,
  PythonStatus,
} from "../../ports/emu.js";
import type {
  CloseReport,
  DynamicSessionPort,
  ExternalSessionDriver,
  OperationContext,
  SessionSummary,
  VisibleSessionState,
} from "../../ports/sessions.js";
import type { Hex } from "../../shared/hex.js";
import type { LocatedBridge } from "./bridgeLocator.js";
import { EmuBridge, type EmuBridgeOptions, type SpawnFn } from "./EmuBridge.js";
import { startErrorToBea, type BridgeErrorContext } from "./errors.js";
import {
  EmuSessionRuntime,
  type RestartNotice,
  type RuntimeFailure,
  type RuntimeRequestOptions,
} from "./EmuSessionRuntime.js";
import type { PythonResolver, ResolvedPython } from "./pythonResolver.js";

/**
 * EmuPort over one EmuSessionRuntime per emulation session (S5 §5.6, CI-B5). Sessions share the live id space:
 * `open` registers through DynamicSessionPort.registerExternal, whose factory starts the bridge and returns the
 * ExternalSessionDriver session_status/close_session/closeAll use. Capacity is `emu.max_sessions` (default 4).
 * `lookup`/`modules` answer from memory (no bridge round trip); `info` is the bridge's `session.info`.
 */
export interface EmuAdapterDeps {
  readonly config: BeaConfig;
  readonly sessions: DynamicSessionPort;
  readonly resolver: PythonResolver;
  readonly bridge: () => Promise<Result<LocatedBridge, BeaError>>;
  readonly logger: Logger;
  /** monotonic ms (performance.now based, like EmuRequestOptions.deadlineAt) */
  readonly now: () => number;
  readonly spawn?: SpawnFn;
  /** test overrides of the bridge timeouts */
  readonly bridgeOptions?: Pick<
    EmuBridgeOptions,
    "startupTimeoutMs" | "killAfterMs" | "cancelGraceMs" | "deadlineBackstopMs"
  >;
  readonly crashLoop?: { readonly losses: number; readonly windowMs: number };
}

const MiB = 1024 * 1024;

const RESTART_NOTE =
  "The emulator bridge was restarted; the session state was reset to its baseline and named snapshots were lost.";

const restartDeviation = (notice: RestartNotice): Deviation => ({
  kind: "bridge_restarted_state_reset",
  note: RESTART_NOTE,
  detail: { generation: notice.generation, lost_snapshots: [...notice.lostSnapshots] },
});

const visibleState = (status: EmuSessionRuntime["status"]): VisibleSessionState => {
  switch (status) {
    case "ready":
      return "ready";
    case "closing":
      return "closing";
    case "closed":
      return "closed";
    default:
      return "lost";
  }
};

const statusView = (status: EmuSessionRuntime["status"]): EmuSessionStatusView["status"] =>
  status === "ready" || status === "opening"
    ? "ready"
    : status === "failed"
      ? "failed"
      : status === "closed" || status === "closing"
        ? "closed"
        : "lost";

/** EmuModuleView[] of an OpenResult: the primary first, then the other mapped modules (deduplicated by base). */
const moduleViews = (open: OpenResult): EmuModuleView[] => {
  const seen = new Set<string>();
  const out: EmuModuleView[] = [];
  for (const [module, primary] of [[open.primary, true] as const, ...open.modules.map((m) => [m, false] as const)]) {
    const key = module.mappedBase.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({
      name: module.name,
      path: module.path,
      sha256: module.sha256,
      base: module.mappedBase as Hex,
      size: module.size,
      preferredBase: (module.preferredBase as Hex | null) ?? null,
      primary,
    });
  }
  return out;
};

const toBea = (failure: RuntimeFailure, operation: string): BeaError =>
  failure.kind === "error"
    ? failure.error
    : failure.reason === "cancelled"
      ? { _tag: "Cancelled", operation, by: "client" }
      : { _tag: "ProviderTimeout", operation, timeout_ms: 0, phase: "emulator" };

const progressAdapter = (onProgress: EmuRequestOptions["onProgress"]): ((event: ProgressEvent) => void) | undefined =>
  onProgress === undefined ? undefined : (event) => onProgress(event.completed, event.total);

export class EmuAdapter implements EmuPort {
  readonly #deps: EmuAdapterDeps;
  readonly #runtimes = new Map<string, EmuSessionRuntime>();
  readonly #python = new Map<string, ResolvedPython>();
  #reserved = 0;

  constructor(deps: EmuAdapterDeps) {
    this.#deps = deps;
  }

  availability(): PythonStatus {
    return this.#deps.resolver.status();
  }

  /** open sessions (not closed) — capacity and status */
  liveCount(): number {
    return [...this.#runtimes.values()].filter((r) => r.status !== "closed").length;
  }
  counts(): { readonly open: number; readonly lost: number; readonly failed: number } {
    const all = [...this.#runtimes.values()];
    return {
      open: all.filter((r) => r.status !== "closed").length,
      lost: all.filter((r) => r.status === "lost" || r.status === "reopening").length,
      failed: all.filter((r) => r.status === "failed").length,
    };
  }

  #runtime(handle: EmuSessionHandle): EmuSessionRuntime | null {
    const runtime = this.#runtimes.get(handle.sessionId);
    return runtime === undefined || runtime.status === "closed" ? null : runtime;
  }

  /** EMU-8: a lost bridge re-opened before the caller reads its lineage; the handle of the generation that runs next. */
  async ensureReady(handle: EmuSessionHandle, o: EmuRequestOptions): Promise<Result<EmuSessionHandle, BeaError>> {
    const runtime = this.#runtime(handle);
    if (runtime === null) return err(sessionNotFound("emu_call", handle.sessionId));
    const ready = await runtime.ensureReady({ signal: o.signal, deadlineAt: o.deadlineAt }, "emu_call");
    return ready.ok ? ok({ sessionId: handle.sessionId, generation: ready.value }) : ready;
  }

  lookup(sessionId: string): EmuSessionHandle | null {
    const runtime = this.#runtimes.get(sessionId);
    return runtime === undefined || runtime.status === "closed" || runtime.status === "closing"
      ? null
      : { sessionId, generation: runtime.generation };
  }

  modules(handle: EmuSessionHandle): readonly EmuModuleView[] {
    const open = this.#runtime(handle)?.openResult;
    return open === null || open === undefined ? [] : moduleViews(open);
  }

  /** The resolved interpreter of a session (emu_open reports source/version/pin). */
  pythonOf(sessionId: string): ResolvedPython | null {
    return this.#python.get(sessionId) ?? null;
  }

  async open(
    input: OpenParams,
    op: OperationContext,
  ): Promise<Result<{ readonly runtime: EmuSessionHandle; readonly open: OpenResult }, BeaError>> {
    const max = this.#deps.config.emu.maxSessions.value;
    if (this.liveCount() + this.#reserved >= max)
      return err({
        _tag: "ResourceConstraint",
        operation: op.name,
        resource: "capacity",
        limits: { max_emulation_sessions: max },
        remediation:
          "Close an emulation session first (close_session). Configure emu.max_sessions (1..16) to raise the limit.",
      });
    this.#reserved += 1;
    try {
      const python = await this.#deps.resolver.resolve(op.name, op.signal);
      if (!python.ok) return python;
      const bridge = await this.#deps.bridge();
      if (!bridge.ok) return bridge;
      const startBridge = this.#starter(python.value, bridge.value, op.name);
      let opened: { readonly runtime: EmuSessionRuntime; readonly open: OpenResult } | null = null;
      const registered = await this.#deps.sessions.registerExternal(
        "emulation",
        async (id, registration) => {
          const runtime = new EmuSessionRuntime(id, input, {
            startBridge,
            now: this.#deps.now,
            logger: this.#deps.logger,
            ...(this.#deps.crashLoop === undefined ? {} : { crashLoop: this.#deps.crashLoop }),
          });
          const started = await runtime.start(this.#options(registration));
          if (!started.ok) return started;
          this.#runtimes.set(id, runtime);
          this.#python.set(id, python.value);
          opened = { runtime, open: started.value };
          return ok(this.#driver(runtime));
        },
        op,
      );
      if (!registered.ok) return registered;
      const result = opened as { readonly runtime: EmuSessionRuntime; readonly open: OpenResult } | null;
      if (result === null) return err({ _tag: "Internal", operation: op.name, diagnostics: { stage: "register" } });
      return ok({ runtime: { sessionId: registered.value, generation: result.runtime.generation }, open: result.open });
    } finally {
      this.#reserved -= 1;
    }
  }

  #options(op: OperationContext): RuntimeRequestOptions {
    const progress = op.progress;
    return {
      signal: op.signal,
      deadlineAt: this.#deps.now() + op.deadline.remaining(),
      ...(progress === undefined
        ? {}
        : {
            onProgress: (event: ProgressEvent) =>
              progress(
                event.phase,
                `${event.phase}: ${String(event.completed)}/${event.total === null ? "?" : String(event.total)}`,
              ),
          }),
    };
  }

  #starter(python: ResolvedPython, bridge: LocatedBridge, operation: string) {
    const config = this.#deps.config;
    const emuDir = config.layout.emuDir;
    return async (signal: AbortSignal): Promise<Result<EmuBridge, BeaError>> => {
      const started = await EmuBridge.start(
        {
          python: { command: python.command, prefixArgs: python.prefixArgs },
          bridge: { path: bridge.path, sha256: bridge.sha256, version: bridge.version },
          memoryLimitBytes: config.emu.memoryLimitMb.value * MiB,
          cacheDir: config.emu.isaCache.value ? join(emuDir, "cache") : null,
          cwd: emuDir,
          clientVersion: BEA_PACKAGE_VERSION,
          startupTimeoutMs: config.emu.startupTimeoutMs.value,
          ...this.#deps.bridgeOptions,
        },
        {
          now: this.#deps.now,
          logger: this.#deps.logger,
          ...(this.#deps.spawn === undefined ? {} : { spawn: this.#deps.spawn }),
        },
        signal,
      );
      if (!started.ok) {
        // a cached interpreter that no longer starts is re-resolved next time
        if (started.error.kind === "spawn_failed") this.#deps.resolver.invalidate();
        return err(startErrorToBea(operation, started.error));
      }
      return ok(started.value);
    };
  }

  #requestOptions(o: EmuRequestOptions): RuntimeRequestOptions {
    const onProgress = progressAdapter(o.onProgress);
    return { signal: o.signal, deadlineAt: o.deadlineAt, ...(onProgress === undefined ? {} : { onProgress }) };
  }

  async #request<
    M extends
      | "emu.call"
      | "emu.batch"
      | "emu.sweep"
      | "session.info"
      | "state.save"
      | "state.restore"
      | "state.drop"
      | "state.list"
      | "mem.read"
      | "mem.disassemble"
      | "mem.regions",
  >(
    handle: EmuSessionHandle,
    method: M,
    params: Omit<EmuMethods[M]["params"], "session">,
    o: EmuRequestOptions,
    context: BridgeErrorContext & { readonly operation: string },
  ): Promise<Result<EmuMethods[M]["result"], RuntimeFailure>> {
    const runtime = this.#runtime(handle);
    if (runtime === null) return err({ kind: "error", error: sessionNotFound(context.operation, handle.sessionId) });
    return runtime.request(method, params as never, this.#requestOptions(o), context) as Promise<
      Result<EmuMethods[M]["result"], RuntimeFailure>
    >;
  }

  async info(
    handle: EmuSessionHandle,
    o: EmuRequestOptions,
  ): Promise<Result<EmuMethods["session.info"]["result"], BeaError>> {
    const reply = await this.#request(handle, "session.info", {}, o, { operation: "session_status" });
    return reply.ok ? reply : err(toBea(reply.error, "session_status"));
  }

  async call(
    handle: EmuSessionHandle,
    req: Omit<EmuMethods["emu.call"]["params"], "session">,
    o: EmuRequestOptions,
  ): Promise<Result<CallResult, BeaError>> {
    const reply = await this.#request(handle, "emu.call", req, o, { operation: "emu_call", path: "state.from" });
    if (!reply.ok) return err(toBea(reply.error, "emu_call"));
    const runtime = this.#runtime(handle);
    runtime?.noteRun(1);
    const notice = runtime?.takeRestartNotice() ?? null;
    return ok(
      notice === null
        ? reply.value
        : { ...reply.value, deviations: [...reply.value.deviations, restartDeviation(notice)] },
    );
  }

  #withNotice(handle: EmuSessionHandle, result: BatchResult): BatchResult {
    const runtime = this.#runtime(handle);
    runtime?.noteRun(result.summary.completed);
    const notice = runtime?.takeRestartNotice() ?? null;
    if (notice === null) return result;
    return {
      ...result,
      aggregates: {
        ...result.aggregates,
        deviations: {
          ...result.aggregates.deviations,
          bridge_restarted_state_reset: {
            vectors: result.summary.completed,
            detail: { generation: notice.generation, lost_snapshots: [...notice.lostSnapshots] },
          },
        },
      },
    };
  }

  async batch(
    handle: EmuSessionHandle,
    req: Omit<EmuMethods["emu.batch"]["params"], "session">,
    o: EmuRequestOptions,
  ): Promise<Result<BatchResult, BeaError | PartialBatch>> {
    const reply = await this.#request(handle, "emu.batch", req, o, { operation: "emu_call", path: "state.from" });
    if (reply.ok) return ok(this.#withNotice(handle, reply.value));
    const failure = reply.error;
    if (
      failure.kind === "partial" &&
      typeof failure.result === "object" &&
      failure.result !== null &&
      "summary" in failure.result
    )
      return err({
        kind: "partial",
        reason: failure.reason,
        result: this.#withNotice(handle, failure.result as BatchResult),
      });
    return err(toBea(failure, "emu_call"));
  }

  async sweep(
    handle: EmuSessionHandle,
    req: Omit<EmuMethods["emu.sweep"]["params"], "session">,
    o: EmuRequestOptions,
  ): Promise<Result<SweepResult, BeaError>> {
    const reply = await this.#request(handle, "emu.sweep", req, o, { operation: "emu_call", path: "sweep" });
    if (!reply.ok) {
      const failure = reply.error;
      if (
        failure.kind === "partial" &&
        typeof failure.result === "object" &&
        failure.result !== null &&
        "rows" in failure.result
      )
        return ok(failure.result as SweepResult);
      return err(toBea(failure, "emu_call"));
    }
    this.#runtime(handle)?.noteRun(reply.value.summary.completed);
    this.#runtime(handle)?.takeRestartNotice();
    return ok(reply.value);
  }

  async state(
    handle: EmuSessionHandle,
    op: { readonly save: string } | { readonly restore: string } | { readonly drop: string } | { readonly list: true },
    o: EmuRequestOptions,
  ): Promise<Result<unknown, BeaError>> {
    const operation = "emu_call";
    const runtime = this.#runtime(handle);
    if ("save" in op) {
      const reply = await this.#request(handle, "state.save", { name: op.save }, o, {
        operation,
        path: "state.save_as",
      });
      if (!reply.ok) return err(toBea(reply.error, operation));
      runtime?.noteSnapshot({ saved: reply.value.name, bytes: reply.value.bytes });
      return ok(reply.value);
    }
    if ("restore" in op) {
      const reply = await this.#request(handle, "state.restore", { name: op.restore }, o, {
        operation,
        path: "state.from",
      });
      return reply.ok ? reply : err(toBea(reply.error, operation));
    }
    if ("drop" in op) {
      const reply = await this.#request(handle, "state.drop", { name: op.drop }, o, { operation, path: "state.drop" });
      if (!reply.ok) return err(toBea(reply.error, operation));
      runtime?.noteSnapshot({ dropped: op.drop });
      return ok(reply.value);
    }
    const reply = await this.#request(handle, "state.list", {}, o, { operation });
    return reply.ok ? reply : err(toBea(reply.error, operation));
  }

  async readMemory(
    handle: EmuSessionHandle,
    address: Hex,
    size: number,
    o: EmuRequestOptions,
  ): Promise<Result<EmuMethods["mem.read"]["result"], BeaError>> {
    const reply = await this.#request(handle, "mem.read", { address, size, encoding: "hex" }, o, {
      operation: "read_memory",
      address,
    });
    return reply.ok ? reply : err(toBea(reply.error, "read_memory"));
  }

  async disassemble(
    handle: EmuSessionHandle,
    address: Hex,
    opts: { readonly count?: number; readonly function?: boolean },
    o: EmuRequestOptions,
  ): Promise<Result<EmuMethods["mem.disassemble"]["result"], BeaError>> {
    const reply = await this.#request(
      handle,
      "mem.disassemble",
      {
        address,
        ...(opts.count === undefined ? {} : { count: opts.count }),
        ...(opts.function === undefined ? {} : { function: opts.function }),
      },
      o,
      { operation: "disassemble", address },
    );
    return reply.ok ? reply : err(toBea(reply.error, "disassemble"));
  }

  async regions(
    handle: EmuSessionHandle,
    o: EmuRequestOptions,
  ): Promise<Result<EmuMethods["mem.regions"]["result"], BeaError>> {
    const reply = await this.#request(handle, "mem.regions", {}, o, { operation: "list_memory_ranges" });
    return reply.ok ? reply : err(toBea(reply.error, "list_memory_ranges"));
  }

  status(handle: EmuSessionHandle): EmuSessionStatusView {
    const runtime = this.#runtimes.get(handle.sessionId);
    if (runtime === undefined)
      return {
        status: "closed",
        generation: handle.generation,
        bridgePid: null,
        childPid: null,
        namedSnapshots: [],
        lostSnapshots: [],
        calls: 0,
        vectors: 0,
      };
    const pids = runtime.bridge?.pids ?? { child: null, bridge: null };
    return {
      status: statusView(runtime.status),
      generation: runtime.generation,
      bridgePid: pids.bridge,
      childPid: pids.child,
      namedSnapshots: runtime.namedSnapshots,
      lostSnapshots: runtime.lostSnapshots,
      calls: runtime.counters.calls,
      vectors: runtime.counters.vectors,
    };
  }

  async close(handle: EmuSessionHandle): Promise<Result<{ readonly bridgeExit: number | null }, BeaError>> {
    const runtime = this.#runtimes.get(handle.sessionId);
    if (runtime === undefined) return err(sessionNotFound("close_session", handle.sessionId));
    const exit = await runtime.close();
    this.#forget(runtime.id);
    return ok({ bridgeExit: exit?.code ?? null });
  }

  #forget(id: string): void {
    this.#runtimes.delete(id);
    this.#python.delete(id);
  }

  /** teardown-targets closer: every bridge concurrently (shutdown -> EOF -> kill at 900 ms). */
  async closeAll(): Promise<void> {
    const runtimes = [...this.#runtimes.values()];
    await Promise.allSettled(runtimes.map((runtime) => runtime.close()));
    for (const runtime of runtimes) this.#forget(runtime.id);
  }

  #summary(runtime: EmuSessionRuntime): SessionSummary {
    const primary = runtime.openResult?.primary;
    return {
      session_id: runtime.id,
      kind: "emulation",
      state: visibleState(runtime.status),
      pid: null,
      ownership: "none",
      image: primary === undefined ? null : (primary.path ?? primary.name),
      instance_id: null,
      active_instruments: 0,
      active_effects: 0,
    };
  }

  async #detail(
    runtime: EmuSessionRuntime,
    level: "summary" | "complete",
    op: OperationContext,
  ): Promise<Result<JsonObject, BeaError>> {
    const open = runtime.openResult;
    const python = this.#python.get(runtime.id) ?? null;
    const pids = runtime.bridge?.pids ?? { child: null, bridge: null };
    const base: Record<string, JsonValue> = {
      kind: "emulation",
      status: runtime.status,
      generation: runtime.generation,
      source: runtime.params.source.kind,
      primary:
        open === null
          ? null
          : { name: open.primary.name, sha256: open.primary.sha256, mapped_base: open.primary.mappedBase },
      bridge: {
        pid: pids.bridge,
        child_pid: pids.child,
        version: runtime.bridge?.readyEvent.bridge.version ?? null,
        python: python === null ? null : { source: python.source, version: python.version, pin: python.pin },
      },
      named_snapshots: runtime.namedSnapshots.map((s) => ({ name: s.name, bytes: s.bytes })),
      lost_snapshots: [...runtime.lostSnapshots],
      calls: runtime.counters.calls,
      vectors: runtime.counters.vectors,
      loader_deviations: (open?.loaderDeviations ?? [])
        .slice(0, 32)
        .map((d) => ({ kind: d.kind, ...(d.count === undefined ? {} : { count: d.count }) })),
      isa:
        open === null
          ? null
          : { sites: { ...open.isa.sites }, guarded: { ...open.isa.guarded }, guard: open.isa.guard },
      memory_limit_mb: this.#deps.config.emu.memoryLimitMb.value,
    };
    if (level === "summary" || runtime.status !== "ready") return ok(base);
    const ping = await runtime.ping();
    const info = await runtime.request("session.info", {}, this.#options(op), { operation: op.name });
    if (!info.ok) return ok({ ...base, alive: ping.alive, busy: ping.busy });
    const state = info.value.state;
    return ok({
      ...base,
      alive: ping.alive,
      busy: ping.busy,
      state: { poisoned: state.poisoned, heap_high: state.heapHigh, calls: state.calls, vectors: state.vectors },
    });
  }

  #driver(runtime: EmuSessionRuntime): ExternalSessionDriver {
    const report = (): CloseReport => ({
      sessionId: runtime.id,
      kind: "emulation",
      ownership: null,
      targetState: "none",
      termination: null,
      exit: null,
      revert: null,
      agentUnloaded: null,
      fridaDetached: false,
      streamsFinalized: [],
      cleanup: { status: "complete" },
      limitations: [],
    });
    return {
      kind: "emulation",
      shutdown: async (_deadline: Deadline) => {
        await runtime.close();
        this.#forget(runtime.id);
        return ok(undefined);
      },
      close: async (_deadline: Deadline) => {
        await runtime.close();
        this.#forget(runtime.id);
        return ok(report());
      },
      summary: () => this.#summary(runtime),
      detail: (level, op) => this.#detail(runtime, level, op),
    };
  }
}
