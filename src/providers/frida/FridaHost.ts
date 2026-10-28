import { Deadline } from "../../domain/deadline.js";
import type { BeaError, BeaErrorOf } from "../../domain/errors/beaError.js";
import type { Logger } from "../../domain/logger.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { OperationContext } from "../../ports/sessions.js";
import { classifyAbort } from "./aborts.js";
import type { AgentBundle } from "./agentBundle.js";
import { EXPECTED_FRIDA_VERSION } from "./fridaLoader.js";
import type { FridaDeviceLike, FridaDeviceManagerLike, FridaModuleLike, OutputHandler } from "./fridaPorts.js";
import { createNativeCancel, type NativeCancel } from "./NativeCancel.js";

/**
 * Frida binding, the OWNED DeviceManager and the local device (S3 §4.2, H1/H2). Single-flight lazy load; a failed
 * import or version check is permanent for the process, a failed device lookup is retried after 5 s. One
 * `device.output` handler fans stdout/stderr out by pid; output for a pid nobody routes yet is buffered briefly (64 KiB
 * total, 5 s TTL). `close` is the `release-frida` lifecycle closer: disconnect output, await dm.close() (VERIFIED
 * 63–68 ms), and the process can exit naturally.
 */
export type FridaBindingState =
  | { readonly state: "not-loaded" }
  | { readonly state: "loading" }
  | { readonly state: "ready"; readonly version: string; readonly loadMs: number }
  | {
      readonly state: "failed";
      readonly stage: "import" | "version" | "device";
      readonly reason: string;
      readonly attempts: number;
      readonly permanent: boolean;
      readonly retryAfterMs: number | null;
    }
  | { readonly state: "closed" };

interface SystemFacts {
  readonly os: string;
  readonly version: string;
  readonly arch: string;
  readonly access: string;
}

export interface LiveDevice {
  readonly device: FridaDeviceLike;
  readonly system: SystemFacts;
}

export interface FridaAvailability {
  readonly binding: FridaBindingState;
  readonly device: "not-acquired" | "ready" | "failed" | "closed";
  readonly agentBundle:
    | { readonly state: "not-loaded" }
    | { readonly state: "ready"; readonly sha256: string; readonly buildId: string; readonly agentVersion: string }
    | { readonly state: "failed"; readonly reason: string };
}

export interface HostCloseReport {
  readonly outputDisconnected: boolean;
  readonly deviceManagerClosed: boolean;
  readonly closeMs: number;
}

export interface FridaHostDeps {
  readonly logger: Logger;
  readonly loadModule: () => Promise<FridaModuleLike>;
  readonly loadAgentBundle: () => Promise<Result<AgentBundle, BeaErrorOf<"CapabilityUnavailable">>>;
  readonly now: () => number;
  readonly orphanOutputBytes: number;
  readonly orphanOutputTtlMs: number;
}

type HostState =
  | { readonly kind: "idle" }
  | { readonly kind: "loading"; readonly promise: Promise<Result<LiveDevice, BeaError>> }
  | {
      readonly kind: "ready";
      readonly mod: FridaModuleLike;
      readonly dm: FridaDeviceManagerLike;
      readonly live: LiveDevice;
      readonly loadMs: number;
    }
  | {
      readonly kind: "failed";
      readonly stage: "import" | "version" | "device";
      readonly reason: string;
      readonly attempts: number;
      readonly at: number;
      readonly permanent: boolean;
      readonly mod: FridaModuleLike | null;
    }
  | { readonly kind: "closed" };

const DEVICE_RETRY_MS = 5_000;
const DEVICE_LOOKUP_MS = 1_000;
const MAX_REASON = 4096;

const reasonOf = (cause: unknown): string =>
  (cause instanceof Error ? cause.message : String(cause)).slice(0, MAX_REASON);

const fridaUnavailable = (
  operation: string,
  reason: string,
  retryable: boolean,
  diagnostics?: Readonly<Record<string, string | number | boolean>>,
): BeaErrorOf<"CapabilityUnavailable"> => ({
  _tag: "CapabilityUnavailable",
  operation,
  capability: "frida",
  reason,
  retryable,
  ...(diagnostics === undefined ? {} : { diagnostics }),
});

interface OrphanChunk {
  readonly fd: number;
  readonly data: Buffer;
  readonly at: number;
}

export class FridaHost {
  readonly #deps: FridaHostDeps;
  #state: HostState = { kind: "idle" };
  #attempts = 0;
  #module: FridaModuleLike | null = null;
  #bundle: Promise<Result<AgentBundle, BeaErrorOf<"CapabilityUnavailable">>> | null = null;
  #bundleState: FridaAvailability["agentBundle"] = { state: "not-loaded" };
  readonly #routes = new Map<number, (fd: number, data: Buffer) => void>();
  readonly #orphans = new Map<number, OrphanChunk[]>();
  #orphanBytes = 0;
  #orphanBytesTotal = 0;
  #outputConnected: FridaDeviceLike | null = null;

  constructor(deps: FridaHostDeps) {
    this.#deps = deps;
  }

  /** Cheap and side-effect free: never loads the binding or the bundle. */
  availability(): FridaAvailability {
    return { binding: this.#bindingState(), device: this.#deviceState(), agentBundle: this.#bundleState };
  }

  /** Total bytes of output that arrived for a pid nobody had routed (status counter). */
  get orphanOutputBytes(): number {
    return this.#orphanBytesTotal;
  }

  async device(op: Pick<OperationContext, "signal">): Promise<Result<LiveDevice, BeaError>> {
    const state = this.#state;
    if (state.kind === "closed") return err(fridaUnavailable("frida.device", "host-closed", false));
    if (state.kind === "ready") return ok(state.live);
    if (state.kind === "failed") {
      if (state.permanent)
        return err(fridaUnavailable("frida.device", `${state.stage}-failed`, false, { detail: state.reason }));
      const waited = this.#deps.now() - state.at;
      if (waited < DEVICE_RETRY_MS)
        return err(
          fridaUnavailable("frida.device", "device-unavailable", true, {
            detail: state.reason,
            retry_after_ms: Math.ceil(DEVICE_RETRY_MS - waited),
          }),
        );
    }
    const loading =
      this.#state.kind === "loading"
        ? this.#state.promise
        : this.#startLoad(state.kind === "failed" ? state.mod : null);
    return raceSignal(loading, op.signal);
  }

  /** The loaded binding (null until a device() call succeeded once). */
  get module(): FridaModuleLike | null {
    return this.#module;
  }

  /** One Cancellable per native call; requires the binding (callers hold a LiveDevice). */
  nativeCancel(spec: { readonly deadline: Deadline; readonly signal?: AbortSignal | undefined }): NativeCancel {
    const mod = this.#module;
    if (mod === null) throw new Error("FridaHost.nativeCancel before the binding was loaded");
    return createNativeCancel(mod.createCancellable(), spec);
  }

  agentBundle(): Promise<Result<AgentBundle, BeaErrorOf<"CapabilityUnavailable">>> {
    this.#bundle ??= this.#deps.loadAgentBundle().then((result) => {
      this.#bundleState = result.ok
        ? {
            state: "ready",
            sha256: result.value.sha256,
            buildId: result.value.buildId,
            agentVersion: result.value.agentVersion,
          }
        : { state: "failed", reason: result.error.reason };
      if (!result.ok) this.#bundle = null; // a rebuilt bundle is picked up by the next attempt
      return result;
    });
    return this.#bundle;
  }

  /** Route a pid's output to `sink` (drains buffered orphan bytes first). Returns the unregister function. */
  routeOutput(pid: number, sink: (fd: number, data: Buffer) => void): () => void {
    this.#routes.set(pid, sink);
    const buffered = this.#orphans.get(pid);
    if (buffered !== undefined) {
      this.#orphans.delete(pid);
      for (const chunk of buffered) {
        this.#orphanBytes -= chunk.data.length;
        sink(chunk.fd, chunk.data);
      }
    }
    return () => {
      if (this.#routes.get(pid) === sink) this.#routes.delete(pid);
    };
  }

  /** release-frida closer: idempotent; a failure keeps the state for a retry. */
  async close(deadline: Deadline, signal?: AbortSignal): Promise<Result<HostCloseReport, BeaError>> {
    const started = this.#deps.now();
    const state = this.#state;
    if (state.kind === "closed") return ok({ outputDisconnected: true, deviceManagerClosed: true, closeMs: 0 });
    if (state.kind === "loading") await raceSignal(state.promise, deadline.signal());
    const current = this.#state;
    const outputDisconnected = this.#disconnectOutput();
    if (current.kind !== "ready") {
      this.#state = { kind: "closed" };
      return ok({ outputDisconnected, deviceManagerClosed: true, closeMs: Math.round(this.#deps.now() - started) });
    }
    const cancel = createNativeCancel(current.mod.createCancellable(), { deadline, signal });
    try {
      await current.dm.close(cancel.token);
      this.#state = { kind: "closed" };
      this.#routes.clear();
      this.#orphans.clear();
      return ok({ outputDisconnected, deviceManagerClosed: true, closeMs: Math.round(this.#deps.now() - started) });
    } catch (cause) {
      this.#deps.logger.warn("frida device manager close failed", { reason: reasonOf(cause) });
      return err({
        _tag: "ProviderFailure",
        operation: "frida.close",
        provider: "frida",
        diagnostics: { stage: "device-manager-close", outcome: cancel.outcome() },
      });
    } finally {
      cancel.dispose();
    }
  }

  #startLoad(previous: FridaModuleLike | null): Promise<Result<LiveDevice, BeaError>> {
    const promise = this.#load(previous);
    this.#state = { kind: "loading", promise };
    return promise;
  }

  async #load(previous: FridaModuleLike | null): Promise<Result<LiveDevice, BeaError>> {
    this.#attempts += 1;
    const started = this.#deps.now();
    let mod = previous;
    if (mod === null) {
      try {
        mod = await this.#deps.loadModule();
      } catch (cause) {
        return this.#fail("import", reasonOf(cause), true, null);
      }
      if (mod.version !== EXPECTED_FRIDA_VERSION)
        return this.#fail("version", `frida ${mod.version}; BEA requires ${EXPECTED_FRIDA_VERSION}`, true, null);
    }
    this.#module = mod;
    const dm = mod.createDeviceManager();
    const cancel = createNativeCancel(mod.createCancellable(), { deadline: Deadline.after(DEVICE_LOOKUP_MS + 500) });
    try {
      const device = await dm.getDeviceById("local", DEVICE_LOOKUP_MS, cancel.token);
      const params = await device.querySystemParameters(cancel.token);
      if (this.#state.kind === "closed") {
        await dm.close().catch(() => undefined);
        return err(fridaUnavailable("frida.device", "host-closed", false));
      }
      device.output.connect(this.#onOutput);
      this.#outputConnected = device;
      const live: LiveDevice = { device, system: systemFactsOf(params) };
      this.#state = { kind: "ready", mod, dm, live, loadMs: Math.round(this.#deps.now() - started) };
      return ok(live);
    } catch (cause) {
      await dm.close().catch(() => undefined);
      return this.#fail("device", reasonOf(cause), false, mod);
    } finally {
      cancel.dispose();
    }
  }

  #fail(
    stage: "import" | "version" | "device",
    reason: string,
    permanent: boolean,
    mod: FridaModuleLike | null,
  ): Result<never, BeaError> {
    if (this.#state.kind !== "closed")
      this.#state = { kind: "failed", stage, reason, attempts: this.#attempts, at: this.#deps.now(), permanent, mod };
    this.#deps.logger.warn("frida binding unavailable", { stage, permanent, reason });
    return err(
      fridaUnavailable(
        "frida.device",
        stage === "device" ? "device-unavailable" : `${stage}-failed`,
        !permanent,
        stage === "device" ? { detail: reason, retry_after_ms: DEVICE_RETRY_MS } : { detail: reason },
      ),
    );
  }

  #disconnectOutput(): boolean {
    const device = this.#outputConnected;
    if (device === null) return true;
    try {
      device.output.disconnect(this.#onOutput);
      this.#outputConnected = null;
      return true;
    } catch (cause) {
      this.#deps.logger.warn("frida output disconnect failed", { reason: reasonOf(cause) });
      return false;
    }
  }

  /** O(1), never throws into Frida. */
  readonly #onOutput: OutputHandler = (pid, fd, data) => {
    try {
      const route = this.#routes.get(pid);
      if (route !== undefined) {
        route(fd, data);
        return;
      }
      this.#bufferOrphan(pid, fd, data);
    } catch (cause) {
      this.#deps.logger.debug("output routing failed", { reason: reasonOf(cause) });
    }
  };

  #bufferOrphan(pid: number, fd: number, data: Buffer): void {
    const now = this.#deps.now();
    this.#orphanBytesTotal += data.length;
    for (const [orphanPid, chunks] of this.#orphans) {
      const fresh = chunks.filter((chunk) => now - chunk.at <= this.#deps.orphanOutputTtlMs);
      for (const stale of chunks.length === fresh.length ? [] : chunks.filter((c) => !fresh.includes(c)))
        this.#orphanBytes -= stale.data.length;
      if (fresh.length === 0) this.#orphans.delete(orphanPid);
      else if (fresh.length !== chunks.length) this.#orphans.set(orphanPid, fresh);
    }
    if (this.#orphanBytes + data.length > this.#deps.orphanOutputBytes) return;
    const list = this.#orphans.get(pid) ?? [];
    list.push({ fd, data: Buffer.from(data), at: now });
    this.#orphans.set(pid, list);
    this.#orphanBytes += data.length;
  }

  #bindingState(): FridaBindingState {
    const state = this.#state;
    switch (state.kind) {
      case "idle":
        return { state: "not-loaded" };
      case "loading":
        return { state: "loading" };
      case "ready":
        return { state: "ready", version: state.mod.version, loadMs: state.loadMs };
      case "failed":
        return {
          state: "failed",
          stage: state.stage,
          reason: state.reason,
          attempts: state.attempts,
          permanent: state.permanent,
          retryAfterMs: state.permanent ? null : Math.max(0, DEVICE_RETRY_MS - (this.#deps.now() - state.at)),
        };
      case "closed":
        return { state: "closed" };
    }
  }

  #deviceState(): FridaAvailability["device"] {
    switch (this.#state.kind) {
      case "ready":
        return "ready";
      case "failed":
        return "failed";
      case "closed":
        return "closed";
      default:
        return "not-acquired";
    }
  }
}

const systemFactsOf = (params: Readonly<Record<string, unknown>>): SystemFacts => {
  const os = (params["os"] ?? {}) as { readonly id?: unknown; readonly version?: unknown };
  return {
    os: typeof os.id === "string" ? os.id : "unknown",
    version: typeof os.version === "string" ? os.version : "unknown",
    arch: typeof params["arch"] === "string" ? params["arch"] : "unknown",
    access: typeof params["access"] === "string" ? params["access"] : "unknown",
  };
};

/** A caller abort stops the wait, never the shared work (S3 §4.2). */
const raceSignal = <T>(work: Promise<Result<T, BeaError>>, signal: AbortSignal): Promise<Result<T, BeaError>> => {
  if (signal.aborted) return Promise.resolve(err(classifyAbort(signal, "frida.device")));
  return new Promise((resolve) => {
    const onAbort = (): void => resolve(err(classifyAbort(signal, "frida.device")));
    signal.addEventListener("abort", onAbort, { once: true });
    void work.then((result) => {
      signal.removeEventListener("abort", onAbort);
      resolve(result);
    });
  });
};
