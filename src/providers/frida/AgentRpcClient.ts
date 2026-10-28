import { Deadline } from "../../domain/deadline.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { mapAgentError } from "../../domain/errors/agentErrorMap.js";
import type { Logger } from "../../domain/logger.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { AgentCallOptions, AgentHealth, AgentReplyValue, AgentRpc } from "../../ports/agentRpc.js";
import type { AgentError, AgentMethodName, AgentParams } from "../../shared/agentProtocol.js";
import {
  AGENT_VALUE_SCHEMAS as VALUE_SCHEMAS,
  agentReplySchema as replySchema,
} from "../../application/sessions/agentSchemas.js";
import { classifyAbort } from "./aborts.js";
import type { CancellableLike, FridaScriptLike } from "./fridaPorts.js";
import { createNativeCancel } from "./NativeCancel.js";
import { mapRpcRejection, type TerminalView } from "./rpcErrors.js";

/**
 * Typed agent RPC (S3 §11, port AgentRpc). `script.exports[method](params, cancellable)` with one fresh Cancellable per
 * call armed by min(timeoutMs ?? config default, op.deadline.remaining()) and op.signal. Replies are validated: the
 * agent shares the target's address space, so a reply is untrusted input. `{ok:false}` maps through agentErrorMap
 * (free text is logged at debug level only, CT-M8); transport rejections through rpcErrors.ts. After a timeout the
 * health turns `suspect` and a background ping decides `ok` or `unresponsive`; an unresponsive agent fails calls fast
 * until a ping answers again (at most one ping per interval).
 */
export interface AgentRpcClientDeps {
  readonly script: FridaScriptLike;
  readonly createCancellable: () => CancellableLike;
  readonly defaultTimeoutMs: number;
  readonly pingTimeoutMs: number;
  readonly pingIntervalMs: number;
  readonly instanceId: () => string;
  /** waits ≤ 50 ms for exit/detach facts when the script went away */
  readonly terminal: () => Promise<TerminalView>;
  readonly logger: Logger;
  readonly now: () => number;
}

const BINARY_METHODS: ReadonlySet<AgentMethodName> = new Set<AgentMethodName>(["readMemory"]);
const protocolViolation = (operation: string, method: string, detail: string): BeaError => ({
  _tag: "ProviderFailure",
  operation,
  provider: "agent",
  message: "The agent's reply did not match the protocol.",
  diagnostics: { method, detail: detail.slice(0, 200) },
});

export class AgentRpcClient implements AgentRpc {
  readonly #deps: AgentRpcClientDeps;
  #health: AgentHealth = { state: "ok" };
  #pingInFlight = false;
  #lastPingAt = Number.NEGATIVE_INFINITY;

  constructor(deps: AgentRpcClientDeps) {
    this.#deps = deps;
  }

  get health(): AgentHealth {
    return this.#health;
  }

  /** The script went away (detach, destroy, unload): every later call fails without touching Frida. */
  markGone(reason: string): void {
    this.#health = { state: "gone", reason };
  }

  async call<M extends AgentMethodName>(
    method: M,
    params: AgentParams<M>,
    opts: AgentCallOptions,
  ): Promise<Result<AgentReplyValue<M>, BeaError>> {
    const { op } = opts;
    const operation = op.name;
    if (this.#health.state === "gone") return err(this.#mapGone(operation, method, await this.#deps.terminal()));
    if (this.#health.state === "unresponsive") {
      this.#maybePing();
      return err({
        _tag: "ProviderTimeout",
        operation,
        timeout_ms: 0,
        phase: "agent-unresponsive",
        message:
          "The agent's JS thread is blocked (a previous call never returned); calls fail until it answers again.",
        remediation:
          "Wait and retry, or close_session (an owned target is killed; an attached target may not detach while blocked).",
      });
    }
    if (op.signal.aborted) return err(classifyAbort(op.signal, operation, { deadline: op.deadline }));
    return this.#invoke(method, params, opts, operation);
  }

  async #invoke<M extends AgentMethodName>(
    method: M,
    params: AgentParams<M>,
    opts: AgentCallOptions,
    operation: string,
  ): Promise<Result<AgentReplyValue<M>, BeaError>> {
    const { op } = opts;
    const timeoutMs = Math.max(0, Math.min(opts.timeoutMs ?? this.#deps.defaultTimeoutMs, op.deadline.remaining()));
    const deadline = Deadline.after(timeoutMs, this.#deps.now);
    const cancel = createNativeCancel(this.#deps.createCancellable(), { deadline, signal: op.signal });
    try {
      const fn = this.#deps.script.exports[method];
      if (fn === undefined) return err(protocolViolation(operation, method, "missing export"));
      const raw = await fn(params, cancel.token);
      return this.#decode(method, raw, operation);
    } catch (cause) {
      const why = cancel.outcome();
      const mapped = mapRpcRejection(cause, {
        method,
        operation,
        why,
        signal: op.signal,
        deadline: op.deadline,
        timeoutMs,
        terminal: await this.#deps.terminal(),
      });
      if (
        mapped._tag === "TargetExited" ||
        (mapped._tag === "CapabilityUnavailable" && mapped.reason !== "protocol-skew")
      )
        this.markGone(mapped._tag === "TargetExited" ? "process-terminated" : mapped.reason);
      if (mapped._tag === "ProviderTimeout" && why === "deadline") this.#onTimeout(method);
      if (mapped._tag === "ProviderFailure")
        this.#deps.logger.debug("agent rpc threw", {
          method,
          text: (cause instanceof Error ? cause.message : String(cause)).slice(0, 512),
        });
      return err(mapped);
    } finally {
      cancel.dispose();
      deadline.dispose();
    }
  }

  #decode<M extends AgentMethodName>(method: M, raw: unknown, operation: string): Result<AgentReplyValue<M>, BeaError> {
    let reply: unknown = raw;
    let data: Buffer | null = null;
    if (BINARY_METHODS.has(method) && Array.isArray(raw)) {
      if (raw.length !== 2 || !Buffer.isBuffer(raw[1]))
        return err(protocolViolation(operation, method, "binary reply is not [reply, data]"));
      reply = raw[0];
      data = raw[1];
    }
    const parsed = replySchema.safeParse(reply);
    if (!parsed.success) return err(protocolViolation(operation, method, "reply is not an AgentResult"));
    if (!parsed.data.ok) {
      const agentError = parsed.data.error as unknown as AgentError;
      this.#deps.logger.debug("agent error", {
        method,
        tag: agentError._tag,
        text: String(agentError.message).slice(0, 512),
      });
      return err(mapAgentError(agentError, { operation, instance_id: this.#deps.instanceId() }));
    }
    const value = parsed.data.value;
    const schema = VALUE_SCHEMAS[method];
    if (schema !== undefined && !schema.safeParse(value).success)
      return err(protocolViolation(operation, method, "reply value does not match the method's result"));
    if (value === undefined) return err(protocolViolation(operation, method, "reply value is missing"));
    if (BINARY_METHODS.has(method)) {
      if (data === null) return err(protocolViolation(operation, method, "binary reply carried no data"));
      return ok({ value, data } as AgentReplyValue<M>);
    }
    return ok(value as AgentReplyValue<M>);
  }

  #mapGone(operation: string, method: string, terminal: TerminalView): BeaError {
    return mapRpcRejection(new Error("Script is destroyed"), {
      method,
      operation,
      why: "none",
      signal: new AbortController().signal,
      deadline: Deadline.after(0),
      timeoutMs: 0,
      terminal,
    });
  }

  #onTimeout(method: string): void {
    if (this.#health.state === "ok") this.#health = { state: "suspect", since: this.#deps.now(), method };
    this.#maybePing();
  }

  #maybePing(): void {
    const now = this.#deps.now();
    if (this.#pingInFlight || now - this.#lastPingAt < this.#deps.pingIntervalMs) return;
    this.#pingInFlight = true;
    this.#lastPingAt = now;
    const deadline = Deadline.after(this.#deps.pingTimeoutMs, this.#deps.now);
    const cancel = createNativeCancel(this.#deps.createCancellable(), { deadline });
    const ping = this.#deps.script.exports["ping"];
    void (ping === undefined ? Promise.reject(new Error("no ping export")) : ping({}, cancel.token))
      .then(
        () => {
          if (this.#health.state !== "gone") this.#health = { state: "ok" };
        },
        () => {
          if (this.#health.state === "suspect" || this.#health.state === "unresponsive")
            this.#health = { state: "unresponsive", since: this.#deps.now() };
        },
      )
      .finally(() => {
        this.#pingInFlight = false;
        cancel.dispose();
        deadline.dispose();
      });
  }
}
