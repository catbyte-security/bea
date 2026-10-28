import type { BeaError } from "../../../src/domain/errors/beaError.js";
import { mapAgentError } from "../../../src/domain/errors/agentErrorMap.js";
import { err, ok, type Result } from "../../../src/domain/result.js";
import type { AgentCallOptions, AgentHealth, AgentReplyValue, AgentRpc } from "../../../src/ports/agentRpc.js";
import type { AgentError, AgentMethodName, AgentParams, AgentValue } from "../../../src/shared/agentProtocol.js";

/**
 * Fake AgentRpc (WP4-SESS test support; DESIGN §9.1 rule 4). Every area's unit tests script the agent per method:
 * a handler returns the method's value (binary methods: `{value, data}`), an AgentError (`{agentError}`, mapped
 * through the real agentErrorMap exactly like AgentRpcClient), or a BeaError (`{beaError}`, e.g. a transport
 * failure). Unscripted methods answer the agent's `Unsupported`. Calls are logged with their params; an aborted op
 * answers `cancelled` without calling the handler.
 */
export type FakeAgentReply<M extends AgentMethodName> =
  | AgentReplyValue<M>
  | { readonly agentError: AgentError }
  | { readonly beaError: BeaError };

export type FakeAgentHandler<M extends AgentMethodName> = (
  params: AgentParams<M>,
  opts: AgentCallOptions,
) => FakeAgentReply<M> | Promise<FakeAgentReply<M>>;

export type FakeAgentHandlers = { readonly [M in AgentMethodName]?: FakeAgentHandler<M> };

export interface FakeAgentCall {
  readonly method: AgentMethodName;
  readonly params: unknown;
  readonly operation: string;
  readonly timeoutMs: number | undefined;
}

export class FakeAgentRpc implements AgentRpc {
  readonly calls: FakeAgentCall[] = [];
  health: AgentHealth = { state: "ok" };
  readonly #handlers: { [M in AgentMethodName]?: FakeAgentHandler<M> } = {};
  readonly #instanceId: string;

  constructor(handlers: FakeAgentHandlers = {}, instanceId = `pi_${"0".repeat(64)}`) {
    Object.assign(this.#handlers, handlers);
    this.#instanceId = instanceId;
  }

  /** Replace or add one method's handler. */
  on<M extends AgentMethodName>(method: M, handler: FakeAgentHandler<M>): this {
    (this.#handlers as Record<string, unknown>)[method] = handler;
    return this;
  }

  callsOf(method: AgentMethodName): readonly FakeAgentCall[] {
    return this.calls.filter((call) => call.method === method);
  }

  async call<M extends AgentMethodName>(
    method: M,
    params: AgentParams<M>,
    opts: AgentCallOptions,
  ): Promise<Result<AgentReplyValue<M>, BeaError>> {
    this.calls.push({ method, params, operation: opts.op.name, timeoutMs: opts.timeoutMs });
    if (this.health.state === "gone")
      return err({
        _tag: "CapabilityUnavailable",
        operation: opts.op.name,
        capability: "agent",
        reason: "agent-gone",
        retryable: false,
      });
    if (opts.op.signal.aborted) return err({ _tag: "Cancelled", operation: opts.op.name, by: "client" });
    const handler = this.#handlers[method] as FakeAgentHandler<M> | undefined;
    if (handler === undefined)
      return err(
        mapAgentError(
          { _tag: "Unsupported", message: "not scripted in FakeAgentRpc", feature: method, reason: "not-implemented" },
          { operation: opts.op.name, instance_id: this.#instanceId },
        ),
      );
    const reply = await handler(params, opts);
    if (typeof reply === "object" && reply !== null && "agentError" in reply)
      return err(mapAgentError(reply.agentError, { operation: opts.op.name, instance_id: this.#instanceId }));
    if (typeof reply === "object" && reply !== null && "beaError" in reply) return err(reply.beaError);
    return ok(reply as AgentReplyValue<M>);
  }
}

/** Convenience: a value-only handler. */
export const replies =
  <M extends AgentMethodName>(value: AgentValue<M>): FakeAgentHandler<M> =>
  () =>
    value as FakeAgentReply<M>;
