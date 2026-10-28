import type { BeaError } from "../domain/errors/beaError.js";
import type { Result } from "../domain/result.js";
import type { AgentMethodName, AgentParams, AgentValue, IsBinary } from "../shared/agentProtocol.js";
import type { OperationContext } from "./sessions.js";

/**
 * Typed agent RPC (S3 §11 + S4 §2.2). One fresh frida.Cancellable per call armed by the deadline and op.signal;
 * replies are zod-validated (the agent shares the target's address space); AgentError maps through
 * src/domain/errors/agentErrorMap.ts; transport rejections through src/providers/frida/rpcErrors.ts.
 * Never sends BigInt. Binary replies arrive as [AgentResult, Buffer] and surface as `data`.
 */
export type AgentHealth =
  | { readonly state: "ok" }
  | { readonly state: "suspect"; readonly since: number; readonly method: string }
  | { readonly state: "unresponsive"; readonly since: number }
  | { readonly state: "gone"; readonly reason: string };

export interface AgentCallOptions {
  readonly op: OperationContext;
  /** default limits.rpcDefaultTimeoutMs (config, 1000..115000); always ≤ op.deadline.remaining() */
  readonly timeoutMs?: number;
}

export type AgentReplyValue<M extends AgentMethodName> =
  IsBinary<M> extends true ? { readonly value: AgentValue<M>; readonly data: Buffer } : AgentValue<M>;

export interface AgentRpc {
  call<M extends AgentMethodName>(
    method: M,
    params: AgentParams<M>,
    opts: AgentCallOptions,
  ): Promise<Result<AgentReplyValue<M>, BeaError>>;
  readonly health: AgentHealth;
}
