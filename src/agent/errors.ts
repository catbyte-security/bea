import type { AgentError, AgentResult } from "../shared/agentProtocol.js";
import { agentErrorFromThrown, type ThrownInfo } from "./pure/coreErrors.js";

/**
 * AgentError constructors + mapThrown (S4 §5.2). WP-AGENT owns; features import only these helpers. Every RPC returns
 * plain data (`AgentResult`); thrown errors are converted here, so the host only ever sees transport throws.
 */
export const ok = <T>(value: T): AgentResult<T> => ({ ok: true, value });
export const fail = (error: AgentError): AgentResult<never> => ({ ok: false, error });
/** @public */
export const unsupported = (feature: string): AgentResult<never> =>
  fail({
    _tag: "Unsupported",
    message: `${feature} is not implemented in this agent build`,
    feature,
    reason: "not-implemented",
  });

/** A thrown carrier for an AgentError (boot failures, deep helpers); mapThrown returns the carried error as is. */
export class AgentErrorThrown extends Error {
  readonly agentError: AgentError;

  constructor(agentError: AgentError) {
    super(agentError.message);
    this.name = "AgentErrorThrown";
    this.agentError = agentError;
  }
}

/** Throw an AgentError from a helper (caught by the RPC wrapper or the boot try/catch). */
export const raise = (error: AgentError): never => {
  throw new AgentErrorThrown(error);
};

const field = (e: object, key: string): string | undefined => {
  const v = (e as Record<string, unknown>)[key];
  return v === undefined || v === null ? undefined : String(v);
};

/** The fields mapThrown reads from any thrown value (stolen NativeFunction exceptions carry type/address/memory). */
export const thrownInfo = (e: unknown): ThrownInfo => {
  if (typeof e !== "object" || e === null) return { text: String(e) };
  const text = e instanceof Error ? e.message : String(e);
  const memory = (e as { memory?: unknown }).memory;
  const mem = typeof memory === "object" && memory !== null ? memory : null;
  const type = field(e, "type");
  const address = field(e, "address");
  const memoryOperation = mem === null ? undefined : field(mem, "operation");
  const memoryAddress = mem === null ? undefined : field(mem, "address");
  return {
    text,
    ...(type === undefined ? {} : { type }),
    ...(address === undefined ? {} : { address }),
    ...(memoryOperation === undefined ? {} : { memoryOperation }),
    ...(memoryAddress === undefined ? {} : { memoryAddress }),
  };
};

/** Frida error text / stolen exception → tagged AgentError (S4 §5.2 table); never throws. */
export function mapThrown(e: unknown, where: string): AgentError {
  if (e instanceof AgentErrorThrown) return e.agentError;
  try {
    return agentErrorFromThrown(thrownInfo(e), where);
  } catch {
    return { _tag: "Internal", message: "agent internal error", where };
  }
}

/** BadParams with one issue. */
export const badParam = (path: string, problem: string): AgentError => ({
  _tag: "BadParams",
  message: `invalid parameter ${path}`,
  issues: [{ path, problem }],
});

/** NotFound{what, id}. */
export const notFound = (what: Extract<AgentError, { _tag: "NotFound" }>["what"], id: string): AgentError => ({
  _tag: "NotFound",
  message: `${what} not found`,
  what,
  id,
});
