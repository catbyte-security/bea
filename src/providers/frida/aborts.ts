import type { Deadline } from "../../domain/deadline.js";
import type { BeaError } from "../../domain/errors/beaError.js";

/**
 * Typed abort classification (S3 §7.2, §16 rule 8). Sources are read from the abort reason, never from message text:
 * shutdown → cancelled(server-shutdown); session-closing → capability_unavailable(agent, closing); an expired
 * deadline (its own reason, or a caller signal that fired at the deadline) → provider_timeout; anything else is the
 * caller → cancelled(client).
 */
export const classifyAbort = (
  signal: AbortSignal,
  operation: string,
  context: { readonly deadline?: Deadline; readonly phase?: string } = {},
): BeaError => {
  const reason = signal.reason as { readonly kind?: unknown; readonly ms?: unknown } | undefined;
  const kind = typeof reason === "object" && reason !== null ? reason.kind : undefined;
  if (kind === "shutdown") return { _tag: "Cancelled", operation, by: "server-shutdown" };
  if (kind === "session-closing")
    return { _tag: "CapabilityUnavailable", operation, capability: "agent", reason: "closing", retryable: false };
  if (kind === "deadline" || context.deadline?.expired === true)
    return {
      _tag: "ProviderTimeout",
      operation,
      timeout_ms: kind === "deadline" && typeof reason?.ms === "number" ? reason.ms : (context.deadline?.budgetMs ?? 0),
      phase: context.phase ?? operation,
    };
  return { _tag: "Cancelled", operation, by: "client" };
};

/** The abort as an error when `signal` has fired, else null (checkpoint after every await, S3 §16 rule 1). */
export const abortedError = (
  signal: AbortSignal,
  operation: string,
  context: { readonly deadline?: Deadline; readonly phase?: string } = {},
): BeaError | null => (signal.aborted ? classifyAbort(signal, operation, context) : null);
