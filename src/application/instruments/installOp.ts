import { Deadline } from "../../domain/deadline.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import type { OperationContext } from "../../ports/sessions.js";

/**
 * Review fix LIFE-6: an install RPC (hookInstall, overrideInstall, profileInstall) is a non-cancellable step. Frida
 * posts the request before it checks the Cancellable, so a client cancel (or the tool deadline) that lands after the
 * dispatch left the instrument live in the agent with no host recording, effect or way to stop it. The install and
 * every rollback therefore run on a detached op (its own deadline, never the caller's signal); the caller's abort is
 * checked once the reply arrived, and the then-known instrument is stopped again.
 */
/** Budget of an install RPC and its compensating stop (the agent answers in milliseconds; a wedged one is cut here). */
export const INSTALL_RPC_MS = 30_000;

export interface DetachedOp {
  readonly op: OperationContext;
  readonly dispose: () => void;
}

export const detachedOp = (op: OperationContext, ms: number): DetachedOp => {
  const deadline = Deadline.after(Math.max(1_000, ms));
  return {
    op: { opId: op.opId, name: op.name, signal: deadline.signal(), deadline },
    dispose: () => deadline.dispose(),
  };
};

/** The caller's abort as an error once a non-cancellable step finished (null: not aborted). */
export const abortedAfter = (op: OperationContext): BeaError | null => {
  if (!op.signal.aborted) return null;
  const reason = op.signal.reason as { readonly kind?: unknown } | undefined;
  const kind = typeof reason === "object" && reason !== null ? reason.kind : undefined;
  if (kind === "shutdown") return { _tag: "Cancelled", operation: op.name, by: "server-shutdown" };
  if (kind === "deadline" || op.deadline.expired)
    return { _tag: "ProviderTimeout", operation: op.name, timeout_ms: op.deadline.budgetMs, phase: "install" };
  return { _tag: "Cancelled", operation: op.name, by: "client" };
};
