import type { Deadline } from "../../domain/deadline.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import type { ExitInfo } from "../../domain/process/instance.js";
import { classifyAbort } from "./aborts.js";

/**
 * Frida RPC rejection → BeaError (S3 §11.3). Messages are curated; Frida/agent text never reaches the wire (CT-M8),
 * only bounded classification facts. "Script is destroyed" depends on WHY the script went away, which the session
 * knows (detach reason, jobhost/watcher root exit); the caller supplies that terminal view.
 */
export interface TerminalView {
  /** the session is closing or BEA is shutting down */
  readonly closing: boolean;
  /** the process terminated (detach process-terminated or a root exit), with exit facts when known */
  readonly exited: { readonly exit: ExitInfo | null } | null;
  readonly detachReason: string | null;
  readonly instanceId: string;
}

const UNKNOWN_EXIT: ExitInfo = { code: null, code_hex: null, kind: "unknown", name: null };

export const mapRpcRejection = (
  cause: unknown,
  context: {
    readonly method: string;
    readonly operation: string;
    readonly why: "none" | "deadline" | "aborted";
    readonly signal: AbortSignal;
    readonly deadline: Deadline;
    readonly timeoutMs: number;
    readonly terminal: TerminalView;
  },
): BeaError => {
  const text = cause instanceof Error ? cause.message : String(cause);
  const { operation, terminal } = context;
  if (/Script is destroyed/u.test(text)) {
    if (terminal.exited !== null)
      return {
        _tag: "TargetExited",
        operation,
        instance_id: terminal.instanceId,
        exit: terminal.exited.exit ?? UNKNOWN_EXIT,
        detach_reason: terminal.detachReason,
      };
    if (terminal.closing)
      return { _tag: "CapabilityUnavailable", operation, capability: "agent", reason: "closing", retryable: false };
    return {
      _tag: "CapabilityUnavailable",
      operation,
      capability: "agent",
      reason: "agent-gone",
      retryable: false,
      diagnostics: { detach_reason: terminal.detachReason ?? "unknown" },
    };
  }
  if (/Operation was cancelled/u.test(text)) {
    if (context.why === "deadline")
      return { _tag: "ProviderTimeout", operation, timeout_ms: context.timeoutMs, phase: `rpc:${context.method}` };
    return classifyAbort(context.signal, operation, { deadline: context.deadline, phase: `rpc:${context.method}` });
  }
  if (/unable to find method/u.test(text))
    return {
      _tag: "CapabilityUnavailable",
      operation,
      capability: "agent",
      reason: "protocol-skew",
      retryable: false,
      diagnostics: { method: context.method },
    };
  const name = cause instanceof Error ? cause.name.slice(0, 64) : "unknown";
  return {
    _tag: "ProviderFailure",
    operation,
    provider: "agent",
    message: "The BEA agent threw instead of returning a result (an agent bug).",
    diagnostics: { method: context.method, agent_error_name: name },
  };
};
