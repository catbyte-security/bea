import type { Deadline } from "../../domain/deadline.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import type { ExitInfo } from "../../domain/process/instance.js";
import type { SensitiveLiterals } from "../../domain/redaction/literals.js";
import { textContainsLiteral } from "../../domain/redaction/redact.js";
import { classifyAbort } from "./aborts.js";

/** Longest Frida error text copied into error diagnostics (UTF-16 code units, the ellipsis included). */
export const FRIDA_MESSAGE_MAX_CHARS = 300;

/**
 * Frida's own rejection text for error diagnostics (BEA-FEEDBACK item 1c), or null when there is none. Untrusted (Frida
 * quotes process names and paths): control, format and separator characters (bidi overrides included) become spaces,
 * whitespace collapses, and the text is cut at FRIDA_MESSAGE_MAX_CHARS without splitting a surrogate pair.
 */
export const fridaMessageOf = (cause: unknown): string | null => {
  const raw = cause instanceof Error ? cause.message : typeof cause === "string" ? cause : null;
  if (raw === null) return null;
  const text = raw
    .replace(/[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]+/gu, " ")
    .replace(/\s+/gu, " ")
    .trim();
  if (text.length === 0) return null;
  if (text.length <= FRIDA_MESSAGE_MAX_CHARS) return text;
  let end = FRIDA_MESSAGE_MAX_CHARS - 1;
  const last = text.charCodeAt(end - 1);
  if (last >= 0xd800 && last <= 0xdbff) end -= 1;
  return `${text.slice(0, end)}…`;
};

/**
 * A host-side Frida step's curated error plus Frida's own text in `diagnostics.frida_message` (BEA-FEEDBACK item 1c:
 * before, "refused to load frida-agent" reached only the debug log). The message and remediation stay curated BEA
 * text; the Frida text is data. Deadline and abort errors are BEA's own verdicts and stay unchanged; a text that
 * contains a caller-declared sensitive literal is withheld (`frida_message_withheld`). Used for the attach path,
 * whose results carry the untrusted marker; agent free text stays out of diagnostics (CT-M8).
 */
export const withFridaMessage = (error: BeaError, cause: unknown, literals: SensitiveLiterals | null): BeaError => {
  if (error._tag === "ProviderTimeout" || error._tag === "Cancelled") return error;
  const text = fridaMessageOf(cause);
  if (text === null) return error;
  const withheld = literals !== null && textContainsLiteral(text, literals);
  return {
    ...error,
    diagnostics: { ...error.diagnostics, ...(withheld ? { frida_message_withheld: true } : { frida_message: text }) },
  };
};

/**
 * Frida RPC rejection → BeaError (S3 §11.3). Messages are curated; Frida/agent text of an RPC never reaches the wire
 * (CT-M8), only bounded classification facts. "Script is destroyed" depends on WHY the script went away, which the
 * session knows (detach reason, jobhost/watcher root exit); the caller supplies that terminal view.
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
