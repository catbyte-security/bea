import type { AgentError, AgentErrorTag } from "../../shared/agentProtocol.js";
import type { JsonObject } from "../json.js";
import type { BeaError } from "./beaError.js";

/**
 * AgentError (plain data from the in-target agent, S4 §4.2) -> BeaError (S1 closed union). Exhaustive by
 * `satisfies` (S4 §4.11). Curated catalog messages are used on the wire. CT-M8: the agent shares the target's
 * address space, so its free text (`message`, `frida_message`) is NEVER copied into diagnostics (it would reach
 * clients without the untrusted marker on returnsTargetContent:false tools); only structured fields are. The
 * AgentRpcClient (WP-SESS) logs the free text at debug level.
 */
export interface AgentErrorContext {
  readonly operation: string;
  readonly instance_id?: string;
  readonly effects_applied?: readonly string[];
}

type Mapper<T extends AgentErrorTag> = (e: Extract<AgentError, { _tag: T }>, c: AgentErrorContext) => BeaError;

const FREE_TEXT_KEYS: ReadonlySet<string> = new Set(["frida_message"]);
const diag = (e: AgentError): JsonObject => {
  const { _tag, message, ...rest } = e as AgentError & Record<string, unknown>;
  void message;
  const structured = Object.entries(JSON.parse(JSON.stringify(rest)) as JsonObject).filter(
    ([key]) => !FREE_TEXT_KEYS.has(key),
  );
  return { agent_tag: _tag, ...Object.fromEntries(structured) };
};
const base = (c: AgentErrorContext, e: AgentError) => ({
  operation: c.operation,
  diagnostics: diag(e),
  ...(c.instance_id !== undefined ? { instance_id: c.instance_id } : {}),
  ...(c.effects_applied !== undefined && c.effects_applied.length > 0
    ? { effects_applied: [...c.effects_applied] }
    : {}),
});

export const AGENT_ERROR_MAP = {
  BadParams: (e, c) => ({
    ...base(c, e),
    _tag: "InputError",
    issues: e.issues.map((i) => ({ path: i.path, reason: "invalid_value", message: i.problem.slice(0, 200) })),
  }),
  NotReady: (e, c) => ({ ...base(c, e), _tag: "InvalidState", state: "agent-loaded", expected: ["agent-ready"] }),
  ProtocolMismatch: (e, c) => ({
    ...base(c, e),
    _tag: "CapabilityUnavailable",
    capability: "agent",
    reason: "protocol-mismatch",
    retryable: false,
  }),
  ShuttingDown: (e, c) => ({
    ...base(c, e),
    _tag: "CapabilityUnavailable",
    capability: "agent",
    reason: "closing",
    retryable: false,
  }),
  GateClosed: (e, c) => ({
    ...base(c, e),
    _tag: "GateDisabled",
    gate: e.gate === "call_function" ? "call_attached" : e.gate,
  }),
  AccessViolation: (e, c) => ({
    ...base(c, e),
    _tag: "MemoryAccessFailed",
    address: e.address,
    access: e.operation ?? "read",
    size: e.partial_bytes ?? null,
  }),
  GuardPage: (e, c) => ({ ...base(c, e), _tag: "MemoryAccessFailed", address: e.address, access: "read", size: null }),
  ModuleNotFound: (e, c) => ({ ...base(c, e), _tag: "AddressUnmapped", address: e.module, module_map_id: null }),
  ExportNotFound: (e, c) => ({
    ...base(c, e),
    _tag: "InputError",
    issues: [{ path: "address", reason: "invalid_value", message: "The export is not in that module." }],
  }),
  NoFunctionRange: (e, c) => ({
    ...base(c, e),
    _tag: "InputError",
    issues: [{ path: "address", reason: "invalid_value", message: "No .pdata function contains this address." }],
  }),
  NotExecutable: (e, c) => ({
    ...base(c, e),
    _tag: "MemoryAccessFailed",
    address: e.address,
    access: "execute",
    size: null,
  }),
  WatchInvalid: (e, c) => ({
    ...base(c, e),
    _tag: "InputError",
    issues: [{ path: "size", reason: "invalid_value", message: `The watch is invalid (${e.reason}).` }],
  }),
  HookDenied: (e, c) => ({
    ...base(c, e),
    _tag: "InstrumentationFailed",
    reason: "hook-denied",
    address: e.address,
    conflicting_id: null,
  }),
  HookInstallFailed: (e, c) => ({
    ...base(c, e),
    _tag: "InstrumentationFailed",
    reason: "install-failed",
    address: e.address,
    conflicting_id: null,
  }),
  HookConflict: (e, c) => ({
    ...base(c, e),
    _tag: "InstrumentationFailed",
    reason: "conflict",
    address: e.address,
    conflicting_id: e.existing,
  }),
  NoFreeDebugRegister: (e, c) => ({
    ...base(c, e),
    _tag: "InstrumentationFailed",
    reason: "no-free-slot",
    address: null,
    conflicting_id: null,
  }),
  ThreadBusy: (e, c) => ({
    ...base(c, e),
    _tag: "InvalidState",
    state: e.reason === "in-syscall" ? "thread-in-syscall" : "thread-suspended",
    expected: ["thread-running-user-code"],
  }),
  StalkerBusy: (e, c) => ({
    ...base(c, e),
    _tag: "ResourceConstraint",
    resource: "capacity",
    limits: { thread_id: e.thread_id, retry_after_ms: e.retry_after_ms },
    retryable: true,
  }),
  NotFound: (e, c) => ({
    ...base(c, e),
    _tag: "ReferenceNotFound",
    reference: {
      kind:
        e.what === "instrument"
          ? "instrument"
          : e.what === "scan"
            ? "scan"
            : e.what === "job"
              ? "job"
              : e.what === "snapshot"
                ? "snapshot"
                : e.what === "blob"
                  ? "blob"
                  : "session-scoped-handle",
      id: e.id,
    },
  }),
  WriteConflict: (e, c) => ({ ...base(c, e), _tag: "EffectUnreverted", effect_ids: [] }),
  Timeout: (e, c) => ({ ...base(c, e), _tag: "ProviderTimeout", timeout_ms: e.timeout_ms, phase: e.phase }),
  Cancelled: (e, c) => ({ ...base(c, e), _tag: "Cancelled", by: "client" }),
  ResourceLimit: (e, c) => ({
    ...base(c, e),
    _tag: "ResourceConstraint",
    resource: e.resource === "agent_memory" ? "memory" : "capacity",
    limits: { resource: e.resource, limit: e.limit, ...(e.observed !== undefined ? { observed: e.observed } : {}) },
  }),
  Unsupported: (e, c) => ({ ...base(c, e), _tag: "UnsupportedTarget", reason: "unsupported-feature" }),
  Internal: (e, c) => ({ ...base(c, e), _tag: "ProviderFailure", provider: "agent" }),
} as const satisfies { readonly [T in AgentErrorTag]: Mapper<T> };

export const mapAgentError = (error: AgentError, context: AgentErrorContext): BeaError =>
  (AGENT_ERROR_MAP[error._tag] as Mapper<typeof error._tag>)(error as never, context);
