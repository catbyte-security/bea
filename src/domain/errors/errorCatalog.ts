import { GATE_SPECS, gateEnableInstruction } from "../gates.js";
import type { JsonObject } from "../json.js";
import type { BeaError, BeaErrorOf, BeaErrorTag } from "./beaError.js";

/** Wire codes (closed). cleanup_incomplete is produced only by the projection override. */
export const BEA_ERROR_CODES = [
  "invalid_request",
  "configuration_invalid",
  "session_not_found",
  "reference_not_found",
  "invalid_state",
  "target_exited",
  "instance_mismatch",
  "address_unmapped",
  "memory_access_failed",
  "instrumentation_failed",
  "effect_unreverted",
  "access_denied",
  "unsupported_target",
  "capability_unavailable",
  "provider_timeout",
  "cancelled",
  "resource_constraint",
  "evidence_integrity_mismatch",
  "revision_conflict",
  "file_operation_failed",
  "cleanup_incomplete",
  "execution_failure",
] as const;
export type BeaErrorCode = (typeof BEA_ERROR_CODES)[number];

export const BEA_ERROR_CATEGORIES = [
  "invalid_input",
  "target_state",
  "unsupported",
  "unavailable",
  "timeout",
  "cancelled",
  "resource_constraint",
  "integrity_mismatch",
  "execution_failure",
] as const;
export type BeaErrorCategory = (typeof BEA_ERROR_CATEGORIES)[number];

export type BeaErrorRecovery =
  | { readonly kind: "inspect_input_contract"; readonly operation: string }
  | {
      readonly kind: "inspect_timeout_state";
      readonly operation: string;
      readonly timeout_ms: number;
    }
  | { readonly kind: "reattach"; readonly previous_instance_id: string }
  | { readonly kind: "refresh_module_map"; readonly instance_id: string | null }
  | { readonly kind: "revert_effects"; readonly effect_ids: readonly string[] };

export interface TagSpec<Tag extends BeaErrorTag> {
  readonly code: Exclude<BeaErrorCode, "cleanup_incomplete">;
  readonly category: BeaErrorCategory;
  readonly retryable: (error: BeaErrorOf<Tag>) => boolean;
  readonly message: (error: BeaErrorOf<Tag>) => string;
  readonly remediation: (error: BeaErrorOf<Tag>) => string;
  readonly recovery?: (error: BeaErrorOf<Tag>) => BeaErrorRecovery;
  /** Tag-specific wire details (snake_case). Base fields are added by the projection. */
  readonly details: (error: BeaErrorOf<Tag>) => JsonObject;
}

const never = (): boolean => false;
const always = (): boolean => true;
const none = (): JsonObject => ({});

/** Exhaustive by construction: the mapped type fails to compile if a tag is missing. */
export const ERROR_CATALOG: { readonly [Tag in BeaErrorTag]: TagSpec<Tag> } = {
  InputError: {
    code: "invalid_request",
    category: "invalid_input",
    retryable: never,
    message: (e) =>
      `The ${e.operation} arguments are invalid (${String(e.issues.length)} issue${e.issues.length === 1 ? "" : "s"}).`,
    remediation: () =>
      "Correct the fields listed in details.issues using the tool's input schema, then retry. Do not repeat the unchanged call.",
    recovery: (e) => ({ kind: "inspect_input_contract", operation: e.operation }),
    details: (e) => ({ issues: e.issues.map((issue) => ({ ...issue })) }),
  },
  ConfigurationError: {
    code: "configuration_invalid",
    category: "invalid_input",
    retryable: never,
    message: () => "BEA's configuration is invalid.",
    remediation: () =>
      "Fix the settings listed in details.settings (environment or BEA_HOME/config.json), restart BEA, and run `bea doctor` to confirm.",
    details: (e) => ({ settings: e.settings.map((s) => ({ ...s })) }),
  },
  SessionNotFound: {
    code: "session_not_found",
    category: "invalid_input",
    retryable: never,
    message: (e) => `No open BEA session has id ${e.session_id}.`,
    remediation: () =>
      "Call bea_status to list open sessions, or start one with spawn_process, attach_process or emu_open. Do not retry with this session_id.",
    details: (e) => ({ session_id: e.session_id }),
  },
  ReferenceNotFound: {
    code: "reference_not_found",
    category: "invalid_input",
    retryable: never,
    message: (e) => `No ${e.reference.kind} with id ${e.reference.id} exists in this BEA run.`,
    remediation: () =>
      "Use an id returned earlier by this server run; ids do not survive a server restart. Call session_status or get_evidence to list current ids.",
    details: (e) => ({ reference: { ...e.reference } }),
  },
  InvalidState: {
    code: "invalid_state",
    category: "target_state",
    retryable: never,
    message: (e) => `${e.operation} requires state ${e.expected.join(" or ")}, but the session is ${e.state}.`,
    remediation: () => "Call session_status to read the current state, then choose an operation valid in that state.",
    details: (e) => ({ state: e.state, expected: [...e.expected] }),
  },
  TargetExited: {
    code: "target_exited",
    category: "target_state",
    retryable: never,
    message: (e) =>
      `The target process ended${e.exit.code_hex === null ? "" : ` with ${e.exit.name ?? e.exit.code_hex}`}.`,
    remediation: () =>
      "Spawn or attach again; that creates a new process instance. Evidence from the ended instance stays retrievable with get_evidence.",
    recovery: (e) => ({ kind: "reattach", previous_instance_id: e.instance_id }),
    details: (e) => ({ exit: { ...e.exit }, detach_reason: e.detach_reason }),
  },
  InstanceMismatch: {
    code: "instance_mismatch",
    category: "target_state",
    retryable: never,
    message: () => "The process behind this pid is not the instance this session was bound to (pid reuse or restart).",
    remediation: () => "Attach again to the intended process and use the new session_id.",
    recovery: (e) => ({ kind: "reattach", previous_instance_id: e.expected_instance_id }),
    details: (e) => ({
      expected_instance_id: e.expected_instance_id,
      observed: { ...e.observed },
    }),
  },
  AddressUnmapped: {
    code: "address_unmapped",
    category: "target_state",
    retryable: always,
    message: (e) => `Address ${e.address} is not inside any mapped module or range.`,
    remediation: () =>
      "Refresh the module map with list_modules and re-resolve the address (module+offset is stable across reloads), then retry.",
    recovery: (e) => ({
      kind: "refresh_module_map",
      instance_id: e.instance_id ?? null,
    }),
    details: (e) => ({ address: e.address, module_map_id: e.module_map_id }),
  },
  MemoryAccessFailed: {
    code: "memory_access_failed",
    category: "target_state",
    retryable: never,
    message: (e) => `The target refused a ${e.access} access at ${e.address}.`,
    remediation: () =>
      "Check list_memory_ranges for the region's protection; read a smaller range or a different address.",
    details: (e) => ({ address: e.address, access: e.access, size: e.size }),
  },
  InstrumentationFailed: {
    code: "instrumentation_failed",
    category: "execution_failure",
    retryable: never,
    message: (e) => `BEA could not install instrumentation (${e.reason}).`,
    remediation: (e) =>
      e.reason === "no-free-slot"
        ? 'All 4 debug registers are in use. Stop one of the recordings in details.diagnostics.holders (rec_ ids) with stop_instrumentation; a data watch can instead use method "page_guard" (or "auto", which falls back to it). Execute watches need a debug register.'
        : e.reason === "conflict"
          ? "Stop the conflicting instrument named in details.conflicting_id first."
          : "Instrument a nearby site instead (the caller or a later instruction), or use watch_memory or trace_execution.",
    details: (e) => ({
      reason: e.reason,
      address: e.address,
      conflicting_id: e.conflicting_id,
    }),
  },
  EffectUnreverted: {
    code: "effect_unreverted",
    category: "target_state",
    retryable: always,
    message: (e) => `${String(e.effect_ids.length)} effect(s) could not be reverted; the target may still be modified.`,
    remediation: () =>
      "Retry stop_instrumentation or close_session for the listed effects. If the target is BEA-owned, closing the session kills it.",
    recovery: (e) => ({ kind: "revert_effects", effect_ids: [...e.effect_ids] }),
    details: (e) => ({ effect_ids: [...e.effect_ids] }),
  },
  AccessDenied: {
    code: "access_denied",
    category: "unavailable",
    retryable: never,
    message: (e) => `The operating system denied access (${e.reason}).`,
    remediation: (e) =>
      e.reason === "elevation-required"
        ? "BEA does not elevate. Run the target unelevated, or start BEA from an elevated shell if the user approves."
        : e.reason === "anti-cheat-detected"
          ? "Anti-cheat signals were found for this target; injecting may trigger a ban. BEA refuses by default. Only the user can allow it: restart BEA with BEA_ALLOW_ANTI_CHEAT=1 (or attach.allow_anti_cheat=true in BEA_HOME/config.json)."
          : e.reason === "policy"
            ? "BEA's policy refused this request. For an output path: omit out_path to write under this run's exports directory, or ask the user to add the directory to exports.allowed_roots in BEA_HOME/config.json."
            : "BEA does not support this target. Choose a process the user owns and that is not protected.",
    details: (e) => ({ reason: e.reason }),
  },
  UnsupportedTarget: {
    code: "unsupported_target",
    category: "unsupported",
    retryable: never,
    message: (e) => `This target is not supported by BEA v0.1 (${e.reason}).`,
    remediation: () => "BEA v0.1 supports 64-bit Windows user-mode PE targets. Use a 64-bit build of the program.",
    details: (e) => ({ reason: e.reason }),
  },
  CapabilityUnavailable: {
    code: "capability_unavailable",
    category: "unavailable",
    retryable: (e) => e.retryable,
    message: (e) => `The ${e.capability} capability is unavailable (${e.reason}).`,
    remediation: () => "Run `bea doctor` and follow its remediation for the failing check.",
    details: (e) => ({ capability: e.capability, reason: e.reason }),
  },
  GateDisabled: {
    code: "capability_unavailable",
    category: "unavailable",
    retryable: never,
    message: (e) => `${e.operation} is disabled by the ${e.gate} gate.`,
    remediation: (e) =>
      `Only the user can enable this: restart BEA with ${GATE_SPECS[e.gate].env}=1 or set gates.${e.gate}=true in BEA_HOME/config.json. It cannot be enabled at runtime.`,
    details: (e) => ({
      capability: "gate",
      gate: e.gate,
      enables: GATE_SPECS[e.gate].enables,
      enable: gateEnableInstruction(e.gate),
    }),
  },
  ProviderTimeout: {
    code: "provider_timeout",
    category: "timeout",
    retryable: always,
    message: (e) => `${e.operation} did not finish within ${String(e.timeout_ms)} ms (phase ${e.phase}).`,
    remediation: () =>
      "Call session_status to see what completed, then retry with a smaller scope. This is a BEA deadline, not your client's tool timeout.",
    recovery: (e) => ({
      kind: "inspect_timeout_state",
      operation: e.operation,
      timeout_ms: e.timeout_ms,
    }),
    details: (e) => ({ timeout_ms: e.timeout_ms, phase: e.phase }),
  },
  Cancelled: {
    code: "cancelled",
    category: "cancelled",
    retryable: always,
    message: (e) => `${e.operation} was cancelled (${e.by}).`,
    remediation: () =>
      "Partial results, if any, are retained: check details.partial_observation or get_evidence before retrying.",
    details: (e) => ({ by: e.by }),
  },
  ResourceConstraint: {
    code: "resource_constraint",
    category: "resource_constraint",
    retryable: (e) => e.retryable ?? e.resource === "capacity",
    message: (e) => `${e.operation} hit BEA's ${e.resource} limit.`,
    remediation: (e) =>
      e.resource === "transport"
        ? "The result is retained but too large for one MCP response. Page it (offset/limit), use detail summary, or export_evidence."
        : e.resource === "capacity"
          ? "Close an unused session or instrument, then retry. This release has no runtime override."
          : e.resource === "disk"
            ? "Export the evidence bundle, then raise the quota in BEA_HOME/config.json and restart, or close the session."
            : "Narrow the request (shorter duration, fewer events, smaller range) and retry.",
    details: (e) => ({ resource: e.resource, limits: e.limits }),
  },
  EvidenceIntegrity: {
    code: "evidence_integrity_mismatch",
    category: "integrity_mismatch",
    retryable: never,
    message: (e) => `Evidence failed an integrity check (${e.reason}).`,
    remediation: () =>
      "Do not use the affected records. Re-export from the producing BEA run, or re-run the observation.",
    details: (e) => ({ reason: e.reason }),
  },
  RevisionConflict: {
    code: "revision_conflict",
    category: "integrity_mismatch",
    retryable: always,
    message: (e) =>
      `Unknown ${e.unknown_id} is at revision ${String(e.actual_revision)}, not ${String(e.expected_revision)}.`,
    remediation: () =>
      "Read the unknown's current revision with get_evidence, merge your change into it, and retry with that expected_revision.",
    details: (e) => ({
      unknown_id: e.unknown_id,
      expected_revision: e.expected_revision,
      actual_revision: e.actual_revision,
    }),
  },
  FileOperationFailed: {
    code: "file_operation_failed",
    category: "execution_failure",
    retryable: never,
    message: (e) => `Could not ${e.file_operation} ${e.path} (${e.reason}).`,
    remediation: (e) =>
      e.reason === "exists"
        ? "Choose a new path, or pass overwrite: true if replacing the file is intended."
        : "Check the path, its parent directory and permissions, then retry.",
    details: (e) => ({ file_operation: e.file_operation, path: e.path, reason: e.reason }),
  },
  ProviderFailure: {
    code: "execution_failure",
    category: "execution_failure",
    retryable: never,
    message: (e) => `The ${e.provider} backend failed during ${e.operation}.`,
    remediation: () =>
      "Call session_status to check the target, then run `bea doctor`. Report the details.diagnostics if it repeats.",
    details: (e) => ({ provider: e.provider }),
  },
  Internal: {
    code: "execution_failure",
    category: "execution_failure",
    retryable: never,
    message: () => "BEA hit an internal error.",
    remediation: () => "Retry once. If it repeats, run `bea doctor` and report the operation and details.",
    details: none,
  },
};

/** Typed lookup. The cast is sound: the entry is selected by the error's own tag. */
export const specFor = (error: BeaError): TagSpec<BeaErrorTag> =>
  ERROR_CATALOG[error._tag] as unknown as TagSpec<BeaErrorTag>;
