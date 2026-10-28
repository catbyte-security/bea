import type { GateId } from "../gates.js";
import type { JsonObject } from "../json.js";

/** Closed list. Adding a tag is a contract change: update ERROR_CATALOG and the golden. */
export const BEA_ERROR_TAGS = [
  "InputError",
  "ConfigurationError",
  "SessionNotFound",
  "ReferenceNotFound",
  "InvalidState",
  "TargetExited",
  "InstanceMismatch",
  "AddressUnmapped",
  "MemoryAccessFailed",
  "InstrumentationFailed",
  "EffectUnreverted",
  "AccessDenied",
  "UnsupportedTarget",
  "CapabilityUnavailable",
  "GateDisabled",
  "ProviderTimeout",
  "Cancelled",
  "ResourceConstraint",
  "EvidenceIntegrity",
  "RevisionConflict",
  "FileOperationFailed",
  "ProviderFailure",
  "Internal",
] as const;

export type BeaErrorTag = (typeof BEA_ERROR_TAGS)[number];

/** Agent errors (src/shared/agentProtocol.ts AgentError) are a SEPARATE closed union mapped exhaustively by
 *  src/domain/errors/agentErrorMap.ts (S4 §4.11; DESIGN conflict C-05). */

export type InputIssueReason =
  | "unknown_argument"
  | "missing_argument"
  | "invalid_type"
  | "out_of_range"
  | "invalid_value"
  | "invalid_format"
  | "conflicting_arguments";

/** Secret-safe: built from the schema and the caller's own field names. */
export interface InputIssue {
  readonly path: string;
  readonly reason: InputIssueReason;
  readonly message: string;
  readonly expected?: string;
  readonly minimum?: number;
  readonly maximum?: number;
}

export interface RetainedEvidenceRef {
  readonly kind: "retained-evidence";
  readonly evidence_id: string;
}

export interface CleanupState {
  readonly status: "incomplete";
  readonly resources: readonly string[];
  readonly reason: string;
}

/** Fields every error may carry. Plain data: structured-clone and JSON safe except `cause`. */
export interface BeaErrorBase<Tag extends BeaErrorTag> {
  readonly _tag: Tag;
  /** Tool name or internal operation ("spawn_process", "ledger.append"). */
  readonly operation: string;
  /** Curated, caller-safe override of the catalog message. Never raw provider text. */
  readonly message?: string;
  /** Curated override of the catalog remediation. */
  readonly remediation?: string;
  /** Producer-owned, caller-safe facts. Bounded strings only. */
  readonly diagnostics?: JsonObject;
  /** Evidence retained before the failure. */
  readonly partial?: RetainedEvidenceRef;
  /** Effects (fx_ ids) applied to a target before the failure. Always projected. */
  readonly effects_applied?: readonly string[];
  /** Unresolved cleanup. Overrides the wire code to cleanup_incomplete. */
  readonly cleanup?: CleanupState;
  /** The process instance involved, if any. */
  readonly instance_id?: string;
  /** Host-only. Never projected, never sent across a process boundary. */
  readonly cause?: unknown;
}

export type ReferenceKind =
  | "instrument"
  | "scan"
  | "stream"
  | "evidence"
  | "effect"
  | "snapshot"
  | "unknown"
  | "blob"
  | "job"
  | "recording"
  | "instance"
  | "module_map"
  | "session-scoped-handle";

export type ExitKind = "normal" | "ntstatus" | "bea-kill" | "unknown";

export type BeaError =
  | (BeaErrorBase<"InputError"> & { readonly issues: readonly InputIssue[] })
  | (BeaErrorBase<"ConfigurationError"> & {
      readonly settings: readonly {
        readonly setting: string;
        readonly constraint: string;
        readonly source: "env" | "config-file" | "cli";
      }[];
    })
  | (BeaErrorBase<"SessionNotFound"> & { readonly session_id: string })
  | (BeaErrorBase<"ReferenceNotFound"> & {
      readonly reference: { readonly kind: ReferenceKind; readonly id: string };
    })
  | (BeaErrorBase<"InvalidState"> & {
      readonly state: string;
      readonly expected: readonly string[];
    })
  | (BeaErrorBase<"TargetExited"> & {
      readonly instance_id: string;
      readonly exit: {
        readonly code: number | null;
        readonly code_hex: string | null;
        readonly kind: ExitKind;
        readonly name: string | null;
      };
      readonly detach_reason: string | null;
    })
  | (BeaErrorBase<"InstanceMismatch"> & {
      readonly expected_instance_id: string;
      readonly observed: { readonly pid: number; readonly start_time: string | null };
    })
  | (BeaErrorBase<"AddressUnmapped"> & {
      readonly address: string;
      readonly module_map_id: string | null;
    })
  | (BeaErrorBase<"MemoryAccessFailed"> & {
      readonly address: string;
      readonly access: "read" | "write" | "execute";
      readonly size: number | null;
    })
  | (BeaErrorBase<"InstrumentationFailed"> & {
      readonly reason:
        | "install-failed"
        | "conflict"
        | "no-free-slot"
        | "unsupported-code"
        | "stalker-failed"
        | "monitor-failed"
        | "hook-denied";
      readonly address: string | null;
      readonly conflicting_id: string | null;
    })
  | (BeaErrorBase<"EffectUnreverted"> & { readonly effect_ids: readonly string[] })
  | (BeaErrorBase<"AccessDenied"> & {
      readonly reason:
        | "elevation-required"
        | "protected-process"
        | "critical-process"
        | "system-process"
        | "session-0"
        | "other-user"
        | "higher-integrity"
        | "bea-process-tree"
        | "anti-cheat-detected"
        | "policy"
        | "os-denied";
    })
  | (BeaErrorBase<"UnsupportedTarget"> & {
      readonly reason:
        | "wow64"
        | "not-pe64"
        | "unsupported-arch"
        | "unsupported-platform"
        | "unsupported-format"
        | "unsupported-feature";
    })
  | (BeaErrorBase<"CapabilityUnavailable"> & {
      readonly capability: "frida" | "jobhost" | "containment" | "emulator" | "agent" | "server" | "platform";
      /** Short curated reason code, e.g. "binding-load-failed", "shutting-down". */
      readonly reason: string;
      readonly retryable: boolean;
    })
  | (BeaErrorBase<"GateDisabled"> & { readonly gate: GateId })
  | (BeaErrorBase<"ProviderTimeout"> & {
      readonly timeout_ms: number;
      readonly phase: string;
    })
  | (BeaErrorBase<"Cancelled"> & {
      readonly by: "client" | "signal" | "server-shutdown";
    })
  | (BeaErrorBase<"ResourceConstraint"> & {
      readonly resource: "capacity" | "transport" | "disk" | "events" | "memory" | "time";
      readonly limits: JsonObject;
      /** Default: resource === "capacity". */
      readonly retryable?: boolean;
    })
  | (BeaErrorBase<"EvidenceIntegrity"> & {
      readonly reason: "id-mismatch" | "conflicting-record" | "dangling-link" | "non-canonical" | "schema";
    })
  | (BeaErrorBase<"RevisionConflict"> & {
      readonly unknown_id: string;
      readonly expected_revision: number;
      readonly actual_revision: number;
    })
  | (BeaErrorBase<"FileOperationFailed"> & {
      readonly file_operation: "read" | "write" | "rename" | "link" | "mkdir" | "stat" | "remove";
      readonly path: string;
      readonly reason:
        | "exists"
        | "missing"
        | "not-file"
        | "not-directory"
        | "permission"
        | "symlink"
        | "invalid-json"
        | "io";
    })
  | (BeaErrorBase<"ProviderFailure"> & {
      readonly provider: "frida" | "agent" | "jobhost" | "emulator" | "python" | "filesystem";
    })
  | BeaErrorBase<"Internal">;

export type BeaErrorOf<Tag extends BeaErrorTag> = Extract<BeaError, { readonly _tag: Tag }>;

const TAG_SET: ReadonlySet<string> = new Set(BEA_ERROR_TAGS);

/** Structural guard for values that crossed a boundary (agent RPC, worker). */
export const isBeaError = (value: unknown): value is BeaError =>
  typeof value === "object" &&
  value !== null &&
  typeof Reflect.get(value, "_tag") === "string" &&
  TAG_SET.has(Reflect.get(value, "_tag") as string) &&
  typeof Reflect.get(value, "operation") === "string";
