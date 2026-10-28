import type { BridgeErrorBody } from "../../domain/emuProtocol.js";
import type { BeaError, BeaErrorOf, InputIssue } from "../../domain/errors/beaError.js";
import type { JsonObject, JsonValue } from "../../domain/json.js";
import type { BridgeExit, EmuRequestFailure, EmuStartError } from "./EmuBridge.js";

/**
 * Bridge and host conditions -> BEA errors (S5 §12). Messages and remediations are BEA-authored; nothing the bridge
 * or the emulated image wrote (error messages, stderr, tracebacks) reaches a diagnostic, because emulated code and
 * image metadata are target content (CT-M8 applied to the emulator). Bridge text goes to the debug log only.
 */
export const SETUP_REMEDIATION =
  "Run `bea setup --emulator` (creates a BEA-owned Python venv with pinned unicorn 2.1.4, capstone 5.0.9, pefile 2024.8.26), then retry (a running server picks it up); or set BEA_PYTHON to a Python >= 3.10 that has them and restart the server.";
const REINSTALL_REMEDIATION = "The bridge file does not match this BEA build; reinstall bea-agents (or rebuild it).";
const DOCTOR_REMEDIATION = "Run `bea doctor --backend emulation --probe` and follow its remediation.";
const LOST_REMEDIATION = "Retry the call; the emulation session will be re-opened from its baseline.";

const unavailable = (
  operation: string,
  reason: string,
  retryable: boolean,
  extra: { readonly remediation?: string; readonly message?: string; readonly diagnostics?: JsonObject } = {},
): BeaErrorOf<"CapabilityUnavailable"> => ({
  _tag: "CapabilityUnavailable",
  operation,
  capability: "emulator",
  reason,
  retryable,
  ...extra,
});

const providerFailure = (operation: string, code: string): BeaErrorOf<"ProviderFailure"> => ({
  _tag: "ProviderFailure",
  operation,
  provider: "emulator",
  diagnostics: { bridge_error: code },
});

const issue = (path: string, message: string): InputIssue => ({ path, reason: "invalid_value", message });

/** Only BEA-controlled scalars of a bridge error's data survive (counts, codes); strings never do. */
const safeNumber = (data: Readonly<Record<string, unknown>> | undefined, key: string): number | null => {
  const value = data?.[key];
  return typeof value === "number" && Number.isFinite(value) ? value : null;
};

export interface BridgeErrorContext {
  /** input path a semantic bridge error points at (the state source, the patches …); default "$" */
  readonly path?: string;
  /** a bridge-side invalid_params is an input error only where the bridge validates caller input itself */
  readonly invalidParamsPath?: string;
  readonly address?: string;
  readonly imagePath?: string;
}

/** S5 §12, row by row. */
export const bridgeErrorToBea = (
  operation: string,
  body: BridgeErrorBody,
  context: BridgeErrorContext = {},
): BeaError => {
  const path = context.path ?? "$";
  switch (body.code) {
    case "protocol_mismatch":
      return unavailable(operation, "bridge-version-mismatch", false, { remediation: REINSTALL_REMEDIATION });
    case "engine_crashed":
    case "session_poisoned":
      return unavailable(operation, "bridge-lost", true, {
        remediation: LOST_REMEDIATION,
        message: "The emulator engine crashed during this request; the session will re-open from its baseline.",
      });
    case "unknown_session":
      return unavailable(operation, "bridge-session-lost", true, { remediation: LOST_REMEDIATION });
    case "unknown_snapshot":
      return {
        _tag: "InputError",
        operation,
        issues: [
          issue(
            context.path ?? "state.from",
            "No named snapshot with that name exists in this emulation session (session_status lists the named and the lost snapshots).",
          ),
        ],
      };
    case "unknown_symbol":
      return {
        _tag: "InputError",
        operation,
        issues: [issue(path, "The symbol is not exported by that module of the emulation session.")],
      };
    case "image_unreadable":
      return {
        _tag: "FileOperationFailed",
        operation,
        file_operation: "read",
        path: context.imagePath ?? "",
        reason: "io",
      };
    case "unsupported_image":
      return {
        _tag: "UnsupportedTarget",
        operation,
        reason: "not-pe64",
        remediation:
          "The emulator runs 64-bit PE images only; 32-bit (WoW64) and ARM64 images are unsupported in v0.1.",
      };
    case "relocation_unavailable":
      return {
        _tag: "InputError",
        operation,
        issues: [issue("image_base", "The image has no .reloc section, so it cannot be relocated; omit image_base.")],
      };
    case "layout_conflict":
      return { _tag: "UnsupportedTarget", operation, reason: "unsupported-feature" };
    case "dump_invalid":
      return {
        _tag: "EvidenceIntegrity",
        operation,
        reason: "id-mismatch",
        message: "The dump bundle failed the bridge's integrity check (a region file does not match its digest).",
        remediation: 'Re-capture the bundle with dump_memory {format:"bundle"} or emu_open {live_session_id}.',
      };
    case "dump_incomplete":
      return {
        _tag: "InputError",
        operation,
        issues: [
          issue(
            "dump_path",
            "The bundle lacks what the emulator needs (the chosen thread's TEB or the primary module); re-capture including them.",
          ),
        ],
      };
    case "unmapped":
      return {
        _tag: "MemoryAccessFailed",
        operation,
        address: context.address ?? "0x0",
        access: "read",
        size: safeNumber(body.data, "size"),
      };
    case "resource_exhausted": {
      // review fix EMU-6: a vector whose buffers do not fit the EMULATED heap or scratch region is not a bridge
      // memory problem; the fix is a session option, not the bridge-process memory limit
      const emulated = body.data?.["resource"];
      if (emulated === "heap" || emulated === "scratch") {
        const bytes = safeNumber(body.data, emulated === "heap" ? "heapBytes" : "scratchBytes");
        return {
          _tag: "ResourceConstraint",
          operation,
          resource: "memory",
          retryable: false,
          limits: {
            bridge_error: "resource_exhausted",
            emulated_region: emulated,
            ...(bytes === null ? {} : { region_bytes: bytes }),
          },
          remediation:
            emulated === "heap"
              ? 'The emulated heap cannot hold the placement:"heap" buffers (they stay allocated in the session state): re-open the session with a larger memory.heap_mb (at most 256), or use placement:"scratch" for buffers the function does not keep.'
              : "The emulator's argument scratch region cannot hold the buffers: re-open the session with a larger memory.scratch_mb (at most 256) or pass smaller buffers.",
        };
      }
      return {
        _tag: "ResourceConstraint",
        operation,
        resource: "memory",
        retryable: true,
        limits: { bridge_error: "resource_exhausted" },
        remediation:
          "Close emulation sessions, reduce memory.heap_mb or the dump size, or raise emu.memory_limit_mb (BEA_EMU_MEMORY_LIMIT_MB) and restart.",
      };
    }
    case "unsupported_combination":
      return {
        _tag: "InputError",
        operation,
        issues: [issue(path, "This combination of options is not supported by the emulator (see the tool's refines).")],
      };
    case "invalid_params": {
      // review fix EMU-2: the bridge refuses, before anything runs, vectors whose out buffers would not fit one
      // result (56 MiB of hex, Σ(2 × size + 3) per vector); that depends on the caller's vector count
      const maxVectors = safeNumber(body.data, "maxVectors");
      if (body.data?.["path"] === "params.vectors" && maxVectors !== null)
        return {
          _tag: "InputError",
          operation,
          issues: [
            issue(
              "vectors",
              `The out buffers of these vectors exceed what one emulator result carries (56 MiB of hex); send at most ${String(maxVectors)} vector(s) per call and continue with vector_offset.`,
            ),
          ],
        };
      // TypeScript validates and classifies everything before the bridge sees it: a refusal is an input error only
      // where the caller marks an input the bridge checks itself, else a host bug.
      return context.invalidParamsPath === undefined
        ? providerFailure(operation, body.code)
        : {
            _tag: "InputError",
            operation,
            issues: [issue(context.invalidParamsPath, "The emulator rejected this value.")],
          };
    }
    case "cancelled":
      return { _tag: "Cancelled", operation, by: "client" };
    case "parse_error":
    case "frame_too_large":
    case "invalid_request":
    case "unknown_method":
    case "internal_error":
      return providerFailure(operation, body.code);
  }
};

/** Bridge startup failures (S5 §5.2 EmuStartError). */
export const startErrorToBea = (operation: string, error: EmuStartError): BeaError => {
  switch (error.kind) {
    case "spawn_failed":
      return unavailable(operation, "bridge-spawn-failed", true, { remediation: DOCTOR_REMEDIATION });
    case "engine_unavailable":
      return unavailable(operation, "engine-unavailable", false, {
        remediation:
          "The Python found has no usable unicorn/capstone/pefile; run `bea setup --emulator` (or fix BEA_PYTHON).",
        diagnostics: { missing: (error.missing ?? []).slice(0, 8).map((m) => m.slice(0, 32)) },
      });
    case "exited":
      return unavailable(operation, "bridge-exited", true, {
        remediation: DOCTOR_REMEDIATION,
        diagnostics: exitDiagnostics(error.exit),
      });
    case "timeout":
      return unavailable(operation, "bridge-startup-timeout", true, {
        remediation: DOCTOR_REMEDIATION,
        diagnostics: { after_ms: Math.round(error.afterMs) },
      });
    case "version_mismatch":
      return unavailable(operation, "bridge-version-mismatch", false, {
        remediation: REINSTALL_REMEDIATION,
        diagnostics: { field: error.field },
      });
    case "cancelled":
      return { _tag: "Cancelled", operation, by: "client" };
  }
};

/** Exit facts only (code, reason); stderr is bridge/target text and stays in the debug log. */
const exitDiagnostics = (exit: BridgeExit): JsonObject => ({
  bridge_exit: { code: exit.code, reason: exit.reason } as Record<string, JsonValue>,
});

/** A failed bridge request (S5 §5.2 EmuRequestFailure) -> BEA error. */
export const requestFailureToBea = (
  operation: string,
  failure: EmuRequestFailure,
  context: BridgeErrorContext & { readonly generation?: number; readonly timeoutMs?: number } = {},
): BeaError => {
  switch (failure.kind) {
    case "bridge_error":
      return bridgeErrorToBea(operation, failure.error, context);
    case "bridge_lost":
      return unavailable(operation, "bridge-lost", true, {
        remediation: LOST_REMEDIATION,
        message: "The emulator bridge exited during this request; no result was produced.",
        diagnostics: {
          ...exitDiagnostics(failure.exit),
          ...(context.generation === undefined ? {} : { generation: context.generation }),
        },
      });
    case "deadline":
      return { _tag: "ProviderTimeout", operation, timeout_ms: context.timeoutMs ?? 0, phase: "emulator" };
    case "cancelled":
      return { _tag: "Cancelled", operation, by: "client" };
    case "local":
      return providerFailure(operation, "host_frame_rejected");
  }
};

export const crashLoopError = (operation: string): BeaErrorOf<"ProviderFailure"> => ({
  _tag: "ProviderFailure",
  operation,
  provider: "emulator",
  message: "The emulator crashed repeatedly for this session.",
  remediation:
    "close_session, then emu_open again (consider isa_guard, a smaller instruction budget, or a smaller dump).",
  diagnostics: { reason: "crash-loop" },
});

export const identityChangedError = (operation: string): BeaErrorOf<"EvidenceIntegrity"> => ({
  _tag: "EvidenceIntegrity",
  operation,
  reason: "id-mismatch",
  message: "The image or bundle changed on disk since emu_open, so the emulation session cannot be re-opened.",
  remediation: "close_session, then emu_open again on the current file.",
});
