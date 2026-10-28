import type { AbortReason } from "../../domain/deadline.js";
import { isAbortReason } from "../../domain/deadline.js";
import type { BeaError, BeaErrorOf } from "../../domain/errors/beaError.js";
import { cancelled, inputError, providerTimeout } from "../../domain/errors/constructors.js";
import type { JobHostEvent } from "../../domain/jobhostProtocol.js";
import type { StatusViolation } from "./statusLines.js";

/**
 * bea-jobhost failures → BeaError (S3 §5.7 table, §17). Messages stay curated: helper `detail` strings are fixed
 * ASCII tokens authored by bea-jobhost.c and only ever go to bounded `diagnostics`, never to `message`.
 */
export type HelperErrorEvent = Extract<JobHostEvent, { readonly event: "error" }>;

/** What the caller asked for, so a failure can name the right input (`pid` or `exe`). */
export interface HelperRequestFacts {
  readonly pid?: number;
  readonly exe?: string;
}

const ERROR_ACCESS_DENIED = 5;
const ERROR_FILE_NOT_FOUND = 2;
const ERROR_PATH_NOT_FOUND = 3;
const ERROR_INVALID_PARAMETER = 87;
const ERROR_ELEVATION_REQUIRED = 740;

const diagnosticsOf = (e: HelperErrorEvent): Record<string, string | number | boolean> => ({
  stage: e.stage,
  win32: e.win32,
  detail: e.detail.slice(0, 128),
  ...(e.expected === undefined ? {} : { expected: e.expected }),
  ...(e.actual === undefined ? {} : { actual: e.actual }),
  ...(e.wasInJob === undefined ? {} : { was_in_job: e.wasInJob }),
});

const providerFailure = (
  operation: string,
  diagnostics: Record<string, string | number | boolean | null>,
): BeaErrorOf<"ProviderFailure"> => ({ _tag: "ProviderFailure", operation, provider: "jobhost", diagnostics });

/** S3 §5.7 error mapping for an `error` status event received before the mode's decisive event. */
export const mapHelperError = (operation: string, e: HelperErrorEvent, facts: HelperRequestFacts): BeaError => {
  const diagnostics = diagnosticsOf(e);
  switch (e.stage) {
    case "identity":
      return {
        _tag: "InstanceMismatch",
        operation,
        // The provider has no instance id; the session layer that bound the identity substitutes its own.
        expected_instance_id: "",
        observed: { pid: facts.pid ?? 0, start_time: e.actual ?? null },
        // review fix LIFE-5: since the helper compares file identity (a junction, symlink, subst drive or 8.3 name
        // of the same file is accepted), image-path means a genuinely different file, not pid reuse or a restart
        ...(e.detail === "image-path"
          ? {
              message:
                "The image Windows reports for the process is a different file from the requested program; BEA did not adopt it.",
              remediation:
                "Check that program names the executable that actually runs (a launcher may start another file), then retry.",
            }
          : {}),
        diagnostics,
      };
    case "open":
      if (e.win32 === ERROR_INVALID_PARAMETER)
        return {
          ...inputError(operation, [
            { path: "pid", reason: "invalid_value", message: "No process with this pid exists." },
          ]),
          diagnostics,
        };
      if (e.win32 === ERROR_ACCESS_DENIED) return { _tag: "AccessDenied", operation, reason: "os-denied", diagnostics };
      return providerFailure(operation, diagnostics);
    case "assign":
      return {
        _tag: "CapabilityUnavailable",
        operation,
        capability: "containment",
        reason: "assign-failed",
        retryable: false,
        diagnostics,
      };
    case "create":
      if (e.win32 === ERROR_ELEVATION_REQUIRED)
        return { _tag: "AccessDenied", operation, reason: "elevation-required", diagnostics };
      if (e.win32 === ERROR_FILE_NOT_FOUND || e.win32 === ERROR_PATH_NOT_FOUND)
        return {
          ...inputError(operation, [
            { path: "exe", reason: "invalid_value", message: "The program file was not found." },
          ]),
          diagnostics,
        };
      if (e.win32 === ERROR_ACCESS_DENIED) return { _tag: "AccessDenied", operation, reason: "os-denied", diagnostics };
      return providerFailure(operation, diagnostics);
    case "usage":
      if (e.detail === "command-line-too-long")
        return {
          ...inputError(operation, [
            { path: "args", reason: "out_of_range", message: "The command line exceeds 32,767 characters." },
          ]),
          diagnostics,
        };
      return providerFailure(operation, diagnostics);
    default:
      return providerFailure(operation, diagnostics);
  }
};

/** The status channel broke the protocol: the helper is terminated (S3 §5.2). */
export const protocolViolationError = (operation: string, violation: StatusViolation): BeaError => {
  if (violation.kind === "protocol-mismatch")
    return {
      _tag: "CapabilityUnavailable",
      operation,
      capability: "jobhost",
      reason: "protocol-mismatch",
      retryable: false,
      diagnostics: { protocol: typeof violation.protocol === "number" ? violation.protocol : null },
    };
  return providerFailure(operation, { reason: "protocol-violation", violation: violation.kind });
};

/** The helper exited (or could not start) before its decisive event, without an `error` line. */
export const helperExitedEarlyError = (
  operation: string,
  facts: { readonly code: number | null; readonly signal: string | null; readonly stderr: string },
): BeaError =>
  providerFailure(operation, {
    reason: "helper-exited-early",
    helper_exit_code: facts.code,
    signal: facts.signal,
    stderr: facts.stderr.slice(0, 512),
  });

/** `child_process.spawn` of the helper failed (missing file, access denied). */
export const helperLaunchError = (operation: string, cause: unknown): BeaError => {
  const code = typeof cause === "object" && cause !== null ? String(Reflect.get(cause, "code") ?? "") : "";
  if (code === "ENOENT")
    return {
      _tag: "CapabilityUnavailable",
      operation,
      capability: "jobhost",
      reason: "binary-missing",
      retryable: false,
    };
  return providerFailure(operation, { reason: "helper-launch-failed", errno: code.slice(0, 32) });
};

/** Deadline or caller abort while the helper was starting (the helper has been terminated). */
export const startAbortedError = (operation: string, reason: unknown, budgetMs: number, phase: string): BeaError => {
  const typed: AbortReason | null = isAbortReason(reason) ? reason : null;
  if (typed?.kind === "deadline") return providerTimeout(operation, budgetMs, phase);
  return cancelled(operation, typed?.kind === "shutdown" ? "server-shutdown" : "signal");
};
