import type { z } from "zod";

import type { GateId } from "../gates.js";
import type { BeaError, BeaErrorOf, CleanupState, InputIssue, ReferenceKind } from "./beaError.js";

/** Format a zod path as `a.b[2].c`; the root is "". */
export const formatIssuePath = (path: readonly PropertyKey[]): string => {
  let out = "";
  for (const key of path) {
    if (typeof key === "number") out += `[${String(key)}]`;
    else out += out.length === 0 ? String(key) : `.${String(key)}`;
  }
  return out;
};

const hasPath = (root: unknown, path: readonly PropertyKey[]): boolean => {
  let value: unknown = root;
  for (const key of path) {
    if (typeof value !== "object" || value === null || !Object.hasOwn(value, key)) return false;
    value = Reflect.get(value, key);
  }
  return true;
};

const toNumber = (value: unknown): number | undefined =>
  typeof value === "number" ? value : typeof value === "bigint" ? Number(value) : undefined;

/** Map zod 4 issues to REA-style input issues. `raw` is the caller's unparsed input. */
export const issuesFromZod = (raw: unknown, issues: readonly z.core.$ZodIssue[]): InputIssue[] => {
  const out: InputIssue[] = [];
  for (const issue of issues) {
    const path = formatIssuePath(issue.path);
    switch (issue.code) {
      case "unrecognized_keys":
        for (const key of issue.keys)
          out.push({
            path: formatIssuePath([...issue.path, key]),
            reason: "unknown_argument",
            message: `Unknown field "${key}".`,
          });
        break;
      case "invalid_type":
        out.push(
          hasPath(raw, issue.path)
            ? { path, reason: "invalid_type", message: issue.message, expected: issue.expected }
            : { path, reason: "missing_argument", message: "Required field is missing." },
        );
        break;
      case "too_small": {
        const minimum = toNumber(issue.minimum);
        out.push({
          path,
          reason: "out_of_range",
          message: issue.message,
          ...(minimum === undefined ? {} : { minimum }),
        });
        break;
      }
      case "too_big": {
        const maximum = toNumber(issue.maximum);
        out.push({
          path,
          reason: "out_of_range",
          message: issue.message,
          ...(maximum === undefined ? {} : { maximum }),
        });
        break;
      }
      case "invalid_format":
        out.push({ path, reason: "invalid_format", message: issue.message, expected: issue.format });
        break;
      case "custom":
        out.push({
          path,
          reason: issue.path.length === 0 ? "conflicting_arguments" : "invalid_value",
          message: issue.message,
        });
        break;
      default:
        out.push({ path, reason: "invalid_value", message: issue.message });
    }
  }
  return out;
};

export const inputError = (operation: string, issues: readonly InputIssue[]): BeaErrorOf<"InputError"> => ({
  _tag: "InputError",
  operation,
  issues,
});

export const inputErrorFromZod = (operation: string, raw: unknown, error: z.ZodError): BeaErrorOf<"InputError"> =>
  inputError(operation, issuesFromZod(raw, error.issues));

export const sessionNotFound = (operation: string, session_id: string): BeaErrorOf<"SessionNotFound"> => ({
  _tag: "SessionNotFound",
  operation,
  session_id,
});

export const referenceNotFound = (
  operation: string,
  kind: ReferenceKind,
  id: string,
): BeaErrorOf<"ReferenceNotFound"> => ({
  _tag: "ReferenceNotFound",
  operation,
  reference: { kind, id },
});

export const invalidState = (
  operation: string,
  state: string,
  expected: readonly string[],
): BeaErrorOf<"InvalidState"> => ({ _tag: "InvalidState", operation, state, expected });

export const gateDisabled = (operation: string, gate: GateId): BeaErrorOf<"GateDisabled"> => ({
  _tag: "GateDisabled",
  operation,
  gate,
});

export const cancelled = (operation: string, by: BeaErrorOf<"Cancelled">["by"]): BeaErrorOf<"Cancelled"> => ({
  _tag: "Cancelled",
  operation,
  by,
});

export const providerTimeout = (
  operation: string,
  timeout_ms: number,
  phase: string,
): BeaErrorOf<"ProviderTimeout"> => ({ _tag: "ProviderTimeout", operation, timeout_ms, phase });

export const serverShuttingDown = (operation: string): BeaErrorOf<"CapabilityUnavailable"> => ({
  _tag: "CapabilityUnavailable",
  operation,
  capability: "server",
  reason: "shutting-down",
  retryable: false,
});

/** Programmer or unexpected failure. `cause` is logged at debug level, never projected. */
export const internalError = (operation: string, cause: unknown): BeaErrorOf<"Internal"> => ({
  _tag: "Internal",
  operation,
  cause,
});

export const withEffects = <E extends BeaError>(error: E, effectIds: readonly string[]): E =>
  effectIds.length === 0 ? error : { ...error, effects_applied: [...(error.effects_applied ?? []), ...effectIds] };

export const withPartial = <E extends BeaError>(error: E, evidenceId: string): E =>
  error.partial !== undefined ? error : { ...error, partial: { kind: "retained-evidence", evidence_id: evidenceId } };

export const withCleanup = <E extends BeaError>(error: E, cleanup: CleanupState): E => ({
  ...error,
  cleanup,
});
