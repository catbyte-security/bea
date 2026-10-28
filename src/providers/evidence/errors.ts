import type { BeaErrorOf } from "../../domain/errors/beaError.js";
import type { JsonObject } from "../../domain/json.js";

/** Evidence-store error constructors (S2 §20). Messages are BEA-authored; paths are BEA's own run files. */
type FileOp = BeaErrorOf<"FileOperationFailed">["file_operation"];
type FileReason = BeaErrorOf<"FileOperationFailed">["reason"];

const errnoOf = (cause: unknown): string | undefined =>
  typeof cause === "object" && cause !== null && typeof Reflect.get(cause, "code") === "string"
    ? (Reflect.get(cause, "code") as string)
    : undefined;

export const isErrno = (cause: unknown, ...codes: readonly string[]): boolean => {
  const code = errnoOf(cause);
  return code !== undefined && codes.includes(code);
};

const reasonOf = (cause: unknown): FileReason => {
  switch (errnoOf(cause)) {
    case "EEXIST":
    case "ENOTEMPTY":
      return "exists";
    case "ENOENT":
      return "missing";
    case "EISDIR":
      return "not-file";
    case "ENOTDIR":
      return "not-directory";
    case "EACCES":
    case "EPERM":
    case "EBUSY":
      return "permission";
    case "ELOOP":
      return "symlink";
    default:
      return "io";
  }
};

export const fileError = (
  operation: string,
  file_operation: FileOp,
  path: string,
  cause?: unknown,
  reason?: FileReason,
): BeaErrorOf<"FileOperationFailed"> => ({
  _tag: "FileOperationFailed",
  operation,
  file_operation,
  path,
  reason: reason ?? reasonOf(cause),
  ...(cause === undefined ? {} : { cause }),
});

export type QuotaKind = "ledger" | "blobs" | "stream" | "streams";

const KNOBS: { readonly [K in QuotaKind]: string } = {
  ledger: "BEA_LEDGER_QUOTA_MB",
  blobs: "BEA_BLOB_QUOTA_MB",
  stream: "BEA_STREAM_QUOTA_MB",
  streams: "BEA_STREAM_TOTAL_QUOTA_MB",
};

/** S2 §9.7: quota errors name the knob; not retryable in this run. */
export const quotaError = (
  operation: string,
  quota: QuotaKind,
  limitMib: number,
  extra: JsonObject = {},
): BeaErrorOf<"ResourceConstraint"> => ({
  _tag: "ResourceConstraint",
  operation,
  resource: "disk",
  limits: { quota, limit_mib: limitMib, knob: KNOBS[quota], ...extra },
  retryable: false,
  message: `${operation} reached the run's ${quota} quota (${String(limitMib)} MiB); later data was not retained.`,
  remediation: `Export the evidence, then set ${KNOBS[quota]} (or config.json quotas) before starting the server.`,
});

export const noSpaceError = (operation: string, path: string, cause: unknown): BeaErrorOf<"ResourceConstraint"> => ({
  _tag: "ResourceConstraint",
  operation,
  resource: "disk",
  limits: { reason: "no_space", path },
  retryable: false,
  cause,
});

/** Map an fs failure: ENOSPC is a disk resource constraint, everything else a file operation failure. */
export const ioError = (
  operation: string,
  file_operation: FileOp,
  path: string,
  cause: unknown,
): BeaErrorOf<"ResourceConstraint"> | BeaErrorOf<"FileOperationFailed"> =>
  isErrno(cause, "ENOSPC") ? noSpaceError(operation, path, cause) : fileError(operation, file_operation, path, cause);

export const internalError = (operation: string, detail: string, cause?: unknown): BeaErrorOf<"Internal"> => ({
  _tag: "Internal",
  operation,
  diagnostics: { detail: detail.slice(0, 300) },
  ...(cause === undefined ? {} : { cause }),
});
