import type { BeaError } from "../../domain/errors/beaError.js";
import type { PeError, PeErrorKind } from "../../ports/pe.js";

/**
 * PeError (S2 §17.1) as a throwable inside the reader, and its projection onto the closed BeaError union.
 * `detail` is BEA-curated text (never raw file bytes); the path is the caller's own input.
 */
export class PeFailure extends Error {
  override readonly name = "PeFailure";
  constructor(
    readonly pe: PeError,
    /** PE32 (optional header magic 0x10b): WoW64 images are unsupported_target{wow64} (F8) */
    readonly pe32 = false,
  ) {
    super(pe.detail);
  }
}

export const peFailure = (kind: PeErrorKind, detail: string, field?: string): PeFailure =>
  new PeFailure(field === undefined ? { kind, detail } : { kind, detail, field });

/** Node fs error code → PeErrorKind. */
export const fsErrorKind = (cause: unknown): PeErrorKind => {
  const code = typeof cause === "object" && cause !== null ? Reflect.get(cause, "code") : undefined;
  return code === "ENOENT" || code === "ENOTDIR" ? "not_found" : "io";
};

const fsReason = (cause: unknown): "missing" | "permission" | "not-file" | "io" => {
  const code = typeof cause === "object" && cause !== null ? Reflect.get(cause, "code") : undefined;
  if (code === "ENOENT" || code === "ENOTDIR") return "missing";
  if (code === "EACCES" || code === "EPERM" || code === "EBUSY") return "permission";
  if (code === "EISDIR") return "not-file";
  return "io";
};

/** Wrap a filesystem failure while opening/reading a PE. */
export const fileError = (operation: string, path: string, cause: unknown): BeaError => ({
  _tag: "FileOperationFailed",
  operation,
  file_operation: "read",
  path,
  reason: fsReason(cause),
  cause,
});

/** PeError → BeaError (S2 §16.2: "the module's PE cannot be read" → unsupported_target / file_operation_failed). */
export const peErrorToBea = (operation: string, path: string, failure: PeFailure): BeaError => {
  const { pe } = failure;
  const diagnostics = { pe_error: pe.kind, detail: pe.detail.slice(0, 200), ...(pe.field ? { field: pe.field } : {}) };
  switch (pe.kind) {
    case "not_found":
      return { _tag: "FileOperationFailed", operation, file_operation: "read", path, reason: "missing", diagnostics };
    case "io":
      return { _tag: "FileOperationFailed", operation, file_operation: "read", path, reason: "io", diagnostics };
    case "not_pe":
      return { _tag: "UnsupportedTarget", operation, reason: "not-pe64", diagnostics };
    case "unsupported_format":
      return {
        _tag: "UnsupportedTarget",
        operation,
        reason: failure.pe32 ? "wow64" : "unsupported-format",
        diagnostics,
        ...(failure.pe32
          ? { message: "The file is a 32-bit (PE32) image; BEA v0.1 supports only 64-bit (PE32+) Windows images." }
          : {}),
      };
    case "malformed":
      return { _tag: "UnsupportedTarget", operation, reason: "unsupported-format", diagnostics };
  }
};
