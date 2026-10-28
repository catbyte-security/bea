import { realpath } from "node:fs";

import type { BeaError } from "../domain/errors/beaError.js";
import { isDriveAbsolute, type HostPlatform } from "../domain/paths.js";
import { err, ok, type Result } from "../domain/result.js";

/**
 * Review fix SEC-2: one rule for every caller-supplied INPUT path (pe_path, image_path, dump_path, import_evidence
 * path, spawn cwd), next to the out_path rules. Opening a UNC path authenticates to that host with the user's NTLM
 * credentials, and a spawn cwd on a share lets the target load DLLs from it. On Windows an input path must be
 * drive-absolute (no \\host\share, \\?\, \\.\ or // forms, no drive-relative or relative text), and its final path
 * (junctions, symlinks and mapped network drives resolved) must not be a network location.
 */
const LONG_PREFIX = "\\\\?\\";

/** True for a final path that names a network location ("\\server\share\…", "\\?\UNC\…"). */
export const isNetworkPath = (path: string): boolean => {
  if (path.startsWith(LONG_PREFIX)) return path.slice(LONG_PREFIX.length).toUpperCase().startsWith("UNC\\");
  return /^[\\/]{2}/u.test(path);
};

/** The final path of an existing file or directory, or null (missing, unreadable, an execution alias). */
export const finalPathOrNull = (path: string): Promise<string | null> =>
  new Promise((resolve) => {
    realpath.native(path, (error, value) => resolve(error === null ? value : null));
  });

const issue = (operation: string, field: string, message: string): BeaError => ({
  _tag: "InputError",
  operation,
  issues: [{ path: field, reason: "invalid_value", message }],
});

/** Syntax half of the rule (no filesystem access). */
export const localPathTextError = (
  operation: string,
  field: string,
  path: string,
  platform: HostPlatform,
): BeaError | null =>
  path.includes("\u0000") || !isDriveAbsolute(path, platform)
    ? issue(
        operation,
        field,
        platform === "win32"
          ? `${field} must be a drive-absolute local path such as C:\\dir\\file (no UNC, device or relative paths).`
          : `${field} must be an absolute local path.`,
      )
    : null;

/** Both halves: the text first (before any filesystem access), then the resolved location (Windows). */
export const checkLocalInputPath = async (
  operation: string,
  field: string,
  path: string,
  platform: HostPlatform,
  resolve: (path: string) => Promise<string | null> = finalPathOrNull,
): Promise<Result<true, BeaError>> => {
  const textError = localPathTextError(operation, field, path, platform);
  if (textError !== null) return err(textError);
  if (platform !== "win32") return ok(true);
  const final = await resolve(path);
  if (final !== null && isNetworkPath(final))
    return err({
      _tag: "AccessDenied",
      operation,
      reason: "policy",
      message: `${field} resolves to a network location; BEA opens local files only.`,
      remediation: "Copy the file (or directory) to a local drive and pass that path.",
      diagnostics: { field },
    });
  return ok(true);
};
