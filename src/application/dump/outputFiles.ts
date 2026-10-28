import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat, mkdir, open, rename, rm, stat } from "node:fs/promises";
import { posix, win32 } from "node:path";

import type { BeaConfig } from "../../domain/config.js";
import type { BeaError, BeaErrorOf } from "../../domain/errors/beaError.js";
import { checkOutputPath, type OutputPathPolicy } from "../../domain/outputPaths.js";
import { err, ok, type Result } from "../../domain/result.js";

/**
 * Output files of dump_memory (D-INT-42 / CT-I8). Every caller-chosen out_path passes checkOutputPath (refusal →
 * access_denied {reason:"policy"}); the default lives under <run dir>/exports/. Writers never overwrite: files are
 * created with O_EXCL ('wx'), bundle directories are staged next to the target and renamed into place only when the
 * target does not exist. Parents are created only under the exports directory.
 */
export const outputPolicy = (
  config: BeaConfig,
  runId: string,
  env: Readonly<Record<string, string | undefined>>,
): OutputPathPolicy => {
  const systemRoots =
    config.platform === "win32"
      ? [env["SystemRoot"], env["windir"], "C:\\Windows"].filter(
          (root): root is string => root !== undefined && /^[A-Za-z]:[\\/]/u.test(root),
        )
      : ["/etc", "/usr", "/bin", "/sbin", "/lib"];
  return {
    platform: config.platform,
    exportsDir: config.layout.exportsDir(runId),
    allowedRoots: config.exports.allowedRoots.value,
    systemRoots,
  };
};

const pathApi = (policy: OutputPathPolicy) => (policy.platform === "win32" ? win32 : posix);

export const checkOutPath = (
  operation: string,
  requested: string,
  policy: OutputPathPolicy,
): Result<string, BeaErrorOf<"AccessDenied">> => {
  const checked = checkOutputPath(requested, policy);
  return checked.ok
    ? ok(checked.path)
    : err({
        _tag: "AccessDenied",
        operation,
        reason: "policy",
        message: checked.message,
        diagnostics: { policy: checked.reason },
      });
};

/** Untrusted module text → a short, safe file-name stem. */
export const safeStem = (text: string): string => {
  const stem = text
    .replace(/[^A-Za-z0-9._-]+/gu, "_")
    .replace(/^[._]+/u, "")
    .slice(0, 64);
  return stem.length > 0 ? stem : "dump";
};

export const defaultOutPath = (policy: OutputPathPolicy, fileName: string): string =>
  pathApi(policy).join(policy.exportsDir, fileName);

const fileError = (
  operation: string,
  file_operation: BeaErrorOf<"FileOperationFailed">["file_operation"],
  path: string,
  cause: unknown,
): BeaErrorOf<"FileOperationFailed"> => {
  const code = typeof cause === "object" && cause !== null ? Reflect.get(cause, "code") : undefined;
  const reason =
    code === "EEXIST" || code === "ENOTEMPTY"
      ? "exists"
      : code === "ENOENT"
        ? "missing"
        : code === "EACCES" || code === "EPERM"
          ? "permission"
          : code === "ENOTDIR"
            ? "not-directory"
            : code === "EISDIR"
              ? "not-file"
              : "io";
  return { _tag: "FileOperationFailed", operation, file_operation, path, reason, cause };
};

/** Creates the parent directory when it lies under the exports directory; elsewhere it must already exist. */
export const prepareParent = async (
  operation: string,
  path: string,
  policy: OutputPathPolicy,
): Promise<Result<void, BeaError>> => {
  const api = pathApi(policy);
  const parent = api.dirname(path);
  const fold = (p: string) => (policy.platform === "win32" ? api.normalize(p).toLowerCase() : api.normalize(p));
  const exportsDir = fold(policy.exportsDir);
  const underExports = fold(parent) === exportsDir || fold(parent).startsWith(`${exportsDir}${api.sep}`);
  try {
    if (underExports) await mkdir(parent, { recursive: true });
    else if (!(await stat(parent)).isDirectory()) return err(fileError(operation, "stat", parent, { code: "ENOTDIR" }));
    return ok(undefined);
  } catch (cause) {
    return err(fileError(operation, underExports ? "mkdir" : "stat", parent, cause));
  }
};

export interface WrittenFile {
  readonly path: string;
  readonly bytes: number;
  readonly sha256: string;
}

/** Writes a NEW file (O_EXCL). On any failure after creation the partial file is removed. */
export const writeNewFile = async (
  operation: string,
  path: string,
  content: Uint8Array | AsyncIterable<Uint8Array>,
  signal?: AbortSignal,
): Promise<Result<WrittenFile, BeaError>> => {
  let handle;
  try {
    handle = await open(path, "wx");
  } catch (cause) {
    return err(fileError(operation, "write", path, cause));
  }
  const hash = createHash("sha256");
  let bytes = 0;
  try {
    const chunks: AsyncIterable<Uint8Array> | Uint8Array[] = content instanceof Uint8Array ? [content] : content;
    for await (const chunk of chunks) {
      if (signal?.aborted === true) throw Object.assign(new Error("cancelled"), { code: "ECANCELED" });
      hash.update(chunk);
      let written = 0;
      while (written < chunk.length) {
        const { bytesWritten } = await handle.write(chunk, written, chunk.length - written);
        written += bytesWritten;
      }
      bytes += chunk.length;
    }
    await handle.close();
    return ok({ path, bytes, sha256: hash.digest("hex") });
  } catch (cause) {
    await handle.close().catch(() => undefined);
    await rm(path, { force: true }).catch(() => undefined);
    return err(fileError(operation, "write", path, cause));
  }
};

/** sha256 + size of an existing regular file, or null. */
export const hashFile = async (
  path: string,
  signal?: AbortSignal,
): Promise<{ readonly bytes: number; readonly sha256: string } | null> => {
  try {
    const info = await lstat(path);
    if (!info.isFile()) return null;
    const hash = createHash("sha256");
    for await (const chunk of createReadStream(path, { signal })) hash.update(chunk as Buffer);
    return { bytes: info.size, sha256: hash.digest("hex") };
  } catch {
    return null;
  }
};

/** True when nothing exists at `path` (a dangling symlink counts as existing). */
export const pathIsFree = async (path: string): Promise<boolean> => {
  try {
    await lstat(path);
    return false;
  } catch (cause) {
    return typeof cause === "object" && cause !== null && Reflect.get(cause, "code") === "ENOENT";
  }
};

/** Publishes a staged directory at `target` (R10): refuses an existing target; removes the staging dir on failure. */
export const publishDirectory = async (
  operation: string,
  staging: string,
  target: string,
): Promise<Result<void, BeaError>> => {
  if (!(await pathIsFree(target))) {
    await rm(staging, { recursive: true, force: true }).catch(() => undefined);
    return err(fileError(operation, "rename", target, { code: "EEXIST" }));
  }
  try {
    await rename(staging, target);
    return ok(undefined);
  } catch (cause) {
    await rm(staging, { recursive: true, force: true }).catch(() => undefined);
    return err(fileError(operation, "rename", target, cause));
  }
};
