import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat, readFile } from "node:fs/promises";
import { join } from "node:path";

import { canonicalJson } from "../../domain/canonical.js";
import {
  DUMP_MANIFEST_FILE,
  DUMP_REGIONS_DIR,
  dumpManifestIssues,
  dumpManifestSchema,
  dumpTotalBytes,
  type DumpManifest,
} from "../../domain/dumpBundle.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { inputError } from "../../domain/errors/constructors.js";
import type { JsonValue } from "../../domain/json.js";
import { err, ok, type Result } from "../../domain/result.js";
import { bundleIdOf } from "./DumpBundleWriter.js";

/**
 * TypeScript-side verification of a bea.dump/1 bundle (S5 §10.1/§10.3 step 0; CI-M18: the fs half lives here, the
 * schema and pure constraints in src/domain/dumpBundle.ts). Checks, in order: manifest.json is strict-schema valid,
 * JCS-canonical and carries its own bundle_id; the layout constraints (alignment, no overlap, readable-only memory
 * map, one primary thread whose TEB is captured, size limits); every region file exists, is a regular file of exactly
 * `size` bytes and hashes to its name. Used by dump_memory after writing and by WP-EMU before `session.open`.
 *
 * Errors: a missing/unreadable directory or manifest → file_operation_failed; a malformed or inconsistent bundle →
 * invalid_request at `path` (default "dump_path"); a region file whose bytes do not match → evidence_integrity_mismatch;
 * over the size limits → resource_constraint (memory).
 */
export interface VerifyDumpOptions {
  /** emu.dump_max_mb in bytes */
  readonly maxTotalBytes: number;
  readonly memoryLimitBytes?: number;
  readonly threadId?: number;
  /** input path used in invalid_request issues */
  readonly path?: string;
  readonly operation?: string;
  readonly signal?: AbortSignal;
}
export interface VerifiedDumpBundle {
  readonly dir: string;
  readonly manifest: DumpManifest;
  readonly totalBytes: number;
}

const ISSUE_CAP = 16;

const invalid = (operation: string, path: string, problems: readonly string[]): BeaError =>
  inputError(
    operation,
    problems.slice(0, ISSUE_CAP).map((problem) => ({
      path,
      reason: "invalid_value",
      message: `Not a valid bea.dump/1 bundle: ${problem}.`,
    })),
  );

const sha256File = async (path: string, signal?: AbortSignal): Promise<string> => {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path, signal === undefined ? {} : { signal }))
    hash.update(chunk as Buffer);
  return hash.digest("hex");
};

const readManifest = async (
  dir: string,
  operation: string,
): Promise<Result<{ readonly text: string; readonly value: unknown }, BeaError>> => {
  const file = join(dir, DUMP_MANIFEST_FILE);
  let text: string;
  try {
    text = await readFile(file, "utf8");
  } catch (cause) {
    const code = typeof cause === "object" && cause !== null ? Reflect.get(cause, "code") : undefined;
    return err({
      _tag: "FileOperationFailed",
      operation,
      file_operation: "read",
      path: file,
      reason: code === "ENOENT" ? "missing" : code === "EISDIR" ? "not-file" : "io",
      cause,
    });
  }
  try {
    return ok({ text, value: JSON.parse(text) as unknown });
  } catch (cause) {
    return err({
      _tag: "FileOperationFailed",
      operation,
      file_operation: "read",
      path: file,
      reason: "invalid-json",
      cause,
    });
  }
};

export const verifyDumpBundle = async (
  dir: string,
  options: VerifyDumpOptions,
): Promise<Result<VerifiedDumpBundle, BeaError>> => {
  const operation = options.operation ?? "verify_dump_bundle";
  const path = options.path ?? "dump_path";
  const read = await readManifest(dir, operation);
  if (!read.ok) return read;
  const parsed = dumpManifestSchema.safeParse(read.value.value);
  if (!parsed.success)
    return err(
      invalid(
        operation,
        path,
        parsed.error.issues.map((i) => `manifest ${i.path.map(String).join(".") || "(root)"}: ${i.code}`),
      ),
    );
  const manifest = parsed.data;
  if (canonicalJson(read.value.value as JsonValue) !== read.value.text)
    return err(invalid(operation, path, ["manifest.json is not JCS (RFC 8785) canonical JSON"]));
  const { bundle_id: bundleId, ...withoutId } = manifest;
  if (bundleIdOf(withoutId) !== bundleId)
    return err({
      _tag: "EvidenceIntegrity",
      operation,
      reason: "id-mismatch",
      message: "The bundle_id does not match the manifest content.",
    });
  const issues = dumpManifestIssues(manifest, {
    maxTotalBytes: options.maxTotalBytes,
    ...(options.memoryLimitBytes !== undefined ? { memoryLimitBytes: options.memoryLimitBytes } : {}),
    ...(options.threadId !== undefined ? { threadId: options.threadId } : {}),
  });
  const sizeIssues = issues.filter((i) => i.kind === "size");
  if (sizeIssues.length > 0)
    return err({
      _tag: "ResourceConstraint",
      operation,
      resource: "memory",
      limits: {
        total_bytes: dumpTotalBytes(manifest),
        max_total_bytes: options.maxTotalBytes,
        memory_limit_bytes: options.memoryLimitBytes ?? null,
      },
      retryable: false,
      message: `The bundle is too large to load: ${sizeIssues.map((i) => i.problem).join("; ")}.`,
    });
  if (issues.length > 0)
    return err(
      invalid(
        operation,
        path,
        issues.map((i) => `${i.path}: ${i.problem}`),
      ),
    );
  for (const region of new Map(manifest.regions.map((r) => [r.sha256, r])).values()) {
    const file = join(dir, DUMP_REGIONS_DIR, `${region.sha256}.bin`);
    let size: number;
    try {
      const info = await lstat(file);
      if (!info.isFile())
        return err(invalid(operation, path, [`region file ${region.sha256}.bin is not a regular file`]));
      size = info.size;
    } catch {
      return err(invalid(operation, path, [`region file ${region.sha256}.bin is missing`]));
    }
    if (size !== region.size)
      return err(
        invalid(operation, path, [
          `region file ${region.sha256}.bin has ${String(size)} bytes, not ${String(region.size)}`,
        ]),
      );
    if ((await sha256File(file, options.signal)) !== region.sha256)
      return err({
        _tag: "EvidenceIntegrity",
        operation,
        reason: "id-mismatch",
        message: "A region file's content does not match its sha256 name.",
        diagnostics: { region: region.sha256 },
      });
  }
  return ok({ dir, manifest, totalBytes: dumpTotalBytes(manifest) });
};
