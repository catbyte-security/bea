import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

import type { BeaError, BeaErrorOf } from "../../domain/errors/beaError.js";
import type { HostPlatform } from "../../domain/paths.js";
import { err, ok, type Result } from "../../domain/result.js";

/**
 * Locates the bea-jobhost binary of the running build (S3 §5.6, DESIGN §5.2). Production resolves it through
 * src/application/distLayout.ts (relative to the running dist only; no environment override); tests inject paths.
 * The exe's sha256 must equal its build manifest (`bea-jobhost.json`, schema bea.native-build/1, protocol 1). Every
 * run additionally checks `hello.protocol === 1` (JobHostSession). Success is memoized; a failure is re-checked on
 * the next call (a later build can fix it).
 */
export interface JobHostBinary {
  readonly path: string;
  readonly sha256: string;
  readonly bytes: number;
  readonly protocol: 1;
}

export interface HelperLocatorOptions {
  readonly exePath: string;
  readonly manifestPath: string;
  readonly platform: HostPlatform;
}

/** scripts/build-native.mjs output; extra fields (compiler, args, source_sha256) are informational. */
interface NativeBuildManifest {
  readonly sha256: string;
  readonly bytes: number;
}

/** Checks the bea.native-build/1 fields the locator relies on (providers may not import zod; DESIGN §4.1). */
const parseManifest = (raw: unknown): NativeBuildManifest | "protocol-mismatch" | null => {
  if (typeof raw !== "object" || raw === null) return null;
  const field = (name: string): unknown => Reflect.get(raw, name);
  const protocol = field("protocol");
  if (protocol !== undefined && protocol !== 1) return "protocol-mismatch";
  const sha256 = field("sha256");
  const bytes = field("bytes");
  if (
    field("schema") !== "bea.native-build/1" ||
    field("file") !== "bea-jobhost.exe" ||
    protocol !== 1 ||
    typeof sha256 !== "string" ||
    !/^[0-9a-f]{64}$/u.test(sha256) ||
    typeof bytes !== "number" ||
    !Number.isSafeInteger(bytes) ||
    bytes <= 0
  )
    return null;
  return { sha256, bytes };
};

type LocateFailureReason =
  | "unsupported-platform"
  | "binary-missing"
  | "binary-unreadable"
  | "manifest-missing"
  | "manifest-invalid"
  | "protocol-mismatch"
  | "binary-digest-mismatch";

const unavailable = (
  operation: string,
  reason: LocateFailureReason,
  diagnostics?: Record<string, string | number>,
): BeaErrorOf<"CapabilityUnavailable"> => ({
  _tag: "CapabilityUnavailable",
  operation,
  capability: "jobhost",
  reason,
  retryable: false,
  ...(diagnostics === undefined ? {} : { diagnostics }),
});

const isMissing = (cause: unknown): boolean =>
  typeof cause === "object" && cause !== null && ["ENOENT", "ENOTDIR"].includes(String(Reflect.get(cause, "code")));

export class HelperLocator {
  readonly #options: HelperLocatorOptions;
  #located: JobHostBinary | null = null;
  #inflight: Promise<Result<JobHostBinary, BeaError>> | null = null;

  constructor(options: HelperLocatorOptions) {
    this.#options = options;
  }

  locate(operation = "jobhost.locate"): Promise<Result<JobHostBinary, BeaError>> {
    if (this.#located !== null) return Promise.resolve(ok(this.#located));
    this.#inflight ??= this.#check(operation).finally(() => {
      this.#inflight = null;
    });
    return this.#inflight;
  }

  async #check(operation: string): Promise<Result<JobHostBinary, BeaError>> {
    const { exePath, manifestPath, platform } = this.#options;
    if (platform !== "win32") return err(unavailable(operation, "unsupported-platform", { platform }));
    let exe: Buffer;
    try {
      exe = await readFile(exePath);
    } catch (cause) {
      return err(unavailable(operation, isMissing(cause) ? "binary-missing" : "binary-unreadable"));
    }
    let manifestText: string;
    try {
      manifestText = await readFile(manifestPath, "utf8");
    } catch (cause) {
      return err(unavailable(operation, isMissing(cause) ? "manifest-missing" : "manifest-invalid"));
    }
    let manifestRaw: unknown;
    try {
      manifestRaw = JSON.parse(manifestText);
    } catch {
      return err(unavailable(operation, "manifest-invalid"));
    }
    const manifest = parseManifest(manifestRaw);
    if (manifest === null || manifest === "protocol-mismatch")
      return err(unavailable(operation, manifest ?? "manifest-invalid"));
    const sha256 = createHash("sha256").update(exe).digest("hex");
    if (sha256 !== manifest.sha256 || exe.length !== manifest.bytes)
      return err(unavailable(operation, "binary-digest-mismatch", { expected_sha256: manifest.sha256, sha256 }));
    this.#located = { path: exePath, sha256, bytes: exe.length, protocol: 1 };
    return ok(this.#located);
  }
}
