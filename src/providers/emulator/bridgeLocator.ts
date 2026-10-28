import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

import type { DistLayout } from "../../application/distLayout.js";
import { BEA_PACKAGE_VERSION } from "../../application/emu/packageVersion.js";
import { EMU_PROTOCOL } from "../../domain/emuProtocol.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { BridgeArtifact } from "./EmuBridge.js";

/**
 * Locates bridge/emu/bea_emu_bridge.py of the RUNNING build (src/application/distLayout.ts: the package root above
 * this build's dist) and the digest it must report (S5 §4.2 step 2): `dist/bridge-manifest.json`, written by
 * scripts/build-bridge.mjs. The file's own sha256 must equal the manifest's, so an edited or swapped bridge is
 * refused before it ever runs. Code running from the TypeScript sources (tests) may have no manifest; the digest
 * is then computed from the file itself (`source: "computed"`).
 */
export interface LocatedBridge extends BridgeArtifact {
  readonly protocol: typeof EMU_PROTOCOL;
  readonly requirementsLock: string;
  readonly lockSha256: string | null;
  readonly manifestPath: string;
  readonly source: "manifest" | "computed";
}

export interface BridgeLocatorDeps {
  readonly readFile?: (path: string) => Promise<Buffer>;
}

export const sha256Of = (bytes: Uint8Array): string => createHash("sha256").update(bytes).digest("hex");

const unavailable = (operation: string, reason: string, message: string): BeaError => ({
  _tag: "CapabilityUnavailable",
  operation,
  capability: "emulator",
  reason,
  retryable: false,
  message,
  remediation:
    "Rebuild BEA (`npm run build`) or reinstall bea-agents so bridge/emu/bea_emu_bridge.py and dist/bridge-manifest.json match.",
});

/**
 * Manifest fields this build accepts. scripts/build-bridge.mjs writes `sha256`, `protocol` and the lock digest;
 * `bridge_sha256`/`bridge_version`/`version` are accepted too (S5 §2 spelling), and the version falls back to the
 * package version, which the bridge stamps as BRIDGE_VERSION.
 */
const readManifest = (
  json: unknown,
): { sha256: string | null; version: string | null; protocol: string | null; lock: string | null } | null => {
  if (typeof json !== "object" || json === null) return null;
  const record = json as Record<string, unknown>;
  const text = (key: string): string | null => (typeof record[key] === "string" ? (record[key] as string) : null);
  return {
    sha256: text("sha256") ?? text("bridge_sha256"),
    version: text("bridge_version") ?? text("version"),
    protocol: text("protocol"),
    lock: text("requirements_lock_sha256") ?? text("lock_sha256"),
  };
};

const isMissing = (cause: unknown): boolean =>
  typeof cause === "object" && cause !== null && Reflect.get(cause, "code") === "ENOENT";

export const locateBridge = async (
  layout: DistLayout,
  operation: string,
  deps: BridgeLocatorDeps = {},
): Promise<Result<LocatedBridge, BeaError>> => {
  const read = deps.readFile ?? ((path: string) => readFile(path));
  let script: Buffer;
  try {
    script = await read(layout.bridgeScript);
  } catch (cause) {
    return err(
      unavailable(
        operation,
        isMissing(cause) ? "bridge-missing" : "bridge-unreadable",
        "The emulator bridge script is missing from this BEA installation.",
      ),
    );
  }
  const actual = sha256Of(script);
  let manifestText: string | null = null;
  try {
    manifestText = (await read(layout.bridgeManifest)).toString("utf8");
  } catch (cause) {
    if (!isMissing(cause))
      return err(unavailable(operation, "bridge-manifest-unreadable", "The bridge build manifest cannot be read."));
  }
  if (manifestText === null) {
    if (!layout.fromSource)
      return err(
        unavailable(
          operation,
          "bridge-manifest-missing",
          "This build has no bridge manifest (dist/bridge-manifest.json).",
        ),
      );
    return ok({
      path: layout.bridgeScript,
      sha256: actual,
      version: BEA_PACKAGE_VERSION,
      protocol: EMU_PROTOCOL,
      requirementsLock: layout.bridgeRequirements,
      lockSha256: null,
      manifestPath: layout.bridgeManifest,
      source: "computed",
    });
  }
  let parsed: ReturnType<typeof readManifest> = null;
  try {
    parsed = readManifest(JSON.parse(manifestText));
  } catch {
    parsed = null;
  }
  if (parsed?.sha256 === null || parsed === null)
    return err(unavailable(operation, "bridge-manifest-invalid", "The bridge build manifest is malformed."));
  if (parsed.protocol !== null && parsed.protocol !== EMU_PROTOCOL)
    return err(
      unavailable(operation, "bridge-protocol-mismatch", "The bridge build speaks a different bea-emu protocol."),
    );
  if (parsed.sha256.toLowerCase() !== actual)
    return err(
      unavailable(
        operation,
        "bridge-file-mismatch",
        "The emulator bridge file does not match this BEA build (its sha256 differs from the build manifest).",
      ),
    );
  return ok({
    path: layout.bridgeScript,
    sha256: actual,
    version: parsed.version ?? BEA_PACKAGE_VERSION,
    protocol: EMU_PROTOCOL,
    requirementsLock: layout.bridgeRequirements,
    lockSha256: parsed.lock,
    manifestPath: layout.bridgeManifest,
    source: "manifest",
  });
};
