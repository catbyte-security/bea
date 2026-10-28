import { readFile } from "node:fs/promises";

import { resolveDistLayout } from "../../application/distLayout.js";
import { agentBuildManifestSchema as manifestSchema } from "../../application/sessions/agentSchemas.js";
import { sha256Hex } from "../../domain/canonical.js";
import type { BeaErrorOf } from "../../domain/errors/beaError.js";
import { err, ok, type Result } from "../../domain/result.js";
import { AGENT_PROTOCOL } from "../../shared/agentProtocol.js";
import { EXPECTED_FRIDA_VERSION } from "./fridaLoader.js";

/**
 * The agent bundle built at BUILD time by frida.Compiler (F13, D-INT-25): dist/agent/bea-agent.js plus its
 * `bea.agent-build/1` manifest. Loaded once and memoized by FridaHost; the bundle is re-hashed and must equal the
 * manifest (a mismatch means a partial copy or a tampered build). The ready handshake later checks the agent's own
 * build_id against `buildId`.
 */
export interface AgentBundle {
  readonly source: string;
  readonly sha256: string;
  readonly bytes: number;
  readonly protocol: typeof AGENT_PROTOCOL;
  readonly protocolMinor: number;
  readonly agentVersion: string;
  readonly buildId: string;
  readonly fridaVersion: string;
  readonly runtime: "qjs";
}

export interface AgentBundleFiles {
  readonly bundlePath: string;
  readonly manifestPath: string;
  readonly readText: (path: string) => Promise<string>;
}

export const defaultAgentBundleFiles = (): AgentBundleFiles => {
  const layout = resolveDistLayout();
  return {
    bundlePath: layout.agentBundle,
    manifestPath: layout.agentManifest,
    readText: (path) => readFile(path, "utf8"),
  };
};

const bundleUnavailable = (reason: string, detail: string): BeaErrorOf<"CapabilityUnavailable"> => ({
  _tag: "CapabilityUnavailable",
  operation: "agent.bundle",
  capability: "agent",
  reason,
  retryable: false,
  remediation: "Rebuild the agent (npm run build) or reinstall BEA; then run `bea doctor`.",
  diagnostics: { detail: detail.slice(0, 512) },
});

export const loadAgentBundle = async (
  files: AgentBundleFiles,
): Promise<Result<AgentBundle, BeaErrorOf<"CapabilityUnavailable">>> => {
  let manifestText: string;
  let source: string;
  try {
    manifestText = await files.readText(files.manifestPath);
    source = await files.readText(files.bundlePath);
  } catch (cause) {
    return err(bundleUnavailable("bundle-missing", cause instanceof Error ? cause.message : String(cause)));
  }
  let raw: unknown;
  try {
    raw = JSON.parse(manifestText);
  } catch {
    return err(bundleUnavailable("manifest-invalid", "the manifest is not JSON"));
  }
  const manifest = manifestSchema.safeParse(raw);
  if (!manifest.success) return err(bundleUnavailable("manifest-invalid", manifest.error.message));
  const m = manifest.data;
  if (m.protocol !== AGENT_PROTOCOL)
    return err(bundleUnavailable("protocol-mismatch", `bundle protocol ${m.protocol}, host ${AGENT_PROTOCOL}`));
  if (m.frida_version !== EXPECTED_FRIDA_VERSION)
    return err(bundleUnavailable("frida-version-mismatch", `bundle built for frida ${m.frida_version}`));
  const sha256 = sha256Hex(source);
  if (sha256 !== m.sha256) return err(bundleUnavailable("hash-mismatch", "the bundle does not match its manifest"));
  return ok({
    source,
    sha256,
    bytes: Buffer.byteLength(source, "utf8"),
    protocol: AGENT_PROTOCOL,
    protocolMinor: m.protocol_minor,
    agentVersion: m.agent_version,
    buildId: m.build_id,
    fridaVersion: m.frida_version,
    runtime: "qjs",
  });
};
