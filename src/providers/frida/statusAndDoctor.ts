import type { BeaError } from "../../domain/errors/beaError.js";
import type { BeaCore } from "../../application/BeaApplication.js";
import type { DoctorCheckResult } from "../../application/doctor.js";
import type { BackendStatus, StatusContributor } from "../../application/status.js";
import { machineWideNote } from "./antiCheatSignals.js";
import type { FridaHost } from "./FridaHost.js";
import type { SessionManager } from "./SessionManager.js";

/**
 * SESS's bea_status contributor (backends `frida` and `agent`, the open sessions, the machine-wide anti-cheat note)
 * and its doctor checks (`frida:binding`, `frida:local-device`, `build:agent`, `frida:inject-probe` with --probe).
 * Status never loads Frida or spawns anything; reading the agent manifest and hashing the 20 KB bundle is the only
 * file work. The inject probe spawns BEA's OWN `node -e` child through Path 1 directly (never the spawn_process policy),
 * reads 16 bytes of its main module, closes the session and checks that it is gone.
 */
const bounded = (text: string): string => (text.length > 500 ? `${text.slice(0, 499)}…` : text);

const fridaBackend = (host: FridaHost): BackendStatus => {
  const binding = host.availability().binding;
  switch (binding.state) {
    case "ready":
      return {
        id: "frida",
        state: "available",
        version: binding.version,
        detail: `local device ready (loaded in ${String(binding.loadMs)} ms)`,
      };
    case "failed":
      return {
        id: "frida",
        state: binding.permanent ? "unavailable" : "failed",
        version: null,
        detail: bounded(
          `${binding.stage} failed: ${binding.reason}${binding.retryAfterMs === null ? "" : ` (retry in ${String(binding.retryAfterMs)} ms)`}`,
        ),
      };
    case "loading":
      return { id: "frida", state: "not-loaded", version: null, detail: "loading" };
    case "closed":
      return { id: "frida", state: "not-loaded", version: null, detail: "closed (server shutting down)" };
    default:
      return { id: "frida", state: "not-loaded", version: null, detail: "loads on first use (frida 17.23.2)" };
  }
};

const agentBackend = async (host: FridaHost): Promise<BackendStatus> => {
  const bundle = await host.agentBundle();
  return bundle.ok
    ? {
        id: "agent",
        state: "available",
        version: bundle.value.agentVersion,
        detail: `build ${bundle.value.buildId}, protocol ${bundle.value.protocol}.${String(bundle.value.protocolMinor)}, ${String(bundle.value.bytes)} B`,
      }
    : { id: "agent", state: "unavailable", version: null, detail: bounded(`agent bundle ${bundle.error.reason}`) };
};

export const sessionsStatusContributor = (host: FridaHost, manager: SessionManager): StatusContributor => ({
  name: "sessions",
  backends: async () => [fridaBackend(host), await agentBackend(host)],
  sessions: () => manager.list(),
  notes: () => (manager.machineWideAntiCheat.length > 0 ? [machineWideNote(manager.machineWideAntiCheat)] : []),
});

const result = (
  name: string,
  ok: boolean,
  classification: DoctorCheckResult["classification"],
  detail: string,
  remediation?: string,
): DoctorCheckResult => ({
  name,
  ok,
  classification,
  detail: bounded(detail),
  ...(remediation === undefined ? {} : { remediation }),
});

const errorDetail = (error: BeaError): string => {
  const diag = error.diagnostics?.["detail"];
  return `${error._tag}${"reason" in error ? ` (${String(error.reason)})` : ""}${typeof diag === "string" ? `: ${diag}` : ""}`;
};

export const registerSessionDoctorChecks = (core: BeaCore, host: FridaHost, manager: SessionManager): void => {
  core.doctor.add({
    name: "frida:binding",
    scope: "backend:frida",
    run: async (signal) => {
      await host.device({ signal });
      const binding = host.availability().binding;
      if (binding.state === "ready") return result("frida:binding", true, "healthy", `frida ${binding.version} loaded`);
      if (binding.state === "failed" && binding.stage === "device")
        return result(
          "frida:binding",
          true,
          "healthy",
          "the frida binding loaded (device lookup is checked separately)",
        );
      return result(
        "frida:binding",
        false,
        binding.state === "failed" && binding.stage === "version" ? "configuration_invalid" : "missing_dependency",
        binding.state === "failed" ? `${binding.stage}: ${binding.reason}` : binding.state,
        "Reinstall BEA's dependencies (npm ci) so frida 17.23.2 and its native binding are present.",
      );
    },
  });
  core.doctor.add({
    name: "frida:local-device",
    scope: "backend:frida",
    run: async (signal) => {
      const device = await host.device({ signal });
      return device.ok
        ? result(
            "frida:local-device",
            true,
            "healthy",
            `local device: ${device.value.system.os} ${device.value.system.version} ${device.value.system.arch}`,
          )
        : result(
            "frida:local-device",
            false,
            "runtime_failure",
            errorDetail(device.error),
            "Run `bea doctor` again; if it persists, check antivirus quarantine of frida's native binding.",
          );
    },
  });
  core.doctor.add({
    name: "build:agent",
    scope: "always",
    run: async () => {
      const bundle = await host.agentBundle();
      return bundle.ok
        ? result(
            "build:agent",
            true,
            "healthy",
            `agent ${bundle.value.agentVersion} build ${bundle.value.buildId} (${String(bundle.value.bytes)} B, sha256 ok)`,
          )
        : result(
            "build:agent",
            false,
            "missing_dependency",
            errorDetail(bundle.error),
            "Rebuild the agent (npm run build) or reinstall BEA.",
          );
    },
  });
  core.doctor.add({
    name: "frida:inject-probe",
    scope: "probe",
    run: (signal) => injectProbe(manager, signal),
  });
};

/** --probe: BEA's own `node -e` child through Path 1; reads 16 bytes of its main module; closes; verifies it is gone. */
const injectProbe = async (manager: SessionManager, signal: AbortSignal): Promise<DoctorCheckResult> => {
  const outcome = await manager.admit("doctor_inject_probe", { signal, timeoutMs: 30_000 }, async (op) => {
    const spawned = await manager.spawnWith(
      {
        program: process.execPath,
        argv: ["-e", "setInterval(() => {}, 1000)"],
        captureOutput: true,
        resume: false,
        redactLiterals: [],
      },
      op,
      true,
    );
    if (!spawned.ok) return spawned;
    const sessionId = spawned.value.sessionId;
    const base = spawned.value.agent.hello.process.main_module.base;
    const read = await manager.withSession(sessionId, op, "exclusive", async (session) =>
      session.agent.call("readMemory", { address: base, size: 16 }, { op }),
    );
    const closed = await manager.close(sessionId, { force: false }, op);
    if (!read.ok) return read;
    if (!closed.ok) return closed;
    const header = read.value.data.subarray(0, 2).toString("latin1");
    const gone = closed.value.targetState === "killed" || closed.value.targetState === "already-exited";
    return { ok: true as const, value: { header, gone, ms: spawned.value.startup.totalMs } };
  });
  if (!outcome.ok)
    return result(
      "frida:inject-probe",
      false,
      "runtime_failure",
      errorDetail(outcome.error),
      "Run `bea doctor` without --probe to see which prerequisite fails.",
    );
  if (outcome.value.header !== "MZ" || !outcome.value.gone)
    return result(
      "frida:inject-probe",
      false,
      "runtime_failure",
      `probe read ${JSON.stringify(outcome.value.header)}, target gone: ${String(outcome.value.gone)}`,
    );
  return result(
    "frida:inject-probe",
    true,
    "healthy",
    `spawned, injected and read the probe child in ${String(outcome.value.ms)} ms; it was killed at close`,
  );
};
