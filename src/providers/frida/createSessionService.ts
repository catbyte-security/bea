import type { BeaCore } from "../../application/BeaApplication.js";
import { BEA_PACKAGE_VERSION } from "../../application/sessions/productVersion.js";
import { SessionEvidenceSink } from "../../application/sessions/SessionEvidenceSink.js";
import { HARD_LIMITS } from "../../domain/config.js";
import { Deadline } from "../../domain/deadline.js";
import type { DynamicSessionPort, ShutdownReason } from "../../ports/sessions.js";
import type { EvidenceRuntime } from "../../ports/evidence.js";
import type { JobHostFactory } from "../../ports/jobhost.js";
import type { RecordingRegistry } from "../../ports/recordings.js";
import type { AddressService } from "../../ports/address.js";
import { defaultAgentBundleFiles, loadAgentBundle } from "./agentBundle.js";
import { finalPathOf, inspectDirectory, listImageNeighbourhood, sha256File } from "./fileHash.js";
import { loadFridaModule } from "./fridaLoader.js";
import { prepareFridaTemp, releaseFridaTemp } from "./fridaTemp.js";
import type { FridaModuleLike } from "./fridaPorts.js";
import { FridaHost } from "./FridaHost.js";
import { hostLimitsFrom } from "./hostLimits.js";
import { readPeHeader } from "./peHeader.js";
import { SessionManager } from "./SessionManager.js";
import { registerSessionDoctorChecks, sessionsStatusContributor } from "./statusAndDoctor.js";

/**
 * WP-SESS composition (DESIGN §5.1): FridaHost + SessionManager + agent channel. Construction is synchronous and
 * cheap — no target contact, no frida import, no helper spawn, no file writes (CI-M20). It registers the
 * `teardown-targets` closer (SessionManager.closeAll, kill-first) and the `release-frida` closer (FridaHost.close:
 * disconnect device.output, await dm.close()), the bea_status contributor and the doctor checks.
 */
export interface SessionServiceOverrides {
  /** tests: a fake binding instead of the lazy import("frida") */
  readonly loadModule?: () => Promise<FridaModuleLike>;
  readonly serverEnv?: Readonly<Record<string, string | undefined>>;
  readonly hostPlatform?: NodeJS.Platform;
}

const shutdownReasonOf = (transport: BeaCore["run"]["transport"]): ShutdownReason =>
  transport === "cli" ? "cli-exit" : "connection-closed";

export const createSessionService = (
  core: BeaCore,
  deps: {
    readonly evidence: EvidenceRuntime;
    readonly jobhost: JobHostFactory;
    readonly recordings: RecordingRegistry;
    readonly address: AddressService;
  },
  overrides: SessionServiceOverrides = {},
): DynamicSessionPort => {
  const { config, logger: rootLogger, clock } = core;
  const logger = rootLogger.child({ component: "sessions" });
  const limits = hostLimitsFrom(config);
  // LIFE-3: targets get the user's TEMP from this snapshot (an attach briefly points TEMP at BEA's Frida directory)
  const serverEnv = overrides.serverEnv ?? { ...process.env };
  // the BEA-owned directory Frida extracts its agent into (prepared, and the sweep run, at the first injection)
  let fridaTemp: string | null | undefined;
  const fridaTempDir = (): string | null =>
    overrides.loadModule !== undefined
      ? null
      : (fridaTemp ??= prepareFridaTemp(config.layout.fridaTempDir, core.run.runId));
  const host = new FridaHost({
    logger,
    loadModule: overrides.loadModule ?? loadFridaModule,
    loadAgentBundle: () => loadAgentBundle(defaultAgentBundleFiles()),
    now: () => clock.monoMs(),
    orphanOutputBytes: limits.capture.orphanOutputBytes,
    orphanOutputTtlMs: limits.capture.orphanOutputTtlMs,
  });
  const sink = new SessionEvidenceSink({
    evidence: deps.evidence,
    recordings: deps.recordings,
    logger,
    fridaVersion: () => host.module?.version ?? null,
  });
  const manager = new SessionManager({
    host,
    jobhost: deps.jobhost,
    evidence: deps.evidence,
    recordings: deps.recordings,
    address: deps.address,
    sink,
    limits,
    logger,
    clock,
    ids: core.ids,
    lifecycleShutdown: core.lifecycle.shutdownSignal,
    serverEnv,
    selfPid: process.pid,
    selfPpid: typeof process.ppid === "number" ? process.ppid : null,
    hostPlatform: overrides.hostPlatform ?? process.platform,
    beaVersion: BEA_PACKAGE_VERSION,
    gates: {
      writeMemory: core.gates.isEnabled("write_memory"),
      overrideFunction: core.gates.isEnabled("override_function"),
      callAttached: core.gates.isEnabled("call_attached"),
    },
    policy: {
      envMode: config.spawn.envMode.value,
      allowInterpreters: config.spawn.allowInterpreters.value,
      allowedPrograms: config.spawn.allowedPrograms.value,
      allowAntiCheat: config.attach.allowAntiCheat.value,
      allowAntiCheatImages: config.attach.allowAntiCheatImages.value,
      allowSession0: config.attach.allowSession0.value,
      extraDenylist: config.attach.extraDenylist.value,
    },
    maxEmulationSessions: config.emu.maxSessions.value,
    files: {
      hashFile: sha256File,
      listNeighbourhood: listImageNeighbourhood,
      readPe: readPeHeader,
      realPath: finalPathOf,
      inspectDirectory,
      fridaTempDir,
    },
    systemRoot: serverEnv["SystemRoot"] ?? serverEnv["SYSTEMROOT"] ?? "C:\\Windows",
  });
  core.lifecycle.register({
    name: "sessions.closeAll",
    phase: "teardown-targets",
    close: async () => {
      const closed = await manager.closeAll(
        shutdownReasonOf(core.run.transport),
        Deadline.after(limits.shutdown.settleUntilMs),
      );
      if (!closed.ok) throw new Error(`session teardown failed: ${closed.error._tag}`);
      if (closed.value.failures.length > 0)
        throw new Error(`session teardown incomplete: ${closed.value.failures.map((f) => f._tag).join(", ")}`);
    },
  });
  core.lifecycle.register({
    name: "frida.release",
    phase: "release-frida",
    close: async (signal) => {
      // LIFE-3: dm.close gets the rest of the shutdown budget (the phase signal), not a fixed 250 ms; once it removed
      // Frida's extraction directory the run's own temp directory goes too (a kill leaves it for the next sweep)
      const closed = await host.close(Deadline.after(HARD_LIMITS.hardExitAfterMs), signal);
      if (!closed.ok) throw new Error("frida device manager close failed");
      releaseFridaTemp(fridaTemp ?? null);
    },
  });
  core.status.add(sessionsStatusContributor(host, manager));
  registerSessionDoctorChecks(core, host, manager);
  return manager;
};
