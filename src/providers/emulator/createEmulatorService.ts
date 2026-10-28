import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";

import type { BeaCore } from "../../application/BeaApplication.js";
import type { DoctorCheckResult } from "../../application/doctor.js";
import { resolveDistLayout, type DistLayout } from "../../application/distLayout.js";
import { BEA_PACKAGE_VERSION } from "../../application/emu/packageVersion.js";
import type { BeaServices } from "../../application/services/index.js";
import type { BackendStatus } from "../../application/status.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import type { Result } from "../../domain/result.js";
import type { DumpCapturePort } from "../../ports/dumps.js";
import type { EmuPort } from "../../ports/emu.js";
import type { EvidenceRuntime } from "../../ports/evidence.js";
import type { DynamicSessionPort } from "../../ports/sessions.js";
import { locateBridge, sha256Of, type LocatedBridge } from "./bridgeLocator.js";
import { EmuAdapter } from "./EmuAdapter.js";
import { EmuBridge, type SpawnFn } from "./EmuBridge.js";
import { PythonResolver, runBridgeProbe, venvPython, type ResolvedPython } from "./pythonResolver.js";
import { compareSelftest, type SelftestComparison, type SelftestReport } from "./selftestExpectations.js";

/**
 * WP-EMU composition (S5 §5–§6, CI-B3/B5). Construction is synchronous-cheap: no filesystem access, no child
 * process, no bridge (everything is lazy, at the first emu_open or doctor check). Registers on `core`:
 * - the lifecycle closer `emulator.bridges` in `teardown-targets` (every bridge: shutdown -> EOF -> kill at 900 ms);
 * - the bea_status contributor (backend row `emulator`: the last Python resolution, sessions, the selftest);
 * - the doctor checks `emulation:python|pins|bridge-file|venv` (backend:emulation) and `emulation:selftest|start`
 *   (probe).
 * `dumps` (CI-B3) is consumed by the application's EmulationService (emu_open {live_session_id}), which reaches it
 * as app.services.dumps; the evidence and PE slots are likewise used by the application layer.
 */
export interface EmulatorServiceOverrides {
  readonly layout?: DistLayout;
  readonly spawn?: SpawnFn;
  readonly now?: () => number;
}

const VENV_MARKER = "bea-emu.json";

export const createEmulatorService = (
  core: BeaCore,
  deps: {
    readonly evidence: EvidenceRuntime;
    readonly sessions: DynamicSessionPort;
    readonly pe: BeaServices["pe"];
    readonly dumps: DumpCapturePort;
  },
  overrides: EmulatorServiceOverrides = {},
): EmuPort => {
  const config = core.config;
  const now = overrides.now ?? (() => core.clock.monoMs());
  const logger = core.logger.child({ component: "emulator" });
  let layout: DistLayout | undefined = overrides.layout;
  const distLayout = (): DistLayout => (layout ??= resolveDistLayout());
  let located: Promise<Result<LocatedBridge, BeaError>> | null = null;
  const bridge = (): Promise<Result<LocatedBridge, BeaError>> => {
    located ??= locateBridge(distLayout(), "emu_open").then((r) => {
      if (!r.ok) located = null; // a rebuilt or reinstalled bridge is picked up on the next call
      return r;
    });
    return located;
  };
  const makeResolver = (): PythonResolver =>
    new PythonResolver({
      platform: config.platform,
      configured: config.python,
      venvDir: config.layout.venvDir,
      bridge,
      ...(overrides.spawn === undefined ? {} : { probe: (request) => runBridgeProbe(request, overrides.spawn) }),
    });
  const resolver = makeResolver();
  const adapter = new EmuAdapter({
    config,
    sessions: deps.sessions,
    resolver,
    bridge,
    logger,
    now,
    ...(overrides.spawn === undefined ? {} : { spawn: overrides.spawn }),
  });

  // ---------------------------------------------------------------- selftest (S5 §3.16; once per process)
  let selftest: Promise<SelftestComparison | null> | null = null;
  const runSelftest = (python: ResolvedPython, located: LocatedBridge): Promise<SelftestComparison | null> =>
    runBridgeProbe(
      { command: python, bridgePath: located.path, mode: "--selftest", timeoutMs: 30_000 },
      overrides.spawn,
    ).then((outcome) =>
      outcome.kind === "line"
        ? compareSelftest(outcome.line as unknown as SelftestReport, python.engines.unicorn)
        : null,
    );
  const selftestWanted = (python: ResolvedPython): boolean =>
    config.emu.selftest.value === "always" || (config.emu.selftest.value === "auto" && python.pin === "compatible");

  core.lifecycle.register({
    name: "emulator.bridges",
    phase: "teardown-targets",
    close: async () => {
      await adapter.closeAll();
    },
  });

  core.status.add({
    name: "emulator",
    backends: async (): Promise<readonly BackendStatus[]> => {
      const status = adapter.availability();
      const counts = adapter.counts();
      const sessions = `sessions ${String(counts.open)}/${String(config.emu.maxSessions.value)}${counts.lost > 0 ? `, ${String(counts.lost)} lost` : ""}${counts.failed > 0 ? `, ${String(counts.failed)} failed` : ""}`;
      const tested = selftest === null ? null : await selftest;
      const selftestText =
        tested === null
          ? ""
          : tested.passed
            ? "; selftest passed"
            : `; selftest mismatches: ${tested.mismatches.join(", ")}`;
      if (status.state === "available")
        return [
          {
            id: "emulator",
            state: "available",
            version: status.versions?.unicorn ?? null,
            detail:
              `python ${status.versions?.python ?? "?"} (${status.source ?? "?"}, ${status.pin ?? "?"}); memory cap ${String(config.emu.memoryLimitMb.value)} MiB; ${sessions}${selftestText}`.slice(
                0,
                512,
              ),
          },
        ];
      if (status.state === "unavailable")
        return [
          {
            id: "emulator",
            state: "unavailable",
            version: null,
            detail:
              `${status.reason ?? "no usable Python"}; run \`bea setup --emulator\` or \`bea doctor --backend emulation\``.slice(
                0,
                512,
              ),
          },
        ];
      return [
        {
          id: "emulator",
          state: "not-loaded",
          version: null,
          detail:
            "Python and the bridge are resolved at the first emu_open; `bea doctor --backend emulation` checks them now.",
        },
      ];
    },
  });

  // ---------------------------------------------------------------- doctor (S5 §6.6, D-INT-35)
  const check = (
    name: string,
    ok: boolean,
    classification: DoctorCheckResult["classification"],
    detail?: string,
    remediation?: string,
  ): DoctorCheckResult => ({
    name,
    ok,
    classification,
    ...(detail === undefined ? {} : { detail: detail.slice(0, 1000) }),
    ...(remediation === undefined ? {} : { remediation }),
  });
  /** doctor resolves afresh (a CLI process; never the server's memoized resolution) */
  let doctorResolution: Promise<{ resolver: PythonResolver; result: Result<ResolvedPython, BeaError> }> | null = null;
  const doctorResolve = () => {
    doctorResolution ??= (async () => {
      const fresh = makeResolver();
      return { resolver: fresh, result: await fresh.resolve("bea_doctor") };
    })();
    return doctorResolution;
  };

  core.doctor.add({
    name: "emulation:bridge-file",
    scope: "backend:emulation",
    run: async () => {
      const located = await locateBridge(distLayout(), "bea_doctor");
      if (!located.ok)
        return check(
          "emulation:bridge-file",
          false,
          "missing_dependency",
          located.error.message ?? "bridge unavailable",
          "Rebuild or reinstall bea-agents.",
        );
      return check(
        "emulation:bridge-file",
        true,
        "healthy",
        `${located.value.path} sha256 ${located.value.sha256.slice(0, 16)}… (${located.value.source})`,
      );
    },
  });
  core.doctor.add({
    name: "emulation:python",
    scope: "backend:emulation",
    run: async () => {
      const { resolver: fresh, result } = await doctorResolve();
      const tried = fresh
        .report()
        .candidates.map((c) => `${c.source}: ${c.outcome}`)
        .join("; ");
      if (!result.ok)
        return check(
          "emulation:python",
          false,
          "missing_dependency",
          tried,
          "Run `bea setup --emulator` or set BEA_PYTHON.",
        );
      return check(
        "emulation:python",
        true,
        "healthy",
        `${result.value.source} ${result.value.executable} (Python ${result.value.version}); ${tried}`,
      );
    },
  });
  core.doctor.add({
    name: "emulation:pins",
    scope: "backend:emulation",
    run: async () => {
      const { result } = await doctorResolve();
      if (!result.ok) return check("emulation:pins", false, "missing_dependency", "no usable Python");
      const engines = result.value.engines;
      const text = `unicorn ${engines.unicorn}, capstone ${engines.capstone}, pefile ${engines.pefile}`;
      return result.value.pin === "exact"
        ? check("emulation:pins", true, "healthy", text)
        : check(
            "emulation:pins",
            true,
            "config_drift",
            `${text}: unvalidated engine set; the selftest runs at the first bridge start`,
          );
    },
  });
  core.doctor.add({
    name: "emulation:venv",
    scope: "backend:emulation",
    run: async () => {
      const venvDir = config.layout.venvDir;
      // review fix ONBOARD-4: `bea setup --emulator --repair` does not exist; a plain setup replaces a BEA-owned venv,
      // and a directory BEA did not create has to be moved away by the user first
      const notOwned = (detail: string) =>
        check(
          "emulation:venv",
          false,
          "config_drift",
          detail,
          `${venvDir} was not created by this BEA version: delete it (or move it away), then run \`bea setup --emulator\`.`,
        );
      let markerText: string;
      try {
        markerText = await readFile(join(venvDir, VENV_MARKER), "utf8");
      } catch {
        return (await stat(venvDir).then(
          () => true,
          () => false,
        ))
          ? notOwned("the venv directory has no readable BEA marker")
          : check(
              "emulation:venv",
              true,
              "unknown",
              `no BEA venv at ${venvDir} (optional; \`bea setup --emulator\` creates it)`,
            );
      }
      let marker: Record<string, unknown>;
      try {
        marker = JSON.parse(markerText) as Record<string, unknown>;
      } catch {
        return notOwned("the venv marker is not valid JSON");
      }
      if (marker["schema"] !== "bea.emu-venv/1") return notOwned("the venv marker is not a bea.emu-venv/1 marker");
      let lockSha: string | null = null;
      try {
        lockSha = sha256Of(await readFile(distLayout().bridgeRequirements));
      } catch {
        lockSha = null;
      }
      if (lockSha !== null && marker["lock_sha256"] !== lockSha)
        return check(
          "emulation:venv",
          false,
          "config_drift",
          "the venv was built from a different requirements.lock (stale)",
          "Run `bea setup --emulator` (it replaces BEA's own venv).",
        );
      return check("emulation:venv", true, "healthy", `owned venv ${venvPython(venvDir, config.platform)}`);
    },
  });
  core.doctor.add({
    name: "emulation:selftest",
    scope: "probe",
    run: async () => {
      const { result } = await doctorResolve();
      const located = await bridge();
      if (!result.ok || !located.ok)
        return check("emulation:selftest", false, "missing_dependency", "no usable Python or bridge");
      const outcome = await runSelftest(result.value, located.value);
      if (outcome === null)
        return check("emulation:selftest", false, "runtime_failure", "the bridge --selftest produced no result line");
      if (!outcome.passed)
        return check(
          "emulation:selftest",
          false,
          "runtime_failure",
          `mismatched gotchas: ${outcome.mismatches.join(", ")}`,
          "Rebuild the pinned engines with `bea setup --emulator`.",
        );
      return check(
        "emulation:selftest",
        true,
        "healthy",
        `validated against unicorn ${outcome.validatedAgainst ?? "?"}${outcome.warnings.length > 0 ? `; believed items differ: ${outcome.warnings.join(", ")}` : ""}`,
      );
    },
  });
  core.doctor.add({
    name: "emulation:start",
    scope: "probe",
    run: async (signal) => {
      const { result } = await doctorResolve();
      const located = await bridge();
      if (!result.ok || !located.ok)
        return check("emulation:start", false, "missing_dependency", "no usable Python or bridge");
      const started = now();
      const startedBridge = await EmuBridge.start(
        {
          python: result.value,
          bridge: { path: located.value.path, sha256: located.value.sha256, version: located.value.version },
          memoryLimitBytes: config.emu.memoryLimitMb.value * 1024 * 1024,
          cacheDir: null,
          cwd: config.layout.emuDir,
          clientVersion: BEA_PACKAGE_VERSION,
          startupTimeoutMs: config.emu.startupTimeoutMs.value,
        },
        { now, logger, ...(overrides.spawn === undefined ? {} : { spawn: overrides.spawn }) },
        signal,
      );
      if (!startedBridge.ok)
        return check("emulation:start", false, "runtime_failure", `bridge did not start (${startedBridge.error.kind})`);
      const ready = Math.round(now() - started);
      const instance = startedBridge.value;
      try {
        // the interpreter itself is a PE64 on disk: no shipped fixture is needed (S5 §6.6)
        const opened = await instance.request(
          "session.open",
          { source: { kind: "image", path: result.value.executable } },
          { signal, deadlineAt: now() + 30_000 },
        );
        if (opened.ok)
          await instance.request(
            "session.close",
            { session: opened.value.session },
            { signal, deadlineAt: now() + 5_000 },
          );
        const limit = instance.readyEvent.memoryLimit;
        return opened.ok
          ? check(
              "emulation:start",
              true,
              "healthy",
              `ready in ${String(ready)} ms; memory limit ${limit.applied ? `${String(Math.round((limit.bytes ?? 0) / 1048576))} MiB (${limit.mechanism})` : "not applied"}`,
            )
          : check("emulation:start", false, "runtime_failure", `session.open failed (${opened.error.kind})`);
      } finally {
        await instance.close();
      }
    },
  });

  // the selftest of an unvalidated engine runs once, at the first open (bea_status reports it)
  const port: EmuPort = {
    availability: () => adapter.availability(),
    lookup: (id) => adapter.lookup(id),
    modules: (h) => adapter.modules(h),
    info: (h, o) => adapter.info(h, o),
    open: async (input, op) => {
      const opened = await adapter.open(input, op);
      if (opened.ok && selftest === null) {
        const python = adapter.pythonOf(opened.value.runtime.sessionId);
        const located = await bridge();
        if (python !== null && located.ok && selftestWanted(python))
          selftest = runSelftest(python, located.value).catch(() => null);
      }
      return opened;
    },
    call: (h, req, o) => adapter.call(h, req, o),
    batch: (h, req, o) => adapter.batch(h, req, o),
    sweep: (h, req, o) => adapter.sweep(h, req, o),
    state: (h, op, o) => adapter.state(h, op, o),
    readMemory: (h, address, size, o) => adapter.readMemory(h, address, size, o),
    disassemble: (h, address, opts, o) => adapter.disassemble(h, address, opts, o),
    regions: (h, o) => adapter.regions(h, o),
    status: (h) => adapter.status(h),
    close: (h) => adapter.close(h),
  };
  return port;
};
