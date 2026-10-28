import { spawn as nodeSpawn } from "node:child_process";
import { access } from "node:fs/promises";
import { posix, win32 } from "node:path";

import type { EngineVersions } from "../../domain/emuProtocol.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import type { HostPlatform } from "../../domain/paths.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { PythonStatus } from "../../ports/emu.js";
import type { PythonCommand, SpawnFn } from "./EmuBridge.js";
import { SETUP_REMEDIATION } from "./errors.js";

/**
 * Python resolution for the emulator bridge (F7, S5 §6.1, CI-M7, CT-M11): BEA_PYTHON > config.json `python` >
 * the BEA venv (<BEA_HOME>/emu/venv) > `python`/`py -3` (win32) or `python3`/`python` (linux) on PATH. Every
 * candidate is checked by running THE BRIDGE ITSELF with `--probe` under `-I -X utf8` (versions from distribution
 * metadata, S5 §6.3); pins are `exact` (unicorn 2.1.4, capstone 5.0.9, pefile 2024.8.26, Python >= 3.10),
 * `compatible` (unicorn 2.1.x, capstone 5.x, pefile present) or `mismatch` (rejected). Explicit configuration never
 * falls through: a broken BEA_PYTHON (or config `python`) is reported, not silently replaced. Resolution is memoized
 * per server process; `invalidate()` forgets it (after `bea setup --emulator`, or when a cached command fails).
 */
export type PythonSource = "BEA_PYTHON" | "config" | "bea-venv" | "path";

export interface ResolvedPython extends PythonCommand {
  readonly source: PythonSource;
  /** sys.executable reported by the probe (a venv reports its Scripts\python.exe launcher) */
  readonly executable: string;
  readonly version: string;
  readonly inVenv: boolean;
  readonly engines: EngineVersions;
  readonly pin: "exact" | "compatible";
  /** computed by the bridge itself during the probe */
  readonly bridgeSha256: string;
  readonly probeMs: number;
}

export interface CandidateReport {
  readonly source: PythonSource;
  readonly command: string;
  /** BEA-authored outcome text ("ok (exact)", "not found", "unicorn missing under -I", …) */
  readonly outcome: string;
}
export interface ResolutionReport {
  readonly chosen: ResolvedPython | null;
  readonly candidates: readonly CandidateReport[];
}

/** The `--probe` line (S5 §6.3). */
export interface ProbeLine {
  readonly probe: string;
  readonly ok: boolean;
  readonly bridge?: { readonly version?: string; readonly sha256?: string };
  readonly python?: {
    readonly version?: string;
    readonly implementation?: string;
    readonly executable?: string;
    readonly inVenv?: boolean;
    readonly bits?: number;
    readonly platform?: string;
  };
  readonly engines?: Partial<Record<"unicorn" | "unicornCore" | "capstone" | "pefile", string>>;
  readonly missing?: readonly string[];
}
export type ProbeOutcome =
  | { readonly kind: "line"; readonly line: ProbeLine; readonly ms: number; readonly exitCode: number | null }
  | { readonly kind: "not-found" }
  | { readonly kind: "failed"; readonly reason: string; readonly exitCode: number | null };

export interface ProbeRequest {
  readonly command: PythonCommand;
  readonly bridgePath: string;
  readonly mode: "--probe" | "--selftest";
  readonly timeoutMs: number;
  readonly signal?: AbortSignal;
}

const PROBE_TIMEOUT_MS = 15_000;
const MAX_PROBE_STDOUT = 64 * 1024;
/** cmd.exe/WindowsApps alias exit code when no Python is installed behind the alias [S5 §17.1 A9: believed] */
const NOT_INSTALLED_EXIT = 9009;

/**
 * Runs `<command> [prefix] -I -X utf8 <bridge> --probe|--selftest` and parses the LAST non-empty stdout line.
 * ENOENT and exit 9009 mean "not installed"; stdout is capped (64 KiB) and the child is killed at the timeout.
 */
/**
 * The environment for interpreter probes and installer steps: the Windows Python install manager (the `py` launcher
 * and the WindowsApps `python` alias) otherwise downloads and registers a whole Python on first use when the
 * LOCALAPPDATA it sees holds none (observed with a fresh LOCALAPPDATA: a 166 MB install plus HKCU registry keys).
 * A probe must never install anything, so automatic installs are switched off (pymanager.json's own variable).
 */
export const noAutoInstallEnv = (extra: Readonly<Record<string, string>> = {}): NodeJS.ProcessEnv => ({
  ...process.env,
  PYTHON_MANAGER_AUTOMATIC_INSTALL: "false",
  ...extra,
});

const MAX_PROBE_STDERR = 2048;
/** 0xA0000006: the Python install manager's launcher with no runtime installed (PYTHON_MANAGER_AUTOMATIC_INSTALL=false). */
const PYMANAGER_NO_RUNTIME = 0xa000_0006;

/** "no output" with the exit code (hex for NTSTATUS-like codes) and the last stderr line (ONBOARD-11). */
export const noOutputReason = (code: number | null, stderr: string): string => {
  if (code === PYMANAGER_NO_RUNTIME)
    return "Python install manager present but no runtime installed (run `py install default`, then `bea setup --emulator`)";
  const exit = code === null ? "none" : code >= 0x8000_0000 ? `0x${code.toString(16)}` : String(code);
  const line = stderr
    .split(/\r?\n/u)
    .map((l) => l.trim())
    .filter((l) => l.length > 0)
    .at(-1);
  return line === undefined ? `no output (exit ${exit})` : `no output (exit ${exit}): ${line.slice(0, 200)}`;
};

export const runBridgeProbe = (request: ProbeRequest, spawn: SpawnFn = nodeSpawn as SpawnFn): Promise<ProbeOutcome> =>
  new Promise((resolve) => {
    const started = performance.now();
    let settled = false;
    let stdout = "";
    const finish = (outcome: ProbeOutcome): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      request.signal?.removeEventListener("abort", onAbort);
      resolve(outcome);
    };
    let child: ReturnType<SpawnFn>;
    try {
      child = spawn(
        request.command.command,
        [...request.command.prefixArgs, "-I", "-X", "utf8", request.bridgePath, request.mode],
        { stdio: ["ignore", "pipe", "pipe"], windowsHide: true, detached: false, env: noAutoInstallEnv() },
      );
    } catch (cause) {
      resolve({ kind: "failed", reason: `spawn failed (${String(cause)})`, exitCode: null });
      return;
    }
    const timer = setTimeout(() => {
      child.kill();
      finish({ kind: "failed", reason: `no answer within ${String(request.timeoutMs)} ms`, exitCode: null });
    }, request.timeoutMs);
    const onAbort = (): void => {
      child.kill();
      finish({ kind: "failed", reason: "cancelled", exitCode: null });
    };
    request.signal?.addEventListener("abort", onAbort, { once: true });
    child.stdout?.setEncoding("utf8");
    child.stdout?.on("data", (text: string) => {
      if (stdout.length < MAX_PROBE_STDOUT) stdout += text.slice(0, MAX_PROBE_STDOUT - stdout.length);
    });
    // review fix ONBOARD-11: keep the tail of stderr (the Python install manager explains itself there)
    let stderr = "";
    child.stderr?.setEncoding("utf8");
    child.stderr?.on("data", (text: string) => {
      stderr = (stderr + text).slice(-MAX_PROBE_STDERR);
    });
    child.once("error", (cause: NodeJS.ErrnoException) =>
      finish(
        cause.code === "ENOENT"
          ? { kind: "not-found" }
          : { kind: "failed", reason: cause.code ?? "spawn error", exitCode: null },
      ),
    );
    child.once("close", (code: number | null) => {
      if (code === NOT_INSTALLED_EXIT) return finish({ kind: "not-found" });
      const last = stdout
        .split(/\r?\n/u)
        .map((line) => line.trim())
        .filter((line) => line.length > 0)
        .at(-1);
      if (last === undefined) return finish({ kind: "failed", reason: noOutputReason(code, stderr), exitCode: code });
      try {
        const line = JSON.parse(last) as unknown;
        if (typeof line !== "object" || line === null) throw new TypeError("not an object");
        finish({ kind: "line", line: line as ProbeLine, ms: performance.now() - started, exitCode: code });
      } catch {
        finish({ kind: "failed", reason: `unparseable output (exit ${String(code)})`, exitCode: code });
      }
    });
  });

const versionTuple = (text: string | undefined): number[] =>
  (text ?? "")
    .split(".")
    .map((part) => Number.parseInt(part, 10))
    .filter((n) => Number.isFinite(n));

/** S5 §6.1 pin table. */
export const classifyPin = (
  pythonVersion: string | undefined,
  engines: ProbeLine["engines"],
): { readonly pin: "exact" | "compatible" | "mismatch"; readonly reason: string } => {
  const [major = 0, minor = 0] = versionTuple(pythonVersion);
  if (major < 3 || (major === 3 && minor < 10))
    return { pin: "mismatch", reason: `Python ${pythonVersion ?? "?"} is older than 3.10` };
  const unicorn = engines?.unicorn;
  const capstone = engines?.capstone;
  const pefile = engines?.pefile;
  if (unicorn === undefined || capstone === undefined || pefile === undefined || pefile === "")
    return { pin: "mismatch", reason: "unicorn, capstone or pefile is missing" };
  if (unicorn === "2.1.4" && capstone === "5.0.9" && pefile === "2024.8.26")
    return { pin: "exact", reason: "pinned set" };
  const [uMajor, uMinor] = versionTuple(unicorn);
  const [cMajor] = versionTuple(capstone);
  if (uMajor === 2 && uMinor === 1 && cMajor === 5)
    return {
      pin: "compatible",
      reason: `unvalidated engines (unicorn ${unicorn}, capstone ${capstone}, pefile ${pefile})`,
    };
  return { pin: "mismatch", reason: `unsupported engines (unicorn ${unicorn}, capstone ${capstone})` };
};

const USER_SITE_HINT =
  "unicorn/capstone/pefile are not importable under `python -I`; if they were installed with `pip install --user`, the isolated mode ignores the user site-packages — install them into that interpreter, or run `bea setup --emulator`";

export interface PythonResolverDeps {
  readonly platform: HostPlatform;
  /** config.python: env BEA_PYTHON (source "env") or config.json `python` (source "config-file") */
  readonly configured: { readonly value: string | null; readonly source: "env" | "config-file" | "default" };
  readonly venvDir: string;
  /** the bridge to probe with (bridgeLocator) */
  readonly bridge: () => Promise<Result<{ readonly path: string; readonly sha256: string }, BeaError>>;
  readonly probe?: (request: ProbeRequest) => Promise<ProbeOutcome>;
  readonly exists?: (path: string) => Promise<boolean>;
}

interface Candidate {
  readonly source: PythonSource;
  readonly command: PythonCommand;
  readonly explicit: boolean;
}

const fileExists = async (path: string): Promise<boolean> => {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
};

export const venvPython = (venvDir: string, platform: HostPlatform): string =>
  platform === "win32" ? win32.join(venvDir, "Scripts", "python.exe") : posix.join(venvDir, "bin", "python3");

export class PythonResolver {
  readonly #deps: PythonResolverDeps;
  #resolution: Promise<Result<ResolvedPython, BeaError>> | null = null;
  #report: ResolutionReport = { chosen: null, candidates: [] };
  #status: PythonStatus = {
    state: "not-resolved",
    source: null,
    command: null,
    versions: null,
    pin: null,
    reason: null,
  };

  constructor(deps: PythonResolverDeps) {
    this.#deps = deps;
  }

  /**
   * Memoized per process while it SUCCEEDS (concurrent callers share one resolution). Review fix ONBOARD-2: a failed
   * resolution is not kept: after `bea setup --emulator` created the venv, the running server picks it up on the next
   * emu_open instead of answering the stale failure until a restart (status() still shows the last failure).
   */
  resolve(operation: string, signal?: AbortSignal): Promise<Result<ResolvedPython, BeaError>> {
    if (this.#resolution === null) {
      const pending = this.#resolve(operation, signal);
      this.#resolution = pending;
      void pending.then((result) => {
        if (!result.ok && this.#resolution === pending) this.#resolution = null;
      });
    }
    return this.#resolution;
  }

  invalidate(): void {
    this.#resolution = null;
    this.#status = { state: "not-resolved", source: null, command: null, versions: null, pin: null, reason: null };
  }

  report(): ResolutionReport {
    return this.#report;
  }

  /** EmuPort.availability(): no probe, the last resolution only. */
  status(): PythonStatus {
    return this.#status;
  }

  #candidates(): { readonly explicit: Candidate | null; readonly fallbacks: readonly Candidate[] } {
    const { configured, platform, venvDir } = this.#deps;
    if (configured.value !== null && configured.source !== "default")
      return {
        explicit: {
          source: configured.source === "env" ? "BEA_PYTHON" : "config",
          command: { command: configured.value, prefixArgs: [] },
          explicit: true,
        },
        fallbacks: [],
      };
    const venv: Candidate = {
      source: "bea-venv",
      command: { command: venvPython(venvDir, platform), prefixArgs: [] },
      explicit: false,
    };
    const path: Candidate[] =
      platform === "win32"
        ? [
            { source: "path", command: { command: "python", prefixArgs: [] }, explicit: false },
            { source: "path", command: { command: "py", prefixArgs: ["-3"] }, explicit: false },
          ]
        : [
            { source: "path", command: { command: "python3", prefixArgs: [] }, explicit: false },
            { source: "path", command: { command: "python", prefixArgs: [] }, explicit: false },
          ];
    return { explicit: null, fallbacks: [venv, ...path] };
  }

  async #resolve(operation: string, signal: AbortSignal | undefined): Promise<Result<ResolvedPython, BeaError>> {
    const bridge = await this.#deps.bridge();
    if (!bridge.ok) {
      this.#status = { ...this.#status, state: "unavailable", reason: "bridge unavailable" };
      this.#resolution = null; // a rebuilt bridge must be picked up on the next call
      return bridge;
    }
    const probe = this.#deps.probe ?? ((request: ProbeRequest) => runBridgeProbe(request));
    const exists = this.#deps.exists ?? fileExists;
    const reports: CandidateReport[] = [];
    const { explicit, fallbacks } = this.#candidates();
    const tryCandidate = async (
      candidate: Candidate,
    ): Promise<{ readonly resolved: ResolvedPython | null; readonly outcome: string; readonly notFound: boolean }> => {
      const outcome = await probe({
        command: candidate.command,
        bridgePath: bridge.value.path,
        mode: "--probe",
        timeoutMs: PROBE_TIMEOUT_MS,
        ...(signal === undefined ? {} : { signal }),
      });
      if (outcome.kind === "not-found") return { resolved: null, outcome: "not found", notFound: true };
      if (outcome.kind === "failed")
        return { resolved: null, outcome: `probe failed: ${outcome.reason}`, notFound: false };
      const line = outcome.line;
      if (line.probe !== "bea-emu/0.1")
        return { resolved: null, outcome: "probe answered with an unexpected protocol", notFound: false };
      if (!line.ok) {
        const missing = (line.missing ?? []).filter((m) => typeof m === "string").slice(0, 4);
        return {
          resolved: null,
          outcome: `${missing.length > 0 ? `${missing.join(", ")} missing` : "engines unavailable"}; ${USER_SITE_HINT}`,
          notFound: false,
        };
      }
      const pin = classifyPin(line.python?.version, line.engines);
      if (pin.pin === "mismatch") return { resolved: null, outcome: `rejected: ${pin.reason}`, notFound: false };
      const engines: EngineVersions = {
        python: line.python?.version ?? "",
        unicorn: line.engines?.unicorn ?? "",
        unicornCore: line.engines?.unicornCore ?? "",
        capstone: line.engines?.capstone ?? "",
        pefile: line.engines?.pefile ?? "",
      };
      return {
        resolved: {
          ...candidate.command,
          source: candidate.source,
          executable: line.python?.executable ?? candidate.command.command,
          version: line.python?.version ?? "",
          inVenv: line.python?.inVenv === true,
          engines,
          pin: pin.pin,
          bridgeSha256: line.bridge?.sha256 ?? "",
          probeMs: Math.round(outcome.ms),
        },
        outcome: `ok (${pin.pin})`,
        notFound: false,
      };
    };

    if (explicit !== null) {
      if (!(await exists(explicit.command.command))) {
        reports.push({ source: explicit.source, command: explicit.command.command, outcome: "file does not exist" });
        this.#report = { chosen: null, candidates: reports };
        this.#status = {
          state: "unavailable",
          source: explicit.source,
          command: explicit.command.command,
          versions: null,
          pin: null,
          reason: "configured python does not exist",
        };
        return err({
          _tag: "ConfigurationError",
          operation,
          settings: [
            {
              setting: explicit.source === "BEA_PYTHON" ? "BEA_PYTHON" : "config.json:python",
              constraint: "must name an existing python executable",
              source: explicit.source === "BEA_PYTHON" ? "env" : "config-file",
            },
          ],
        });
      }
      const tried = await tryCandidate(explicit);
      reports.push({ source: explicit.source, command: explicit.command.command, outcome: tried.outcome });
      return this.#settle(
        operation,
        tried.resolved,
        reports,
        explicit.source === "BEA_PYTHON" ? "BEA_PYTHON" : "config.json python",
      );
    }
    for (const candidate of fallbacks) {
      if (candidate.source === "bea-venv" && !(await exists(candidate.command.command))) {
        reports.push({ source: candidate.source, command: candidate.command.command, outcome: "not created" });
        continue;
      }
      const tried = await tryCandidate(candidate);
      reports.push({
        source: candidate.source,
        command: [candidate.command.command, ...candidate.command.prefixArgs].join(" "),
        outcome:
          candidate.source === "bea-venv" && tried.resolved === null
            ? `BEA venv is broken (${tried.outcome}): run \`bea setup --emulator\``
            : tried.outcome,
      });
      if (tried.resolved !== null) return this.#settle(operation, tried.resolved, reports, null);
    }
    return this.#settle(operation, null, reports, null);
  }

  #settle(
    operation: string,
    chosen: ResolvedPython | null,
    candidates: CandidateReport[],
    explicitName: string | null,
  ): Result<ResolvedPython, BeaError> {
    this.#report = { chosen, candidates };
    if (chosen !== null) {
      this.#status = {
        state: "available",
        source: chosen.source,
        command: [chosen.command, ...chosen.prefixArgs].join(" "),
        versions: chosen.engines,
        pin: chosen.pin,
        reason: null,
      };
      return ok(chosen);
    }
    const last = candidates.at(-1);
    this.#status = {
      state: "unavailable",
      source: null,
      command: null,
      versions: null,
      pin: null,
      reason: explicitName === null ? "no usable Python with unicorn 2.1.x" : `${explicitName} is not usable`,
    };
    return err({
      _tag: "CapabilityUnavailable",
      operation,
      capability: "emulator",
      reason: explicitName === null ? "python-unavailable" : "configured-python-unusable",
      retryable: false,
      message:
        explicitName === null
          ? "No usable Python with unicorn 2.1.x, capstone 5.x and pefile was found for the emulator."
          : `${explicitName} cannot run the emulator bridge (${last?.outcome.slice(0, 200) ?? "probe failed"}).`,
      remediation: SETUP_REMEDIATION,
      diagnostics: { candidates: candidates.map((c) => ({ source: c.source, outcome: c.outcome.slice(0, 300) })) },
    });
  }
}
