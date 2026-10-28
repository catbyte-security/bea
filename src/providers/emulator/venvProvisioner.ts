import { spawn as nodeSpawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdir, open, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { resolveDistLayout, type DistLayout } from "../../application/distLayout.js";
import { BEA_PACKAGE_NAME, BEA_PACKAGE_VERSION } from "../../application/emu/packageVersion.js";
import type { BeaConfig } from "../../domain/config.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { EmulatorProvisioner, ProvisionEmulatorAction } from "../../ports/provisioner.js";
import { sha256Of } from "./bridgeLocator.js";
import { classifyPin, noAutoInstallEnv, runBridgeProbe, venvPython, type ProbeLine } from "./pythonResolver.js";
import { compareSelftest, type SelftestReport } from "./selftestExpectations.js";

/**
 * `bea setup --emulator` behind the WP0 port (S5 §6.4, D-INT-28, CI-I7): a BEA-owned venv at <BEA_HOME>/emu/venv,
 * built in a staging directory with `uv venv` + `uv pip install --require-hashes --only-binary :all: --no-deps -r
 * bridge/emu/requirements.lock` (else `python -m venv` + pip with the same flags), verified with the bridge's own
 * `--probe` (pin exact) and `--selftest`, marked with bea-emu.json, then committed by rename with rollback. The
 * user's package-index configuration is respected; integrity comes from the hash-locked requirements. Runs under
 * <BEA_HOME>/emu/.setup.lock (O_EXCL, stale after 10 minutes). Constructed without an application (setup builds no
 * BeaCore); no work happens at construction.
 */
export interface CommandOutcome {
  readonly exitCode: number | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly timedOut: boolean;
  readonly notFound: boolean;
}
export type CommandRunner = (
  argv: readonly string[],
  options: {
    readonly timeoutMs: number;
    readonly signal: AbortSignal;
    readonly env?: Readonly<Record<string, string>>;
  },
) => Promise<CommandOutcome>;

export interface ProvisionerOverrides {
  readonly run?: CommandRunner;
  readonly layout?: DistLayout;
  readonly randomId?: () => string;
  readonly nowIso?: () => string;
  /** the bridge probe/selftest of the staged interpreter (tests) */
  readonly probe?: typeof runBridgeProbe;
}

export const VENV_MARKER_FILE = "bea-emu.json";
const VENV_MARKER_SCHEMA = "bea.emu-venv/1";
const SETUP_LOCK = ".setup.lock";
const STALE_LOCK_MS = 10 * 60_000;
const OUTPUT_TAIL = 4096;
const NETWORK_ORIGINS = ["https://pypi.org", "https://files.pythonhosted.org"] as const;

/** Package pins of requirements.lock ("name==version" lines; hashes stay in the file and are enforced by pip/uv). */
export const parseRequirementsLock = (text: string): string[] =>
  text
    .split(/\r?\n/u)
    .map((line) => /^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)/u.exec(line.trim()))
    .filter((m): m is RegExpExecArray => m !== null)
    .map((m) => `${m[1] ?? ""}==${m[2] ?? ""}`);

const tail = (text: string): string => (text.length > OUTPUT_TAIL ? text.slice(-OUTPUT_TAIL) : text);

const runCommand: CommandRunner = (argv, options) =>
  new Promise((resolve) => {
    const [command, ...args] = argv;
    if (command === undefined) {
      resolve({ exitCode: null, stdout: "", stderr: "", timedOut: false, notFound: true });
      return;
    }
    let stdout = "";
    let stderr = "";
    let settled = false;
    const finish = (outcome: CommandOutcome): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      options.signal.removeEventListener("abort", onAbort);
      resolve(outcome);
    };
    const child = nodeSpawn(command, args, {
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
      env: noAutoInstallEnv(options.env),
    });
    const timer = setTimeout(() => {
      child.kill();
      finish({ exitCode: null, stdout: tail(stdout), stderr: tail(stderr), timedOut: true, notFound: false });
    }, options.timeoutMs);
    const onAbort = (): void => {
      child.kill();
      finish({ exitCode: null, stdout: tail(stdout), stderr: tail(stderr), timedOut: false, notFound: false });
    };
    options.signal.addEventListener("abort", onAbort, { once: true });
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (text: string) => (stdout = tail(stdout + text)));
    child.stderr.on("data", (text: string) => (stderr = tail(stderr + text)));
    child.once("error", (cause: NodeJS.ErrnoException) =>
      finish({
        exitCode: null,
        stdout: "",
        stderr: cause.code ?? "",
        timedOut: false,
        notFound: cause.code === "ENOENT",
      }),
    );
    child.once("close", (code: number | null) =>
      finish({ exitCode: code, stdout: tail(stdout), stderr: tail(stderr), timedOut: false, notFound: code === 9009 }),
    );
  });

const BASE_PROBE =
  "import json,struct,sys;print(json.dumps({'v':'%d.%d.%d'%sys.version_info[:3],'impl':sys.implementation.name,'bits':struct.calcsize('P')*8,'exe':sys.executable}))";

interface BaseInterpreter {
  readonly argv: readonly string[];
  readonly executable: string;
  readonly version: string;
}

const failure = (operation: string, step: string, outcome: CommandOutcome | null, message: string): BeaError => ({
  _tag: "ProviderFailure",
  operation,
  provider: "python",
  message,
  remediation:
    "Check network access to your Python package index and that the base Python is CPython >= 3.10 (64-bit); re-run `bea setup --emulator`.",
  diagnostics: {
    step,
    exit_code: outcome?.exitCode ?? null,
    timed_out: outcome?.timedOut ?? false,
  },
});

const fileFailure = (
  operation: string,
  fileOperation: "read" | "write" | "rename" | "mkdir" | "remove",
  path: string,
  reason: "exists" | "missing" | "permission" | "io",
  message?: string,
): BeaError => ({
  _tag: "FileOperationFailed",
  operation,
  file_operation: fileOperation,
  path,
  reason,
  ...(message === undefined ? {} : { message }),
});

const errnoReason = (cause: unknown): "exists" | "missing" | "permission" | "io" => {
  const code = typeof cause === "object" && cause !== null ? Reflect.get(cause, "code") : undefined;
  return code === "EEXIST"
    ? "exists"
    : code === "ENOENT"
      ? "missing"
      : code === "EACCES" || code === "EPERM"
        ? "permission"
        : "io";
};

const pathExists = async (path: string): Promise<boolean> => {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
};

export const createEmulatorProvisioner = (
  deps: { readonly config: BeaConfig },
  overrides: ProvisionerOverrides = {},
): EmulatorProvisioner => {
  const run = overrides.run ?? runCommand;
  const probe = overrides.probe ?? runBridgeProbe;
  const layoutOf = (): DistLayout => overrides.layout ?? resolveDistLayout();
  const randomId = overrides.randomId ?? (() => randomBytes(4).toString("hex"));
  const nowIso = overrides.nowIso ?? (() => new Date().toISOString());
  const OPERATION = "setup_emulator";

  /** CPython >= 3.10, 64-bit (probed with -I -c). */
  const inspectBase = async (argv: readonly string[], signal: AbortSignal): Promise<BaseInterpreter | null> => {
    const outcome = await run([...argv, "-I", "-c", BASE_PROBE], { timeoutMs: 15_000, signal });
    if (outcome.exitCode !== 0) return null;
    try {
      const info = JSON.parse(outcome.stdout.trim().split(/\r?\n/u).at(-1) ?? "") as Record<string, unknown>;
      const version = String(info["v"]);
      const [major = 0, minor = 0] = version.split(".").map(Number);
      if (info["impl"] !== "cpython" || info["bits"] !== 64 || major < 3 || (major === 3 && minor < 10)) return null;
      return { argv, executable: String(info["exe"]), version };
    } catch {
      return null;
    }
  };

  const findBase = async (config: BeaConfig, signal: AbortSignal, uv: boolean): Promise<BaseInterpreter | null> => {
    const candidates: (readonly string[])[] = [];
    if (config.python.value !== null) candidates.push([config.python.value]);
    if (uv) {
      const found = await run(["uv", "python", "find", ">=3.10"], {
        timeoutMs: 15_000,
        signal,
        env: { UV_PYTHON_DOWNLOADS: "never" },
      });
      const path = found.stdout.trim().split(/\r?\n/u).at(-1);
      if (found.exitCode === 0 && path !== undefined && path.length > 0) candidates.push([path]);
    }
    if (config.platform === "win32") candidates.push(["py", "-3"], ["python"]);
    else candidates.push(["python3"], ["python"]);
    for (const argv of candidates) {
      const base = await inspectBase(argv, signal);
      if (base !== null) return base;
    }
    return null;
  };

  const plan = async (config: BeaConfig, signal: AbortSignal): Promise<Result<ProvisionEmulatorAction, BeaError>> => {
    const layout = layoutOf();
    let lockText: string;
    try {
      lockText = await readFile(layout.bridgeRequirements, "utf8");
    } catch (cause) {
      return err(
        fileFailure(
          OPERATION,
          "read",
          layout.bridgeRequirements,
          errnoReason(cause),
          "The emulator requirements lock is missing from this BEA installation.",
        ),
      );
    }
    const packages = parseRequirementsLock(lockText);
    if (packages.length === 0)
      return err(
        fileFailure(OPERATION, "read", layout.bridgeRequirements, "io", "The requirements lock lists no package pins."),
      );
    const uvVersion = await run(["uv", "--version"], { timeoutMs: 15_000, signal });
    const tool: ProvisionEmulatorAction["tool"] = uvVersion.exitCode === 0 ? "uv" : "venv+pip";
    const base = await findBase(config, signal, tool === "uv");
    if (base === null)
      return err({
        _tag: "CapabilityUnavailable",
        operation: OPERATION,
        capability: "emulator",
        reason: "python-unavailable",
        retryable: false,
        message: "No CPython >= 3.10 (64-bit) was found to create the emulator venv.",
        remediation:
          "Install Python 3.10 or newer (python.org or `uv python install`), or set BEA_PYTHON / config.json python.",
      });
    const id = randomId();
    const venv = config.layout.venvDir;
    const staging = join(config.layout.emuDir, `venv.staging-${id}`);
    const stagingPython = venvPython(staging, config.platform);
    const commands: (readonly string[])[] =
      tool === "uv"
        ? [
            ["uv", "venv", staging, "--python", base.executable],
            [
              "uv",
              "pip",
              "install",
              "--python",
              stagingPython,
              "--require-hashes",
              "--only-binary",
              ":all:",
              "--no-deps",
              "-r",
              layout.bridgeRequirements,
            ],
          ]
        : [
            [...base.argv, "-I", "-m", "venv", staging],
            [
              stagingPython,
              "-I",
              "-m",
              "pip",
              "install",
              "--require-hashes",
              "--only-binary=:all:",
              "--no-deps",
              "--no-input",
              "--disable-pip-version-check",
              "-r",
              layout.bridgeRequirements,
            ],
          ];
    return ok({
      id,
      kind: "provision_emulator",
      venv,
      tool,
      python: base.executable,
      packages,
      network_origins: [...NETWORK_ORIGINS],
      commands,
    });
  };

  /** O_EXCL lock file; a lock older than ten minutes is stale and taken over. */
  const acquireLock = async (emuDir: string): Promise<Result<() => Promise<void>, BeaError>> => {
    await mkdir(emuDir, { recursive: true });
    const path = join(emuDir, SETUP_LOCK);
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const handle = await open(path, "wx");
        await handle.writeFile(JSON.stringify({ pid: process.pid, at: nowIso() }));
        await handle.close();
        return ok(async () => {
          await rm(path, { force: true });
        });
      } catch (cause) {
        if (errnoReason(cause) !== "exists") return err(fileFailure(OPERATION, "write", path, errnoReason(cause)));
        const info = await stat(path).catch(() => null);
        if (info !== null && Date.now() - info.mtimeMs < STALE_LOCK_MS)
          return err({
            _tag: "ResourceConstraint",
            operation: OPERATION,
            resource: "capacity",
            limits: { setup_lock: path },
            message: "Another `bea setup --emulator` is running (the setup lock is held).",
            remediation: "Wait for it to finish; a lock older than ten minutes is taken over automatically.",
          });
        await rm(path, { force: true });
      }
    }
    return err(fileFailure(OPERATION, "write", path, "exists"));
  };

  const verify = async (
    python: string,
    bridgePath: string,
    signal: AbortSignal,
  ): Promise<Result<ProbeLine, BeaError>> => {
    const probed = await probe({
      command: { command: python, prefixArgs: [] },
      bridgePath,
      mode: "--probe",
      timeoutMs: 30_000,
      signal,
    });
    if (probed.kind !== "line" || !probed.line.ok)
      return err(
        failure(OPERATION, "verify-probe", null, "The new venv cannot run the emulator bridge (--probe failed)."),
      );
    if (classifyPin(probed.line.python?.version, probed.line.engines).pin !== "exact")
      return err(failure(OPERATION, "verify-probe", null, "The new venv does not hold the pinned engine set."));
    return ok(probed.line);
  };

  /** The venv path is absent, or holds BEA's own venv (its marker). */
  const ownedOrAbsent = async (venv: string): Promise<boolean> => {
    if (!(await pathExists(venv))) return true;
    const existing = await readFile(join(venv, VENV_MARKER_FILE), "utf8")
      .then((t) => JSON.parse(t) as Record<string, unknown>)
      .catch(() => null);
    return existing?.["schema"] === VENV_MARKER_SCHEMA;
  };

  const apply = async (
    action: ProvisionEmulatorAction,
    signal: AbortSignal,
  ): Promise<Result<{ readonly python: string; readonly versions: Readonly<Record<string, string>> }, BeaError>> => {
    const layout = layoutOf();
    const emuDir = dirname(action.venv);
    const staging = join(emuDir, `venv.staging-${action.id}`);
    const platform = deps.config.platform;
    const stagingPython = venvPython(staging, platform);
    const finalPython = venvPython(action.venv, platform);
    const lock = await acquireLock(emuDir);
    if (!lock.ok) return lock;
    let committed = false;
    try {
      // ONBOARD-4: refuse a target BEA does not own BEFORE building a whole staging venv (time, network)
      const owned = await ownedOrAbsent(action.venv);
      if (!owned)
        return err(
          fileFailure(
            OPERATION,
            "rename",
            action.venv,
            "exists",
            `The venv path holds a directory BEA did not create (no bea.emu-venv/1 marker); delete or move ${action.venv}, then run \`bea setup --emulator\` again.`,
          ),
        );
      const steps: readonly { readonly name: string; readonly timeoutMs: number }[] = [
        { name: "create", timeoutMs: 60_000 },
        { name: "install", timeoutMs: 300_000 },
      ];
      for (const [index, argv] of action.commands.entries()) {
        const step = steps[index] ?? { name: `step-${String(index)}`, timeoutMs: 300_000 };
        const outcome = await run(argv, { timeoutMs: step.timeoutMs, signal, env: { UV_PYTHON_DOWNLOADS: "never" } });
        if (signal.aborted) return err({ _tag: "Cancelled", operation: OPERATION, by: "signal" });
        if (outcome.exitCode !== 0)
          return err(
            failure(
              OPERATION,
              step.name,
              outcome,
              `The venv ${step.name} step failed${outcome.timedOut ? " (timed out)" : ""}.`,
            ),
          );
      }
      const probed = await verify(stagingPython, layout.bridgeScript, signal);
      if (!probed.ok) return probed;
      const selftest = await probe({
        command: { command: stagingPython, prefixArgs: [] },
        bridgePath: layout.bridgeScript,
        mode: "--selftest",
        timeoutMs: 60_000,
        signal,
      });
      if (selftest.kind !== "line")
        return err(
          failure(OPERATION, "verify-selftest", null, "The bridge --selftest did not answer in the new venv."),
        );
      const compared = compareSelftest(selftest.line as unknown as SelftestReport, probed.value.engines?.unicorn ?? "");
      if (!compared.passed)
        return err(
          failure(
            OPERATION,
            "verify-selftest",
            null,
            `The engine self-test differs from the validated set (${compared.mismatches.join(", ")}).`,
          ),
        );
      const [lockBytes, bridgeBytes] = await Promise.all([
        readFile(layout.bridgeRequirements),
        readFile(layout.bridgeScript),
      ]);
      const versions: Record<string, string> = {
        python: probed.value.python?.version ?? "",
        unicorn: probed.value.engines?.unicorn ?? "",
        capstone: probed.value.engines?.capstone ?? "",
        pefile: probed.value.engines?.pefile ?? "",
      };
      const marker = {
        schema: VENV_MARKER_SCHEMA,
        created_by: { package: BEA_PACKAGE_NAME, version: BEA_PACKAGE_VERSION },
        lock_sha256: sha256Of(lockBytes),
        bridge_sha256: sha256Of(bridgeBytes),
        tool: action.tool,
        python: { version: versions["python"] ?? "", base_executable: action.python },
        engines: versions,
        created_at: nowIso(),
      };
      try {
        await writeFile(join(staging, VENV_MARKER_FILE), `${JSON.stringify(marker, null, 2)}\n`, "utf8");
      } catch (cause) {
        return err(fileFailure(OPERATION, "write", join(staging, VENV_MARKER_FILE), errnoReason(cause)));
      }
      // commit: an existing target must be BEA's own (marker), then target -> prev, staging -> target, re-probe
      let previous: string | null = null;
      if (await pathExists(action.venv)) {
        const existing = await readFile(join(action.venv, VENV_MARKER_FILE), "utf8")
          .then((t) => JSON.parse(t) as Record<string, unknown>)
          .catch(() => null);
        if (existing?.["schema"] !== VENV_MARKER_SCHEMA)
          return err(
            fileFailure(
              OPERATION,
              "rename",
              action.venv,
              "exists",
              "The venv path holds a directory BEA did not create; refusing to replace it.",
            ),
          );
        previous = join(
          emuDir,
          `venv.prev-${nowIso()
            .replace(/[^0-9]/gu, "")
            .slice(0, 14)}-${action.id}`,
        );
        try {
          await rename(action.venv, previous);
        } catch (cause) {
          return err(fileFailure(OPERATION, "rename", action.venv, errnoReason(cause)));
        }
      }
      try {
        await rename(staging, action.venv);
      } catch (cause) {
        if (previous !== null) await rename(previous, action.venv).catch(() => undefined);
        return err(fileFailure(OPERATION, "rename", staging, errnoReason(cause)));
      }
      // relocating a venv by rename is believed safe (the launcher finds pyvenv.cfg next to itself): re-probe
      const reprobe = await verify(finalPython, layout.bridgeScript, signal);
      if (!reprobe.ok) {
        await rename(action.venv, staging).catch(() => undefined);
        if (previous !== null) await rename(previous, action.venv).catch(() => undefined);
        return reprobe;
      }
      committed = true;
      if (previous !== null) await rm(previous, { recursive: true, force: true }).catch(() => undefined);
      return ok({ python: finalPython, versions });
    } finally {
      if (!committed) await rm(staging, { recursive: true, force: true, maxRetries: 3 }).catch(() => undefined);
      await lock.value();
    }
  };

  return { plan, apply };
};
