import type { DoctorCheckDefinition, DoctorCheckResult } from "../../application/doctor.js";
import { createApplication } from "../../application/createApplication.js";
import type { BeaConfig } from "../../domain/config.js";
import { isBeaError } from "../../domain/errors/beaError.js";
import { projectBeaError } from "../../domain/errors/projection.js";
import { createLogger } from "../../domain/logger.js";
import { PRODUCT_IDENTITY } from "../../identity.js";
import type { CliDeps, OutputFormat } from "../io.js";
import { EXIT } from "../output.js";
import { discardCliRun, loadCliConfig, missingHomeDirs, printDocument, printError } from "../runtime.js";
import { clientContext, parseSetupArgs } from "../setup/approval.js";
import { CLIENT_IDS, type ClientId } from "../setup/clients.js";
import { inspectClient, resolveRegisteredCommand, type ClientInspection } from "../setup/registration.js";
import { inspectSkill, type SkillInspection } from "../setup/skill.js";
import {
  configCheck,
  homeCheck,
  nodeCheck,
  platformCheck,
  registrationCheck,
  skillCheck,
  unknownEnvCheck,
} from "./checks.js";

export const DOCTOR_BACKENDS = ["frida", "emulation"] as const;
export type DoctorBackend = (typeof DOCTOR_BACKENDS)[number];
/** A registered check that hangs must not hang doctor. */
const CHECK_TIMEOUT_MS = 30_000;

export interface RegistrationStatus {
  readonly client: ClientId;
  readonly path: string;
  readonly detected: boolean;
  readonly state: string;
}

export interface SkillStatus {
  readonly path: string;
  readonly state: string;
  readonly version: string | null;
  readonly tool_count: number | null;
}

/** S1 §7.8 report. */
export interface DoctorReport {
  readonly schema: "bea.doctor/1";
  readonly healthy: boolean;
  readonly environment_healthy: boolean;
  readonly scope: {
    readonly mode: "audit-wide" | "explicit";
    readonly clients: readonly string[];
    readonly backends: readonly string[];
    readonly skill: boolean;
    readonly probe: boolean;
  };
  readonly scope_checks: readonly DoctorCheckResult[];
  readonly informational_checks: readonly DoctorCheckResult[];
  readonly identity: {
    readonly cli_package_version: string;
    readonly expected_skill_version: string;
    readonly node: string;
    readonly platform: string;
    readonly frida_version: string | null;
    readonly registrations: readonly RegistrationStatus[];
    readonly skill: SkillStatus;
  };
}

const DOCTOR_OPTIONS = {
  client: { type: "string", multiple: true },
  backend: { type: "string", multiple: true },
  skill: { type: "boolean" },
  probe: { type: "boolean" },
  json: { type: "boolean" },
  help: { type: "boolean", short: "h" },
} as const;

const USAGE = `Usage: bea doctor [--client ID]… [--backend frida|emulation]… [--skill] [--probe] [--json]

Read-only health report (bea.doctor/1). No option audits the core, every detected client registration and the skill;
any option makes the scope explicit, and only the scoped checks decide "healthy" and the exit code. Backend checks run
only with --backend (frida is never loaded otherwise); probes that start BEA-owned processes run only with --probe.
`;

type Placement = "scope" | "informational";
interface Ran {
  readonly result: DoctorCheckResult;
  readonly placement: Placement;
  /** intrinsically informational checks never affect environment_healthy */
  readonly advisory: boolean;
}

/** Runs one registered check with a deadline; a throw or timeout is a runtime_failure, never a doctor crash. */
const runRegistered = async (check: DoctorCheckDefinition): Promise<DoctorCheckResult> => {
  const deadline = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      check.run(deadline.signal),
      new Promise<DoctorCheckResult>((resolve) => {
        timer = setTimeout(() => {
          deadline.abort();
          resolve({
            name: check.name,
            ok: false,
            classification: "runtime_failure",
            detail: `The check did not finish within ${String(CHECK_TIMEOUT_MS)} ms.`,
          });
        }, CHECK_TIMEOUT_MS);
      }),
    ]);
  } catch (cause: unknown) {
    return {
      name: check.name,
      ok: false,
      classification: "runtime_failure",
      detail: isBeaError(cause)
        ? projectBeaError(cause).message
        : cause instanceof Error
          ? cause.message.slice(0, 500)
          : String(cause),
    };
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
};

interface Scope {
  readonly explicit: boolean;
  readonly clients: readonly ClientId[];
  readonly backends: readonly DoctorBackend[];
  readonly skill: boolean;
  readonly probe: boolean;
}

/**
 * S1 §7.8 runs the emulator's probes with "backend emulation and --probe", but the frozen DoctorCheckDefinition scope
 * has a single "probe" value. Until the port can say so, a probe in the emulator's namespace also needs
 * `--backend emulation` (it starts Python and the bridge); other probes (frida:inject-probe) run with `--probe` alone.
 */
const EMULATION_PROBE = /^emulat(?:ion|or):/u;
const wantedCheck = (check: DoctorCheckDefinition, scope: Scope): boolean => {
  switch (check.scope) {
    case "always":
    case "informational":
      return true;
    case "backend:frida":
      return scope.backends.includes("frida");
    case "backend:emulation":
      return scope.backends.includes("emulation");
    case "probe":
      return scope.probe && (!EMULATION_PROBE.test(check.name) || scope.backends.includes("emulation"));
  }
};

/** Checks contributed on core.doctor by service factories (SESS frida:*, build:agent; PROC jobhost:*, host:elevation; EMU emulation:*). */
const registeredChecks = async (deps: CliDeps, config: BeaConfig, scope: Scope): Promise<Ran[]> => {
  // Doctor leaves nothing behind: a probe that records evidence (frida:inject-probe) writes a CLI run, which is
  // deleted after the close; directories this doctor created (runs/, the bridge's emu/ cwd, BEA_HOME) go when empty.
  const created = await missingHomeDirs(config);
  const app = await createApplication({
    config,
    logger: createLogger({ level: config.logLevel.value, write: deps.stderr }),
    transport: "cli",
    services: deps.services,
  });
  try {
    const ran: Ran[] = [];
    for (const check of app.doctor.list()) {
      if (!wantedCheck(check, scope)) continue;
      const advisory = check.scope === "informational";
      ran.push({ result: await runRegistered(check), placement: advisory ? "informational" : "scope", advisory });
    }
    return ran;
  } finally {
    const closed = await app.lifecycle.closeAll("doctor-exit");
    if (closed.ok) await discardCliRun(deps, config, app.run.runId, created);
  }
};

const registrationRuns = (inspections: readonly ClientInspection[], scope: Scope): Ran[] =>
  inspections.flatMap((inspection): Ran[] => {
    const inScope = scope.explicit ? scope.clients.includes(inspection.client) : inspection.detected;
    if (!inScope && !inspection.detected) return [];
    return [{ result: registrationCheck(inspection), placement: inScope ? "scope" : "informational", advisory: false }];
  });

/** Builds the report (S1 §7.8); never writes configuration and never creates BEA_HOME. */
export const buildDoctorReport = async (deps: CliDeps, scope: Scope): Promise<DoctorReport> => {
  const loaded = await loadCliConfig(deps);
  const config = loaded.ok ? loaded.value : null;
  const ran: Ran[] = [
    { result: nodeCheck(deps.nodeVersion), placement: "scope", advisory: false },
    { result: platformCheck(deps.platform, deps.arch), placement: "scope", advisory: false },
    { result: configCheck(loaded), placement: "scope", advisory: false },
    { result: unknownEnvCheck(config), placement: "informational", advisory: true },
    { result: await homeCheck(config?.home.value ?? null), placement: "scope", advisory: false },
  ];
  const ctx = clientContext(deps);
  const identity = await resolveRegisteredCommand(deps.execPath, deps.layout.dispatcher);
  const inspections: ClientInspection[] = [];
  if (identity.ok) for (const client of CLIENT_IDS) inspections.push(await inspectClient(client, ctx, identity.value));
  else
    ran.push({
      result: { name: "registration", ok: false, classification: "missing_dependency", detail: identity.reason },
      placement: scope.explicit && scope.clients.length === 0 ? "informational" : "scope",
      advisory: false,
    });
  ran.push(...registrationRuns(inspections, scope));
  const skill: SkillInspection = await inspectSkill(ctx, deps.layout);
  const claudeDetected = inspections.some((i) => i.client === "claude_code" && i.detected);
  const skillInScope = scope.explicit ? scope.skill : claudeDetected;
  // review fix ONBOARD-10: the skill is Claude Code's; without Claude Code (and without --skill) a missing skill is
  // informational only and never makes the environment unhealthy (a Codex-only machine is fine)
  ran.push({
    result: skillCheck(skill),
    placement: skillInScope ? "scope" : "informational",
    advisory: !skillInScope && !claudeDetected,
  });
  if (config !== null) ran.push(...(await registeredChecks(deps, config, scope)));
  const scopeChecks = ran.filter((r) => r.placement === "scope").map((r) => r.result);
  const fridaBinding = ran.find((r) => r.result.name === "frida:binding" && r.result.ok)?.result.detail ?? "";
  return {
    schema: "bea.doctor/1",
    healthy: scopeChecks.every((check) => check.ok),
    environment_healthy: ran.filter((r) => !r.advisory).every((r) => r.result.ok),
    scope: {
      mode: scope.explicit ? "explicit" : "audit-wide",
      clients: scope.clients,
      backends: scope.backends,
      skill: scope.skill,
      probe: scope.probe,
    },
    scope_checks: scopeChecks,
    informational_checks: ran.filter((r) => r.placement === "informational").map((r) => r.result),
    identity: {
      cli_package_version: PRODUCT_IDENTITY.packageVersion,
      expected_skill_version: PRODUCT_IDENTITY.skillVersion,
      node: deps.nodeVersion,
      platform: `${deps.platform}-${deps.arch}`,
      frida_version: /\b(\d+\.\d+\.\d+)\b/u.exec(fridaBinding)?.[1] ?? null,
      registrations: inspections.map((i) => ({ client: i.client, path: i.path, detected: i.detected, state: i.state })),
      skill: {
        path: skill.path,
        state: skill.state,
        version: skill.installed?.version ?? null,
        tool_count: skill.installed?.tool_count ?? null,
      },
    },
  };
};

/** `bea doctor` (S1 §7.8): exit 0 iff healthy. */
export const runDoctorCommand = async (deps: CliDeps, argv: readonly string[]): Promise<number> => {
  const format: OutputFormat = argv.includes("--json") ? "json" : "toon";
  const args = parseSetupArgs("doctor", argv, DOCTOR_OPTIONS);
  if (!args.ok) {
    printError(deps, args.error, format);
    return EXIT.failed;
  }
  const values = args.value.values;
  if (values["help"] === true) {
    deps.io.stdout(USAGE);
    return EXIT.ok;
  }
  const rawBackends = Array.isArray(values["backend"]) ? (values["backend"] as string[]) : [];
  const badBackend = rawBackends.find((b) => !(DOCTOR_BACKENDS as readonly string[]).includes(b));
  if (badBackend !== undefined) {
    printError(
      deps,
      {
        _tag: "InputError",
        operation: "doctor",
        issues: [
          {
            path: "--backend",
            reason: "invalid_value",
            message: `Unknown backend ${badBackend}; use frida or emulation.`,
          },
        ],
      },
      format,
    );
    return EXIT.failed;
  }
  const backends = [...new Set(rawBackends)] as DoctorBackend[];
  const scope: Scope = {
    explicit:
      args.value.clients.length > 0 || backends.length > 0 || values["skill"] === true || values["probe"] === true,
    clients: args.value.clients,
    backends,
    skill: values["skill"] === true,
    probe: values["probe"] === true,
  };
  const report = await buildDoctorReport(deps, scope);
  printDocument(deps, report, format);
  return report.healthy ? EXIT.ok : EXIT.failed;
};
