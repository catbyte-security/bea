import { mkdir } from "node:fs/promises";
import { dirname } from "node:path";

import type { DoctorCheckResult } from "../../application/doctor.js";
import { isBeaError, type BeaError } from "../../domain/errors/beaError.js";
import { internalError } from "../../domain/errors/constructors.js";
import { projectBeaError } from "../../domain/errors/projection.js";
import type { ProvisionEmulatorAction } from "../../ports/provisioner.js";
import { registrationCheck, skillCheck } from "../doctor/checks.js";
import type { CliDeps, OutputFormat } from "../io.js";
import { EXIT } from "../output.js";
import { loadCliConfig, printDocument, printError } from "../runtime.js";
import { isChange, statusExit, type ClientOutcome, type SetupAction, type SetupStatus } from "./actions.js";
import { clientContext, decideApproval, parseSetupArgs } from "./approval.js";
import { CLIENT_IDS, CLIENTS, type ClientContext, type ClientId } from "./clients.js";
import {
  fileHoldsEntry,
  inspectClient,
  NEEDS_HUMAN_STATES,
  resolveRegisteredCommand,
  type ClientInspection,
  type CommandIdentity,
} from "./registration.js";
import { inspectSkill, installSkill, type SkillInspection } from "./skill.js";
import { publishConfigFile } from "./transaction.js";

const SETUP_OPTIONS = {
  client: { type: "string", multiple: true },
  "all-detected": { type: "boolean" },
  skill: { type: "boolean" },
  emulator: { type: "boolean" },
  "dry-run": { type: "boolean" },
  yes: { type: "boolean", short: "y" },
  json: { type: "boolean" },
  help: { type: "boolean", short: "h" },
} as const;

const SETUP_USAGE = `Usage: bea setup [--client ID]… [--all-detected] [--skill|--no-skill] [--emulator] [--dry-run] [--yes] [--json]

Registers BEA (\`node <package>/scripts/bea.mjs mcp\`) with MCP clients and installs the agent skill.
Clients: ${CLIENT_IDS.join(", ")}. Without --client or --all-detected, only existing BEA registrations are refreshed.
--dry-run prints the plan; without --yes a non-interactive run stops at needs_confirmation. See docs/setup.md.
`;

export interface DoctorSummary {
  readonly healthy: boolean;
  readonly checks: readonly DoctorCheckResult[];
}

/** The scoped doctor view after setup: the selected registrations and, when selected, the skill. */
export const scopedSummary = async (
  deps: CliDeps,
  ctx: ClientContext,
  identity: CommandIdentity,
  clients: readonly ClientId[],
  skill: boolean,
): Promise<DoctorSummary> => {
  const checks = [
    ...(await Promise.all(
      clients.map(async (client) => registrationCheck(await inspectClient(client, ctx, identity))),
    )),
    ...(skill ? [skillCheck(await inspectSkill(ctx, deps.layout))] : []),
  ];
  return { healthy: checks.every((check) => check.ok), checks };
};

const configureAction = (inspection: ClientInspection): SetupAction => ({
  id: `configure_${inspection.client}`,
  kind: "configure_client",
  client: inspection.client,
  path: inspection.path,
  operation: inspection.state === "missing" ? "create" : inspection.state === "stale" ? "update" : "unchanged",
  backup_path: inspection.snapshot !== null && inspection.next !== null ? `${inspection.path}.bea.backup` : null,
  entry_preview: JSON.stringify(inspection.planned),
  notes: CLIENTS[inspection.client].notes,
});

const skillAction = (inspection: SkillInspection): SetupAction => ({
  id: "install_skill",
  kind: "install_skill",
  path: inspection.path,
  operation: inspection.operation ?? "unchanged",
  files: inspection.files,
});

const errorText = (cause: unknown): string =>
  isBeaError(cause) ? projectBeaError(cause).message : cause instanceof Error ? cause.message : String(cause);

/** EMU's provisioner (a port; a WP0 stub until EMU fills it). Any failure is a plan blocker, never a crash. */
const planEmulator = async (deps: CliDeps): Promise<{ action: ProvisionEmulatorAction } | { error: BeaError }> => {
  const config = await loadCliConfig(deps);
  if (!config.ok) return { error: config.error };
  try {
    const planned = await deps.provisioner(config.value).plan(config.value, new AbortController().signal);
    return planned.ok ? { action: planned.value } : { error: planned.error };
  } catch (cause: unknown) {
    return { error: isBeaError(cause) ? cause : internalError("setup.emulator", cause) };
  }
};

interface Plan {
  readonly selected: readonly ClientId[];
  readonly inspections: ReadonlyMap<ClientId, ClientInspection>;
  readonly skill: SkillInspection | null;
  readonly emulator: ProvisionEmulatorAction | null;
  readonly actions: readonly SetupAction[];
  readonly blockers: readonly string[];
}

const buildPlan = async (
  deps: CliDeps,
  ctx: ClientContext,
  identity: CommandIdentity,
  flags: {
    readonly clients: readonly ClientId[];
    readonly allDetected: boolean;
    readonly skill: boolean | undefined;
    readonly emulator: boolean;
  },
): Promise<Plan> => {
  const inspections = new Map<ClientId, ClientInspection>();
  for (const client of CLIENT_IDS) inspections.set(client, await inspectClient(client, ctx, identity));
  const all = [...inspections.values()];
  // Detection is not permission: without --client, --all-detected adds clients; otherwise only owned ones refresh.
  const selected =
    flags.clients.length > 0
      ? flags.clients
      : flags.allDetected
        ? all.filter((i) => i.detected).map((i) => i.client)
        : all.filter((i) => i.state === "aligned" || i.state === "stale").map((i) => i.client);
  const wantSkill = flags.skill ?? selected.includes("claude_code");
  const skill = wantSkill ? await inspectSkill(ctx, deps.layout) : null;
  const blockers: string[] = [];
  for (const client of selected) {
    const inspection = inspections.get(client);
    if (inspection !== undefined && NEEDS_HUMAN_STATES.includes(inspection.state))
      blockers.push(`${client}: ${inspection.state} — ${inspection.reason ?? ""}`.trim());
  }
  if (skill !== null && skill.operation === null) blockers.push(`skill: ${skill.reason ?? skill.state}`);
  let emulator: ProvisionEmulatorAction | null = null;
  if (flags.emulator) {
    const planned = await planEmulator(deps);
    if ("error" in planned) blockers.push(`emulator: ${errorText(planned.error)}`);
    else emulator = planned.action;
  }
  const actions: SetupAction[] = [
    ...selected.map((client) => configureAction(inspections.get(client) as ClientInspection)),
    ...(skill !== null && skill.operation !== null ? [skillAction(skill)] : []),
    ...(emulator === null ? [] : [emulator]),
  ];
  return { selected, inspections, skill, emulator, actions, blockers };
};

interface Applied {
  readonly applied: string[];
  readonly failures: string[];
  readonly clients: Record<string, ClientOutcome>;
}

const applyPlan = async (deps: CliDeps, plan: Plan): Promise<Applied> => {
  const applied: string[] = [];
  const failures: string[] = [];
  const clients: Record<string, ClientOutcome> = {};
  for (const client of plan.selected) {
    const inspection = plan.inspections.get(client) as ClientInspection;
    if (inspection.next === null) {
      clients[client] = { state_before: inspection.state, outcome: "unchanged" };
      continue;
    }
    try {
      if (inspection.snapshot === null) await mkdir(dirname(inspection.path), { recursive: true });
      const published = await publishConfigFile(inspection.path, inspection.snapshot, inspection.next, (text) =>
        fileHoldsEntry(client, text, inspection.planned),
      );
      if (published.ok) {
        applied.push(`configured_${client}`);
        clients[client] = { state_before: inspection.state, outcome: "configured" };
      } else {
        failures.push(`${client}: ${published.failure ?? "write"}`);
        clients[client] = { state_before: inspection.state, outcome: "failed", reason: published.failure ?? "write" };
      }
    } catch (cause: unknown) {
      failures.push(`${client}: ${errorText(cause)}`);
      clients[client] = { state_before: inspection.state, outcome: "failed", reason: "write" };
    }
  }
  if (plan.skill !== null && plan.skill.operation !== null && plan.skill.operation !== "unchanged") {
    try {
      await installSkill(plan.skill);
      applied.push("installed_skill");
    } catch (cause: unknown) {
      failures.push(`skill: ${errorText(cause)}`);
    }
  }
  if (plan.emulator !== null) {
    const config = await loadCliConfig(deps);
    try {
      const result = config.ok
        ? await deps.provisioner(config.value).apply(plan.emulator, new AbortController().signal)
        : config;
      if (result.ok) applied.push("provisioned_emulator");
      else failures.push(`emulator: ${errorText(result.error)}`);
    } catch (cause: unknown) {
      failures.push(`emulator: ${errorText(cause)}`);
    }
  }
  return { applied, failures, clients };
};

const finish = (
  deps: CliDeps,
  format: OutputFormat,
  document: Readonly<Record<string, unknown>> & { readonly status: SetupStatus },
): number => {
  printDocument(deps, { schema: "bea.setup/1", ...document }, format);
  return statusExit(document.status);
};

/** `bea setup` (S1 §7.9). Every write goes through publishConfigFile; nothing is written before approval. */
export const runSetupCommand = async (deps: CliDeps, argv: readonly string[]): Promise<number> => {
  const args = parseSetupArgs("setup", argv, SETUP_OPTIONS);
  const format: OutputFormat = argv.includes("--json") ? "json" : "toon";
  if (!args.ok) {
    printError(deps, args.error, format);
    return EXIT.failed;
  }
  if (args.value.values["help"] === true) {
    deps.io.stdout(SETUP_USAGE);
    return EXIT.ok;
  }
  const values = args.value.values;
  const ctx = clientContext(deps);
  const identity = await resolveRegisteredCommand(deps.execPath, deps.layout.dispatcher);
  if (!identity.ok)
    return finish(deps, format, {
      status: "needs_human",
      planned_actions: [],
      applied_actions: [],
      clients: {},
      restart: [],
      remediation: identity.reason,
    });
  const skillFlag = values["skill"];
  const plan = await buildPlan(deps, ctx, identity.value, {
    clients: args.value.clients,
    allDetected: values["all-detected"] === true,
    skill: typeof skillFlag === "boolean" ? skillFlag : undefined,
    emulator: values["emulator"] === true,
  });
  const before = Object.fromEntries(
    plan.selected.map((client) => [
      client,
      { state_before: plan.inspections.get(client)?.state ?? "unknown", outcome: "skipped" },
    ]),
  ) as Record<string, ClientOutcome>;
  const summary = (): Promise<DoctorSummary> =>
    scopedSummary(deps, ctx, identity.value, plan.selected, plan.skill !== null);
  const changes = plan.actions.filter(isChange);
  const base = { planned_actions: plan.actions };
  if (plan.blockers.length > 0)
    return finish(deps, format, {
      status: "needs_human",
      ...base,
      applied_actions: [],
      clients: before,
      restart: [],
      doctor: await summary(),
      remediation: `Nothing was written. Resolve: ${plan.blockers.join("; ")}`,
    });
  if (changes.length === 0)
    return finish(deps, format, {
      status: "ready",
      ...base,
      applied_actions: [],
      clients: Object.fromEntries(
        plan.selected.map((c) => [c, { state_before: before[c]?.state_before ?? "aligned", outcome: "unchanged" }]),
      ),
      restart: [...plan.selected],
      doctor: await summary(),
      ...(plan.actions.length === 0
        ? { remediation: "Nothing selected: pass --client ID (or --all-detected) to register BEA with a client." }
        : {}),
    });
  const approval = await decideApproval(
    deps,
    { dryRun: values["dry-run"] === true, yes: values["yes"] === true, json: values["json"] === true },
    changes,
  );
  if (approval !== "apply")
    return finish(deps, format, {
      status: approval,
      ...base,
      applied_actions: [],
      clients: before,
      restart: [],
      doctor: await summary(),
      ...(approval === "needs_confirmation"
        ? { remediation: "Review planned_actions, then rerun with --yes (or run interactively in a terminal)." }
        : {}),
    });
  const applied = await applyPlan(deps, plan);
  const restart = plan.selected.filter((client) => applied.clients[client]?.outcome !== "failed");
  if (restart.length > 0)
    deps.stderr(`Restart ${restart.map((c) => CLIENTS[c].label).join(", ")} so it loads BEA's tools.\n`);
  return finish(deps, format, {
    status: applied.failures.length === 0 ? "ready" : "needs_human",
    ...base,
    applied_actions: applied.applied,
    clients: applied.clients,
    restart,
    doctor: await summary(),
    ...(applied.failures.length === 0
      ? {}
      : {
          failures: applied.failures,
          remediation:
            "Some changes failed (see failures); earlier files are intact or backed up. Fix the cause and rerun setup.",
        }),
  });
};
