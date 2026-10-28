import { isBeaError } from "../../domain/errors/beaError.js";
import { projectBeaError } from "../../domain/errors/projection.js";
import type { CliDeps, OutputFormat } from "../io.js";
import { EXIT } from "../output.js";
import { printDocument, printError } from "../runtime.js";
import { statusExit, type ClientOutcome, type SetupAction, type SetupStatus } from "./actions.js";
import { clientContext, decideApproval, parseSetupArgs } from "./approval.js";
import { CLIENT_IDS, CLIENTS, type ClientId } from "./clients.js";
import { inspectClient, resolveRegisteredCommand, type ClientInspection } from "./registration.js";
import { holdsNoEntry, removeCodexTable, removeJsonEntry } from "./removeEntry.js";
import { inspectSkill, removeSkill, type SkillInspection } from "./skill.js";
import { publishConfigFile } from "./transaction.js";

const UNINSTALL_OPTIONS = {
  client: { type: "string", multiple: true },
  skill: { type: "boolean" },
  "dry-run": { type: "boolean" },
  yes: { type: "boolean", short: "y" },
  json: { type: "boolean" },
  help: { type: "boolean", short: "h" },
} as const;

const USAGE = `Usage: bea uninstall [--client ID]… [--skill] [--dry-run] [--yes] [--json]

Removes BEA-owned registrations (and, with --skill or when no --client is given, BEA's skill) using the same
backup/verify/rollback transaction as setup. Entries BEA did not write are never touched. BEA_HOME is kept.
`;

const isOwned = (inspection: ClientInspection): boolean =>
  inspection.state === "aligned" || inspection.state === "stale";

const removalText = (inspection: ClientInspection, text: string) => {
  const spec = CLIENTS[inspection.client];
  return spec.format === "toml" ? removeCodexTable(text) : removeJsonEntry(text, spec.keyPath, spec.format);
};

const messageOf = (cause: unknown): string =>
  isBeaError(cause) ? projectBeaError(cause).message : cause instanceof Error ? cause.message : String(cause);

/** `bea uninstall` (P2): only owned entries and the owned skill directory; BEA_HOME stays. */
export const runUninstallCommand = async (deps: CliDeps, argv: readonly string[]): Promise<number> => {
  const format: OutputFormat = argv.includes("--json") ? "json" : "toon";
  const args = parseSetupArgs("uninstall", argv, UNINSTALL_OPTIONS);
  if (!args.ok) {
    printError(deps, args.error, format);
    return EXIT.failed;
  }
  if (args.value.values["help"] === true) {
    deps.io.stdout(USAGE);
    return EXIT.ok;
  }
  const values = args.value.values;
  const ctx = clientContext(deps);
  const identity = await resolveRegisteredCommand(deps.execPath, deps.layout.dispatcher);
  const finish = (document: Readonly<Record<string, unknown>> & { readonly status: SetupStatus }): number => {
    printDocument(deps, { schema: "bea.uninstall/1", ...document }, format);
    return statusExit(document.status);
  };
  if (!identity.ok)
    return finish({
      status: "needs_human",
      planned_actions: [],
      applied_actions: [],
      clients: {},
      remediation: identity.reason,
    });
  const inspections: ClientInspection[] = [];
  for (const client of CLIENT_IDS) inspections.push(await inspectClient(client, ctx, identity.value));
  const explicit = args.value.clients;
  const selected: ClientId[] =
    explicit.length > 0 ? [...explicit] : inspections.filter(isOwned).map((inspection) => inspection.client);
  const wantSkill = values["skill"] === true || (explicit.length === 0 && values["skill"] !== false);
  const skill: SkillInspection | null = wantSkill ? await inspectSkill(ctx, deps.layout) : null;
  const clients: Record<string, ClientOutcome> = {};
  const removals: { readonly inspection: ClientInspection; readonly next: string }[] = [];
  for (const client of selected) {
    const inspection = inspections.find((i) => i.client === client) as ClientInspection;
    const text = inspection.snapshot?.bytes.toString("utf8") ?? null;
    if (!isOwned(inspection) || text === null) {
      clients[client] = {
        state_before: inspection.state,
        outcome: "skipped",
        reason: inspection.state === "missing" ? "no bea entry" : `not removed: ${inspection.state}`,
      };
      continue;
    }
    const edit = removalText(inspection, text);
    if (edit.kind !== "edited") {
      clients[client] = { state_before: inspection.state, outcome: "skipped", reason: edit.reason };
      continue;
    }
    removals.push({ inspection, next: edit.text });
    clients[client] = { state_before: inspection.state, outcome: "skipped", reason: "planned" };
  }
  const skillOwned = skill !== null && (skill.state === "aligned" || skill.state === "stale");
  const actions: SetupAction[] = [
    ...removals.map(({ inspection }) => ({
      id: `remove_${inspection.client}`,
      kind: "remove_client" as const,
      client: inspection.client,
      path: inspection.path,
      backup_path: `${inspection.path}.bea.backup`,
    })),
    ...(skillOwned ? [{ id: "remove_skill", kind: "remove_skill" as const, path: skill.path }] : []),
  ];
  if (actions.length === 0) return finish({ status: "ready", planned_actions: [], applied_actions: [], clients });
  const approval = await decideApproval(
    deps,
    { dryRun: values["dry-run"] === true, yes: values["yes"] === true, json: values["json"] === true },
    actions,
  );
  if (approval !== "apply") return finish({ status: approval, planned_actions: actions, applied_actions: [], clients });
  const applied: string[] = [];
  const failures: string[] = [];
  for (const { inspection, next } of removals) {
    const spec = CLIENTS[inspection.client];
    const published = await publishConfigFile(inspection.path, inspection.snapshot, next, (text) =>
      holdsNoEntry(spec.format, spec.keyPath, text),
    );
    clients[inspection.client] = published.ok
      ? { state_before: inspection.state, outcome: "removed" }
      : { state_before: inspection.state, outcome: "failed", reason: published.failure ?? "write" };
    if (published.ok) applied.push(`removed_${inspection.client}`);
    else failures.push(`${inspection.client}: ${published.failure ?? "write"}`);
  }
  if (skillOwned) {
    try {
      await removeSkill(skill);
      applied.push("removed_skill");
    } catch (cause: unknown) {
      failures.push(`skill: ${messageOf(cause)}`);
    }
  }
  return finish({
    status: failures.length === 0 ? "ready" : "needs_human",
    planned_actions: actions,
    applied_actions: applied,
    clients,
    ...(failures.length === 0
      ? {}
      : { failures, remediation: "Some removals failed; files were restored or left unchanged." }),
  });
};
