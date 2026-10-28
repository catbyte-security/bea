import { join } from "node:path";
import { parseArgs } from "node:util";

import { z } from "zod";

import type { ToolOutput } from "../application/invokeTool.js";
import { createGateEvaluator } from "../application/gatePolicy.js";
import type { ToolContract } from "../contracts/toolContract.js";
import type { BeaConfig } from "../domain/config.js";
import type { BeaError, InputIssue } from "../domain/errors/beaError.js";
import { formatIssuePath, inputError, issuesFromZod } from "../domain/errors/constructors.js";
import { projectBeaError } from "../domain/errors/projection.js";
import { isJsonObject, jsonObjectSchema } from "../domain/json.js";
import { checkOutputPath, type OutputPathPolicy } from "../domain/outputPaths.js";
import { isDriveAbsolute } from "../domain/paths.js";
import { err, ok, type Result } from "../domain/result.js";
import { readInputDocument } from "./inputs.js";
import type { CliDeps, OutputFormat } from "./io.js";
import { PLACEHOLDER_SESSION_ID, sessionIdOf } from "./oneShot.js";
import { EXIT, progressLine } from "./output.js";
import {
  formatFromArgv,
  inputFieldsOf,
  loadCliConfig,
  openCliRun,
  printDocument,
  printError,
  reportCleanup,
  stderrProgress,
  type CliRun,
} from "./runtime.js";

const SAVE_AS = /^[a-z][a-z0-9_]{0,31}$/u;
/** S1 §7.5: whole-string `${name.path}` references; no interpolation. */
const REFERENCE = /^\$\{([a-z][a-z0-9_]{0,31})\.([A-Za-z0-9_.[\]]+)\}$/u;
const SCENARIO_FILE_MAX_BYTES = 1024 * 1024;

/** Tools that create a session; allowed as steps with `save_as` (D-INT-47, CI-B7). */
export const SESSION_CREATING_TOOLS = ["spawn_process", "attach_process", "emu_open"] as const;
const TARGET_TOOL = { spawn: "spawn_process", attach: "attach_process", emulate: "emu_open" } as const;

/** S1 §7.5 schema as amended by D-INT-47 (bea-scenario/1). */
export const scenarioSchema = z.strictObject({
  schema: z.literal("bea-scenario/1"),
  target: z
    .union([
      z.strictObject({ spawn: jsonObjectSchema }),
      z.strictObject({ attach: jsonObjectSchema }),
      z.strictObject({ emulate: jsonObjectSchema }),
    ])
    .optional(),
  steps: z
    .array(
      z.strictObject({
        tool: z.string().min(3).max(48),
        input: jsonObjectSchema.default({}),
        save_as: z.string().regex(SAVE_AS).optional(),
        expect: z.enum(["ok", "error", "any"]).default("ok"),
      }),
    )
    .min(1)
    .max(256),
  teardown: z.literal("close").default("close"),
  on_error: z.enum(["stop", "continue"]).default("stop"),
  limits: z
    .strictObject({ total_ms: z.number().int().min(1_000).max(3_600_000).default(600_000) })
    .default({ total_ms: 600_000 }),
});
export type Scenario = z.output<typeof scenarioSchema>;
type Step = Scenario["steps"][number];

const targetKind = (scenario: Scenario): keyof typeof TARGET_TOOL | null =>
  scenario.target === undefined ? null : (Object.keys(scenario.target)[0] as keyof typeof TARGET_TOOL);

const targetInput = (scenario: Scenario): Readonly<Record<string, unknown>> => {
  const target = scenario.target as Readonly<Record<string, Readonly<Record<string, unknown>>>> | undefined;
  const kind = targetKind(scenario);
  return kind === null || target === undefined ? {} : (target[kind] ?? {});
};

interface Reference {
  readonly path: string;
  readonly name: string;
  readonly at: string;
}

/** Every `${name.path}` string in a step input, with its location in the input. */
export const findReferences = (value: unknown, path: (string | number)[] = []): Reference[] => {
  if (typeof value === "string") {
    const match = REFERENCE.exec(value);
    return match === null ? [] : [{ path: formatIssuePath(path), name: match[1] ?? "", at: match[2] ?? "" }];
  }
  if (Array.isArray(value)) return value.flatMap((item, index) => findReferences(item, [...path, index]));
  if (isJsonObject(value)) return Object.entries(value).flatMap(([key, item]) => findReferences(item, [...path, key]));
  return [];
};

/** `instrument.recording_id`, `rows[0].address` → keys; numeric keys index arrays. */
const lookup = (root: unknown, at: string): { readonly found: boolean; readonly value: unknown } => {
  let value = root;
  for (const key of at
    .replaceAll(/\[(\d+)\]/gu, ".$1")
    .split(".")
    .filter((part) => part.length > 0)) {
    if (Array.isArray(value) && /^\d+$/u.test(key)) value = value[Number(key)];
    else if (isJsonObject(value) && Object.hasOwn(value, key)) value = value[key];
    else return { found: false, value: undefined };
    if (value === undefined) return { found: false, value: undefined };
  }
  return { found: true, value };
};

/** Whole-string substitution from saved step results (S1 §7.5 step 5). */
export const substituteReferences = (
  value: unknown,
  saved: ReadonlyMap<string, unknown>,
  missing: string[],
): unknown => {
  if (typeof value === "string") {
    const match = REFERENCE.exec(value);
    if (match === null) return value;
    const name = match[1] ?? "";
    const resolved = saved.has(name) ? lookup(saved.get(name), match[2] ?? "") : { found: false, value: undefined };
    if (!resolved.found) missing.push(value);
    return resolved.value;
  }
  if (Array.isArray(value)) return value.map((item) => substituteReferences(item, saved, missing));
  if (isJsonObject(value))
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, substituteReferences(item, saved, missing)]),
    );
  return value;
};

const issue = (path: string, reason: InputIssue["reason"], message: string): InputIssue => ({ path, reason, message });

const parseIssues = (
  contract: ToolContract,
  input: Readonly<Record<string, unknown>>,
  prefix: string,
): InputIssue[] => {
  const parsed = contract.inputSchema.safeParse(input);
  if (parsed.success) return [];
  return issuesFromZod(input, parsed.error.issues).map((i) => ({
    ...i,
    path: `${prefix}${i.path === "" ? "" : `.${i.path}`}`,
  }));
};

/** Pre-validation of one step (S1 §7.5 step 2 as amended): tier, gate, references, and the input when ref-free. */
const validateStep = (
  step: Step,
  index: number,
  contracts: ReadonlyMap<string, ToolContract>,
  known: ReadonlySet<string>,
  hasTarget: boolean,
  config: BeaConfig,
): { readonly issues: InputIssue[]; readonly gateError: BeaError | null } => {
  const at = `scenario.steps[${String(index)}]`;
  const contract = contracts.get(step.tool);
  if (contract === undefined)
    return {
      issues: [issue(`${at}.tool`, "invalid_value", `Unknown tool "${step.tool}". \`bea tools\` lists them.`)],
      gateError: null,
    };
  if (contract.cli.tier === "mcp-only")
    return {
      issues: [issue(`${at}.tool`, "invalid_value", `${step.tool} is MCP-only: ${contract.cli.reason}`)],
      gateError: null,
    };
  if (step.tool === "close_session")
    return {
      issues: [
        issue(
          `${at}.tool`,
          "invalid_value",
          "close_session is the scenario teardown; every created session is closed at the end.",
        ),
      ],
      gateError: null,
    };
  const issues: InputIssue[] = [];
  const references = findReferences(step.input);
  for (const reference of references)
    if (!known.has(reference.name))
      issues.push(
        issue(
          `${at}.input${reference.path === "" ? "" : `.${reference.path}`}`,
          "invalid_value",
          `\${${reference.name}.…} names no earlier save_as${hasTarget ? " (or target)" : ""}.`,
        ),
      );
  const gate =
    contract.gate?.scope === "always" ? createGateEvaluator(config).require(contract.gate.id, step.tool) : null;
  if (references.length === 0) {
    const injected =
      hasTarget && inputFieldsOf(contract).has("session_id") && !("session_id" in step.input)
        ? { ...step.input, session_id: PLACEHOLDER_SESSION_ID }
        : step.input;
    issues.push(...parseIssues(contract, injected, `${at}.input`));
  }
  return { issues, gateError: gate !== null && !gate.ok ? gate.error : null };
};

/** Validate before any effect: a failure here means no handler ran (S6 "fail fast, exit 1"). */
export const validateScenario = (
  scenario: Scenario,
  contracts: readonly ToolContract[],
  config: BeaConfig,
): Result<void, BeaError> => {
  const byName = new Map(contracts.map((contract) => [contract.name, contract]));
  const issues: InputIssue[] = [];
  const kind = targetKind(scenario);
  if (kind !== null) {
    const contract = byName.get(TARGET_TOOL[kind]);
    if (contract === undefined)
      issues.push(
        issue(`scenario.target.${kind}`, "invalid_value", `${TARGET_TOOL[kind]} is not available in this build.`),
      );
    else issues.push(...parseIssues(contract, targetInput(scenario), `scenario.target.${kind}`));
  }
  const known = new Set<string>(kind === null ? [] : ["target"]);
  let gateError: BeaError | null = null;
  scenario.steps.forEach((step, index) => {
    const checked = validateStep(step, index, byName, known, kind !== null, config);
    issues.push(...checked.issues);
    gateError ??= checked.gateError;
    if (step.save_as !== undefined) {
      if (step.save_as === "target" || known.has(step.save_as))
        issues.push(
          issue(
            `scenario.steps[${String(index)}].save_as`,
            "invalid_value",
            `save_as "${step.save_as}" is reserved or already used.`,
          ),
        );
      known.add(step.save_as);
    }
  });
  if (issues.length > 0) return err(inputError("scenario", issues));
  return gateError === null ? ok(undefined) : err(gateError);
};

interface CallRecord {
  readonly tool: string;
  readonly ok: boolean;
  readonly ms: number;
  readonly result?: ToolOutput;
  readonly error?: ReturnType<typeof projectBeaError>;
}

const record = (tool: string, started: number, result: Result<ToolOutput, BeaError>): CallRecord => ({
  tool,
  ok: result.ok,
  ms: Math.round(performance.now() - started),
  ...(result.ok ? { result: result.value } : { error: projectBeaError(result.error) }),
});

interface CreatedSession {
  readonly session_id: string;
  readonly tool: string;
  /** "target" or the creating step's index */
  readonly created_by: "target" | number;
}

/** The step input after references, plus the target session_id where the contract has that field (D-INT-47). */
const prepareStepInput = (
  run: CliRun,
  step: Step,
  saved: ReadonlyMap<string, unknown>,
  targetSession: string | null,
): Result<Readonly<Record<string, unknown>>, BeaError> => {
  const missing: string[] = [];
  const substituted = substituteReferences(step.input, saved, missing) as Record<string, unknown>;
  if (missing.length > 0)
    return err(
      inputError(
        step.tool,
        missing.map((ref) =>
          issue("input", "invalid_value", `Reference ${ref} did not resolve (no value at that path).`),
        ),
      ),
    );
  const contract = run.findContract(step.tool);
  const inject =
    targetSession !== null &&
    contract !== undefined &&
    inputFieldsOf(contract).has("session_id") &&
    !("session_id" in step.input);
  // Never into live_session_id / emu_session_id: those always come from ${…} references.
  return ok(inject ? { ...substituted, session_id: targetSession } : substituted);
};

const expectationHeld = (step: Step, succeeded: boolean): boolean =>
  step.expect === "any" || (step.expect === "ok") === succeeded;

type StepRecord = CallRecord & {
  readonly index: number;
  readonly save_as?: string;
  readonly expect: Step["expect"];
  readonly passed: boolean;
};

/** What the steps phase leaves behind for the teardown and the result document. */
interface StepsState {
  readonly saved: Map<string, unknown>;
  readonly created: CreatedSession[];
  readonly steps: StepRecord[];
  target: CallRecord | null;
  targetSession: string | null;
}

const progressWriter = (deps: CliDeps) => {
  let seq = 0;
  return (tool: string, phase: string, message: string): void => {
    seq += 1;
    deps.stderr(progressLine(tool, seq, phase, message));
  };
};

const remember = (
  state: StepsState,
  tool: string,
  output: ToolOutput,
  createdBy: CreatedSession["created_by"],
): void => {
  const id = sessionIdOf(tool, output);
  if (id.ok) state.created.push({ session_id: id.value, tool, created_by: createdBy });
};

/** S1 §7.5 steps 4–5: open the target (if any), then run the steps in order until done, stopped or aborted. */
const runSteps = async (
  run: CliRun,
  scenario: Scenario,
  state: StepsState,
  progress: ReturnType<typeof progressWriter>,
): Promise<void> => {
  const kind = targetKind(scenario);
  if (kind !== null) {
    const tool = TARGET_TOOL[kind];
    const started = performance.now();
    const opened = await run.call(tool, targetInput(scenario));
    state.target = record(tool, started, opened);
    progress(tool, "target", opened.ok ? "ok" : "failed");
    if (!opened.ok) return;
    remember(state, tool, opened.value, "target");
    const id = sessionIdOf(tool, opened.value);
    if (!id.ok) {
      state.target = record(tool, started, id);
      return;
    }
    state.targetSession = id.value;
    state.saved.set("target", opened.value);
  }
  for (const [index, step] of scenario.steps.entries()) {
    if (run.signal.aborted) return;
    const started = performance.now();
    const prepared = prepareStepInput(run, step, state.saved, state.targetSession);
    const result = prepared.ok ? await run.call(step.tool, prepared.value) : prepared;
    const passed = expectationHeld(step, result.ok);
    state.steps.push({
      index,
      ...(step.save_as === undefined ? {} : { save_as: step.save_as }),
      expect: step.expect,
      passed,
      ...record(step.tool, started, result),
    });
    if (result.ok && (SESSION_CREATING_TOOLS as readonly string[]).includes(step.tool))
      remember(state, step.tool, result.value, index);
    if (step.save_as !== undefined)
      state.saved.set(step.save_as, result.ok ? result.value : { error: projectBeaError(result.error) });
    progress(step.tool, `step ${String(index)}`, passed ? "ok" : "expectation failed");
    if (!passed && scenario.on_error === "stop") return;
  }
};

interface TeardownResult {
  readonly closed: CallRecord[];
  readonly bundle: Readonly<Record<string, unknown>> | null;
  readonly cleanupOk: boolean;
}

/** S1 §7.5 step 6: close every created session (newest first), export evidence when asked, close the application. */
const teardownScenario = async (
  deps: CliDeps,
  run: CliRun,
  created: readonly CreatedSession[],
  evidenceOut: EvidenceOut | null,
  config: BeaConfig,
): Promise<TeardownResult> => {
  const closed: CallRecord[] = [];
  for (const session of [...created].reverse()) {
    const started = performance.now();
    closed.push(
      record("close_session", started, await run.cleanupCall("close_session", { session_id: session.session_id })),
    );
  }
  let bundle: Readonly<Record<string, unknown>> | null = null;
  if (evidenceOut !== null) {
    const outPath =
      evidenceOut.kind === "absolute"
        ? evidenceOut.path
        : join(config.layout.exportsDir(run.app.run.runId), ...evidenceOut.path.split(/[\\/]/u));
    const exported = await run.cleanupCall("export_evidence", { out_path: outPath });
    bundle = exported.ok
      ? {
          path: exported.value["path"] ?? null,
          bytes: exported.value["bytes"] ?? null,
          sha256: exported.value["bundle_digest"] ?? null,
        }
      : { error: projectBeaError(exported.error) };
  }
  const report = await run.close();
  reportCleanup(deps, report);
  return { closed, bundle, cleanupOk: report.ok };
};

/**
 * Review fixes UX-8/ONBOARD-3: `--evidence-out DIR`. A relative DIR (a plain name, no `..`, drive or stream) is
 * resolved under THIS run's exports directory once the run exists (the run id is unknowable before); an absolute DIR
 * must pass the output policy (exports.allowed_roots) during validation, before any effect.
 */
type EvidenceOut =
  | { readonly kind: "relative"; readonly path: string }
  | { readonly kind: "absolute"; readonly path: string };

interface ScenarioOptions {
  readonly format: OutputFormat;
  readonly evidenceOut: EvidenceOut | null;
  readonly keepRun: boolean;
}

const RELATIVE_OUT = /^(?![\\/])(?![A-Za-z]:)[^:*?"<>|\u0000]+$/u;

/** --evidence-out checked before anything runs (null = valid; the error otherwise). */
const checkEvidenceOut = (
  raw: string,
  config: BeaConfig,
): { readonly out: EvidenceOut } | { readonly error: BeaError } => {
  const issue = (message: string): { readonly error: BeaError } => ({
    error: inputError("run", [{ path: "argv.--evidence-out", reason: "invalid_value", message }]),
  });
  if (isDriveAbsolute(raw, config.platform)) {
    const policy: OutputPathPolicy = {
      platform: config.platform,
      exportsDir: config.layout.runsDir, // the run's own exports dir does not exist yet; relative names land there
      allowedRoots: config.exports.allowedRoots.value,
      systemRoots:
        config.platform === "win32"
          ? [process.env["SystemRoot"], process.env["windir"], "C:\\Windows"].filter(
              (root): root is string => root !== undefined && /^[A-Za-z]:[\\/]/u.test(root),
            )
          : ["/etc", "/usr", "/bin", "/sbin", "/lib"],
    };
    const checked = checkOutputPath(raw, policy);
    if (checked.ok && !raw.split(/[\\/]/u).includes("runs")) return { out: { kind: "absolute", path: checked.path } };
    return {
      error: {
        _tag: "AccessDenied",
        operation: "run",
        reason: "policy",
        message: checked.ok ? "--evidence-out may not point into BEA's runs directory." : checked.message,
        remediation:
          "Give a relative name (the bundle is written under this run's exports directory), or ask the user to add the parent directory to exports.allowed_roots in BEA_HOME/config.json.",
        diagnostics: { policy: checked.ok ? "runs-directory" : checked.reason },
      },
    };
  }
  if (!RELATIVE_OUT.test(raw) || raw.split(/[\\/]/u).some((segment) => segment === ".." || segment === ""))
    return issue(
      "--evidence-out takes a relative name (written under this run's exports directory) or an absolute path under exports.allowed_roots.",
    );
  return { out: { kind: "relative", path: raw } };
};

/** Steps 3–7 of S1 §7.5 once validation passed. Returns the exit code. */
const executeScenario = async (
  deps: CliDeps,
  config: BeaConfig,
  scenario: Scenario,
  options: ScenarioOptions,
): Promise<number> => {
  const limit = AbortSignal.timeout(scenario.limits.total_ms);
  const run = await openCliRun(deps, config, {
    surface: "scenario",
    progress: (tool) => stderrProgress(deps, tool),
    abortOn: limit,
    // The bundle of --evidence-out lives in the run's exports directory, so an export keeps the run (S2 §9.2).
    keepRun: options.keepRun || options.evidenceOut !== null,
  });
  const state: StepsState = { saved: new Map(), created: [], steps: [], target: null, targetSession: null };
  let torn: TeardownResult;
  try {
    await runSteps(run, scenario, state, progressWriter(deps));
  } finally {
    // Teardown always runs, including after SIGINT or the time limit.
    torn = await teardownScenario(deps, run, state.created, options.evidenceOut, config);
  }
  const stopped = run.signalStatus() !== undefined ? "signal" : limit.aborted ? "time_limit" : null;
  const scenarioOk =
    (state.target === null || state.target.ok) &&
    state.steps.length === scenario.steps.length &&
    state.steps.every((step) => step.passed) &&
    torn.closed.every((c) => c.ok) &&
    (torn.bundle === null || !("error" in torn.bundle)) &&
    torn.cleanupOk &&
    stopped === null;
  printDocument(
    deps,
    {
      schema: "bea-scenario-result/1",
      ok: scenarioOk,
      session_id: state.targetSession,
      ...(stopped === null ? {} : { stopped }),
      target: state.target,
      steps: state.steps,
      sessions: state.created,
      teardown: { closed: torn.closed, cleanup_ok: torn.cleanupOk },
      ...(torn.bundle === null ? {} : { evidence_bundle: torn.bundle }),
    },
    options.format,
  );
  return run.signalStatus() ?? (scenarioOk ? EXIT.ok : EXIT.failed);
};

/** `bea run <scenario.json> [--evidence-out DIR] [--keep-run] [--json]`. */
export const runScenarioCommand = async (deps: CliDeps, argv: readonly string[]): Promise<number> => {
  const format = formatFromArgv(argv);
  let args: ReturnType<typeof parseArgs>;
  try {
    args = parseArgs({
      args: [...argv],
      options: {
        "evidence-out": { type: "string" },
        "keep-run": { type: "boolean" },
        json: { type: "boolean" },
        help: { type: "boolean", short: "h" },
      },
      strict: true,
      allowPositionals: true,
    });
  } catch (cause: unknown) {
    printError(
      deps,
      inputError("run", [issue("argv", "unknown_argument", cause instanceof Error ? cause.message : String(cause))]),
      format,
    );
    return EXIT.failed;
  }
  if (args.values["help"] === true) {
    deps.io.stdout(
      "Usage: bea run <scenario.json|-> [--evidence-out DIR] [--keep-run] [--json]\n\nRuns a bea-scenario/1 file: validates every step before any effect, runs the steps, then closes every session it created (and exports an evidence bundle to DIR when given: a relative DIR is written under the run's exports directory, an absolute DIR must lie under a BEA_HOME/config.json exports.allowed_roots entry). The evidence run is deleted at exit unless --keep-run or --evidence-out is given. See docs/cli.md.\n",
    );
    return EXIT.ok;
  }
  const [file, ...extra] = args.positionals;
  if (file === undefined || extra.length > 0) {
    printError(
      deps,
      inputError("run", [
        issue(
          "argv",
          file === undefined ? "missing_argument" : "unknown_argument",
          "Give exactly one scenario file (or - for stdin).",
        ),
      ]),
      format,
    );
    return EXIT.failed;
  }
  const config = await loadCliConfig(deps);
  if (!config.ok) {
    printError(deps, config.error, format);
    return EXIT.failed;
  }
  const document = await readInputDocument(deps, "run", file, SCENARIO_FILE_MAX_BYTES);
  if (!document.ok) {
    printError(deps, document.error, format);
    return EXIT.failed;
  }
  const parsed = scenarioSchema.safeParse(document.value);
  if (!parsed.success) {
    const issues = issuesFromZod(document.value, parsed.error.issues).map((i) => ({
      ...i,
      path: i.path === "" ? "scenario" : `scenario.${i.path}`,
    }));
    printError(deps, inputError("run", issues), format);
    return EXIT.failed;
  }
  const valid = validateScenario(parsed.data, deps.contracts, config.value);
  if (!valid.ok) {
    printError(deps, valid.error, format);
    return EXIT.failed;
  }
  const evidenceOut = args.values["evidence-out"];
  let out: EvidenceOut | null = null;
  if (typeof evidenceOut === "string") {
    const checked = checkEvidenceOut(evidenceOut, config.value);
    if ("error" in checked) {
      printError(deps, checked.error, format);
      return EXIT.failed;
    }
    out = checked.out;
  }
  return executeScenario(deps, config.value, parsed.data, {
    format,
    evidenceOut: out,
    keepRun: args.values["keep-run"] === true,
  });
};
