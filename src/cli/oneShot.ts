import { resolve } from "node:path";

import type { ToolOutput } from "../application/invokeTool.js";
import type { BeaError } from "../domain/errors/beaError.js";
import { inputErrorFromZod, internalError } from "../domain/errors/constructors.js";
import { err, ok, type Result } from "../domain/result.js";
import { parseCommandArgs, type CliTarget, type DerivedCommand } from "./argv.js";
import { renderCommandHelp } from "./help.js";
import { assembleInput } from "./inputs.js";
import { runInstrument, withSession } from "./instrumentRunner.js";
import type { CliDeps, OutputFormat } from "./io.js";
import { EXIT } from "./output.js";
import {
  formatFromArgv,
  KEEP_RUN_FLAG,
  loadCliConfig,
  openCliRun,
  printDocument,
  printError,
  progressFor,
  reportCleanup,
  type CliRun,
} from "./runtime.js";
import { expandCliShorthands } from "./shorthands.js";

/** The session a session-creating call returned (spawn_process, attach_process, emu_open all output `session_id`). */
export const sessionIdOf = (tool: string, output: ToolOutput): Result<string, BeaError> => {
  const id = output["session_id"];
  return typeof id === "string" && id.length > 0
    ? ok(id)
    : err(internalError(tool, new Error(`${tool} output carries no session_id`)));
};

interface Execution {
  readonly result: Result<unknown, BeaError>;
  readonly degraded: boolean;
}

const done = (result: Result<unknown, BeaError>): Execution => ({ result, degraded: false });

/** A syntactically valid session id for pre-validation; never reaches a handler. */
export const PLACEHOLDER_SESSION_ID = "00000000-0000-4000-8000-000000000000";

/**
 * Before a session tier touches a target: the "always" gate and the tool input (with a placeholder session_id) must
 * pass, so a typo or a closed gate never costs an agent injection or a spawned process.
 */
const prevalidate = (
  run: CliRun,
  command: DerivedCommand,
  input: Readonly<Record<string, unknown>>,
): Result<void, BeaError> => {
  const contract = command.contract;
  if (contract.gate?.scope === "always") {
    const gate = run.app.gates.require(contract.gate.id, contract.name);
    if (!gate.ok) return gate;
  }
  const parsed = contract.inputSchema.safeParse({ ...input, session_id: PLACEHOLDER_SESSION_ID });
  return parsed.success ? ok(undefined) : err(inputErrorFromZod(contract.name, input, parsed.error));
};

/** spawn (paused) or attach, per the target flags. */
const openLiveSession = (deps: CliDeps, run: CliRun, target: Exclude<CliTarget, { kind: "image" }>) =>
  target.kind === "spawn"
    ? run.call("spawn_process", { program: resolve(deps.cwd, target.program), args: [...target.args] })
    : run.call("attach_process", target.kind === "pid" ? { pid: target.pid } : { name: target.name });

/**
 * S1 §7.4 runGenerated, minus printing and teardown (the caller owns both). `onSession` hands every session this
 * command created to the caller before anything else can fail, so the `finally` closes it.
 */
const execute = async (
  deps: CliDeps,
  run: CliRun,
  command: DerivedCommand,
  target: CliTarget | null,
  input: Readonly<Record<string, unknown>>,
  onSession: (sessionId: string) => void,
): Promise<Execution> => {
  const name = command.contract.name;
  // oneshot tools, and session tools invoked offline (cli.offlineField given: `bea symbols --pe-path X`).
  if (command.tier === "oneshot" || target === null) return done(await run.call(name, input));
  const valid = prevalidate(run, command, input);
  if (!valid.ok) return done(valid);
  if (target.kind === "image") {
    const opened = await run.call("emu_open", { image_path: resolve(deps.cwd, target.path) });
    if (!opened.ok) return done(opened);
    const session = sessionIdOf("emu_open", opened.value);
    if (!session.ok) return done(session);
    onSession(session.value);
    return done(await run.call(name, { ...input, session_id: session.value }));
  }
  const opened = await openLiveSession(deps, run, target);
  if (!opened.ok) return done(opened);
  const tool = target.kind === "spawn" ? "spawn_process" : "attach_process";
  const session = sessionIdOf(tool, opened.value);
  if (!session.ok) return done(session);
  onSession(session.value);
  const spawned = target.kind === "spawn";
  const toolInput = { ...input, session_id: session.value };
  if (command.tier === "instrument-oneshot")
    return runInstrument(run, command.contract, toolInput, session.value, spawned);
  if (spawned) {
    // S6 §8.1: a spawned target starts paused; a session one-shot resumes it before the tool runs.
    const resumed = await run.call("resume_process", withSession(run, "resume_process", {}, session.value));
    if (!resumed.ok) return done(resumed);
  }
  return done(await run.call(name, toolInput));
};

/** Closes every session the command created, then the application. Returns the adjusted exit code. */
const teardown = async (deps: CliDeps, run: CliRun, sessions: readonly string[], code: number): Promise<number> => {
  let next = code;
  for (const sessionId of [...sessions].reverse()) {
    // Kills a spawned target, detaches an attached one, closes an emulation session.
    const closed = await run.cleanupCall("close_session", { session_id: sessionId });
    if (!closed.ok) {
      deps.stderr(`bea: closing session ${sessionId} failed (${closed.error._tag}); run \`bea status\`.\n`);
      if (next === EXIT.ok) next = EXIT.failed;
    }
  }
  const report = await run.close();
  reportCleanup(deps, report);
  if (!report.ok && next === EXIT.ok) next = EXIT.failed;
  return run.signalStatus() ?? next;
};

const printOutcome = (deps: CliDeps, result: Result<unknown, BeaError>, format: OutputFormat): void => {
  if (result.ok) printDocument(deps, result.value, format);
  else printError(deps, result.error, format);
};

/** `bea <generated command> …` for the oneshot, session-oneshot, instrument-oneshot and emu-oneshot tiers. */
export const runGeneratedCommand = async (
  deps: CliDeps,
  command: DerivedCommand,
  argv: readonly string[],
): Promise<number> => {
  const format = formatFromArgv(argv);
  const split = argv.indexOf("--");
  const head = split === -1 ? argv : argv.slice(0, split);
  if (head.includes("--help") || head.includes("-h")) {
    deps.io.stdout(renderCommandHelp(command));
    return EXIT.ok;
  }
  // `--keep-run` (S2 §9.2) is a runner flag, not a tool field: taken out before the generated parser sees argv.
  const keepRun = head.includes(KEEP_RUN_FLAG);
  const runnerArgv = keepRun ? [...head.filter((arg) => arg !== KEEP_RUN_FLAG), ...argv.slice(head.length)] : argv;
  // The router expands shorthands (S6 §8.1 `--capture`, src/cli/shorthands.ts) before parsing.
  const expanded = expandCliShorthands(command.contract, runnerArgv);
  if (!expanded.ok) {
    printError(deps, expanded.error, format);
    return EXIT.failed;
  }
  const parsed = parseCommandArgs(command, expanded.value.argv);
  if (!parsed.ok) {
    printError(deps, parsed.error, format);
    return EXIT.failed;
  }
  const config = await loadCliConfig(deps);
  if (!config.ok) {
    printError(deps, config.error, format);
    return EXIT.failed;
  }
  const input = await assembleInput(deps, command, parsed.value, expanded.value.input);
  if (!input.ok) {
    printError(deps, input.error, format);
    return EXIT.failed;
  }
  const run = await openCliRun(deps, config.value, {
    surface: "cli",
    progress: progressFor(deps, parsed.value.progress),
    keepRun,
  });
  const sessions: string[] = [];
  let code: number = EXIT.failed;
  try {
    const execution = await execute(deps, run, command, parsed.value.target, input.value, (id) => sessions.push(id));
    printOutcome(deps, execution.result, format);
    code = execution.result.ok && !execution.degraded ? EXIT.ok : EXIT.failed;
  } finally {
    code = await teardown(deps, run, sessions, code);
  }
  return code;
};
