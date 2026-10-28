import { inputError } from "../domain/errors/constructors.js";
import { PRODUCT_IDENTITY } from "../identity.js";
import {
  buildCommandTable,
  findCommandOrTool,
  matchCommand,
  type BuiltinCommand,
  type CommandTable,
} from "./commands.js";
import { runDoctorCommand } from "./doctor/runDoctor.js";
import { renderBuiltinHelp, renderCommandHelp, renderGeneralHelp, renderGroupHelp } from "./help.js";
import type { CliDeps } from "./io.js";
import { runGeneratedCommand } from "./oneShot.js";
import { EXIT } from "./output.js";
import { formatFromArgv, printError } from "./runtime.js";
import { runScenarioCommand } from "./scenario.js";
import { runSetupCommand } from "./setup/runSetup.js";
import { runUninstallCommand } from "./setup/uninstall.js";
import { runSchemaCommand, runToolsCommand } from "./tools.js";

const runHelp = (deps: CliDeps, table: CommandTable, words: readonly string[]): number | Promise<number> => {
  if (words.length === 0) {
    deps.io.stdout(renderGeneralHelp(table));
    return EXIT.ok;
  }
  const group = table.groups.get(words.join(" "));
  if (group !== undefined) {
    deps.io.stdout(renderGroupHelp(words.join(" "), group));
    return EXIT.ok;
  }
  // ONBOARD-12: the built-ins the general help lists (run, doctor, setup, uninstall print their own --help)
  const [first] = words;
  if (words.length === 1 && first !== undefined) {
    if (first === "run" || first === "doctor" || first === "setup" || first === "uninstall")
      return runBuiltin(deps, table, first, ["--help"]);
    const usage = renderBuiltinHelp(first);
    if (usage !== null) {
      deps.io.stdout(usage);
      return EXIT.ok;
    }
  }
  const found = findCommandOrTool(table, deps.contracts, words);
  if (found?.command !== null && found?.command !== undefined) {
    deps.io.stdout(renderCommandHelp(found.command));
    return EXIT.ok;
  }
  if (found !== null && found !== undefined) {
    const cli = found.contract.cli;
    deps.io.stdout(
      `${found.contract.name} has no CLI command (${cli.tier}): ${"reason" in cli ? cli.reason : ""}\n${found.contract.description}\n`,
    );
    return EXIT.ok;
  }
  deps.stderr(`bea: no command or tool named "${words.join(" ")}". Run \`bea help\`.\n`);
  return EXIT.failed;
};

const runBuiltin = (
  deps: CliDeps,
  table: CommandTable,
  name: BuiltinCommand,
  rest: readonly string[],
): number | Promise<number> => {
  switch (name) {
    case "help":
      return runHelp(deps, table, rest);
    case "tools":
      return runToolsCommand(deps, rest);
    case "schema":
      return runSchemaCommand(deps, table, rest);
    case "run":
      return runScenarioCommand(deps, rest);
    case "doctor":
      return runDoctorCommand(deps, rest);
    case "setup":
      return runSetupCommand(deps, rest);
    case "uninstall":
      return runUninstallCommand(deps, rest);
  }
};

/**
 * `bea <command>` router (S1 §7.2): built-ins, then the generated commands by longest prefix (`evidence show`). Every
 * command prints exactly one document on stdout (or help text) and returns the exit code; scripts/bea.mjs sets it.
 */
export const runCli = async (deps: CliDeps, argv: readonly string[]): Promise<number> => {
  const table = buildCommandTable(deps.contracts);
  const match = matchCommand(table, argv);
  switch (match.kind) {
    case "help":
      return runHelp(deps, table, []);
    case "builtin":
      return runBuiltin(deps, table, match.name, match.rest);
    case "generated":
      return runGeneratedCommand(deps, match.command, match.rest);
    case "group":
      deps.stderr(renderGroupHelp(match.group, match.commands));
      printError(
        deps,
        inputError(match.group, [
          { path: "argv[1]", reason: "missing_argument", message: `\`bea ${match.group}\` needs a subcommand.` },
        ]),
        formatFromArgv(argv),
      );
      return EXIT.failed;
    case "unknown":
      if (match.word === "version" || match.word === "--version" || match.word === "-v") {
        deps.io.stdout(`${PRODUCT_IDENTITY.packageVersion}\n`);
        return EXIT.ok;
      }
      deps.stderr(`bea: unknown command "${match.word}". Run \`bea help\` for the command list.\n`);
      printError(
        deps,
        inputError("cli", [
          { path: "argv[0]", reason: "unknown_argument", message: `Unknown command "${match.word}".` },
        ]),
        formatFromArgv(argv),
      );
      return EXIT.failed;
  }
};
