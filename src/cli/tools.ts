import { parseArgs } from "node:util";

import { z } from "zod";

import { isCommandTier, type ToolContract } from "../contracts/toolContract.js";
import { inputError } from "../domain/errors/constructors.js";
import { findCommandOrTool, type CommandTable } from "./commands.js";
import type { CliDeps } from "./io.js";
import { EXIT } from "./output.js";
import { formatFromArgv, printDocument, printError } from "./runtime.js";

/** One `bea tools` row: everything an agent needs to pick a surface for a tool. */
export const toolRow = (contract: ToolContract) => ({
  name: contract.name,
  area: contract.area,
  phase: contract.phase,
  read_only: contract.annotations.readOnlyHint,
  destructive: contract.annotations.destructiveHint,
  idempotent: contract.annotations.idempotentHint,
  open_world: contract.annotations.openWorldHint,
  gate: contract.gate === null ? null : `${contract.gate.id} (${contract.gate.scope})`,
  cli_tier: contract.cli.tier,
  cli: isCommandTier(contract.cli) ? `bea ${contract.cli.command}` : contract.cli.reason,
});

export const runToolsCommand = (deps: CliDeps, argv: readonly string[]): number => {
  const format = formatFromArgv(argv);
  const unexpected = argv.filter((arg) => arg !== "--json");
  if (unexpected.length > 0) {
    printError(
      deps,
      inputError("tools", [
        { path: "argv", reason: "unknown_argument", message: `Unexpected argument "${unexpected[0] ?? ""}".` },
      ]),
      format,
    );
    return EXIT.failed;
  }
  printDocument(
    deps,
    { schema: "bea.tools/1", count: deps.contracts.length, tools: deps.contracts.map(toolRow) },
    format,
  );
  return EXIT.ok;
};

/** The schema a client sees in tools/list (input: io "input", so defaults are optional; output: io "output"). */
export const jsonSchemaOf = (contract: ToolContract, which: "input" | "output"): Record<string, unknown> =>
  z.toJSONSchema(which === "input" ? contract.inputSchema : contract.outputSchema, {
    io: which,
    target: "draft-2020-12",
    unrepresentable: "any",
  }) as Record<string, unknown>;

/** `bea schema <tool|command> [--output]`: always JSON (a JSON Schema is JSON); indented on a TTY. */
export const runSchemaCommand = (deps: CliDeps, table: CommandTable, argv: readonly string[]): number => {
  let parsed: ReturnType<typeof parseArgs>;
  try {
    parsed = parseArgs({
      args: [...argv],
      options: { output: { type: "boolean" }, json: { type: "boolean" } },
      strict: true,
      allowPositionals: true,
    });
  } catch (cause: unknown) {
    printError(
      deps,
      inputError("schema", [
        { path: "argv", reason: "unknown_argument", message: cause instanceof Error ? cause.message : String(cause) },
      ]),
      "json",
    );
    return EXIT.failed;
  }
  const found = parsed.positionals.length === 0 ? null : findCommandOrTool(table, deps.contracts, parsed.positionals);
  if (found === null) {
    printError(
      deps,
      inputError("schema", [
        {
          path: "argv[0]",
          reason: parsed.positionals.length === 0 ? "missing_argument" : "invalid_value",
          message: "Name a tool (e.g. read_memory) or a command (e.g. read). `bea tools` lists them.",
        },
      ]),
      "json",
    );
    return EXIT.failed;
  }
  printDocument(deps, jsonSchemaOf(found.contract, parsed.values["output"] === true ? "output" : "input"), "json");
  return EXIT.ok;
};
