import { isCommandTier, type ToolContract } from "../contracts/toolContract.js";
import { deriveCommand, type DerivedCommand } from "./argv.js";

/** Hand-written commands (S1 §7.2). `mcp` and `version` are routed by scripts/bea.mjs before the CLI loads. */
export const BUILTIN_COMMANDS = ["run", "doctor", "setup", "uninstall", "tools", "schema", "help"] as const;
export type BuiltinCommand = (typeof BUILTIN_COMMANDS)[number];

export interface CommandTable {
  readonly generated: readonly DerivedCommand[];
  readonly byCommand: ReadonlyMap<string, DerivedCommand>;
  /** First words of two-word commands ("evidence"), for group help. */
  readonly groups: ReadonlyMap<string, readonly DerivedCommand[]>;
  /** Tools without a generated command, with the contract's reason (tier scenario, scenario-target, mcp-only). */
  readonly withoutCommand: readonly ToolContract[];
}

export const buildCommandTable = (contracts: readonly ToolContract[]): CommandTable => {
  const generated: DerivedCommand[] = [];
  const withoutCommand: ToolContract[] = [];
  for (const contract of contracts) {
    const derived = deriveCommand(contract);
    if (derived === null) withoutCommand.push(contract);
    else generated.push(derived);
  }
  const groups = new Map<string, DerivedCommand[]>();
  for (const command of generated) {
    const [first, second] = command.command.split(" ");
    if (first !== undefined && second !== undefined) groups.set(first, [...(groups.get(first) ?? []), command]);
  }
  return {
    generated,
    byCommand: new Map(generated.map((command) => [command.command, command])),
    groups,
    withoutCommand,
  };
};

export type CommandMatch =
  | { readonly kind: "help" }
  | { readonly kind: "builtin"; readonly name: BuiltinCommand; readonly rest: readonly string[] }
  | { readonly kind: "generated"; readonly command: DerivedCommand; readonly rest: readonly string[] }
  | { readonly kind: "group"; readonly group: string; readonly commands: readonly DerivedCommand[] }
  | { readonly kind: "unknown"; readonly word: string };

/** Built-ins first (generated commands cannot shadow them: defineTool), then the longest command prefix. */
export const matchCommand = (table: CommandTable, argv: readonly string[]): CommandMatch => {
  const [first, second] = argv;
  if (first === undefined || first === "--help" || first === "-h") return { kind: "help" };
  if ((BUILTIN_COMMANDS as readonly string[]).includes(first))
    return { kind: "builtin", name: first as BuiltinCommand, rest: argv.slice(1) };
  if (second !== undefined) {
    const two = table.byCommand.get(`${first} ${second}`);
    if (two !== undefined) return { kind: "generated", command: two, rest: argv.slice(2) };
  }
  const one = table.byCommand.get(first);
  if (one !== undefined) return { kind: "generated", command: one, rest: argv.slice(1) };
  const group = table.groups.get(first);
  if (group !== undefined) return { kind: "group", group: first, commands: group };
  return { kind: "unknown", word: first };
};

/** A command's or tool's generated command, by command words or tool name (`bea help read`, `bea schema read_memory`). */
export const findCommandOrTool = (
  table: CommandTable,
  contracts: readonly ToolContract[],
  words: readonly string[],
): { readonly contract: ToolContract; readonly command: DerivedCommand | null } | null => {
  const joined = words.join(" ");
  const command = table.byCommand.get(joined);
  if (command !== undefined) return { contract: command.contract, command };
  const contract = contracts.find((c) => c.name === joined);
  if (contract === undefined) return null;
  return {
    contract,
    command: isCommandTier(contract.cli) ? (table.byCommand.get(contract.cli.command) ?? null) : null,
  };
};
