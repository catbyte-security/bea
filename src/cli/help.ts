import type { ToolContract } from "../contracts/toolContract.js";
import { PRODUCT_IDENTITY } from "../identity.js";
import type { DerivedCommand, DerivedOption } from "./argv.js";
import type { CommandTable } from "./commands.js";
import { CAPTURE_GRAMMAR } from "./shorthands.js";

/** S1 §7.3 [ext-frida §4], [rea-cli §9.7]: printed by every session and instrument command's help. */
export const INJECTION_NOTICE =
  "Attaches to (or spawns) the target: loads BEA's Frida agent (frida-agent.dll + 24 system DLLs; 11 stay loaded after detach). A spawned target is killed when the command ends. Use only on processes you own.";

const TARGET_USAGE: Readonly<Record<DerivedCommand["tier"], string>> = {
  oneshot: "",
  "session-oneshot": "(--pid N | --name EXE | --spawn PROG [-- args…])",
  "instrument-oneshot": "(--pid N | --name EXE | --spawn PROG [-- args…])",
  "emu-oneshot": "--image PE",
};

const BUILTIN_USAGE = [
  [
    "run <scenario.json> [--evidence-out DIR] [--keep-run] [--json]",
    "run a bea-scenario/1 file (validated before any effect)",
  ],
  [
    "doctor [--client ID]… [--backend frida|emulation]… [--skill] [--probe] [--json]",
    "read-only health report (bea.doctor/1)",
  ],
  [
    "setup [--client ID]… [--all-detected] [--skill|--no-skill] [--emulator] [--dry-run] [--yes] [--json]",
    "register BEA with MCP clients and install the skill",
  ],
  ["uninstall [--client ID]… [--skill] [--dry-run] [--yes] [--json]", "remove BEA-owned registrations and skill"],
  ["tools [--json]", "list every tool: area, phase, hints, gate, CLI command or reason"],
  ["schema <tool|command> [--output]", "print a tool's input (or output) JSON Schema"],
  ["help [command]", "this help, or one command's help"],
  ["version", "print the package version"],
] as const;

const SERVER_USAGE = [
  ["mcp", "run the MCP server over stdio"],
  ["mcp --http [--port N] [--json-response] [--connection-file PATH]", "run the MCP server over local HTTP"],
  ["mcp doctor [--json] [--timeout-ms N]", "start the real server and check it answers (bea.mcp-doctor/1)"],
] as const;

/**
 * Review fix ONBOARD-12: `bea help <built-in>` for the commands that have no --help of their own here (tools, schema,
 * help, version, mcp): their usage rows. run/doctor/setup/uninstall print their own --help (runCli routes them).
 */
export const renderBuiltinHelp = (name: string): string | null => {
  const rows = [...BUILTIN_USAGE, ...SERVER_USAGE].filter(([usage]) => usage.split(" ")[0] === name);
  return rows.length === 0 ? null : `${pad(rows.map(([usage, text]) => [`bea ${usage}`, text] as const)).join("\n")}\n`;
};

const pad = (rows: readonly (readonly [string, string])[]): string[] => {
  const width = Math.min(48, Math.max(...rows.map(([left]) => left.length)));
  return rows.map(([left, right]) =>
    left.length > width ? `  ${left}\n  ${" ".repeat(width)}  ${right}` : `  ${left.padEnd(width)}  ${right}`,
  );
};

const isList = (option: DerivedOption | undefined): boolean =>
  option !== undefined && (option.kind === "string-list" || option.kind === "number-list");

/** `<address> [size]`, `[pid]`, `<addresses…>`. */
export const positionalUsage = (command: DerivedCommand): string => {
  const last = command.positional[command.positional.length - 1];
  return command.positional
    .map((field) => {
      if (field === "pid") return "[pid]";
      const option = command.options.find((o) => o.field === field);
      const name = `${field}${field === last && isList(option) ? "…" : ""}`;
      return option?.required === true || command.fileFields.includes(field) ? `<${name}>` : `[${name}]`;
    })
    .join(" ");
};

const shortDescription = (contract: ToolContract): string => {
  const sentence = /^(.{1,110}?[.;:])(?:\s|$)/u.exec(contract.description)?.[1] ?? contract.description.slice(0, 110);
  return sentence.replace(/[.;:]$/u, "");
};

export const commandUsage = (command: DerivedCommand): string =>
  ["bea", command.command, positionalUsage(command), TARGET_USAGE[command.tier], "[options]"]
    .filter((part) => part.length > 0)
    .join(" ");

export const renderGeneralHelp = (table: CommandTable): string => {
  const section = (title: string, tier: DerivedCommand["tier"]): string[] => {
    const rows = table.generated
      .filter((command) => command.tier === tier)
      .map(
        (command) =>
          [`${command.command} ${positionalUsage(command)}`.trim(), shortDescription(command.contract)] as const,
      );
    return rows.length === 0 ? [] : ["", title, ...pad(rows)];
  };
  const reasonRows = (tier: string): string[] =>
    table.withoutCommand.filter((contract) => contract.cli.tier === tier).map((contract) => contract.name);
  const scenarioOnly = [...reasonRows("scenario"), ...reasonRows("scenario-target")];
  const mcpOnly = reasonRows("mcp-only");
  return [
    PRODUCT_IDENTITY.tagline,
    "",
    "Usage: bea <command> [arguments] [--json]",
    "Output is one TOON document on stdout (--json for JSON); progress and logs go to stderr.",
    "Exit codes: 0 completed, 1 failed, 130 SIGINT, 143 SIGTERM, 141 stdout closed early.",
    "",
    "Server:",
    ...pad(SERVER_USAGE),
    "",
    "Built-in commands:",
    ...pad(BUILTIN_USAGE),
    ...section("Tool commands (no target):", "oneshot"),
    ...section(`Session commands ${TARGET_USAGE["session-oneshot"]}:`, "session-oneshot"),
    ...section(`Instrument commands ${TARGET_USAGE["instrument-oneshot"]}:`, "instrument-oneshot"),
    ...section(`Emulation commands ${TARGET_USAGE["emu-oneshot"]}:`, "emu-oneshot"),
    ...(scenarioOnly.length === 0
      ? []
      : ["", "Scenario steps only (bea run scenario.json):", `  ${scenarioOnly.join(", ")}`]),
    ...(mcpOnly.length === 0 ? [] : ["", "MCP only:", `  ${mcpOnly.join(", ")}`]),
    "",
    "`bea help <command>` or `bea <command> --help` shows a command's arguments.",
    "",
  ].join("\n");
};

const optionLabel = (option: DerivedOption): string => {
  if (option.kind === "boolean") return `--${option.flag} | --no-${option.flag}`;
  if (option.kind === "enum") return `--${option.flag} <${option.values.join("|")}>`;
  const value = option.kind === "number" || option.kind === "number-list" ? "N" : "VALUE";
  return `--${option.flag} ${value}${isList(option) ? " (repeatable)" : ""}`;
};

export const renderCommandHelp = (command: DerivedCommand): string => {
  const contract = command.contract;
  const session = command.tier === "session-oneshot" || command.tier === "instrument-oneshot";
  const optionRows = command.options.map(
    (option) =>
      [
        optionLabel(option),
        [option.required ? "(required)" : "", option.description.replace(/\s+/gu, " ").slice(0, 160)]
          .filter((part) => part.length > 0)
          .join(" "),
      ] as const,
  );
  const targetRows: (readonly [string, string])[] = session
    ? [
        ["--pid N", "attach to a running process (or give the pid positionally)"],
        ["--name EXE", "attach to the single process with this image name"],
        ["--spawn PROG [-- args…]", "spawn PROG suspended (killed when the command ends)"],
      ]
    : command.tier === "emu-oneshot"
      ? [["--image PE", "open an emulation session on this PE image"]]
      : [];
  return [
    `Usage: ${commandUsage(command)}`,
    "",
    contract.description,
    ...(session ? ["", INJECTION_NOTICE] : []),
    ...(command.offlineField === null
      ? []
      : ["", `--${command.offlineField.replaceAll("_", "-")} runs offline: no target flag, no session.`]),
    ...(command.fileFields.length === 0
      ? []
      : ["", `File arguments (a path; "-" reads stdin): ${command.fileFields.join(", ")}.`]),
    ...(contract.gate === null || contract.gate.scope !== "always"
      ? []
      : ["", `Gated: the user must enable gate ${contract.gate.id} (see \`bea status\`).`]),
    ...(targetRows.length === 0 ? [] : ["", "Target:", ...pad(targetRows)]),
    ...(optionRows.length === 0 ? [] : ["", "Options:", ...pad(optionRows)]),
    // ONBOARD-12: the --capture shorthand of hook_function (S6 §8.1) is a flag too, not input-only
    ...(contract.name === "hook_function"
      ? ["", "Shorthands:", ...pad([["--capture SPEC (repeatable)", CAPTURE_GRAMMAR]])]
      : []),
    ...(command.jsonOnly.filter((field) => !(contract.name === "hook_function" && field === "capture")).length === 0
      ? []
      : [
          "",
          `Only through --input FILE|- (JSON object, merged under flags): ${command.jsonOnly
            .filter((field) => !(contract.name === "hook_function" && field === "capture"))
            .join(", ")}.`,
        ]),
    "",
    "Global:",
    ...pad([
      ["--input FILE|-", "JSON object with any input fields (flags win)"],
      ["--json", "JSON instead of TOON on stdout"],
      ["--progress", "JSON-lines progress on stderr"],
      ["--keep-run", "keep this command's evidence run under BEA_HOME/runs (deleted at exit otherwise)"],
      ["--help, -h", "this help"],
    ]),
    "",
    `Numbers: decimal or 0x-hex; negative values as --flag=-1. Tool: ${contract.name} (\`bea schema ${contract.name}\`).`,
    "",
  ].join("\n");
};

export const renderGroupHelp = (group: string, commands: readonly DerivedCommand[]): string =>
  [
    `bea ${group} has these subcommands:`,
    ...pad(commands.map((command) => [commandUsage(command).slice(4), shortDescription(command.contract)] as const)),
    "",
  ].join("\n");
