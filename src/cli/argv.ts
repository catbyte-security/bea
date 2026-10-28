import { parseArgs, type ParseArgsConfig } from "node:util";

import { z } from "zod";

import { isCommandTier, type CliCommandTier, type ToolContract } from "../contracts/toolContract.js";
import type { BeaErrorOf, InputIssue } from "../domain/errors/beaError.js";
import { inputError } from "../domain/errors/constructors.js";
import { err, ok, type Result } from "../domain/result.js";

export type OptionKind = "string" | "number" | "boolean" | "enum" | "string-list" | "number-list";

export interface DerivedOption {
  readonly field: string;
  readonly flag: string;
  readonly kind: OptionKind;
  readonly values: readonly string[];
  readonly required: boolean;
  readonly description: string;
}

/** One generated command. Built from the advertised input JSON Schema, never zod internals. */
export interface DerivedCommand {
  readonly contract: ToolContract;
  readonly command: string;
  readonly tier: CliCommandTier;
  readonly positional: readonly string[];
  readonly options: readonly DerivedOption[];
  /** Object/array-of-object fields: only through --input FILE|- (merged under flags). */
  readonly jsonOnly: readonly string[];
  /** CI-I11: given, this field waives the session target and the command runs as a plain one-shot. */
  readonly offlineField: string | null;
  /** CI-I11: fields whose CLI value is a file path ("-" = stdin), read by the CLI runner. */
  readonly fileFields: readonly string[];
}

/** Flags every generated command accepts. Contract fields may not use these names (invariant test). */
export const GLOBAL_FLAGS = ["input", "json", "progress", "help"] as const;
/** Target flags of the session and instrument tiers (exactly one is required). */
export const SESSION_TARGET_FLAGS = ["pid", "name", "spawn"] as const;
/** Target flag of the emu-oneshot tier. */
export const EMU_TARGET_FLAGS = ["image"] as const;

export const targetFlagsFor = (tier: CliCommandTier): readonly string[] =>
  tier === "session-oneshot" || tier === "instrument-oneshot"
    ? SESSION_TARGET_FLAGS
    : tier === "emu-oneshot"
      ? EMU_TARGET_FLAGS
      : [];

type JsonSchemaNode = {
  readonly type?: string | readonly string[];
  readonly enum?: readonly unknown[];
  readonly items?: JsonSchemaNode;
  readonly description?: string;
};

const classify = (node: JsonSchemaNode): { kind: OptionKind; values: string[] } | null => {
  if (node.enum !== undefined && node.enum.every((v) => typeof v === "string"))
    return { kind: "enum", values: node.enum as string[] };
  if (node.type === "string") return { kind: "string", values: [] };
  if (node.type === "integer" || node.type === "number") return { kind: "number", values: [] };
  if (node.type === "boolean") return { kind: "boolean", values: [] };
  if (node.type === "array" && node.items !== undefined) {
    if (node.items.type === "string") return { kind: "string-list", values: [] };
    if (node.items.type === "integer" || node.items.type === "number") return { kind: "number-list", values: [] };
  }
  return null;
};

const kebabFlag = (field: string): string => field.replaceAll("_", "-");

export const deriveCommand = (contract: ToolContract): DerivedCommand | null => {
  const cli = contract.cli;
  if (!isCommandTier(cli)) return null;
  const schema = z.toJSONSchema(contract.inputSchema, {
    io: "input",
    target: "draft-2020-12",
    unrepresentable: "any",
  }) as {
    readonly properties?: Readonly<Record<string, JsonSchemaNode>>;
    readonly required?: readonly string[];
  };
  const required = new Set(schema.required ?? []);
  const options: DerivedOption[] = [];
  const jsonOnly: string[] = [];
  for (const [field, node] of Object.entries(schema.properties ?? {})) {
    if (cli.tier !== "oneshot" && field === "session_id") continue; // replaced by the target flags
    const kind = classify(node);
    if (kind === null) {
      jsonOnly.push(field);
      continue;
    }
    options.push({
      field,
      flag: kebabFlag(field),
      ...kind,
      required: required.has(field),
      description: node.description ?? "",
    });
  }
  return {
    contract,
    command: cli.command,
    tier: cli.tier,
    positional: cli.positional,
    options,
    jsonOnly,
    offlineField: cli.offlineField ?? null,
    fileFields: cli.fileFields ?? [],
  };
};

export type CliTarget =
  | { readonly kind: "pid"; readonly pid: number }
  | { readonly kind: "name"; readonly name: string }
  | { readonly kind: "spawn"; readonly program: string; readonly args: readonly string[] }
  | { readonly kind: "image"; readonly path: string };

export interface ParsedCommand {
  readonly input: Record<string, unknown>;
  /** null for oneshot commands and for offline invocations (offlineField given) */
  readonly target: CliTarget | null;
  /** CI-I11: fileFields values; the runner reads each file (UTF-8, ≤ the field's maxLength) into input[field] */
  readonly fileInputs: readonly { readonly field: string; readonly path: string }[];
  readonly inputFile: string | null;
  readonly format: "toon" | "json";
  readonly progress: boolean;
  readonly help: boolean;
}

/**
 * CT-M12: CLI numbers use the schema grammar: decimal (optional sign, fraction, exponent) or 0x-hex with an optional
 * sign. Anything else (including the empty string, which Number() turns into 0) becomes NaN and fails validation.
 * A negative value needs the `--flag=-1` form, because parseArgs reads `-1` as a short flag.
 */
export const parseCliNumber = (text: string): number => {
  const trimmed = text.trim();
  if (/^[+-]?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/u.test(trimmed)) return Number(trimmed);
  const hex = /^([+-]?)0x([0-9a-fA-F]{1,16})$/u.exec(trimmed);
  if (hex === null) return Number.NaN;
  const magnitude = Number.parseInt(hex[2] ?? "", 16);
  return hex[1] === "-" ? -magnitude : magnitude;
};

const convert = (option: DerivedOption, raw: string | boolean | (string | boolean)[]): unknown => {
  const one = (value: string | boolean): unknown =>
    (option.kind === "number" || option.kind === "number-list") && typeof value === "string"
      ? parseCliNumber(value)
      : value;
  return Array.isArray(raw) ? raw.map(one) : one(raw);
};

/**
 * argv after the command words. For session/instrument tiers everything after
 * `--` is the spawned program's argv (requires --spawn). Unknown flags, a
 * missing or ambiguous target, and type problems become invalid_request issues.
 */
export const parseCommandArgs = (
  command: DerivedCommand,
  argv: readonly string[],
): Result<ParsedCommand, BeaErrorOf<"InputError">> => {
  const fail = (issues: InputIssue[]) => err(inputError(command.contract.name, issues));
  const targetFlags = targetFlagsFor(command.tier);
  const split = argv.indexOf("--");
  const head =
    split === -1 || command.tier === "oneshot" || command.tier === "emu-oneshot" ? [...argv] : argv.slice(0, split);
  const spawnArgs = split === -1 || head.length === argv.length ? [] : argv.slice(split + 1);
  const config: NonNullable<ParseArgsConfig["options"]> = {
    input: { type: "string" },
    json: { type: "boolean" },
    progress: { type: "boolean" },
    help: { type: "boolean", short: "h" },
  };
  for (const flag of targetFlags) config[flag] = { type: "string" };
  for (const option of command.options)
    config[option.flag] =
      option.kind === "boolean"
        ? { type: "boolean" }
        : { type: "string", multiple: option.kind === "string-list" || option.kind === "number-list" };
  let parsed: ReturnType<typeof parseArgs>;
  try {
    parsed = parseArgs({ args: head, options: config, strict: true, allowPositionals: true, allowNegative: true });
  } catch (cause: unknown) {
    return fail([
      { path: "argv", reason: "unknown_argument", message: cause instanceof Error ? cause.message : String(cause) },
    ]);
  }
  const issues: InputIssue[] = [];
  const input: Record<string, unknown> = {};
  const targetValues: Record<string, string> = {};
  for (const flag of targetFlags) {
    const value = parsed.values[flag];
    if (typeof value === "string") targetValues[flag] = value;
  }
  // A field given as a flag leaves the positional sequence; any target flag removes the pid slot.
  const positionalFields = command.positional.filter((field) => {
    if (field === "pid") return Object.keys(targetValues).length === 0;
    const option = command.options.find((o) => o.field === field);
    return option === undefined || parsed.values[option.flag] === undefined;
  });
  // CI-I11: a list-typed LAST positional is variadic (`bea map <addresses…>`).
  const isList = (field: string | undefined): boolean => {
    const option = command.options.find((o) => o.field === field);
    return option !== undefined && (option.kind === "string-list" || option.kind === "number-list");
  };
  const lastField = positionalFields[positionalFields.length - 1];
  parsed.positionals.forEach((value, index) => {
    const field = positionalFields[index] ?? (isList(lastField) ? lastField : undefined);
    if (field === undefined) {
      issues.push({
        path: `argv[${String(index)}]`,
        reason: "unknown_argument",
        message: `Unexpected positional argument "${value}".`,
      });
      return;
    }
    if (field === "pid") {
      targetValues["pid"] = value;
      return;
    }
    const option = command.options.find((o) => o.field === field);
    if (option !== undefined && isList(field)) {
      const previous = input[field];
      input[field] = [...(Array.isArray(previous) ? (previous as unknown[]) : []), convert(option, value)];
      return;
    }
    input[field] = option === undefined ? value : convert(option, value);
  });
  for (const option of command.options) {
    const raw = parsed.values[option.flag];
    if (raw !== undefined) input[option.field] = convert(option, raw);
  }
  // CI-I11: fileFields leave `input` and become file references for the runner.
  const fileInputs: { field: string; path: string }[] = [];
  for (const field of command.fileFields) {
    const value = input[field];
    if (typeof value === "string") {
      fileInputs.push({ field, path: value });
      delete input[field];
    }
  }
  let target: CliTarget | null = null;
  const given = Object.keys(targetValues);
  const offline =
    command.offlineField !== null &&
    (input[command.offlineField] !== undefined || fileInputs.some((f) => f.field === command.offlineField));
  if (offline && given.length > 0)
    issues.push({
      path: targetFlags.join("|"),
      reason: "conflicting_arguments",
      message: `--${kebabFlag(command.offlineField ?? "")} runs offline; do not combine it with ${targetFlags.map((f) => `--${f}`).join(", ")}.`,
    });
  else if (targetFlags.length > 0 && !offline) {
    if (given.length !== 1)
      issues.push({
        path: targetFlags.join("|"),
        reason: given.length === 0 ? "missing_argument" : "conflicting_arguments",
        message: `Give exactly one of ${targetFlags.map((f) => `--${f}`).join(", ")}.`,
      });
    else if (targetValues["pid"] !== undefined) {
      const pid = Number(targetValues["pid"]);
      if (!Number.isSafeInteger(pid) || pid <= 0)
        issues.push({ path: "pid", reason: "invalid_value", message: "--pid must be a positive integer." });
      else target = { kind: "pid", pid };
    } else if (targetValues["name"] !== undefined) target = { kind: "name", name: targetValues["name"] };
    else if (targetValues["spawn"] !== undefined)
      target = { kind: "spawn", program: targetValues["spawn"], args: spawnArgs };
    else if (targetValues["image"] !== undefined) target = { kind: "image", path: targetValues["image"] };
  }
  if (spawnArgs.length > 0 && target?.kind !== "spawn")
    issues.push({
      path: "argv",
      reason: "conflicting_arguments",
      message: "Arguments after -- are only allowed with --spawn.",
    });
  if (issues.length > 0) return fail(issues);
  const inputFile = parsed.values["input"];
  return ok({
    input,
    target,
    fileInputs,
    inputFile: typeof inputFile === "string" ? inputFile : null,
    format: parsed.values["json"] === true ? "json" : "toon",
    progress: parsed.values["progress"] === true,
    help: parsed.values["help"] === true,
  });
};
