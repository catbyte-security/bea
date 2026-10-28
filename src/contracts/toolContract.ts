import { z } from "zod";

import { HARD_LIMITS } from "../domain/config.js";
import type { BeaErrorCode } from "../domain/errors/errorCatalog.js";
import type { GateId } from "../domain/gates.js";
import type { JsonValue } from "../domain/json.js";
import { annotationsFromEffects, type DerivedToolAnnotations, type ToolEffects } from "./effects.js";
import { ENVELOPE_RESERVED_KEYS, REQUIRED_ENVELOPE_KEYS } from "./schemas/envelope.js";

/** One file per area under src/contracts/areas/, pre-wired in src/contracts/index.ts. */
export const TOOL_AREAS = [
  "sessions",
  "inspect",
  "address",
  "scan",
  "instrument",
  "behavior",
  "watch",
  "call",
  "modify",
  "dump",
  "emulation",
  "evidence",
] as const;
export type ToolArea = (typeof TOOL_AREAS)[number];

export type ToolPhase = "P1" | "P2" | "P3";

/** Roots are z.ZodObject at runtime (defineTool + invariant test); typed loosely for generics. */
export type ToolInputSchema = z.ZodType<Readonly<Record<string, unknown>>>;
export type ToolOutputSchema = z.ZodType<Readonly<Record<string, unknown>>>;

export type GateScope = "always" | "attached-targets";
export interface GateDeclaration {
  readonly id: GateId;
  /** always: checked before the handler runs. attached-targets: the handler checks it once ownership is known. */
  readonly scope: GateScope;
}

/** CLI tiers (S6 §8.1). Command tiers are generated; the others name a reason. */
export type CliCommandTier = "oneshot" | "session-oneshot" | "instrument-oneshot" | "emu-oneshot";
export type CliReasonTier = "scenario" | "scenario-target" | "mcp-only";
export type CliMapping =
  | {
      readonly tier: CliCommandTier;
      /** "status", "read", or a two-word group command such as "evidence show". */
      readonly command: string;
      /**
       * Input fields taken positionally, in order. "pid" names the attach target (session tiers). A list-typed LAST
       * positional is variadic (`bea map <addresses…>`, CI-I11).
       */
      readonly positional: readonly string[];
      /**
       * CI-I11: an input field that, when given, waives the session target (--pid/--name/--spawn) and runs the command
       * as a plain one-shot (`bea symbols --pe-path X`, `bea map 0x140001000 --pe-path X`). Must be an input field.
       */
      readonly offlineField?: string;
      /**
       * CI-I11: string fields whose CLI value is a FILE PATH ("-" = stdin); the CLI runner reads the file (UTF-8, at
       * most the field's maxLength) and passes its text (`bea script hook.js --pid 1234` fills `source`).
       */
      readonly fileFields?: readonly string[];
    }
  | { readonly tier: CliReasonTier; readonly reason: string };

/** Built-ins the generated commands may not shadow. */
export const RESERVED_COMMANDS = [
  "mcp",
  "run",
  "doctor",
  "setup",
  "uninstall",
  "tools",
  "schema",
  "help",
  "version",
] as const;

export const SESSION_STATE_REASON =
  "Session state cannot cross CLI processes; use it from MCP or as a step of `bea run scenario.json`.";

export type SessionKind = "live" | "emulation" | "none";

/** Catalog metadata S6 relies on for its tests. S1 adapters only carry it. */
export interface EvidencePolicy {
  readonly predicate: string | null;
  readonly recorded: "always" | "never" | "detail-complete" | "when-done";
  /** input keys excluded from evidence identity beyond the Recorder defaults (S2 §7.9 step 2) */
  readonly identityExclude?: readonly string[];
}

export interface ToolExample {
  readonly title: string;
  readonly input: Readonly<Record<string, JsonValue>>;
}

/** What an area author writes. */
export interface ToolSpec<N extends string, I extends ToolInputSchema, O extends ToolOutputSchema> {
  readonly name: N;
  readonly area: ToolArea;
  readonly phase: ToolPhase;
  /** Defaults to Title Case of the name. */
  readonly title?: string;
  /** 40-600 chars. State lifecycle consequences ("does not kill the target"). */
  readonly description: string;
  readonly inputSchema: I;
  readonly outputSchema: O;
  readonly effects: ToolEffects;
  readonly gate?: GateDeclaration;
  /** Default true. false only for tools audited to never carry target-derived text. */
  readonly returnsTargetContent?: boolean;
  readonly cli: CliMapping;
  /** Default: ["live"] when the input has session_id, else ["none"]. */
  readonly sessionKinds?: readonly SessionKind[];
  /** Default { predicate: null, recorded: "never" }. */
  readonly evidence?: EvidencePolicy;
  /** Codes beyond the universal set this tool may return. Default []. */
  readonly errors?: readonly BeaErrorCode[];
  /** Hard per-call deadline; default 30000, max 120000. */
  readonly maxBlockingMs?: number;
  /**
   * CT-B3: serialized-argument ceiling enforced by invokeTool BEFORE parsing (invalid_request, reason out_of_range).
   * Default HARD_LIMITS.defaultToolInputBytes (1 MiB); max HARD_LIMITS.maxToolInputBytes (64 MiB − 64 KiB), so no
   * accepted input can exceed the stdio read buffer. Call-model tools set 48 MiB.
   */
  readonly maxInputBytes?: number;
  readonly examples: readonly ToolExample[];
}

/** The registered, derived contract: the single source for MCP, CLI, docs and tests. */
export interface ToolContract<
  N extends string = string,
  I extends ToolInputSchema = ToolInputSchema,
  O extends ToolOutputSchema = ToolOutputSchema,
> {
  readonly name: N;
  readonly area: ToolArea;
  readonly phase: ToolPhase;
  readonly title: string;
  readonly description: string;
  readonly inputSchema: I;
  readonly outputSchema: O;
  readonly effects: ToolEffects;
  readonly annotations: DerivedToolAnnotations;
  readonly gate: GateDeclaration | null;
  readonly returnsTargetContent: boolean;
  readonly cli: CliMapping;
  readonly sessionKinds: readonly SessionKind[];
  readonly evidence: EvidencePolicy;
  readonly errors: readonly BeaErrorCode[];
  readonly maxBlockingMs: number;
  readonly maxInputBytes: number;
  readonly examples: readonly ToolExample[];
}

export class ContractDefinitionError extends Error {
  override readonly name = "ContractDefinitionError";
}

const NAME_PATTERN = /^[a-z][a-z0-9_]{2,47}$/u;
const COMMAND_PATTERN = /^[a-z][a-z0-9-]{1,31}(?: [a-z][a-z0-9-]{1,31})?$/u;
const DEFAULT_BLOCKING_MS = 30_000;
const NO_EVIDENCE: EvidencePolicy = { predicate: null, recorded: "never" };

const titleCase = (name: string): string =>
  name
    .split("_")
    .map((word) => (word === "bea" ? "BEA" : `${word.charAt(0).toUpperCase()}${word.slice(1)}`))
    .join(" ");

export const isCommandTier = (cli: CliMapping): cli is Extract<CliMapping, { tier: CliCommandTier }> =>
  cli.tier === "oneshot" ||
  cli.tier === "session-oneshot" ||
  cli.tier === "instrument-oneshot" ||
  cli.tier === "emu-oneshot";

/**
 * Validate and derive. Throws ContractDefinitionError at module load: a broken
 * contract is a programmer error, caught by the first test that imports the registry.
 */
export const defineTool = <const N extends string, I extends ToolInputSchema, O extends ToolOutputSchema>(
  spec: ToolSpec<N, I, O>,
): ToolContract<N, I, O> => {
  const fail = (why: string): never => {
    throw new ContractDefinitionError(`${spec.name}: ${why}`);
  };
  if (!NAME_PATTERN.test(spec.name)) fail("name must match ^[a-z][a-z0-9_]{2,47}$");
  if (spec.description.length < 40 || spec.description.length > 600) fail("description must be 40-600 characters");
  if (!(spec.inputSchema instanceof z.ZodObject)) fail("inputSchema root must be a z.ZodObject");
  if (!(spec.outputSchema instanceof z.ZodObject)) fail("outputSchema root must be a z.ZodObject");
  const outShape = (spec.outputSchema as unknown as z.ZodObject).shape;
  for (const key of REQUIRED_ENVELOPE_KEYS)
    if (!(key in outShape))
      fail(`outputSchema must be built with recordedOutput/pollOutput (missing envelope key ${key})`);
  void ENVELOPE_RESERVED_KEYS;
  const shape = (spec.inputSchema as unknown as z.ZodObject).shape;
  const maxBlockingMs = spec.maxBlockingMs ?? DEFAULT_BLOCKING_MS;
  if (!Number.isInteger(maxBlockingMs) || maxBlockingMs < 1 || maxBlockingMs > HARD_LIMITS.maxToolCallMs)
    fail(`maxBlockingMs must be 1-${String(HARD_LIMITS.maxToolCallMs)}`);
  const maxInputBytes = spec.maxInputBytes ?? HARD_LIMITS.defaultToolInputBytes;
  if (!Number.isInteger(maxInputBytes) || maxInputBytes < 1024 || maxInputBytes > HARD_LIMITS.maxToolInputBytes)
    fail(`maxInputBytes must be 1024-${String(HARD_LIMITS.maxToolInputBytes)}`);
  if (spec.effects.writesTargetMemory && spec.gate === undefined)
    fail("writesTargetMemory requires a gate declaration");
  if (spec.effects.accessesNetwork) fail("accessesNetwork is not supported in v0.1");
  const cli = spec.cli;
  if (isCommandTier(cli)) {
    if (!COMMAND_PATTERN.test(cli.command)) fail("cli.command must be kebab-case (one or two words)");
    if ((RESERVED_COMMANDS as readonly string[]).includes(cli.command.split(" ")[0] ?? ""))
      fail(`cli.command ${cli.command} shadows a built-in`);
    if (cli.tier !== "oneshot" && !("session_id" in shape))
      fail(`cli tier ${cli.tier} requires a session_id input field`);
    if (cli.offlineField !== undefined && !(cli.offlineField in shape))
      fail(`cli.offlineField ${cli.offlineField} is not an input field`);
    for (const field of cli.fileFields ?? [])
      if (!(field in shape)) fail(`cli.fileFields entry ${field} is not an input field`);
  } else if (cli.reason.length < 10) fail("cli.reason must explain why the tool has no generated command");
  for (const example of spec.examples) {
    const parsed = spec.inputSchema.safeParse(example.input);
    if (!parsed.success) fail(`example "${example.title}" does not parse: ${parsed.error.message}`);
  }
  return Object.freeze({
    name: spec.name,
    area: spec.area,
    phase: spec.phase,
    title: spec.title ?? titleCase(spec.name),
    description: spec.description,
    inputSchema: spec.inputSchema,
    outputSchema: spec.outputSchema,
    effects: spec.effects,
    annotations: annotationsFromEffects(spec.effects),
    gate: spec.gate ?? null,
    returnsTargetContent: spec.returnsTargetContent ?? true,
    cli,
    sessionKinds: spec.sessionKinds ?? (("session_id" in shape ? ["live"] : ["none"]) as readonly SessionKind[]),
    evidence: spec.evidence ?? NO_EVIDENCE,
    errors: spec.errors ?? [],
    maxBlockingMs,
    maxInputBytes,
    examples: spec.examples,
  });
};

/** kebab-case CLI name for a tool name. @public */
export const kebab = (name: string): string => name.replaceAll("_", "-");
