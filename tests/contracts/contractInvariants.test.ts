import { describe, expect, it } from "vitest";
import { z } from "zod";

import { deriveCommand, GLOBAL_FLAGS, targetFlagsFor } from "../../src/cli/argv.js";
import { annotationsFromEffects, EFFECT_FLAGS } from "../../src/contracts/effects.js";
import { TOOL_CONTRACTS } from "../../src/contracts/index.js";
import { isCommandTier, TOOL_AREAS } from "../../src/contracts/toolContract.js";
import { HARD_LIMITS } from "../../src/domain/config.js";
import { BEA_ERROR_TAGS } from "../../src/domain/errors/beaError.js";
import { withCleanup } from "../../src/domain/errors/constructors.js";
import { BEA_ERROR_CODES, ERROR_CATALOG } from "../../src/domain/errors/errorCatalog.js";
import { ERROR_SAMPLES } from "../../src/domain/errors/errorSamples.fixture.js";
import { beaErrorEnvelopeSchema, projectBeaError } from "../../src/domain/errors/projection.js";

const MAX_TOOLS = 40;
/** D-INT-10 (CI-B2): 4 KiB per tool, 12 KiB for the three call-model tools (matches catalog-budget.json). */
const MAX_INPUT_SCHEMA_BYTES_DEFAULT = 4 * 1024;
const MAX_INPUT_SCHEMA_BYTES_BY_TOOL: Readonly<Record<string, number>> = {
  call_function: 12 * 1024,
  emu_call: 12 * 1024,
  diff_function: 12 * 1024,
};
const MAX_OUTPUT_SCHEMA_BYTES = 16 * 1024;
const MAX_SCHEMA_DEPTH = 10;

const inputJson = (schema: z.ZodType) =>
  z.toJSONSchema(schema, { io: "input", target: "draft-2020-12", unrepresentable: "any" });
const outputJson = (schema: z.ZodType) =>
  z.toJSONSchema(schema, { io: "output", target: "draft-2020-12", unrepresentable: "any" });

const depth = (node: unknown): number =>
  typeof node !== "object" || node === null
    ? 0
    : 1 + Math.max(0, ...Object.values(node as Record<string, unknown>).map(depth));

/**
 * Every advertised INTEGER must carry both bounds (a bare int advertises +/-2^53). Doubles (`type:"number"`) are
 * exempt (CI-B1 option A: zod 4 z.number() already rejects NaN/Infinity, and bounds would cost ~70 B each).
 */
const unboundedIntegers = (node: unknown, path = "$"): string[] => {
  if (typeof node !== "object" || node === null) return [];
  const record = node as Record<string, unknown>;
  const own =
    record["type"] === "integer" &&
    ((record["minimum"] === undefined && record["exclusiveMinimum"] === undefined) ||
      (record["maximum"] === undefined && record["exclusiveMaximum"] === undefined))
      ? [path]
      : [];
  return [...own, ...Object.entries(record).flatMap(([key, value]) => unboundedIntegers(value, `${path}.${key}`))];
};

describe("tool catalog invariants", () => {
  it("has between 1 and 40 tools with unique names", () => {
    expect(TOOL_CONTRACTS.length).toBeGreaterThan(0);
    expect(TOOL_CONTRACTS.length).toBeLessThanOrEqual(MAX_TOOLS);
    expect(new Set(TOOL_CONTRACTS.map((c) => c.name)).size).toBe(TOOL_CONTRACTS.length);
  });

  it("audits every effect flag explicitly and derives annotations only from effects", () => {
    for (const contract of TOOL_CONTRACTS) {
      expect(Object.keys(contract.effects).sort(), contract.name).toEqual([...EFFECT_FLAGS].sort());
      expect(contract.annotations, contract.name).toEqual(annotationsFromEffects(contract.effects));
    }
  });

  it("gates every target-writing tool and keeps v0.1 local-only", () => {
    for (const contract of TOOL_CONTRACTS) {
      if (contract.effects.writesTargetMemory) {
        expect(contract.gate, contract.name).not.toBeNull();
        expect(contract.annotations.destructiveHint, contract.name).toBe(true);
      }
      expect(contract.effects.accessesNetwork, contract.name).toBe(false);
      expect(TOOL_AREAS, contract.name).toContain(contract.area);
    }
  });

  it("parses every example through the real input schema", () => {
    for (const contract of TOOL_CONTRACTS)
      for (const example of contract.examples)
        expect(contract.inputSchema.safeParse(example.input).success, `${contract.name}: ${example.title}`).toBe(true);
  });

  it("advertises flat, strict object roots within byte, depth and number-bound budgets", () => {
    for (const contract of TOOL_CONTRACTS) {
      const input = inputJson(contract.inputSchema) as Record<string, unknown>;
      const output = outputJson(contract.outputSchema) as Record<string, unknown>;
      expect(input["type"], contract.name).toBe("object");
      expect(input["additionalProperties"], contract.name).toBe(false);
      for (const key of ["anyOf", "oneOf", "allOf"]) expect(input[key], `${contract.name} root ${key}`).toBeUndefined();
      expect(JSON.stringify(input).length, contract.name).toBeLessThanOrEqual(
        MAX_INPUT_SCHEMA_BYTES_BY_TOOL[contract.name] ?? MAX_INPUT_SCHEMA_BYTES_DEFAULT,
      );
      expect(JSON.stringify(output).length, contract.name).toBeLessThanOrEqual(MAX_OUTPUT_SCHEMA_BYTES);
      expect(depth(input), contract.name).toBeLessThanOrEqual(MAX_SCHEMA_DEPTH);
      expect(unboundedIntegers(input), contract.name).toEqual([]);
    }
  });

  it("keeps every accepted input below the stdio read buffer (CT-B3)", () => {
    expect(HARD_LIMITS.maxToolInputBytes).toBeLessThanOrEqual(HARD_LIMITS.maxStdioRequestBytes - 64 * 1024);
    for (const contract of TOOL_CONTRACTS) {
      expect(contract.maxInputBytes, contract.name).toBeGreaterThanOrEqual(1024);
      expect(contract.maxInputBytes, contract.name).toBeLessThanOrEqual(HARD_LIMITS.maxToolInputBytes);
    }
  });

  it("maps every tool to exactly one CLI tier: a unique command or a reason, without flag collisions", () => {
    const commands = new Set<string>();
    for (const contract of TOOL_CONTRACTS) {
      const cli = contract.cli;
      if (!isCommandTier(cli)) {
        expect(cli.reason.length, contract.name).toBeGreaterThanOrEqual(10);
        continue;
      }
      expect(commands.has(cli.command), contract.name).toBe(false);
      commands.add(cli.command);
      const derived = deriveCommand(contract);
      expect(derived, contract.name).not.toBeNull();
      const reserved = [...GLOBAL_FLAGS, ...targetFlagsFor(cli.tier)];
      for (const option of derived?.options ?? [])
        expect(reserved.includes(option.flag), `${contract.name} --${option.flag}`).toBe(false);
      for (const positional of cli.positional)
        expect(
          positional === "pid" || derived?.options.some((o) => o.field === positional),
          `${contract.name} positional ${positional}`,
        ).toBe(true);
    }
  });
});

describe("error catalog invariants", () => {
  it("maps every tag, and uses every code except the projection-only cleanup_incomplete", () => {
    expect(Object.keys(ERROR_CATALOG).sort()).toEqual([...BEA_ERROR_TAGS].sort());
    const used = new Set<string>(Object.values(ERROR_CATALOG).map((spec) => spec.code));
    expect(BEA_ERROR_CODES.filter((code) => !used.has(code))).toEqual(["cleanup_incomplete"]);
  });

  it("projects a strict REA-shaped envelope with effects_applied for every tag", () => {
    for (const tag of BEA_ERROR_TAGS) {
      const projected = projectBeaError(ERROR_SAMPLES[tag]);
      expect(beaErrorEnvelopeSchema.safeParse({ error: projected }).success, tag).toBe(true);
      expect(projected.details["effects_applied"], tag).toEqual([]);
      expect(JSON.stringify(projected), tag).not.toContain("cause");
    }
  });

  it("overrides the code to cleanup_incomplete and keeps the original in details", () => {
    const error = withCleanup(ERROR_SAMPLES.ProviderFailure, {
      status: "incomplete",
      resources: ["recording rec_0000000b"],
      reason: "unhook failed",
    });
    const projected = projectBeaError({ ...error, effects_applied: ["fx_1"] });
    expect(projected.code).toBe("cleanup_incomplete");
    expect(projected.retryable).toBe(false);
    expect(projected.details).toMatchObject({
      execution_failure: "execution_failure",
      cleanup: "incomplete",
      effects_applied: ["fx_1"],
    });
  });
});
