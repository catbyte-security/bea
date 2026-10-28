import type { StandardSchemaWithJSON } from "@modelcontextprotocol/server";

import type { ToolContract } from "../contracts/toolContract.js";

type Converter = StandardSchemaWithJSON["~standard"]["jsonSchema"]["input"];
type ConverterOptions = Parameters<Converter>[0];

/** The SDK reconverts every schema on each tools/list; contracts never change at runtime. */
const memoByTarget = (convert: Converter): Converter => {
  const byTarget = new Map<string, Record<string, unknown>>();
  return (options: ConverterOptions) => {
    if (options.libraryOptions !== undefined) return convert(options);
    const hit = byTarget.get(options.target);
    if (hit !== undefined) return hit;
    const projected = convert(options);
    byTarget.set(options.target, projected);
    return projected;
  };
};

/** Output schemas ship in every tools/list; their prose is dropped (BRIEF §1.11). */
const withoutDescriptions = (node: unknown): unknown => {
  if (Array.isArray(node)) return node.map(withoutDescriptions);
  if (typeof node !== "object" || node === null) return node;
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(node)) {
    if (key === "description") continue;
    // enum/const/default/examples hold literal data, not schemas: copy verbatim.
    out[key] =
      key === "enum" || key === "const" || key === "default" || key === "examples" ? value : withoutDescriptions(value);
  }
  return out;
};

const inputCache = new WeakMap<object, StandardSchemaWithJSON>();
const outputCache = new WeakMap<object, StandardSchemaWithJSON>();

/**
 * Pass-through validation (REA applicationToolRegistrationOptions): the SDK
 * accepts any arguments; invokeTool parses with the contract and returns the
 * canonical invalid_request error (VERIFIED: advertised schema unchanged).
 */
export const advertisedInputSchema = (contract: ToolContract): StandardSchemaWithJSON => {
  const cached = inputCache.get(contract.inputSchema);
  if (cached !== undefined) return cached;
  const standard = (contract.inputSchema as unknown as StandardSchemaWithJSON)["~standard"];
  const schema: StandardSchemaWithJSON = {
    "~standard": {
      ...standard,
      vendor: "bea",
      validate: (value: unknown) => ({ value }),
      jsonSchema: {
        input: memoByTarget((options) => standard.jsonSchema.input(options)),
        output: memoByTarget((options) => standard.jsonSchema.output(options)),
      },
    },
  };
  inputCache.set(contract.inputSchema, schema);
  return schema;
};

/**
 * Advertisement memoized, prose stripped. CT-M5: validation is pass-through as well, because invokeTool already
 * parsed the handler output with the contract (the self-check) and the SDK would otherwise validate it a second time.
 */
export const advertisedOutputSchema = (contract: ToolContract): StandardSchemaWithJSON => {
  const cached = outputCache.get(contract.outputSchema);
  if (cached !== undefined) return cached;
  const standard = (contract.outputSchema as unknown as StandardSchemaWithJSON)["~standard"];
  const schema: StandardSchemaWithJSON = {
    "~standard": {
      ...standard,
      vendor: "bea",
      validate: (value: unknown) => ({ value }),
      jsonSchema: {
        input: memoByTarget(
          (options) => withoutDescriptions(standard.jsonSchema.input(options)) as Record<string, unknown>,
        ),
        output: memoByTarget(
          (options) => withoutDescriptions(standard.jsonSchema.output(options)) as Record<string, unknown>,
        ),
      },
    },
  };
  outputCache.set(contract.outputSchema, schema);
  return schema;
};
