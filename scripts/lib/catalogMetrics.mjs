// scripts/lib/catalogMetrics.mjs (WP0): the S6 §7.1 catalog measurement, shared by scripts/catalog-golden.mjs,
// scripts/generate.mjs (per-area goldens) and tests/contracts/catalogBudget.test.ts, so every consumer computes the
// same numbers from the same `tools/list` result.
import { createHash } from "node:crypto";

/** UTF-8 bytes of compact JSON. */
export const jsonBytes = (value) => Buffer.byteLength(JSON.stringify(value));

/** REA's schema depth metric (compactInputSchema.ts:47-61): nesting levels of objects/arrays below the root value. */
export const schemaDepth = (node, level = 0) =>
  node !== null && typeof node === "object"
    ? Math.max(level, ...Object.values(node).map((child) => schemaDepth(child, level + 1)))
    : level;

/** The part of a tool definition a model reads: name, title, description, inputSchema, annotations. */
export const modelVisible = (tool) => ({
  name: tool.name,
  title: tool.title,
  description: tool.description,
  inputSchema: tool.inputSchema,
  annotations: tool.annotations,
});

/** One row per advertised tool, in tools/list order. */
export const measureTool = (tool) => ({
  name: tool.name,
  description_chars: (tool.description ?? "").length,
  input_bytes: jsonBytes(tool.inputSchema),
  output_bytes: tool.outputSchema === undefined ? 0 : jsonBytes(tool.outputSchema),
  input_depth: schemaDepth(tool.inputSchema),
  output_depth: tool.outputSchema === undefined ? 0 : schemaDepth(tool.outputSchema),
  model_visible_bytes: jsonBytes(modelVisible(tool)),
  wire_bytes: jsonBytes(tool),
});

/** Totals in the shape of catalog-budget.json `measured`. */
export const measureCatalog = (tools) => {
  const rows = tools.map(measureTool);
  const sum = (key) => rows.reduce((total, row) => total + row[key], 0);
  return {
    rows,
    totals: {
      tools: rows.length,
      model_visible_bytes: sum("model_visible_bytes"),
      wire_bytes: jsonBytes({ tools }),
      input_bytes: sum("input_bytes"),
      output_bytes: sum("output_bytes"),
      description_chars: sum("description_chars"),
    },
  };
};

/** JSON with object keys sorted (UTF-16 order), so the digest ignores key order. */
export const sortedJson = (value) =>
  JSON.stringify(value, (_key, node) =>
    node !== null && typeof node === "object" && !Array.isArray(node)
      ? Object.fromEntries(
          Object.keys(node)
            .sort()
            .map((key) => [key, node[key]]),
        )
      : node,
  );

/** sha256 of the canonical tools/list JSON (`catalog_sha256` in the budget golden). */
export const catalogSha256 = (tools) => createHash("sha256").update(sortedJson({ tools })).digest("hex");

/** Ceiling violations of catalog-budget.json `ceilings` (D-INT-10). Empty when within budget. */
export const budgetViolations = (measured, budget) => {
  const { ceilings, tool_count: toolCount } = budget;
  const issues = [];
  if (measured.totals.tools > toolCount.max) issues.push(`tools ${measured.totals.tools} > ${toolCount.max}`);
  if (measured.totals.model_visible_bytes > ceilings.model_visible_bytes)
    issues.push(`model-visible bytes ${measured.totals.model_visible_bytes} > ${ceilings.model_visible_bytes}`);
  if (measured.totals.wire_bytes > ceilings.wire_bytes)
    issues.push(`wire tools/list bytes ${measured.totals.wire_bytes} > ${ceilings.wire_bytes}`);
  for (const row of measured.rows) {
    const inputCeiling = ceilings.per_tool_input_bytes_overrides?.[row.name] ?? ceilings.per_tool_input_bytes;
    if (row.input_bytes > inputCeiling) issues.push(`${row.name}: input schema ${row.input_bytes} B > ${inputCeiling}`);
    if (row.description_chars > ceilings.description_chars)
      issues.push(`${row.name}: description ${row.description_chars} chars > ${ceilings.description_chars}`);
    if (row.input_depth > ceilings.input_depth)
      issues.push(`${row.name}: input depth ${row.input_depth} > ${ceilings.input_depth}`);
  }
  return issues;
};

/** Measured totals that moved more than the tolerance from the golden (either direction). */
export const driftIssues = (measured, golden, tolerance) => {
  const issues = [];
  for (const [key, expected] of Object.entries(golden)) {
    const actual = measured.totals[key];
    if (typeof expected !== "number" || typeof actual !== "number") continue;
    const allowed = Math.abs(expected) * tolerance;
    if (Math.abs(actual - expected) > allowed)
      issues.push(`${key}: ${actual} vs golden ${expected} (±${tolerance * 100}%)`);
  }
  return issues;
};

/** A fixed-width per-tool table for failure messages and the catalog:golden report. */
export const formatTable = (rows) => {
  const header = "name                     desc  in_B  out_B  dIn dOut visible_B";
  const lines = rows.map(
    (row) =>
      `${row.name.padEnd(24)} ${String(row.description_chars).padStart(4)} ${String(row.input_bytes).padStart(5)} ` +
      `${String(row.output_bytes).padStart(6)} ${String(row.input_depth).padStart(4)} ${String(row.output_depth).padStart(4)} ` +
      `${String(row.model_visible_bytes).padStart(9)}`,
  );
  return [header, ...lines].join("\n");
};
