import { readFileSync } from "node:fs";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  budgetViolations,
  catalogSha256,
  driftIssues,
  formatTable,
  measureCatalog,
  type AdvertisedTool,
  type CatalogBudget,
  type CatalogMeasure,
} from "../../scripts/lib/catalogMetrics.mjs";
import { TOOL_CONTRACTS } from "../../src/contracts/index.js";
import { connectInMemoryBea, type InMemoryBea } from "../support/mcp/inMemory.js";

/**
 * S6 §7.2 over the production createMcpServer with fake services (DESIGN §8.3, D-INT-10): the advertised catalog stays
 * within the ceilings of tests/contracts/catalog-budget.json, and — once `npm run catalog:golden` has recorded
 * `measured` (WP18) — within ±2% of it with an unchanged catalog_sha256. The same metric code as catalog-golden.mjs.
 */
const budget = JSON.parse(readFileSync(new URL("./catalog-budget.json", import.meta.url), "utf8")) as CatalogBudget;

let bea: InMemoryBea;
let tools: readonly AdvertisedTool[];
let measured: CatalogMeasure;

beforeAll(async () => {
  bea = await connectInMemoryBea();
  tools = (await bea.client.listTools()).tools as unknown as readonly AdvertisedTool[];
  measured = measureCatalog(tools);
});
afterAll(async () => {
  await bea.close();
});

describe("catalog budget (S6 §7.2, D-INT-10)", () => {
  it("advertises every contract, in registry order", () => {
    expect(tools.map((tool) => tool.name)).toEqual(TOOL_CONTRACTS.map((contract) => contract.name));
  });

  it("stays within every ceiling", () => {
    const issues = budgetViolations(measured, budget);
    expect(issues, `${issues.join("\n")}\n${formatTable(measured.rows)}`).toEqual([]);
  });

  it("matches the measured golden within the drift tolerance (inactive while measured is null, until npm run catalog:golden)", () => {
    if (budget.measured === null) {
      expect(budget.catalog_sha256).toBeNull();
      return;
    }
    const drift = driftIssues(measured, budget.measured, budget.drift_tolerance);
    expect(
      drift,
      `${drift.join("\n")}\nrun npm run catalog:golden and commit the result\n${formatTable(measured.rows)}`,
    ).toEqual([]);
    expect(catalogSha256(tools), "the catalog changed: run npm run catalog:golden").toBe(budget.catalog_sha256);
  });
});
