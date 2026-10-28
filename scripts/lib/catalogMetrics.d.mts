// Types for scripts/lib/catalogMetrics.mjs (imported by tests/contracts/catalogBudget.test.ts).

export interface AdvertisedTool {
  readonly name: string;
  readonly title?: string;
  readonly description?: string;
  readonly inputSchema: unknown;
  readonly outputSchema?: unknown;
  readonly annotations?: unknown;
  readonly [key: string]: unknown;
}

export interface ToolMeasure {
  readonly name: string;
  readonly description_chars: number;
  readonly input_bytes: number;
  readonly output_bytes: number;
  readonly input_depth: number;
  readonly output_depth: number;
  readonly model_visible_bytes: number;
  readonly wire_bytes: number;
}

export interface CatalogTotals {
  readonly tools: number;
  readonly model_visible_bytes: number;
  readonly wire_bytes: number;
  readonly input_bytes: number;
  readonly output_bytes: number;
  readonly description_chars: number;
}

export interface CatalogMeasure {
  readonly rows: readonly ToolMeasure[];
  readonly totals: CatalogTotals;
}

export interface CatalogBudget {
  readonly schema: "bea.catalog-budget/1";
  readonly note?: string;
  readonly tool_count: { readonly max: number; readonly expected_at_release: number };
  readonly ceilings: {
    readonly model_visible_bytes: number;
    readonly wire_bytes: number;
    readonly per_tool_input_bytes: number;
    readonly per_tool_input_bytes_overrides: Readonly<Record<string, number>>;
    readonly description_chars: number;
    readonly input_depth: number;
  };
  readonly measured: Readonly<Partial<CatalogTotals>> | null;
  readonly drift_tolerance: number;
  readonly catalog_sha256: string | null;
}

export declare const jsonBytes: (value: unknown) => number;
export declare const schemaDepth: (node: unknown, level?: number) => number;
export declare const modelVisible: (tool: AdvertisedTool) => Record<string, unknown>;
export declare const measureTool: (tool: AdvertisedTool) => ToolMeasure;
export declare const measureCatalog: (tools: readonly AdvertisedTool[]) => CatalogMeasure;
export declare const sortedJson: (value: unknown) => string;
export declare const catalogSha256: (tools: readonly AdvertisedTool[]) => string;
export declare const budgetViolations: (measured: CatalogMeasure, budget: CatalogBudget) => string[];
export declare const driftIssues: (
  measured: CatalogMeasure,
  golden: Readonly<Partial<CatalogTotals>>,
  tolerance: number,
) => string[];
export declare const formatTable: (rows: readonly ToolMeasure[]) => string;
