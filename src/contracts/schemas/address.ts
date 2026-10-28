import { z } from "zod";

/**
 * AddrExpr (S2 §16.1 grammar + S6 §2.1 static form; DESIGN conflict C-01). ONE string accepted by every address
 * field, including nested positions. The full parser is src/domain/address/grammar.ts (WP-ADDR); the schema only
 * bounds the string so the advertised JSON Schema stays small (~170 B per field).
 */
export const ADDR_EXPR_SUMMARY =
  "0xVA | module+0xRVA | +0xRVA (main) | module!export[+0xN] | module!#ordinal | module:0xSTATIC_VA[/0xSTATIC_BASE] | $main:0xSTATIC_VA; quote names with + or spaces; module@0xBASE picks one of two same-named modules";

export const addrExprSchema = z.string().min(2).max(600).describe(ADDR_EXPR_SUMMARY);

/** Exactly-one-of helper for refines with a corrective message (rea-mcp §2.4). */
export const exactlyOne = (fields: readonly string[], example: string) => ({
  check: (v: Record<string, unknown>): boolean => fields.filter((f) => v[f] !== undefined).length === 1,
  message: `Provide exactly one of ${fields.join(" or ")}. Example: ${example}`,
});
