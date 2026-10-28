import { z } from "zod";

import { hexSchema } from "../hex.js";
import { evIdSchema, mmIdSchema, sha256Schema } from "../ids.js";

/**
 * Address OUTPUT forms (S2 §16.4–16.5 + S6 §2.2; DESIGN conflict C-03):
 * - single-address results use AddressRef (every form, module-map id, symbol);
 * - rows / hits / frames / summaries use the compact Addr/Loc strings plus a `modules` legend.
 * Every `at` / `static` string parses back as an AddrExpr input (round-trip unit test).
 */
export const STATIC_BASE_SOURCES = ["pe-header", "caller", "rea-evidence", "emulation"] as const;

export const symbolSchema = z.strictObject({
  name: z.string().max(1024).nullable(), // null for .pdata-only functions (no fabricated names)
  kind: z.enum(["export", "caller", "import-slot", "function", "debug-hint"]),
  offset: hexSchema, // address − symbol start
  source: z.enum(["pe-export", "pe-pdata", "pe-import", "caller-table", "dbghelp"]),
  function_start: hexSchema.exactOptional(), // rva of the primary .pdata entry (unwind chains resolved)
  function_end: hexSchema.exactOptional(),
  fragment: z.boolean().exactOptional(),
  forwarded_from: z.string().max(600).exactOptional(),
  evidence_id: evIdSchema.exactOptional(), // caller-table names: the bea.symbols.caller record
});

export const addressRefSchema = z.strictObject({
  va: hexSchema,
  module: z.string().max(260).nullable(), // display basename (loader casing); untrusted text
  rva: hexSchema.nullable(),
  static_va: hexSchema.nullable(),
  static_base: hexSchema.nullable(),
  static_base_source: z.enum(STATIC_BASE_SOURCES).nullable(),
  module_map_id: mmIdSchema.nullable(), // null: emulation (non-dump) or pure-arithmetic mode
  image_sha256: sha256Schema.nullable().exactOptional(), // omitted when not computed; null = could not hash
  symbol: symbolSchema.exactOptional(),
  section: z.string().max(16).exactOptional(),
});
export type AddressRef = z.infer<typeof addressRefSchema>;

/** "module+0xrva" | "module@0xbase+0xrva" (ambiguous basename) | "0x<va>" (non-module). @public */
export type AddressText = string;

/** Compact data address (S6 §2.2): va + module-relative + static text ("game.exe:0x1401234ab"). */
export const addrSchema = z.strictObject({
  va: hexSchema,
  at: z.string().max(600).nullable(),
  static: z.string().max(600).nullable(),
});
/** Compact code address: adds the enclosing .pdata function start and an exact-export symbol. */
export const locSchema = z.strictObject({
  va: hexSchema,
  at: z.string().max(600).nullable(),
  static: z.string().max(600).nullable(),
  func: z.string().max(600).nullable(),
  sym: z.string().max(1100).nullable(),
});
export type Addr = z.infer<typeof addrSchema>;
export type Loc = z.infer<typeof locSchema>;

/** @public */
export const moduleLegendSchema = z.record(
  z.string().max(300),
  z.strictObject({
    base: hexSchema,
    size: z.number().int(),
    static_base: hexSchema,
    static_base_source: z.enum(STATIC_BASE_SOURCES),
    image_sha256: sha256Schema.nullable().exactOptional(),
    module_map_id: mmIdSchema.nullable(),
  }),
);
