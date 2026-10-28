import type { z } from "zod";

import type { symbolSchema } from "./addressRef.js";
import { formatHex } from "../hex.js";
import type { EvId } from "../ids.js";

/**
 * Symbolization policy (S2 §19.1; first hit wins): caller table > exact or function-start export > import slot >
 * `.pdata` bounds. Never "nearest preceding export" (dbghelp named a static function after the wrong export,
 * [ext-frida §3.12]); `.pdata`-only functions get `name:null`, never a fabricated `sub_XXXX`. Pure.
 */
export type SymbolInfo = z.infer<typeof symbolSchema>;

export interface CallerSymbol {
  readonly rva: number;
  readonly name: string;
  readonly size: number | null;
  readonly evidence_id: EvId | null;
}

export interface FunctionBounds {
  /** fragment containing the address */
  readonly begin: number;
  readonly end: number;
  /** primary entry (unwind chains followed): the function start */
  readonly primary_begin: number;
  readonly fragment: boolean;
}

export interface ExportEntry {
  readonly rva: number;
  readonly name: string;
  /** data exports match only exactly */
  readonly code: boolean;
}

export interface ImportSlot {
  readonly slot_rva: number;
  readonly dll: string;
  readonly name: string | null;
  readonly ordinal: number | null;
}

export interface SymbolSources {
  /** sorted by rva (later registrations already override earlier ones at the same rva) */
  readonly caller: readonly CallerSymbol[];
  /** export name by rva (first name in ordinal order wins for aliases) */
  readonly exportAt: (rva: number) => ExportEntry | null;
  /** import slot containing rva */
  readonly importAt: (rva: number) => ImportSlot | null;
  /** `.pdata` fragment containing rva (unwind chains resolved) */
  readonly functionAt: (rva: number) => FunctionBounds | null;
  /** export forwarded to this address (resolution through a forwarder) */
  readonly forwardedFrom?: string;
}

const hex = (n: number) => formatHex(n);
const CALLER_SCAN = 64;

const functionFields = (fn: FunctionBounds) => ({
  function_start: hex(fn.primary_begin),
  function_end: hex(fn.end),
  fragment: fn.fragment,
});

/** Binary search: last caller entry with rva ≤ x. */
const callerFloor = (table: readonly CallerSymbol[], x: number): number => {
  let lo = 0;
  let hi = table.length - 1;
  let found = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const entry = table[mid];
    if (entry === undefined) break;
    if (entry.rva <= x) {
      found = mid;
      lo = mid + 1;
    } else hi = mid - 1;
  }
  return found;
};

const callerMatch = (table: readonly CallerSymbol[], x: number, fn: FunctionBounds | null): CallerSymbol | null => {
  if (table.length === 0) return null;
  // exact, or a sized range containing x: the nearest entries at or below x (bounded scan; nested ranges are rare)
  for (let i = callerFloor(table, x), steps = 0; i >= 0 && steps < CALLER_SCAN; i--, steps++) {
    const entry = table[i];
    if (entry === undefined) break;
    if (entry.rva === x) return entry;
    if (entry.size !== null && x < entry.rva + entry.size) return entry;
  }
  if (fn !== null) {
    const start = table[callerFloor(table, fn.primary_begin)];
    if (start !== undefined && start.rva === fn.primary_begin) return start;
  }
  return null;
};

/** S2 §19.1 for one module-relative address. */
export const symbolize = (x: number, sources: SymbolSources): SymbolInfo | null => {
  const fn = sources.functionAt(x);
  const caller = callerMatch(sources.caller, x, fn);
  if (caller !== null)
    return {
      name: caller.name,
      kind: "caller",
      source: "caller-table",
      offset: hex(x - caller.rva),
      ...(fn !== null && fn.primary_begin === caller.rva ? functionFields(fn) : {}),
      ...(caller.evidence_id === null ? {} : { evidence_id: caller.evidence_id }),
    };
  const exact = sources.exportAt(x);
  if (exact !== null)
    return {
      name: exact.name,
      kind: "export",
      source: "pe-export",
      offset: "0x0",
      ...(fn !== null && fn.primary_begin === x ? functionFields(fn) : {}),
      ...(sources.forwardedFrom === undefined ? {} : { forwarded_from: sources.forwardedFrom }),
    };
  if (fn !== null) {
    const start = sources.exportAt(fn.primary_begin);
    if (start !== null && start.code)
      return {
        name: start.name,
        kind: "export",
        source: "pe-export",
        offset: hex(x - fn.primary_begin),
        ...functionFields(fn),
      };
  }
  const slot = sources.importAt(x);
  if (slot !== null)
    return {
      name: `${slot.dll}!${slot.name ?? `#${String(slot.ordinal ?? 0)}`}`,
      kind: "import-slot",
      source: "pe-import",
      offset: hex(x - slot.slot_rva),
    };
  if (fn !== null)
    return {
      name: null,
      kind: "function",
      source: "pe-pdata",
      offset: hex(x - fn.primary_begin),
      ...functionFields(fn),
    };
  return null;
};
