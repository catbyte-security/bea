import type { FunctionTable, PeExport, PeImport } from "../../ports/pe.js";
import { DIR } from "./headers.js";
import { TableError, type ImageView } from "./view.js";

/**
 * Lazy PE tables (S2 §17.2 steps 6–13). Each parser is synchronous over an ImageView and never throws to its
 * caller: a malformed table yields what was read so far plus an issue (coverage `partial`, `malformed_pe_directory`
 * / `pe_table_cap`). Caps follow S2 §17.2. Ordinal-only imports stay ordinal-only (BEA never invents names).
 */
export interface TableIssue {
  readonly table: string;
  readonly reason: string;
}
export interface Parsed<T> {
  readonly value: T;
  readonly issues: readonly TableIssue[];
}

const MAX_EXPORTS = 1_000_000;
const MAX_NAME = 4096;
const MAX_IMPORT_DESCRIPTORS = 4096;
const MAX_THUNKS = 65_536;
/**
 * Review fix DATA-1: aggregate caps. Per-descriptor caps alone let ~1 MB of crafted descriptors that share one thunk
 * array (delay imports load fine: the loader resolves them lazily) produce 4096 × 65 536 rows per directory and kill
 * the server with a V8 heap OOM. All descriptors of both import directories share one row budget, repeated
 * (lookup, IAT) pairs are read once, and exports and imports share one name-byte budget.
 */
const MAX_IMPORT_ROWS = 1_048_576;
const MAX_NAME_BYTES = 64 * 1024 * 1024;
const MAX_PDATA = 10_000_000;
const MAX_UNWIND_DEPTH = 32;
const MAX_RELOCS = 20_000_000;
const MAX_TLS_CALLBACKS = 256;
const MAX_DEBUG_ENTRIES = 64;

const guarded = <T>(table: string, empty: T, parse: (issues: TableIssue[]) => T): Parsed<T> => {
  const issues: TableIssue[] = [];
  try {
    return { value: parse(issues), issues };
  } catch (thrown) {
    if (!(thrown instanceof TableError)) throw thrown;
    issues.push({ table, reason: thrown.message.slice(0, 120) });
    return { value: empty, issues };
  }
};

// ---------------------------------------------------------------- exports (dir 0)

/** One entry per exported NAME (aliases included) plus one per unnamed (NONAME) ordinal, like pefile. */
export const parseExports = (view: ImageView): Parsed<PeExport[]> =>
  guarded("exports", [], (issues) => {
    const dir = view.headers.dirs[DIR.export];
    if (dir === undefined || dir.rva === 0) return [];
    const e = dir.rva;
    const base = view.u32(e + 16);
    let nFunctions = view.u32(e + 20);
    let nNames = view.u32(e + 24);
    const aFunctions = view.u32(e + 28);
    const aNames = view.u32(e + 32);
    const aOrdinals = view.u32(e + 36);
    if (nFunctions > MAX_EXPORTS || nNames > MAX_EXPORTS) {
      issues.push({ table: "exports", reason: "entry cap reached" });
      nFunctions = Math.min(nFunctions, MAX_EXPORTS);
      nNames = Math.min(nNames, MAX_EXPORTS);
    }
    const target = (rva: number): { rva: number | null; forwarder: string | null } =>
      rva >= e && rva < e + dir.size ? { rva: null, forwarder: view.cstr(rva, MAX_NAME) } : { rva, forwarder: null };
    const out: PeExport[] = [];
    const named = new Set<number>();
    let nameBytes = MAX_NAME_BYTES;
    for (let i = 0; i < nNames; i++) {
      const index = view.u16(aOrdinals + i * 2);
      if (index >= nFunctions) continue;
      const rva = view.u32(aFunctions + index * 4);
      if (rva === 0) continue;
      if (nameBytes <= 0) {
        issues.push({ table: "exports", reason: "name bytes cap reached" });
        break;
      }
      const name = view.cstr(view.u32(aNames + i * 4), MAX_NAME);
      nameBytes -= name?.length ?? 0;
      named.add(index);
      out.push({ ordinal: base + index, name, ...target(rva) });
    }
    for (let index = 0; index < nFunctions; index++) {
      if (named.has(index)) continue;
      const rva = view.u32(aFunctions + index * 4);
      if (rva === 0) continue;
      out.push({ ordinal: base + index, name: null, ...target(rva) });
    }
    out.sort((a, b) => a.ordinal - b.ordinal || (a.name ?? "").localeCompare(b.name ?? ""));
    return out;
  });

// ---------------------------------------------------------------- imports (dir 1) + delay imports (dir 13)

/** The rows and name bytes a table parse may still produce (shared across descriptors and directories). */
interface TableBudget {
  rows: number;
  nameBytes: number;
  readonly seen: Set<string>;
}

const readThunks = (
  view: ImageView,
  issues: TableIssue[],
  budget: TableBudget,
  lookupRva: number,
  slotRva: number,
  dll: string,
  delay: boolean,
): PeImport[] => {
  const out: PeImport[] = [];
  const table = delay ? "delay_imports" : "imports";
  const from = lookupRva !== 0 ? lookupRva : slotRva;
  const key = `${String(from)}:${String(slotRva)}`;
  if (budget.seen.has(key)) {
    issues.push({ table, reason: "repeated import descriptor skipped" });
    return out;
  }
  budget.seen.add(key);
  for (let i = 0; i < MAX_THUNKS; i++) {
    const thunk = view.u64(from + i * 8);
    if (thunk === 0n) return out;
    if (budget.rows <= 0 || budget.nameBytes <= 0) {
      issues.push({ table, reason: "aggregate cap reached" });
      return out;
    }
    const byOrdinal = (thunk & (1n << 63n)) !== 0n;
    const name = byOrdinal ? null : view.cstr(Number(thunk & 0x7fff_ffffn) + 2, MAX_NAME);
    budget.rows -= 1;
    budget.nameBytes -= name?.length ?? 0;
    out.push({
      dll,
      name,
      ordinal: byOrdinal ? Number(thunk & 0xffffn) : null,
      slot_rva: slotRva + i * 8,
      delay,
    });
  }
  issues.push({ table, reason: "thunk cap reached" });
  return out;
};

export const parseImports = (view: ImageView): Parsed<PeImport[]> => {
  const budget: TableBudget = { rows: MAX_IMPORT_ROWS, nameBytes: MAX_NAME_BYTES, seen: new Set() };
  const regular = guarded<PeImport[]>("imports", [], (issues) => {
    const dir = view.headers.dirs[DIR.import];
    if (dir === undefined || dir.rva === 0) return [];
    const out: PeImport[] = [];
    for (let k = 0; k < MAX_IMPORT_DESCRIPTORS; k++) {
      const d = dir.rva + k * 20;
      const oft = view.u32(d);
      const tds = view.u32(d + 4);
      const chain = view.u32(d + 8);
      const nameRva = view.u32(d + 12);
      const ft = view.u32(d + 16);
      if (oft === 0 && tds === 0 && chain === 0 && nameRva === 0 && ft === 0) return out;
      const dll = view.cstr(nameRva, 256) ?? "";
      for (const row of readThunks(view, issues, budget, oft, ft, dll, false)) out.push(row);
    }
    issues.push({ table: "imports", reason: "descriptor cap reached" });
    return out;
  });
  const delayed = guarded<PeImport[]>("delay_imports", [], (issues) => {
    const dir = view.headers.dirs[DIR.delayImport];
    if (dir === undefined || dir.rva === 0) return [];
    const out: PeImport[] = [];
    const imageBase = view.headers.imageBase;
    for (let k = 0; k < MAX_IMPORT_DESCRIPTORS; k++) {
      const d = dir.rva + k * 32;
      const attributes = view.u32(d);
      const nameField = view.u32(d + 4);
      const iatField = view.u32(d + 12);
      const intField = view.u32(d + 16);
      if (nameField === 0 && iatField === 0) return out;
      // Attributes bit 0 clear: old-style descriptors hold VAs (subtract ImageBase)
      const rvaOf = (value: number): number => {
        if ((attributes & 1) !== 0 || value === 0) return value;
        const rva = BigInt(value) - imageBase;
        if (rva < 0n || rva >= 2n ** 32n) throw new TableError("old-style delay descriptor VA outside the image");
        return Number(rva);
      };
      const dll = view.cstr(rvaOf(nameField), 256) ?? "";
      for (const row of readThunks(view, issues, budget, rvaOf(intField), rvaOf(iatField), dll, true)) out.push(row);
    }
    issues.push({ table: "delay_imports", reason: "descriptor cap reached" });
    return out;
  });
  return { value: [...regular.value, ...delayed.value], issues: [...regular.issues, ...delayed.issues] };
};

// ---------------------------------------------------------------- .pdata (dir 3)

export interface PdataTable extends FunctionTable {
  /** primary (function-start) fragment end for a primary begin (size of the function's first fragment) */
  primaryEnd(primaryBegin: number): number | null;
  readonly indirect: number;
}

const EMPTY_PDATA: PdataTable = {
  count: 0,
  chained: 0,
  indirect: 0,
  lookup: () => null,
  entries: () => [],
  primaryEnd: () => null,
};

export const parsePdata = (view: ImageView): Parsed<PdataTable> =>
  guarded<PdataTable>("pdata", EMPTY_PDATA, (issues) => {
    const dir = view.headers.dirs[DIR.exception];
    if (dir === undefined || dir.rva === 0 || dir.size < 12) return EMPTY_PDATA;
    let n = Math.floor(dir.size / 12);
    if (n > MAX_PDATA) {
      issues.push({ table: "pdata", reason: "entry cap reached" });
      n = MAX_PDATA;
    }
    // review fix DATA-1: entries past the file-backed bytes are zero (begin = end = 0): a 1.5 KB file whose directory
    // covers 1 GiB of zero-fill must not allocate 10 M entries
    const backed = Math.floor(view.fileBackedPrefix(dir.rva, n * 12) / 12);
    if (backed < n) {
      issues.push({ table: "pdata", reason: "entries past the file-backed data ignored" });
      n = backed;
    }
    if (n === 0) return EMPTY_PDATA;
    const begin = new Uint32Array(n);
    const end = new Uint32Array(n);
    const unwind = new Uint32Array(n);
    const raw = view.bytes(dir.rva, n * 12);
    for (let i = 0; i < n; i++) {
      begin[i] = raw.readUInt32LE(i * 12);
      end[i] = raw.readUInt32LE(i * 12 + 4);
      unwind[i] = raw.readUInt32LE(i * 12 + 8);
    }
    let chained = 0;
    let indirect = 0;
    let deepChains = 0;
    const primary = new Uint32Array(n);
    // memo: unwind-info rva → primary begin
    const memo = new Map<number, number>();
    const primaryOf = (b: number, u: number): number => {
      let curBegin = b;
      let curUnwind = u;
      const seen: number[] = [];
      for (let depth = 0; depth <= MAX_UNWIND_DEPTH; depth++) {
        const cached = memo.get(curUnwind);
        if (cached !== undefined) {
          for (const s of seen) memo.set(s, cached);
          return cached;
        }
        seen.push(curUnwind);
        if ((curUnwind & 1) !== 0) {
          // RUNTIME_FUNCTION_INDIRECT: the field points at another RUNTIME_FUNCTION
          const r = curUnwind - 1;
          curBegin = view.u32(r);
          curUnwind = view.u32(r + 8);
          continue;
        }
        const head = view.u32(curUnwind);
        const flags = (head & 0xff) >>> 3;
        if ((flags & 4) === 0) {
          for (const s of seen) memo.set(s, curBegin);
          return curBegin;
        }
        const count = (head >>> 16) & 0xff;
        const r = curUnwind + 4 + 2 * ((count + 1) & ~1);
        curBegin = view.u32(r);
        curUnwind = view.u32(r + 8);
      }
      deepChains++;
      return b;
    };
    for (let i = 0; i < n; i++) {
      const b = begin[i] ?? 0;
      const u = unwind[i] ?? 0;
      if ((u & 1) !== 0) indirect++;
      else if (u !== 0 && ((view.u32(u) & 0xff) >>> 3) & 4) chained++;
      primary[i] = u === 0 ? b : primaryOf(b, u);
    }
    if (deepChains > 0) issues.push({ table: "pdata", reason: "unwind chain deeper than 32" });
    // binary search needs Begin order (linkers emit it sorted; sort defensively)
    let sorted = true;
    for (let i = 1; i < n; i++) if ((begin[i] ?? 0) < (begin[i - 1] ?? 0)) sorted = false;
    let order: Uint32Array | null = null;
    if (!sorted) {
      order = new Uint32Array(n);
      for (let i = 0; i < n; i++) order[i] = i;
      order.sort((a, b) => (begin[a] ?? 0) - (begin[b] ?? 0));
    }
    const at = (k: number): number => (order === null ? k : (order[k] ?? 0));
    const endByBegin = new Map<number, number>();
    for (let i = 0; i < n; i++) if (primary[i] === begin[i]) endByBegin.set(begin[i] ?? 0, end[i] ?? 0);
    return {
      count: n,
      chained,
      indirect,
      lookup: (rva) => {
        let lo = 0;
        let hi = n - 1;
        while (lo <= hi) {
          const mid = (lo + hi) >> 1;
          const i = at(mid);
          const b = begin[i] ?? 0;
          if (rva < b) hi = mid - 1;
          else if (rva >= (end[i] ?? 0)) lo = mid + 1;
          else {
            const p = primary[i] ?? b;
            return { begin: b, end: end[i] ?? 0, primary_begin: p, fragment: p !== b };
          }
        }
        return null;
      },
      entries: function* () {
        for (let k = 0; k < n; k++) {
          const i = at(k);
          yield { begin: begin[i] ?? 0, end: end[i] ?? 0, primary_begin: primary[i] ?? 0 };
        }
      },
      primaryEnd: (primaryBegin) => endByBegin.get(primaryBegin) ?? null,
    };
  });

// ---------------------------------------------------------------- relocations (dir 5)

export const parseRelocations = (view: ImageView): Parsed<{ readonly slots: Uint32Array; readonly other: number }> =>
  guarded("relocations", { slots: new Uint32Array(0), other: 0 }, (issues) => {
    const dir = view.headers.dirs[DIR.basereloc];
    if (dir === undefined || dir.rva === 0) return { slots: new Uint32Array(0), other: 0 };
    const raw = view.bytes(dir.rva, dir.size);
    const slots: number[] = [];
    let other = 0;
    let p = 0;
    while (p + 8 <= raw.length) {
      const page = raw.readUInt32LE(p);
      const blockSize = raw.readUInt32LE(p + 4);
      if (blockSize < 8 || p + blockSize > raw.length) {
        if (!(blockSize === 0 && page === 0)) issues.push({ table: "relocations", reason: "malformed block" });
        break;
      }
      for (let k = 8; k + 2 <= blockSize; k += 2) {
        const entry = raw.readUInt16LE(p + k);
        const type = entry >>> 12;
        if (type === 10) {
          if (slots.length >= MAX_RELOCS) {
            issues.push({ table: "relocations", reason: "entry cap reached" });
            break;
          }
          slots.push(page + (entry & 0xfff));
        } else if (type !== 0) other++;
      }
      p += blockSize;
    }
    const out = Uint32Array.from(slots);
    out.sort();
    return { slots: out, other };
  });

// ---------------------------------------------------------------- debug (dir 6), TLS (dir 9), load config (dir 10)

export interface DebugEntry {
  readonly type: number;
  readonly sizeOfData: number;
  readonly pointerToRawData: number;
}

export const parseDebugDirectory = (view: ImageView): Parsed<DebugEntry[]> =>
  guarded<DebugEntry[]>("debug", [], () => {
    const dir = view.headers.dirs[DIR.debug];
    if (dir === undefined || dir.rva === 0) return [];
    const out: DebugEntry[] = [];
    const n = Math.min(Math.floor(dir.size / 28), MAX_DEBUG_ENTRIES);
    for (let i = 0; i < n; i++) {
      const d = dir.rva + i * 28;
      out.push({ type: view.u32(d + 12), sizeOfData: view.u32(d + 16), pointerToRawData: view.u32(d + 24) });
    }
    return out;
  });

/** CodeView RSDS record → {guid (upper-case 8-4-4-4-12), age, pdb_path}. */
export const parseCodeView = (raw: Buffer): { guid: string; age: number; pdb_path: string } | null => {
  if (raw.length < 24 || raw.toString("latin1", 0, 4) !== "RSDS") return null;
  const g = raw.subarray(4, 20);
  const guid = [
    g.readUInt32LE(0).toString(16).padStart(8, "0"),
    g.readUInt16LE(4).toString(16).padStart(4, "0"),
    g.readUInt16LE(6).toString(16).padStart(4, "0"),
    g.subarray(8, 10).toString("hex"),
    g.subarray(10, 16).toString("hex"),
  ]
    .join("-")
    .toUpperCase();
  const zero = raw.indexOf(0, 24);
  return { guid, age: raw.readUInt32LE(20), pdb_path: raw.toString("utf8", 24, zero === -1 ? raw.length : zero) };
};

export const parseTlsCallbacks = (view: ImageView): Parsed<number[]> =>
  guarded<number[]>("tls", [], (issues) => {
    const dir = view.headers.dirs[DIR.tls];
    if (dir === undefined || dir.rva === 0) return [];
    const imageBase = view.headers.imageBase;
    const callbacksVa = view.u64(dir.rva + 24);
    if (callbacksVa === 0n) return [];
    const arrayRva = callbacksVa - imageBase;
    if (arrayRva < 0n || arrayRva >= BigInt(view.headers.sizeOfImage))
      throw new TableError("AddressOfCallBacks outside the image");
    const out: number[] = [];
    for (let i = 0; i < MAX_TLS_CALLBACKS; i++) {
      const va = view.u64(Number(arrayRva) + i * 8);
      if (va === 0n) return out;
      const rva = va - imageBase;
      if (rva < 0n || rva >= BigInt(view.headers.sizeOfImage))
        throw new TableError("a TLS callback is outside the image");
      out.push(Number(rva));
    }
    issues.push({ table: "tls", reason: "callback cap reached" });
    return out;
  });

/** GuardCFCheckFunctionPointer (+0x70) / GuardCFDispatchFunctionPointer (+0x78) slot rvas (A20). */
export const parseCfgSlots = (view: ImageView): Parsed<number[]> =>
  guarded<number[]>("load_config", [], () => {
    const dir = view.headers.dirs[DIR.loadConfig];
    if (dir === undefined || dir.rva === 0) return [];
    const size = view.u32(dir.rva);
    const out: number[] = [];
    for (const field of [0x70, 0x78]) {
      if (size < field + 8) continue;
      const va = view.u64(dir.rva + field);
      if (va === 0n) continue;
      const rva = va - view.headers.imageBase;
      if (rva >= 0n && rva + 8n <= BigInt(view.headers.sizeOfImage)) out.push(Number(rva));
    }
    return out;
  });
