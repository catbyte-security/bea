// =================================================================================================
// src/agent/pure/corePe.ts — WP3-AGENT pure helpers: PE32+ facts from the MAPPED image in memory (S4 §8.1). The
// reader takes an RVA (mapped layout: offset = RVA) and returns the bytes or null when unreadable; every read is
// bounded. The loader rewrites only ImageBase, so these are in-memory facts; on-disk facts (preferred base, file
// sha256, long section names) are host-side [ext-frida §3.14].
// =================================================================================================
import { readLeBigint, readLeU16, readLeU32 } from "./coreHex.js";

export type RvaReader = (rva: number, len: number) => Uint8Array | null;

export const DATA_DIR = { export: 0, import: 1, exception: 3, debug: 6, tls: 9, delayImport: 13 } as const;
const PE32PLUS_MAGIC = 0x20b;
const IMAGE_DEBUG_TYPE_CODEVIEW = 2;
const UNW_FLAG_CHAININFO = 4;

export interface PeHeaders {
  readonly ntRva: number;
  readonly machine: number;
  readonly numberOfSections: number;
  readonly timeDateStamp: number;
  readonly entryRva: number;
  readonly imageBase: bigint;
  readonly sizeOfImage: number;
  readonly checksum: number;
  readonly subsystem: number;
  readonly dllCharacteristics: number;
  readonly dataDirs: readonly { readonly rva: number; readonly size: number }[];
  readonly sectionTableRva: number;
}

export type HeaderParse =
  | { readonly ok: true; readonly headers: PeHeaders }
  | { readonly ok: false; readonly reason: "unreadable" | "not-pe" | "not-pe32plus" };

export const parseHeaders = (read: RvaReader): HeaderParse => {
  const dos = read(0, 0x40);
  if (dos === null) return { ok: false, reason: "unreadable" };
  if (dos[0] !== 0x4d || dos[1] !== 0x5a) return { ok: false, reason: "not-pe" };
  const ntRva = readLeU32(dos, 0x3c);
  if (ntRva === 0 || ntRva > 0x10000) return { ok: false, reason: "not-pe" };
  const nt = read(ntRva, 0x18 + 0x70 + 16 * 8);
  if (nt === null) return { ok: false, reason: "unreadable" };
  if (readLeU32(nt, 0) !== 0x00004550) return { ok: false, reason: "not-pe" };
  const sizeOfOptionalHeader = readLeU16(nt, 0x14);
  const opt = 0x18;
  if (readLeU16(nt, opt) !== PE32PLUS_MAGIC) return { ok: false, reason: "not-pe32plus" };
  const count = Math.min(readLeU32(nt, opt + 0x6c), 16);
  const dataDirs: { rva: number; size: number }[] = [];
  for (let i = 0; i < count; i++)
    dataDirs.push({ rva: readLeU32(nt, opt + 0x70 + 8 * i), size: readLeU32(nt, opt + 0x74 + 8 * i) });
  return {
    ok: true,
    headers: {
      ntRva,
      machine: readLeU16(nt, 4),
      numberOfSections: readLeU16(nt, 6),
      timeDateStamp: readLeU32(nt, 8),
      entryRva: readLeU32(nt, opt + 0x10),
      imageBase: readLeBigint(nt, opt + 0x18, 8),
      sizeOfImage: readLeU32(nt, opt + 0x38),
      checksum: readLeU32(nt, opt + 0x40),
      subsystem: readLeU16(nt, opt + 0x44),
      dllCharacteristics: readLeU16(nt, opt + 0x46),
      dataDirs,
      sectionTableRva: ntRva + 0x18 + sizeOfOptionalHeader,
    },
  };
};

export const dataDir = (h: PeHeaders, index: number): { rva: number; size: number } | null => {
  const d = h.dataDirs[index];
  return d === undefined || d.rva === 0 || d.size === 0 ? null : d;
};

export interface SectionHeader {
  readonly rawName: string;
  readonly rva: number;
  readonly virtualSize: number;
  readonly characteristics: number;
}

/** Raw 8-byte names (gcc "/4" long names stay unresolved: the COFF string table is host-side). */
export const parseSections = (read: RvaReader, h: PeHeaders): SectionHeader[] => {
  const n = Math.min(h.numberOfSections, 96);
  const table = read(h.sectionTableRva, 40 * n);
  if (table === null) return [];
  const out: SectionHeader[] = [];
  for (let i = 0; i < n; i++) {
    const at = 40 * i;
    let rawName = "";
    for (let j = 0; j < 8; j++) {
      const c = table[at + j] ?? 0;
      if (c === 0) break;
      rawName += String.fromCharCode(c);
    }
    out.push({
      rawName,
      virtualSize: readLeU32(table, at + 8),
      rva: readLeU32(table, at + 0xc),
      characteristics: readLeU32(table, at + 0x24),
    });
  }
  return out;
};

export interface PdataTable {
  readonly begins: Uint32Array;
  readonly ends: Uint32Array;
  readonly unwinds: Uint32Array;
}

/** RUNTIME_FUNCTION[] (12 B each) from DataDirectory[3], sorted by begin (the loader requires it). */
export const parsePdata = (read: RvaReader, h: PeHeaders, maxEntries = 1 << 20): PdataTable => {
  const dir = dataDir(h, DATA_DIR.exception);
  const n = dir === null ? 0 : Math.min(Math.floor(dir.size / 12), maxEntries);
  const bytes = n === 0 || dir === null ? null : read(dir.rva, n * 12);
  const count = bytes === null ? 0 : n;
  const begins = new Uint32Array(count);
  const ends = new Uint32Array(count);
  const unwinds = new Uint32Array(count);
  for (let i = 0; i < count && bytes !== null; i++) {
    begins[i] = readLeU32(bytes, 12 * i);
    ends[i] = readLeU32(bytes, 12 * i + 4);
    unwinds[i] = readLeU32(bytes, 12 * i + 8);
  }
  return { begins, ends, unwinds };
};

/** UNWIND_INFO flags byte (byte 0 >> 3) has UNW_FLAG_CHAININFO. */
export const isChainedUnwind = (read: RvaReader, unwindRva: number): boolean => {
  const b = read(unwindRva, 1);
  return b !== null && (((b[0] ?? 0) >> 3) & UNW_FLAG_CHAININFO) !== 0;
};

const cString = (bytes: Uint8Array, off: number, max: number): string => {
  let out = "";
  for (let i = off; i < Math.min(bytes.length, off + max); i++) {
    const c = bytes[i] ?? 0;
    if (c === 0) break;
    out += String.fromCharCode(c);
  }
  return out;
};

/** A NUL-terminated ASCII string at an RVA (≤ max bytes, read in 64-byte chunks; partial when a chunk fails). */
export const readCString = (read: RvaReader, rva: number, max = 260): string | null => {
  let out = "";
  for (let off = 0; off < max; off += 64) {
    const b = read(rva + off, Math.min(64, max - off));
    if (b === null) return off === 0 ? null : out;
    for (const c of b) {
      if (c === 0) return out;
      out += String.fromCharCode(c);
    }
  }
  return out;
};

const hex2 = (b: number): string => b.toString(16).padStart(2, "0").toUpperCase();

/** GUID bytes (Data1 LE u32, Data2 LE u16, Data3 LE u16, Data4[8]) → "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX". */
export const guidText = (g: Uint8Array): string => {
  const d1 = readLeU32(g, 0).toString(16).padStart(8, "0").toUpperCase();
  const d2 = readLeU16(g, 4).toString(16).padStart(4, "0").toUpperCase();
  const d3 = readLeU16(g, 6).toString(16).padStart(4, "0").toUpperCase();
  const d4 = Array.from(g.slice(8, 10), hex2).join("");
  const d5 = Array.from(g.slice(10, 16), hex2).join("");
  return `${d1}-${d2}-${d3}-${d4}-${d5}`;
};

/** CodeView RSDS record from the debug directory (first CODEVIEW entry), or null. */
export const parseCodeView = (read: RvaReader, h: PeHeaders): { guid: string; age: number; pdb: string } | null => {
  const dir = dataDir(h, DATA_DIR.debug);
  if (dir === null) return null;
  const n = Math.min(Math.floor(dir.size / 28), 32);
  const entries = read(dir.rva, 28 * n);
  if (entries === null) return null;
  for (let i = 0; i < n; i++) {
    if (readLeU32(entries, 28 * i + 0xc) !== IMAGE_DEBUG_TYPE_CODEVIEW) continue;
    const rva = readLeU32(entries, 28 * i + 0x14);
    const head = rva === 0 ? null : read(rva, 24);
    if (head === null || cString(head, 0, 4) !== "RSDS") continue;
    return { guid: guidText(head.slice(4, 20)), age: readLeU32(head, 20), pdb: readCString(read, rva + 24, 260) ?? "" };
  }
  return null;
};

/** TLS callback VAs (IMAGE_TLS_DIRECTORY64.AddressOfCallBacks, ≤ 64, null-terminated); VAs inside the image only. */
export const parseTlsCallbacks = (read: RvaReader, h: PeHeaders, base: bigint): bigint[] => {
  const dir = dataDir(h, DATA_DIR.tls);
  const tls = dir === null ? null : read(dir.rva, 0x28);
  if (tls === null) return [];
  const arrayVa = readLeBigint(tls, 0x18, 8);
  if (arrayVa < base || arrayVa >= base + BigInt(h.sizeOfImage)) return [];
  const arr = read(Number(arrayVa - base), 8 * 64);
  if (arr === null) return [];
  const out: bigint[] = [];
  for (let i = 0; i < 64; i++) {
    const va = readLeBigint(arr, 8 * i, 8);
    if (va === 0n) break;
    out.push(va);
  }
  return out;
};

export interface DelayImportEntry {
  readonly dll: string;
  readonly name: string | null;
  readonly ordinal: number | null;
  readonly slotRva: number;
}

/** Delay-load imports (ImgDelayDescr, 32 B each). PE32+ images use the RVA form (Attributes bit 0); the obsolete VA
 *  form is skipped. */
export const parseDelayImports = (read: RvaReader, h: PeHeaders, maxEntries = 4096): DelayImportEntry[] => {
  const dir = dataDir(h, DATA_DIR.delayImport);
  if (dir === null) return [];
  const out: DelayImportEntry[] = [];
  const maxDescriptors = Math.min(Math.floor(dir.size / 32), 256);
  const descs = read(dir.rva, 32 * maxDescriptors);
  if (descs === null) return out;
  for (let d = 0; d < maxDescriptors && out.length < maxEntries; d++) {
    const nameRva = readLeU32(descs, 32 * d + 4);
    if (nameRva === 0) break;
    if ((readLeU32(descs, 32 * d) & 1) !== 1) continue;
    const dll = readCString(read, nameRva, 260) ?? "";
    const iatRva = readLeU32(descs, 32 * d + 0xc);
    const intRva = readLeU32(descs, 32 * d + 0x10);
    for (let i = 0; i < 4096 && out.length < maxEntries; i++) {
      const thunk = read(intRva + 8 * i, 8);
      if (thunk === null) break;
      const v = readLeBigint(thunk, 0, 8);
      if (v === 0n) break;
      const byOrdinal = v >> 63n === 1n;
      out.push({
        dll,
        name: byOrdinal ? null : readCString(read, Number(v & 0x7fffffffn) + 2, 256),
        ordinal: byOrdinal ? Number(v & 0xffffn) : null,
        slotRva: iatRva + 8 * i,
      });
    }
  }
  return out;
};
