import type { PeSection } from "../../ports/pe.js";
import { peFailure, PeFailure } from "./errors.js";
import type { FileReader } from "./fileAccess.js";

/**
 * PE32+ headers and the rva → file layout (S2 §17.2 steps 1–5). Only an invalid header is a PeFailure; tables
 * are parsed lazily elsewhere and degrade to `issues`.
 */
export const DIR = {
  export: 0,
  import: 1,
  exception: 3,
  security: 4,
  basereloc: 5,
  debug: 6,
  tls: 9,
  loadConfig: 10,
  iat: 12,
  delayImport: 13,
  clr: 14,
} as const;

interface DataDirectory {
  readonly rva: number;
  readonly size: number;
}

export interface PeHeaders {
  readonly fileSize: number;
  readonly machine: number;
  readonly timeDateStamp: number;
  readonly characteristics: number;
  readonly entryRva: number;
  readonly imageBase: bigint;
  readonly sizeOfImage: number;
  readonly sizeOfHeaders: number;
  readonly subsystem: number;
  readonly dllCharacteristics: number;
  readonly dirs: readonly DataDirectory[];
  readonly sections: readonly PeSection[];
  /** file offset of OptionalHeader.ImageBase (the loader rewrites it in memory) */
  readonly imageBaseFieldOffset: number;
  readonly issues: readonly { readonly table: string; readonly reason: string }[];
}

const MAX_SECTIONS = 96;
const MAX_STRING_TABLE = 1024 * 1024;
const SCN_MEM_EXECUTE = 0x2000_0000;
const SCN_MEM_READ = 0x4000_0000;
const SCN_MEM_WRITE = 0x8000_0000;

const permsOf = (characteristics: number): PeSection["perms"] =>
  `${characteristics & SCN_MEM_READ ? "r" : "-"}${(characteristics & SCN_MEM_WRITE) !== 0 ? "w" : "-"}${
    characteristics & SCN_MEM_EXECUTE ? "x" : "-"
  }` as PeSection["perms"];

const cString = (buf: Buffer, start: number, end: number): string => {
  const zero = buf.indexOf(0, start);
  return buf.toString("utf8", start, zero === -1 || zero > end ? end : zero);
};

export const parseHeaders = async (reader: FileReader): Promise<PeHeaders> => {
  const size = reader.size;
  if (size < 0x40) throw peFailure("not_pe", "The file is too small to be a PE image.");
  const dos = await reader.readAt(0, 0x40);
  if (dos.readUInt16LE(0) !== 0x5a4d) throw peFailure("not_pe", "Missing the MZ signature.", "e_magic");
  const lfanew = dos.readUInt32LE(0x3c);
  if (lfanew < 0x40 || lfanew > size - 24) throw peFailure("not_pe", "e_lfanew points outside the file.", "e_lfanew");
  const nt = await reader.readAt(lfanew, 24);
  if (nt.readUInt32LE(0) !== 0x0000_4550) throw peFailure("not_pe", "Missing the PE signature.", "signature");
  const machine = nt.readUInt16LE(4);
  const numberOfSections = nt.readUInt16LE(6);
  const timeDateStamp = nt.readUInt32LE(8);
  const pointerToSymbolTable = nt.readUInt32LE(12);
  const numberOfSymbols = nt.readUInt32LE(16);
  const sizeOfOptionalHeader = nt.readUInt16LE(20);
  const characteristics = nt.readUInt16LE(22);
  if (numberOfSections > MAX_SECTIONS) throw peFailure("malformed", "More than 96 sections.", "NumberOfSections");
  const optOffset = lfanew + 24;
  if (sizeOfOptionalHeader < 2 || optOffset + sizeOfOptionalHeader > size)
    throw peFailure("malformed", "The optional header is truncated.", "SizeOfOptionalHeader");
  const opt = await reader.readAt(optOffset, sizeOfOptionalHeader);
  const magic = opt.readUInt16LE(0);
  if (magic === 0x10b)
    throw new PeFailure({ kind: "unsupported_format", detail: "PE32 (32-bit) image.", field: "Magic" }, true);
  if (magic !== 0x20b) throw peFailure("unsupported_format", "Unknown optional header magic.", "Magic");
  if (sizeOfOptionalHeader < 112)
    throw peFailure("malformed", "The PE32+ optional header is truncated.", "SizeOfOptionalHeader");
  const entryRva = opt.readUInt32LE(16);
  const imageBase = opt.readBigUInt64LE(24);
  const sizeOfImage = opt.readUInt32LE(56);
  const sizeOfHeaders = opt.readUInt32LE(60);
  const subsystem = opt.readUInt16LE(68);
  const dllCharacteristics = opt.readUInt16LE(70);
  const numberOfRvaAndSizes = opt.readUInt32LE(108);
  if (sizeOfImage === 0) throw peFailure("malformed", "SizeOfImage is zero.", "SizeOfImage");
  const issues: { table: string; reason: string }[] = [];
  const dirs: DataDirectory[] = [];
  const dirCount = Math.min(numberOfRvaAndSizes, 16, Math.floor((sizeOfOptionalHeader - 112) / 8));
  for (let i = 0; i < 16; i++) {
    if (i >= dirCount) {
      dirs.push({ rva: 0, size: 0 });
      continue;
    }
    const rva = opt.readUInt32LE(112 + i * 8);
    const dirSize = opt.readUInt32LE(116 + i * 8);
    // security (4) holds a FILE offset, not an rva
    if (i !== DIR.security && rva !== 0 && (rva >= sizeOfImage || dirSize > sizeOfImage)) {
      issues.push({ table: `directory_${String(i)}`, reason: "outside the image" });
      dirs.push({ rva: 0, size: 0 });
    } else dirs.push({ rva, size: dirSize });
  }
  const sectionOffset = optOffset + sizeOfOptionalHeader;
  if (sectionOffset + numberOfSections * 40 > size)
    throw peFailure("malformed", "The section table is truncated.", "NumberOfSections");
  const table = numberOfSections === 0 ? Buffer.alloc(0) : await reader.readAt(sectionOffset, numberOfSections * 40);
  let strings: Buffer | null = null;
  const needsStrings = Array.from({ length: numberOfSections }, (_, i) => table[i * 40] === 0x2f).some(Boolean);
  if (needsStrings && pointerToSymbolTable !== 0) {
    const strOffset = pointerToSymbolTable + numberOfSymbols * 18;
    if (strOffset + 4 <= size) {
      const declared = (await reader.readAt(strOffset, 4)).readUInt32LE(0);
      const len = Math.min(declared, MAX_STRING_TABLE, size - strOffset);
      strings = len > 4 ? await reader.readAt(strOffset, len) : null;
    }
  }
  const sections: PeSection[] = [];
  for (let i = 0; i < numberOfSections; i++) {
    const s = table.subarray(i * 40, i * 40 + 40);
    const shortName = cString(s, 0, 8);
    let name = shortName;
    const long = /^\/(\d+)$/u.exec(shortName);
    if (long !== null) {
      const at = Number(long[1]);
      if (strings !== null && at >= 4 && at < strings.length) name = cString(strings, at, strings.length);
      else issues.push({ table: "sections", reason: "unresolved long section name" });
    }
    const sectionCharacteristics = s.readUInt32LE(36);
    let rawOffset = s.readUInt32LE(20);
    let rawSize = s.readUInt32LE(16);
    if (rawSize === 0) {
      // review fix DATA-8: no raw data (a pure BSS section): the loader ignores PointerToRawData, and so does BEA
      rawOffset = 0;
    } else if (rawOffset >= size) {
      issues.push({ table: "sections", reason: "raw data outside the file" });
      rawOffset = 0;
      rawSize = 0;
    } else if (rawOffset + rawSize > size) {
      issues.push({ table: "sections", reason: "raw data truncated by the end of the file" });
      rawSize = Math.max(0, size - rawOffset);
    }
    sections.push({
      name,
      short_name: shortName,
      rva: s.readUInt32LE(12),
      virtual_size: s.readUInt32LE(8),
      raw_offset: rawOffset,
      raw_size: rawSize,
      characteristics: sectionCharacteristics,
      perms: permsOf(sectionCharacteristics),
    });
  }
  return {
    fileSize: size,
    machine,
    timeDateStamp,
    characteristics,
    entryRva,
    imageBase,
    sizeOfImage,
    sizeOfHeaders,
    subsystem,
    dllCharacteristics,
    dirs,
    sections,
    imageBaseFieldOffset: optOffset + 24,
    issues,
  };
};

/** Where an rva lives: a file offset run, zero-fill inside the image, or outside every mapped part. */
export type RvaLocation =
  | { readonly kind: "file"; readonly offset: number; readonly run: number; readonly segment: number }
  | { readonly kind: "zero"; readonly run: number }
  | { readonly kind: "outside" };

/** Segment -1 = the headers; segment i = section i's raw data. */
export const locateRva = (h: PeHeaders, rva: number): RvaLocation => {
  if (rva < 0 || rva >= 2 ** 32) return { kind: "outside" };
  const headerLen = Math.min(h.sizeOfHeaders, h.fileSize);
  if (rva < h.sizeOfHeaders) {
    if (rva < headerLen) return { kind: "file", offset: rva, run: headerLen - rva, segment: -1 };
    return { kind: "zero", run: h.sizeOfHeaders - rva };
  }
  for (let i = 0; i < h.sections.length; i++) {
    const s = h.sections[i];
    if (s === undefined) continue;
    const span = Math.max(s.virtual_size, s.raw_size);
    if (rva < s.rva || rva >= s.rva + span) continue;
    const delta = rva - s.rva;
    if (delta < s.raw_size) return { kind: "file", offset: s.raw_offset + delta, run: s.raw_size - delta, segment: i };
    return { kind: "zero", run: span - delta };
  }
  return { kind: "outside" };
};

/** The section containing rva (by max(VirtualSize, SizeOfRawData)), or null. */
export const sectionIndexOf = (h: PeHeaders, rva: number): number => {
  for (let i = 0; i < h.sections.length; i++) {
    const s = h.sections[i];
    if (s !== undefined && rva >= s.rva && rva < s.rva + Math.max(s.virtual_size, s.raw_size)) return i;
  }
  return -1;
};

/** File range of a segment (headers or a section's raw data). */
export const segmentRange = (h: PeHeaders, segment: number): { readonly offset: number; readonly length: number } => {
  if (segment === -1) return { offset: 0, length: Math.min(h.sizeOfHeaders, h.fileSize) };
  const s = h.sections[segment];
  return s === undefined ? { offset: 0, length: 0 } : { offset: s.raw_offset, length: s.raw_size };
};
