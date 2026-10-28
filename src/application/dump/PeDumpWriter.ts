import { err, ok, type Result } from "../../domain/result.js";

/**
 * The PE half of dump_memory {format:"pe"} (S6 §4.15; DESIGN §6.2 #30; WP-DUMP). Input is a module image in MAPPED
 * layout (what the loader put in memory, read by the agent), already patch-restored. Output is either the mapped
 * image (`mapped`) or the same bytes with section headers that load as a PE (`pe_realigned`: PointerToRawData =
 * VirtualAddress, SizeOfRawData = VirtualSize rounded up to SectionAlignment, FileAlignment = SectionAlignment), so the
 * file is SizeOfImage bytes and every RVA equals its file offset. A COFF symbol table (gcc/MinGW images: it also holds
 * the long section names "/N") is addressed by file offset and never mapped: the realigned file carries the on-disk
 * table as overlay after SizeOfImage when the caller read it, else drops it and gives "/N" sections their resolved
 * names (≤ 8 bytes), so a loader never reads a string table from unrelated bytes. `rebase_to:"preferred"` writes the on-disk
 * preferred ImageBase and subtracts the load delta at every on-disk DIR64 relocation site (sites the program rewrote
 * at runtime end up wrong; the caller adds a limitation). The IAT is not rebuilt. Pure: no I/O.
 */
export interface MappedPeSection {
  readonly name: string;
  readonly virtualAddress: number;
  readonly virtualSize: number;
  readonly sizeOfRawData: number;
  readonly pointerToRawData: number;
  readonly characteristics: number;
  /** byte offset of this IMAGE_SECTION_HEADER in the image */
  readonly headerOffset: number;
}
export interface MappedPe {
  /** offset of IMAGE_FILE_HEADER (after the PE signature) */
  readonly fileHeaderOffset: number;
  readonly timeDateStamp: number;
  /** FileHeader.PointerToSymbolTable (a FILE offset; 0 = none) and NumberOfSymbols */
  readonly pointerToSymbolTable: number;
  readonly numberOfSymbols: number;
  readonly optOffset: number;
  /** OptionalHeader.ImageBase as found in memory (the loader rewrites it to the runtime base) */
  readonly imageBase: bigint;
  readonly sectionAlignment: number;
  readonly fileAlignment: number;
  readonly sizeOfImage: number;
  readonly sizeOfHeaders: number;
  readonly sections: readonly MappedPeSection[];
  readonly directories: readonly { readonly rva: number; readonly size: number }[];
}

export const IMAGE_SCN_MEM_WRITE = 0x80000000;
/** bytes per COFF symbol record; the string table (u32 size, itself included) follows the records */
export const COFF_SYMBOL_BYTES = 18;
const DIR_SECURITY = 4;
const DIR_DEBUG = 6;
const DEBUG_ENTRY_BYTES = 28;
const MASK64 = (1n << 64n) - 1n;

const view = (bytes: Uint8Array): DataView => new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

/** Parses the PE32+ headers of a mapped image. Errors are BEA-authored reasons. */
export const parseMappedPe = (image: Uint8Array): Result<MappedPe, string> => {
  if (image.length < 0x200) return err("image smaller than a PE header");
  const v = view(image);
  if (v.getUint16(0, true) !== 0x5a4d) return err("no MZ signature");
  const nt = v.getUint32(0x3c, true);
  if (nt + 24 > image.length || v.getUint32(nt, true) !== 0x4550) return err("no PE signature");
  const sectionCount = v.getUint16(nt + 6, true);
  const optSize = v.getUint16(nt + 20, true);
  const opt = nt + 24;
  if (opt + 112 > image.length || v.getUint16(opt, true) !== 0x20b) return err("not a PE32+ optional header");
  const dirCount = Math.min(16, v.getUint32(opt + 108, true));
  if (opt + 112 + dirCount * 8 > image.length) return err("data directories outside the header");
  const directories = Array.from({ length: dirCount }, (_, i) => ({
    rva: v.getUint32(opt + 112 + 8 * i, true),
    size: v.getUint32(opt + 112 + 8 * i + 4, true),
  }));
  const table = opt + optSize;
  if (table + sectionCount * 40 > image.length) return err("section table outside the image");
  const sections: MappedPeSection[] = [];
  for (let i = 0; i < sectionCount; i++) {
    const h = table + 40 * i;
    let name = "";
    for (let k = 0; k < 8 && image[h + k] !== 0; k++) name += String.fromCharCode(image[h + k] ?? 0);
    sections.push({
      name,
      virtualSize: v.getUint32(h + 8, true),
      virtualAddress: v.getUint32(h + 12, true),
      sizeOfRawData: v.getUint32(h + 16, true),
      pointerToRawData: v.getUint32(h + 20, true),
      characteristics: v.getUint32(h + 36, true),
      headerOffset: h,
    });
  }
  const sectionAlignment = v.getUint32(opt + 32, true);
  if (sectionAlignment === 0 || (sectionAlignment & (sectionAlignment - 1)) !== 0)
    return err("SectionAlignment is not a power of two");
  return ok({
    fileHeaderOffset: nt + 4,
    timeDateStamp: v.getUint32(nt + 8, true),
    pointerToSymbolTable: v.getUint32(nt + 12, true),
    numberOfSymbols: v.getUint32(nt + 16, true),
    optOffset: opt,
    imageBase: v.getBigUint64(opt + 24, true),
    sectionAlignment,
    fileAlignment: v.getUint32(opt + 36, true),
    sizeOfImage: v.getUint32(opt + 56, true),
    sizeOfHeaders: v.getUint32(opt + 60, true),
    sections,
    directories,
  });
};

/** A section's in-memory extent: VirtualSize (or SizeOfRawData when VirtualSize is 0), clipped to the image. */
export const sectionExtent = (section: MappedPeSection, imageSize: number): { rva: number; size: number } => {
  const raw = section.virtualSize === 0 ? section.sizeOfRawData : section.virtualSize;
  return { rva: section.virtualAddress, size: Math.max(0, Math.min(raw, imageSize - section.virtualAddress)) };
};

const alignUp = (value: number, to: number): number => Math.ceil(value / to) * to;

export interface PeDumpOptions {
  readonly layout: "pe_realigned" | "mapped";
  /** null: keep the runtime base */
  readonly rebase: {
    readonly preferredBase: bigint;
    readonly runtimeBase: bigint;
    /** on-disk DIR64 relocation site RVAs, sorted */
    readonly relocations: Uint32Array;
  } | null;
  /** zero-filled (unreadable) ranges of the image, rva-relative; relocation sites inside them are left alone */
  readonly gaps: readonly { readonly rva: number; readonly size: number }[];
  /** pe_realigned: the on-disk COFF symbol records + string table (`readCoffSymbolTable`), or null when unavailable */
  readonly coffSymbolTable?: Uint8Array | null;
  /** pe_realigned without the table: resolved section names by RVA (PeImage.sections), for "/N" headers */
  readonly sectionNames?: ReadonlyMap<number, string>;
}
export interface PeDumpOutcome {
  /** bytes the file carries after the image (the COFF symbol table overlay), or null */
  readonly trailer: Uint8Array | null;
  /** what happened to a COFF symbol table named by the header: none, appended as overlay, dropped */
  readonly coffSymbols: "none" | "appended" | "dropped";
  readonly imageBaseInFile: bigint;
  /** sites adjusted, or null when not rebased */
  readonly relocationsReverted: number | null;
  /** sites outside the image or inside a gap */
  readonly relocationsSkipped: number;
}

const inGap = (rva: number, gaps: PeDumpOptions["gaps"]): boolean =>
  gaps.some((g) => rva + 8 > g.rva && rva < g.rva + g.size);

const SECTION_NAME_BYTES = 8;

/** pe_realigned: point the header at the appended on-disk symbol table, or drop it and inline the long names. */
const realignSymbolTable = (
  image: Uint8Array,
  pe: MappedPe,
  options: PeDumpOptions,
): Pick<PeDumpOutcome, "trailer" | "coffSymbols"> => {
  if (pe.pointerToSymbolTable === 0) return { trailer: null, coffSymbols: "none" };
  const v = view(image);
  const table = options.coffSymbolTable ?? null;
  // at least the records + the string table's size field; the reader checked the rest against the file
  if (table !== null && table.length >= pe.numberOfSymbols * COFF_SYMBOL_BYTES + 4) {
    v.setUint32(pe.fileHeaderOffset + 8, image.length, true);
    return { trailer: table, coffSymbols: "appended" };
  }
  v.setUint32(pe.fileHeaderOffset + 8, 0, true);
  v.setUint32(pe.fileHeaderOffset + 12, 0, true);
  pe.sections.forEach((section, index) => {
    if (!section.name.startsWith("/")) return;
    const resolved = options.sectionNames?.get(section.virtualAddress) ?? `.sec${String(index)}`;
    const ascii = [...resolved].map((c) => c.charCodeAt(0)).filter((c) => c > 0x20 && c < 0x7f);
    for (let k = 0; k < SECTION_NAME_BYTES; k++) image[section.headerOffset + k] = ascii[k] ?? 0;
  });
  return { trailer: null, coffSymbols: "dropped" };
};

/**
 * Rewrites `image` in place (headers and relocation sites only); the file is `image` followed by `trailer` (the
 * pe_realigned COFF symbol table overlay, when there is one).
 */
export const writePeDump = (image: Uint8Array, pe: MappedPe, options: PeDumpOptions): PeDumpOutcome => {
  const v = view(image);
  let symbols: Pick<PeDumpOutcome, "trailer" | "coffSymbols"> = { trailer: null, coffSymbols: "none" };
  if (options.layout === "mapped") {
    // Review fix GHIDRA-1: a mapped dump is a raw memory image. Its headers still hold on-disk file offsets; at least
    // never point a loader at a "COFF symbol table" inside unrelated mapped bytes (PointerToSymbolTable is a file offset)
    const fileHeader = pe.optOffset - 20;
    if (fileHeader >= 0 && fileHeader + 16 <= image.length) {
      v.setUint32(fileHeader + 8, 0, true);
      v.setUint32(fileHeader + 12, 0, true);
    }
  }
  if (options.layout === "pe_realigned") {
    symbols = realignSymbolTable(image, pe, options);
    for (const section of pe.sections) {
      const extent = sectionExtent(section, image.length);
      const rawSize = Math.min(alignUp(extent.size, pe.sectionAlignment), image.length - section.virtualAddress);
      v.setUint32(section.headerOffset + 16, Math.max(0, rawSize), true);
      v.setUint32(section.headerOffset + 20, section.virtualAddress, true);
    }
    v.setUint32(pe.optOffset + 36, pe.sectionAlignment, true);
    // The certificate table is addressed by file offset and is not mapped: drop the stale directory entry.
    const security = pe.optOffset + 112 + 8 * DIR_SECURITY;
    if (pe.directories.length > DIR_SECURITY) {
      v.setUint32(security, 0, true);
      v.setUint32(security + 4, 0, true);
    }
    // Debug entries carry a file offset of their data: in a realigned file that offset is the RVA.
    const debug = pe.directories[DIR_DEBUG];
    if (debug !== undefined && debug.rva > 0 && debug.rva + debug.size <= image.length)
      for (let e = debug.rva; e + DEBUG_ENTRY_BYTES <= debug.rva + debug.size; e += DEBUG_ENTRY_BYTES) {
        const addressOfRawData = v.getUint32(e + 20, true);
        if (addressOfRawData !== 0) v.setUint32(e + 24, addressOfRawData, true);
      }
  }
  if (options.rebase === null)
    return { ...symbols, imageBaseInFile: pe.imageBase, relocationsReverted: null, relocationsSkipped: 0 };
  const { preferredBase, runtimeBase, relocations } = options.rebase;
  v.setBigUint64(pe.optOffset + 24, preferredBase, true);
  const delta = (runtimeBase - preferredBase) & MASK64;
  let reverted = 0;
  let skipped = 0;
  for (const rva of relocations) {
    if (rva + 8 > image.length || inGap(rva, options.gaps)) {
      skipped++;
      continue;
    }
    if (delta !== 0n) v.setBigUint64(rva, (v.getBigUint64(rva, true) - delta) & MASK64, true);
    reverted++;
  }
  return { ...symbols, imageBaseInFile: preferredBase, relocationsReverted: reverted, relocationsSkipped: skipped };
};
