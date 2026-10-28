import { open } from "node:fs/promises";

import { COFF_SYMBOL_BYTES, type MappedPe } from "./PeDumpWriter.js";

/**
 * The on-disk COFF symbol table of a module (gcc/MinGW images carry one; its string table also holds the long section
 * names "/N"), read for the pe_realigned overlay (PeDumpWriter). The table lives at a FILE offset and is never mapped,
 * so it cannot come from the agent's capture. The file must still be the image the process loaded: its FileHeader
 * TimeDateStamp, PointerToSymbolTable and NumberOfSymbols must equal the in-memory header's (the loader maps the
 * headers verbatim). Bounded positional reads; any mismatch, malformed table or I/O failure yields null and the writer
 * drops the table instead.
 */
const MAX_TABLE_BYTES = 64 * 1024 * 1024;
const HEADER_PROBE_BYTES = 0x40;
/** PE signature (4) + IMAGE_FILE_HEADER fields up to NumberOfSymbols (16) */
const FILE_HEADER_PROBE_BYTES = 20;

const readExact = async (
  file: Awaited<ReturnType<typeof open>>,
  position: number,
  length: number,
): Promise<Uint8Array | null> => {
  const buffer = new Uint8Array(length);
  let done = 0;
  while (done < length) {
    const { bytesRead } = await file.read(buffer, done, length - done, position + done);
    if (bytesRead === 0) return null;
    done += bytesRead;
  }
  return buffer;
};

export const readCoffSymbolTable = async (
  path: string,
  pe: Pick<MappedPe, "timeDateStamp" | "pointerToSymbolTable" | "numberOfSymbols">,
): Promise<Uint8Array | null> => {
  if (pe.pointerToSymbolTable === 0) return null;
  const records = pe.numberOfSymbols * COFF_SYMBOL_BYTES;
  if (records > MAX_TABLE_BYTES) return null;
  let file: Awaited<ReturnType<typeof open>> | undefined;
  try {
    file = await open(path, "r");
    const size = (await file.stat()).size;
    const dos = await readExact(file, 0, HEADER_PROBE_BYTES);
    if (dos === null) return null;
    const dosView = new DataView(dos.buffer);
    if (dosView.getUint16(0, true) !== 0x5a4d) return null;
    const nt = dosView.getUint32(0x3c, true);
    const header = await readExact(file, nt, FILE_HEADER_PROBE_BYTES);
    if (header === null) return null;
    const h = new DataView(header.buffer);
    if (
      h.getUint32(0, true) !== 0x4550 ||
      h.getUint32(8, true) !== pe.timeDateStamp ||
      h.getUint32(12, true) !== pe.pointerToSymbolTable ||
      h.getUint32(16, true) !== pe.numberOfSymbols
    )
      return null;
    const sizeField = await readExact(file, pe.pointerToSymbolTable + records, 4);
    if (sizeField === null) return null;
    const strings = new DataView(sizeField.buffer).getUint32(0, true);
    // the string table's size counts its own u32 field
    const total = records + strings;
    if (strings < 4 || total > MAX_TABLE_BYTES || pe.pointerToSymbolTable + total > size) return null;
    return await readExact(file, pe.pointerToSymbolTable, total);
  } catch {
    return null;
  } finally {
    await file?.close().catch(() => undefined);
  }
};
