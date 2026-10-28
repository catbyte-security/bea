// scripts/lib/peParse.mjs (WP0; S1 §1.1, S6 §10.2): a small PE32/PE32+ reader for fixture manifests and test
// helpers: headers, sections, exports (with forwarders), import DLL names and .pdata RUNTIME_FUNCTION entries.
// Not the product's PE reader (that is src/providers/pe, WP-ADDR); it throws PeFormatError on anything malformed.
const IMAGE_FILE_MACHINE = { 0x14c: "i386", 0x8664: "x64", 0xaa64: "arm64" };
const DLL_CHARACTERISTICS = { highEntropyVa: 0x20, dynamicBase: 0x40, nxCompat: 0x100 };

export class PeFormatError extends Error {
  name = "PeFormatError";
}

const hex = (value) => `0x${value.toString(16)}`;

/** Parse a PE image held in a Buffer (the file as stored on disk). */
export function parsePe(buffer) {
  const fail = (why) => {
    throw new PeFormatError(why);
  };
  const u16 = (offset) =>
    offset + 2 <= buffer.length ? buffer.readUInt16LE(offset) : fail(`read past end at ${hex(offset)}`);
  const u32 = (offset) =>
    offset + 4 <= buffer.length ? buffer.readUInt32LE(offset) : fail(`read past end at ${hex(offset)}`);
  const u64 = (offset) =>
    offset + 8 <= buffer.length ? buffer.readBigUInt64LE(offset) : fail(`read past end at ${hex(offset)}`);

  if (buffer.length < 0x40 || buffer.toString("latin1", 0, 2) !== "MZ") fail("missing MZ header");
  const peOffset = u32(0x3c);
  if (buffer.toString("latin1", peOffset, peOffset + 4) !== "PE\0\0") fail("missing PE signature");
  const coff = peOffset + 4;
  const machine = u16(coff);
  const sectionCount = u16(coff + 2);
  const optionalSize = u16(coff + 16);
  const characteristics = u16(coff + 18);
  const opt = coff + 20;
  const magic = u16(opt);
  if (magic !== 0x10b && magic !== 0x20b) fail(`unknown optional header magic ${hex(magic)}`);
  const pe32plus = magic === 0x20b;
  const imageBase = pe32plus ? u64(opt + 24) : BigInt(u32(opt + 28));
  const dllCharacteristics = u16(opt + 70);
  const directoryCount = u32(opt + (pe32plus ? 108 : 92));
  const directories = [];
  const directoryBase = opt + (pe32plus ? 112 : 96);
  for (let i = 0; i < Math.min(directoryCount, 16); i += 1)
    directories.push({ rva: u32(directoryBase + i * 8), size: u32(directoryBase + i * 8 + 4) });

  const sections = [];
  const sectionBase = opt + optionalSize;
  for (let i = 0; i < sectionCount; i += 1) {
    const at = sectionBase + i * 40;
    sections.push({
      name: buffer.toString("latin1", at, at + 8).replace(/\0+$/u, ""),
      rva: u32(at + 12),
      virtualSize: u32(at + 8),
      rawOffset: u32(at + 20),
      rawSize: u32(at + 16),
      characteristics: u32(at + 36),
    });
  }
  const offsetOf = (rva) => {
    for (const s of sections)
      if (rva >= s.rva && rva < s.rva + Math.max(s.virtualSize, s.rawSize)) {
        const delta = rva - s.rva;
        return delta < s.rawSize ? s.rawOffset + delta : fail(`rva ${hex(rva)} is in uninitialised data`);
      }
    return rva < u32(opt + 60) ? rva : fail(`rva ${hex(rva)} is outside every section`);
  };
  const cString = (rva) => {
    const start = offsetOf(rva);
    const end = buffer.indexOf(0, start);
    if (end < 0) fail(`unterminated string at rva ${hex(rva)}`);
    return buffer.toString("latin1", start, end);
  };

  // Exports (directory 0): name -> rva, or a forwarder string.
  const exports = [];
  const exportDir = directories[0];
  if (exportDir !== undefined && exportDir.rva !== 0 && exportDir.size !== 0) {
    const at = offsetOf(exportDir.rva);
    const ordinalBase = u32(at + 16);
    const functionCount = u32(at + 20);
    const nameCount = u32(at + 24);
    const functions = offsetOf(u32(at + 28));
    const names = nameCount === 0 ? 0 : offsetOf(u32(at + 32));
    const ordinals = nameCount === 0 ? 0 : offsetOf(u32(at + 36));
    const named = new Map();
    for (let i = 0; i < nameCount; i += 1) named.set(u16(ordinals + i * 2), cString(u32(names + i * 4)));
    for (let index = 0; index < functionCount; index += 1) {
      const rva = u32(functions + index * 4);
      if (rva === 0) continue;
      const forwarded = rva >= exportDir.rva && rva < exportDir.rva + exportDir.size;
      exports.push({
        name: named.get(index) ?? null,
        ordinal: ordinalBase + index,
        rva: forwarded ? null : rva,
        forwarder: forwarded ? cString(rva) : null,
      });
    }
  }

  // Imports (directory 1): DLL names in descriptor order.
  const imports = [];
  const importDir = directories[1];
  if (importDir !== undefined && importDir.rva !== 0 && importDir.size !== 0) {
    for (let at = offsetOf(importDir.rva); ; at += 20) {
      const nameRva = u32(at + 12);
      if (nameRva === 0 && u32(at) === 0 && u32(at + 16) === 0) break;
      imports.push(cString(nameRva));
    }
  }

  // .pdata (directory 3, x64 RUNTIME_FUNCTION {begin, end, unwind}).
  const pdata = [];
  const exceptionDir = directories[3];
  if (machine === 0x8664 && exceptionDir !== undefined && exceptionDir.rva !== 0 && exceptionDir.size !== 0) {
    const at = offsetOf(exceptionDir.rva);
    for (let i = 0; i < Math.floor(exceptionDir.size / 12); i += 1)
      pdata.push({ begin: u32(at + i * 12), end: u32(at + i * 12 + 4), unwind: u32(at + i * 12 + 8) });
  }

  return {
    machine: IMAGE_FILE_MACHINE[machine] ?? hex(machine),
    format: pe32plus ? "PE32+" : "PE32",
    characteristics,
    isDll: (characteristics & 0x2000) !== 0,
    imageBase: `0x${imageBase.toString(16)}`,
    entryRva: u32(opt + 16),
    sizeOfImage: u32(opt + 56),
    sizeOfHeaders: u32(opt + 60),
    subsystem: u16(opt + 68),
    dllCharacteristics,
    dynamicBase: (dllCharacteristics & DLL_CHARACTERISTICS.dynamicBase) !== 0,
    highEntropyVa: (dllCharacteristics & DLL_CHARACTERISTICS.highEntropyVa) !== 0,
    nxCompat: (dllCharacteristics & DLL_CHARACTERISTICS.nxCompat) !== 0,
    sections,
    exports,
    imports,
    pdata,
    /** Read `size` bytes at an RVA (file-backed data only). */
    readRva: (rva, size) => {
      const start = offsetOf(rva);
      if (start + size > buffer.length) fail(`read of ${size} bytes at rva ${hex(rva)} runs past the file`);
      return buffer.subarray(start, start + size);
    },
  };
}

/** name -> rva of every named, non-forwarded export. */
export const exportRvas = (pe) =>
  Object.fromEntries(pe.exports.filter((e) => e.name !== null && e.rva !== null).map((e) => [e.name, e.rva]));

/** name -> {rva, size} for every export that starts a .pdata function. */
export function exportedFunctions(pe) {
  const byBegin = new Map(pe.pdata.map((entry) => [entry.begin, entry]));
  const out = {};
  for (const e of pe.exports) {
    if (e.name === null || e.rva === null) continue;
    const entry = byBegin.get(e.rva);
    if (entry !== undefined) out[e.name] = { rva: e.rva, size: entry.end - entry.begin };
  }
  return out;
}
