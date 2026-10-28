import { existsSync, readFileSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { readCoffSymbolTable } from "../../../src/application/dump/coffSymbols.js";
import { parseMappedPe, sectionExtent, writePeDump } from "../../../src/application/dump/PeDumpWriter.js";
import { fileFacts, fileSectionBytes, mapPe, sampleImage } from "./peBuilder.js";

const RUNTIME = 0x7ff6_a000_0000n;

const header = (image: Uint8Array) => {
  const parsed = parseMappedPe(image);
  if (!parsed.ok) throw new Error(parsed.error);
  return parsed.value;
};

describe("parseMappedPe", () => {
  it("reads the loader-rewritten ImageBase, alignment and section table of a mapped image", () => {
    const pe = sampleImage();
    const h = header(mapPe(pe.file, RUNTIME));
    expect(h.imageBase).toBe(RUNTIME);
    expect(h.sectionAlignment).toBe(0x1000);
    expect(h.fileAlignment).toBe(0x200);
    expect(h.sizeOfImage).toBe(pe.sizeOfImage);
    expect(h.sections.map((s) => s.name)).toEqual([".text", ".rdata", ".data", ".reloc"]);
    expect(sectionExtent(h.sections[2]!, h.sizeOfImage)).toEqual({ rva: 0x4000, size: 0x1200 });
  });

  it("refuses non-PE bytes, PE32 and a section table outside the image", () => {
    expect(parseMappedPe(new Uint8Array(0x1000)).ok).toBe(false);
    const image = mapPe(sampleImage().file, RUNTIME);
    const pe32 = image.slice();
    new DataView(pe32.buffer).setUint16(0x98, 0x10b, true);
    expect(parseMappedPe(pe32)).toEqual({ ok: false, error: "not a PE32+ optional header" });
    const truncated = image.slice(0, 0x200);
    new DataView(truncated.buffer).setUint16(0x86, 40, true);
    expect(parseMappedPe(truncated).ok).toBe(false);
  });
});

describe("writePeDump", () => {
  it("pe_realigned: PointerToRawData = VirtualAddress, SizeOfRawData = aligned VirtualSize, FileAlignment = SectionAlignment", () => {
    const pe = sampleImage();
    const image = mapPe(pe.file, RUNTIME);
    const out = writePeDump(image, header(image), { layout: "pe_realigned", rebase: null, gaps: [] });
    expect(out).toEqual({
      trailer: null,
      coffSymbols: "none",
      imageBaseInFile: RUNTIME,
      relocationsReverted: null,
      relocationsSkipped: 0,
    });
    const facts = fileFacts(image);
    expect(header(image).fileAlignment).toBe(0x1000);
    for (const s of facts.sections) {
      expect(s.rawOffset).toBe(s.rva);
      expect(s.rawSize).toBe(Math.min(Math.ceil(s.virtualSize / 0x1000) * 0x1000, image.length - s.rva));
    }
    // the security directory (file offsets, never mapped) is dropped; the debug entry's file offset = its RVA
    const v = new DataView(image.buffer);
    expect(v.getUint32(0x98 + 112 + 32, true)).toBe(0);
    expect(v.getUint32(0x3100 + 24, true)).toBe(0x3200);
    // the realigned file maps onto itself: a loader reading raw data at PointerToRawData sees the same bytes
    expect(mapPe(image, RUNTIME)).toEqual(image);
  });

  it("rebase_to preferred: header ImageBase and every DIR64 site return to the on-disk values, so .text equals the file", () => {
    const pe = sampleImage();
    const image = mapPe(pe.file, RUNTIME);
    const out = writePeDump(image, header(image), {
      layout: "pe_realigned",
      rebase: { preferredBase: pe.preferredBase, runtimeBase: RUNTIME, relocations: pe.relocations },
      gaps: [],
    });
    expect(out.imageBaseInFile).toBe(pe.preferredBase);
    expect(out.relocationsReverted).toBe(3);
    expect(header(image).imageBase).toBe(pe.preferredBase);
    const text = fileSectionBytes(pe.file, 0x1000);
    expect(image.subarray(0x1000, 0x1000 + text.length)).toEqual(text);
    // .rdata equals the file too, except the debug entry's PointerToRawData (realigned to its RVA)
    const rdata = fileSectionBytes(pe.file, 0x3000).slice();
    new DataView(rdata.buffer).setUint32(0x100 + 24, 0x3200, true);
    expect(image.subarray(0x3000, 0x3000 + rdata.length)).toEqual(rdata);
    expect(new DataView(image.buffer).getBigUint64(0x4008, true)).toBe(pe.preferredBase + 0x1000n);
  });

  it("mapped layout keeps the section table; relocation sites inside zero-filled gaps are skipped", () => {
    const pe = sampleImage();
    const image = mapPe(pe.file, RUNTIME);
    const before = image.slice();
    image.fill(0, 0x4000, 0x5000); // .data unreadable
    const out = writePeDump(image, header(image), {
      layout: "mapped",
      rebase: { preferredBase: pe.preferredBase, runtimeBase: RUNTIME, relocations: pe.relocations },
      gaps: [{ rva: 0x4000, size: 0x1000 }],
    });
    expect(out.relocationsReverted).toBe(2);
    expect(out.relocationsSkipped).toBe(1);
    expect(new DataView(image.buffer).getBigUint64(0x4008, true)).toBe(0n);
    expect(header(image).sections.map((s) => s.pointerToRawData)).toEqual(
      header(before).sections.map((s) => s.pointerToRawData),
    );
    expect(header(image).fileAlignment).toBe(0x200);
  });

  it("a zero load delta leaves every byte but the header alone", () => {
    const pe = sampleImage();
    const image = mapPe(pe.file, pe.preferredBase);
    const before = image.slice();
    const out = writePeDump(image, header(image), {
      layout: "mapped",
      rebase: { preferredBase: pe.preferredBase, runtimeBase: pe.preferredBase, relocations: pe.relocations },
      gaps: [],
    });
    expect(out.relocationsReverted).toBe(3);
    expect(image).toEqual(before);
  });

  const kernel32 = "C:\\Windows\\System32\\kernel32.dll";
  it.skipIf(!existsSync(kernel32))(
    "a real system DLL mapped at a random base dumps back to its on-disk code and read-only data",
    () => {
      const file = new Uint8Array(readFileSync(kernel32));
      const facts = fileFacts(file);
      const base = 0x7ffa_1234_0000n;
      const image = mapPe(file, base);
      const out = writePeDump(image, header(image), {
        layout: "pe_realigned",
        rebase: { preferredBase: facts.preferredBase, runtimeBase: base, relocations: facts.relocations },
        gaps: [],
      });
      expect(out.relocationsReverted).toBe(facts.relocations.length);
      expect(header(image).imageBase).toBe(facts.preferredBase);
      for (const s of facts.sections.filter((x) => (x.characteristics & 0x80000000) === 0 && x.rawSize > 0)) {
        const disk = fileSectionBytes(file, s.rva);
        expect(
          Buffer.from(image.subarray(s.rva, s.rva + disk.length)).equals(Buffer.from(disk)),
          `section 0x${s.rva.toString(16)}`,
        ).toBe(true);
      }
    },
  );
});

/**
 * gcc/MinGW layout: a COFF symbol table after the sections (a FILE offset, never mapped) whose string table also holds
 * the long section name of .rdata ("/4"). Two 18-byte records, then the string table (u32 size, then the strings).
 */
const LONG_NAME = ".rdata_long_name";
const RDATA_HEADER = 0x98 + 0xf0 + 40;
const FILE_HEADER = 0x84;
const withCoffSymbols = (file: Uint8Array): { file: Uint8Array; table: Uint8Array } => {
  const strings = new TextEncoder().encode(`\u0000\u0000\u0000\u0000${LONG_NAME}\u0000`);
  new DataView(strings.buffer).setUint32(0, strings.length, true);
  const table = new Uint8Array(2 * 18 + strings.length);
  table.set(strings, 2 * 18);
  table[0] = 0x2e; // a record's bytes are carried verbatim
  const out = new Uint8Array(file.length + table.length);
  out.set(file, 0);
  out.set(table, file.length);
  const v = new DataView(out.buffer);
  v.setUint32(FILE_HEADER + 4, 0x6511_2233, true); // TimeDateStamp
  v.setUint32(FILE_HEADER + 8, file.length, true); // PointerToSymbolTable
  v.setUint32(FILE_HEADER + 12, 2, true); // NumberOfSymbols
  out.fill(0, RDATA_HEADER, RDATA_HEADER + 8);
  out.set(new TextEncoder().encode("/4"), RDATA_HEADER);
  return { file: out, table };
};
const nameAt = (image: Uint8Array, at: number): string =>
  Buffer.from(image.subarray(at, at + 8))
    .toString("latin1")
    .replace(/\u0000+$/u, "");

describe("pe_realigned and the COFF symbol table (file offsets are never mapped)", () => {
  it("carries the on-disk table as overlay after SizeOfImage, so the long section names still resolve", () => {
    const { file, table } = withCoffSymbols(sampleImage().file);
    const image = mapPe(file, RUNTIME);
    const out = writePeDump(image, header(image), {
      layout: "pe_realigned",
      rebase: null,
      gaps: [],
      coffSymbolTable: table,
    });
    expect(out.coffSymbols).toBe("appended");
    expect(out.trailer).toEqual(table);
    const v = new DataView(image.buffer);
    expect(v.getUint32(FILE_HEADER + 8, true)).toBe(image.length);
    expect(v.getUint32(FILE_HEADER + 12, true)).toBe(2);
    expect(nameAt(image, RDATA_HEADER)).toBe("/4");
    const written = Buffer.concat([image, out.trailer!]);
    const at = image.length + 2 * 18 + 4;
    expect(written.toString("latin1", at, at + LONG_NAME.length)).toBe(LONG_NAME);
  });

  it("without the table: drops the pointer and gives /N sections their resolved names (8 bytes), else a neutral one", () => {
    const { file } = withCoffSymbols(sampleImage().file);
    for (const [names, expected] of [
      [new Map([[0x3000, LONG_NAME]]), ".rdata_l"],
      [undefined, ".sec1"],
    ] as const) {
      const image = mapPe(file, RUNTIME);
      const out = writePeDump(image, header(image), {
        layout: "pe_realigned",
        rebase: null,
        gaps: [],
        coffSymbolTable: null,
        ...(names === undefined ? {} : { sectionNames: names }),
      });
      expect(out).toMatchObject({ coffSymbols: "dropped", trailer: null });
      const v = new DataView(image.buffer);
      expect([v.getUint32(FILE_HEADER + 8, true), v.getUint32(FILE_HEADER + 12, true)]).toEqual([0, 0]);
      expect(header(image).sections.map((s) => s.name)).toEqual([".text", expected, ".data", ".reloc"]);
    }
  });

  it("a table shorter than its records is not appended; the mapped layout only drops the symbol table pointer", () => {
    const { file, table } = withCoffSymbols(sampleImage().file);
    const short = mapPe(file, RUNTIME);
    expect(
      writePeDump(short, header(short), {
        layout: "pe_realigned",
        rebase: null,
        gaps: [],
        coffSymbolTable: table.subarray(0, 30),
      }).coffSymbols,
    ).toBe("dropped");
    const image = mapPe(file, RUNTIME);
    const before = header(image);
    const out = writePeDump(image, before, { layout: "mapped", rebase: null, gaps: [], coffSymbolTable: table });
    expect(out).toMatchObject({ coffSymbols: "none", trailer: null });
    // GHIDRA-1: the mapped layout keeps the headers except the COFF symbol table pointer (a file offset that would
    // point a loader into unrelated mapped bytes): zeroed with its count
    expect(before.pointerToSymbolTable).not.toBe(0);
    expect(header(image).pointerToSymbolTable).toBe(0);
    expect(nameAt(image, RDATA_HEADER)).toBe("/4");
  });

  it("readCoffSymbolTable reads the records + string table of the SAME file, else null", async () => {
    const dir = await mkdtemp(join(tmpdir(), "bea-coff-"));
    try {
      const { file, table } = withCoffSymbols(sampleImage().file);
      const path = join(dir, "m.exe");
      await writeFile(path, file);
      const pe = header(mapPe(file, RUNTIME));
      expect(pe).toMatchObject({ timeDateStamp: 0x6511_2233, pointerToSymbolTable: file.length - table.length });
      expect(await readCoffSymbolTable(path, pe)).toEqual(table);
      // a different build at the same path (another TimeDateStamp or table position) is not this image's table
      expect(await readCoffSymbolTable(path, { ...pe, timeDateStamp: 1 })).toBeNull();
      expect(await readCoffSymbolTable(path, { ...pe, numberOfSymbols: 3 })).toBeNull();
      expect(await readCoffSymbolTable(path, { ...pe, pointerToSymbolTable: 0 })).toBeNull();
      expect(await readCoffSymbolTable(join(dir, "missing.exe"), pe)).toBeNull();
      // a string table size that runs past the end of the file
      const broken = file.slice();
      new DataView(broken.buffer).setUint32(file.length - table.length + 2 * 18, 0x10000, true);
      await writeFile(path, broken);
      expect(await readCoffSymbolTable(path, pe)).toBeNull();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
