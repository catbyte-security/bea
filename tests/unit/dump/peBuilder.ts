/**
 * WP13 test helper: synthetic PE32+ images in FILE layout and in MAPPED layout (what the Windows loader puts in
 * memory at a runtime base: headers + sections at their RVAs, ImageBase rewritten, DIR64 relocations applied). Also
 * maps a real PE file from disk the same way, so writer tests can compare against on-disk section bytes.
 */
export interface SectionSpec {
  readonly name: string;
  readonly rva: number;
  readonly data: Uint8Array;
  /** in-memory size (default data.length) */
  readonly virtualSize?: number;
  readonly characteristics: number;
}
export interface BuiltPe {
  readonly file: Uint8Array;
  readonly preferredBase: bigint;
  readonly sizeOfImage: number;
  readonly relocations: Uint32Array;
  readonly sections: readonly {
    name: string;
    rva: number;
    virtualSize: number;
    rawOffset: number;
    rawSize: number;
    characteristics: number;
  }[];
}

export const SCN_CODE = 0x60000020; // CODE | EXECUTE | READ
export const SCN_RDATA = 0x40000040; // INITIALIZED_DATA | READ
export const SCN_DATA = 0xc0000040; // INITIALIZED_DATA | READ | WRITE
const SCN_RELOC = 0x42000040; // INITIALIZED_DATA | DISCARDABLE | READ

const align = (v: number, a: number): number => Math.ceil(v / a) * a;

/** Base relocation blocks for DIR64 sites. */
const relocBlocks = (sites: readonly number[]): Uint8Array => {
  const pages = new Map<number, number[]>();
  for (const s of [...sites].sort((a, b) => a - b)) {
    const page = s & ~0xfff;
    pages.set(page, [...(pages.get(page) ?? []), s & 0xfff]);
  }
  const chunks: Uint8Array[] = [];
  for (const [page, offsets] of pages) {
    const entries = offsets.length % 2 === 0 ? offsets.length : offsets.length + 1;
    const block = new Uint8Array(8 + 2 * entries);
    const v = new DataView(block.buffer);
    v.setUint32(0, page, true);
    v.setUint32(4, block.length, true);
    offsets.forEach((o, i) => v.setUint16(8 + 2 * i, (10 << 12) | o, true));
    chunks.push(block);
  }
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.length;
  }
  return out;
};

/**
 * Builds a PE32+ file. Each `pointerSites` entry is an RVA where a pointer (preferredBase + target RVA) is stored and
 * relocated. A debug directory entry (in the first read-only section) points at `debugRva` when given.
 */
export const buildPe = (spec: {
  readonly preferredBase: bigint;
  readonly sections: readonly SectionSpec[];
  readonly pointerSites: readonly { readonly rva: number; readonly target: number }[];
  readonly debug?: { readonly entryRva: number; readonly dataRva: number; readonly dataSize: number };
  readonly security?: boolean;
}): BuiltPe => {
  const fileAlign = 0x200;
  const lastSection = spec.sections.reduce((m, s) => Math.max(m, s.rva + (s.virtualSize ?? s.data.length)), 0x1000);
  const relocRva = align(lastSection, 0x1000);
  const relocData = relocBlocks(spec.pointerSites.map((p) => p.rva));
  const all: SectionSpec[] = [
    ...spec.sections,
    { name: ".reloc", rva: relocRva, data: relocData, characteristics: SCN_RELOC },
  ];
  const sizeOfImage = align(relocRva + relocData.length, 0x1000);
  const headers = 0x400;
  const layout: {
    name: string;
    rva: number;
    virtualSize: number;
    rawOffset: number;
    rawSize: number;
    characteristics: number;
  }[] = [];
  let raw = headers;
  for (const s of all) {
    const rawSize = align(s.data.length, fileAlign);
    layout.push({
      name: s.name,
      rva: s.rva,
      virtualSize: s.virtualSize ?? s.data.length,
      rawOffset: raw,
      rawSize,
      characteristics: s.characteristics,
    });
    raw += rawSize;
  }
  const file = new Uint8Array(raw);
  const v = new DataView(file.buffer);
  file[0] = 0x4d;
  file[1] = 0x5a;
  v.setUint32(0x3c, 0x80, true);
  v.setUint32(0x80, 0x4550, true);
  v.setUint16(0x84, 0x8664, true);
  v.setUint16(0x86, all.length, true);
  v.setUint16(0x94, 0xf0, true);
  v.setUint16(0x96, 0x22, true);
  const opt = 0x98;
  v.setUint16(opt, 0x20b, true);
  v.setUint32(opt + 16, spec.sections[0]?.rva ?? 0, true);
  v.setBigUint64(opt + 24, spec.preferredBase, true);
  v.setUint32(opt + 32, 0x1000, true);
  v.setUint32(opt + 36, fileAlign, true);
  v.setUint32(opt + 56, sizeOfImage, true);
  v.setUint32(opt + 60, headers, true);
  v.setUint16(opt + 68, 3, true);
  v.setUint16(opt + 70, 0x160, true);
  v.setUint32(opt + 108, 16, true);
  v.setUint32(opt + 112 + 8 * 5, relocRva, true);
  v.setUint32(opt + 112 + 8 * 5 + 4, relocData.length, true);
  if (spec.security === true) {
    v.setUint32(opt + 112 + 8 * 4, raw, true); // a file offset past the sections
    v.setUint32(opt + 112 + 8 * 4 + 4, 0x100, true);
  }
  if (spec.debug !== undefined) {
    v.setUint32(opt + 112 + 8 * 6, spec.debug.entryRva, true);
    v.setUint32(opt + 112 + 8 * 6 + 4, 28, true);
  }
  layout.forEach((s, i) => {
    const h = opt + 0xf0 + 40 * i;
    for (let k = 0; k < Math.min(8, s.name.length); k++) file[h + k] = s.name.charCodeAt(k);
    v.setUint32(h + 8, s.virtualSize, true);
    v.setUint32(h + 12, s.rva, true);
    v.setUint32(h + 16, s.rawSize, true);
    v.setUint32(h + 20, s.rawOffset, true);
    v.setUint32(h + 36, s.characteristics, true);
    file.set(all[i]?.data ?? new Uint8Array(0), s.rawOffset);
  });
  const fileOffsetOf = (rva: number): number => {
    const s = layout.find((x) => rva >= x.rva && rva < x.rva + x.rawSize);
    if (s === undefined) throw new Error(`rva 0x${rva.toString(16)} not in a section`);
    return s.rawOffset + (rva - s.rva);
  };
  for (const p of spec.pointerSites) v.setBigUint64(fileOffsetOf(p.rva), spec.preferredBase + BigInt(p.target), true);
  if (spec.debug !== undefined) {
    const e = fileOffsetOf(spec.debug.entryRva);
    v.setUint32(e + 12, 2, true); // IMAGE_DEBUG_TYPE_CODEVIEW
    v.setUint32(e + 16, spec.debug.dataSize, true);
    v.setUint32(e + 20, spec.debug.dataRva, true);
    v.setUint32(e + 24, fileOffsetOf(spec.debug.dataRva), true);
  }
  return {
    file,
    preferredBase: spec.preferredBase,
    sizeOfImage,
    relocations: Uint32Array.from(spec.pointerSites.map((p) => p.rva).sort((a, b) => a - b)),
    sections: layout,
  };
};

/** Parses the section table and DIR64 relocation sites of a PE32+ FILE (headers sit at the same offsets). */
export const fileFacts = (file: Uint8Array) => {
  const v = new DataView(file.buffer, file.byteOffset, file.byteLength);
  const nt = v.getUint32(0x3c, true);
  const count = v.getUint16(nt + 6, true);
  const opt = nt + 24;
  const table = opt + v.getUint16(nt + 20, true);
  const sections = Array.from({ length: count }, (_, i) => {
    const h = table + 40 * i;
    return {
      rva: v.getUint32(h + 12, true),
      virtualSize: v.getUint32(h + 8, true),
      rawSize: v.getUint32(h + 16, true),
      rawOffset: v.getUint32(h + 20, true),
      characteristics: v.getUint32(h + 36, true),
    };
  });
  const sizeOfImage = v.getUint32(opt + 56, true);
  const sizeOfHeaders = v.getUint32(opt + 60, true);
  const preferredBase = v.getBigUint64(opt + 24, true);
  const relocRva = v.getUint32(opt + 112 + 8 * 5, true);
  const relocSize = v.getUint32(opt + 112 + 8 * 5 + 4, true);
  const toOff = (rva: number): number => {
    const s = sections.find((x) => rva >= x.rva && rva < x.rva + Math.max(x.rawSize, x.virtualSize));
    return s === undefined ? -1 : s.rawOffset + (rva - s.rva);
  };
  const sites: number[] = [];
  for (let at = toOff(relocRva), end = at + relocSize; relocSize > 0 && at + 8 <= end;) {
    const page = v.getUint32(at, true);
    const size = v.getUint32(at + 4, true);
    if (size < 8) break;
    for (let e = at + 8; e + 2 <= at + size; e += 2) {
      const entry = v.getUint16(e, true);
      if (entry >> 12 === 10) sites.push(page + (entry & 0xfff));
    }
    at += size;
  }
  return {
    sections,
    sizeOfImage,
    sizeOfHeaders,
    preferredBase,
    relocations: Uint32Array.from(sites.sort((a, b) => a - b)),
  };
};

/** The loader's view: headers + sections at their RVAs, ImageBase = base, DIR64 sites relocated. */
export const mapPe = (file: Uint8Array, base: bigint): Uint8Array => {
  const facts = fileFacts(file);
  const image = new Uint8Array(facts.sizeOfImage);
  image.set(file.subarray(0, Math.min(facts.sizeOfHeaders, file.length)), 0);
  for (const s of facts.sections) {
    const n = Math.min(s.rawSize, s.virtualSize === 0 ? s.rawSize : s.virtualSize, facts.sizeOfImage - s.rva);
    if (n > 0) image.set(file.subarray(s.rawOffset, s.rawOffset + n), s.rva);
  }
  const v = new DataView(image.buffer);
  const nt = v.getUint32(0x3c, true);
  v.setBigUint64(nt + 24 + 24, base, true);
  const delta = base - facts.preferredBase;
  for (const rva of facts.relocations)
    if (rva + 8 <= image.length) v.setBigUint64(rva, (v.getBigUint64(rva, true) + delta) & ((1n << 64n) - 1n), true);
  return image;
};

/** The bytes of a section as the file holds them (min of raw and virtual size). */
export const fileSectionBytes = (file: Uint8Array, rva: number): Uint8Array => {
  const facts = fileFacts(file);
  const s = facts.sections.find((x) => x.rva === rva);
  if (s === undefined) throw new Error("no such section");
  const n = Math.min(s.rawSize, s.virtualSize === 0 ? s.rawSize : s.virtualSize);
  return file.subarray(s.rawOffset, s.rawOffset + n);
};

/** A small game-like image: .text with code + a function-pointer table site, .rdata with debug data, .data. */
export const sampleImage = (): BuiltPe => {
  const text = new Uint8Array(0x1800).map((_, i) => (i * 7 + 3) & 0xff);
  const rdata = new Uint8Array(0x400).fill(0);
  const data = new Uint8Array(0x300).fill(0x11);
  return buildPe({
    preferredBase: 0x1_4000_0000n,
    sections: [
      { name: ".text", rva: 0x1000, data: text, characteristics: SCN_CODE },
      { name: ".rdata", rva: 0x3000, data: rdata, characteristics: SCN_RDATA },
      { name: ".data", rva: 0x4000, data, virtualSize: 0x1200, characteristics: SCN_DATA },
    ],
    pointerSites: [
      { rva: 0x1100, target: 0x1760 },
      { rva: 0x3010, target: 0x4000 },
      { rva: 0x4008, target: 0x1000 },
    ],
    debug: { entryRva: 0x3100, dataRva: 0x3200, dataSize: 0x20 },
    security: true,
  });
};
