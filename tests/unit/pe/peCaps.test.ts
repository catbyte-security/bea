import { rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { LruPeImageCache } from "../../../src/providers/pe/PeImageCache.js";
import { createTempHome, type TempHome } from "../../support/workspace/tempHome.js";

/**
 * Review fixes DATA-1 and DATA-8: crafted (but loader-acceptable) PE32+ files must not make BEA build hundreds of
 * millions of rows, allocate for zero-fill, or report impossible section facts.
 */
interface Section {
  readonly name: string;
  readonly rva: number;
  readonly data: Buffer;
  /** default: data.length */
  readonly virtualSize?: number;
  /** override the raw pointer / size fields (malformed layouts) */
  readonly rawPointer?: number;
  readonly rawSize?: number;
}

const FILE_ALIGN = 0x200;
const align = (v: number, a: number): number => Math.ceil(v / a) * a;

const buildPe = (sections: readonly Section[], dirs: Readonly<Record<number, readonly [number, number]>>): Buffer => {
  const headers = 0x400;
  let raw = headers;
  const layout = sections.map((s) => {
    const offset = raw;
    raw += align(s.data.length, FILE_ALIGN);
    return { ...s, offset };
  });
  const file = Buffer.alloc(raw);
  file.write("MZ", 0, "latin1");
  file.writeUInt32LE(0x80, 0x3c);
  file.writeUInt32LE(0x4550, 0x80);
  file.writeUInt16LE(0x8664, 0x84);
  file.writeUInt16LE(sections.length, 0x86);
  file.writeUInt16LE(0xf0, 0x94);
  file.writeUInt16LE(0x22, 0x96);
  const opt = 0x98;
  file.writeUInt16LE(0x20b, opt);
  file.writeBigUInt64LE(0x140000000n, opt + 24);
  file.writeUInt32LE(0x1000, opt + 32);
  file.writeUInt32LE(FILE_ALIGN, opt + 36);
  const end = sections.reduce((m, s) => Math.max(m, s.rva + (s.virtualSize ?? s.data.length)), 0x1000);
  file.writeUInt32LE(align(end, 0x1000), opt + 56);
  file.writeUInt32LE(headers, opt + 60);
  file.writeUInt16LE(3, opt + 68);
  file.writeUInt32LE(16, opt + 108);
  for (const [index, [rva, size]] of Object.entries(dirs)) {
    file.writeUInt32LE(rva, opt + 112 + 8 * Number(index));
    file.writeUInt32LE(size, opt + 112 + 8 * Number(index) + 4);
  }
  layout.forEach((s, i) => {
    const h = opt + 0xf0 + 40 * i;
    file.write(s.name, h, "latin1");
    file.writeUInt32LE(s.virtualSize ?? s.data.length, h + 8);
    file.writeUInt32LE(s.rva, h + 12);
    file.writeUInt32LE(s.rawSize ?? align(s.data.length, FILE_ALIGN), h + 16);
    file.writeUInt32LE(s.rawPointer ?? s.offset, h + 20);
    file.writeUInt32LE(0x40000040, h + 36);
    s.data.copy(file, s.offset);
  });
  return file;
};

let home: TempHome;
beforeAll(async () => {
  home = await createTempHome("pecaps");
});
afterAll(async () => {
  await home.cleanup();
});

const cache = new LruPeImageCache(process.platform === "win32" ? "win32" : "linux", 4);
const openPe = async (name: string, bytes: Buffer) => {
  const path = join(home.root, name);
  await writeFile(path, bytes);
  const opened = await cache.open(path);
  if (!opened.ok) throw new Error(JSON.stringify(opened.error));
  return { image: opened.value, path };
};

describe("PE reader aggregate caps (DATA-1)", () => {
  it("reads descriptors that share one thunk array once, and caps all import rows together", async () => {
    const THUNKS = 65_535;
    const rdata = Buffer.alloc(0x2000 + (THUNKS + 1) * 8 + 0x40);
    const thunksAt = 0x2000; // offset inside the section (rva 0x1000 + offset)
    for (let i = 0; i < THUNKS; i++) rdata.writeBigUInt64LE((1n << 63n) | BigInt(i + 1), thunksAt + i * 8);
    const nameAt = thunksAt + (THUNKS + 1) * 8;
    rdata.write("bomb.dll\0", nameAt, "latin1");
    const rva = (offset: number): number => 0x1000 + offset;
    // 64 identical descriptors (deduped to one) + 40 descriptors at shifted offsets of the same array
    let d = 0;
    const descriptor = (from: number): void => {
      rdata.writeUInt32LE(rva(from), d);
      rdata.writeUInt32LE(rva(nameAt), d + 12);
      rdata.writeUInt32LE(rva(from), d + 16);
      d += 20;
    };
    for (let k = 0; k < 64; k++) descriptor(thunksAt);
    for (let k = 1; k <= 40; k++) descriptor(thunksAt + k * 8);
    const bytes = buildPe([{ name: ".rdata", rva: 0x1000, data: rdata }], { 1: [0x1000, d + 20] });
    const { image } = await openPe("imports-bomb.dll", bytes);
    const started = performance.now();
    const imports = await image.imports();
    expect(performance.now() - started).toBeLessThan(20_000);
    // 65 535 (one read of the shared array) + capped shifted reads = the aggregate budget exactly
    expect(imports.length).toBe(1_048_576);
    const reasons = image.issues.map((i) => i.reason);
    expect(reasons).toContain("repeated import descriptor skipped");
    expect(reasons).toContain("aggregate cap reached");
  }, 60_000);

  it("ignores .pdata entries that lie in zero-fill instead of allocating them", async () => {
    const pdata = Buffer.alloc(0x200);
    // two real entries, then the directory claims 1 GiB of (zero-fill) entries
    pdata.writeUInt32LE(0x2000, 0);
    pdata.writeUInt32LE(0x2010, 4);
    pdata.writeUInt32LE(0, 8);
    pdata.writeUInt32LE(0x2010, 12);
    pdata.writeUInt32LE(0x2020, 16);
    const bytes = buildPe(
      [
        { name: ".pdata", rva: 0x1000, data: pdata, virtualSize: 0x4000_0000 },
        { name: ".text", rva: 0x4000_2000, data: Buffer.alloc(0x200, 0xc3) },
      ],
      { 3: [0x1000, 0x4000_0000] },
    );
    const { image } = await openPe("pdata-zero.dll", bytes);
    const before = process.memoryUsage().arrayBuffers;
    const table = await image.functions();
    expect(table.count).toBeLessThanOrEqual(0x200 / 12);
    expect(process.memoryUsage().arrayBuffers - before).toBeLessThan(64 * 1024 * 1024);
    expect(image.issues.map((i) => i.reason)).toContain("entries past the file-backed data ignored");
  });
});

describe("section headers (DATA-8)", () => {
  it("an empty section whose PointerToRawData is past EOF has no raw data and no issue", async () => {
    const bytes = buildPe(
      [
        { name: ".text", rva: 0x1000, data: Buffer.alloc(0x200, 0xc3) },
        { name: ".bss", rva: 0x2000, data: Buffer.alloc(0), virtualSize: 0x2000, rawPointer: 0x7fff_0000, rawSize: 0 },
      ],
      {},
    );
    const { image, path } = await openPe("bss.dll", bytes);
    const bss = image.headers.sections.find((s) => s.name === ".bss");
    expect(bss).toMatchObject({ raw_size: 0, raw_offset: 0 });
    expect(image.issues.filter((i) => i.table === "sections")).toEqual([]);
    expect((await image.readRva(0x2800, 4)).bytes).toEqual(Buffer.alloc(4));
    await rm(path, { force: true });
  });
});
