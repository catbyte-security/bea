// WP3-AGENT unit tests: overlay-aware decoding fix-ups and access-instruction recovery (S4 §8.4) with a fake decoder,
// and PE32+ facts read from a MAPPED image (S4 §8.1): headers, raw section names, .pdata (sorted, chained flag),
// CodeView RSDS, TLS callbacks, delay imports; the committed PE32 header is refused.
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";

import { describe, expect, it } from "vitest";

import {
  backScan,
  branchTargetInPlace,
  isRelativeBranch,
  overlayBytes,
  recoverAccessInsn,
  relocateDecoded,
  sweepToPc,
  type DecodedInsn,
} from "../../../../src/agent/pure/coreDisasm.js";
import {
  DATA_DIR,
  guidText,
  isChainedUnwind,
  parseCodeView,
  parseDelayImports,
  parseHeaders,
  parsePdata,
  parseSections,
  parseTlsCallbacks,
  readCString,
  type RvaReader,
} from "../../../../src/agent/pure/corePe.js";

const insn = (over: Partial<DecodedInsn>): DecodedInsn => ({
  size: 5,
  mnemonic: "call",
  opStr: "0x10000105",
  groups: ["call", "branch_relative"],
  imms: [0x10000105n],
  ...over,
});

describe("overlay decoding fix-ups", () => {
  it("relocates relative branches decoded in scratch back to the real address", () => {
    const d = insn({});
    expect(isRelativeBranch(d)).toBe(true);
    // decoded at scratch 0x10000100 → target scratch+5; the real instruction is at 0x7ff6aa001760
    expect(relocateDecoded(d, 0x10000100n, 0x7ff6aa001760n)).toEqual({
      opStr: "0x7ff6aa001765",
      branchTarget: 0x7ff6aa001765n,
    });
    const mov = insn({ mnemonic: "mov", opStr: "eax, dword ptr [rip + 0x2b]", groups: ["mode64"], imms: [] });
    expect(relocateDecoded(mov, 1n, 2n)).toEqual({ opStr: "eax, dword ptr [rip + 0x2b]", branchTarget: null });
    const indirect = insn({ opStr: "qword ptr [rip + 0x10]", imms: [] });
    expect(isRelativeBranch(indirect)).toBe(false);
    expect(
      branchTargetInPlace(
        insn({ mnemonic: "jne", opStr: "0x1810", groups: ["jump", "branch_relative"], imms: [0x1810n] }),
      ),
    ).toBe(0x1810n);
  });

  it("overlays original bytes only inside the window", () => {
    const live = new Uint8Array([0xe9, 0x11, 0x22, 0x33, 0x44, 0x90, 0x90, 0x90]);
    const o = overlayBytes(live, 0x1000n, [
      { address: 0xffen, bytes: new Uint8Array([0xaa, 0xbb, 0x48, 0x89, 0x5c]) },
      { address: 0x2000n, bytes: new Uint8Array([1]) },
    ]);
    expect([...o.bytes]).toEqual([0x48, 0x89, 0x5c, 0x33, 0x44, 0x90, 0x90, 0x90]);
    expect(o.changed).toBe(true);
    expect(overlayBytes(live, 0x1000n, []).changed).toBe(false);
  });

  // a tiny fake ISA: instruction sizes by address (the decoder is Instruction.parse in the agent)
  const sizes = new Map<bigint, number>([
    [0x1760n, 1],
    [0x1761n, 3],
    [0x1764n, 4],
    [0x1768n, 2],
    [0x176an, 3],
  ]);
  const decode = (a: bigint): number | null => sizes.get(a) ?? null;

  it("recovers the accessing instruction by a sweep from the function start (trap-after pc)", () => {
    expect(sweepToPc(decode, 0x1760n, 0x176an)).toBe(0x1768n);
    expect(sweepToPc(decode, 0x1760n, 0x1769n)).toBeNull(); // pc inside an instruction
    expect(recoverAccessInsn(decode, 0x1768n, 0x1760n)).toEqual({ address: 0x1764n, size: 4, conf: "swept" });
  });

  it("falls back to a back-scan: one candidate → heuristic, none or several → unknown", () => {
    expect(backScan(decode, 0x176dn)).toEqual({ address: 0x176an, size: 3, conf: "heuristic" });
    const ambiguous = (a: bigint): number | null => (a === 0x2000n - 2n ? 2 : a === 0x2000n - 4n ? 4 : null);
    expect(backScan(ambiguous, 0x2000n)).toEqual({ address: null, size: null, conf: "unknown" });
    expect(recoverAccessInsn(decode, 0x176dn, null)).toMatchObject({ conf: "heuristic" });
    expect(recoverAccessInsn(() => null, 0x9000n, 0x8000n)).toMatchObject({ conf: "unknown" });
  });
});

/** A synthetic mapped PE32+ image (offset = RVA). */
const buildImage = (): Uint8Array => {
  const img = new Uint8Array(0x3000);
  const dv = new DataView(img.buffer);
  img[0] = 0x4d;
  img[1] = 0x5a;
  dv.setUint32(0x3c, 0x80, true);
  dv.setUint32(0x80, 0x4550, true); // "PE\0\0"
  dv.setUint16(0x84, 0x8664, true);
  dv.setUint16(0x86, 2, true); // sections
  dv.setUint32(0x88, 0x12345678, true);
  dv.setUint16(0x94, 0xf0, true); // SizeOfOptionalHeader
  const opt = 0x98;
  dv.setUint16(opt, 0x20b, true);
  dv.setUint32(opt + 0x10, 0x1010, true); // entry
  dv.setBigUint64(opt + 0x18, 0x7ff6aa000000n, true); // ImageBase (rewritten by the loader)
  dv.setUint32(opt + 0x38, 0x3000, true);
  dv.setUint32(opt + 0x40, 0xbeef, true);
  dv.setUint16(opt + 0x44, 3, true);
  dv.setUint16(opt + 0x46, 0x160, true);
  dv.setUint32(opt + 0x6c, 16, true);
  const dir = (i: number, rva: number, size: number): void => {
    dv.setUint32(opt + 0x70 + 8 * i, rva, true);
    dv.setUint32(opt + 0x74 + 8 * i, size, true);
  };
  dir(DATA_DIR.exception, 0x2000, 24);
  dir(DATA_DIR.debug, 0x2100, 28);
  dir(DATA_DIR.tls, 0x2200, 0x28);
  dir(DATA_DIR.delayImport, 0x2300, 64);
  const sec = opt + 0xf0;
  for (const [i, name, rva, vsize, ch] of [
    [0, ".text", 0x1000, 0x800, 0x60000020],
    [1, "/4", 0x2000, 0x1000, 0x40000040],
  ] as const) {
    for (let j = 0; j < name.length; j++) img[sec + 40 * i + j] = name.charCodeAt(j);
    dv.setUint32(sec + 40 * i + 8, vsize, true);
    dv.setUint32(sec + 40 * i + 0xc, rva, true);
    dv.setUint32(sec + 40 * i + 0x24, ch, true);
  }
  // .pdata: two RUNTIME_FUNCTIONs; the second's unwind info is chained
  for (const [i, b, e, u] of [
    [0, 0x1000, 0x1017, 0x2800],
    [1, 0x1017, 0x1030, 0x2808],
  ] as const) {
    dv.setUint32(0x2000 + 12 * i, b, true);
    dv.setUint32(0x2004 + 12 * i, e, true);
    dv.setUint32(0x2008 + 12 * i, u, true);
  }
  img[0x2800] = 0x01;
  img[0x2808] = 0x01 | (4 << 3);
  // debug directory → RSDS
  dv.setUint32(0x2100 + 0xc, 2, true);
  dv.setUint32(0x2100 + 0x14, 0x2400, true);
  img.set([0x52, 0x53, 0x44, 0x53], 0x2400);
  img.set([0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 1, 2, 3, 4, 5, 6, 7, 8], 0x2404);
  dv.setUint32(0x2414, 3, true);
  img.set([...Buffer.from("C:\\b\\game.pdb\0")], 0x2418);
  // TLS directory → callback array VA (image base 0x7ff6aa000000)
  dv.setBigUint64(0x2200 + 0x18, 0x7ff6aa002500n, true);
  dv.setBigUint64(0x2500, 0x7ff6aa001100n, true);
  dv.setBigUint64(0x2508, 0x7ff6aa001200n, true);
  // delay imports: one RVA-form descriptor for "mathlib.dll" with a by-name and a by-ordinal entry
  dv.setUint32(0x2300, 1, true);
  dv.setUint32(0x2304, 0x2600, true);
  dv.setUint32(0x230c, 0x2700, true);
  dv.setUint32(0x2310, 0x2680, true);
  img.set([...Buffer.from("mathlib.dll\0")], 0x2600);
  dv.setBigUint64(0x2680, 0x2640n, true);
  dv.setBigUint64(0x2688, (1n << 63n) | 7n, true);
  img.set([0, 0, ...Buffer.from("mf_lerp\0")], 0x2640);
  return img;
};

const readerOf =
  (img: Uint8Array): RvaReader =>
  (rva, len) =>
    rva < 0 || rva + len > img.length ? null : img.slice(rva, rva + len);

describe("PE32+ facts from a mapped image", () => {
  const img = buildImage();
  const read = readerOf(img);
  const parsed = parseHeaders(read);

  it("parses the headers and raw section names", () => {
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.headers).toMatchObject({
      machine: 0x8664,
      numberOfSections: 2,
      timeDateStamp: 0x12345678,
      entryRva: 0x1010,
      imageBase: 0x7ff6aa000000n,
      sizeOfImage: 0x3000,
      checksum: 0xbeef,
      subsystem: 3,
      dllCharacteristics: 0x160,
    });
    expect(parseSections(read, parsed.headers).map((s) => [s.rawName, s.rva, s.virtualSize])).toEqual([
      [".text", 0x1000, 0x800],
      ["/4", 0x2000, 0x1000],
    ]);
  });

  it("reads .pdata, the chained flag, CodeView, TLS callbacks and delay imports", () => {
    if (!parsed.ok) throw new Error("headers");
    const h = parsed.headers;
    const p = parsePdata(read, h);
    expect([...p.begins]).toEqual([0x1000, 0x1017]);
    expect([...p.ends]).toEqual([0x1017, 0x1030]);
    expect(isChainedUnwind(read, p.unwinds[0]!)).toBe(false);
    expect(isChainedUnwind(read, p.unwinds[1]!)).toBe(true);
    expect(parseCodeView(read, h)).toEqual({
      guid: "12345678-1234-5678-0102-030405060708",
      age: 3,
      pdb: "C:\\b\\game.pdb",
    });
    expect(parseTlsCallbacks(read, h, 0x7ff6aa000000n)).toEqual([0x7ff6aa001100n, 0x7ff6aa001200n]);
    expect(parseTlsCallbacks(read, h, 0x10000n)).toEqual([]); // array VA outside the image
    expect(parseDelayImports(read, h)).toEqual([
      { dll: "mathlib.dll", name: "mf_lerp", ordinal: null, slotRva: 0x2700 },
      { dll: "mathlib.dll", name: null, ordinal: 7, slotRva: 0x2708 },
    ]);
    expect(guidText(new Uint8Array(16))).toBe("00000000-0000-0000-0000-000000000000");
    expect(readCString(read, 0x2600)).toBe("mathlib.dll");
    expect(readCString(read, 0x9999)).toBeNull();
  });

  it("refuses non-PE and PE32 images", () => {
    expect(parseHeaders(() => null)).toEqual({ ok: false, reason: "unreadable" });
    expect(parseHeaders(readerOf(new Uint8Array(0x400)))).toEqual({ ok: false, reason: "not-pe" });
    const pe32 = readFileSync(
      join(resolve(import.meta.dirname, "..", "..", "..", ".."), "fixtures", "golden", "pe32-minimal.bin"),
    );
    expect(parseHeaders(readerOf(new Uint8Array(pe32)))).toEqual({ ok: false, reason: "not-pe32plus" });
  });
});
