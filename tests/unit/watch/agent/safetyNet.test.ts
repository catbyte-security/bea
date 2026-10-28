import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { fixtureToolchain } from "../../../../scripts/lib/fixtures.mjs";
import {
  SAFETY_NET_ALLOC_BYTES,
  SAFETY_NET_CODE,
  SAFETY_NET_CODE_HEX,
  SAFETY_NET_DATA_OFFSET,
  SAFETY_NET_LAYOUT,
  SAFETY_NET_MAGIC,
} from "../../../../src/agent/pure/watchSafetyNetCode.js";
import { gccSkip, skipNote } from "../../../support/acceptance/fixtures.js";

const SOURCE = join(import.meta.dirname, "safetyNet.S");

/** The raw .text section of an x64 COFF object: 20-byte file header, optional header, 40-byte section headers. */
const coffText = (obj: Uint8Array): Uint8Array => {
  const dv = new DataView(obj.buffer, obj.byteOffset, obj.byteLength);
  const sections = dv.getUint16(2, true);
  const first = 20 + dv.getUint16(16, true);
  for (let i = 0; i < sections; i++) {
    const at = first + i * 40;
    const name = new TextDecoder().decode(obj.subarray(at, at + 8)).replace(/\0+$/u, "");
    if (name !== ".text") continue;
    const size = dv.getUint32(at + 16, true);
    const raw = dv.getUint32(at + 20, true);
    return obj.subarray(raw, raw + size);
  }
  throw new Error("the object has no .text section");
};

/** The fixtures' gcc (WinLibs on this host, CC overrides; a named skip elsewhere) assembles the source. */
const assemble = (): Uint8Array => {
  const toolchain = fixtureToolchain();
  if ("unavailable" in toolchain) throw new Error(toolchain.unavailable);
  const dir = mkdtempSync(join(tmpdir(), "bea-wp9-asm-"));
  try {
    const obj = join(dir, "sn.o");
    const cc = spawnSync(toolchain.cc.command, ["-c", "-x", "assembler-with-cpp", SOURCE, "-o", obj], {
      encoding: "utf8",
      windowsHide: true,
    });
    if (cc.status !== 0) throw new Error(`assembling failed: ${cc.stderr}`);
    return coffText(new Uint8Array(readFileSync(obj)));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
};

describe("attached-session safety net code (DESIGN §5.3, CT-I4)", () => {
  it(`matches the assembled source byte for byte${skipNote(gccSkip())}`, ({ skip }) => {
    if (gccSkip() !== false) skip();
    const built = assemble();
    expect([...built.subarray(0, SAFETY_NET_CODE.length)]).toEqual([...SAFETY_NET_CODE]);
    expect([...built.subarray(SAFETY_NET_CODE.length)].every((b) => b === 0x90)).toBe(true); // section padding
  });

  it("fits its page and addresses the data page one page later", () => {
    expect(SAFETY_NET_CODE.length).toBe(SAFETY_NET_CODE_HEX.length / 2);
    expect(SAFETY_NET_CODE.length).toBeLessThan(SAFETY_NET_DATA_OFFSET);
    expect(SAFETY_NET_ALLOC_BYTES).toBe(2 * SAFETY_NET_DATA_OFFSET);
    // 07: lea r9,[rip+disp32]; rip = 0x0e, so disp32 must be 0x1000 - 0x0e
    const lea = SAFETY_NET_CODE.subarray(7, 14);
    expect([...lea.subarray(0, 3)]).toEqual([0x4c, 0x8d, 0x0d]);
    expect(new DataView(lea.buffer, lea.byteOffset + 3, 4).getInt32(0, true)).toBe(SAFETY_NET_DATA_OFFSET - 0x0e);
  });

  it("uses the data-page offsets the agent writes", () => {
    const code = SAFETY_NET_CODE;
    const at = (bytes: number[]): number => {
      for (let i = 0; i + bytes.length <= code.length; i++) if (bytes.every((b, k) => code[i + k] === b)) return i;
      return -1;
    };
    expect(at([0x45, 0x8b, 0x59, SAFETY_NET_LAYOUT.slotMask])).toBeGreaterThan(0); // mov r11d,[r9+slot_mask]
    expect(at([0x4d, 0x8b, 0x51, SAFETY_NET_LAYOUT.dr7Clear])).toBeGreaterThan(0); // mov r10,[r9+dr7_clear]
    expect(at([0x41, 0x8b, 0x49, SAFETY_NET_LAYOUT.nTf])).toBeGreaterThan(0); // mov ecx,[r9+n_tf]
    expect(at([0x41, 0x8b, 0x49, SAFETY_NET_LAYOUT.nGuard])).toBeGreaterThan(0); // mov ecx,[r9+n_guard]
    expect(at([0x4d, 0x8d, 0x59, SAFETY_NET_LAYOUT.guardPages])).toBeGreaterThan(0); // lea r11,[r9+guard_pages]
    expect(at([0x4d, 0x8d, 0x99, 0x40, 0x02, 0x00, 0x00])).toBeGreaterThan(0); // lea r11,[r9+0x240] tf_tids
    expect(SAFETY_NET_LAYOUT.tfTids).toBe(0x240);
    for (const counter of [SAFETY_NET_LAYOUT.hitsDr, SAFETY_NET_LAYOUT.hitsTf, SAFETY_NET_LAYOUT.hitsGuard])
      expect(at([0xf0, 0x49, 0xff, 0x41, counter])).toBeGreaterThan(0); // lock inc qword [r9+counter]
    expect(SAFETY_NET_LAYOUT.guardPages + 64 * 8).toBeLessThanOrEqual(SAFETY_NET_LAYOUT.tfTids);
    expect(SAFETY_NET_LAYOUT.tfTids + 64 * 4).toBeLessThanOrEqual(SAFETY_NET_DATA_OFFSET);
    expect(SAFETY_NET_MAGIC).toBe(0x53414542);
  });
});
