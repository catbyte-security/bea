import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, describe, expect, it } from "vitest";

import { ARG, ARGS_BYTES, SCAN_KERNEL_SOURCE } from "../../../src/agent/pure/scanKernelSource.js";
import { addrAt, createReferenceKernels, setAddrAt } from "../../../src/agent/pure/scanReference.js";
import {
  OP_CODE,
  type Bits64,
  type KernelOp,
  type KernelSpec,
  type ScanBuf,
} from "../../../src/agent/pure/scanTypes.js";
import { fixtureToolchain } from "../../../scripts/lib/fixtures.mjs";
import { gccSkip, skipNote } from "../../support/acceptance/fixtures.js";
import { FakeMemory } from "./support/fakePlatform.js";

/**
 * WP10-SCAN (S4 §9.4 "C kernels are tested on the host by compiling the same C with gcc against a tiny shim"): the
 * CModule source is compiled with gcc into a harness that runs batched kernel calls on images the test lays out; every
 * call is compared field by field with the JS reference kernels (scanReference.ts), for all value types and ops.
 */
const HARNESS_MAIN = String.raw`
#include <stdio.h>
#include <stdlib.h>
int main (int argc, char ** argv)
{
  FILE * in, * out;
  u64 hdr[3];
  if (argc < 3) return 2;
  in = fopen (argv[1], "rb");
  out = fopen (argv[2], "wb");
  if (in == 0 || out == 0) return 2;
  while (fread (hdr, 8, 3, in) == 3) {
    BeaScanArgs a;
    u8 * raw;
    u64 base, i, n;
    u64 * addrs;
    if (fread (&a, sizeof a, 1, in) != 1) return 3;
    raw = (u8 *) malloc (hdr[1] + 64);
    base = ((u64) raw + 63) & ~(u64) 63;
    if (fread ((u8 *) base, 1, hdr[1], in) != hdr[1]) return 4;
    a.p += base; a.addrs += base; a.vals += base; a.snap += base; a.operand += base;
    a.firsts = a.firsts == (u64) -1 ? 0 : a.firsts + base;
    addrs = (u64 *) a.addrs;
    for (i = 0; i < hdr[2]; i++) addrs[i] += base;
    if (hdr[0] == 0) bea_scan_cmp (&a); else if (hdr[0] == 1) bea_scan_next (&a); else bea_scan_snap (&a);
    n = a.at > hdr[2] ? a.at : hdr[2];
    for (i = 0; i < n; i++) addrs[i] -= base;
    fwrite (&a.at, 8, 1, out);
    fwrite (&a.progress, 8, 1, out);
    fwrite ((u8 *) base, 1, hdr[1], out);
    free (raw);
  }
  fclose (out);
  return 0;
}
`;

// ---------------------------------------------------------------- deterministic inputs
let seed = 0x5eed_1234;
const rand = (): number => {
  seed ^= seed << 13;
  seed ^= seed >>> 17;
  seed ^= seed << 5;
  return (seed >>> 0) / 4_294_967_296;
};
const pick = <T>(xs: readonly T[]): T => xs[Math.floor(rand() * xs.length)] as T;

interface VtInfo {
  readonly vt: number;
  readonly elem: number;
  readonly pool: readonly (bigint | number)[];
}
const F32_POOL = [0, -0, 1.5, -2.25, 20, 24.000001, Number.NaN, Infinity, -Infinity, 1e-40, 3.4e38];
const F64_POOL = [0, -0, 1.5, -2.25, 20, 24.000000001, Number.NaN, Infinity, -Infinity, 5e-324, 1.7e308];
const VTS: readonly VtInfo[] = [
  { vt: 0, elem: 1, pool: [-128n, -1n, 0n, 1n, 5n, 127n] },
  { vt: 1, elem: 1, pool: [0n, 1n, 5n, 200n, 255n] },
  { vt: 2, elem: 2, pool: [-32_768n, -7n, 0n, 7n, 32_767n] },
  { vt: 3, elem: 2, pool: [0n, 7n, 40_000n, 65_535n] },
  { vt: 4, elem: 4, pool: [-2_147_483_648n, -100n, 0n, 100n, 2_147_483_647n] },
  { vt: 5, elem: 4, pool: [0n, 100n, 3_000_000_000n, 4_294_967_295n] },
  { vt: 6, elem: 8, pool: [-(1n << 63n), -5n, 0n, 5n, (1n << 63n) - 1n] },
  { vt: 7, elem: 8, pool: [0n, 5n, 1n << 63n, (1n << 64n) - 1n] },
  { vt: 8, elem: 4, pool: F32_POOL },
  { vt: 9, elem: 8, pool: F64_POOL },
  { vt: 10, elem: 8, pool: [0n, 0x7ff7_1234_5678n, (1n << 64n) - 1n] },
];
const SIGNED = new Set([0, 2, 4, 6]);

const bytesOf = (info: VtInfo, v: bigint | number): Uint8Array => {
  const out = new Uint8Array(info.elem);
  const view = new DataView(out.buffer);
  if (info.vt === 8) view.setFloat32(0, v as number, true);
  else if (info.vt === 9) view.setFloat64(0, v as number, true);
  else {
    let u = BigInt.asUintN(64, v as bigint);
    for (let i = 0; i < info.elem; i++) {
      out[i] = Number(u & 0xffn);
      u >>= 8n;
    }
  }
  return out;
};
const bitsOf = (info: VtInfo, v: bigint | number): Bits64 => {
  const b = new Uint8Array(8);
  if (info.vt === 8 || info.vt === 9) b.set(bytesOf(info, v));
  else {
    const u = BigInt.asUintN(64, SIGNED.has(info.vt) ? BigInt.asIntN(info.elem * 8, v as bigint) : (v as bigint));
    new DataView(b.buffer).setBigUint64(0, u, true);
  }
  const view = new DataView(b.buffer);
  return { lo: view.getUint32(0, true), hi: view.getUint32(4, true) };
};

// ---------------------------------------------------------------- cases
const VA = 0x1000_0000;
interface Case {
  readonly kind: 0 | 1 | 2;
  readonly spec: KernelSpec;
  readonly cur: Uint8Array;
  readonly old: Uint8Array | null;
  /** next: candidate element offsets with their previous values (from `old`) */
  readonly cands: readonly number[];
  readonly cap: number;
  readonly firsts: boolean;
  readonly len: number;
  readonly label: string;
}

const memoryOf = (info: VtInfo, n: number): Uint8Array => {
  const mem = new Uint8Array(n * info.elem + 3);
  for (let i = 0; i < n; i++) mem.set(bytesOf(info, pick(info.pool)), i * info.elem);
  for (let i = n * info.elem; i < mem.length; i++) mem[i] = Math.floor(rand() * 256);
  return mem;
};
const mutate = (info: VtInfo, mem: Uint8Array, n: number): Uint8Array => {
  const out = mem.slice();
  for (let i = 0; i < n; i++) if (rand() < 0.5) out.set(bytesOf(info, pick(info.pool)), i * info.elem);
  return out;
};

const FIRST_OPS: readonly KernelOp[] = ["eq", "ne", "approx", "gt", "lt", "range"];
const NEXT_OPS: readonly KernelOp[] = [
  "eq",
  "ne",
  "approx",
  "gt",
  "lt",
  "range",
  "changed",
  "unchanged",
  "increased",
  "decreased",
  "increased_by",
  "decreased_by",
  "same_as_first",
];

const specOf = (info: VtInfo, op: KernelOp, align: number, eps: number): KernelSpec => {
  const a = pick(info.pool);
  const b = pick(info.pool);
  return {
    vt: info.vt,
    elem: info.elem,
    align,
    op,
    a: bitsOf(info, a),
    b: bitsOf(info, b),
    eps,
    operand: bytesOf(info, a),
  };
};

const buildCases = (): Case[] => {
  const cases: Case[] = [];
  const n = 64;
  for (const info of VTS) {
    const float = info.vt === 8 || info.vt === 9;
    for (let round = 0; round < 3; round++) {
      const cur = memoryOf(info, n);
      for (const op of float ? [...FIRST_OPS, "eq_bits" as const] : FIRST_OPS)
        for (const align of [info.elem, 1]) {
          const eps = op === "approx" ? pick([0, 0.5, 3, 1e30]) : 0;
          const cap = pick([1000, 7]);
          cases.push({
            kind: 0,
            spec: specOf(info, op, align, eps),
            cur,
            old: null,
            cands: [],
            cap,
            firsts: false,
            len: cur.length,
            label: `cmp vt${info.vt} ${op} a${align}`,
          });
        }
      const old = memoryOf(info, n);
      const now = mutate(info, old, n);
      const cands = Array.from({ length: n }, (_, i) => i * info.elem).filter(() => rand() < 0.8);
      for (const op of NEXT_OPS)
        for (const eps of float ? [0, 0.5] : [0, 2]) {
          const spec = specOf(info, op, info.elem, eps);
          cases.push({
            kind: 1,
            spec,
            cur: now,
            old,
            cands,
            cap: n,
            firsts: true,
            len: now.length,
            label: `next vt${info.vt} ${op} eps${eps}`,
          });
          cases.push({
            kind: 2,
            spec,
            cur: now,
            old,
            cands: [],
            cap: pick([n * 2, 5]),
            firsts: true,
            len: n * info.elem,
            label: `snap vt${info.vt} ${op} eps${eps}`,
          });
        }
    }
  }
  // byte strings (vt 11): memcmp ops
  const bytesInfo = { vt: 11, elem: 3, pool: [] } as const;
  const cur = new Uint8Array(96).map(() => pick([0xaa, 0xbb, 0xcc]));
  const old = cur.map((x) => (rand() < 0.3 ? pick([0xaa, 0xbb]) : x));
  for (const op of ["eq", "ne", "changed", "unchanged", "same_as_first"] as const) {
    const spec: KernelSpec = {
      vt: 11,
      elem: bytesInfo.elem,
      align: 1,
      op,
      a: { lo: 0, hi: 0 },
      b: { lo: 0, hi: 0 },
      eps: 0,
      operand: Uint8Array.from([0xaa, 0xbb, 0xaa]),
    };
    if (op === "eq" || op === "ne")
      cases.push({
        kind: 0,
        spec,
        cur,
        old: null,
        cands: [],
        cap: 1000,
        firsts: false,
        len: cur.length,
        label: `cmp bytes ${op}`,
      });
    cases.push({
      kind: 1,
      spec,
      cur,
      old,
      cands: Array.from({ length: 30 }, (_, i) => i * 3),
      cap: 30,
      firsts: true,
      len: cur.length,
      label: `next bytes ${op}`,
    });
    cases.push({ kind: 2, spec, cur, old, cands: [], cap: 200, firsts: true, len: 90, label: `snap bytes ${op}` });
  }
  return cases;
};

// ---------------------------------------------------------------- image layout shared by both sides
const align64 = (n: number): number => Math.ceil(n / 64) * 64;
interface Layout {
  readonly mem: number;
  readonly addrs: number;
  readonly vals: number;
  readonly firsts: number;
  readonly snap: number;
  readonly operand: number;
  readonly total: number;
}
const layoutOf = (c: Case): Layout => {
  const mem = 0;
  const addrs = align64(c.cur.length);
  const vals = align64(addrs + c.cap * 8);
  const firsts = align64(vals + c.cap * c.spec.elem);
  const snap = align64(firsts + c.cap * c.spec.elem);
  const operand = align64(snap + c.cur.length);
  return { mem, addrs, vals, firsts, snap, operand, total: operand + 256 };
};

const bufAt = (image: Uint8Array, off: number, bytes: number): ScanBuf => ({
  u8: image.subarray(off, off + bytes),
  bytes,
  native: null,
});

/** The initial image (both sides start from it) with candidate addresses given by `addrOf(offset)`. */
const imageOf = (c: Case, l: Layout, addrOf: (off: number) => number): Uint8Array => {
  const image = new Uint8Array(l.total);
  image.set(c.cur, l.mem);
  if (c.old !== null) image.set(c.old, l.snap);
  image.set(c.spec.operand ?? new Uint8Array(0), l.operand);
  const addrs = bufAt(image, l.addrs, c.cap * 8);
  c.cands.forEach((off, i) => {
    setAddrAt(addrs, i, addrOf(off));
    const old = (c.old ?? c.cur).subarray(off, off + c.spec.elem);
    image.set(old, l.vals + i * c.spec.elem);
    image.set(old, l.firsts + i * c.spec.elem);
  });
  return image;
};

const encodeArgs = (c: Case, l: Layout): Uint8Array => {
  const out = new Uint8Array(ARGS_BYTES);
  const v = new DataView(out.buffer);
  const u64 = (at: number, x: number | bigint): void => v.setBigUint64(at, BigInt(x), true);
  const bits = (at: number, b: Bits64): void => {
    v.setUint32(at, b.lo >>> 0, true);
    v.setUint32(at + 4, b.hi >>> 0, true);
  };
  u64(ARG.p, l.mem);
  u64(ARG.len, c.len);
  u64(ARG.avail, c.cur.length);
  u64(ARG.vt, c.spec.vt);
  u64(ARG.elem, c.spec.elem);
  u64(ARG.align, c.spec.align);
  u64(ARG.op, OP_CODE[c.spec.op]);
  bits(ARG.a, c.spec.a);
  bits(ARG.b, c.spec.b);
  v.setFloat64(ARG.eps, c.spec.eps, true);
  u64(ARG.epsi, c.spec.eps >= 2 ** 64 ? (1n << 64n) - 1n : BigInt(Math.floor(c.spec.eps)));
  u64(ARG.addrs, l.addrs);
  u64(ARG.vals, l.vals);
  u64(ARG.firsts, c.firsts ? BigInt(l.firsts) : (1n << 64n) - 1n);
  u64(ARG.at, 0);
  u64(ARG.cap, c.cap);
  u64(ARG.progress, 0);
  u64(ARG.snap, l.snap);
  u64(ARG.operand, l.operand);
  u64(ARG.end, c.cands.length);
  return out;
};

interface Observed {
  readonly at: number;
  readonly progress: number;
  readonly addrs: number[];
  readonly vals: string;
  readonly firsts: string;
}
const observe = (
  c: Case,
  l: Layout,
  image: Uint8Array,
  at: number,
  progress: number,
  offsetOf: (a: number) => number,
): Observed => {
  const addrs = bufAt(image, l.addrs, c.cap * 8);
  const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
  return {
    at,
    progress,
    addrs: Array.from({ length: at }, (_, i) => offsetOf(addrAt(addrs, i))),
    vals: hex(image.subarray(l.vals, l.vals + at * c.spec.elem)),
    firsts: c.firsts ? hex(image.subarray(l.firsts, l.firsts + at * c.spec.elem)) : "",
  };
};

const reference = (c: Case): Observed => {
  const l = layoutOf(c);
  const image = imageOf(c, l, (off) => VA + off);
  const mem = new FakeMemory();
  mem.map(VA, c.cur.length).bytes.set(c.cur);
  const k = createReferenceKernels((va, len) => mem.read(va, len));
  const out = {
    addrs: bufAt(image, l.addrs, c.cap * 8),
    vals: bufAt(image, l.vals, c.cap * c.spec.elem),
    firsts: c.firsts ? bufAt(image, l.firsts, c.cap * c.spec.elem) : null,
    cap: c.cap,
  };
  const r =
    c.kind === 0
      ? k.cmp(c.spec, { va: VA, len: c.len, avail: c.cur.length, progress: 0, out, at: 0 })
      : c.kind === 1
        ? k.next(c.spec, { store: out, progress: 0, end: c.cands.length, kept: 0 })
        : k.snap(c.spec, {
            va: VA,
            snap: bufAt(image, l.snap, c.cur.length),
            snapOff: 0,
            len: c.len,
            avail: c.cur.length,
            progress: 0,
            out,
            at: 0,
          });
  return observe(c, l, image, r.at, r.progress, (a) => a - VA);
};

const work = mkdtempSync(join(tmpdir(), "bea-scan-kernels-"));
afterAll(() => rmSync(work, { recursive: true, force: true }));

describe("scan kernels: gcc-compiled C == JS reference", () => {
  const skip = gccSkip();
  it.skipIf(skip !== false)(
    `every value type and op, cmp/next/snap, including out-of-space stops${skipNote(skip)}`,
    () => {
      const harness = join(work, "kernels.c");
      const exe = join(work, "kernels.exe");
      writeFileSync(harness, `${SCAN_KERNEL_SOURCE}\n${HARNESS_MAIN}`);
      const toolchain = fixtureToolchain();
      if ("unavailable" in toolchain) throw new Error(toolchain.unavailable);
      const cc = spawnSync(
        toolchain.cc.path,
        [
          "-O1",
          "-fno-strict-aliasing",
          "-Wall",
          "-Wno-unused-variable",
          "-Wno-unused-but-set-variable",
          "-o",
          exe,
          harness,
        ],
        { encoding: "utf8" },
      );
      expect(cc.status, cc.stderr).toBe(0);
      expect(cc.stderr.trim(), "gcc warnings").toBe("");
      const cases = buildCases();
      const layouts = cases.map(layoutOf);
      const chunks: Uint8Array[] = [];
      cases.forEach((c, i) => {
        const l = layouts[i] as Layout;
        const hdr = new Uint8Array(24);
        const hv = new DataView(hdr.buffer);
        hv.setBigUint64(0, BigInt(c.kind), true);
        hv.setBigUint64(8, BigInt(l.total), true);
        hv.setBigUint64(16, BigInt(c.kind === 1 ? c.cands.length : 0), true);
        chunks.push(
          hdr,
          encodeArgs(c, l),
          imageOf(c, l, (off) => l.mem + off),
        );
      });
      writeFileSync(join(work, "in.bin"), Buffer.concat(chunks));
      const run = spawnSync(exe, [join(work, "in.bin"), join(work, "out.bin")], { encoding: "utf8" });
      expect(run.status, run.stderr).toBe(0);
      const out = readFileSync(join(work, "out.bin"));
      let pos = 0;
      let hits = 0;
      cases.forEach((c, i) => {
        const l = layouts[i] as Layout;
        const at = Number(out.readBigUInt64LE(pos));
        const progress = Number(out.readBigUInt64LE(pos + 8));
        const image = new Uint8Array(out.subarray(pos + 16, pos + 16 + l.total));
        pos += 16 + l.total;
        const native = observe(c, l, image, at, progress, (a) => a - l.mem);
        expect(native, c.label).toEqual(reference(c));
        hits += at;
      });
      expect(pos).toBe(out.length);
      expect(cases.length).toBeGreaterThan(500);
      expect(hits).toBeGreaterThan(1000); // the generated cases do match, not only reject
    },
  );
});
