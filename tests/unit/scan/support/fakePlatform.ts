import { createReferenceKernels } from "../../../../src/agent/pure/scanReference.js";
import type { RawRange, ScanBuf, ScanKernels, ScanPlatform } from "../../../../src/agent/pure/scanTypes.js";

/**
 * WP10-SCAN test double: a fake target address space and the ScanPlatform the engine runs on (the agent binds
 * GumJS instead). Regions are byte arrays at fixed VAs; an "unreadable" region (or page) throws/answers null like a
 * freed page does under Frida.
 */
export interface FakeRegion {
  readonly base: number;
  readonly bytes: Uint8Array;
  readonly protection: string;
  readonly module: string | null;
  /** whole region unreadable (scanSync/findPointers throw, reads return null) */
  unreadable?: boolean;
  /** page bases that became unreadable */
  readonly deadPages?: Set<number>;
}

export class FakeMemory {
  readonly regions: FakeRegion[] = [];

  map(base: number, size: number, opts: Partial<Pick<FakeRegion, "protection" | "module">> = {}): FakeRegion {
    const region: FakeRegion = {
      base,
      bytes: new Uint8Array(size),
      protection: opts.protection ?? "rw-",
      module: opts.module ?? null,
      deadPages: new Set(),
    };
    this.regions.push(region);
    return region;
  }

  #locate(va: number, len: number): { region: FakeRegion; off: number } | null {
    for (const region of this.regions) {
      const off = va - region.base;
      if (off >= 0 && off + len <= region.bytes.length) return { region, off };
    }
    return null;
  }

  readable(va: number, len: number): boolean {
    const hit = this.#locate(va, len);
    if (hit === null || hit.region.unreadable === true) return false;
    for (let page = Math.floor(va / 4096) * 4096; page < va + len; page += 4096)
      if (hit.region.deadPages?.has(page) === true) return false;
    return true;
  }

  read(va: number, len: number): Uint8Array | null {
    if (len === 0) return new Uint8Array(0);
    if (!this.readable(va, len)) return null;
    const hit = this.#locate(va, len);
    return hit === null ? null : hit.region.bytes.slice(hit.off, hit.off + len);
  }

  write(va: number, data: Uint8Array): void {
    const hit = this.#locate(va, data.length);
    if (hit === null) throw new Error(`fake write outside mapped memory at 0x${va.toString(16)}`);
    hit.region.bytes.set(data, hit.off);
  }

  writeF32(va: number, x: number): void {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setFloat32(0, x, true);
    this.write(va, b);
  }
  writeF64(va: number, x: number): void {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setFloat64(0, x, true);
    this.write(va, b);
  }
  writeI32(va: number, x: number): void {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setInt32(0, x, true);
    this.write(va, b);
  }
  writeU64(va: number, x: number): void {
    const b = new Uint8Array(8);
    const v = new DataView(b.buffer);
    v.setUint32(0, x % 4_294_967_296, true);
    v.setUint32(4, Math.floor(x / 4_294_967_296), true);
    this.write(va, b);
  }
}

const PATTERN_TOKEN = /^[0-9a-fA-F?]{2}$/u;
/** Frida-compatible subset: hex, "??", nibble wildcards and ": mask". */
const compilePattern = (pattern: string): { value: number[]; mask: number[] } => {
  const [valuePart = "", maskPart] = pattern.split(":");
  const tokens = valuePart.trim().split(/\s+/u);
  if (tokens.length === 0 || !tokens.every((t) => PATTERN_TOKEN.test(t))) throw new Error("invalid match pattern");
  const value: number[] = [];
  const mask: number[] = [];
  for (const t of tokens) {
    const hi = t[0] === "?" ? 0 : Number.parseInt(t[0] ?? "0", 16);
    const lo = t[1] === "?" ? 0 : Number.parseInt(t[1] ?? "0", 16);
    value.push((hi << 4) | lo);
    mask.push((t[0] === "?" ? 0 : 0xf0) | (t[1] === "?" ? 0 : 0x0f));
  }
  if (maskPart !== undefined) {
    const m = maskPart
      .trim()
      .split(/\s+/u)
      .map((t) => Number.parseInt(t, 16));
    if (m.length !== tokens.length) throw new Error("invalid match pattern");
    m.forEach((x, i) => {
      mask[i] = (mask[i] ?? 0) & x;
      value[i] = (value[i] ?? 0) & x;
    });
  }
  return { value, mask };
};

export interface FakePlatform extends ScanPlatform {
  readonly suspended: { base: number; size: number }[];
  allocated: number;
  /** allocations fail once more than this many bytes are live (default: unlimited) */
  allocLimit: number;
  /** ms the fake clock advances per nowMs() call */
  tickMs: number;
  nowCalls: number;
}

export const createFakePlatform = (mem: FakeMemory, kernels?: ScanKernels): FakePlatform => {
  let clock = 0;
  const read = (va: number, len: number) => mem.read(va, len);
  const platform: FakePlatform = {
    suspended: [],
    allocated: 0,
    allocLimit: Number.POSITIVE_INFINITY,
    tickMs: 1,
    nowCalls: 0,
    nowMs: () => {
      platform.nowCalls += 1;
      clock += platform.tickMs;
      return clock;
    },
    nowUs: () => clock * 1000,
    alloc: (bytes: number): ScanBuf | null => {
      const n = Math.max(8, bytes);
      if (platform.allocated + n > platform.allocLimit) return null;
      platform.allocated += n;
      return { u8: new Uint8Array(n), bytes: n, native: null };
    },
    free: (buf) => {
      platform.allocated -= buf.bytes;
    },
    ranges: (protection: string): readonly RawRange[] =>
      mem.regions
        .filter((r) => [...protection].every((ch) => ch === "-" || r.protection.includes(ch)))
        .map((r) => ({ base: r.base, size: r.bytes.length, protection: r.protection, module: r.module })),
    scanPattern: (base, size, pattern) => {
      const { value, mask } = compilePattern(pattern);
      const data = mem.read(base, size);
      if (data === null) throw new Error(`access violation accessing 0x${base.toString(16)}`);
      const hits: number[] = [];
      for (let o = 0; o + value.length <= data.length; o++) {
        let ok = true;
        for (let k = 0; k < value.length && ok; k++) ok = ((data[o + k] ?? 0) & (mask[k] ?? 0)) === value[k];
        if (ok) hits.push(base + o);
      }
      return hits;
    },
    findPointers: (base, size, targets) => {
      const data = mem.read(base, size);
      if (data === null) throw new Error(`access violation accessing 0x${base.toString(16)}`);
      const view = new DataView(data.buffer);
      const out: { address: number; value: number }[] = [];
      for (let o = (8 - (base % 8)) % 8; o + 8 <= data.length; o += 8) {
        const v = view.getUint32(o, true) + view.getUint32(o + 4, true) * 4_294_967_296;
        if (targets.includes(v)) out.push({ address: base + o, value: v });
      }
      return out;
    },
    read,
    copyIn: (dst, dstOff, va, len) => {
      const data = mem.read(va, len);
      if (data === null) return false;
      dst.u8.set(data, dstOff);
      return true;
    },
    suspendGuards: (span, fn) => {
      platform.suspended.push({ base: span.base, size: span.size });
      return fn();
    },
    kernels: kernels ?? createReferenceKernels(read),
  };
  return platform;
};

/** Runs a job to completion; returns the number of step() calls. */
export const runToEnd = (
  work: { step(budgetMs: number): "more" | "done" },
  budgetMs = 8,
  maxSteps = 100_000,
): number => {
  for (let steps = 1; steps <= maxSteps; steps++) if (work.step(budgetMs) === "done") return steps;
  throw new Error("job did not finish");
};

export const LIMITS = {
  scan_max_concurrent: 8,
  scan_max_candidates: 4_194_304,
  scan_snapshot_bytes: 256 * 1024 * 1024,
  scan_page_rows: 1000,
};
