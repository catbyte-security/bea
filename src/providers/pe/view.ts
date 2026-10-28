import type { FileReader } from "./fileAccess.js";
import { locateRva, segmentRange, type PeHeaders } from "./headers.js";

/**
 * Synchronous rva accessors over lazily loaded segments (headers / one section's raw data). A table parser runs
 * synchronously; touching a segment that is not loaded throws NeedSegment, runTable() loads it with one positioned
 * read and re-runs the parser. A parse touches only a handful of segments (e.g. .rdata + .pdata + .xdata), so the
 * restarts are bounded by the section count and no file data outlives the call (S2 §17.4: parsed tables are
 * cached, never file bytes).
 */
class NeedSegment {
  constructor(readonly segment: number) {}
}

/** A table touched something outside the image: the table is malformed (→ issues, never a throw to callers). */
export class TableError extends Error {
  override readonly name = "TableError";
}

const MAX_SEGMENT_BYTES = 512 * 1024 * 1024;

export class ImageView {
  constructor(
    readonly headers: PeHeaders,
    private readonly segments: ReadonlyMap<number, Buffer>,
  ) {}

  /** One byte; zero-fill reads as 0; outside the image is a TableError. */
  u8(rva: number): number {
    const at = locateRva(this.headers, rva);
    if (at.kind === "outside") throw new TableError(`rva 0x${rva.toString(16)} is outside the image`);
    if (at.kind === "zero") return 0;
    const seg = this.segments.get(at.segment);
    if (seg === undefined) throw new NeedSegment(at.segment);
    const base = segmentRange(this.headers, at.segment).offset;
    return seg[at.offset - base] ?? 0;
  }

  /** len bytes (zero-filled where not file-backed). */
  bytes(rva: number, len: number): Buffer {
    const out = Buffer.alloc(len);
    let i = 0;
    while (i < len) {
      const at = locateRva(this.headers, rva + i);
      if (at.kind === "outside") throw new TableError(`rva 0x${(rva + i).toString(16)} is outside the image`);
      const run = Math.min(at.run, len - i);
      if (at.kind === "file") {
        const seg = this.segments.get(at.segment);
        if (seg === undefined) throw new NeedSegment(at.segment);
        const start = at.offset - segmentRange(this.headers, at.segment).offset;
        seg.copy(out, i, start, start + run);
      }
      i += run;
    }
    return out;
  }

  u16(rva: number): number {
    return this.bytes(rva, 2).readUInt16LE(0);
  }

  u32(rva: number): number {
    return this.bytes(rva, 4).readUInt32LE(0);
  }

  u64(rva: number): bigint {
    return this.bytes(rva, 8).readBigUInt64LE(0);
  }

  /** NUL-terminated latin1 string (≤ max bytes), or null when rva is outside the image. */
  cstr(rva: number, max = 4096): string | null {
    const at = locateRva(this.headers, rva);
    if (at.kind === "outside") return null;
    if (at.kind === "zero") return "";
    const seg = this.segments.get(at.segment);
    if (seg === undefined) throw new NeedSegment(at.segment);
    const start = at.offset - segmentRange(this.headers, at.segment).offset;
    const end = Math.min(seg.length, start + max);
    // review fix DATA-1: search only the name's window (a NUL-free segment made every name O(segment size))
    const zero = seg.subarray(start, end).indexOf(0);
    return seg.toString("latin1", start, zero === -1 ? end : start + zero);
  }

  /** Bytes of [rva, rva + len) that are file-backed from rva on (zero-fill or the image end stops the run). */
  fileBackedPrefix(rva: number, len: number): number {
    let i = 0;
    while (i < len) {
      const at = locateRva(this.headers, rva + i);
      if (at.kind !== "file") break;
      i += Math.min(at.run, len - i);
    }
    return i;
  }

  /** Is the rva inside the image's mapped parts? */
  inImage(rva: number): boolean {
    return locateRva(this.headers, rva).kind !== "outside";
  }
}

/** Run a synchronous table parser, loading segments on demand. */
export const runTable = async <T>(
  reader: FileReader,
  headers: PeHeaders,
  parse: (view: ImageView) => T,
): Promise<T> => {
  const segments = new Map<number, Buffer>();
  let loaded = 0;
  for (;;) {
    try {
      return parse(new ImageView(headers, segments));
    } catch (thrown) {
      if (!(thrown instanceof NeedSegment)) throw thrown;
      const range = segmentRange(headers, thrown.segment);
      loaded += range.length;
      if (segments.has(thrown.segment) || loaded > MAX_SEGMENT_BYTES)
        throw new TableError("table data exceeds the read budget");
      segments.set(
        thrown.segment,
        range.length === 0 ? Buffer.alloc(0) : await reader.readAt(range.offset, range.length),
      );
    }
  }
};
