import type { HostFrame } from "../../domain/emuProtocol.js";

/**
 * bea-emu/0.1 transport framing (S5 §4.1, §5.1): one compact UTF-8 JSON object per LF-terminated line, at most
 * 64 MiB per frame in each direction, CRLF tolerated. The splitter works on bytes and never decodes a partial
 * UTF-8 sequence; a frame is decoded only once its LF arrived.
 */
export const MAX_FRAME_BYTES = 64 * 1024 * 1024;

export class FrameTooLarge extends Error {
  override readonly name = "FrameTooLarge";
}

/** Splits a byte stream into LF-terminated frames; strips one trailing CR; empty lines are skipped. */
export class NdjsonSplitter {
  #chunks: Buffer[] = [];
  #length = 0;

  /** Complete frames contained in `chunk` (without the LF). Throws FrameTooLarge once a pending line passes the cap. */
  push(chunk: Buffer): Buffer[] {
    const out: Buffer[] = [];
    let start = 0;
    for (let lf = chunk.indexOf(0x0a); lf !== -1; lf = chunk.indexOf(0x0a, start)) {
      const piece = chunk.subarray(start, lf);
      const line = this.#length === 0 ? piece : Buffer.concat([...this.#chunks, piece], this.#length + piece.length);
      this.#chunks = [];
      this.#length = 0;
      start = lf + 1;
      if (line.length > MAX_FRAME_BYTES)
        throw new FrameTooLarge(`frame of ${String(line.length)} bytes exceeds ${String(MAX_FRAME_BYTES)}`);
      const end = line.length > 0 && line[line.length - 1] === 0x0d ? line.length - 1 : line.length;
      if (end > 0) out.push(line.subarray(0, end));
    }
    const rest = chunk.subarray(start);
    if (rest.length > 0) {
      this.#chunks.push(rest);
      this.#length += rest.length;
    }
    if (this.#length > MAX_FRAME_BYTES)
      throw new FrameTooLarge(`pending frame exceeds ${String(MAX_FRAME_BYTES)} bytes`);
    return out;
  }

  /** Bytes of an unterminated line still buffered (diagnostics only). */
  get pendingBytes(): number {
    return this.#length;
  }
}

/**
 * Path of the first non-finite number leaf, or null. Host frames never carry NaN/Infinity (every float travels as
 * bits, S5 §7), and JSON.stringify would silently turn them into null, so encodeFrame refuses them.
 */
export const nonFiniteNumberPath = (value: unknown, path = "$"): string | null => {
  if (typeof value === "number") return Number.isFinite(value) ? null : path;
  if (Array.isArray(value)) {
    for (const [i, item] of value.entries()) {
      const found = nonFiniteNumberPath(item, `${path}[${String(i)}]`);
      if (found !== null) return found;
    }
    return null;
  }
  if (typeof value === "object" && value !== null)
    for (const [key, item] of Object.entries(value)) {
      const found = nonFiniteNumberPath(item, `${path}.${key}`);
      if (found !== null) return found;
    }
  return null;
};

export type EncodedFrame =
  | { readonly ok: true; readonly bytes: Buffer }
  | { readonly ok: false; readonly reason: string };

/** One host frame as bytes (compact JSON + LF), or why it cannot be sent. */
export const encodeFrame = (frame: HostFrame): EncodedFrame => {
  const bad = nonFiniteNumberPath(frame.params, "$.params");
  if (bad !== null) return { ok: false, reason: `non-finite number at ${bad}` };
  const bytes = Buffer.from(`${JSON.stringify(frame)}\n`, "utf8");
  if (bytes.length - 1 > MAX_FRAME_BYTES)
    return { ok: false, reason: `frame of ${String(bytes.length - 1)} bytes exceeds ${String(MAX_FRAME_BYTES)}` };
  return { ok: true, bytes };
};
