import { createHash } from "node:crypto";

import { canonicalJson } from "../../domain/canonical.js";
import type { JsonValue } from "../../domain/json.js";
import { formatHex } from "../../domain/hex.js";
import type { BinaryField } from "../../shared/agentProtocol.js";
import type { StreamEncoding } from "../../ports/evidence.js";

/**
 * Chunk file framing (S2 §10.3): `u32le header_len | canonical JSON header | u32le payload_len | payload`.
 * Payloads are the agent's batches unchanged (JSON rows as NDJSON); decoding happens only at query time.
 */
export interface FrameHeader {
  readonly k: "batch" | "redacted" | "gap";
  readonly first_seq: number;
  readonly count: number;
  readonly dropped_before: number;
  readonly recv_mono_ns: string;
  readonly module_map_epoch: number | null;
  readonly final?: true;
  readonly bseq?: number;
  readonly g0?: number;
  readonly g1?: number;
  readonly layout_rev: 1;
}

export interface Frame {
  readonly header: FrameHeader;
  readonly payload: Uint8Array;
  /** byte offset of the frame inside its chunk */
  readonly offset: number;
  readonly bytes: number;
}

export const CHUNK_SEAL_BYTES = 8 * 1024 * 1024;
export const MAX_FRAME_HEADER_BYTES = 64 * 1024;

export const encodeFrame = (header: FrameHeader, payload: Uint8Array): Buffer => {
  const head = Buffer.from(canonicalJson(header as unknown as JsonValue), "utf8");
  const out = Buffer.alloc(8 + head.length + payload.length);
  out.writeUInt32LE(head.length, 0);
  head.copy(out, 4);
  out.writeUInt32LE(payload.length, 4 + head.length);
  out.set(payload, 8 + head.length);
  return out;
};

const isFrameHeader = (value: unknown): value is FrameHeader => {
  if (typeof value !== "object" || value === null) return false;
  const h = value as Record<string, unknown>;
  return (
    (h["k"] === "batch" || h["k"] === "redacted" || h["k"] === "gap") &&
    Number.isSafeInteger(h["first_seq"]) &&
    Number.isSafeInteger(h["count"]) &&
    Number.isSafeInteger(h["dropped_before"]) &&
    typeof h["recv_mono_ns"] === "string" &&
    h["layout_rev"] === 1
  );
};

/** Decode frames; stops at a torn tail (an unsealed chunk of a crashed run) and reports the consumed length. */
export const decodeFrames = (
  buffer: Uint8Array,
): { readonly frames: Frame[]; readonly consumed: number; readonly torn: boolean } => {
  const view = Buffer.from(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  const frames: Frame[] = [];
  let at = 0;
  while (at < view.length) {
    if (at + 4 > view.length) return { frames, consumed: at, torn: true };
    const headLength = view.readUInt32LE(at);
    if (headLength > MAX_FRAME_HEADER_BYTES || at + 8 + headLength > view.length)
      return { frames, consumed: at, torn: true };
    let header: unknown;
    try {
      header = JSON.parse(view.toString("utf8", at + 4, at + 4 + headLength));
    } catch {
      return { frames, consumed: at, torn: true };
    }
    const payloadLength = view.readUInt32LE(at + 4 + headLength);
    const start = at + 8 + headLength;
    if (!isFrameHeader(header) || start + payloadLength > view.length) return { frames, consumed: at, torn: true };
    frames.push({
      header,
      payload: view.subarray(start, start + payloadLength),
      offset: at,
      bytes: 8 + headLength + payloadLength,
    });
    at = start + payloadLength;
  }
  return { frames, consumed: at, torn: false };
};

/** chain_i = sha256("bea.stream.chain/1\n" + chain_{i-1} + "\n" + chunk_sha256_i); chain_{-1} = descriptor sha. */
export const nextChain = (previous: string, chunkSha256: string): string =>
  createHash("sha256").update(`bea.stream.chain/1\n${previous}\n${chunkSha256}`).digest("hex");

export interface ChainLine {
  readonly index: number;
  readonly file: string;
  readonly sha256: string;
  readonly bytes: number;
  readonly frames: number;
  readonly records: number;
  readonly first_seq: number | null;
  readonly last_seq: number | null;
  readonly dropped: number;
  readonly redacted: number;
  readonly chain: string;
}

export const chunkFileName = (index: number): string => `chunk-${String(index).padStart(6, "0")}.bin`;

/** Review fix DATA-4: marker of an imported stream whose bundle carried no chunks (included "manifests-only"). */
export const CHUNKS_ABSENT_MARKER = "chunks.absent";

const HEX64 = /^[0-9a-f]{64}$/u;
const isCount = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
const isSeq = (v: unknown): boolean => v === null || isCount(v);
const isHex64 = (v: unknown): boolean => typeof v === "string" && HEX64.test(v);

/**
 * One chain.jsonl line of a stream from OUTSIDE this run (an imported bundle), checked before anything uses its `file`
 * as a path: index = position, file = chunk-NNNNNN.bin of that index, counts non-negative, digests lowercase hex.
 */
export const parseForeignChainLine = (text: string, position: number): ChainLine | null => {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const v = value as Record<string, unknown>;
  const valid =
    v["index"] === position &&
    v["file"] === chunkFileName(position) &&
    isHex64(v["sha256"]) &&
    isHex64(v["chain"]) &&
    ["bytes", "frames", "records", "dropped", "redacted"].every((key) => isCount(v[key])) &&
    isSeq(v["first_seq"]) &&
    isSeq(v["last_seq"]);
  return valid ? (value as ChainLine) : null;
};

const FIELD_BYTES: { readonly [T in BinaryField["type"]]: number } = { u8: 1, u16: 2, u32: 4, i32: 4, u64: 8 };

const readField = (view: Buffer, at: number, field: BinaryField): JsonValue => {
  switch (field.type) {
    case "u8":
      return view.readUInt8(at);
    case "u16":
      return view.readUInt16LE(at);
    case "u32":
      return view.readUInt32LE(at);
    case "i32":
      return view.readInt32LE(at);
    case "u64":
      return formatHex(view.readBigUInt64LE(at));
    default:
      return null;
  }
};

/** Decoded records of one batch frame: [seq offset within the frame, fields]. Undecodable rows are skipped. */
export const decodePayload = (
  encoding: StreamEncoding,
  frame: Frame,
): { readonly index: number; readonly fields: JsonValue }[] => {
  const payload = Buffer.from(frame.payload.buffer, frame.payload.byteOffset, frame.payload.byteLength);
  switch (encoding.kind) {
    case "json-rows":
    case "ndjson": {
      const out: { index: number; fields: JsonValue }[] = [];
      const lines = payload.toString("utf8").split("\n");
      if (lines.at(-1) === "") lines.pop();
      lines.forEach((line, index) => {
        try {
          out.push({ index, fields: JSON.parse(line) as JsonValue });
        } catch {
          // a torn or non-JSON row is not fabricated into a record
        }
      });
      return out;
    }
    case "fixed-records": {
      const size = encoding.record_bytes;
      const out: { index: number; fields: JsonValue }[] = [];
      for (let i = 0; size > 0 && (i + 1) * size <= payload.length; i++) {
        const fields: Record<string, JsonValue> = {};
        for (const field of encoding.fields)
          if (field.offset + FIELD_BYTES[field.type] <= size)
            fields[field.name] = readField(payload, i * size + field.offset, field);
        out.push({ index: i, fields });
      }
      return out;
    }
    case "bytes":
      return [{ index: 0, fields: { hex: payload.toString("hex") } }];
    default:
      return [];
  }
};
