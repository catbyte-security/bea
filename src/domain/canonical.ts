import { createHash, randomBytes, randomUUID } from "node:crypto";

import type { JsonValue } from "./json.js";

export class CanonicalizationError extends TypeError {
  override readonly name = "CanonicalizationError";
}

const MAX_DEPTH = 256;
const FLUSH_AT = 8192;

/**
 * RFC 8785 (JCS) emitter owned by BEA (S2-2; DESIGN D-INT-3). Object keys sort by UTF-16 code units
 * (Array.prototype.sort default), numbers use ECMAScript Number::toString (JSON.stringify), strings use
 * JSON.stringify escaping, `undefined` object members are skipped. Throws CanonicalizationError on NaN,
 * ±Infinity, BigInt, functions, symbols, `undefined` array elements or root, and depth > 256 (cycles).
 * Oracle: canonicalize@5.1.0 (devDependency) in a property test; RFC 8785 Appendix B number vectors.
 */
const emit = (value: unknown, out: (chunk: string) => void, depth: number): void => {
  if (depth > MAX_DEPTH) throw new CanonicalizationError("JSON value nests deeper than 256 levels (cycle?)");
  if (value === null) return out("null");
  switch (typeof value) {
    case "boolean":
      return out(value ? "true" : "false");
    case "number":
      if (!Number.isFinite(value)) throw new CanonicalizationError("NaN and Infinity have no JSON form");
      return out(JSON.stringify(value));
    case "string":
      return out(JSON.stringify(value));
    case "object": {
      if (Array.isArray(value)) {
        out("[");
        for (let i = 0; i < value.length; i++) {
          if (i > 0) out(",");
          const item: unknown = value[i];
          if (item === undefined) throw new CanonicalizationError("undefined array element has no JSON form");
          emit(item, out, depth + 1);
        }
        return out("]");
      }
      const record = value as Record<string, unknown>;
      const keys = Object.keys(record)
        .filter((k) => record[k] !== undefined)
        .sort();
      out("{");
      keys.forEach((key, i) => {
        if (i > 0) out(",");
        out(JSON.stringify(key));
        out(":");
        emit(record[key], out, depth + 1);
      });
      return out("}");
    }
    default:
      throw new CanonicalizationError(`a ${typeof value} has no JSON form`);
  }
};

export const canonicalJson = (value: JsonValue): string => {
  if (value === undefined) throw new CanonicalizationError("Value has no canonical JSON form");
  const parts: string[] = [];
  emit(value, (chunk) => parts.push(chunk), 0);
  return parts.join("");
};

export const sha256Hex = (data: string | Uint8Array): string => createHash("sha256").update(data).digest("hex");

/** Streaming digest: never materializes the whole canonical string (8 KiB parts). */
export const canonicalDigest = (value: JsonValue): string => {
  const hash = createHash("sha256");
  let buffer = "";
  emit(
    value,
    (chunk) => {
      buffer += chunk;
      if (buffer.length >= FLUSH_AT) {
        hash.update(buffer);
        buffer = "";
      }
    },
    0,
  );
  if (buffer.length > 0) hash.update(buffer);
  return hash.digest("hex");
};

/**
 * Random, per-run handles (S6 §2.4): `rec_` (instrument = recording), `scan_`, `job_`. 8 lowercase hex.
 * A pasted digest id (64 hex) never validates as a handle and vice versa. Allocators retry on collision.
 */
export const HANDLE_PREFIXES = ["rec", "scan", "job"] as const;
export type HandlePrefix = (typeof HANDLE_PREFIXES)[number];
export type Handle<P extends HandlePrefix> = `${P}_${string}`;
/** @public */
export const handlePattern = (prefix: HandlePrefix): RegExp => new RegExp(`^${prefix}_[0-9a-f]{8}$`, "u");

export const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;

/** Injectable randomness so tests can make ids deterministic [rea-testing §11.5]. */
export interface IdSource {
  readonly uuid: () => string;
  readonly handle: <P extends HandlePrefix>(prefix: P) => Handle<P>;
  readonly runId: (now: Date) => `run_${string}`;
}

const compactUtc = (now: Date): string =>
  now
    .toISOString()
    .replaceAll("-", "")
    .replaceAll(":", "")
    .replace(/\.\d{3}Z$/u, "Z");

export const systemIdSource: IdSource = {
  uuid: () => randomUUID(),
  handle: (prefix) => `${prefix}_${randomBytes(4).toString("hex")}`,
  runId: (now) => `run_${compactUtc(now)}_${randomBytes(8).toString("hex")}`,
};

/** Deterministic source for tests: uuids and handles count up from 1. */
export const sequentialIdSource = (): IdSource => {
  let n = 0;
  const next = (): string => (n += 1).toString(16).padStart(12, "0");
  return {
    uuid: () => `00000000-0000-4000-8000-${next()}`,
    handle: (prefix) => `${prefix}_${next().slice(-8)}`,
    runId: (now) => `run_${compactUtc(now)}_${next().padStart(16, "0")}`,
  };
};
