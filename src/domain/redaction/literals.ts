import { z } from "zod";

import type { InputIssue } from "../errors/beaError.js";
import { err, ok, type Result } from "../result.js";

/**
 * Caller-declared sensitive literals (S2 §15.1). Sources: a per-call `sensitive_values` input and the server-level
 * file (BEA_SENSITIVE_VALUES_FILE / config `sensitive_values_file`). Neither is ever persisted; records keep only a
 * count. Structurally identical to the `SensitiveLiterals` port type (src/ports/evidence.ts).
 */
export interface SensitiveLiterals {
  readonly count: number;
  /** unique, longest first */
  readonly texts: readonly string[];
  /** utf8(lit) and utf16le(lit) for every literal, unique, longest first */
  readonly spellings: readonly Uint8Array[];
}

/** BEA deviation from REA: a one-character literal would erase everything (foot-gun prevention). */
export const MIN_LITERAL_UTF8_BYTES = 4;
export const MAX_LITERAL_CHARS = 1024;
export const MAX_CALL_LITERALS = 64;
export const MAX_SERVER_LITERALS = 256;

/** Per-call input fragment for contracts whose results may carry target content. @public */
export const sensitiveValuesInputSchema = z.array(z.string().min(1).max(MAX_LITERAL_CHARS)).max(MAX_CALL_LITERALS);

export const NO_LITERALS: SensitiveLiterals = Object.freeze({ count: 0, texts: [], spellings: [] });

const utf8 = new TextEncoder();

const utf16le = (text: string): Uint8Array => {
  const out = new Uint8Array(text.length * 2);
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    out[2 * i] = unit & 0xff;
    out[2 * i + 1] = unit >> 8;
  }
  return out;
};

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
};

/** Build the literal set from already-validated texts (dedupe, longest first, both spellings). */
export const literalsOf = (texts: readonly string[]): SensitiveLiterals => {
  const unique = [...new Set(texts)].sort((a, b) => b.length - a.length || (a < b ? -1 : a > b ? 1 : 0));
  if (unique.length === 0) return NO_LITERALS;
  const spellings: Uint8Array[] = [];
  for (const text of unique)
    for (const spelling of [utf8.encode(text), utf16le(text)])
      if (!spellings.some((known) => sameBytes(known, spelling))) spellings.push(spelling);
  spellings.sort((a, b) => b.length - a.length);
  return Object.freeze({ count: unique.length, texts: Object.freeze(unique), spellings: Object.freeze(spellings) });
};

/**
 * Validate per-call literals (each ≥ 4 UTF-8 bytes) and merge them with the server-level set. Issues name the
 * caller's own field path (`sensitive_values[i]`); the literal itself never appears in a message.
 */
export const sensitiveLiterals = (
  perCall: readonly string[] | undefined,
  serverLevel: readonly string[],
  path = "sensitive_values",
): Result<SensitiveLiterals, InputIssue[]> => {
  const issues: InputIssue[] = [];
  (perCall ?? []).forEach((text, index) => {
    if (utf8.encode(text).length < MIN_LITERAL_UTF8_BYTES)
      issues.push({
        path: `${path}[${String(index)}]`,
        reason: "out_of_range",
        message: `A sensitive value must be at least ${String(MIN_LITERAL_UTF8_BYTES)} UTF-8 bytes long; shorter values would erase unrelated data.`,
        minimum: MIN_LITERAL_UTF8_BYTES,
      });
  });
  if ((perCall?.length ?? 0) > MAX_CALL_LITERALS)
    issues.push({
      path,
      reason: "out_of_range",
      message: `At most ${String(MAX_CALL_LITERALS)} sensitive values per call.`,
      maximum: MAX_CALL_LITERALS,
    });
  if (issues.length > 0) return err(issues);
  return ok(literalsOf([...(perCall ?? []), ...serverLevel]));
};

/**
 * Parse the server-level literals file: UTF-8, one literal per line (CR/LF trimmed, blank lines skipped), at most
 * 256, each ≥ 4 UTF-8 bytes. Returns the constraint text on failure (configuration_invalid).
 */
export const parseLiteralsFile = (text: string): Result<readonly string[], string> => {
  const lines = text
    .replace(/^﻿/u, "")
    .split(/\r?\n/u)
    .map((line) => line.replace(/\r$/u, ""))
    .filter((line) => line.length > 0);
  if (lines.length > MAX_SERVER_LITERALS)
    return err(`the sensitive values file holds at most ${String(MAX_SERVER_LITERALS)} literals`);
  const short = lines.findIndex((line) => utf8.encode(line).length < MIN_LITERAL_UTF8_BYTES);
  if (short !== -1)
    return err(
      `line ${String(short + 1)} of the sensitive values file is shorter than ${String(MIN_LITERAL_UTF8_BYTES)} UTF-8 bytes`,
    );
  if (lines.some((line) => line.length > MAX_LITERAL_CHARS))
    return err(`a sensitive value is longer than ${String(MAX_LITERAL_CHARS)} characters`);
  return ok(lines);
};
