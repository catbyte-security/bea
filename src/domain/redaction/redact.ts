import type { JsonValue } from "../json.js";
import type { SensitiveLiterals } from "./literals.js";

/**
 * Redaction algorithms (S2 §15.2). Explicit literals only, matched as text and as UTF-8 / UTF-16LE bytes; no case
 * folding, no other encodings (anything else would be guessing). Matching fields are removed WHOLE (value → null,
 * property dropped), never rewritten with a marker, so nothing fabricated enters a record.
 */
export interface Redaction {
  /** RFC 6901 pointer into the record */
  readonly pointer: string;
  readonly reason: "explicit-sensitive-value";
  readonly scope: "value" | "property-name" | "blob" | "batch" | "parameter";
}

/** REA's exact text semantics: replace (longest first); a literal re-formed across a boundary empties the text. */
export const redactExplicitText = (value: string, literals: SensitiveLiterals): string => {
  const texts = literals.texts;
  if (texts.length === 0) return value;
  const replacement = ["[REDACTED]", "…", ""].find((c) => texts.every((l) => !c.includes(l))) ?? "";
  let result = value;
  for (const literal of texts) result = result.replaceAll(literal, replacement);
  return texts.some((literal) => result.includes(literal)) ? "" : result;
};

export const textContainsLiteral = (value: string, literals: SensitiveLiterals): boolean =>
  literals.texts.some((literal) => value.includes(literal));

const indexOfBytes = (haystack: Uint8Array, needle: Uint8Array, from = 0): number => {
  if (needle.length === 0) return -1;
  const first = needle[0];
  const last = haystack.length - needle.length;
  outer: for (let i = from; i <= last; i++) {
    if (haystack[i] !== first) continue;
    for (let j = 1; j < needle.length; j++) if (haystack[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
};

export const bytesContainLiteral = (bytes: Uint8Array, literals: SensitiveLiterals): boolean =>
  literals.spellings.some((spelling) => indexOfBytes(bytes, spelling) !== -1);

/** Longest spelling minus one: the overlap a chunked scanner keeps between chunks. */
export const literalOverlap = (literals: SensitiveLiterals): number =>
  Math.max(0, ...literals.spellings.map((spelling) => spelling.length - 1));

export const escapePointerToken = (token: string): string => token.replaceAll("~", "~0").replaceAll("/", "~1");
export const unescapePointerToken = (token: string): string => token.replaceAll("~1", "/").replaceAll("~0", "~");

/** Split "/a/b/0" into tokens (unescaped). "" is the root. */
export const pointerTokens = (pointer: string): string[] | null => {
  if (pointer === "") return [];
  if (!pointer.startsWith("/")) return null;
  return pointer.slice(1).split("/").map(unescapePointerToken);
};

/** Pattern tokens: "*" matches any single token (array index or key). */
const matchesPattern = (path: readonly string[], pattern: readonly string[]): boolean =>
  path.length === pattern.length && pattern.every((token, i) => token === "*" || token === path[i]);

const HEX_RE = /^(?:[0-9a-fA-F]{2})*$/u;
const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/u;

/** Decode a byte field (hex as records store it; base64 tolerated). null when it is neither. */
export const decodeByteField = (value: string): Uint8Array | null => {
  if (HEX_RE.test(value)) {
    const out = new Uint8Array(value.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(value.slice(2 * i, 2 * i + 2), 16);
    return out;
  }
  if (value.length % 4 === 0 && BASE64_RE.test(value)) {
    const binary = atob(value);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  }
  return null;
};

export interface RedactedPayload {
  readonly value: JsonValue;
  readonly redactions: readonly Redaction[];
}

/**
 * Walk `value` depth-first. `at` is the pointer of `value` inside the record ("/result"); `byteFields` are pointer
 * patterns RELATIVE to `value` ("/data", "/rows/* /b"). Returns the input object unchanged when nothing matched.
 */
export const redactJsonPayload = (
  value: JsonValue,
  literals: SensitiveLiterals,
  at: string,
  byteFields: readonly string[] = [],
): RedactedPayload => {
  if (literals.count === 0) return { value, redactions: [] };
  const patterns = byteFields.map((field) => pointerTokens(field) ?? []);
  const redactions: Redaction[] = [];
  const walk = (node: JsonValue, path: string[]): JsonValue => {
    const pointer = `${at}${path.map((t) => `/${escapePointerToken(t)}`).join("")}`;
    if (typeof node === "string") {
      if (textContainsLiteral(node, literals)) {
        redactions.push({ pointer, reason: "explicit-sensitive-value", scope: "value" });
        return null;
      }
      if (patterns.some((pattern) => matchesPattern(path, pattern))) {
        const bytes = decodeByteField(node);
        if (bytes !== null && bytesContainLiteral(bytes, literals)) {
          redactions.push({ pointer, reason: "explicit-sensitive-value", scope: "value" });
          return null;
        }
      }
      return node;
    }
    if (node === null || typeof node !== "object") return node;
    if (Array.isArray(node)) {
      let changed = false;
      const out = (node as readonly JsonValue[]).map((item, index) => {
        const next = walk(item, [...path, String(index)]);
        changed ||= next !== item;
        return next;
      });
      return changed ? out : node;
    }
    const record = node as { readonly [key: string]: JsonValue };
    let changed = false;
    const out: { [key: string]: JsonValue } = {};
    for (const [key, item] of Object.entries(record)) {
      if (textContainsLiteral(key, literals)) {
        redactions.push({ pointer, reason: "explicit-sensitive-value", scope: "property-name" });
        changed = true;
        continue;
      }
      const next = walk(item, [...path, key]);
      changed ||= next !== item;
      out[key] = next;
    }
    return changed ? out : node;
  };
  const redacted = walk(value, []);
  return { value: redacted, redactions };
};

/** True when any string anywhere in `value` (keys included) contains a literal as text. */
export const jsonContainsLiteral = (value: JsonValue, literals: SensitiveLiterals): boolean => {
  if (literals.count === 0) return false;
  if (typeof value === "string") return textContainsLiteral(value, literals);
  if (value === null || typeof value !== "object") return false;
  if (Array.isArray(value)) return (value as readonly JsonValue[]).some((item) => jsonContainsLiteral(item, literals));
  return Object.entries(value as { readonly [key: string]: JsonValue }).some(
    ([key, item]) => textContainsLiteral(key, literals) || jsonContainsLiteral(item, literals),
  );
};
