import { isDeepStrictEqual } from "node:util";

import { applyEdits, modify, parse as parseJsonc, type ParseError } from "jsonc-parser";
import { parse as parseToml } from "smol-toml";

import type { EditOutcome } from "./configDocument.js";

const stripBom = (text: string): string => text.replace(/^﻿/u, "");

const withoutKey = (root: unknown, path: readonly string[]): unknown => {
  const copy = structuredClone(root) as Record<string, unknown>;
  let parent: Record<string, unknown> | undefined = copy;
  for (const key of path.slice(0, -1)) {
    const next: unknown = parent?.[key];
    parent =
      typeof next === "object" && next !== null && !Array.isArray(next) ? (next as Record<string, unknown>) : undefined;
  }
  if (parent !== undefined) Reflect.deleteProperty(parent, path[path.length - 1] ?? "");
  return copy;
};

const detectIndent = (text: string) => {
  const indent = /^([ \t]+)\S/mu.exec(text)?.[1] ?? "  ";
  return {
    insertSpaces: !indent.startsWith("\t"),
    tabSize: indent.startsWith("\t") ? 1 : indent.length,
    eol: text.includes("\r\n") ? "\r\n" : "\n",
  };
};

/**
 * Uninstall counterpart of editJsonEntry: removes `keyPath` with a jsonc-parser edit (comments, order and formatting of
 * everything else are kept) and proves that nothing else changed.
 */
export const removeJsonEntry = (
  text: string,
  keyPath: readonly string[],
  format: "json-strict" | "jsonc",
): EditOutcome => {
  const source = stripBom(text);
  const errors: ParseError[] = [];
  const before: unknown = parseJsonc(source, errors, {
    allowTrailingComma: format === "jsonc",
    disallowComments: format === "json-strict",
  });
  if (errors.length > 0 || typeof before !== "object" || before === null || Array.isArray(before))
    return { kind: "invalid", reason: "The file is not a valid JSON object; BEA will not edit it." };
  const edited = applyEdits(
    source,
    modify(source, [...keyPath], undefined, { formattingOptions: detectIndent(source) }),
  );
  const after: unknown = parseJsonc(edited, [], { allowTrailingComma: true });
  if (!isDeepStrictEqual(after, withoutKey(before, keyPath)))
    return { kind: "invalid", reason: "The removal changed more than the bea entry; refusing." };
  return { kind: "edited", text: edited, previous: undefined };
};

const BEA_TABLE = /^\s*\[\s*mcp_servers\s*\.\s*bea\s*(?:\]|\.)/u;
const ANY_HEADER = /^\s*\[/u;

/** Removes `[mcp_servers.bea]` and its sub-tables (`[mcp_servers.bea.env]`, approvals); dotted/inline → manual. */
export const removeCodexTable = (text: string): EditOutcome => {
  const source = stripBom(text);
  let before: Record<string, unknown>;
  try {
    before = parseToml(source) as Record<string, unknown>;
  } catch {
    return { kind: "invalid", reason: "config.toml is not valid TOML; BEA will not edit it." };
  }
  const eol = source.includes("\r\n") ? "\r\n" : "\n";
  const lines = source.split(/\r?\n/u);
  if (!lines.some((line) => BEA_TABLE.test(line)))
    return { kind: "manual", reason: "mcp_servers.bea is defined inline or with dotted keys; remove it by hand." };
  const kept: string[] = [];
  let inBea = false;
  for (const line of lines) {
    if (ANY_HEADER.test(line)) inBea = BEA_TABLE.test(line);
    if (!inBea) kept.push(line);
  }
  const edited = kept.join(eol);
  let after: Record<string, unknown>;
  try {
    after = parseToml(edited) as Record<string, unknown>;
  } catch {
    return { kind: "invalid", reason: "The removal did not produce valid TOML; refusing." };
  }
  // Both sides cloned (smol-toml values are class instances); an emptied [mcp_servers] disappears from the parse.
  const expected = withoutKey(before, ["mcp_servers", "bea"]) as Record<string, unknown>;
  const servers = expected["mcp_servers"];
  if (typeof servers === "object" && servers !== null && Object.keys(servers).length === 0 && !("mcp_servers" in after))
    Reflect.deleteProperty(expected, "mcp_servers");
  if (!isDeepStrictEqual(structuredClone(after), expected))
    return { kind: "invalid", reason: "The removal changed more than mcp_servers.bea; refusing." };
  return { kind: "edited", text: edited, previous: undefined };
};

/** Read-back check after a removal: the file parses and has no entry at `keyPath`. */
export const holdsNoEntry = (
  format: "json-strict" | "jsonc" | "toml",
  keyPath: readonly string[],
  text: string,
): boolean => {
  try {
    let value: unknown =
      format === "toml" ? parseToml(stripBom(text)) : parseJsonc(stripBom(text), [], { allowTrailingComma: true });
    for (const key of keyPath) {
      if (typeof value !== "object" || value === null || Array.isArray(value)) return true;
      value = Reflect.get(value, key);
    }
    return value === undefined;
  } catch {
    return false;
  }
};
