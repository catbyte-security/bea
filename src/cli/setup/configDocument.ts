import { isDeepStrictEqual } from "node:util";

import { applyEdits, modify, parse as parseJsonc, type ParseError } from "jsonc-parser";
import { parse as parseToml } from "smol-toml";

import type { JsonObject } from "../../domain/json.js";

export type EditOutcome =
  | { readonly kind: "edited"; readonly text: string; readonly previous: unknown }
  | { readonly kind: "invalid"; readonly reason: string }
  | { readonly kind: "manual"; readonly reason: string };

const stripBom = (text: string): string => text.replace(/^﻿/u, "");

const detectFormatting = (text: string) => {
  const indent = /^([ \t]+)\S/mu.exec(text)?.[1] ?? "  ";
  return {
    insertSpaces: !indent.startsWith("\t"),
    tabSize: indent.startsWith("\t") ? 1 : indent.length,
    eol: text.includes("\r\n") ? "\r\n" : "\n",
  };
};

const getAt = (root: unknown, path: readonly string[]): unknown => {
  let value = root;
  for (const key of path) {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
    value = Reflect.get(value, key);
  }
  return value;
};

/**
 * Set `keyPath` (e.g. ["mcpServers","bea"]) to `entry`, preserving every other
 * byte (comments, order, formatting) via jsonc-parser edits. Strict files
 * (~/.claude.json, Claude Desktop) must also pass JSON.parse before and after.
 */
export const editJsonEntry = (
  text: string | null,
  keyPath: readonly string[],
  entry: JsonObject,
  format: "json-strict" | "jsonc",
): EditOutcome => {
  const source = text === null ? "{\n}\n" : stripBom(text);
  const errors: ParseError[] = [];
  const root: unknown = parseJsonc(source, errors, {
    allowTrailingComma: format === "jsonc",
    disallowComments: format === "json-strict",
  });
  if (errors.length > 0) return { kind: "invalid", reason: "The file is not valid JSON; BEA will not edit it." };
  if (format === "json-strict") {
    try {
      JSON.parse(source);
    } catch {
      return { kind: "invalid", reason: "The file is not strict JSON; BEA will not edit it." };
    }
  }
  if (typeof root !== "object" || root === null || Array.isArray(root))
    return { kind: "invalid", reason: "The top level is not a JSON object." };
  const previous = getAt(root, keyPath);
  const edited = applyEdits(
    source,
    modify(source, [...keyPath], entry, { formattingOptions: detectFormatting(source) }),
  );
  const reparsed: unknown = parseJsonc(edited, [], { allowTrailingComma: true });
  if (!isDeepStrictEqual(getAt(reparsed, keyPath), entry))
    return { kind: "invalid", reason: "The edit did not round-trip." };
  return { kind: "edited", text: edited, previous };
};

const tomlString = (value: string): string => JSON.stringify(value); // JSON escapes are valid TOML basic-string escapes.

export interface CodexEntry {
  readonly command: string;
  readonly args: readonly string[];
  readonly startup_timeout_sec: number;
  readonly tool_timeout_sec: number;
}

/**
 * Replace only the key/value lines of the `[mcp_servers.bea]` table (header to
 * next header). Sub-tables such as [mcp_servers.bea.env] and per-tool approval
 * tables stay byte-identical. Dotted or inline definitions are left to the user.
 */
export const editCodexToml = (text: string | null, entry: CodexEntry): EditOutcome => {
  const source = text === null ? "" : stripBom(text);
  let before: Record<string, unknown>;
  try {
    before = parseToml(source) as Record<string, unknown>;
  } catch {
    return { kind: "invalid", reason: "config.toml is not valid TOML; BEA will not edit it." };
  }
  const previous = getAt(before, ["mcp_servers", "bea"]);
  const eol = source.includes("\r\n") ? "\r\n" : "\n";
  const lines = source.length === 0 ? [] : source.split(/\r?\n/u);
  const header = lines.findIndex((line) => /^\s*\[\s*mcp_servers\s*\.\s*bea\s*\]\s*(?:#.*)?$/u.test(line));
  if (previous !== undefined && header === -1)
    return { kind: "manual", reason: "mcp_servers.bea is defined inline or with dotted keys; edit it by hand." };
  const keep = (key: "startup_timeout_sec" | "tool_timeout_sec", minimum: number): number => {
    const existing = getAt(previous, [key]);
    return typeof existing === "number" && Number.isInteger(existing) && existing >= minimum ? existing : minimum;
  };
  const body = [
    `command = ${tomlString(entry.command)}`,
    `args = [${entry.args.map(tomlString).join(", ")}]`,
    `startup_timeout_sec = ${String(keep("startup_timeout_sec", entry.startup_timeout_sec))}`,
    `tool_timeout_sec = ${String(keep("tool_timeout_sec", entry.tool_timeout_sec))}`,
  ];
  let out: string[];
  if (header === -1) {
    while (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
    out = [...lines, ...(lines.length > 0 ? [""] : []), "[mcp_servers.bea]", ...body, ""];
  } else {
    let end = header + 1;
    while (end < lines.length && !/^\s*\[/u.test(lines[end] ?? "")) end += 1;
    const trailing = lines.slice(header + 1, end).filter((line) => /^\s*(?:#.*)?$/u.test(line) && line.trim() === "");
    out = [...lines.slice(0, header + 1), ...body, ...trailing, ...lines.slice(end)];
  }
  const edited = out.join(eol);
  let after: Record<string, unknown>;
  try {
    after = parseToml(edited) as Record<string, unknown>;
  } catch {
    return { kind: "invalid", reason: "The edit did not produce valid TOML." };
  }
  const written = getAt(after, ["mcp_servers", "bea"]) as Record<string, unknown> | undefined;
  const othersBefore = structuredClone(before);
  const othersAfter = structuredClone(after);
  for (const doc of [othersBefore, othersAfter]) {
    const servers = doc["mcp_servers"];
    if (typeof servers === "object" && servers !== null) {
      const bea = Reflect.get(servers, "bea") as Record<string, unknown> | undefined;
      if (bea !== undefined)
        for (const key of ["command", "args", "startup_timeout_sec", "tool_timeout_sec"])
          Reflect.deleteProperty(bea, key);
      // WP15 fix to the S1 seed: a created table leaves an empty mcp_servers.bea (and mcp_servers) behind, which is not
      // "more than mcp_servers.bea" (the lab only exercised updates).
      if (bea !== undefined && Object.keys(bea).length === 0) Reflect.deleteProperty(servers, "bea");
      if (Object.keys(servers).length === 0) Reflect.deleteProperty(doc, "mcp_servers");
    }
  }
  if (
    written?.["command"] !== entry.command ||
    !isDeepStrictEqual(written["args"], [...entry.args]) ||
    !isDeepStrictEqual(othersBefore, othersAfter)
  )
    return { kind: "invalid", reason: "The edit changed more than mcp_servers.bea; refusing." };
  return { kind: "edited", text: edited, previous };
};
