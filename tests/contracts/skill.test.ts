import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { parseSkillFrontmatter } from "../../src/cli/setup/skill.js";
import { injectSkillMetadata } from "../../src/cli/setup/skillMetadata.js";
import { TOOL_CONTRACTS } from "../../src/contracts/index.js";
import { PACKAGE_METADATA } from "../../src/generated/packageMetadata.js";

/**
 * The authored agent skill stays consistent with the catalog (DESIGN §7, S6 §9; release checklist "skill tool names ⊆
 * tools/list"). Integrator, implement stage (WP17 change request): the checks of WP17's validator as a contract test,
 * so the skill cannot drift from the catalog unnoticed.
 */
const SKILL_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "skills", "bea-dynamic-analysis");
const REFERENCES = [
  "address-model",
  "connection-and-recovery",
  "crashes",
  "evidence-and-ledger",
  "hooks-and-api-profiles",
  "memory-and-scanning",
  "oracles-and-emulation",
  "tracing-and-coverage",
  "watchpoints",
] as const;
const INTEGRATION_SENTENCE = "(BEA refuses those unless the user explicitly allowed it in BEA's configuration).";

const lineCount = (text: string): number => text.split("\n").length - (text.endsWith("\n") ? 1 : 0);
const skillText = readFileSync(join(SKILL_DIR, "SKILL.md"), "utf8").replace(/\r\n/gu, "\n");
const documents: readonly (readonly [string, string])[] = [
  ["SKILL.md", skillText],
  ...REFERENCES.map(
    (ref) =>
      [
        `references/${ref}.md`,
        readFileSync(join(SKILL_DIR, "references", `${ref}.md`), "utf8").replace(/\r\n/gu, "\n"),
      ] as const,
  ),
];
const toolNames: ReadonlySet<string> = new Set<string>(TOOL_CONTRACTS.map((contract) => contract.name));

/** Names written like tool calls: `snake_name {…}` code spans, code spans that are exactly a tool, `name {` lines. */
const toolLikeNames = (text: string): Set<string> => {
  const body = text.replace(/^---\n[\s\S]*?\n---\n/u, "");
  const names = new Set<string>();
  for (const m of body.matchAll(/`([^`\n]+)`/gu)) {
    const span = (m[1] ?? "").trim();
    const call = /^([a-z][a-z0-9_]*)(?:\s*\{|$)/u.exec(span);
    if (call === null) continue;
    const ident = call[1] ?? "";
    const writtenAsCall = ident.includes("_") && /\{/u.test(span.slice(ident.length));
    if (writtenAsCall || toolNames.has(ident)) names.add(ident);
  }
  for (const m of body.matchAll(/^([a-z][a-z0-9]*(?:_[a-z0-9]+)+) \{/gmu)) names.add(m[1] ?? "");
  return names;
};

describe("agent skill vs catalog (DESIGN §7)", () => {
  it("SKILL.md starts with the ownership marker and stays within 420 lines", () => {
    expect(skillText.startsWith("---\nname: bea-dynamic-analysis\n")).toBe(true);
    expect(lineCount(skillText)).toBeLessThanOrEqual(420);
  });

  it("the authored frontmatter carries metadata.version only; the build injects tool_count and bea_version", () => {
    const authored = parseSkillFrontmatter(skillText);
    expect(authored).toMatchObject({
      name: "bea-dynamic-analysis",
      version: PACKAGE_METADATA.skillVersion,
      tool_count: null,
      bea_version: null,
    });
    const built = parseSkillFrontmatter(
      injectSkillMetadata(skillText, { toolCount: TOOL_CONTRACTS.length, beaVersion: "0.1.0" }),
    );
    expect(built).toEqual({ ...authored, tool_count: TOOL_CONTRACTS.length, bea_version: "0.1.0" });
  });

  it("the description is a folded block of at most 1024 characters ending with the integration sentence", () => {
    const folded = /^description: >-\n((?: {2}.*\n)+)/mu.exec(skillText);
    expect(folded).not.toBeNull();
    const description = (folded?.[1] ?? "")
      .split("\n")
      .map((line) => line.trim())
      .join(" ")
      .trim();
    expect(description.length).toBeLessThanOrEqual(1024);
    expect(description.endsWith(INTEGRATION_SENTENCE)).toBe(true);
  });

  it("ships exactly the nine references, each 60–200 lines", () => {
    const present = readdirSync(join(SKILL_DIR, "references"))
      .filter((file) => file.endsWith(".md"))
      .map((file) => file.slice(0, -3))
      .sort();
    expect(present).toEqual([...REFERENCES]);
    for (const [name, text] of documents.slice(1)) {
      expect(lineCount(text), name).toBeGreaterThanOrEqual(60);
      expect(lineCount(text), name).toBeLessThanOrEqual(200);
    }
  });

  it("every relative link resolves", () => {
    const broken: string[] = [];
    for (const [name, text] of documents)
      for (const m of text.matchAll(/\]\(([^)#\s]+)(#[^)]*)?\)/gu)) {
        const target = m[1] ?? "";
        if (/^[a-z]+:/u.test(target)) continue;
        if (!existsSync(resolve(dirname(join(SKILL_DIR, name)), target))) broken.push(`${name}: ${target}`);
      }
    expect(broken).toEqual([]);
  });

  it("every tool the skill names is in the catalog (skill tool names ⊆ tools/list)", () => {
    const unknown: string[] = [];
    for (const [name, text] of documents)
      for (const tool of toolLikeNames(text)) if (!toolNames.has(tool)) unknown.push(`${name}: ${tool}`);
    expect(unknown).toEqual([]);
  });
});
