/**
 * Build-time skill transforms (scripts/build-skill.mjs imports the compiled copy from dist/): inject the generated
 * `metadata.tool_count` and `metadata.bea_version` into SKILL.md's frontmatter and pin `bea-agents@latest` to this
 * version, so a shipped skill names the catalog and package it was built with (REA generate-skill-metadata).
 */
export class SkillMetadataError extends Error {
  override readonly name = "SkillMetadataError";
}

const GENERATED_KEYS = ["tool_count", "bea_version"] as const;

export const injectSkillMetadata = (
  text: string,
  generated: { readonly toolCount: number; readonly beaVersion: string },
): string => {
  const eol = text.includes("\r\n") ? "\r\n" : "\n";
  const lines = text.split(/\r?\n/u);
  if (lines[0] !== "---") throw new SkillMetadataError("SKILL.md must start with a --- frontmatter block.");
  const close = lines.indexOf("---", 1);
  if (close === -1) throw new SkillMetadataError("SKILL.md frontmatter is not closed with ---.");
  const front = lines.slice(1, close);
  for (const key of GENERATED_KEYS)
    if (front.some((line) => new RegExp(`^\\s*${key}\\s*:`, "u").test(line)))
      throw new SkillMetadataError(`The authored SKILL.md already contains generated metadata (${key}); remove it.`);
  const added = (indent: string): string[] => [
    `${indent}tool_count: ${String(generated.toolCount)}`,
    `${indent}bea_version: ${JSON.stringify(generated.beaVersion)}`,
  ];
  const metadata = front.findIndex((line) => /^metadata:\s*$/u.test(line));
  let nextFront: string[];
  if (metadata === -1) nextFront = [...front, "metadata:", ...added("  ")];
  else {
    let end = metadata + 1;
    while (end < front.length && /^\s+\S/u.test(front[end] ?? "")) end += 1;
    const indent = /^(\s+)\S/u.exec(front[metadata + 1] ?? "")?.[1] ?? "  ";
    nextFront = [...front.slice(0, end), ...added(end > metadata + 1 ? indent : "  "), ...front.slice(end)];
  }
  return [lines[0], ...nextFront, ...lines.slice(close)].join(eol);
};

/** `bea-agents@latest` → `bea-agents@<version>` everywhere in a skill file. */
export const pinPackageVersion = (text: string, packageName: string, version: string): string =>
  text.replaceAll(`${packageName}@latest`, `${packageName}@${version}`);
