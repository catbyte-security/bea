import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { distLayoutAt, type DistLayout } from "../../../src/application/distLayout.js";

export const SKILL_TEXT = (version = "1", toolCount = 37): string =>
  `---\nname: bea-dynamic-analysis\ndescription: test skill\nmetadata:\n  version: "${version}"\n  tool_count: ${String(toolCount)}\n  bea_version: "0.1.0"\n---\n\n# BEA\n`;

/**
 * A minimal package tree for setup/doctor tests: `<root>/scripts/bea.mjs` (the dispatcher whose realpath setup
 * registers) and, unless `skill: null`, a built skill under `<root>/dist/skills/bea-dynamic-analysis/`.
 */
export const createPackageLayout = async (
  root: string,
  options: { readonly skill?: string | null; readonly references?: Readonly<Record<string, string>> } = {},
): Promise<DistLayout> => {
  const layout = distLayoutAt(join(root, "dist"));
  await mkdir(join(root, "scripts"), { recursive: true });
  await writeFile(layout.dispatcher, "// test dispatcher\n");
  const skill = options.skill === undefined ? SKILL_TEXT() : options.skill;
  if (skill !== null) {
    const dir = join(layout.skillsDir, "bea-dynamic-analysis");
    await mkdir(join(dir, "references"), { recursive: true });
    await writeFile(join(dir, "SKILL.md"), skill);
    for (const [name, text] of Object.entries(options.references ?? { "address-model.md": "# Address model\n" }))
      await writeFile(join(dir, "references", name), text);
  }
  return layout;
};
