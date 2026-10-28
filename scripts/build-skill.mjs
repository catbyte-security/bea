#!/usr/bin/env node
// scripts/build-skill.mjs (WP15-CLI; DESIGN §7, S1 §7.9.6): skills/ → dist/skills/ with generated metadata.
// - SKILL.md frontmatter gains metadata.tool_count (= TOOL_CONTRACTS.length of this build) and metadata.bea_version;
//   an authored source that already contains either key is refused.
// - Every Markdown file pins `bea-agents@latest` to `bea-agents@<version>`, so a shipped skill names its own package.
// The transforms are src/cli/setup/skillMetadata.ts, imported (like the catalog) from the compiled dist/, so build:ts
// must run first (`npm run build` does). Runs under the "build" lock and publishes dist/skills/ by rename.
import { cp, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { makeStagingDir, publishDir, removeStagingDir } from "./lib/atomic.mjs";
import { withBuildLock } from "./lib/lock.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const source = join(root, "skills");
const dist = join(root, "dist");

const exists = async (path) => {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
};

const markdownFiles = async (dir) =>
  (await readdir(dir, { recursive: true, withFileTypes: true }))
    .filter((entry) => entry.isFile() && entry.name.toLowerCase().endsWith(".md"))
    .map((entry) => join(entry.parentPath, entry.name));

await withBuildLock(async () => {
  if (!(await exists(source))) {
    process.stderr.write("build:skill skipped (skills/ does not exist yet)\n");
    return;
  }
  const catalogModule = join(dist, "contracts", "index.js");
  const transformModule = join(dist, "cli", "setup", "skillMetadata.js");
  for (const required of [catalogModule, transformModule])
    if (!(await exists(required))) {
      process.stderr.write(`build:skill needs the compiled ${required}; run \`npm run build:ts\` first.\n`);
      process.exitCode = 1;
      return;
    }
  const { TOOL_CONTRACTS } = await import(pathToFileURL(catalogModule).href);
  const { injectSkillMetadata, pinPackageVersion } = await import(pathToFileURL(transformModule).href);
  const pkg = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
  const skills = (await readdir(source, { withFileTypes: true })).filter((entry) => entry.isDirectory());
  const stage = await makeStagingDir("skills", root);
  try {
    const out = join(stage, "skills");
    await cp(source, out, { recursive: true });
    for (const skill of skills) {
      const skillFile = join(out, skill.name, "SKILL.md");
      if (!(await exists(skillFile))) throw new Error(`skills/${skill.name} has no SKILL.md`);
      const text = await readFile(skillFile, "utf8");
      await writeFile(
        skillFile,
        injectSkillMetadata(text, { toolCount: TOOL_CONTRACTS.length, beaVersion: pkg.version }),
        "utf8",
      );
    }
    for (const file of await markdownFiles(out)) {
      const text = await readFile(file, "utf8");
      const pinned = pinPackageVersion(text, pkg.name, pkg.version);
      if (pinned !== text) await writeFile(file, pinned, "utf8");
    }
    await publishDir(out, join(dist, "skills"));
    process.stdout.write(
      `build:skill ok (${String(skills.length)} skill(s), tool_count ${String(TOOL_CONTRACTS.length)}, bea_version ${pkg.version})\n`,
    );
  } finally {
    await removeStagingDir(stage);
  }
});
