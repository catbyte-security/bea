#!/usr/bin/env node
// scripts/generate.mjs (WP0; S1 §2.4 as amended by D-INT-46/CI-I4). Writes the committed generated files:
//   src/generated/packageMetadata.ts            from package.json
//   tests/golden/catalog/<area>.json  (12)      per-area golden slices of the advertised catalog   [gen:area]
//   docs/tools/<area>.md              (12)      per-area tool pages                                 [gen:area]
//   tests/golden/catalog.json, docs/tools.md    indexes: slice names, tools and slice digests       [gen]
//   docs/errors.md, docs/error-contract.schema.json                                                 [gen]
// `--check` writes nothing and exits 1 listing every drifted file. Generated files are never hand-merged: on a conflict
// rerun `npm run generate`. Content comes from scripts/lib/generateContent.mjs, run on the TypeScript sources (no build
// needed); every file is passed through oxfmt with the repository config so `npm run format:check` agrees.
// `--area <name>` (repeatable; `npm run generate -- --area scan`): in a shared working tree, write only those areas'
// slices plus the shared generated files; drifted slices of other areas are reported and left to their owners.
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { writeFileAtomic } from "./lib/atomic.mjs";
import { formatFiles } from "./lib/format.mjs";
import { withBuildLock } from "./lib/lock.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
let check = false;
const areas = new Set();
for (let i = 0; i < args.length; i += 1) {
  if (args[i] === "--check") check = true;
  else if (args[i] === "--area" && /^[a-z]+$/u.test(args[i + 1] ?? "")) areas.add(args[++i]);
  else throw new Error(`generate: unknown option ${args[i]} (use --check and/or --area <name>)`);
}

/** The area of a per-area slice path, or null for the shared generated files. */
const areaOf = (rel) => /^(?:tests\/golden\/catalog|docs\/tools)\/([a-z]+)\.(?:json|md)$/u.exec(rel)?.[1] ?? null;

/** Run the content generator under Node's TypeScript transform with the .js -> .ts resolve hook. */
function generateContent() {
  const run = spawnSync(
    process.execPath,
    [
      "--experimental-transform-types",
      "--disable-warning=ExperimentalWarning",
      "--import",
      pathToFileURL(join(root, "scripts", "lib", "tsHooks.mjs")).href,
      join(root, "scripts", "lib", "generateContent.mjs"),
    ],
    { cwd: root, encoding: "utf8", maxBuffer: 256 * 1024 * 1024, windowsHide: true },
  );
  if (run.status !== 0) {
    process.stderr.write(run.stderr ?? "");
    throw new Error(`generate: content generation failed (exit ${run.status ?? run.signal})`);
  }
  return JSON.parse(run.stdout).files;
}

const readOptional = async (path) => {
  try {
    return await readFile(path, "utf8");
  } catch (cause) {
    if (cause?.code === "ENOENT") return null;
    throw cause;
  }
};

await withBuildLock(async () => {
  const files = await formatFiles(generateContent());
  const known = new Set(
    Object.keys(files)
      .map(areaOf)
      .filter((area) => area !== null),
  );
  for (const area of areas)
    if (!known.has(area)) throw new Error(`generate: unknown area ${area} (areas: ${[...known].join(", ")})`);
  const drifted = [];
  const leftToOwners = [];
  for (const [rel, content] of Object.entries(files)) {
    const current = await readOptional(join(root, rel));
    if (current === content) continue;
    drifted.push(rel);
    if (check) continue;
    const area = areaOf(rel);
    if (areas.size > 0 && area !== null && !areas.has(area)) leftToOwners.push(rel);
    else await writeFileAtomic(join(root, rel), content);
  }
  if (check && drifted.length > 0) {
    process.stderr.write(
      `generate --check: ${drifted.length} generated file(s) are out of date:\n${drifted.map((rel) => `  ${rel}`).join("\n")}\n` +
        "Run `npm run generate` (in a shared tree: `npm run generate -- --area <yours>`) and keep the result; never hand-merge generated files.\n",
    );
    process.exitCode = 1;
    return;
  }
  if (leftToOwners.length > 0)
    process.stderr.write(
      `generate: left ${leftToOwners.length} drifted slice(s) of other areas to their owners:\n${leftToOwners.map((rel) => `  ${rel}`).join("\n")}\n`,
    );
  process.stdout.write(
    check
      ? `generate --check: ${Object.keys(files).length} generated files up to date\n`
      : `generate: ${drifted.length - leftToOwners.length} of ${Object.keys(files).length} generated files updated\n`,
  );
});
