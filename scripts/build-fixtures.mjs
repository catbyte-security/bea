#!/usr/bin/env node
// scripts/build-fixtures.mjs (WP0; DESIGN §8.1, S6 §10.2): `npm run build:fixtures`. Builds (or reuses) every fixture
// into .cache/fixtures/<key>/ with its manifest and fails on a broken fixture invariant. Without gcc/objdump it prints
// the named-skip reason and exits 0. Options: --force (rebuild even when cached), --json (print the manifest).
import { buildFixtures } from "./lib/fixtures.mjs";

const args = process.argv.slice(2);
for (const arg of args)
  if (arg !== "--force" && arg !== "--json") throw new Error(`build-fixtures: unknown option ${arg}`);

try {
  const manifest = await buildFixtures({ force: args.includes("--force") });
  if ("unavailable" in manifest) {
    process.stderr.write(`build:fixtures SKIPPED: ${manifest.unavailable}\n`);
  } else if (args.includes("--json")) {
    process.stdout.write(`${JSON.stringify(manifest, null, 1)}\n`);
  } else {
    const ids = Object.keys(manifest.artifacts);
    process.stdout.write(`build:fixtures ok ${ids.length} artifacts (${ids.join(", ")})\n  ${manifest.dir}\n`);
  }
} catch (cause) {
  process.stderr.write(`build:fixtures FAILED: ${cause?.message ?? cause}\n`);
  process.exitCode = 1;
}
