// scripts/lib/format.mjs (WP0): formats generated files with the repository's oxfmt configuration, so committed
// generated files always pass `npm run format:check` and `generate --check` never fights the formatter.
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { writeFileAtomic } from "./atomic.mjs";
import { REPO_ROOT } from "./lock.mjs";

/**
 * { "<repo-relative path>": content } -> the same map, formatted. One oxfmt run in a scratch tree OUTSIDE the
 * repository (the repository's ignore patterns, such as build/**, must not apply), laid out with the same paths.
 */
export async function formatFiles(files, root = REPO_ROOT) {
  const scratch = await mkdtemp(join(tmpdir(), "bea-format-"));
  try {
    for (const [rel, content] of Object.entries(files)) await writeFileAtomic(join(scratch, rel), content);
    const run = spawnSync(
      process.execPath,
      [join(root, "node_modules", "oxfmt", "bin", "oxfmt"), `--config=${join(root, ".oxfmtrc.json")}`, "."],
      { cwd: scratch, encoding: "utf8", windowsHide: true },
    );
    if (run.status !== 0) {
      process.stderr.write(`${run.stdout ?? ""}${run.stderr ?? ""}`);
      throw new Error(`oxfmt failed (exit ${run.status ?? run.signal})`);
    }
    const formatted = {};
    for (const rel of Object.keys(files)) formatted[rel] = await readFile(join(scratch, rel), "utf8");
    return formatted;
  } finally {
    await rm(scratch, { recursive: true, force: true, maxRetries: 3 });
  }
}
