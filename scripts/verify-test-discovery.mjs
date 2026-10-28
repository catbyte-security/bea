#!/usr/bin/env node
// scripts/verify-test-discovery.mjs (WP0; S1 §1.1, CI-M19). Fails when:
//   - a *.test.ts file under src/ or tests/ matches no vitest project, or more than one;
//   - a file looks like a test but uses a name no project collects (*.spec.*, *.test.{js,mjs,mts,tsx});
//   - any test lives under src/agent/ (it would be staged into the frida.Compiler build; tests of agent pure helpers
//     belong in tests/unit/agent/);
//   - scripts/lib/testProjects.mjs disagrees with the projects declared in vitest.config.ts.
import { readdir, readFile } from "node:fs/promises";
import { join, matchesGlob, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { TEST_PROJECTS } from "./lib/testProjects.mjs";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const SKIP_DIRS = new Set(["node_modules", "dist", "build", ".cache", "coverage", ".git"]);

async function walk(dir, out = []) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch (cause) {
    if (cause?.code === "ENOENT") return out;
    throw cause;
  }
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) await walk(join(dir, entry.name), out);
    } else out.push(relative(root, join(dir, entry.name)).replaceAll("\\", "/"));
  }
  return out;
}

/** { name: [globs] } from vitest.config.ts (its project entries are one line each: name then include). */
function projectsFromConfig(text) {
  const projects = {};
  for (const match of text.matchAll(/name:\s*"([^"]+)",\s*include:\s*\[([^\]]*)\]/gu))
    projects[match[1]] = [...match[2].matchAll(/"([^"]+)"/gu)].map((m) => m[1]);
  return projects;
}

const problems = [];
const configProjects = projectsFromConfig(await readFile(join(root, "vitest.config.ts"), "utf8"));
const tableProjects = Object.fromEntries(TEST_PROJECTS.map((p) => [p.name, p.include]));
if (JSON.stringify(configProjects) !== JSON.stringify(tableProjects))
  problems.push(
    `scripts/lib/testProjects.mjs does not match vitest.config.ts:\n    config: ${JSON.stringify(configProjects)}\n    table:  ${JSON.stringify(tableProjects)}`,
  );

const files = [...(await walk(join(root, "src"))), ...(await walk(join(root, "tests")))].sort();
let tests = 0;
for (const file of files) {
  if (/\.(?:spec)\.[cm]?[jt]sx?$/u.test(file) || /\.test\.(?:[cm]?js|mts|cts|tsx)$/u.test(file)) {
    problems.push(`${file}: test files must be named *.test.ts to be collected by a vitest project`);
    continue;
  }
  if (!file.endsWith(".test.ts")) continue;
  tests += 1;
  if (file.startsWith("src/agent/"))
    problems.push(`${file}: no tests under src/agent (move it to tests/unit/agent/; CI-M19)`);
  const owners = TEST_PROJECTS.filter((p) => p.include.some((glob) => matchesGlob(file, glob))).map((p) => p.name);
  if (owners.length !== 1)
    problems.push(
      `${file}: belongs to ${owners.length === 0 ? "no vitest project" : `${owners.length} projects (${owners.join(", ")})`}`,
    );
}

if (problems.length > 0) {
  process.stderr.write(
    `verify-test-discovery: ${problems.length} problem(s)\n${problems.map((p) => `  ${p}`).join("\n")}\n`,
  );
  process.exitCode = 1;
} else process.stdout.write(`verify-test-discovery: ${tests} test files, each in exactly one project\n`);
