#!/usr/bin/env node
// scripts/verify-module-boundaries.mjs (WP0; DESIGN §4.1 module-boundary table, S1 §1.3 + D-INT-14). Run by
// `npm run lint` after oxlint. Checks every import edge of src/**/*.ts against the layer table, plus the §4.1 text
// rules oxlint cannot express exactly:
//   - only src/providers/frida/fridaLoader.ts loads frida (dynamic import); elsewhere frida is type-only;
//   - device.kill only in src/providers/frida/{spawnSession,startupCleanup}.ts;
//   - no enumerateProcesses({pids}) liveness probes;
//   - AbortSignal.any only in src/domain/abort.ts;
//   - node:child_process only in src/providers/process/** and src/providers/emulator/{EmuBridge,pythonResolver,
//     venvProvisioner}.ts.
// Usage: node scripts/verify-module-boundaries.mjs [file.ts ...]   (default: every .ts file under src/)
import { builtinModules } from "node:module";
import { readdir, readFile } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
const DEPENDENCIES = new Set(Object.keys(pkg.dependencies ?? {}));
const BUILTINS = new Set(builtinModules.filter((m) => !m.startsWith("_")));

const PROVIDERS = ["frida", "process", "evidence", "pe", "emulator"];
/** Zone of a repo-relative path (forward slashes), or null outside src. */
function zoneOf(rel) {
  if (rel === "src/identity.ts") return "identity";
  for (const provider of PROVIDERS) if (rel.startsWith(`src/providers/${provider}/`)) return `providers/${provider}`;
  const match = /^src\/([^/]+)\//u.exec(rel);
  return match ? match[1] : null;
}

const NODE_ANY = { node: "any" };
const NODE_ANY_BUT_NETWORK = { node: "any", nodeDenied: ["child_process", "net", "http", "https"] };
/** importer zone -> allowed relative target zones, packages, node policy. */
const RULES = {
  shared: { zones: ["shared"], packages: [], node: "none" },
  agent: { zones: ["agent", "shared"], packages: [], node: "none" },
  domain: { zones: ["domain", "shared"], packages: ["zod"], node: "list", nodeAllowed: ["crypto", "path", "util"] },
  ports: {
    zones: ["ports", "domain", "shared"],
    packages: [],
    node: "list",
    nodeAllowed: ["stream", "fs/promises"],
    typeOnly: true,
  },
  contracts: { zones: ["contracts", "domain", "shared"], packages: ["zod"], node: "none" },
  application: {
    zones: ["application", "ports", "contracts", "domain", "shared", "identity"],
    packages: ["zod"],
    ...NODE_ANY_BUT_NETWORK,
  },
  ...Object.fromEntries(
    PROVIDERS.map((provider) => [
      `providers/${provider}`,
      {
        zones: [`providers/${provider}`, "application", "ports", "domain", "shared"],
        packages: provider === "evidence" ? ["yazl", "yauzl"] : provider === "frida" ? ["frida"] : [],
        ...NODE_ANY,
      },
    ]),
  ),
  server: {
    zones: ["server", "application", "ports", "contracts", "domain", "shared", "identity"],
    packages: ["@modelcontextprotocol/server", "zod"],
    ...NODE_ANY,
  },
  cli: {
    zones: ["cli", "application", "ports", "contracts", "domain", "shared", "identity"],
    packages: ["@toon-format/toon", "jsonc-parser", "smol-toml", "@modelcontextprotocol/client", "zod"],
    ...NODE_ANY,
  },
  main: { zones: "any", packages: "dependencies", ...NODE_ANY },
  identity: { zones: ["generated"], packages: [], node: "none" },
  generated: { zones: [], packages: [], node: "none" },
};

const CHILD_PROCESS_ALLOWED = (rel) =>
  rel.startsWith("src/providers/process/") ||
  [
    "src/providers/emulator/EmuBridge.ts",
    "src/providers/emulator/pythonResolver.ts",
    "src/providers/emulator/venvProvisioner.ts",
  ].includes(rel);

async function listSources(dir, out = []) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) await listSources(path, out);
    else if (entry.name.endsWith(".ts") && !entry.name.endsWith(".d.ts")) out.push(path);
  }
  return out;
}

/**
 * Import edges of one source file. Statements must start a line (commented-out code starts with // or *), which is
 * how the formatter writes them; dynamic import() is matched anywhere outside comment lines.
 */
function importsOf(text) {
  const edges = [];
  const statement = /^[ \t]*(import|export)\s+(type\s+)?([^;]*?)\bfrom\s*["']([^"']+)["']/gmu;
  for (const m of text.matchAll(statement)) {
    if (m[1] === "export" && !/[{*]/u.test(m[3] ?? "") && m[2] === undefined) continue; // `export const x = ... from` text
    edges.push({ specifier: m[4], typeOnly: m[2] !== undefined, line: lineOf(text, m.index) });
  }
  for (const m of text.matchAll(/^[ \t]*import\s*["']([^"']+)["']/gmu))
    edges.push({ specifier: m[1], typeOnly: false, line: lineOf(text, m.index) });
  const lines = text.split("\n");
  lines.forEach((line, i) => {
    if (/^\s*(?:\/\/|\*|\/\*)/u.test(line)) return;
    for (const m of line.matchAll(/\bimport\s*\(\s*["']([^"']+)["']\s*\)/gu))
      edges.push({ specifier: m[1], typeOnly: false, dynamic: true, line: i + 1 });
  });
  return edges;
}
const lineOf = (text, index) => text.slice(0, index).split("\n").length;
const packageName = (specifier) =>
  specifier.startsWith("@") ? specifier.split("/").slice(0, 2).join("/") : specifier.split("/")[0];

function checkEdge(rel, zone, rule, edge, problems) {
  const where = `${rel}:${edge.line}`;
  const { specifier } = edge;
  if (rule.typeOnly && !edge.typeOnly) problems.push(`${where}: ${zone} may only import types ("${specifier}")`);
  if (specifier.startsWith(".")) {
    const target = relative(root, resolve(dirname(join(root, rel)), specifier))
      .replaceAll("\\", "/")
      .replace(/\.js$/u, ".ts");
    const targetZone = zoneOf(target);
    if (targetZone === null) problems.push(`${where}: import outside src ("${specifier}")`);
    else if (rule.zones !== "any" && !rule.zones.includes(targetZone))
      problems.push(`${where}: ${zone} may not import ${targetZone} ("${specifier}")`);
    return;
  }
  const isNode = specifier.startsWith("node:") || BUILTINS.has(specifier) || BUILTINS.has(specifier.split("/")[0]);
  if (isNode) {
    const name = specifier.replace(/^node:/u, "");
    if (!specifier.startsWith("node:")) problems.push(`${where}: use the node: prefix ("${specifier}")`);
    if (name === "child_process" && !CHILD_PROCESS_ALLOWED(rel))
      problems.push(
        `${where}: node:child_process is allowed only in src/providers/process/** and the emulator bridge/resolver/provisioner`,
      );
    if (rule.node === "none") problems.push(`${where}: ${zone} may not import Node modules ("${specifier}")`);
    else if (rule.node === "list" && !rule.nodeAllowed.includes(name))
      problems.push(
        `${where}: ${zone} may import only ${rule.nodeAllowed.map((n) => `node:${n}`).join(", ")} ("${specifier}")`,
      );
    else if (rule.nodeDenied?.includes(name)) problems.push(`${where}: ${zone} may not import ${specifier}`);
    return;
  }
  const name = packageName(specifier);
  if (name === "frida") {
    const loader = rel === "src/providers/frida/fridaLoader.ts";
    if (edge.dynamic ? !loader : !edge.typeOnly)
      problems.push(
        `${where}: only src/providers/frida/fridaLoader.ts may load frida (import("frida")); elsewhere use import type`,
      );
    if (!edge.dynamic && !["providers/frida", "main"].includes(zone))
      problems.push(`${where}: ${zone} may not import frida types`);
    return;
  }
  const allowed = rule.packages === "dependencies" ? DEPENDENCIES.has(name) : rule.packages.includes(name);
  if (!allowed) problems.push(`${where}: ${zone} may not import the package "${name}"`);
}

function checkText(rel, text, problems) {
  const lines = text.split("\n");
  lines.forEach((line, i) => {
    const where = `${rel}:${i + 1}`;
    if (/^\s*(?:\/\/|\*|\/\*)/u.test(line)) return;
    if (/AbortSignal\s*\.\s*any\b/u.test(line) && rel !== "src/domain/abort.ts")
      problems.push(`${where}: AbortSignal.any is allowed only in src/domain/abort.ts (use composeSignal, CT-I2)`);
    if (
      /\bdevice\s*\.\s*kill\s*\(/u.test(line) &&
      !["src/providers/frida/spawnSession.ts", "src/providers/frida/startupCleanup.ts"].includes(rel)
    )
      problems.push(
        `${where}: device.kill is allowed only in spawnSession.ts and startupCleanup.ts (attached targets are never killed)`,
      );
  });
  for (const m of text.matchAll(/\benumerateProcesses\s*\(\s*\{[^)]*\bpids\b/gu))
    problems.push(
      `${rel}:${lineOf(text, m.index)}: enumerateProcesses({pids}) is not a liveness probe (use the jobhost watcher)`,
    );
}

const selected = process.argv.slice(2);
const files = selected.length > 0 ? selected.map((f) => resolve(f)) : await listSources(join(root, "src"));
const problems = [];
for (const file of files) {
  const rel = relative(root, file).replaceAll("\\", "/");
  const zone = zoneOf(rel);
  if (zone === null) continue;
  const rule = RULES[zone];
  const text = await readFile(file, "utf8");
  if (rule === undefined) {
    problems.push(`${rel}: no module-boundary rule for zone "${zone}" (add the directory to the §4.1 table first)`);
    continue;
  }
  for (const edge of importsOf(text)) checkEdge(rel, zone, rule, edge, problems);
  checkText(rel, text, problems);
}
if (problems.length > 0) {
  process.stderr.write(
    `verify-module-boundaries: ${problems.length} problem(s)\n${problems.map((p) => `  ${p}`).join("\n")}\n`,
  );
  process.exitCode = 1;
} else process.stdout.write(`verify-module-boundaries: ${files.length} files ok\n`);
