#!/usr/bin/env node
// scripts/build-agent.mjs — DESIGN.md §5.3 (S4 §2.1 staging + S1 §2.4 manifest; conflict C-06).
// Stage src/agent + src/shared (minus host-only files) into build/agent-stage/{agent,shared}, write the agent
// tsconfig at the STAGE ROOT (frida.Compiler reads only <projectRoot>/tsconfig.json), generate buildInfo.ts,
// compile with frida.Compiler (esm, typeCheck full), write dist/agent/bea-agent.js + bea-agent.json.
// WP0 concurrency amendment (shared working tree): the stage is a unique directory under build/tmp/ (removed after the
// build), the outputs are published by rename (bundle first, manifest last), and the whole build holds the "build"
// lock (scripts/lib/lock.mjs; re-entrant under `npm run build`).
import { createHash } from "node:crypto";
import { cp, mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { makeStagingDir, publishFile, removeStagingDir } from "./lib/atomic.mjs";
import { withBuildLock } from "./lib/lock.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const outDir = join(root, "dist", "agent");
const HOST_ONLY_SHARED = new Set([]); // every src/shared file is agent-safe by rule (lint-checked)
/**
 * Bundle size budget (S4 §2.1 "a CI check enforces this"; integrator, implement stage, WP3 change request). The design
 * planned 512 KiB; the integrated agent (core + every feature) measures ~588 KB uncompressed, and compression "terser"
 * (~337 KB) mangles names and collapses lines, which S4 §2.1 rejects to keep stack traces readable. The budget is
 * therefore 640 KiB, enforced here (docs/decisions.md, "Change requests applied (implement stage)").
 */
const BUNDLE_BUDGET_BYTES = 640 * 1024;
/** true (and the reason on stderr) when the bundle is over the budget */
const overBudget = (bundle) => {
  const bytes = Buffer.byteLength(bundle);
  if (bytes <= BUNDLE_BUDGET_BYTES) return false;
  process.stderr.write(
    `build:agent failed: the bundle is ${bytes} bytes, over the ${BUNDLE_BUDGET_BYTES}-byte budget\n`,
  );
  return true;
};
const sha256 = (d) => createHash("sha256").update(d).digest("hex");
const listTs = async (dir) =>
  (await readdir(dir, { recursive: true, withFileTypes: true }))
    .filter((e) => e.isFile() && e.name.endsWith(".ts"))
    .map((e) => join(e.parentPath, e.name));

// frida: the package dependency in the real repo; FRIDA_MODULE overrides for the integration lab.
// (A literal import("frida") so dependency analysis sees the package; WP0.)
const fridaModule = process.env.FRIDA_MODULE
  ? await import(pathToFileURL(process.env.FRIDA_MODULE).href)
  : await import("frida");
const frida = fridaModule.default ?? fridaModule;
/**
 * WP0 fix (the lab only ran the FRIDA_MODULE branch): frida's "exports" map does not export ./package.json, so
 * require("frida/package.json") throws ERR_PACKAGE_PATH_NOT_EXPORTED. Walk up from the resolved entry instead.
 */
const packageVersionAbove = async (entryPath, name) => {
  for (let dir = dirname(entryPath); ; dir = dirname(dir)) {
    try {
      const pkgJson = JSON.parse(await readFile(join(dir, "package.json"), "utf8"));
      if (pkgJson.name === name) return pkgJson.version;
    } catch {
      // no package.json at this level
    }
    if (dirname(dir) === dir) throw new Error(`build:agent: cannot find the ${name} package.json above ${entryPath}`);
  }
};
const fridaVersion = process.env.FRIDA_MODULE
  ? JSON.parse(await readFile(join(dirname(process.env.FRIDA_MODULE), "..", "..", "package.json"), "utf8")).version
  : await packageVersionAbove(createRequire(import.meta.url).resolve("frida"), "frida");

const failed = await withBuildLock(async () => {
  const pkg = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
  const stage = await makeStagingDir("agent-stage", root);
  try {
    await mkdir(join(stage, "agent"), { recursive: true });
    await cp(join(root, "src", "agent"), join(stage, "agent"), {
      recursive: true,
      filter: (p) => !p.endsWith("tsconfig.json"),
    });
    await mkdir(join(stage, "shared"), { recursive: true });
    for (const f of await listTs(join(root, "src", "shared"))) {
      const rel = relative(join(root, "src", "shared"), f);
      if (HOST_ONLY_SHARED.has(rel)) continue;
      await mkdir(dirname(join(stage, "shared", rel)), { recursive: true });
      await cp(f, join(stage, "shared", rel));
    }
    const agentTsconfig = JSON.parse(await readFile(join(root, "src", "agent", "tsconfig.json"), "utf8"));
    agentTsconfig.include = ["agent/**/*.ts", "shared/**/*.ts"];
    await writeFile(join(stage, "tsconfig.json"), JSON.stringify(agentTsconfig, null, 2));
    const sources = (await listTs(stage)).sort();
    const srcDigest = createHash("sha256");
    for (const f of sources) {
      srcDigest
        .update(relative(stage, f).replaceAll("\\", "/"))
        .update("\0")
        .update(await readFile(f))
        .update("\0");
    }
    const sourcesSha = srcDigest.digest("hex");
    const buildId = sourcesSha.slice(0, 16);
    await writeFile(
      join(stage, "agent", "buildInfo.ts"),
      `export const AGENT_VERSION = ${JSON.stringify(pkg.version ?? "0.0.0")};\nexport const AGENT_BUILD_ID = ${JSON.stringify(buildId)};\n`,
    );

    const compiler = new frida.Compiler();
    const diagnostics = [];
    compiler.diagnostics.connect((batch) =>
      diagnostics.push(...JSON.parse(JSON.stringify(batch, (_k, v) => (typeof v === "bigint" ? Number(v) : v)))),
    );
    let bundle;
    try {
      bundle = await compiler.build(join(stage, "agent", "index.ts"), {
        projectRoot: stage,
        bundleFormat: "esm",
        typeCheck: "full",
        sourceMaps: "omitted",
        compression: "none",
      });
    } catch (cause) {
      for (const d of diagnostics)
        process.stderr.write(
          `${d.file?.path ?? "?"}:${(d.file?.line ?? 0) + 1} ${d.category} TS${d.code}: ${d.text}\n`,
        );
      process.stderr.write(`build:agent failed: ${cause?.message ?? cause}\n`);
      return true;
    }
    if (diagnostics.length > 0) {
      for (const d of diagnostics)
        process.stderr.write(
          `${d.file?.path ?? "?"}:${(d.file?.line ?? 0) + 1} ${d.category} TS${d.code}: ${d.text}\n`,
        );
      return true;
    }
    if (overBudget(bundle)) return true;
    const { AGENT_PROTOCOL, AGENT_PROTOCOL_MINOR } = { AGENT_PROTOCOL: "bea-agent/1", AGENT_PROTOCOL_MINOR: 0 };
    const staged = join(stage, "out");
    await mkdir(staged, { recursive: true });
    await writeFile(join(staged, "bea-agent.js"), bundle, "utf8");
    await writeFile(
      join(staged, "bea-agent.json"),
      `${JSON.stringify(
        {
          schema: "bea.agent-build/1",
          file: "bea-agent.js",
          sha256: sha256(bundle),
          bytes: Buffer.byteLength(bundle),
          runtime: "qjs",
          bundle_format: "esm",
          frida_version: fridaVersion,
          protocol: AGENT_PROTOCOL,
          protocol_minor: AGENT_PROTOCOL_MINOR,
          agent_version: pkg.version ?? "0.0.0",
          build_id: buildId,
          sources_sha256: sourcesSha,
        },
        null,
        2,
      )}\n`,
    );
    await mkdir(outDir, { recursive: true });
    await publishFile(join(staged, "bea-agent.js"), join(outDir, "bea-agent.js"));
    await publishFile(join(staged, "bea-agent.json"), join(outDir, "bea-agent.json"));
    process.stdout.write(`build:agent ok ${Buffer.byteLength(bundle)} bytes, build_id ${buildId}\n`);
    return false;
  } finally {
    if (process.env.BEA_KEEP_AGENT_STAGE !== "1") await removeStagingDir(stage);
  }
});
if (failed) process.exit(1);
