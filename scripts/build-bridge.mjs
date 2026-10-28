#!/usr/bin/env node
// scripts/build-bridge.mjs (WP14-EMU; DESIGN §3, §5.6; S5 §2 "Packaging"): `npm run build:bridge`.
//
// The emulator bridge is shipped as source in the package root (bridge/emu/, see src/application/distLayout.ts); the
// build only stamps and fingerprints it:
//   1. BRIDGE_VERSION in bridge/emu/bea_emu_bridge.py must equal package.json "version" (S5 §2: the bridge version is
//      the package version). A different literal is re-stamped in place (atomic rewrite, logged); `--check` fails
//      instead of writing anything.
//   2. PROTOCOL in the bridge must be "bea-emu/0.1" (src/domain/emuProtocol.ts EMU_PROTOCOL).
//   3. dist/bridge-manifest.json gets the sha256 of the bridge, requirements.lock and README.md. The TypeScript client
//      compares the bridge's self-reported sha256 (`ready.bridge.sha256`) with `sha256`, and `bridge_version` with
//      `ready.bridge.version`; `bea doctor` checks `requirements_lock_sha256` against the venv marker.
// Manifest (schema "bea.bridge-build/1"): { schema, protocol, bridge_version, file, sha256, bytes,
//   requirements_lock_sha256, files: { "bea_emu_bridge.py", "requirements.lock", "README.md": sha256 }, engines }.
// Runs under the cross-process "build" lock (re-entrant inside `npm run build`); writes are atomic.
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { writeFileAtomic } from "./lib/atomic.mjs";
import { withBuildLock } from "./lib/lock.mjs";

const PROTOCOL = "bea-emu/0.1";
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const bridgeDir = join(root, "bridge", "emu");
const bridgePath = join(bridgeDir, "bea_emu_bridge.py");
const lockPath = join(bridgeDir, "requirements.lock");
const readmePath = join(bridgeDir, "README.md");
const manifestPath = join(root, "dist", "bridge-manifest.json");

const VERSION_LINE = /^BRIDGE_VERSION = "([^"\r\n]*)"(.*)$/mu;
const PROTOCOL_LINE = /^PROTOCOL = "([^"\r\n]*)"$/mu;
const PIN_LINE = /^([A-Za-z0-9_.-]+)==(\S+)/gmu;

const sha256 = (data) => createHash("sha256").update(data).digest("hex");

const args = process.argv.slice(2);
for (const arg of args) if (arg !== "--check") throw new Error(`build-bridge: unknown option ${arg}`);
const check = args.includes("--check");

const fail = (message) => {
  process.stderr.write(`build:bridge FAILED: ${message}\n`);
  process.exitCode = 1;
};

const manifestFor = (source, lock, readme, version) => ({
  schema: "bea.bridge-build/1",
  protocol: PROTOCOL,
  bridge_version: version,
  file: "bridge/emu/bea_emu_bridge.py",
  sha256: sha256(source),
  bytes: source.length,
  requirements_lock_sha256: sha256(lock),
  files: {
    "bea_emu_bridge.py": sha256(source),
    "requirements.lock": sha256(lock),
    "README.md": sha256(readme),
  },
  engines: Object.fromEntries([...lock.toString("utf8").matchAll(PIN_LINE)].map((m) => [m[1].toLowerCase(), m[2]])),
});

await withBuildLock(async () => {
  const pkg = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
  const version = String(pkg.version);
  let source = await readFile(bridgePath);
  const [lock, readme] = await Promise.all([readFile(lockPath), readFile(readmePath)]);
  const text = source.toString("utf8");
  const protocol = PROTOCOL_LINE.exec(text);
  if (protocol?.[1] !== PROTOCOL) return fail(`bridge PROTOCOL is ${protocol?.[1] ?? "missing"}, expected ${PROTOCOL}`);
  const stamped = VERSION_LINE.exec(text);
  if (stamped === null) return fail('bridge has no `BRIDGE_VERSION = "..."` line to stamp');
  if (stamped[1] !== version) {
    if (check)
      return fail(`bridge BRIDGE_VERSION ${stamped[1]} != package version ${version} (run npm run build:bridge)`);
    source = Buffer.from(text.replace(VERSION_LINE, `BRIDGE_VERSION = "${version}"$2`), "utf8");
    await writeFileAtomic(bridgePath, source);
    process.stderr.write(`build:bridge stamped BRIDGE_VERSION ${stamped[1]} -> ${version}\n`);
  }
  const manifest = manifestFor(source, lock, readme, version);
  const body = `${JSON.stringify(manifest, null, 2)}\n`;
  if (check) {
    let current = null;
    try {
      current = await readFile(manifestPath, "utf8");
    } catch (cause) {
      if (cause?.code !== "ENOENT") throw cause;
    }
    if (current !== body) return fail("dist/bridge-manifest.json is missing or stale (run npm run build:bridge)");
    process.stdout.write(`build:bridge --check ok (${manifest.sha256.slice(0, 16)})\n`);
    return;
  }
  await writeFileAtomic(manifestPath, body);
  process.stdout.write(
    `build:bridge ok (${source.length}-byte bridge ${version}, sha256 ${manifest.sha256.slice(0, 16)}…)\n`,
  );
});
