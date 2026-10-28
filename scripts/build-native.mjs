#!/usr/bin/env node
// scripts/build-native.mjs — DESIGN.md §5.2 (S1 §2.4 script + S3 §5.6 flags/protocol; conflict C-28).
// gcc → dist/native/win32-x64/bea-jobhost.exe + bea-jobhost.json (bea.native-build/1). Never committed.
// WP0 concurrency amendment (shared working tree): gcc writes into a unique directory under build/tmp/, the exe and
// then the manifest are published by rename (a running jobhost is moved aside, never overwritten), and the build
// holds the "build" lock (scripts/lib/lock.mjs; re-entrant under `npm run build`).
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { makeStagingDir, publishFile, removeStagingDir } from "./lib/atomic.mjs";
import { withBuildLock } from "./lib/lock.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
if (process.platform !== "win32" || process.env.BEA_SKIP_NATIVE === "1") {
  process.stderr.write(
    `build:native skipped (${process.platform !== "win32" ? "jobhost is Windows-only" : "BEA_SKIP_NATIVE=1"}); spawn_process will report capability_unavailable(jobhost).\n`,
  );
  process.exit(0);
}
const source = join(root, "native", "jobhost", "bea-jobhost.c");
try {
  await access(source);
} catch {
  process.stderr.write("build:native: native/jobhost/bea-jobhost.c is missing.\n");
  process.exit(1);
}
const cc = process.env.CC ?? "gcc";
const probe = spawnSync(cc, ["--version"], { encoding: "utf8" });
if (probe.status !== 0) {
  process.stderr.write(
    `build:native: '${cc}' not found. Install WinLibs MinGW-w64 gcc or set CC, or set BEA_SKIP_NATIVE=1.\n`,
  );
  process.exit(1);
}
const outDir = join(root, "dist", "native", "win32-x64");

const status = await withBuildLock(async () => {
  const stage = await makeStagingDir("native", root);
  try {
    const out = join(stage, "bea-jobhost.exe");
    // S3 §5.6 flags (VERIFIED warning-free with the protocol-1 source): -municode + _WIN32_WINNT for JOB_LIST/wmain,
    // --no-insert-timestamp for byte-reproducible builds, -static so the helper imports only KERNEL32/ADVAPI32/msvcrt.
    const args = [
      "-O2",
      "-s",
      "-municode",
      "-D_WIN32_WINNT=0x0A00",
      "-static",
      "-Wall",
      "-Wextra",
      "-Werror",
      "-Wl,--no-insert-timestamp",
      "-o",
      out,
      source,
    ];
    const run = spawnSync(cc, args, { stdio: "inherit" });
    if (run.status !== 0) return run.status ?? 1;
    const exe = await readFile(out);
    await writeFile(
      join(stage, "bea-jobhost.json"),
      `${JSON.stringify(
        {
          schema: "bea.native-build/1",
          file: "bea-jobhost.exe",
          protocol: 1,
          sha256: createHash("sha256").update(exe).digest("hex"),
          bytes: exe.length,
          compiler: { command: cc, version: probe.stdout.split(/\r?\n/u)[0] },
          args: args.map((a) => (a === out ? "<out>" : a === source ? "<source>" : a)),
          source_sha256: createHash("sha256")
            .update(await readFile(source))
            .digest("hex"),
        },
        null,
        2,
      )}\n`,
    );
    await mkdir(outDir, { recursive: true });
    await publishFile(out, join(outDir, "bea-jobhost.exe"));
    await publishFile(join(stage, "bea-jobhost.json"), join(outDir, "bea-jobhost.json"));
    process.stdout.write(`build:native ok ${exe.length} bytes\n`);
    return 0;
  } finally {
    await removeStagingDir(stage);
  }
});
if (status !== 0) process.exit(status);
