import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { publishDir, publishFile, writeFileAtomic } from "../../scripts/lib/atomic.mjs";
import { acquireLock, lockTokenEnv, withLock } from "../../scripts/lib/lock.mjs";

/**
 * The shared-tree build lock (scripts/lib/lock.mjs) and atomic publication (scripts/lib/atomic.mjs), on a temp root so
 * the repository's own build/.locks is never touched. Child processes are plain `node` scripts this test writes.
 */
const lockModule = pathToFileURL(join(import.meta.dirname, "..", "..", "scripts", "lib", "lock.mjs")).href;
let root: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "bea-test-lock-"));
});
afterEach(async () => {
  await rm(root, { recursive: true, force: true, maxRetries: 5 });
});

/**
 * Runs a child node process with an ESM body; resolves with its exit code and output. The child is an UNRELATED
 * process: lock tokens this test process holds are not inherited unless passed in `env`.
 */
const runChild = (body: string, env: Readonly<Record<string, string>> = {}) =>
  new Promise<{ code: number | null; out: string; err: string }>((resolve, reject) => {
    const script = `import { acquireLock, withLock } from ${JSON.stringify(lockModule)};\nconst root = ${JSON.stringify(root)};\n${body}`;
    const inherited = Object.fromEntries(
      Object.entries(process.env).filter(([key]) => !key.startsWith("BEA_LOCK_TOKEN_")),
    );
    const child = spawn(process.execPath, ["--input-type=module", "-e", script], {
      env: { ...inherited, ...env },
      windowsHide: true,
    });
    let out = "";
    let err = "";
    child.stdout.on("data", (chunk: Buffer) => (out += chunk.toString()));
    child.stderr.on("data", (chunk: Buffer) => (err += chunk.toString()));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, out, err }));
  });

describe("build lock", () => {
  it("re-enters in-process and releases on the outermost release", async () => {
    const outer = await acquireLock("unit", { root, log: () => undefined });
    const inner = await acquireLock("unit", { root, log: () => undefined });
    expect(outer.reentrant).toBe(false);
    expect(inner.reentrant).toBe(true);
    expect(process.env[lockTokenEnv("unit")]).toBe(outer.token);
    inner.release();
    expect(existsSync(join(root, "build", ".locks", "unit"))).toBe(true);
    outer.release();
    expect(existsSync(join(root, "build", ".locks", "unit"))).toBe(false);
    expect(process.env[lockTokenEnv("unit")]).toBeUndefined();
  });

  it("serializes holders across processes", async () => {
    const log = join(root, "order.log");
    const body = `import { appendFileSync } from "node:fs";
await withLock("unit", async () => {
  appendFileSync(${JSON.stringify(log)}, "enter " + process.pid + "\\n");
  await new Promise((r) => setTimeout(r, 150));
  appendFileSync(${JSON.stringify(log)}, "exit " + process.pid + "\\n");
}, { root, log: () => undefined });`;
    const results = await Promise.all([runChild(body), runChild(body), runChild(body)]);
    expect(results.map((r) => r.code)).toEqual([0, 0, 0]);
    const lines = (await readFile(log, "utf8")).trim().split("\n");
    expect(lines).toHaveLength(6);
    for (let i = 0; i < lines.length; i += 2) {
      expect(lines[i]?.startsWith("enter ")).toBe(true);
      expect(lines[i + 1]).toBe(`exit ${lines[i]?.slice("enter ".length)}`);
    }
  });

  it("lets a child of the holder re-enter through the inherited token", async () => {
    await withLock(
      "unit",
      async (lock) => {
        const child = await runChild(
          `const lock = await acquireLock("unit", { root, timeoutMs: 2000, log: () => undefined }); console.log(JSON.stringify({ reentrant: lock.reentrant, token: lock.token })); lock.release();`,
          { [lockTokenEnv("unit")]: lock.token },
        );
        expect(child.code).toBe(0);
        expect(JSON.parse(child.out)).toEqual({ reentrant: true, token: lock.token });
      },
      { root, log: () => undefined },
    );
  });

  it("bounds the wait with a message that names the holder", async () => {
    await withLock(
      "unit",
      async () => {
        const child = await runChild(
          `try { await acquireLock("unit", { root, timeoutMs: 400, log: () => undefined }); console.log("acquired"); } catch (e) { console.log(e.message); }`,
        );
        expect(child.out).toContain("timed out");
        expect(child.out).toContain(`pid ${process.pid}`);
      },
      { root, log: () => undefined, command: "unit-test holder" },
    );
  });

  it("takes over a lock whose owner process is gone", async () => {
    const dead = await runChild("console.log(process.pid);");
    const lockDir = join(root, "build", ".locks", "unit");
    await mkdir(lockDir, { recursive: true });
    await writeFile(
      join(lockDir, "owner.json"),
      JSON.stringify({
        schema: "bea.lock/1",
        name: "unit",
        pid: Number(dead.out.trim()),
        start: { kind: "time-origin", ms: 0 },
        token: "dead-owner",
      }),
    );
    const messages: string[] = [];
    const lock = await acquireLock("unit", { root, timeoutMs: 5000, log: (line) => void messages.push(line) });
    expect(lock.reentrant).toBe(false);
    expect(messages.join("\n")).toContain("took over a stale lock");
    lock.release();
  });

  // The start-time comparison is the win32 path (PowerShell Get-Process); Linux compares /proc start ticks.
  it.runIf(process.platform === "win32")(
    "takes over a lock whose pid now belongs to a different process start",
    async () => {
      const lockDir = join(root, "build", ".locks", "unit");
      await mkdir(lockDir, { recursive: true });
      // A live pid (this worker) recorded with a start time decades away: the pid was "reused".
      await writeFile(
        join(lockDir, "owner.json"),
        JSON.stringify({
          schema: "bea.lock/1",
          name: "unit",
          pid: process.pid,
          start: { kind: "time-origin", ms: 1 },
          token: "old-owner",
        }),
      );
      const messages: string[] = [];
      const lock = await acquireLock("unit", { root, timeoutMs: 20_000, log: (line) => void messages.push(line) });
      expect(messages.join("\n")).toContain("now belongs to another process");
      lock.release();
    },
  );
});

describe("atomic publication", () => {
  it("replaces files and directories by rename", async () => {
    const dest = join(root, "out", "file.txt");
    await writeFileAtomic(dest, "one");
    await writeFileAtomic(dest, "two");
    expect(await readFile(dest, "utf8")).toBe("two");
    const staged = join(root, "staged.txt");
    await writeFile(staged, "three");
    await publishFile(staged, dest);
    expect(await readFile(dest, "utf8")).toBe("three");
    expect(existsSync(staged)).toBe(false);

    const stagedDir = join(root, "stage-dir");
    await mkdir(stagedDir);
    await writeFile(join(stagedDir, "a.txt"), "new");
    await publishDir(stagedDir, join(root, "out"));
    expect(await readFile(join(root, "out", "a.txt"), "utf8")).toBe("new");
    expect(existsSync(join(root, "out", "file.txt"))).toBe(false);
  });
});
