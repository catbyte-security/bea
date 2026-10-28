#!/usr/bin/env node
// scripts/lib/lock.mjs — cross-process mutex for one shared working tree (WP0; docs/testing.md "Build lock").
//
// Several agents build and test in the same checkout at once, so every build-like script (build, build:ts,
// build:agent, build:native, build:bridge, build:skill, build:fixtures, generate, snapshot-dist, catalog-golden)
// holds the "build" lock while it reads sources or writes outputs.
//
// Mechanism: the lock is the directory build/.locks/<name>. mkdir is atomic, so exactly one process creates it; the
// owner then writes owner.json {pid, start, token, command, ...}. A waiter polls with a bounded wait. A lock whose
// owner process is gone (or whose pid now belongs to a different process start) is stale: one waiter claims the
// takeover with an exclusive marker file, renames the directory away and competes for the mkdir again.
// Nested invocations re-enter: the holder exports BEA_LOCK_TOKEN_<NAME> to its children (npm run build -> npm run
// build:agent -> node scripts/build-agent.mjs), and in-process nesting is tracked per name.
//
// CLI: node scripts/lib/lock.mjs <name> [--timeout-ms N] -- <command...>
//   runs the command (through the platform shell, so `a && b` chains work) while holding the lock and exits with
//   its exit code.
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { closeSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

const DEFAULT_TIMEOUT_MS = 20 * 60_000;
const POLL_MS = 200;
const REPORT_EVERY_MS = 30_000;
/** A lock directory without owner.json is a crash between mkdir and the owner write after this long. */
const ORPHAN_DIR_MS = 10_000;
/**
 * win32: the owner's recorded start (performance.timeOrigin) and the OS creation time differ by Node's startup. Wide on
 * purpose: misjudging a live owner as stale would break mutual exclusion, misjudging a reused pid only delays a waiter.
 */
const START_TOLERANCE_MS = 60_000;

/** Environment variable that carries a held lock's token to child processes. */
export const lockTokenEnv = (name) => `BEA_LOCK_TOKEN_${name.toUpperCase().replace(/[^A-Z0-9]/gu, "_")}`;

const NAME_RE = /^[a-z][a-z0-9-]{0,31}$/u;
const randomHex = (bytes) => randomBytes(bytes).toString("hex");
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

/** name -> { token, depth } for locks this process holds (in-process re-entry). */
const held = new Map();

/** Start of the current process as the lock records it (see processStartOf for the comparison side). */
const ownStart = () => {
  if (process.platform === "linux") {
    const ticks = procStatStartTicks("self");
    if (ticks !== null) return { kind: "proc-stat", ticks };
  }
  return { kind: "time-origin", ms: Math.round(performance.timeOrigin) };
};

function procStatStartTicks(pid) {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    // Field 22 (starttime) counted after the parenthesised command name, which may contain spaces.
    const fields = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
    const ticks = fields[19];
    return ticks === undefined ? null : ticks;
  } catch {
    return null;
  }
}

/** true when a process with this pid exists (EPERM: it exists but belongs to someone else). */
const isAlive = (pid) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (cause) {
    return cause?.code === "EPERM";
  }
};

const startCache = new Map();
/**
 * Does the live process `pid` have the start recorded in owner.json? null = cannot tell (treated as "same process",
 * so an unverifiable owner is waited for, never stolen).
 */
function sameStart(pid, start) {
  if (start?.kind === "proc-stat") {
    const ticks = procStatStartTicks(String(pid));
    return ticks === null ? null : ticks === start.ticks;
  }
  if (start?.kind !== "time-origin" || process.platform !== "win32") return null;
  const key = `${pid}:${start.ms}`;
  if (startCache.has(key)) return startCache.get(key);
  // ~0.5 s, once per (owner, start): only reached when a live pid holds the lock we are waiting for.
  const probe = spawnSync(
    "powershell.exe",
    [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      `$p = Get-Process -Id ${Number(pid)} -ErrorAction SilentlyContinue; if ($p) { [DateTimeOffset]::new($p.StartTime).ToUnixTimeMilliseconds() }`,
    ],
    { encoding: "utf8", windowsHide: true, timeout: 15_000 },
  );
  const ms = Number.parseInt((probe.stdout ?? "").trim(), 10);
  const verdict = probe.status === 0 && Number.isFinite(ms) ? Math.abs(ms - start.ms) <= START_TOLERANCE_MS : null;
  startCache.set(key, verdict);
  return verdict;
}

const readOwner = (lockDir) => {
  try {
    return JSON.parse(readFileSync(join(lockDir, "owner.json"), "utf8"));
  } catch {
    return null;
  }
};

const ageMs = (path) => {
  try {
    return Date.now() - statSync(path).mtimeMs;
  } catch {
    return 0;
  }
};

/** Why the current owner no longer holds the lock, or null while it does. */
function staleReason(lockDir, owner) {
  if (owner === null) return ageMs(lockDir) > ORPHAN_DIR_MS ? "lock directory without an owner record" : null;
  if (!Number.isInteger(owner.pid) || !isAlive(owner.pid)) return `owner pid ${owner.pid} is gone`;
  return sameStart(owner.pid, owner.start) === false ? `pid ${owner.pid} now belongs to another process` : null;
}

/**
 * Exactly one waiter may remove a given stale lock: the one that creates takeover-<token> inside it. If the lock was
 * replaced meanwhile (new token), the marker is withdrawn and nothing is removed.
 */
function takeOver(lockDir, owner) {
  const marker = join(lockDir, `takeover-${owner?.token ?? "orphan"}`);
  let fd;
  try {
    fd = openSync(marker, "wx");
  } catch {
    return false; // another waiter is taking it over, or the directory vanished
  }
  closeSync(fd);
  const current = readOwner(lockDir);
  if ((current?.token ?? null) !== (owner?.token ?? null)) {
    rmSync(marker, { force: true });
    return false;
  }
  const aside = `${lockDir}.stale-${process.pid}-${randomHex(4)}`;
  try {
    renameSync(lockDir, aside);
  } catch {
    return false;
  }
  rmSync(aside, { recursive: true, force: true, maxRetries: 3 });
  return true;
}

const describeOwner = (owner) =>
  owner === null ? "an unknown owner" : `pid ${owner.pid} (${owner.command ?? "?"}) since ${owner.acquired_at ?? "?"}`;

/**
 * Acquire `name`. Returns { name, token, reentrant, release() }. Re-entrant when this process already holds it or when
 * the inherited BEA_LOCK_TOKEN_<NAME> matches the current owner (a child of the holder).
 */
export async function acquireLock(name, options = {}) {
  if (!NAME_RE.test(name)) throw new Error(`lock name must match ${NAME_RE}`);
  const root = options.root ?? REPO_ROOT;
  const timeoutMs = options.timeoutMs ?? (Number(process.env.BEA_LOCK_TIMEOUT_MS) || DEFAULT_TIMEOUT_MS);
  const log = options.log ?? ((line) => process.stderr.write(`${line}\n`));
  const command = options.command ?? process.argv.slice(1).join(" ").slice(0, 300);
  const envName = lockTokenEnv(name);
  const locksDir = join(root, "build", ".locks");
  const lockDir = join(locksDir, name);

  const mine = held.get(name);
  if (mine !== undefined) {
    mine.depth += 1;
    return { name, token: mine.token, reentrant: true, release: () => void (mine.depth -= 1) };
  }
  const inherited = process.env[envName];
  if (inherited !== undefined && inherited !== "" && readOwner(lockDir)?.token === inherited)
    return { name, token: inherited, reentrant: true, release: () => undefined };

  mkdirSync(locksDir, { recursive: true });
  const token = randomHex(16);
  const started = Date.now();
  let lastReport = 0;
  for (;;) {
    try {
      mkdirSync(lockDir);
      const owner = {
        schema: "bea.lock/1",
        name,
        pid: process.pid,
        start: ownStart(),
        token,
        command,
        cwd: process.cwd(),
        acquired_at: new Date().toISOString(),
      };
      const tmp = join(lockDir, `owner.json.tmp-${randomHex(4)}`);
      writeFileSync(tmp, `${JSON.stringify(owner, null, 1)}\n`);
      renameSync(tmp, join(lockDir, "owner.json"));
      break;
    } catch (cause) {
      if (cause?.code !== "EEXIST") throw cause;
    }
    const owner = readOwner(lockDir);
    const stale = staleReason(lockDir, owner);
    if (stale !== null) {
      if (takeOver(lockDir, owner)) log(`[lock ${name}] took over a stale lock: ${stale}`);
      continue;
    }
    const waited = Date.now() - started;
    if (waited >= timeoutMs)
      throw new Error(
        `[lock ${name}] timed out after ${Math.round(waited / 1000)} s waiting for ${describeOwner(owner)}. ` +
          `If that process is hung, end it; a lock whose owner process is gone is taken over automatically. ` +
          `Lock directory: ${lockDir}. Raise the wait with BEA_LOCK_TIMEOUT_MS.`,
      );
    if (Date.now() - lastReport >= REPORT_EVERY_MS) {
      lastReport = Date.now();
      log(`[lock ${name}] waiting for ${describeOwner(owner)} (${Math.round(waited / 1000)} s so far)`);
    }
    await sleep(POLL_MS + Math.floor(Math.random() * 100));
  }

  const previousEnv = process.env[envName];
  process.env[envName] = token;
  const entry = { token, depth: 1 };
  held.set(name, entry);
  let released = false;
  const releaseNow = () => {
    if (released) return;
    released = true;
    held.delete(name);
    if (previousEnv === undefined) delete process.env[envName];
    else process.env[envName] = previousEnv;
    process.off("exit", releaseNow);
    if (readOwner(lockDir)?.token !== token) {
      log(`[lock ${name}] was taken over while held; leaving the new owner's lock in place`);
      return;
    }
    const aside = `${lockDir}.released-${process.pid}-${randomHex(4)}`;
    try {
      renameSync(lockDir, aside);
      rmSync(aside, { recursive: true, force: true, maxRetries: 3 });
    } catch {
      // The next waiter sees a dead owner and takes over.
    }
  };
  process.on("exit", releaseNow);
  return {
    name,
    token,
    reentrant: false,
    release: () => {
      entry.depth -= 1;
      if (entry.depth <= 0) releaseNow();
    },
  };
}

/** Run fn while holding `name`; always releases. */
export async function withLock(name, fn, options = {}) {
  const lock = await acquireLock(name, options);
  try {
    return await fn(lock);
  } finally {
    lock.release();
  }
}

/** The shared build lock every build-like script takes. */
export const withBuildLock = (fn, options = {}) => withLock("build", fn, options);

function parseCli(argv) {
  const dash = argv.indexOf("--");
  const head = dash < 0 ? argv : argv.slice(0, dash);
  const command = dash < 0 ? [] : argv.slice(dash + 1);
  const name = head[0];
  let timeoutMs;
  for (let i = 1; i < head.length; i += 1) {
    if (head[i] === "--timeout-ms") timeoutMs = Number(head[++i]);
    else throw new Error(`unknown option ${head[i]}`);
  }
  if (name === undefined || command.length === 0)
    throw new Error("usage: node scripts/lib/lock.mjs <name> [--timeout-ms N] -- <command...>");
  return { name, timeoutMs, command: command.join(" ") };
}

async function main() {
  let cli;
  try {
    cli = parseCli(process.argv.slice(2));
  } catch (cause) {
    process.stderr.write(`${cause.message}\n`);
    return 2;
  }
  return withLock(
    cli.name,
    () =>
      new Promise((done) => {
        // One command string through the platform shell (cmd.exe /d /s /c on Windows): `a && b` chains and PATH
        // lookups (node_modules/.bin from npm) behave exactly as in an npm script.
        const child = spawn(cli.command, { shell: true, stdio: "inherit", env: process.env });
        const forward = (signal) => () => child.kill(signal);
        const onInt = forward("SIGINT");
        const onTerm = forward("SIGTERM");
        process.on("SIGINT", onInt);
        process.on("SIGTERM", onTerm);
        child.on("error", (cause) => {
          process.stderr.write(`[lock ${cli.name}] could not start: ${cause.message}\n`);
          done(1);
        });
        child.on("exit", (code, signal) => {
          process.off("SIGINT", onInt);
          process.off("SIGTERM", onTerm);
          done(code ?? (signal === "SIGINT" ? 130 : 1));
        });
      }),
    { ...(cli.timeoutMs === undefined ? {} : { timeoutMs: cli.timeoutMs }), command: cli.command.slice(0, 300) },
  );
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then(
    (code) => {
      process.exitCode = code;
    },
    (cause) => {
      process.stderr.write(`${cause?.message ?? cause}\n`);
      process.exitCode = 1;
    },
  );
}
