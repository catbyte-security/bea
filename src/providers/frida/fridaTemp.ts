import { mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Review fix LIFE-3: frida-core extracts frida-agent.dll, dbghelp.dll and symsrv.dll for three architectures
 * (~45 MB) into %TEMP%\frida-<hex> at the first injection of a process, and only DeviceManager.close() removes it. A
 * server or CLI that ends any other way (TerminateProcess from its client, the client's 2 s SIGTERM escalation, a
 * crash, a cancelled close) leaks the directory, and nothing else ever reclaims it.
 *
 * frida-core reads the temp directory at the FIRST injection (device.attach) and reuses that extraction for every later
 * one (verified on 17.23.2: TEMP changed after the binding loaded, set only around attach, decides). BEA therefore
 * points TEMP/TMP at a BEA-owned per-run directory <BEA_HOME>\tmp\frida\<run_id> (with owner.json) only for the
 * duration of each device.attach (withTempDir: a narrow, refcounted window, restored as soon as the attach returns;
 * host code never reads TEMP, and targets get the user's TEMP from the server-environment snapshot), and preparing
 * that directory sweeps the run directories whose owner process is gone. A directory whose DLL is still mapped by a live target (a stranded agent) cannot be deleted:
 * the sweep skips it and retries next time. Frida directories in the user's own %TEMP% (other Frida tools use the
 * same naming) are never touched. Targets keep the user's TEMP (their environment comes from a snapshot).
 */
export const FRIDA_TEMP_OWNER = "owner.json";
const OWNER_SCHEMA = "bea.frida-temp/1";
/** a directory without a readable owner younger than this may be a sibling still writing it: left alone */
const UNOWNED_GRACE_MS = 10 * 60_000;

export interface FridaTempOwner {
  readonly schema: typeof OWNER_SCHEMA;
  readonly pid: number;
  readonly run_id: string;
  readonly started_at: string;
}

export interface FridaTempDeps {
  /** true when a process with this pid exists (EPERM counts as alive) */
  readonly pidAlive: (pid: number) => boolean;
  readonly now: () => number;
  readonly selfPid: number;
}

export const productionTempDeps = (): FridaTempDeps => ({
  pidAlive: (pid) => {
    try {
      process.kill(pid, 0);
      return true;
    } catch (cause) {
      return (cause as NodeJS.ErrnoException).code === "EPERM";
    }
  },
  now: () => Date.now(),
  selfPid: process.pid,
});

const readOwner = (dir: string): FridaTempOwner | null => {
  try {
    const parsed = JSON.parse(readFileSync(join(dir, FRIDA_TEMP_OWNER), "utf8")) as Partial<FridaTempOwner>;
    return parsed.schema === OWNER_SCHEMA && typeof parsed.pid === "number" ? (parsed as FridaTempOwner) : null;
  } catch {
    return null;
  }
};

export interface SweepReport {
  readonly removed: number;
  /** directories of dead owners that could not be removed (a DLL still mapped by a live target) */
  readonly busy: number;
}

/** Remove the run directories under `root` whose owner process is gone (never this process's own). */
export const sweepFridaTemp = (root: string, deps: FridaTempDeps = productionTempDeps()): SweepReport => {
  let entries: string[];
  try {
    entries = readdirSync(root);
  } catch {
    return { removed: 0, busy: 0 };
  }
  let removed = 0;
  let busy = 0;
  for (const name of entries) {
    const dir = join(root, name);
    const owner = readOwner(dir);
    if (owner !== null) {
      if (owner.pid === deps.selfPid || deps.pidAlive(owner.pid)) continue;
    } else {
      try {
        if (!statSync(dir).isDirectory() || deps.now() - statSync(dir).mtimeMs < UNOWNED_GRACE_MS) continue;
      } catch {
        continue;
      }
    }
    try {
      rmSync(dir, { recursive: true, force: true, maxRetries: 0 });
      removed += 1;
    } catch {
      busy += 1;
    }
  }
  return { removed, busy };
};

/**
 * frida-core writes <dir>\frida-<32 hex>\x86_64\frida-agent.dll with Win32 calls limited to MAX_PATH (259 characters
 * plus the terminator): under a deep BEA_HOME every injection failed with "Error opening file" (found by the final
 * review verification). A run directory that leaves no room for that suffix is not used.
 */
const FRIDA_EXTRACTION_SUFFIX = "\\frida-00000000000000000000000000000000\\x86_64\\frida-agent.dll";
const MAX_PATH_CHARS = 259;
export const fridaTempFits = (dir: string): boolean => dir.length + FRIDA_EXTRACTION_SUFFIX.length <= MAX_PATH_CHARS;

/**
 * Sweep, then create <root>\<runId> with its owner file. Returns the directory, or null when it could not be prepared
 * or its path would be too long for Frida's extraction (Frida then extracts into the user's TEMP as before).
 */
export const prepareFridaTemp = (
  root: string,
  runId: string,
  deps: FridaTempDeps = productionTempDeps(),
): string | null => {
  sweepFridaTemp(root, deps);
  const dir = join(root, runId);
  if (!fridaTempFits(dir)) return null;
  try {
    mkdirSync(dir, { recursive: true });
    const owner: FridaTempOwner = {
      schema: OWNER_SCHEMA,
      pid: deps.selfPid,
      run_id: runId,
      started_at: new Date(deps.now()).toISOString(),
    };
    writeFileSync(join(dir, FRIDA_TEMP_OWNER), `${JSON.stringify(owner)}\n`);
  } catch {
    return null;
  }
  return dir;
};

let windowDepth = 0;
let saved: { readonly TEMP: string | undefined; readonly TMP: string | undefined } | null = null;

const restore = (env: Record<string, string | undefined>, key: "TEMP" | "TMP", value: string | undefined): void => {
  if (value === undefined) delete env[key];
  else env[key] = value;
};

/**
 * Run `work` (a device.attach: the injection that extracts Frida's agent) with TEMP/TMP pointing at `dir`; the
 * previous values are restored when the last concurrent window closes. `dir: null` runs `work` unchanged.
 */
export const withTempDir = async <T>(
  dir: string | null,
  work: () => Promise<T>,
  env: Record<string, string | undefined> = process.env,
): Promise<T> => {
  if (dir === null) return work();
  if (windowDepth === 0) saved = { TEMP: env["TEMP"], TMP: env["TMP"] };
  windowDepth += 1;
  env["TEMP"] = dir;
  env["TMP"] = dir;
  try {
    return await work();
  } finally {
    windowDepth -= 1;
    if (windowDepth === 0 && saved !== null) {
      restore(env, "TEMP", saved.TEMP);
      restore(env, "TMP", saved.TMP);
      saved = null;
    }
  }
};

/** After DeviceManager.close() removed Frida's own directory: remove the (now empty) run directory, best effort. */
export const releaseFridaTemp = (dir: string | null): void => {
  if (dir === null) return;
  try {
    rmSync(dir, { recursive: true, force: true, maxRetries: 0 });
  } catch {
    // still mapped by a live target: the next sweep retries
  }
};
