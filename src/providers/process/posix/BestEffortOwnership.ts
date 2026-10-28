import type { BeaError } from "../../../domain/errors/beaError.js";
import { inputError } from "../../../domain/errors/constructors.js";
import { err, ok, type Result } from "../../../domain/result.js";
import type { ContainmentFacts } from "../../../ports/sessions.js";
import { nodeProcFs, readProcStat, type ProcFs, type ProcStat } from "./procfs.js";

/**
 * Linux best-effort ownership of a Frida-spawned target (S3 §19; BELIEVED, untested on this host, L10). No kernel
 * container exists, so BEA records `{pid, startTicks}` at spawn and, on close, kills the root, its process group when
 * it leads one, and the descendants found by walking /proc parent links at that moment, re-verifying each pid's start
 * time so a reused pid is never signalled. Daemonized descendants can escape; a hard-killed server kills nothing.
 */
export const POSIX_BEST_EFFORT_LIMITATION =
  "Linux: BEA could not place this Frida-spawned target in a kernel container. On close BEA kills the target, its " +
  "process group if it leads one, and the descendants it finds by walking /proc parent links at that moment (pid and " +
  "start time verified). Daemonized descendants (setsid or double fork) can escape, and if the BEA server is killed " +
  "without running its cleanup, the target and its descendants keep running.";

const POSIX_KILL_POLL_MS = 1000;
const POLL_INTERVAL_MS = 20;

export const posixContainmentFacts = (): ContainmentFacts => ({
  kind: "posix-best-effort",
  helperPid: null,
  killOnClose: true,
  dieOnUnhandledException: false,
  breakawayAllowed: false,
  memLimitBytes: null,
  wasInJobBeforeAdopt: null,
  assignedBeforeResume: false,
  crashSafe: false,
});

export interface PosixProcessApi {
  readonly fs: ProcFs;
  /** process.kill; a negative pid signals the process group */
  readonly kill: (pid: number, signal: "SIGKILL") => void;
  readonly now: () => number;
  readonly sleep: (ms: number) => Promise<void>;
}

const nodePosixProcessApi: PosixProcessApi = {
  fs: nodeProcFs,
  kill: (pid, signal) => void process.kill(pid, signal),
  now: () => performance.now(),
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
};

export interface PosixKillReport {
  /** the root still had the recorded start time when the kill began */
  readonly rootVerified: boolean;
  readonly groupKilled: boolean;
  /** pids sent SIGKILL (root first, then descendants) */
  readonly killed: readonly number[];
  /** descendants skipped because their start time no longer matched */
  readonly skipped: readonly number[];
  /** /proc/<root> disappeared (or turned zombie) within the poll window */
  readonly rootGone: boolean;
  readonly elapsedMs: number;
}

const isGone = (stat: ProcStat | null): boolean => stat === null || stat.state === "Z" || stat.state === "X";

/** Descendants of `root` (breadth first) among processes started no earlier than the root. */
export const findDescendants = (root: ProcStat, all: readonly ProcStat[]): ProcStat[] => {
  const children = new Map<number, ProcStat[]>();
  for (const stat of all) {
    if (stat.pid === root.pid || stat.startTicks < root.startTicks) continue;
    const list = children.get(stat.ppid) ?? [];
    list.push(stat);
    children.set(stat.ppid, list);
  }
  const out: ProcStat[] = [];
  const queue = [root.pid];
  const seen = new Set<number>([root.pid]);
  for (let next = queue.shift(); next !== undefined; next = queue.shift())
    for (const child of children.get(next) ?? []) {
      if (seen.has(child.pid)) continue;
      seen.add(child.pid);
      out.push(child);
      queue.push(child.pid);
    }
  return out;
};

export class BestEffortOwnership {
  readonly pid: number;
  readonly startTicks: bigint;
  readonly #api: PosixProcessApi;
  #kill: Promise<PosixKillReport> | null = null;

  private constructor(pid: number, startTicks: bigint, api: PosixProcessApi) {
    this.pid = pid;
    this.startTicks = startTicks;
    this.#api = api;
  }

  /** Record the identity of a process BEA just spawned. */
  static async capture(
    pid: number,
    api: PosixProcessApi = nodePosixProcessApi,
  ): Promise<Result<BestEffortOwnership, BeaError>> {
    const stat = await readProcStat(api.fs, pid);
    if (stat === null || isGone(stat))
      return err(
        inputError("posix.capture", [{ path: "pid", reason: "invalid_value", message: "Process not found." }]),
      );
    return ok(new BestEffortOwnership(pid, stat.startTicks, api));
  }

  /** S3 §19 kill steps 1–5. Memoized; never throws. */
  kill(): Promise<PosixKillReport> {
    this.#kill ??= this.#runKill();
    return this.#kill;
  }

  async #runKill(): Promise<PosixKillReport> {
    const api = this.#api;
    const started = api.now();
    const signal = (pid: number): boolean => {
      try {
        api.kill(pid, "SIGKILL");
        return true;
      } catch {
        return false;
      }
    };
    const root = await readProcStat(api.fs, this.pid);
    const rootVerified = root !== null && !isGone(root) && root.startTicks === this.startTicks;
    const killed: number[] = [];
    const skipped: number[] = [];
    let groupKilled = false;
    if (rootVerified) {
      const descendants = findDescendants(root, await this.#snapshot());
      if (root.pgrp === root.pid) groupKilled = signal(-root.pid);
      if (signal(root.pid)) killed.push(root.pid);
      for (const child of descendants) {
        const now = await readProcStat(api.fs, child.pid);
        if (now === null || now.startTicks !== child.startTicks) skipped.push(child.pid);
        else if (signal(child.pid)) killed.push(child.pid);
      }
    }
    let rootGone = !rootVerified;
    while (!rootGone && api.now() - started < POSIX_KILL_POLL_MS) {
      const now = await readProcStat(api.fs, this.pid);
      rootGone = isGone(now) || now?.startTicks !== this.startTicks;
      if (!rootGone) await api.sleep(POLL_INTERVAL_MS);
    }
    return { rootVerified, groupKilled, killed, skipped, rootGone, elapsedMs: Math.round(api.now() - started) };
  }

  async #snapshot(): Promise<ProcStat[]> {
    let entries: readonly string[];
    try {
      entries = await this.#api.fs.list("/proc");
    } catch {
      return [];
    }
    const stats = await Promise.all(
      entries.filter((name) => /^\d+$/u.test(name)).map((name) => readProcStat(this.#api.fs, Number(name))),
    );
    return stats.filter((stat): stat is ProcStat => stat !== null);
  }
}
