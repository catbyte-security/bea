import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";

/**
 * Owned-PID ledger (S6 §10.7, rea-testing §11.3). Records `{pid, creation100ns}` of every process a test makes BEA own
 * (spawn_process identities, behavior.exe "CHILD pid=" stragglers) and of every attach target the test spawned
 * itself. After each file: every owned entry must be dead or pid-reused (creation time differs), every test-spawned
 * attach target must be ALIVE (BEA never kills attached processes); leaks are reaped (only when the creation time
 * proves it is the same process) and fail the file. Liveness comes from pidcheck.exe (fixtures manifest), ~5 ms per
 * call; without it, process.kill(pid, 0) is used and pid reuse cannot be excluded.
 */
export interface LedgerEntry {
  readonly pid: number;
  readonly creation100ns: string | null;
  readonly role: "owned" | "attach-target";
  readonly label: string;
}

export interface PidStatus {
  readonly pid: number;
  readonly alive: boolean;
  readonly creation100ns: string | null;
  /** Creation time equals the recorded one; null when nothing was recorded or no oracle is available. */
  readonly matches: boolean | null;
  readonly exit_code: number | null;
}

/** One liveness probe. `pidcheck` is the path of pidcheck.exe, or null for the process.kill fallback. */
export const pidStatus = (pidcheck: string | null, pid: number, creation100ns: string | null = null): PidStatus => {
  if (pidcheck !== null && existsSync(pidcheck)) {
    const args = creation100ns === null ? [String(pid)] : [String(pid), creation100ns];
    const run = spawnSync(pidcheck, args, { encoding: "utf8", windowsHide: true, timeout: 10_000 });
    if (run.status === 0) return JSON.parse(run.stdout) as PidStatus;
    throw new Error(`pidcheck failed for ${pid}: ${run.stderr || String(run.error)}`);
  }
  let alive: boolean;
  try {
    process.kill(pid, 0);
    alive = true;
  } catch (cause) {
    alive = (cause as NodeJS.ErrnoException).code === "EPERM";
  }
  return { pid, alive, creation100ns: null, matches: null, exit_code: null };
};

export interface LedgerAudit {
  /** Owned processes still running with the recorded creation time (or no creation time to compare). */
  readonly leaks: readonly LedgerEntry[];
  /** Test-spawned attach targets that are gone (BEA must never kill them). */
  readonly deadAttachTargets: readonly LedgerEntry[];
}

export class OwnedPidLedger {
  readonly #pidcheck: string | null;
  readonly #entries: LedgerEntry[] = [];

  constructor(pidcheck: string | null) {
    this.#pidcheck = pidcheck;
  }

  entries(): readonly LedgerEntry[] {
    return [...this.#entries];
  }

  /** A BEA-owned process; creation time from the spawn identity, or probed now when unknown. */
  recordOwned(pid: number, creation100ns: string | null, label: string): void {
    this.#entries.push({ pid, creation100ns: creation100ns ?? this.#probeCreation(pid), role: "owned", label });
  }

  /** A process the TEST spawned for attach_process: it must survive close_session and server shutdown. */
  recordAttachTarget(pid: number, creation100ns: string | null, label: string): void {
    this.#entries.push({ pid, creation100ns: creation100ns ?? this.#probeCreation(pid), role: "attach-target", label });
  }

  /**
   * An `identity` object from spawn_process / attach_process. Owned identities are recorded; attached ones are not
   * (the test that spawned the attach target records it with recordAttachTarget).
   */
  recordIdentity(identity: Readonly<Record<string, unknown>>, label: string): void {
    if (identity["ownership"] !== "owned" || typeof identity["pid"] !== "number") return;
    const start = identity["start_time"] as { readonly value?: unknown; readonly source?: unknown } | undefined;
    const creation = start?.source === "os-creation-time" && typeof start.value === "string" ? start.value : null;
    this.recordOwned(identity["pid"], creation, label);
  }

  /** Every `CHILD pid=<n>` line of a fixture's output (behavior.exe stragglers) as owned entries. */
  recordChildLines(output: string, label: string): void {
    for (const match of output.matchAll(/^CHILD pid=(\d+)/gmu))
      this.recordOwned(Number(match[1]), null, `${label} child`);
  }

  async audit(): Promise<LedgerAudit> {
    const leaks: LedgerEntry[] = [];
    const deadAttachTargets: LedgerEntry[] = [];
    for (const entry of this.#entries) {
      const status = pidStatus(this.#pidcheck, entry.pid, entry.creation100ns);
      const sameProcess = status.alive && status.matches !== false;
      if (entry.role === "owned" && sameProcess) leaks.push(entry);
      if (entry.role === "attach-target" && !sameProcess) deadAttachTargets.push(entry);
    }
    return { leaks, deadAttachTargets };
  }

  /**
   * The after-file check: throws when an owned process leaked (after reaping it, only if its creation time matches) or
   * an attach target died. Attach targets stay running; the test ends them with killAttachTargets().
   */
  async assertClean(): Promise<void> {
    const { leaks, deadAttachTargets } = await this.audit();
    const reaped: string[] = [];
    for (const leak of leaks) {
      if (leak.creation100ns === null) continue; // identity unproven: report, never kill
      try {
        process.kill(leak.pid);
        reaped.push(String(leak.pid));
      } catch {
        // already gone
      }
    }
    const problems = [
      ...leaks.map(
        (e) => `owned process leaked: pid ${e.pid} (${e.label})${reaped.includes(String(e.pid)) ? " — reaped" : ""}`,
      ),
      ...deadAttachTargets.map(
        (e) => `attach target died: pid ${e.pid} (${e.label}) — BEA must never kill attached processes`,
      ),
    ];
    if (problems.length > 0) throw new Error(`owned-PID ledger: ${problems.join("; ")}`);
  }

  /** Ends the attach targets this test spawned (only those whose creation time still matches). */
  async killAttachTargets(): Promise<void> {
    for (const entry of this.#entries.filter((e) => e.role === "attach-target")) {
      const status = pidStatus(this.#pidcheck, entry.pid, entry.creation100ns);
      if (status.alive && status.matches !== false && entry.creation100ns !== null) {
        try {
          process.kill(entry.pid);
        } catch {
          // already gone
        }
      }
    }
  }

  #probeCreation(pid: number): string | null {
    try {
      const status = pidStatus(this.#pidcheck, pid);
      return status.alive ? status.creation100ns : null;
    } catch {
      return null;
    }
  }
}
