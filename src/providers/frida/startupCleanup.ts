import { Deadline } from "../../domain/deadline.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { withCleanup } from "../../domain/errors/constructors.js";
import { LIMITATIONS } from "../../domain/evidence/limitations.js";
import type { Logger } from "../../domain/logger.js";
import type { KillReason } from "../../ports/jobhost.js";
import type { CancellableLike, FridaDeviceLike } from "./fridaPorts.js";
import { createNativeCancel } from "./NativeCancel.js";
import type { SessionRecord } from "./SessionRecord.js";

/**
 * Pending-startup cleanup (S3 §8.3): a failed or cancelled spawn/attach never leaves a target behind. Owned:
 * jobHost.kill if containment adopted the root, else device.kill(pid) of the still-suspended root (it has run no
 * code, so it has no descendants), else — a spawn whose guard expired — kill the pid when the spawn resolves later.
 * Attached: unload the script and detach, NEVER kill. Then wait ≤ 500 ms for the detach, disconnect every handler
 * and unroute output. Each step is wrapped; a failure leaves the record `cleanup_pending` with labelled resources
 * (labels only, never authority) and the first startup error stays primary with code cleanup_incomplete.
 */
export interface CleanupDeps {
  readonly createCancellable: () => CancellableLike;
  readonly logger: Logger;
}

export const killUnadoptedRoot = async (device: FridaDeviceLike, pid: number): Promise<boolean> => {
  try {
    await device.kill(pid);
    return true;
  } catch {
    return false;
  }
};

/** The retained-owner pattern for a spawn whose guard expired: the pid is killed whenever the spawn resolves. */
export const killWhenSpawned = (
  spawn: Promise<number>,
  device: FridaDeviceLike,
  onKilled: (pid: number) => void,
): void => {
  void spawn.then(
    async (pid) => {
      const killed = await killUnadoptedRoot(device, pid);
      if (killed) onKilled(pid);
    },
    () => undefined,
  );
};

/**
 * Review fix LIFE-1: wait (bounded) for a startup's in-flight createScript/load before anything unloads or detaches
 * (a detach during createScript strands frida-agent.dll in the target). A script created late is adopted so the
 * caller unloads it. "pending" when it is still in flight after `ms`.
 */
export const settlePendingStartup = async (record: SessionRecord, ms: number): Promise<"settled" | "pending"> => {
  const pending = record.pendingStartup;
  if (pending !== null) {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const outcome = await Promise.race([
      pending.then(
        () => "settled" as const,
        () => "settled" as const,
      ),
      new Promise<"pending">((resolve) => {
        timer = setTimeout(() => resolve("pending"), Math.max(0, ms));
        timer.unref?.();
      }),
    ]);
    if (timer !== undefined) clearTimeout(timer);
    if (outcome === "pending") return "pending";
    record.pendingStartup = null;
  }
  const late = record.pendingScript;
  record.pendingScript = null;
  if (late !== null && record.script === null) {
    const script = await late.then(
      (s) => s,
      () => null,
    );
    if (script !== null) record.script = script;
  }
  return "settled";
};

/** Resource label of an agent that may stay loaded in a target BEA does not own (labels only, never authority). */
export const strandedAgentLabel = (pid: number | null): string => `agent-script:pid:${String(pid ?? 0)}`;

export const cleanupStartup = async (
  deps: CleanupDeps,
  record: SessionRecord,
  primary: BeaError,
  options: { readonly device: FridaDeviceLike | null; readonly reason: KillReason },
): Promise<BeaError> => {
  const resources: string[] = [];
  const pid = record.pid;
  record.killRequested = true;
  record.crash.ackAll("closing");
  if (record.ownership === "owned") {
    if (record.jobHost !== null) {
      const settlement = await record.jobHost.kill(options.reason, 2_000);
      if (settlement.observation === "timed-out-with-active")
        resources.push(`jobhost:${String(record.jobHost.helperPid)}`);
    } else if (pid !== null && options.device !== null) {
      if (await killUnadoptedRoot(options.device, pid)) record.addLimitation(LIMITATIONS.KILLED_BEFORE_ADOPTION);
      else resources.push(`pid:${String(pid)}`);
    }
  } else {
    if ((await settlePendingStartup(record, 2_000)) === "pending") resources.push(strandedAgentLabel(pid));
    const script = record.script;
    if (script !== null && !script.isDestroyed) {
      const cancel = createNativeCancel(deps.createCancellable(), { deadline: Deadline.after(2_000) });
      try {
        await script.unload(cancel.token);
      } catch {
        resources.push("agent-script");
      } finally {
        cancel.dispose();
      }
    }
  }
  const session = record.fridaSession;
  if (session !== null && !session.isDetached()) {
    if (record.ownership === "owned") await record.waitDetached(500);
    if (!session.isDetached()) {
      const cancel = createNativeCancel(deps.createCancellable(), { deadline: Deadline.after(2_000) });
      try {
        await session.detach(cancel.token);
      } catch {
        if (record.ownership === "attached") resources.push("frida-session");
      } finally {
        cancel.dispose();
      }
    }
  }
  if (record.watcher !== null) await record.watcher.stop().catch(() => undefined);
  record.runDisconnectors();
  record.output?.close();
  record.flow.stop();
  if (resources.length === 0) return primary;
  record.retained = { resources, reason: "startup cleanup incomplete" };
  deps.logger.warn("startup cleanup incomplete", { session: record.id, resources: resources.join(",") });
  return withCleanup(primary, { status: "incomplete", resources, reason: "startup cleanup incomplete" });
};
