import { Deadline } from "../../domain/deadline.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import type {
  CloseAllReport,
  CloseReport,
  ExternalSessionDriver,
  SessionId,
  ShutdownReason,
} from "../../ports/sessions.js";
import { abortSessionOps, detachSession, endSessionStreams, ownedTargetState, type CloseDeps } from "./closeSession.js";
import type { FridaDeviceLike } from "./fridaPorts.js";
import { createNativeCancel } from "./NativeCancel.js";
import type { SessionRecord } from "./SessionRecord.js";
import { killUnadoptedRoot, settlePendingStartup, strandedAgentLabel } from "./startupCleanup.js";

/**
 * closeAll — the `teardown-targets` lifecycle phase (S3 §7.6, D-INT-6; VERIFIED 67–72 ms for 3 owned + 1 attached).
 * Kill FIRST: at t0 every op is aborted, every owned job gets `kill` (escalation to TerminateProcess(helper) at 900 ms),
 * owned startups not yet adopted get device.kill (a suspended root that ran no code), every crash waiter is released,
 * emulation bridges shut down, and attached targets are torn down concurrently (queue ≤ 300 → revert ≤ 400 → unload
 * ≤ 300 → detach ≤ 300 → watcher stop). Then: kills awaited ≤ 1000 ms, ops settled ≤ 1300 ms, streams ended and
 * sessionEnded per record ≤ 1500 ms, every handler disconnected. Failures are reported; the caller keeps only the
 * failed owners for a retry (memoized, retryable).
 */
export interface CloseAllInput {
  readonly records: readonly SessionRecord[];
  readonly externals: readonly { readonly id: SessionId; readonly driver: ExternalSessionDriver }[];
  readonly ops: ReadonlyMap<AbortController, { readonly name: string; readonly done: Promise<unknown> }>;
  readonly device: FridaDeviceLike | null;
  readonly reason: ShutdownReason;
}

export interface CloseAllOutcome {
  readonly report: CloseAllReport;
  readonly closed: readonly SessionRecord[];
  readonly closedExternals: readonly SessionId[];
}

const after = (ms: number): Promise<"timeout"> =>
  new Promise((resolve) => {
    const timer = setTimeout(() => resolve("timeout"), Math.max(0, ms));
    timer.unref?.();
  });

export const runCloseAll = async (deps: CloseDeps, input: CloseAllInput): Promise<CloseAllOutcome> => {
  const t0 = deps.now();
  const left = (offset: number): number => Math.max(0, offset - (deps.now() - t0));
  const shutdown = deps.limits.shutdown;
  const failures: BeaError[] = [];
  const reason = { kind: "shutdown" as const };

  // t0: abort everything, release crash waiters
  for (const controller of input.ops.keys()) controller.abort(reason);
  for (const record of input.records) {
    abortSessionOps(record, null, reason);
    record.killRequested = true;
    record.crash.ackAll("closing");
  }

  // t0: owned kills FIRST (fire and collect)
  const owned = input.records.filter((r) => r.ownership === "owned");
  const kills = owned.map(async (record) => {
    if (record.jobHost !== null) {
      const started = deps.now();
      const settlement = await record.jobHost.kill("server-shutdown", shutdown.killEscalateMs);
      const termination: CloseReport["termination"] = {
        method: settlement.method === "helper-terminated" ? "helper-terminated" : "terminate-job",
        activeBefore: settlement.activeBefore,
        settled: settlement.observation,
        elapsedMs: Math.round(deps.now() - started),
      };
      return { record, termination };
    }
    if (record.pid !== null && input.device !== null) {
      const killed = await killUnadoptedRoot(input.device, record.pid);
      return {
        record,
        termination: {
          method: "frida-kill-suspended-root" as const,
          activeBefore: null,
          settled: killed ? ("kernel-enforced-unobserved" as const) : ("unknown" as const),
          elapsedMs: 0,
        },
      };
    }
    return { record, termination: null };
  });

  // t0: emulation bridges
  const externals = input.externals.map(async ({ id, driver }) => {
    const result = await Promise.race([driver.shutdown(Deadline.after(1_200, deps.now)), after(1_250)]);
    const ok = result !== "timeout" && result.ok;
    if (!ok)
      failures.push({
        _tag: "ProviderFailure",
        operation: "close_all",
        provider: "emulator",
        diagnostics: { session: id },
      });
    return { sessionId: id, ok };
  });

  // t0: attached teardown, concurrently
  const attached = input.records
    .filter((r) => r.ownership === "attached")
    .map(async (record) => {
      await Promise.race([record.queue.drained(), after(shutdown.attachedQueueMs)]);
      const agentAlive = record.exit === null && record.detach === null && record.rpc !== null;
      if (agentAlive && record.rpc !== null) {
        const internal = record.internalOpDetached("server_shutdown", shutdown.attachedRevertMs + 100);
        try {
          await record.rpc.call(
            "shutdown",
            { revert: true, timeout_ms: shutdown.attachedRevertMs },
            { op: internal.op, timeoutMs: shutdown.attachedRevertMs },
          );
        } finally {
          internal.dispose();
        }
      }
      // LIFE-1: a startup still in createScript/load is waited for before the unload and the detach
      const stranded =
        (await settlePendingStartup(record, shutdown.attachedQueueMs + shutdown.attachedUnloadMs)) === "pending";
      let agentUnloaded: boolean | null = stranded ? false : null;
      const script = record.script;
      if (script !== null) {
        if (script.isDestroyed) agentUnloaded = true;
        else {
          const cancel = createNativeCancel(deps.createCancellable(), {
            deadline: Deadline.after(shutdown.attachedUnloadMs, deps.now),
          });
          try {
            await script.unload(cancel.token);
            agentUnloaded = true;
          } catch {
            agentUnloaded = script.isDestroyed;
          } finally {
            cancel.dispose();
          }
        }
      }
      const fridaDetached = await detachSession(deps, record, shutdown.attachedDetachMs);
      if (record.watcher !== null) await Promise.race([record.watcher.stop(), after(200)]);
      if (agentUnloaded === false)
        failures.push({
          _tag: "ProviderFailure",
          operation: "close_all",
          provider: "agent",
          diagnostics: { session: record.id, stage: "unload" },
          cleanup: {
            status: "incomplete",
            resources: [stranded ? strandedAgentLabel(record.pid) : "agent-script"],
            reason: stranded ? "agent startup still in flight at shutdown" : "unload failed at shutdown",
          },
        });
      return {
        sessionId: record.id,
        pid: record.pid ?? 0,
        agentUnloaded,
        fridaDetached,
        targetAlive: record.exit === null ? (record.watcher === null ? null : true) : false,
      };
    });

  const ownedResults = await Promise.race([Promise.all(kills), after(left(shutdown.killAwaitMs)).then(() => null)]);
  const ownedReport: CloseAllReport["owned"][number][] = [];
  if (ownedResults === null)
    failures.push({
      _tag: "ProviderTimeout",
      operation: "close_all",
      timeout_ms: shutdown.killAwaitMs,
      phase: "owned-kill",
    });
  else
    for (const { record, termination } of ownedResults) {
      ownedReport.push({ sessionId: record.id, pid: record.pid ?? 0, termination });
      if (termination?.settled === "timed-out-with-active")
        failures.push({
          _tag: "ProviderFailure",
          operation: "close_all",
          provider: "jobhost",
          diagnostics: { session: record.id },
          cleanup: {
            status: "incomplete",
            resources: [`pid:${String(record.pid ?? 0)}`],
            reason: "the job did not settle",
          },
        });
      await Promise.race([record.waitDetached(100), after(left(shutdown.killAwaitMs + 100))]);
    }
  const attachedReport = await Promise.race([
    Promise.all(attached),
    after(left(shutdown.settleUntilMs)).then(() => []),
  ]);
  const externalReport = await Promise.race([
    Promise.all(externals),
    after(left(shutdown.settleUntilMs)).then(() => []),
  ]);

  // ≤ 1300: settle ops
  const pending = [...input.ops.values()];
  const settled = await Promise.race([
    Promise.allSettled(pending.map((op) => op.done)).then(() => true),
    after(left(shutdown.settleUntilMs)),
  ]);
  const abandonedOps = settled === true ? [] : pending.map((op) => op.name);

  // ≤ 1500: streams, sessionEnded, disconnect
  const killedIds = new Set(
    ownedResults
      ?.filter((r) => r.termination !== null && r.termination.settled !== "timed-out-with-active")
      .map((r) => r.record.id) ?? [],
  );
  const closed: SessionRecord[] = [];
  await Promise.all(
    input.records.map(async (record) => {
      if (record.visible) {
        const exited = record.exit !== null || record.detach?.reason === "process-terminated";
        await endSessionStreams(
          deps,
          record,
          record.ownership === "owned" ? (exited ? "process-exited" : "process-killed") : "server-shutdown",
          record.ownership === "owned" && exited ? "target_exited" : "stopped",
          left(shutdown.sinkUntilMs),
        );
      }
      record.runDisconnectors();
      record.output?.close();
      record.flow.stop();
      const ownedRow = ownedResults?.find((r) => r.record === record);
      const report: CloseReport = {
        sessionId: record.id,
        kind: "live",
        ownership: record.ownership,
        targetState:
          record.ownership === "owned"
            ? killedIds.has(record.id)
              ? ownedTargetState(
                  record.exit !== null && record.exit.kind !== "bea-kill",
                  true,
                  ownedRow?.termination ?? null,
                )
              : "unknown"
            : record.exit === null
              ? "alive-detached"
              : "already-exited",
        termination: ownedRow?.termination ?? null,
        exit: record.exit,
        revert: null,
        agentUnloaded: null,
        fridaDetached: record.fridaSession?.isDetached() ?? true,
        streamsFinalized: [],
        cleanup: { status: "complete" },
        limitations: [...record.limitations],
      };
      if (record.visible)
        await Promise.race([
          deps.sink.sessionEnded({
            sessionId: record.id,
            report,
            deadline: Deadline.after(left(shutdown.sinkUntilMs), deps.now),
            operation: "server_shutdown",
          }),
          after(left(shutdown.sinkUntilMs)),
        ]);
      const failed = failures.some((f) => f.diagnostics?.["session"] === record.id);
      if (!failed) closed.push(record);
    }),
  );
  return {
    report: {
      reason: input.reason,
      elapsedMs: Math.round(deps.now() - t0),
      owned: ownedReport,
      attached: attachedReport,
      external: externalReport,
      abandonedOps,
      failures,
    },
    closed,
    closedExternals: externalReport.filter((e) => e.ok).map((e) => e.sessionId),
  };
};
