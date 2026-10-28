import { HARD_LIMITS, type BeaConfig } from "../../domain/config.js";

/**
 * Host constants and the two configurable limits (S3 §3, D-INT-6, D-INT-7). Fixed values carry the sentence "This
 * release has no runtime override." in their refusals.
 */
export interface HostLimits {
  /** config limits.max_live_sessions / BEA_MAX_LIVE_SESSIONS, 1..8 (default 4) */
  readonly maxLiveSessions: number;
  /** fixed: the stdio:'pipe' anomaly starts at the 4th piped target (rea-testing §0.6) */
  readonly maxPipedTargets: 3;
  readonly maxPendingOpsPerSession: 16;
  readonly maxToolCallMs: number;
  readonly maxWaitMs: number;
  /** config limits.rpc_default_timeout_ms / BEA_RPC_TIMEOUT_MS, 1000..115000 (default 10000) */
  readonly rpcDefaultTimeoutMs: number;
  readonly startup: {
    readonly spawnGuardMs: number;
    readonly metadataMs: number;
    readonly adoptMs: number;
    readonly inspectMs: number;
    readonly watchMs: number;
    readonly attachMs: number;
    readonly createScriptMs: number;
    readonly loadMs: number;
    readonly readyMs: number;
    readonly helloMs: number;
    readonly resumeGuardMs: number;
  };
  /** record-before-ack bound for crash and exit reports (orchestrator) */
  readonly crashAckTimeoutMs: number;
  /** a derived crash joins the last crash-class report received at most this long before the root exit */
  readonly crashReportWindowMs: number;
  readonly shutdown: {
    readonly killEscalateMs: number;
    readonly attachedQueueMs: number;
    readonly attachedRevertMs: number;
    readonly attachedUnloadMs: number;
    readonly attachedDetachMs: number;
    readonly killAwaitMs: number;
    readonly settleUntilMs: number;
    readonly sinkUntilMs: number;
  };
  readonly closeSession: {
    readonly killEscalateMs: number;
    readonly detachWaitMs: number;
    readonly queueDrainMs: number;
    readonly revertMs: number;
    readonly unloadMs: number;
    readonly detachMs: number;
    readonly outputEofWaitMs: number;
    readonly sinkMs: number;
  };
  readonly capture: {
    readonly stdioHeadBytes: number;
    readonly stdioTailBytes: number;
    readonly logEntries: number;
    readonly logBytes: number;
    readonly logEntryBytes: number;
    readonly agentFaults: number;
    readonly crashes: number;
    readonly stateHistory: number;
    readonly orphanOutputBytes: number;
    readonly orphanOutputTtlMs: number;
    /** output stream rows are at most this many bytes of text */
    readonly outputChunkBytes: number;
  };
  /** D-INT-7: batches for not-yet-bound agent streams are parked, then counted `unbound` */
  readonly parking: { readonly maxBytes: number; readonly maxAgeMs: number };
  /** S4 §6.5: flow acks after every 1 MiB or 100 ms */
  readonly flow: { readonly ackEveryBytes: number; readonly ackEveryMs: number };
  /** hello: flush period and flow-control water marks (S4 §6.5) */
  readonly hello: { readonly flushMs: number; readonly highWaterBytes: number; readonly lowWaterBytes: number };
  /** D-INT-1 / CI-M23: the per-session instrument cap bea_status reports and the agent enforces */
  readonly maxInstrumentsPerSession: 16;
  /** R-S3-3: a root exit with code 0 this soon after resume, with only the console host left, is a brokered launch */
  readonly brokeredLaunchWindowMs: number;
  /** Frida's process-terminated detach precedes the jobhost/watcher exit report by ms; wait this long for the code */
  readonly exitReportGraceMs: number;
  /** user scripts (run_script): bounded message capture */
  readonly userScript: { readonly maxMessageBytes: number; readonly maxErrors: number; readonly unloadMs: number };
  /** background ping after an RPC timeout; at most one ping per this interval */
  readonly health: { readonly pingTimeoutMs: number; readonly pingIntervalMs: number };
}

const KiB = 1024;
const MiB = 1024 * KiB;

export const hostLimitsFrom = (config: BeaConfig): HostLimits => ({
  maxLiveSessions: config.limits.maxLiveSessions.value,
  maxPipedTargets: 3,
  maxPendingOpsPerSession: 16,
  maxToolCallMs: HARD_LIMITS.maxToolCallMs,
  maxWaitMs: HARD_LIMITS.maxWaitMs,
  rpcDefaultTimeoutMs: config.limits.rpcDefaultTimeoutMs.value,
  startup: {
    spawnGuardMs: 10_000,
    metadataMs: 2_000,
    adoptMs: 3_000,
    inspectMs: 3_000,
    watchMs: 3_000,
    attachMs: 10_000,
    createScriptMs: 10_000,
    loadMs: 10_000,
    readyMs: 5_000,
    helloMs: 5_000,
    resumeGuardMs: 5_000,
  },
  crashAckTimeoutMs: 5_000,
  crashReportWindowMs: 2_000,
  shutdown: {
    killEscalateMs: 900,
    attachedQueueMs: 300,
    attachedRevertMs: 400,
    attachedUnloadMs: 300,
    attachedDetachMs: 300,
    killAwaitMs: 1_000,
    settleUntilMs: 1_300,
    sinkUntilMs: 1_500,
  },
  closeSession: {
    killEscalateMs: 2_000,
    detachWaitMs: 500,
    queueDrainMs: 2_000,
    revertMs: 5_000,
    unloadMs: 2_000,
    detachMs: 2_000,
    outputEofWaitMs: 200,
    sinkMs: 5_000,
  },
  capture: {
    stdioHeadBytes: 64 * KiB,
    stdioTailBytes: 192 * KiB,
    logEntries: 256,
    logBytes: 256 * KiB,
    logEntryBytes: 4 * KiB,
    agentFaults: 32,
    crashes: 16,
    stateHistory: 32,
    orphanOutputBytes: 64 * KiB,
    orphanOutputTtlMs: 5_000,
    outputChunkBytes: 4 * KiB,
  },
  parking: { maxBytes: 256 * KiB, maxAgeMs: 2_000 },
  flow: { ackEveryBytes: 1 * MiB, ackEveryMs: 100 },
  hello: { flushMs: 50, highWaterBytes: 32 * MiB, lowWaterBytes: 8 * MiB },
  maxInstrumentsPerSession: 16,
  brokeredLaunchWindowMs: 5_000,
  exitReportGraceMs: 2_000,
  userScript: { maxMessageBytes: 64 * KiB, maxErrors: 16, unloadMs: 2_000 },
  health: { pingTimeoutMs: 1_000, pingIntervalMs: 2_000 },
});

/** The suffix every fixed-cap refusal carries (rea-mcp §6.2). */
export const NO_RUNTIME_OVERRIDE = "This release has no runtime override.";
