import type { BeaError } from "../../domain/errors/beaError.js";
import type { Logger } from "../../domain/logger.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { AgentFault } from "../../ports/sessions.js";
import type {
  CrashReport,
  ExitMessage,
  InstrumentMessage,
  JobMessage,
  NoticeMessage,
  ReadyMessage,
} from "../../shared/agentProtocol.js";
import { AGENT_PROTOCOL } from "../../shared/agentProtocol.js";
import {
  agentCrashSchema as crashSchema,
  agentExitSchema as exitSchema,
  agentFatalSchema as fatalSchema,
  agentFaultSchema as faultSchema,
  agentInstrumentSchema as instrumentSchema,
  agentJobSchema as jobSchema,
  agentNoticeSchema as noticeSchema,
  agentReadySchema as readySchema,
} from "../../application/sessions/agentSchemas.js";
import type { AgentJobs } from "./AgentJobs.js";
import type { CrashProtocol } from "./CrashProtocol.js";
import type { FridaLogLevel, FridaMessage } from "./fridaPorts.js";
import type { SessionStreamBinder } from "./StreamBinder.js";

/**
 * The agent → host message router (S3 §10 with S4's message set). Never throws into Frida: every handler is wrapped,
 * unknown or malformed payloads are counted (`protocolViolations`), handler exceptions are counted (`handlerErrors`).
 * `ready` settles exactly once: a valid ready message (protocol, build id, pid, arch, runtime checked), or a load error,
 * a fatal message, a detach/destroy or the timeout. Agent text (log lines, error descriptions) is target-derived: it
 * goes to bounded rings and debug logs only, never into error messages (CT-M8).
 */
export interface AgentChannelDeps {
  readonly operation: string;
  readonly expected: { readonly pid: number; readonly buildId: string };
  readonly binder: SessionStreamBinder;
  readonly jobs: AgentJobs;
  readonly crash: CrashProtocol;
  readonly onInstrument: (message: InstrumentMessage) => void;
  readonly onFault: (fault: AgentFault) => void;
  readonly onNotice: (message: NoticeMessage) => void;
  readonly logger: Logger;
  readonly now: () => number;
  readonly wallIso: () => string;
  readonly monoNs: () => bigint;
  readonly limits: {
    readonly logEntries: number;
    readonly logBytes: number;
    readonly logEntryBytes: number;
    readonly agentFaults: number;
  };
}

export interface LogEntry {
  readonly level: FridaLogLevel;
  readonly text: string;
  readonly at: number;
}

export class AgentChannel {
  readonly #deps: AgentChannelDeps;
  #readySettled = false;
  #resolveReady: (result: Result<ReadyMessage, BeaError>) => void = () => undefined;
  readonly ready: Promise<Result<ReadyMessage, BeaError>>;
  readonly #logs: LogEntry[] = [];
  #logBytes = 0;
  readonly #faults: AgentFault[] = [];
  #faultCount = 0;
  #protocolViolations = 0;
  #handlerErrors = 0;
  #destroyed = false;

  constructor(deps: AgentChannelDeps) {
    this.#deps = deps;
    this.ready = new Promise((resolve) => {
      this.#resolveReady = resolve;
    });
  }

  get protocolViolations(): number {
    return this.#protocolViolations + this.#deps.binder.malformedBatches;
  }

  get handlerErrors(): number {
    return this.#handlerErrors;
  }

  get faultCount(): number {
    return this.#faultCount;
  }

  get recentFaults(): readonly AgentFault[] {
    return this.#faults;
  }

  get logs(): readonly LogEntry[] {
    return this.#logs;
  }

  get destroyed(): boolean {
    return this.#destroyed;
  }

  /** Settles `ready` with a failure (detach, destroy, timeout, cancel); no-op once settled. */
  failReady(error: BeaError): void {
    this.#settleReady(err(error));
  }

  readonly onLog = (level: FridaLogLevel, text: string): void => {
    try {
      const bounded = typeof text === "string" ? text.slice(0, this.#deps.limits.logEntryBytes) : "";
      this.#logs.push({ level, text: bounded, at: this.#deps.now() });
      this.#logBytes += bounded.length;
      while (
        this.#logs.length > this.#deps.limits.logEntries ||
        (this.#logBytes > this.#deps.limits.logBytes && this.#logs.length > 0)
      ) {
        const dropped = this.#logs.shift();
        this.#logBytes -= dropped?.text.length ?? 0;
      }
    } catch {
      this.#handlerErrors += 1;
    }
  };

  readonly onDestroyed = (): void => {
    try {
      this.#destroyed = true;
      this.#deps.crash.ackAll("destroyed");
      this.failReady({
        _tag: "CapabilityUnavailable",
        operation: this.#deps.operation,
        capability: "agent",
        reason: "agent-gone",
        retryable: false,
      });
    } catch {
      this.#handlerErrors += 1;
    }
  };

  readonly onMessage = (message: FridaMessage, data: Buffer | null): void => {
    try {
      if (message.type === "error") {
        this.#onScriptError(message);
        return;
      }
      const payload = message.payload as { readonly bea?: unknown } | null;
      if (payload === null || typeof payload !== "object" || typeof payload.bea !== "string") {
        this.#protocolViolations += 1;
        return;
      }
      this.#route(payload.bea, payload as Record<string, unknown>, data);
    } catch (cause) {
      this.#handlerErrors += 1;
      this.#deps.logger.warn("agent message handler failed", { cause: cause instanceof Error ? cause : String(cause) });
    }
  };

  #route(kind: string, payload: Record<string, unknown>, data: Buffer | null): void {
    switch (kind) {
      case "batch":
        this.#deps.binder.onBatch(payload, data);
        return;
      case "blob":
        this.#deps.jobs.onBlob(payload, data);
        return;
      case "ready":
        this.#onReady(payload);
        return;
      case "crash": {
        const parsed = crashSchema.safeParse(payload);
        if (!parsed.success) this.#protocolViolations += 1;
        else this.#deps.crash.onCrash(parsed.data.ack, parsed.data.report as unknown as CrashReport);
        return;
      }
      case "exit": {
        const parsed = exitSchema.safeParse(payload);
        if (!parsed.success) this.#protocolViolations += 1;
        else this.#deps.crash.onExit(parsed.data.ack, parsed.data as unknown as ExitMessage);
        return;
      }
      case "job": {
        const parsed = jobSchema.safeParse(payload);
        if (!parsed.success) this.#protocolViolations += 1;
        else this.#deps.jobs.onJob(parsed.data as unknown as JobMessage);
        return;
      }
      case "instrument": {
        const parsed = instrumentSchema.safeParse(payload);
        if (!parsed.success) this.#protocolViolations += 1;
        else this.#deps.onInstrument(parsed.data as unknown as InstrumentMessage);
        return;
      }
      case "fault": {
        const parsed = faultSchema.safeParse(payload);
        if (!parsed.success) this.#protocolViolations += 1;
        else this.#pushFault("error-message", `agent fault in ${parsed.data.where} (${parsed.data.error._tag})`);
        return;
      }
      case "notice": {
        const parsed = noticeSchema.safeParse(payload);
        if (!parsed.success) this.#protocolViolations += 1;
        else this.#deps.onNotice(parsed.data as unknown as NoticeMessage);
        return;
      }
      case "fatal": {
        const parsed = fatalSchema.safeParse(payload);
        const stage = parsed.success ? parsed.data.stage : "unknown";
        const tag = parsed.success ? parsed.data.error._tag : "unknown";
        this.#pushFault("fatal", `agent fatal at ${stage} (${tag})`);
        this.failReady({
          _tag: "ProviderFailure",
          operation: this.#deps.operation,
          provider: "agent",
          message: "The BEA agent failed to start in the target.",
          diagnostics: { stage, agent_tag: tag },
        });
        return;
      }
      default:
        this.#protocolViolations += 1;
    }
  }

  #onReady(payload: Record<string, unknown>): void {
    if (this.#readySettled) {
      this.#protocolViolations += 1;
      return;
    }
    const parsed = readySchema.safeParse(payload);
    if (!parsed.success) {
      this.failReady({
        _tag: "ProviderFailure",
        operation: this.#deps.operation,
        provider: "agent",
        message: "The agent's ready message did not match the protocol.",
        diagnostics: { stage: "ready" },
      });
      return;
    }
    const ready = parsed.data as unknown as ReadyMessage;
    const op = this.#deps.operation;
    if (ready.protocol !== AGENT_PROTOCOL)
      this.failReady({
        _tag: "CapabilityUnavailable",
        operation: op,
        capability: "agent",
        reason: "protocol-mismatch",
        retryable: false,
      });
    else if (ready.build_id !== this.#deps.expected.buildId)
      this.failReady({
        _tag: "CapabilityUnavailable",
        operation: op,
        capability: "agent",
        reason: "build-mismatch",
        retryable: false,
        remediation: "The loaded agent is not the build BEA expects; rebuild (npm run build) and restart the server.",
      });
    else if (ready.pid !== this.#deps.expected.pid)
      this.failReady({
        _tag: "InstanceMismatch",
        operation: op,
        expected_instance_id: `pid:${String(this.#deps.expected.pid)}`,
        observed: { pid: ready.pid, start_time: null },
      });
    else if (ready.arch !== "x64")
      this.failReady({ _tag: "UnsupportedTarget", operation: op, reason: "unsupported-arch" });
    else if (ready.runtime !== "QJS")
      this.failReady({
        _tag: "CapabilityUnavailable",
        operation: op,
        capability: "agent",
        reason: "runtime-mismatch",
        retryable: false,
      });
    else this.#settleReady(ok(ready));
  }

  #onScriptError(message: Extract<FridaMessage, { type: "error" }>): void {
    this.#deps.logger.debug("agent script error", {
      text: String(message.description).slice(0, 512),
      line: message.lineNumber ?? null,
    });
    if (!this.#readySettled) {
      this.failReady({
        _tag: "ProviderFailure",
        operation: this.#deps.operation,
        provider: "agent",
        message: "The BEA agent threw while loading in the target.",
        diagnostics: { stage: "agent-load", line: message.lineNumber ?? null },
      });
      return;
    }
    this.#pushFault("error-message", "uncaught agent error");
  }

  #pushFault(kind: AgentFault["kind"], description: string): void {
    const fault: AgentFault = {
      kind,
      description,
      at: { monoNs: this.#deps.monoNs().toString(), wall: this.#deps.wallIso() },
    };
    this.#faultCount += 1;
    this.#faults.push(fault);
    if (this.#faults.length > this.#deps.limits.agentFaults) this.#faults.shift();
    this.#deps.onFault(fault);
  }

  #settleReady(result: Result<ReadyMessage, BeaError>): void {
    if (this.#readySettled) return;
    this.#readySettled = true;
    this.#resolveReady(result);
  }
}
