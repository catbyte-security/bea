import type { Deadline } from "../domain/deadline.js";
import type { JsonValue } from "../domain/json.js";
import type { TimeMark } from "../domain/time.js";
import type { CrashReport, ExitMessage } from "../shared/agentProtocol.js";
import type { AgentFault, CloseReport, DetachInfo, ProcessExit, SessionId, SessionState } from "./sessions.js";

/**
 * Session lifecycle → evidence (S3 §18). Implemented by src/application/sessions/SessionEvidenceSink.ts
 * (WP-SESS, over the EvidenceRuntime port). Sync methods must not throw and queue their work; async methods honour
 * their deadline. crashReport/exitReport resolve BEFORE the host posts the agent ack (record-before-ack).
 */
export interface SessionEventSink {
  stateChanged(e: {
    readonly sessionId: SessionId;
    readonly from: SessionState;
    readonly to: SessionState;
    readonly cause: string;
    readonly at: TimeMark;
  }): void;
  targetEffect(e: {
    readonly sessionId: SessionId;
    readonly kind:
      | "process-spawned"
      | "process-attached"
      | "agent-injected"
      | "process-resumed"
      | "process-killed"
      | "agent-unloaded"
      | "process-detached";
    readonly facts: Readonly<Record<string, JsonValue>>;
    readonly at: TimeMark;
  }): void;
  rootExit(e: {
    readonly sessionId: SessionId;
    readonly exit: ProcessExit;
    readonly activeAfterRoot: number | null;
    readonly at: TimeMark;
  }): void;
  procEvent(e: {
    readonly sessionId: SessionId;
    readonly kind: "proc-start" | "proc-exit";
    readonly pid: number;
    readonly abnormal: boolean | null;
    readonly at: TimeMark;
  }): void;
  detached(e: { readonly sessionId: SessionId; readonly info: DetachInfo }): void;
  agentFault(e: { readonly sessionId: SessionId; readonly fault: AgentFault }): void;
  crashReport(e: {
    readonly sessionId: SessionId;
    readonly report: CrashReport;
    readonly deadline: Deadline;
  }): Promise<void>;
  exitReport(e: {
    readonly sessionId: SessionId;
    readonly report: ExitMessage;
    readonly deadline: Deadline;
  }): Promise<void>;
  sessionEnded(e: {
    readonly sessionId: SessionId;
    readonly report: CloseReport;
    readonly deadline: Deadline;
  }): Promise<void>;
}
