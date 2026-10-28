import type { BeaError } from "../domain/errors/beaError.js";
import type { JsonObject } from "../domain/json.js";
import type { Result } from "../domain/result.js";
import type { LiveSession, OperationContext, SessionId, WaitCondition } from "./sessions.js";

/**
 * CI-B6: non-recording handles that cross work packages. `wait` and `stop_instrumentation` (WP-HOOK)
 * and `session_status` (WP-SESS) dispatch on the id; the owning WP registers its kind from its handler factory:
 * `scan_…` = WP-SCAN (ScanService), `fx_…` of memory-written / code-patched effects = WP-MODIFY (WriteService).
 */
export type HandleKind = "scan" | "write";

export interface HandleView {
  readonly id: string;
  readonly kind: HandleKind;
  readonly sessionId: SessionId;
  readonly state: "running" | "ready" | "active" | "released" | "reverted" | "failed";
  /** bounded, BEA-authored digest (scans: value_type, count, iteration) */
  readonly summary: JsonObject;
}

export interface HandleStopOutcome {
  readonly id: string;
  readonly kind: HandleKind;
  readonly status: "released" | "reverted" | "already_ended" | "revert-failed";
}

export interface HandleKindSpec {
  readonly kind: HandleKind;
  /** true when this kind owns the id (prefix and membership) */
  owns(id: string): boolean;
  list(sessionId: SessionId): readonly HandleView[];
  get(id: string): HandleView | undefined;
  /** condition for wait({until:"done"}), e.g. {kind:"agent-job", jobId}; null = already done */
  doneCondition(id: string): WaitCondition | null;
  /** runs inside the caller's exclusive session section */
  stop(session: LiveSession, id: string, op: OperationContext): Promise<Result<HandleStopOutcome, BeaError>>;
}

export interface HandleRegistry {
  register(spec: HandleKindSpec): () => void;
  find(id: string): HandleKindSpec | undefined;
  list(sessionId: SessionId): readonly HandleView[];
}
