import type { EffectKind } from "../../domain/effects/effect.js";
import type { EvId, FxId } from "../../domain/ids.js";
import type { LiveSession, SessionObservation } from "../../ports/sessions.js";

/**
 * Host facts the session provider (WP-SESS) exposes on its LiveSession objects BEYOND the frozen port, read only by
 * the sessions area (handlers/sessions.ts): containment details for session_status, the stream-manifest evidence ids
 * recorded when the session's streams ended (close_session `manifests`), and the lifecycle effects the evidence sink
 * applied (spawn/attach/resume/close `effects_applied`). A LiveSession without them (a fake from another WP's tests)
 * still works: the handlers fall back to what the port offers. Folding these into the port is a filed change request.
 */
export interface LifecycleEffectRef {
  readonly kind: EffectKind;
  readonly id: FxId;
}

export interface SessionContainmentView {
  readonly kind: "win32-job" | "posix-best-effort" | "none";
  /** processes still in the job (owned), from the jobhost's last report */
  readonly activeProcesses: number | null;
  /** pids the jobhost reported starting inside the job, root excluded (≤ 64) */
  readonly childrenSeen: readonly number[];
}

export interface SessionHostFacts {
  readonly beaHostFacts: 1;
  readonly observation: SessionObservation | null;
  containment(): SessionContainmentView | null;
  /** bea.stream.manifest evidence ids of every stream this session ended (≤ 64) */
  manifests(): readonly EvId[];
  /** waits for the evidence sink's queue, then lists the lifecycle effects applied for this session */
  lifecycleEffects(): Promise<readonly LifecycleEffectRef[]>;
  /** limitations accumulated by the session (e.g. BROKERED_LAUNCH, CRASH_PC_UNKNOWN) */
  limitations(): readonly string[];
}

export const hostFactsOf = (session: LiveSession): SessionHostFacts | null =>
  (session as Partial<SessionHostFacts>).beaHostFacts === 1 ? (session as unknown as SessionHostFacts) : null;
