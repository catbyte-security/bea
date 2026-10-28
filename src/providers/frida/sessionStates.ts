import type { SessionState, VisibleSessionState } from "../../ports/sessions.js";

/**
 * The session state machine (S3 §6.2, normative; pure and exhaustively unit-tested). `exited` and `detached` are not
 * terminal for the record: the session stays readable until close_session, because stragglers may still be alive in
 * an owned job. An illegal edge is a programmer error and throws.
 */
export const SESSION_STATES = [
  "spawning",
  "adopted",
  "inspecting",
  "attached",
  "agent_loading",
  "agent_ready",
  "paused",
  "running",
  "exited",
  "detached",
  "failed",
  "closing",
  "cleanup_pending",
  "closed",
] as const satisfies readonly SessionState[];

const STARTUP: readonly SessionState[] = [
  "spawning",
  "adopted",
  "inspecting",
  "attached",
  "agent_loading",
  "agent_ready",
];

/** from → allowed targets */
export const TRANSITIONS: { readonly [S in SessionState]: readonly SessionState[] } = {
  spawning: ["adopted", "failed"],
  adopted: ["attached", "failed"],
  inspecting: ["attached", "failed"],
  attached: ["agent_loading", "failed"],
  agent_loading: ["agent_ready", "failed"],
  agent_ready: ["paused", "running", "failed"],
  paused: ["running", "exited", "detached", "closing"],
  running: ["exited", "detached", "closing"],
  exited: ["closing"],
  detached: ["exited", "closing"],
  failed: ["closed", "cleanup_pending"],
  closing: ["closed", "cleanup_pending"],
  cleanup_pending: ["closing"],
  closed: [],
};

export class IllegalTransitionError extends Error {
  override readonly name = "IllegalTransitionError";
  constructor(
    readonly from: SessionState,
    readonly to: SessionState,
  ) {
    super(`illegal session transition ${from} -> ${to}`);
  }
}

export const canTransition = (from: SessionState, to: SessionState): boolean => TRANSITIONS[from].includes(to);

export const assertTransition = (from: SessionState, to: SessionState): void => {
  if (!canTransition(from, to)) throw new IllegalTransitionError(from, to);
};

export const isStartupState = (state: SessionState): boolean => STARTUP.includes(state);

/** Tool-visible projection (S6 C10): startup states never surface (a failed startup is reported as closed). */
export const visibleState = (state: SessionState): VisibleSessionState => {
  switch (state) {
    case "paused":
    case "running":
    case "exited":
    case "detached":
    case "closing":
    case "cleanup_pending":
    case "closed":
      return state;
    case "failed":
      return "closed";
    default:
      return "closing";
  }
};
