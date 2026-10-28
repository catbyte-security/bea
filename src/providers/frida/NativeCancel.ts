import type { Deadline } from "../../domain/deadline.js";
import type { CancellableLike } from "./fridaPorts.js";

/**
 * One frida Cancellable per native call (S3 §4.3), armed by a deadline timer and an abort signal. Never shared and
 * never combined: `Cancellable.combine` does not disconnect its closures. The timer is unref'd (VERIFIED: a pending
 * Cancellable does not pin the loop, cancellable-leak.mjs), and dispose() detaches both triggers.
 */
export interface NativeCancel {
  /** pass as the LAST argument of exactly one native call */
  readonly token: CancellableLike;
  /** why it fired, if it did */
  outcome(): "none" | "deadline" | "aborted";
  dispose(): void;
}

export const createNativeCancel = (
  token: CancellableLike,
  spec: { readonly deadline: Deadline; readonly signal?: AbortSignal | undefined },
): NativeCancel => {
  let why: "none" | "deadline" | "aborted" = "none";
  const fire = (reason: "deadline" | "aborted"): void => {
    if (why !== "none") return;
    why = reason;
    try {
      token.cancel();
    } catch {
      // a cancel on a finished operation is harmless
    }
  };
  const timer = setTimeout(() => fire("deadline"), Math.max(0, spec.deadline.remaining()));
  timer.unref();
  const onAbort = (): void => fire("aborted");
  if (spec.signal?.aborted === true) fire("aborted");
  else spec.signal?.addEventListener("abort", onAbort, { once: true });
  let disposed = false;
  return {
    token,
    outcome: () => why,
    dispose: () => {
      if (disposed) return;
      disposed = true;
      clearTimeout(timer);
      spec.signal?.removeEventListener("abort", onAbort);
    },
  };
};
