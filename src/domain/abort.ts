/**
 * Abort-signal composition without retention (CT-I2). `AbortSignal.any([...])` over a long-lived source (the
 * lifecycle shutdown signal, a session-closing signal) keeps every composite reachable while any listener stays
 * attached: VERIFIED on Node 24.18 at 1,707 B per composition with a listener left attached and 379 B with it
 * removed, versus 0 B for manual forwarding with removeEventListener. Every per-call or per-operation composition
 * in BEA (invokeTool, DynamicSessionPort.admit's OperationContext, provider waits) uses composeSignal and calls
 * dispose() in a `finally`. oxlint forbids `AbortSignal.any` outside this file.
 */
export interface ComposedSignal {
  readonly signal: AbortSignal;
  /** Detaches from every source. Idempotent; safe after the composite aborted. */
  dispose(): void;
}

export const composeSignal = (sources: readonly AbortSignal[]): ComposedSignal => {
  const controller = new AbortController();
  const subscriptions: (readonly [AbortSignal, () => void])[] = [];
  const dispose = (): void => {
    for (const [source, forward] of subscriptions.splice(0)) source.removeEventListener("abort", forward);
  };
  for (const source of sources) {
    if (source.aborted) {
      controller.abort(source.reason);
      break;
    }
    const forward = (): void => {
      controller.abort(source.reason);
      dispose();
    };
    source.addEventListener("abort", forward, { once: true });
    subscriptions.push([source, forward]);
  }
  if (controller.signal.aborted) dispose();
  return { signal: controller.signal, dispose };
};
