import type { BeaErrorOf } from "../domain/errors/beaError.js";

/** The error every day-0 stub raises (and the shape a missing capability takes in tests). */
export const notImplementedError = (operation: string): BeaErrorOf<"CapabilityUnavailable"> => ({
  _tag: "CapabilityUnavailable",
  operation,
  capability: "server",
  reason: "not-implemented",
  retryable: false,
});

/**
 * Day-0 port stub (WP0). METHODS ONLY: every string property is a function that THROWS the
 * capability_unavailable(not-implemented) BeaError synchronously when called (CI-M22: returning an async function made
 * sync members misbehave, e.g. `literals()` returned a Promise). Callers inside handlers need no special case:
 * invokeTool.mapThrown passes BeaErrors through. `then` is undefined so a stub is never mistaken for a thenable.
 * Value properties of a port (e.g. DynamicSessionPort.closing) must not be read on a stub; owning WPs replace the
 * factory body before anything reads them. Construction contract for every factory stub: no target contact, no
 * filesystem writes, no child processes (CI-M20).
 */
export const notImplementedPort = <T extends object>(port: string): T =>
  new Proxy({} as T, {
    get: (_target, prop) =>
      typeof prop === "string" && prop !== "then"
        ? (): never => {
            throw notImplementedError(`${port}.${prop}`);
          }
        : undefined,
  });
