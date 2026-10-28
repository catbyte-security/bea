/**
 * Test barrier (rea-testing §6.2): a fake provider awaits `gate.wait()` at the point under test; the test awaits
 * `gate.entered`, asserts the in-flight state (cancellation, shutdown, a second caller), then calls `release()` or
 * `fail(cause)`. Every pending and later `wait()` settles the same way. No sleeps.
 */
export interface Gate {
  /** Resolves when the first waiter arrives. */
  readonly entered: Promise<void>;
  readonly isEntered: () => boolean;
  /** Number of wait() calls so far. */
  readonly waiters: () => number;
  /** Called by the code under test; settles on release() or fail(). */
  readonly wait: () => Promise<void>;
  readonly release: () => void;
  readonly fail: (cause: unknown) => void;
}

export const createGate = (): Gate => {
  let markEntered: () => void = () => undefined;
  const entered = new Promise<void>((resolve) => {
    markEntered = resolve;
  });
  let count = 0;
  let outcome: { readonly ok: true } | { readonly ok: false; readonly cause: unknown } | null = null;
  const pending: { resolve: () => void; reject: (cause: unknown) => void }[] = [];
  const settle = (value: NonNullable<typeof outcome>): void => {
    if (outcome !== null) return;
    outcome = value;
    for (const waiter of pending.splice(0)) {
      if (value.ok) waiter.resolve();
      else waiter.reject(value.cause);
    }
  };
  return {
    entered,
    isEntered: () => count > 0,
    waiters: () => count,
    wait: () => {
      count += 1;
      markEntered();
      const settled = outcome;
      if (settled !== null) return settled.ok ? Promise.resolve() : Promise.reject(settled.cause);
      return new Promise<void>((resolve, reject) => {
        pending.push({ resolve, reject });
      });
    },
    release: () => settle({ ok: true }),
    fail: (cause) => settle({ ok: false, cause }),
  };
};

/** Named gates for a fake with several barriers: gates.get("attach").wait(). */
export const createGates = <Name extends string>(names: readonly Name[]): ReadonlyMap<Name, Gate> =>
  new Map(names.map((name) => [name, createGate()] as const));
