export type ShutdownSignal = "SIGINT" | "SIGTERM";

/** 128 + signal number. */
export const SIGNAL_EXIT_STATUS: { readonly [S in ShutdownSignal]: number } = { SIGINT: 130, SIGTERM: 143 };

interface SignalSource {
  on(event: ShutdownSignal, listener: () => void): unknown;
  off(event: ShutdownSignal, listener: () => void): unknown;
}

interface InputSource {
  on(event: "end" | "close", listener: () => void): unknown;
  off(event: "end" | "close", listener: () => void): unknown;
}

export interface ShutdownEvents {
  readonly signals: SignalSource;
  /** Absent for transports that do not own stdin (HTTP). */
  readonly stdin?: InputSource;
}

/** REA src/main/processShutdown.ts: SIGINT, SIGTERM, stdin end and close. Returns the unregister function. */
export const registerProcessShutdown = (
  handler: (signal?: ShutdownSignal) => void,
  events: ShutdownEvents = { signals: process, stdin: process.stdin },
): (() => void) => {
  const onInterrupt = (): void => handler("SIGINT");
  const onTerminate = (): void => handler("SIGTERM");
  const onInputEnd = (): void => handler();
  events.signals.on("SIGINT", onInterrupt);
  events.signals.on("SIGTERM", onTerminate);
  events.stdin?.on("end", onInputEnd);
  events.stdin?.on("close", onInputEnd);
  return () => {
    events.signals.off("SIGINT", onInterrupt);
    events.signals.off("SIGTERM", onTerminate);
    events.stdin?.off("end", onInputEnd);
    events.stdin?.off("close", onInputEnd);
  };
};

/**
 * Review fix LIFE-2: the production hard exit of a server. `code: null` exits with the exit code set so far (else 1);
 * a number exits with it. The timer is REF'D: an unref'd one never fires once the event loop drains into Node's
 * natural-exit teardown, where frida-node's DeviceManager env-cleanup hook (close_sync, no cancellable) blocks forever
 * on a wedged frida-core. The exit is explicit (process.exit skips that teardown). After cleanup (`code` set) the
 * process exits as soon as stdout drained, `ms` capping the wait for a client that stopped reading.
 */
export const processExitAfterMs = (code: number | null, ms: number): void => {
  let exited = false;
  const exit = (): void => {
    if (exited) return;
    exited = true;
    process.exit(code ?? (typeof process.exitCode === "number" ? process.exitCode : 1));
  };
  setTimeout(exit, Math.max(0, ms));
  if (code !== null) process.stdout.write("", exit);
};
