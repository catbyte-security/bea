import type { BeaError } from "../../domain/errors/beaError.js";
import { err, type Result } from "../../domain/result.js";
import { classifyAbort } from "./aborts.js";
import { NO_RUNTIME_OVERRIDE } from "./hostLimits.js";

/**
 * Per-session FIFO for agent RPCs and state changes (S3 §7.3). At most `max` operations wait or run; an aborted
 * waiter leaves the line without breaking FIFO order. The agent's single JS thread serializes RPCs anyway; the queue
 * gives read-after-write ordering and a place to drain before teardown.
 */
export class SerialQueue {
  readonly #max: number;
  #tail: Promise<void> = Promise.resolve();
  #pending = 0;
  #running: string | null = null;

  constructor(max: number) {
    this.#max = max;
  }

  get pending(): number {
    return this.#pending;
  }

  get running(): string | null {
    return this.#running;
  }

  /** Resolves when everything queued before this call has finished (never rejects). */
  drained(): Promise<void> {
    return this.#tail;
  }

  async run<T>(
    name: string,
    signal: AbortSignal,
    fn: () => Promise<Result<T, BeaError>>,
  ): Promise<Result<T, BeaError>> {
    if (this.#pending >= this.#max)
      return err({
        _tag: "ResourceConstraint",
        operation: name,
        resource: "capacity",
        limits: { max_pending_ops: this.#max },
        retryable: true,
        message: `This session already has ${String(this.#max)} queued operations. Wait for some to finish. ${NO_RUNTIME_OVERRIDE}`,
      });
    this.#pending += 1;
    const previous = this.#tail;
    let release: () => void = () => undefined;
    this.#tail = previous.then(
      () =>
        new Promise<void>((resolve) => {
          release = resolve;
        }),
    );
    try {
      await waitUnlessAborted(previous, signal);
      if (signal.aborted) return err(classifyAbort(signal, name));
      this.#running = name;
      return await fn();
    } finally {
      this.#running = null;
      this.#pending -= 1;
      // Our slot settles only after `previous`; release once it has been created.
      void previous.then(() => release());
    }
  }
}

const waitUnlessAborted = (work: Promise<void>, signal: AbortSignal): Promise<void> => {
  if (signal.aborted) return Promise.resolve();
  return new Promise((resolve) => {
    const onAbort = (): void => resolve();
    signal.addEventListener("abort", onAbort, { once: true });
    void work.then(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    });
  });
};
