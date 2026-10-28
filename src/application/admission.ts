import { serverShuttingDown } from "../domain/errors/constructors.js";
import type { BeaError } from "../domain/errors/beaError.js";
import { err, type Result } from "../domain/result.js";
import type { Lifecycle } from "./lifecycle.js";

/** Refuses new work once shutdown starts; drains in-flight work in the first phase (best-effort, CT-I3). */
export class Admission {
  readonly #inFlight = new Set<Promise<unknown>>();

  constructor(private readonly lifecycle: Lifecycle) {
    lifecycle.register({
      name: "admission",
      phase: "stop-admission",
      bestEffort: true,
      close: (signal) => this.#drain(signal),
    });
  }

  get inFlight(): number {
    return this.#inFlight.size;
  }

  async run<T>(operation: string, work: () => Promise<Result<T, BeaError>>): Promise<Result<T, BeaError>> {
    if (this.lifecycle.closing) return err(serverShuttingDown(operation));
    const running = work();
    this.#inFlight.add(running);
    try {
      return await running;
    } finally {
      this.#inFlight.delete(running);
    }
  }

  /** In-flight handlers already see ctx.signal aborted (shutdown); wait for them, bounded by the phase budget. */
  async #drain(signal: AbortSignal): Promise<void> {
    if (this.#inFlight.size === 0) return;
    await Promise.race([
      Promise.allSettled(this.#inFlight),
      new Promise<void>((resolve) => signal.addEventListener("abort", () => resolve(), { once: true })),
    ]);
  }
}
