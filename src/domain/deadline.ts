/**
 * Absolute deadline + its AbortSignal (S3 §16). Every provider call receives min(ctx.remainingMs(), own budget)
 * as a Deadline. Timers are unref'd so a pending deadline never pins the event loop.
 */
export type AbortReason =
  | { readonly kind: "deadline"; readonly ms: number }
  | { readonly kind: "shutdown" }
  | { readonly kind: "session-closing"; readonly sessionId: string }
  | { readonly kind: "caller"; readonly reason: unknown };

export class Deadline {
  readonly #at: number;
  readonly #ms: number;
  readonly #now: () => number;
  #controller: AbortController | null = null;
  #timer: ReturnType<typeof setTimeout> | null = null;

  private constructor(ms: number, now: () => number) {
    this.#ms = Math.max(0, Math.floor(ms));
    this.#at = now() + this.#ms;
    this.#now = now;
  }

  static after(ms: number, now: () => number = () => performance.now()): Deadline {
    return new Deadline(ms, now);
  }

  /** Milliseconds left (never negative). */
  remaining(): number {
    return Math.max(0, this.#at - this.#now());
  }

  get expired(): boolean {
    return this.remaining() === 0;
  }

  get budgetMs(): number {
    return this.#ms;
  }

  /** A deadline that ends at the earlier of this one and `ms` from now. */
  min(ms: number): Deadline {
    return Deadline.after(Math.min(this.remaining(), ms), this.#now);
  }

  /** Lazily created signal that aborts with {kind:"deadline"} when the deadline passes. */
  signal(): AbortSignal {
    if (this.#controller === null) {
      const controller = new AbortController();
      this.#controller = controller;
      const reason: AbortReason = { kind: "deadline", ms: this.#ms };
      const left = this.remaining();
      if (left === 0) controller.abort(reason);
      else {
        this.#timer = setTimeout(() => controller.abort(reason), left);
        this.#timer.unref?.();
      }
    }
    return this.#controller.signal;
  }

  dispose(): void {
    if (this.#timer !== null) clearTimeout(this.#timer);
    this.#timer = null;
  }
}

export const isAbortReason = (value: unknown): value is AbortReason =>
  typeof value === "object" &&
  value !== null &&
  typeof Reflect.get(value, "kind") === "string" &&
  ["deadline", "shutdown", "session-closing", "caller"].includes(Reflect.get(value, "kind") as string);
