// =================================================================================================
// src/agent/pure/coreAck.ts — WP3-AGENT pure core of the bounded host acknowledgements (S4 §6.6, F12). One persistent
// `ack` receiver serves every concurrent waiter (two crashing threads, an exit during a crash report) and matches
// them by token; a per-waiter recv() would consume another waiter's ack. Tokens are "crash-<n>" / "exit-<n>".
// =================================================================================================
import type { AckToken } from "../../shared/agentProtocol.js";

export class AckRouter<H> {
  readonly #waiters = new Map<AckToken, H>();
  readonly #early = new Set<AckToken>();
  #next = 1;

  /** A fresh token for a crash or exit message. */
  token(kind: "crash" | "exit"): AckToken {
    return `${kind}-${this.#next++}`;
  }

  /** Register a waiter; true when the ack already arrived (raced ahead of the wait). */
  add(token: AckToken, handle: H): boolean {
    this.#waiters.set(token, handle);
    return this.#early.delete(token);
  }

  remove(token: AckToken): void {
    this.#waiters.delete(token);
    this.#early.delete(token);
  }

  /** An ack post arrived: the waiter's handle, or null (remembered briefly in case its waiter registers late). */
  route(token: AckToken): H | null {
    const h = this.#waiters.get(token);
    if (h !== undefined) return h;
    this.#early.add(token);
    if (this.#early.size > 64) {
      const oldest = this.#early.values().next();
      if (oldest.done !== true) this.#early.delete(oldest.value);
    }
    return null;
  }

  get waiting(): number {
    return this.#waiters.size;
  }
}
