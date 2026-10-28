import { Deadline } from "../../domain/deadline.js";
import type { Logger } from "../../domain/logger.js";
import type { CrashReport, ExitMessage } from "../../shared/agentProtocol.js";

/**
 * Crash and exit reports (D-INT-27, S3 §13 with S4's ack form): the agent sends `{bea:"crash", ack, report}` (a
 * first-chance blocking report for crash-class types, or the last-chance UEF report) or `{bea:"exit", ack, …}` and
 * waits, bounded and cooperatively, for `{type:"ack", token}`. The host RECORDS FIRST (sink, ≤ 5 s) and then posts the
 * ack exactly once; `ackAll` releases every pending waiter at once on close, shutdown and script destroy, so the
 * target is never held. Reports are kept in a bounded ring for crash derivation.
 */
export interface ReceivedCrash {
  readonly report: CrashReport;
  readonly receivedAt: number;
  ackVia: "recorded" | "timeout" | "closing" | "destroyed" | null;
}

export interface CrashProtocolDeps {
  readonly post: (message: unknown) => void;
  readonly recordCrash: (report: CrashReport, deadline: Deadline) => Promise<void>;
  readonly recordExit: (message: ExitMessage, deadline: Deadline) => Promise<void>;
  readonly ackTimeoutMs: number;
  readonly ringSize: number;
  readonly now: () => number;
  readonly logger: Logger;
  readonly onReport: () => void;
}

export class CrashProtocol {
  readonly #deps: CrashProtocolDeps;
  readonly #pending = new Map<string, (via: "closing" | "destroyed") => void>();
  readonly #acked = new Set<string>();
  readonly #crashes: ReceivedCrash[] = [];
  #crashCount = 0;
  #exit: { readonly message: ExitMessage; readonly receivedAt: number } | null = null;
  #closed = false;

  constructor(deps: CrashProtocolDeps) {
    this.#deps = deps;
  }

  get crashCount(): number {
    return this.#crashCount;
  }

  /** Most recent first-chance/last-chance reports (bounded ring, oldest first). */
  get crashes(): readonly ReceivedCrash[] {
    return this.#crashes;
  }

  get exit(): { readonly message: ExitMessage; readonly receivedAt: number } | null {
    return this.#exit;
  }

  get pendingAcks(): number {
    return this.#pending.size;
  }

  onCrash(token: string, report: CrashReport): void {
    if (this.#acked.has(token) || this.#pending.has(token)) return;
    const received: ReceivedCrash = { report, receivedAt: this.#deps.now(), ackVia: null };
    this.#crashes.push(received);
    this.#crashCount += 1;
    if (this.#crashes.length > this.#deps.ringSize) this.#crashes.shift();
    this.#deps.onReport();
    this.#recordThenAck(
      token,
      (deadline) => this.#deps.recordCrash(report, deadline),
      (via) => {
        received.ackVia = via;
      },
    );
  }

  onExit(token: string, message: ExitMessage): void {
    if (this.#acked.has(token) || this.#pending.has(token)) return;
    this.#exit ??= { message, receivedAt: this.#deps.now() };
    this.#deps.onReport();
    this.#recordThenAck(
      token,
      (deadline) => this.#deps.recordExit(message, deadline),
      () => undefined,
    );
  }

  /** Releases every waiter now (close, shutdown, script destroyed). Idempotent. */
  ackAll(via: "closing" | "destroyed"): void {
    for (const release of [...this.#pending.values()]) release(via);
    if (via === "destroyed") this.#closed = true;
  }

  #recordThenAck(
    token: string,
    record: (deadline: Deadline) => Promise<void>,
    noteVia: (via: "recorded" | "timeout" | "closing" | "destroyed") => void,
  ): void {
    if (this.#closed) {
      this.#ack(token, "destroyed");
      noteVia("destroyed");
      return;
    }
    const deadline = Deadline.after(this.#deps.ackTimeoutMs, this.#deps.now);
    let settled = false;
    const settle = (via: "recorded" | "timeout" | "closing" | "destroyed"): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      this.#pending.delete(token);
      noteVia(via);
      this.#ack(token, via);
      deadline.dispose();
    };
    const timer = setTimeout(() => settle("timeout"), this.#deps.ackTimeoutMs);
    timer.unref?.();
    this.#pending.set(token, (via) => settle(via));
    void record(deadline).then(
      () => settle("recorded"),
      (cause: unknown) => {
        this.#deps.logger.warn("crash/exit report recording failed", {
          cause: cause instanceof Error ? cause : String(cause),
        });
        settle("recorded");
      },
    );
  }

  /** Exactly one ack per token. */
  #ack(token: string, via: string): void {
    if (this.#acked.has(token)) return;
    this.#acked.add(token);
    try {
      this.#deps.post({ type: "ack", token });
    } catch (cause) {
      this.#deps.logger.debug("ack post failed", { via, cause: cause instanceof Error ? cause : String(cause) });
    }
  }
}
