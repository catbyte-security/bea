// =================================================================================================
// src/agent/ack.ts — WP3-AGENT persistent host-post receivers and bounded acknowledgements (S4 §6.6, F12, CI-I3).
// recv() is one-shot, so each receiver re-arms itself: `ack` (crash/exit waiters matched by token), `flow`
// (cumulative received bytes → flow control) and `resumed` (arms clock:"resume" instrument timers). A waiter creates a
// manual-reset Win32 event, sends its message and waits with a COOPERATIVE WaitForSingleObject, so the JS thread can
// run the ack receiver meanwhile; the wait is always bounded (no unbounded recv().wait()). On the JS thread itself the
// wait would block the receiver, so it degrades to send-without-wait.
// =================================================================================================
import type { AckToken, CrashMessage, ExitMessage, HostPost } from "../shared/agentProtocol.js";
import { AckRouter } from "./pure/coreAck.js";
import type { AgentCore } from "./state.js";

const WAIT_OBJECT_0 = 0;
const MAX_ACK_WAIT_MS = 5000;

export class AckService {
  readonly #core: AgentCore;
  readonly #router = new AckRouter<NativePointer>();
  #armed = false;
  acked = 0;
  timeouts = 0;

  constructor(core: AgentCore) {
    this.#core = core;
  }

  token(kind: "crash" | "exit"): AckToken {
    return this.#router.token(kind);
  }

  /** Boot (events.init): arm the persistent receivers. */
  start(): void {
    if (this.#armed) return;
    this.#armed = true;
    this.#armAck();
    this.#armFlow();
    this.#armResumed();
  }

  /**
   * Send a crash/exit message that needs a host ack and wait for it, bounded (≤ 5 s). Returns whether the ack came.
   * Safe on any thread except the JS thread, where it sends without waiting.
   */
  sendAndAwaitAck(msg: CrashMessage | ExitMessage, timeoutMs: number): { acked: boolean; waited_ms: number } {
    const c = this.#core;
    if (Process.getCurrentThreadId() === c.jsTid) {
      send(msg);
      return { acked: false, waited_ms: 0 };
    }
    const win = c.win;
    const h = win.CreateEventW(NULL, 1, 0, NULL);
    if (h.isNull()) {
      send(msg);
      return { acked: false, waited_ms: 0 };
    }
    const early = this.#router.add(msg.ack, h);
    const t0 = Date.now();
    try {
      send(msg);
      if (early) return { acked: true, waited_ms: 0 };
      const r = win.WaitForSingleObject(h, Math.max(0, Math.min(timeoutMs, MAX_ACK_WAIT_MS)));
      const acked = r === WAIT_OBJECT_0;
      if (acked) this.acked++;
      else this.timeouts++;
      return { acked, waited_ms: Date.now() - t0 };
    } finally {
      this.#router.remove(msg.ack);
      win.CloseHandle(h);
    }
  }

  #armAck(): void {
    recv("ack", (m: Extract<HostPost, { type: "ack" }>) => {
      try {
        const h = typeof m?.token === "string" ? this.#router.route(m.token) : null;
        if (h !== null) this.#core.win.SetEvent(h);
      } catch (e) {
        this.#core.fault("ack-receiver", e);
      }
      this.#armAck();
    });
  }

  #armFlow(): void {
    recv("flow", (m: Extract<HostPost, { type: "flow" }>) => {
      try {
        if (typeof m?.received_bytes === "number") this.#core.streams.onFlowPost(m.received_bytes);
      } catch (e) {
        this.#core.fault("flow-receiver", e);
      }
      this.#armFlow();
    });
  }

  #armResumed(): void {
    recv("resumed", () => {
      try {
        this.#core.instruments.onResumed();
      } catch (e) {
        this.#core.fault("resumed-receiver", e);
      }
      this.#armResumed();
    });
  }
}
