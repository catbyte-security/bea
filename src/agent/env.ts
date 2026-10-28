// =================================================================================================
// src/agent/env.ts — WP3-AGENT façade over the GumJS globals the core runtime uses (S4 §3). Keeping these accesses in
// one place keeps the core logic in pure/ (unit-tested with fakes) and makes the GumJS surface the agent depends on
// explicit: thread identity and cloaking, the message channel, timers, and platform facts.
// =================================================================================================
import type { ThreadId } from "../shared/agentProtocol.js";

export const env = {
  /** Process.pageSize (4096 on Windows x64). */
  pageSize: Process.pageSize,
  pointerSize: Process.pointerSize,
  isWindowsX64: (): boolean => Process.platform === "windows" && Process.arch === "x64",
  currentThreadId: (): ThreadId => Process.getCurrentThreadId(),
  /** The current thread is an agent or Frida-internal thread (F2: true on the agent JS thread). */
  isCloakedThread: (): boolean => Cloak.hasCurrentThread(),
  nowMs: (): number => Date.now(),
  /** send() to the host; binary payloads ride as the second argument (F1). */
  send: (message: unknown, data?: ArrayBuffer): void => {
    if (data === undefined) send(message);
    else send(message, data);
  },
  /** One later turn on the JS thread (job slices, deferred module-map rebuilds). */
  defer: (fn: () => void): void => {
    setImmediate(fn);
  },
  /** Timers on the JS thread (timeouts and intervals are cancelled with their own function). */
  after: (ms: number, fn: () => void): number => setTimeout(fn, ms),
  cancelAfter: (id: number): void => clearTimeout(id),
  every: (ms: number, fn: () => void): number => setInterval(fn, ms),
  cancelEvery: (id: number): void => clearInterval(id),
  /** Frida's private heap (shared by every script and Frida's runtime). */
  heapBytes: (): number => Frida.heapSize,
};
