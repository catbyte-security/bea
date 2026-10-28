// =================================================================================================
// src/agent/threads.ts — WP3-AGENT ThreadService (S4 §5.6). Thread enumeration (Frida's and the agent's own threads
// are cloaked, F2), TEB and stack bounds through NtQueryInformationThread (A-10), exclusive suspended
// GetThreadContext (VERIFIED for the debug registers [ext-frida §3.9 a6e]), optional names, and the lazily attached
// thread observer: needed when s:threads is enabled or a debug-register slot is armed; `onAdded` runs ON the new
// thread and also fires for existing threads at attach. Subscribers (WP9 hwbp: arm new threads) register here.
// =================================================================================================
import type { Hex, ThreadId, ThreadRow } from "../shared/agentProtocol.js";
import { hex } from "./encode.js";
import { CTX, parseContext, TEB, THREAD_ACCESS, type ParsedContext } from "./pure/coreWin64.js";
import type { AgentCore } from "./state.js";

/** Observer callbacks get the stable subset of ThreadDetails (id, name, entrypoint, hardware breakpoint methods). */
export interface ThreadObserverSubscriber {
  readonly onAdded?: (thread: StableThreadDetails) => void;
  readonly onRemoved?: (thread: StableThreadDetails) => void;
}

export class ThreadService {
  readonly #core: AgentCore;
  readonly #subscribers = new Set<ThreadObserverSubscriber>();
  #observer: ThreadObserver | null = null;
  #ctx: NativePointer | null = null;
  #info: NativePointer | null = null;

  constructor(core: AgentCore) {
    this.#core = core;
  }

  enumerate(): ThreadDetails[] {
    return Process.enumerateThreads();
  }

  /** TEB base of `tid` via ThreadBasicInformation (A-10); the current thread's through the TEB stub. */
  teb(tid: ThreadId): NativePointer | null {
    if (tid === Process.getCurrentThreadId() && this.#core.native.ready) return this.#core.native.currentTeb();
    const win = this.#core.win;
    const h = win.OpenThread(THREAD_ACCESS.queryLimited, 0, tid);
    if (h.isNull()) return null;
    try {
      this.#info ??= Memory.alloc(TEB.basicInfoSize);
      const status = win.NtQueryInformationThread(h, 0, this.#info, TEB.basicInfoSize, NULL);
      return status === 0 ? this.#info.add(TEB.tebBaseInBasicInfo).readPointer() : null;
    } finally {
      win.CloseHandle(h);
    }
  }

  /** NT_TIB stack bounds of `tid`. */
  stack(tid: ThreadId): { base: Hex; limit: Hex } | null {
    const teb = this.teb(tid);
    if (teb === null) return null;
    try {
      return { base: hex(teb.add(TEB.stackBase).readPointer()), limit: hex(teb.add(TEB.stackLimit).readPointer()) };
    } catch {
      return null;
    }
  }

  /**
   * A raw CONTEXT copy of `tid`: OpenThread → SuspendThread → GetThreadContext → ResumeThread, all exclusive. Refuses
   * the calling thread (it would suspend itself). `flags` are CONTEXT_* values (CONTEXT_AMD64 included).
   */
  contextBytes(tid: ThreadId, flags: number): Uint8Array | null {
    if (tid === Process.getCurrentThreadId()) return null;
    const win = this.#core.win;
    const h = win.OpenThread(
      THREAD_ACCESS.getContext | THREAD_ACCESS.suspendResume | THREAD_ACCESS.queryLimited,
      0,
      tid,
    );
    if (h.isNull()) return null;
    try {
      // 16-byte aligned CONTEXT inside a larger allocation
      this.#ctx ??= Memory.alloc(CTX.size + 16);
      const ctx = this.#ctx.add((16 - (this.#ctx.toUInt32() & 15)) & 15);
      ctx.writeByteArray(new ArrayBuffer(CTX.size));
      ctx.add(CTX.ContextFlags).writeU32(flags);
      if (win.SuspendThread(h) === 0xffffffff) return null;
      let ok = 0;
      try {
        ok = win.GetThreadContext(h, ctx);
      } finally {
        win.ResumeThread(h);
      }
      if (ok === 0) return null;
      const ab = ctx.readByteArray(CTX.size);
      return ab === null ? null : new Uint8Array(ab);
    } finally {
      win.CloseHandle(h);
    }
  }

  /** Decoded CONTEXT of `tid` (debug registers, MXCSR/FPCW, GPRs). */
  context(tid: ThreadId, flags: number): ParsedContext | null {
    const bytes = this.contextBytes(tid, flags);
    return bytes === null ? null : parseContext(bytes);
  }

  /** GetThreadDescription (optional; null when absent or empty). */
  name(tid: ThreadId): string | null {
    const win = this.#core.win;
    if (win.address("kernelbase.dll", "GetThreadDescription") === null) return null;
    const h = win.OpenThread(THREAD_ACCESS.queryLimited, 0, tid);
    if (h.isNull()) return null;
    const out = Memory.alloc(8);
    try {
      if (win.GetThreadDescription(h, out) < 0) return null;
      const p = out.readPointer();
      if (p.isNull()) return null;
      try {
        const s = p.readUtf16String(256);
        return s === null || s === "" ? null : s;
      } finally {
        win.LocalFree(p);
      }
    } finally {
      win.CloseHandle(h);
    }
  }

  /** Add an observer subscriber; attaches the Frida thread observer on first use (onAdded fires for existing threads). */
  subscribe(sub: ThreadObserverSubscriber): () => void {
    this.#subscribers.add(sub);
    this.#ensureObserver();
    return () => {
      this.#subscribers.delete(sub);
      if (this.#subscribers.size === 0 && !this.#wantsRows()) this.#detachObserver();
    };
  }

  /** s:threads was enabled at hello: attach the observer so thread/1 rows flow. */
  enableRows(): void {
    this.#ensureObserver();
  }

  /** dispose: detach the observer (Frida removes it on unload too). */
  dispose(): void {
    this.#detachObserver();
  }

  #wantsRows(): boolean {
    return this.#core.systemStreams.threads !== null;
  }

  #ensureObserver(): void {
    if (this.#observer !== null) return;
    this.#observer = Process.attachThreadObserver({
      onAdded: (t) => this.#onEvent("S", t),
      onRemoved: (t) => this.#onEvent("E", t),
    });
  }

  #detachObserver(): void {
    const obs = this.#observer;
    this.#observer = null;
    try {
      obs?.detach();
    } catch (e) {
      this.#core.fault("thread-observer-detach", e);
    }
  }

  #onEvent(ev: "S" | "E", t: StableThreadDetails): void {
    try {
      const stream = this.#core.systemStreams.threads;
      if (stream !== null) {
        const c = this.#core;
        const entry = ev === "S" && t.entrypoint !== undefined ? hex(t.entrypoint.routine) : null;
        const row: ThreadRow = [c.native.nextG(), c.native.nowUs(), ev, t.id, entry];
        c.streams.emit(stream, row);
      }
      if (ev === "E") this.#core.stalkerCo.forget(t.id);
      for (const sub of this.#subscribers) {
        try {
          if (ev === "S") sub.onAdded?.(t);
          else sub.onRemoved?.(t);
        } catch (e) {
          this.#core.fault("thread-observer-subscriber", e);
        }
      }
    } catch (e) {
      this.#core.fault("thread-observer", e);
    }
  }
}
