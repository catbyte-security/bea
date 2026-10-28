import type { JobHostEvent } from "../../domain/jobhostProtocol.js";
import type { ProcessWatcherPort, RootExit } from "../../ports/jobhost.js";
import { raceTimeout } from "./JobHost.js";
import type { HelperSession, JobHostEventOf } from "./JobHostSession.js";

/**
 * The attached-target watcher (S3 §5.4 watch, §5.9). The watch helper opens the target with SYNCHRONIZE |
 * QUERY_LIMITED only, creates no job and refuses `kill` (VERIFIED), so this class has no kill path at all: `stop()`
 * ends the control pipe (EOF → `watch-ended`, exit 0) and, should the helper not exit in time, terminates the HELPER
 * (never the target; the helper holds no right that could affect it).
 */
const WATCH_STOP_WAIT_MS = 2000;

export class ProcessWatcher implements ProcessWatcherPort {
  readonly exited: Promise<RootExit | null>;

  readonly #session: HelperSession;
  readonly #now: () => number;
  readonly #listeners = new Set<(event: JobHostEvent) => void>();
  #watching: JobHostEventOf<"watching"> | null = null;
  #rootExit: RootExit | null = null;
  #stop: Promise<void> | null = null;

  constructor(session: HelperSession, now: () => number) {
    this.#session = session;
    this.#now = now;
    session.subscribe((event) => this.#onEvent(event));
    this.exited = session.finished.then(() => this.#rootExit);
  }

  get helperPid(): number {
    return this.#session.helperPid;
  }
  get pid(): number {
    return this.#watching?.pid ?? 0;
  }
  get creationTime100ns(): bigint {
    return BigInt(this.#watching?.creationTime100ns ?? "0");
  }
  get imagePath(): string | null {
    return this.#watching?.imagePath ?? null;
  }
  get rootExit(): RootExit | null {
    return this.#rootExit;
  }

  on(listener: (event: JobHostEvent) => void): () => void {
    this.#listeners.add(listener);
    return () => void this.#listeners.delete(listener);
  }

  stop(): Promise<void> {
    this.#stop ??= this.#runStop();
    return this.#stop;
  }

  /** Shutdown backstop: terminate the WATCH HELPER now (it holds no right over the target). Idempotent. */
  forceStop(): void {
    this.#session.terminate();
  }

  /** Called by the factory once `watching` resolved the start. */
  bindWatching(event: JobHostEventOf<"watching">): void {
    this.#watching = event;
  }

  async #runStop(): Promise<void> {
    if (this.#session.exit !== null) {
      await this.#session.finished;
      return;
    }
    this.#session.endControl();
    if ((await raceTimeout(this.#session.finished, WATCH_STOP_WAIT_MS)) === "timeout") {
      this.#session.terminate();
      await raceTimeout(this.#session.finished, WATCH_STOP_WAIT_MS);
    }
  }

  #onEvent(event: JobHostEvent): void {
    if (event.event === "root-exit")
      this.#rootExit = {
        code: event.code,
        codeHex: event.codeHex,
        byKill: false,
        activeAfterRoot: null,
        at: this.#now(),
      };
    for (const listener of this.#listeners) {
      try {
        listener(event);
      } catch {
        // listeners must be O(1) and never throw (S3 §16 rule 10)
      }
    }
  }
}
