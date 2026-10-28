import { AsyncLocalStorage } from "node:async_hooks";
import { createHash } from "node:crypto";
import { writeSync } from "node:fs";
import { open, type FileHandle } from "node:fs/promises";

import type { BeaError } from "../../domain/errors/beaError.js";
import { serverShuttingDown } from "../../domain/errors/constructors.js";
import { err, ok, type Result } from "../../domain/result.js";
import { internalError, ioError, quotaError } from "./errors.js";
import { encodeLine, MAX_LINE_BYTES, type LedgerLine } from "./LedgerLines.js";
import { mibOf, type QuotaGuard } from "./Quotas.js";

export interface AppendedLine {
  readonly offset: number;
  readonly length: number;
  /** sha256 of the line text without the newline (duplicate-vs-conflict comparison) */
  readonly sha256: string;
}

/** Marks the finalize sequence: its own appends (final manifests, effect ends, the end line) pass the fence. */
export const finalizeScope = new AsyncLocalStorage<true>();

export interface LedgerHooks {
  /** run directory, lock, run.json — before the ledger file is opened */
  readonly prepare: () => Promise<void>;
  /** lines written first (the {t:"run"} line) */
  readonly initial: () => readonly LedgerLine[];
}

export interface AppendOptions {
  readonly operation: string;
  /** fxt, close, exit and final-manifest lines may use the 8 MiB reserve (S2 §9.7) */
  readonly lifecycle?: boolean;
  /** finalize's own lines after the fence (CT-M6) */
  readonly privileged?: boolean;
}

/**
 * The run's single append queue (S2 §9.5): one promise chain, writes never interleave, `ledger.jsonl` opened 'a'.
 * The first append runs `start` (run directory, lock, run.json, the {t:"run"} line) inside the queue, so a server
 * that never records anything never touches the disk (CI-M20). Quotas are reserved synchronously at enqueue.
 * No fsync per line (F10); `sync()` is called at the finalize points.
 */
export class Ledger {
  readonly #path: string;
  readonly #quotas: QuotaGuard;
  readonly #hooks: LedgerHooks;
  #queue: Promise<unknown> = Promise.resolve();
  #handle: FileHandle | undefined;
  #reader: FileHandle | undefined;
  #started: Promise<void> | undefined;
  #size = 0;
  #lines = 0;
  #broken: BeaError | undefined;
  #fenced = false;
  #late = 0;

  constructor(path: string, quotas: QuotaGuard, hooks: LedgerHooks) {
    this.#path = path;
    this.#quotas = quotas;
    this.#hooks = hooks;
  }

  get bytes(): number {
    return this.#size;
  }
  get lines(): number {
    return this.#lines;
  }
  get lateAppends(): number {
    return this.#late;
  }
  get started(): boolean {
    return this.#handle !== undefined;
  }
  get fenced(): boolean {
    return this.#fenced;
  }

  /** CT-M6: after this, only privileged (finalize) appends are accepted; others are rejected and counted. */
  fence(): void {
    this.#fenced = true;
  }

  append(line: LedgerLine, options: AppendOptions): Promise<Result<AppendedLine, BeaError>> {
    return this.appendText(encodeLine(line), options);
  }

  /** Append an already canonical line (`canonicalJson(line) + "
"`; the Recorder reuses its record encoding). */
  appendText(text: string, options: AppendOptions): Promise<Result<AppendedLine, BeaError>> {
    if (this.#fenced && options.privileged !== true && finalizeScope.getStore() !== true) {
      this.#late += 1;
      return Promise.resolve(err(serverShuttingDown(options.operation)));
    }
    const bytes = Buffer.byteLength(text, "utf8");
    if (bytes > MAX_LINE_BYTES)
      return Promise.resolve(err(internalError(options.operation, `ledger line of ${String(bytes)} bytes`)));
    if (!this.#quotas.reserveLedger(bytes, options.lifecycle === true))
      return Promise.resolve(err(quotaError(options.operation, "ledger", mibOf(this.#quotas.limits.ledgerBytes))));
    const task = this.#queue.then(async (): Promise<Result<AppendedLine, BeaError>> => {
      try {
        await this.#ensureStarted();
        if (this.#broken !== undefined) {
          this.#quotas.releaseLedger(bytes);
          return err(this.#broken);
        }
        return ok(this.#write(text));
      } catch (cause) {
        this.#quotas.releaseLedger(bytes);
        const error = ioError(options.operation, "write", this.#path, cause);
        this.#broken ??= error;
        return err(error);
      }
    });
    this.#queue = task;
    return task;
  }

  /** Create the run (directory, lock, run.json, {t:"run"}) without appending anything else. */
  start(operation: string): Promise<Result<void, BeaError>> {
    const task = this.#queue.then(async (): Promise<Result<void, BeaError>> => {
      try {
        await this.#ensureStarted();
        return this.#broken === undefined ? ok(undefined) : err(this.#broken);
      } catch (cause) {
        const error = ioError(operation, "write", this.#path, cause);
        this.#broken ??= error;
        return err(error);
      }
    });
    this.#queue = task;
    return task;
  }

  #ensureStarted(): Promise<void> {
    this.#started ??= (async () => {
      await this.#hooks.prepare();
      this.#handle = await open(this.#path, "a");
      const stat = await this.#handle.stat();
      this.#size = stat.size;
      for (const line of this.#hooks.initial()) {
        const text = encodeLine(line);
        this.#quotas.reserveLedger(Buffer.byteLength(text, "utf8"), true);
        this.#write(text);
      }
    })();
    return this.#started;
  }

  #write(text: string): AppendedLine {
    const handle = this.#handle;
    if (handle === undefined) throw new Error("ledger not open");
    const buffer = Buffer.from(text, "utf8");
    // A synchronous write of one ≤ 4 MiB line into the page cache (S2 E5: writeSync in the 48 µs/record budget); the
    // promise queue still orders appends, and no fsync happens here (F10).
    let written = 0;
    while (written < buffer.length) written += writeSync(handle.fd, buffer, written, buffer.length - written);
    const offset = this.#size;
    this.#size += buffer.length;
    this.#lines += 1;
    return {
      offset,
      length: buffer.length - 1,
      sha256: createHash("sha256")
        .update(buffer.subarray(0, buffer.length - 1))
        .digest("hex"),
    };
  }

  /** Resolves when every queued append has been written. */
  async drain(): Promise<void> {
    await this.#queue.catch(() => undefined);
  }

  /** Read one committed line (no newline). */
  async readAt(offset: number, length: number, operation: string): Promise<Result<string, BeaError>> {
    try {
      this.#reader ??= await open(this.#path, "r");
      const buffer = Buffer.alloc(length);
      let read = 0;
      while (read < length) {
        const { bytesRead } = await this.#reader.read(buffer, read, length - read, offset + read);
        if (bytesRead === 0) break;
        read += bytesRead;
      }
      if (read !== length) return err(internalError(operation, "short ledger read"));
      return ok(buffer.toString("utf8"));
    } catch (cause) {
      return err(ioError(operation, "read", this.#path, cause));
    }
  }

  /** fsync the ledger (stream finalize, close_session, export, run finalize). No-op before the first append. */
  async sync(): Promise<void> {
    await this.drain();
    if (this.#handle !== undefined) await this.#handle.sync();
  }

  async close(): Promise<void> {
    await this.drain();
    const handles = [this.#handle, this.#reader];
    this.#handle = undefined;
    this.#reader = undefined;
    await Promise.allSettled(handles.map((h) => h?.close()));
  }
}
