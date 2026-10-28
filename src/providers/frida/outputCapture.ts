import type { OutputCapture } from "../../ports/sessions.js";

/**
 * stdout/stderr of a piped owned target (S3 §15, H11): every byte drains; the first `headBytes` and a ring of the last
 * `tailBytes` are kept per fd, observed and retained bytes are counted separately, and truncation is evidence, not
 * failure. A zero-length chunk is EOF on that fd (VERIFIED). Each chunk is also handed to `onChunk` (the output
 * recording's stream). Target text is untrusted: the delivery layer marks it.
 */
interface FdCapture {
  readonly head: Buffer[];
  headBytes: number;
  tail: Buffer[];
  tailBytes: number;
  observed: number;
  eof: boolean;
}

const newFd = (): FdCapture => ({ head: [], headBytes: 0, tail: [], tailBytes: 0, observed: 0, eof: false });

export class BoundedOutputCapture implements OutputCapture {
  readonly #headLimit: number;
  readonly #tailLimit: number;
  readonly #fds = { 1: newFd(), 2: newFd() } as const;
  readonly #eofWaiters = new Set<() => void>();
  #closed = false;
  #otherFdBytes = 0;
  readonly #onChunk: ((fd: 1 | 2, data: Buffer) => void) | null;

  constructor(options: {
    readonly headBytes: number;
    readonly tailBytes: number;
    readonly onChunk?: (fd: 1 | 2, data: Buffer) => void;
  }) {
    this.#headLimit = options.headBytes;
    this.#tailLimit = options.tailBytes;
    this.#onChunk = options.onChunk ?? null;
  }

  get observedBytes(): { readonly stdout: number; readonly stderr: number } {
    return { stdout: this.#fds[1].observed, stderr: this.#fds[2].observed };
  }

  get truncated(): boolean {
    return [this.#fds[1], this.#fds[2]].some((fd) => fd.observed > fd.headBytes + fd.tailBytes);
  }

  get eof(): { readonly stdout: boolean; readonly stderr: boolean } {
    return { stdout: this.#fds[1].eof, stderr: this.#fds[2].eof };
  }

  get otherFdBytes(): number {
    return this.#otherFdBytes;
  }

  /** O(1) amortized; never throws (called from the Frida output handler). */
  push(fd: number, data: Buffer): void {
    if (fd !== 1 && fd !== 2) {
      this.#otherFdBytes += data.length;
      return;
    }
    const capture = this.#fds[fd];
    if (data.length === 0) {
      capture.eof = true;
      if (this.#fds[1].eof && this.#fds[2].eof) this.#releaseEofWaiters();
      return;
    }
    if (this.#closed) return;
    capture.observed += data.length;
    let rest = data;
    if (capture.headBytes < this.#headLimit) {
      const take = Math.min(this.#headLimit - capture.headBytes, rest.length);
      capture.head.push(Buffer.from(rest.subarray(0, take)));
      capture.headBytes += take;
      rest = rest.subarray(take);
    }
    if (rest.length > 0) {
      capture.tail.push(Buffer.from(rest));
      capture.tailBytes += rest.length;
      while (capture.tailBytes > this.#tailLimit && capture.tail.length > 0) {
        const first = capture.tail[0];
        if (first === undefined) break;
        const excess = capture.tailBytes - this.#tailLimit;
        if (first.length <= excess) {
          capture.tail.shift();
          capture.tailBytes -= first.length;
        } else {
          capture.tail[0] = first.subarray(excess);
          capture.tailBytes -= excess;
        }
      }
    }
    try {
      this.#onChunk?.(fd, data);
    } catch {
      // the stream sink counts its own failures; output always drains
    }
  }

  /** The last `maxBytes` of retained text on `fd` (UTF-8 with replacement, cut at a code-point boundary). */
  tail(fd: 1 | 2, maxBytes: number): string {
    const capture = this.#fds[fd];
    const all = Buffer.concat([...capture.head, ...capture.tail]);
    const start = Math.max(0, all.length - Math.max(0, maxBytes));
    let cut = start;
    while (cut < all.length && cut > 0 && ((all[cut] ?? 0) & 0xc0) === 0x80) cut += 1;
    return all.subarray(cut).toString("utf8");
  }

  /** Searches the retained head and tail of both fds (a marker in the omitted middle is not found). */
  contains(text: string): boolean {
    if (text.length === 0) return true;
    for (const fd of [1, 2] as const) {
      const capture = this.#fds[fd];
      const contiguous = capture.observed === capture.headBytes + capture.tailBytes;
      const parts = contiguous ? [[...capture.head, ...capture.tail]] : [capture.head, capture.tail];
      if (parts.some((part) => Buffer.concat(part).toString("utf8").includes(text))) return true;
    }
    return false;
  }

  /** Resolves when both fds reached EOF or after `ms` (never rejects). */
  waitEof(ms: number): Promise<boolean> {
    if (this.#fds[1].eof && this.#fds[2].eof) return Promise.resolve(true);
    return new Promise((resolve) => {
      const done = (): void => {
        clearTimeout(timer);
        this.#eofWaiters.delete(done);
        resolve(this.#fds[1].eof && this.#fds[2].eof);
      };
      const timer = setTimeout(done, Math.max(0, ms));
      timer.unref?.();
      this.#eofWaiters.add(done);
    });
  }

  /** Stops accepting data (idempotent). */
  close(): void {
    this.#closed = true;
    this.#releaseEofWaiters();
  }

  #releaseEofWaiters(): void {
    for (const waiter of [...this.#eofWaiters]) waiter();
  }
}
