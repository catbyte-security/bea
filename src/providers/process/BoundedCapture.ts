import type { StreamWriter } from "../../ports/evidence.js";
import type { OutputCapture } from "../../ports/sessions.js";

/**
 * Bounded target-output capture (S3 §15; port `OutputCapture` in ports/sessions.ts). Every byte is drained; per fd the
 * first `headBytes` (64 KiB) and a ring of the last `tailBytes` (192 KiB) are retained. Observed and retained bytes are
 * counted separately: truncation is evidence, not failure. Each chunk is also appended to the session's `stdio`
 * stream (`stdio.v1`: u8 fd + bytes, one record per chunk); once that stream refuses (quota, closed) output still
 * drains into head and tail and the refusals are counted. A zero-length chunk is EOF on that fd (VERIFIED).
 */
const OUTPUT_HEAD_BYTES = 64 * 1024;
const OUTPUT_TAIL_BYTES = 192 * 1024;

export interface StreamTextCapture {
  /** UTF-8 decoded with replacement, trimmed to code-point boundaries */
  readonly head: string;
  readonly tail: string;
  readonly observedBytes: number;
  readonly retainedBytes: number;
  readonly omittedBytes: number;
  readonly truncated: boolean;
  readonly invalidUtf8: boolean;
  readonly eof: boolean;
}
export interface OutputSnapshot {
  readonly stdout: StreamTextCapture;
  readonly stderr: StreamTextCapture;
  readonly otherFds: readonly { readonly fd: number; readonly bytes: number }[];
}
export interface BoundedOutputCapture extends OutputCapture {
  readonly pid: number;
  onChunk(fd: number, data: Uint8Array): void;
  snapshot(): OutputSnapshot;
  /** both fd1 and fd2 reached EOF (or the capture was closed) */
  readonly ended: Promise<void>;
  /** stops accepting chunks; idempotent */
  close(): void;
  readonly stream: { readonly appended: number; readonly refused: number };
}

/** Byte length of a trailing incomplete UTF-8 sequence (0 when the buffer ends on a boundary). */
export const incompleteUtf8Tail = (bytes: Uint8Array): number => {
  const n = bytes.length;
  for (let back = 1; back <= Math.min(3, n); back++) {
    const byte = bytes[n - back] ?? 0;
    if ((byte & 0xc0) === 0x80) continue;
    const need = byte >= 0xf0 ? 4 : byte >= 0xe0 ? 3 : byte >= 0xc0 ? 2 : 1;
    return need > back ? back : 0;
  }
  return 0;
};

/** Leading UTF-8 continuation bytes (a tail ring that starts mid code point). */
export const leadingContinuationBytes = (bytes: Uint8Array): number => {
  let i = 0;
  while (i < Math.min(3, bytes.length) && ((bytes[i] ?? 0) & 0xc0) === 0x80) i++;
  return i;
};

const lenient = new TextDecoder("utf-8");
const isValidUtf8 = (bytes: Uint8Array): boolean => {
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return true;
  } catch {
    return false;
  }
};

class FdCapture {
  readonly #head: Uint8Array;
  #headLength = 0;
  readonly #ring: Uint8Array;
  #ringStart = 0;
  #ringLength = 0;
  observed = 0;
  eof = false;

  constructor(headBytes: number, tailBytes: number) {
    this.#head = new Uint8Array(headBytes);
    this.#ring = new Uint8Array(tailBytes);
  }

  push(data: Uint8Array): void {
    this.observed += data.length;
    let rest = data;
    if (this.#headLength < this.#head.length) {
      const take = Math.min(this.#head.length - this.#headLength, rest.length);
      this.#head.set(rest.subarray(0, take), this.#headLength);
      this.#headLength += take;
      rest = rest.subarray(take);
    }
    const cap = this.#ring.length;
    if (rest.length === 0 || cap === 0) return;
    if (rest.length >= cap) {
      this.#ring.set(rest.subarray(rest.length - cap));
      this.#ringStart = 0;
      this.#ringLength = cap;
      return;
    }
    let write = (this.#ringStart + this.#ringLength) % cap;
    for (let offset = 0; offset < rest.length;) {
      const span = Math.min(rest.length - offset, cap - write);
      this.#ring.set(rest.subarray(offset, offset + span), write);
      offset += span;
      write = (write + span) % cap;
    }
    const total = this.#ringLength + rest.length;
    if (total > cap) this.#ringStart = (this.#ringStart + total - cap) % cap;
    this.#ringLength = Math.min(total, cap);
  }

  headBytes(): Uint8Array {
    return this.#head.subarray(0, this.#headLength);
  }

  tailBytes(): Uint8Array {
    const out = new Uint8Array(this.#ringLength);
    const first = Math.min(this.#ringLength, this.#ring.length - this.#ringStart);
    out.set(this.#ring.subarray(this.#ringStart, this.#ringStart + first));
    out.set(this.#ring.subarray(0, this.#ringLength - first), first);
    return out;
  }

  /** Head and tail are contiguous when nothing was omitted between them. */
  get omitted(): number {
    return this.observed - this.#headLength - this.#ringLength;
  }

  /** The last `max` retained bytes (contiguous data only), trimmed to code-point boundaries. */
  last(max: number): Uint8Array {
    const tail = this.tailBytes();
    const joined = this.omitted === 0 ? concat(this.headBytes(), tail) : tail.subarray(leadingContinuationBytes(tail));
    const slice = joined.subarray(Math.max(0, joined.length - Math.max(0, max)));
    return slice.subarray(leadingContinuationBytes(slice));
  }

  text(): StreamTextCapture {
    const headRaw = this.headBytes();
    const tailRaw = this.tailBytes();
    const truncated = this.omitted > 0;
    // A head cut by the size limit may end mid code point; a ring that wrapped may start mid code point.
    const cutHead =
      this.#headLength === this.#head.length && this.observed > this.#headLength ? incompleteUtf8Tail(headRaw) : 0;
    const head = headRaw.subarray(0, headRaw.length - cutHead);
    // Contiguous data: the bytes cut from the head start the tail, so no code point is split between the two.
    const tail = truncated
      ? tailRaw.subarray(leadingContinuationBytes(tailRaw))
      : concat(headRaw.subarray(headRaw.length - cutHead), tailRaw);
    const contiguous = truncated ? null : concat(headRaw, tailRaw);
    return {
      head: lenient.decode(head),
      tail: lenient.decode(tail),
      observedBytes: this.observed,
      retainedBytes: this.#headLength + this.#ringLength,
      omittedBytes: this.omitted,
      truncated,
      invalidUtf8: contiguous === null ? !isValidUtf8(head) || !isValidUtf8(tail) : !isValidUtf8(contiguous),
      eof: this.eof,
    };
  }
}

const concat = (a: Uint8Array, b: Uint8Array): Uint8Array => {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
};

export const createOutputCapture = (o: {
  readonly pid: number;
  readonly headBytes?: number;
  readonly tailBytes?: number;
  readonly stream: StreamWriter | null;
}): BoundedOutputCapture => {
  const headBytes = o.headBytes ?? OUTPUT_HEAD_BYTES;
  const tailBytes = o.tailBytes ?? OUTPUT_TAIL_BYTES;
  const fds = { 1: new FdCapture(headBytes, tailBytes), 2: new FdCapture(headBytes, tailBytes) };
  const other = new Map<number, number>();
  let closed = false;
  let chunks = 0;
  let appended = 0;
  let refused = 0;
  let streamOpen = o.stream !== null;
  let resolveEnded: () => void = () => {};
  const ended = new Promise<void>((resolve) => {
    resolveEnded = resolve;
  });
  const checkEnded = (): void => {
    if (closed || (fds[1].eof && fds[2].eof)) resolveEnded();
  };

  const record = (fd: number, data: Uint8Array): void => {
    chunks += 1;
    if (!streamOpen || o.stream === null) {
      refused += o.stream === null ? 0 : 1;
      return;
    }
    const payload = new Uint8Array(data.length + 1);
    payload[0] = fd & 0xff;
    payload.set(data, 1);
    const outcome = o.stream.append(
      { first_seq: chunks, count: 1, dropped_before: 0, module_map_epoch: null },
      payload,
    );
    if (outcome === "accepted" || outcome === "redacted") appended += 1;
    else {
      refused += 1;
      if (outcome === "quota-exceeded" || outcome === "closed") streamOpen = false;
    }
  };

  const decode = (bytes: Uint8Array): string => lenient.decode(bytes);

  return {
    pid: o.pid,
    ended,
    get stream() {
      return { appended, refused };
    },
    onChunk(fd, data) {
      if (closed) return;
      if (fd !== 1 && fd !== 2) {
        other.set(fd, (other.get(fd) ?? 0) + data.length);
        return;
      }
      const capture = fds[fd];
      if (data.length === 0) {
        capture.eof = true;
        checkEnded();
        return;
      }
      capture.push(data);
      record(fd, data);
    },
    snapshot() {
      return {
        stdout: fds[1].text(),
        stderr: fds[2].text(),
        otherFds: [...other].map(([fd, bytes]) => ({ fd, bytes })).sort((a, b) => a.fd - b.fd),
      };
    },
    close() {
      closed = true;
      checkEnded();
    },
    // ------------------------------------------------------------ ports/sessions OutputCapture view
    get observedBytes() {
      return { stdout: fds[1].observed, stderr: fds[2].observed };
    },
    tail(fd, maxBytes) {
      return decode(fds[fd].last(maxBytes));
    },
    contains(text) {
      if (text.length === 0) return true;
      return [fds[1], fds[2]].some((capture) => {
        const t = capture.text();
        return t.head.includes(text) || t.tail.includes(text) || (!t.truncated && (t.head + t.tail).includes(text));
      });
    },
    get truncated() {
      return fds[1].omitted > 0 || fds[2].omitted > 0;
    },
    get eof() {
      return { stdout: fds[1].eof, stderr: fds[2].eof };
    },
  };
};
