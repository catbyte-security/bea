/**
 * Host side of the agent's flow control (S4 §6.5): the host posts `{type:"flow", received_bytes}` (cumulative) after
 * every 1 MiB received or every 100 ms. The agent sheds non-system rows while sent − received is above its high-water
 * mark, so the host must count in the AGENT's units: binary payloads and blob parts by their length, JSON rows by the
 * agent's estimate (src/agent/pure/coreStreams.ts `estimateBytes`, mirrored here because providers may not import agent
 * code). The estimate rule is the shared contract: 12 per number, "0x…" strings 20, other strings 2 + length,
 * null/boolean 4, arrays 2 + Σ(item + 1), objects 2 + Σ(key + 3 + item), deeper than 6 levels 16.
 */
export const estimateRowBytes = (value: unknown, depth = 0): number => {
  if (typeof value === "number") return 12;
  if (typeof value === "string") return value.startsWith("0x") ? 20 : 2 + value.length;
  if (value === null || typeof value === "boolean" || value === undefined) return 4;
  if (depth > 6) return 16;
  if (Array.isArray(value)) {
    let n = 2;
    for (const item of value) n += estimateRowBytes(item, depth + 1) + 1;
    return n;
  }
  if (typeof value === "object") {
    let n = 2;
    for (const [key, item] of Object.entries(value as Record<string, unknown>))
      n += key.length + 3 + estimateRowBytes(item, depth + 1);
    return n;
  }
  return 8;
};

export class FlowTracker {
  readonly #post: (receivedBytes: number) => void;
  readonly #everyBytes: number;
  readonly #everyMs: number;
  #received = 0;
  #posted = 0;
  #timer: ReturnType<typeof setTimeout> | null = null;
  #stopped = false;

  constructor(options: {
    readonly post: (receivedBytes: number) => void;
    readonly everyBytes: number;
    readonly everyMs: number;
  }) {
    this.#post = options.post;
    this.#everyBytes = options.everyBytes;
    this.#everyMs = options.everyMs;
  }

  get received(): number {
    return this.#received;
  }

  /** Called after the bytes were handed to the evidence writer (O(1); never throws). */
  add(bytes: number): void {
    if (this.#stopped || bytes <= 0) return;
    this.#received += bytes;
    if (this.#received - this.#posted >= this.#everyBytes) this.#flush();
    else if (this.#timer === null) {
      this.#timer = setTimeout(() => {
        this.#timer = null;
        this.#flush();
      }, this.#everyMs);
      this.#timer.unref?.();
    }
  }

  stop(): void {
    this.#stopped = true;
    if (this.#timer !== null) clearTimeout(this.#timer);
    this.#timer = null;
  }

  #flush(): void {
    if (this.#stopped || this.#received === this.#posted) return;
    this.#posted = this.#received;
    try {
      this.#post(this.#received);
    } catch {
      // a post on a destroyed script is harmless; the session is ending
    }
  }
}
