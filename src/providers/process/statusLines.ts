import { jobHostEventSchema, type JobHostEvent } from "../../domain/jobhostProtocol.js";

/**
 * bea-jobhost status channel parser (S3 §5.2): NDJSON on fd3, one protocol-1 event per line, each line at most
 * {@link STATUS_LINE_MAX_BYTES}. Anything else is a protocol violation; the owner terminates the helper (and with it
 * the job) and reports execution_failure. Pure and synchronous: callbacks run inline and must not throw.
 */
export const STATUS_LINE_MAX_BYTES = 8 * 1024;

export type StatusViolation =
  | { readonly kind: "line-too-long"; readonly bytes: number }
  | { readonly kind: "invalid-json" }
  | { readonly kind: "schema"; readonly event: string | null }
  | { readonly kind: "protocol-mismatch"; readonly protocol: unknown }
  | { readonly kind: "unterminated-line"; readonly bytes: number };

export interface StatusLineParser {
  push(chunk: Uint8Array): void;
  /** The channel ended: a pending partial line is reported as `unterminated-line`. */
  end(): void;
  /** Once a violation was reported, every later byte is ignored. */
  readonly violated: boolean;
}

const NEWLINE = 0x0a;

/** Parse one complete line (without its newline). Exported for tests. */
export const parseStatusLine = (
  text: string,
):
  | { readonly ok: true; readonly event: JobHostEvent }
  | { readonly ok: false; readonly violation: StatusViolation } => {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return { ok: false, violation: { kind: "invalid-json" } };
  }
  const parsed = jobHostEventSchema.safeParse(raw);
  if (parsed.success) return { ok: true, event: parsed.data };
  const event = typeof raw === "object" && raw !== null ? Reflect.get(raw, "event") : undefined;
  if (event === "hello" && Reflect.get(raw as object, "protocol") !== 1)
    return { ok: false, violation: { kind: "protocol-mismatch", protocol: Reflect.get(raw as object, "protocol") } };
  return { ok: false, violation: { kind: "schema", event: typeof event === "string" ? event.slice(0, 32) : null } };
};

export const createStatusLineParser = (handlers: {
  readonly onEvent: (event: JobHostEvent) => void;
  readonly onViolation: (violation: StatusViolation) => void;
}): StatusLineParser => {
  let pending: Uint8Array[] = [];
  let pendingBytes = 0;
  let violated = false;
  const decoder = new TextDecoder("utf-8");

  const fail = (violation: StatusViolation): void => {
    violated = true;
    pending = [];
    pendingBytes = 0;
    handlers.onViolation(violation);
  };

  const line = (bytes: Uint8Array): void => {
    let end = bytes.length;
    if (end > 0 && bytes[end - 1] === 0x0d) end -= 1;
    if (end === 0) return;
    const result = parseStatusLine(decoder.decode(bytes.subarray(0, end)));
    if (result.ok) handlers.onEvent(result.event);
    else fail(result.violation);
  };

  return {
    get violated() {
      return violated;
    },
    push(chunk) {
      let start = 0;
      while (!violated && start < chunk.length) {
        const nl = chunk.indexOf(NEWLINE, start);
        const stop = nl === -1 ? chunk.length : nl;
        const piece = chunk.subarray(start, stop);
        if (pendingBytes + piece.length > STATUS_LINE_MAX_BYTES) {
          fail({ kind: "line-too-long", bytes: pendingBytes + piece.length });
          return;
        }
        if (nl === -1) {
          pending.push(piece.slice());
          pendingBytes += piece.length;
          return;
        }
        if (pending.length === 0) line(piece);
        else {
          pending.push(piece);
          const joined = new Uint8Array(pendingBytes + piece.length);
          let at = 0;
          for (const part of pending) {
            joined.set(part, at);
            at += part.length;
          }
          pending = [];
          pendingBytes = 0;
          line(joined);
        }
        start = nl + 1;
      }
    },
    end() {
      if (!violated && pendingBytes > 0) fail({ kind: "unterminated-line", bytes: pendingBytes });
    },
  };
};
