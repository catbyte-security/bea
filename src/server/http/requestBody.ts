import { HARD_LIMITS } from "../../domain/config.js";
import { jsonRpcErrorResponse } from "./auth.js";

/**
 * CT-B3 / D-INT-12: the largest request body `bea mcp --http` reads, the same 64 MiB as the stdio read buffer, so every
 * input a contract accepts (≤ 64 MiB − 64 KiB, D-INT-37) fits with its JSON-RPC envelope. Larger bodies get 413
 * before anything is parsed. (The SDK transport's own default is 4 MiB, which would refuse call-model inputs.)
 */
export const MAX_HTTP_REQUEST_BYTES = HARD_LIMITS.maxStdioRequestBytes;

export type BodyRead = { readonly tooLarge: true } | { readonly tooLarge: false; readonly text: string };

/**
 * Read a request body as UTF-8 text, at most `maxBytes`. A declared Content-Length above the limit is refused without
 * reading; a streamed body is cancelled as soon as it crosses the limit (the node bridge then pauses the socket, and
 * the HTTP layer discards the rest after answering).
 */
export const readBodyLimited = async (request: Request, maxBytes: number): Promise<BodyRead> => {
  const declared = request.headers.get("content-length");
  if (declared !== null && Number(declared) > maxBytes) {
    await request.body?.cancel().catch(() => undefined);
    return { tooLarge: true };
  }
  if (request.body === null) return { tooLarge: false, text: "" };
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let received = 0;
  try {
    for (let next = await reader.read(); !next.done; next = await reader.read()) {
      received += next.value.byteLength;
      if (received > maxBytes) {
        await reader.cancel().catch(() => undefined);
        return { tooLarge: true };
      }
      chunks.push(next.value);
    }
  } finally {
    reader.releaseLock();
  }
  return { tooLarge: false, text: Buffer.concat(chunks, received).toString("utf8") };
};

export const payloadTooLarge = (maxBytes: number): Response =>
  jsonRpcErrorResponse(
    413,
    -32000,
    `Request body exceeds ${String(maxBytes)} bytes. Pass large inputs through files (CLI --input) or smaller batches.`,
  );

/** JSON.parse without throwing; `ok: false` lets the SDK transport answer its own 400 "Parse error". */
export const parseJsonBody = (
  text: string,
): { readonly ok: true; readonly value: unknown } | { readonly ok: false } => {
  try {
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch {
    return { ok: false };
  }
};
