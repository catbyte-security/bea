import type { IncomingMessage, ServerResponse } from "node:http";

/** Trimmed from REA src/server/http/nodeHttpBridge.ts. Origin-form targets only. */
export class UnsupportedRequestTargetError extends Error {
  override readonly name = "UnsupportedRequestTargetError";
}

const requestUrl = (target: string, origin: string): URL => {
  if (!target.startsWith("/") || target.includes("#")) throw new UnsupportedRequestTargetError(target);
  const url = new URL(`${origin}${target}`);
  // Refuse targets URL parsing would rewrite (dot segments, `//host`), so routing sees the raw path.
  if (url.pathname !== (target.split("?")[0] ?? "")) throw new UnsupportedRequestTargetError(target);
  return url;
};

const toHeaders = (incoming: IncomingMessage["headers"]): Headers => {
  const headers = new Headers();
  for (const [name, value] of Object.entries(incoming)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) for (const entry of value) headers.append(name, entry);
    else headers.set(name, value);
  }
  return headers;
};

/**
 * Body stream with backpressure: pause the socket when the web stream is full. Once the consumer cancels (the body
 * limit refused the request), late socket events must not touch the closed controller, so every call is guarded;
 * drainUnreadBody() takes over the socket afterwards.
 */
const requestBody = (request: IncomingMessage): ReadableStream<Uint8Array> => {
  let done = false;
  return new ReadableStream<Uint8Array>({
    start(controller) {
      request.on("data", (chunk: Buffer) => {
        if (done) return;
        controller.enqueue(new Uint8Array(chunk));
        if ((controller.desiredSize ?? 0) <= 0) request.pause();
      });
      request.once("end", () => {
        if (done) return;
        done = true;
        controller.close();
      });
      request.once("error", (cause) => {
        if (done) return;
        done = true;
        controller.error(cause);
      });
    },
    pull() {
      request.resume();
    },
    cancel() {
      done = true;
      request.pause();
    },
  });
};

/** The web Request's signal aborts when the client goes away before the reply finished. */
export const toWebRequest = (request: IncomingMessage, response: ServerResponse, origin: string): Request => {
  const controller = new AbortController();
  response.once("close", () => {
    if (!response.writableFinished) controller.abort();
  });
  const method = request.method ?? "GET";
  return new Request(requestUrl(request.url ?? "/", origin), {
    method,
    headers: toHeaders(request.headers),
    signal: controller.signal,
    ...(method === "GET" || method === "HEAD" ? {} : { body: requestBody(request), duplex: "half" }),
  });
};

/**
 * Discard whatever the client is still sending when BEA answers without reading the whole body (413, 401,
 * /shutdown …), and resolve once the request has ended, BEFORE the answer is written: node:http closes the connection
 * when a response finishes while the request body is still arriving, and a client that writes its whole body before
 * reading (Python urllib, node:http) then sees ECONNRESET instead of the 413 (VERIFIED on Node 24 with a 65 MiB
 * body). Resolves false when the client sent more than `maxBytes` (socket destroyed) or the connection died.
 */
export const drainUnreadBody = (request: IncomingMessage, maxBytes: number): Promise<boolean> => {
  if (request.readableEnded) return Promise.resolve(true);
  if (request.destroyed) return Promise.resolve(false);
  return new Promise((resolve) => {
    request.removeAllListeners("data");
    let discarded = 0;
    request.on("data", (chunk: Buffer) => {
      discarded += chunk.byteLength;
      if (discarded > maxBytes) request.socket.destroy();
    });
    request.once("end", () => resolve(true));
    request.once("close", () => resolve(request.readableEnded));
    request.resume();
  });
};

const drainOrClose = (target: ServerResponse): Promise<void> =>
  new Promise((resolve) => {
    const settle = (): void => {
      target.off("drain", settle);
      target.off("close", settle);
      resolve();
    };
    target.once("drain", settle);
    target.once("close", settle);
  });

/** Stream a web Response (JSON or SSE) into node:http, flushing headers first. */
export const writeWebResponse = async (response: Response, target: ServerResponse): Promise<void> => {
  const headers: Record<string, string | string[]> = {};
  for (const [name, value] of response.headers) if (name !== "set-cookie") headers[name] = value;
  target.writeHead(response.status, headers);
  target.flushHeaders();
  const reader = response.body?.getReader();
  if (reader === undefined || target.req.method === "HEAD") {
    target.end();
    await reader?.cancel().catch(() => undefined);
    return;
  }
  let left = false;
  const leave = (): void => {
    left = true;
    void reader.cancel().catch(() => undefined);
  };
  target.once("close", leave);
  try {
    for (let next = await reader.read(); !next.done && !left; next = await reader.read())
      if (!target.write(next.value) && !left) await drainOrClose(target);
  } finally {
    target.off("close", leave);
    reader.releaseLock();
  }
  if (!left) target.end();
};
