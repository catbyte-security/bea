import { createServer, type Server as HttpServer } from "node:http";
import type { AddressInfo } from "node:net";

import {
  hostHeaderValidationResponse,
  localhostAllowedHostnames,
  localhostAllowedOrigins,
  originValidationResponse,
  type McpServer,
} from "@modelcontextprotocol/server";

import type { Clock } from "../../domain/clock.js";
import type { Logger } from "../../domain/logger.js";
import { bearerVerifier, jsonRpcErrorResponse, unauthorized } from "./auth.js";
import { drainUnreadBody, toWebRequest, UnsupportedRequestTargetError, writeWebResponse } from "./nodeBridge.js";
import { MAX_HTTP_REQUEST_BYTES, parseJsonBody, payloadTooLarge, readBodyLimited } from "./requestBody.js";
import { HttpSessionMap } from "./sessionMap.js";

const MCP_HTTP_PATH = "/mcp";
/** Graceful stop for scripts: on Windows a parent's kill() is TerminateProcess and runs no cleanup. */
const SHUTDOWN_PATH = "/shutdown";
export const LOOPBACK = "127.0.0.1";
const EVICTION_INTERVAL_MS = 60_000;
const GRACEFUL_CLOSE_MS = 500;

export interface ServeHttpOptions {
  /** 0 = ephemeral. */
  readonly port: number;
  readonly token: string;
  readonly jsonResponse: boolean;
  /** One McpServer view per MCP session over the shared application (no onServedInstanceClosed). */
  readonly createServer: () => McpServer;
  readonly clock: Clock;
  readonly logger: Logger;
  /** Authenticated POST /shutdown; called after the 202 has been fully written. */
  readonly onShutdownRequest: () => void;
  /** Tests only: a smaller body limit. Default MAX_HTTP_REQUEST_BYTES (64 MiB). */
  readonly maxRequestBytes?: number;
}

export interface HttpListener {
  /** http://127.0.0.1:<port>/mcp */
  readonly url: string;
  readonly port: number;
  /** The MCP session map (tests drive evictIdle() with a manual clock). */
  readonly sessions: HttpSessionMap;
  /** Stop accepting, close every MCP session, force remaining connections after 500 ms. Idempotent. */
  readonly close: () => Promise<void>;
}

interface Routed {
  readonly response: Response;
  /** Runs after the response is completely written (VERIFIED: shutting down earlier truncates the 202). */
  readonly after?: () => void;
}

/**
 * Minimal `bea mcp --http` (S1 §6.6 as amended by D-INT-12): loopback only, bearer token, one SDK
 * WebStandardStreamableHTTPServerTransport per MCP session. Per request, before any body byte is read:
 * Host -> Origin -> path -> bearer; then /shutdown, or the 64 MiB body limit (413) and session routing.
 */
export const serveHttp = async (options: ServeHttpOptions): Promise<HttpListener> => {
  const maxRequestBytes = options.maxRequestBytes ?? MAX_HTTP_REQUEST_BYTES;
  const verify = bearerVerifier(options.token);
  const sessions = new HttpSessionMap(options.createServer, {
    jsonResponse: options.jsonResponse,
    clock: options.clock,
    logger: options.logger,
    maxRequestBytes,
  });
  const hosts = localhostAllowedHostnames();
  const origins = localhostAllowedOrigins();
  let origin = "";

  const route = async (request: Request): Promise<Routed> => {
    const refused = hostHeaderValidationResponse(request, hosts) ?? originValidationResponse(request, origins);
    if (refused !== undefined) return { response: refused };
    const { pathname } = new URL(request.url);
    if (pathname !== MCP_HTTP_PATH && pathname !== SHUTDOWN_PATH)
      return { response: jsonRpcErrorResponse(404, -32601, `Only ${MCP_HTTP_PATH} is served.`) };
    if (!verify(request.headers.get("authorization"))) return { response: unauthorized() };
    if (pathname === SHUTDOWN_PATH) {
      if (request.method !== "POST")
        return { response: jsonRpcErrorResponse(405, -32601, "Use POST /shutdown.", { allow: "POST" }) };
      return {
        response: new Response(JSON.stringify({ shutting_down: true }), {
          status: 202,
          headers: { "content-type": "application/json", connection: "close" },
        }),
        after: options.onShutdownRequest,
      };
    }
    if (request.method !== "POST") return { response: await sessions.handle(request) };
    const body = await readBodyLimited(request, maxRequestBytes);
    if (body.tooLarge) return { response: payloadTooLarge(maxRequestBytes) };
    const parsed = parseJsonBody(body.text);
    if (parsed.ok) return { response: await sessions.handle(request, { parsedBody: parsed.value }) };
    // Not JSON: hand the text to the transport, which answers with its own 406/415/400 in its own order.
    const replay = new Request(request.url, {
      method: "POST",
      headers: request.headers,
      body: body.text,
      signal: request.signal,
    });
    return { response: await sessions.handle(replay) };
  };

  const http: HttpServer = createServer((req, res) => {
    void (async () => {
      let routed: Routed;
      try {
        routed = await route(toWebRequest(req, res, origin));
      } catch (cause: unknown) {
        const target = cause instanceof UnsupportedRequestTargetError;
        if (!target)
          options.logger.error("http dispatch failed", { cause: cause instanceof Error ? cause : String(cause) });
        routed = {
          response: target
            ? jsonRpcErrorResponse(400, -32600, "Unsupported request target.")
            : jsonRpcErrorResponse(500, -32603, "Internal error."),
        };
      }
      // Answered without reading the whole body (413, 401, /shutdown …): discard the rest first, so the client can
      // read the reply; a client sending more than twice the limit loses the connection instead.
      if (!(await drainUnreadBody(req, 2 * maxRequestBytes))) {
        await routed.response.body?.cancel().catch(() => undefined);
        return;
      }
      await writeWebResponse(routed.response, res).catch(() => undefined);
      routed.after?.();
    })();
  });
  await new Promise<void>((resolve, reject) => {
    http.once("error", reject);
    http.listen(options.port, LOOPBACK, () => {
      http.off("error", reject);
      resolve();
    });
  });
  http.on("error", (cause) => options.logger.warn("http server error", { cause }));
  const address = http.address() as AddressInfo;
  origin = `http://${LOOPBACK}:${String(address.port)}`;
  const eviction = setInterval(() => void sessions.evictIdle(), EVICTION_INTERVAL_MS);
  eviction.unref();

  let closing: Promise<void> | undefined;
  return {
    url: `${origin}${MCP_HTTP_PATH}`,
    port: address.port,
    sessions,
    close: () =>
      (closing ??= (async () => {
        clearInterval(eviction);
        // Stop accepting; Node closes idle keep-alive sockets on close().
        const closed = new Promise<void>((resolve) => http.close(() => resolve()));
        // Ends every session's SSE streams through the SDK transport.
        await sessions.closeAll();
        const forced = setTimeout(() => http.closeAllConnections(), GRACEFUL_CLOSE_MS);
        await closed;
        clearTimeout(forced);
      })()),
  };
};
