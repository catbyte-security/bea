import { randomUUID } from "node:crypto";

import {
  isInitializeRequest,
  WebStandardStreamableHTTPServerTransport,
  type McpServer,
} from "@modelcontextprotocol/server";

import type { Clock } from "../../domain/clock.js";
import type { Logger } from "../../domain/logger.js";
import { jsonRpcErrorResponse } from "./auth.js";

/** D-INT-12: at most this many live MCP sessions; this release has no runtime override. */
export const MAX_HTTP_MCP_SESSIONS = 4;
/** D-INT-12 / CT-I10: a session with nothing in flight for longer than this is closed by evictIdle(). */
export const HTTP_SESSION_IDLE_MS = 5 * 60 * 1000;

export interface HttpSessionMapOptions {
  readonly jsonResponse: boolean;
  readonly clock: Clock;
  readonly logger: Logger;
  /** Passed to the SDK transport for bodies it reads itself (the HTTP layer normally pre-reads and pre-parses). */
  readonly maxRequestBytes: number;
}

/** What the HTTP layer already did with the body: `parsedBody` present = parsed JSON (the transport skips reading). */
export interface SessionRequestOptions {
  readonly parsedBody?: unknown;
}

export interface HttpSessionView {
  readonly inFlight: number;
  readonly idleMs: number;
}

/** One POST carrying JSON-RPC requests, in flight until its reply settles or every request in it is cancelled. */
interface Exchange {
  /** JSON-RPC ids (JSON-encoded) still awaiting a reply; empty for an unparsed body. */
  readonly ids: Set<string>;
}

interface Entry {
  readonly server: McpServer;
  readonly transport: WebStandardStreamableHTTPServerTransport;
  lastSeen: number;
  /**
   * POSTs whose reply (JSON body or SSE stream) has not settled; GET streams do not count. A cancelled request ends
   * its exchange too: the SDK sends no reply for it, so its SSE stream stays open until the client goes away.
   */
  readonly exchanges: Set<Exchange>;
  closing: boolean;
}

const messagesOf = (body: unknown): readonly unknown[] => (Array.isArray(body) ? body : [body]);

const isInitialize = (body: unknown): boolean => messagesOf(body).some((message) => isInitializeRequest(message));

const field = (value: unknown, key: string): unknown =>
  typeof value === "object" && value !== null ? Reflect.get(value, key) : undefined;

/** JSON-encoded ids of the JSON-RPC requests (method + id) in a parsed body. */
const requestIds = (body: unknown): readonly string[] =>
  messagesOf(body)
    .filter((m) => typeof field(m, "method") === "string" && field(m, "id") !== undefined && field(m, "id") !== null)
    .map((m) => JSON.stringify(field(m, "id")));

/** JSON-encoded request ids named by `notifications/cancelled` messages in a parsed body. */
const cancelledIds = (body: unknown): readonly string[] =>
  messagesOf(body)
    .filter((m) => field(m, "method") === "notifications/cancelled")
    .map((m) => field(field(m, "params"), "requestId"))
    .filter((id) => id !== undefined && id !== null)
    .map((id) => JSON.stringify(id));

const isEventStream = (response: Response): boolean =>
  (response.headers.get("content-type") ?? "").toLowerCase().startsWith("text/event-stream");

/**
 * The response with `done` called exactly once when its body has been fully read, cancelled (client went away) or
 * failed. For SSE replies this is when the tool call really ends; the SDK returns the Response immediately.
 */
const onBodySettled = (response: Response, done: () => void): Response => {
  if (response.body === null || !isEventStream(response)) {
    done();
    return response;
  }
  const reader = response.body.getReader();
  let settled = false;
  const settle = (): void => {
    if (settled) return;
    settled = true;
    done();
  };
  const body = new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const next = await reader.read();
        if (next.done) {
          settle();
          controller.close();
        } else controller.enqueue(next.value);
      } catch (cause: unknown) {
        settle();
        controller.error(cause);
      }
    },
    async cancel(reason: unknown) {
      settle();
      await reader.cancel(reason).catch(() => undefined);
    },
  });
  return new Response(body, { status: response.status, statusText: response.statusText, headers: response.headers });
};

/**
 * One McpServer + stateful SDK transport per MCP session, all over the one shared application (S1 §6.6, VERIFIED lab
 * probe2: isolated cancellation with the client's reason, DELETE removes the session, unknown session -> 404). The
 * application is never closed by a session: BEA sessions and targets belong to the process, so scripts reconnect.
 *
 * Capacity (D-INT-12, CT-I10): at most MAX_HTTP_MCP_SESSIONS. A new `initialize` at capacity evicts the least recently
 * used session with no request in flight; only when every session is busy is the answer 503. Sessions idle longer than
 * HTTP_SESSION_IDLE_MS are closed by evictIdle() (the HTTP server runs it every minute). Not REA's slot/drain machinery.
 */
export class HttpSessionMap {
  readonly #sessions = new Map<string, Entry>();
  readonly #createServer: () => McpServer;
  readonly #options: HttpSessionMapOptions;
  /** `initialize` requests between the capacity check and session registration (they hold a slot). */
  #opening = 0;
  #closed = false;

  constructor(createServer: () => McpServer, options: HttpSessionMapOptions) {
    this.#createServer = createServer;
    this.#options = options;
  }

  get size(): number {
    return this.#sessions.size;
  }

  /** Diagnostics and tests: in-flight count and idle time per live session, in insertion order. Ids are not exposed. */
  sessions(): readonly HttpSessionView[] {
    const now = this.#options.clock.monoMs();
    return [...this.#sessions.values()].map((e) => ({ inFlight: e.exchanges.size, idleMs: now - e.lastSeen }));
  }

  async handle(request: Request, options: SessionRequestOptions = {}): Promise<Response> {
    if (this.#closed) return jsonRpcErrorResponse(503, -32000, "BEA is shutting down.");
    const sessionId = request.headers.get("mcp-session-id");
    if (sessionId !== null) {
      const entry = this.#sessions.get(sessionId);
      if (entry === undefined || entry.closing)
        return jsonRpcErrorResponse(404, -32001, "Session not found; initialize a new MCP session.");
      return this.#exchange(entry, request, options, () => entry.transport.handleRequest(request, options));
    }
    if (request.method !== "POST") return jsonRpcErrorResponse(400, -32000, "Missing mcp-session-id header.");
    if (!("parsedBody" in options) || !isInitialize(options.parsedBody)) return this.#open(request, options, false);
    if (this.#sessions.size + this.#opening >= MAX_HTTP_MCP_SESSIONS) {
      const victim = this.#leastRecentlyUsedIdle();
      if (victim === undefined)
        return jsonRpcErrorResponse(
          503,
          -32000,
          `All ${String(MAX_HTTP_MCP_SESSIONS)} MCP sessions have a request in flight; retry when one finishes, or DELETE an unused session. This release has no runtime override.`,
        );
      await this.#evict(victim, "capacity");
    }
    return this.#open(request, options, true);
  }

  /** Close sessions idle longer than HTTP_SESSION_IDLE_MS with nothing in flight. Returns how many were closed. */
  async evictIdle(): Promise<number> {
    const now = this.#options.clock.monoMs();
    const idle = [...new Set(this.#sessions.values())].filter(
      (e) => e.exchanges.size === 0 && now - e.lastSeen > HTTP_SESSION_IDLE_MS,
    );
    await Promise.allSettled(idle.map((e) => this.#evict(e, "idle")));
    return idle.length;
  }

  /** Refuse new requests and close every session (their SSE streams end through the SDK transport). */
  async closeAll(): Promise<void> {
    this.#closed = true;
    const all = [...new Set(this.#sessions.values())];
    this.#sessions.clear();
    await Promise.allSettled(all.map((e) => e.server.close()));
  }

  #leastRecentlyUsedIdle(): Entry | undefined {
    let best: Entry | undefined;
    for (const entry of this.#sessions.values())
      if (entry.exchanges.size === 0 && !entry.closing && (best === undefined || entry.lastSeen < best.lastSeen))
        best = entry;
    return best;
  }

  #unregister(entry: Entry): void {
    for (const [id, candidate] of this.#sessions) if (candidate === entry) this.#sessions.delete(id);
  }

  async #evict(entry: Entry, reason: "capacity" | "idle"): Promise<void> {
    entry.closing = true;
    this.#unregister(entry);
    try {
      await entry.server.close();
    } catch (cause: unknown) {
      this.#options.logger.warn("mcp http session close failed", {
        cause: cause instanceof Error ? cause : String(cause),
      });
    }
    this.#options.logger.info("mcp http session evicted", { reason, sessions: this.#sessions.size });
  }

  /**
   * One request on a session: `lastSeen` at start and end. A POST with JSON-RPC requests is in flight until its body
   * settles; a POST with `notifications/cancelled` ends the exchanges of the requests it names.
   */
  async #exchange(
    entry: Entry,
    request: Request,
    options: SessionRequestOptions,
    run: () => Promise<Response>,
  ): Promise<Response> {
    const clock = this.#options.clock;
    entry.lastSeen = clock.monoMs();
    const parsed = "parsedBody" in options;
    if (parsed)
      for (const id of cancelledIds(options.parsedBody))
        for (const exchange of entry.exchanges) {
          exchange.ids.delete(id);
          if (exchange.ids.size === 0) entry.exchanges.delete(exchange);
        }
    const ids = parsed ? requestIds(options.parsedBody) : [];
    if (request.method !== "POST" || (parsed && ids.length === 0))
      try {
        return await run();
      } finally {
        entry.lastSeen = clock.monoMs();
      }
    const exchange: Exchange = { ids: new Set(ids) };
    entry.exchanges.add(exchange);
    const done = (): void => {
      entry.exchanges.delete(exchange);
      entry.lastSeen = clock.monoMs();
    };
    let response: Response;
    try {
      response = await run();
    } catch (cause: unknown) {
      done();
      throw cause;
    }
    return onBodySettled(response, done);
  }

  async #open(request: Request, options: SessionRequestOptions, initialize: boolean): Promise<Response> {
    const server = this.#createServer();
    const { clock, logger } = this.#options;
    const entry: Entry = {
      server,
      transport: new WebStandardStreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        enableJsonResponse: this.#options.jsonResponse,
        maxRequestBodySize: this.#options.maxRequestBytes,
        onsessioninitialized: (id) => {
          if (this.#closed) return;
          this.#sessions.set(id, entry);
          logger.info("mcp http session opened", { sessions: this.#sessions.size });
        },
        onsessionclosed: () => {
          this.#unregister(entry);
          logger.info("mcp http session closed by client", { sessions: this.#sessions.size });
        },
      }),
      lastSeen: clock.monoMs(),
      exchanges: new Set(),
      closing: false,
    };
    const previous = server.server.onclose;
    server.server.onclose = () => {
      previous?.();
      this.#unregister(entry);
    };
    if (initialize) this.#opening += 1;
    let response: Response;
    try {
      await server.connect(entry.transport);
      response = await this.#exchange(entry, request, options, () => entry.transport.handleRequest(request, options));
    } finally {
      if (initialize) this.#opening -= 1;
    }
    // Not an initialize (or refused): the SDK answered 400 itself and no session exists; drop the instance.
    // Shutting down meanwhile: closeAll() never saw this session, so close it here.
    if (entry.transport.sessionId === undefined || this.#closed) {
      this.#unregister(entry);
      await server.close().catch(() => undefined);
    }
    return response;
  }
}
