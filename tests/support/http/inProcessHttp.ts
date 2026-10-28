import { request as httpRequest, type IncomingHttpHeaders } from "node:http";

import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";

import type { BeaApplication } from "../../../src/application/BeaApplication.js";
import { createApplication } from "../../../src/application/createApplication.js";
import type { ToolHandler } from "../../../src/application/handlerContext.js";
import { createToolHandlers } from "../../../src/application/handlers/index.js";
import type { HandlerLookup } from "../../../src/application/invokeTool.js";
import { TOOL_CONTRACTS } from "../../../src/contracts/index.js";
import type { ToolContract } from "../../../src/contracts/toolContract.js";
import type { Clock } from "../../../src/domain/clock.js";
import { HARD_LIMITS, loadConfig } from "../../../src/domain/config.js";
import { silentLogger, type Logger } from "../../../src/domain/logger.js";
import type { HostPlatform } from "../../../src/domain/paths.js";
import { createMcpServer } from "../../../src/server/createMcpServer.js";
import { Delivery } from "../../../src/server/delivery.js";
import { newHttpToken } from "../../../src/server/http/auth.js";
import { serveHttp, type HttpListener } from "../../../src/server/http/serveHttp.js";
import { fakeServices } from "../fakes/fakeServices.js";
import { createTempHome, type TempHome } from "../workspace/tempHome.js";
import { createHttpTestState, HTTP_TEST_CONTRACTS, httpTestHandlers, type HttpTestState } from "./testTools.js";

/**
 * serveHttp in-process over real node:http on 127.0.0.1:0: the production per-request pipeline and session map,
 * with fakeServices(), the WP16 test tools and an injectable clock (idle eviction with a manual clock).
 */
export interface InProcessHttpOptions {
  readonly clock?: Clock;
  readonly jsonResponse?: boolean;
  readonly maxRequestBytes?: number;
  readonly logger?: Logger;
}

export interface InProcessHttp {
  readonly listener: HttpListener;
  readonly token: string;
  readonly app: BeaApplication;
  readonly state: HttpTestState;
  readonly home: TempHome;
  readonly shutdownRequests: () => number;
  /** A connected SDK client (StreamableHTTPClientTransport with the bearer token). */
  readonly client: (
    name?: string,
  ) => Promise<{ readonly client: Client; readonly transport: StreamableHTTPClientTransport }>;
  readonly close: () => Promise<void>;
}

export const startInProcessHttp = async (options: InProcessHttpOptions = {}): Promise<InProcessHttp> => {
  const home = await createTempHome("http-inproc");
  const loaded = await loadConfig({
    env: { BEA_HOME: home.beaHome },
    platform: process.platform as HostPlatform,
    accountHome: home.home,
    readConfigFile: async () => null,
  });
  if (!loaded.ok) throw new Error(`config: ${JSON.stringify(loaded.error)}`);
  const app = await createApplication({
    config: loaded.value,
    logger: options.logger ?? silentLogger,
    transport: "http",
    services: fakeServices(),
    ...(options.clock === undefined ? {} : { clock: options.clock }),
  });
  const state = createHttpTestState();
  const table = createToolHandlers(app) as unknown as Readonly<Record<string, ToolHandler<ToolContract>>>;
  const extra = httpTestHandlers(state);
  const handlers: HandlerLookup = (name) => table[name] ?? extra(name);
  const contracts = [...TOOL_CONTRACTS, ...HTTP_TEST_CONTRACTS];
  const delivery = new Delivery(HARD_LIMITS.defaultResponseBytes);
  const token = newHttpToken();
  let shutdowns = 0;
  const listener = await serveHttp({
    port: 0,
    token,
    jsonResponse: options.jsonResponse ?? false,
    createServer: () => createMcpServer({ core: app, handlers, contracts, delivery }),
    clock: app.clock,
    logger: options.logger ?? silentLogger,
    onShutdownRequest: () => {
      shutdowns += 1;
    },
    ...(options.maxRequestBytes === undefined ? {} : { maxRequestBytes: options.maxRequestBytes }),
  });
  const clients: { readonly client: Client }[] = [];
  return {
    listener,
    token,
    app,
    state,
    home,
    shutdownRequests: () => shutdowns,
    client: async (name = "bea-http-test") => {
      const client = new Client({ name, version: "1" });
      const transport = new StreamableHTTPClientTransport(new URL(listener.url), {
        requestInit: { headers: { authorization: `Bearer ${token}` } },
      });
      await client.connect(transport);
      clients.push({ client });
      return { client, transport };
    },
    close: async () => {
      await Promise.allSettled(clients.map(({ client }) => client.close()));
      await listener.close();
      await app.lifecycle.closeAll("test-closed");
      await home.cleanup();
    },
  };
};

export interface RawResponse {
  readonly status: number;
  readonly headers: IncomingHttpHeaders;
  readonly body: string;
}

/**
 * One request over node:http with full control of the Host header and the body (string, Buffer, or a chunk
 * generator for a streamed body without Content-Length). Resolves with the reply; rejects on socket errors.
 */
export const rawRequest = (options: {
  readonly port: number;
  readonly method?: string;
  readonly path?: string;
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: string | Buffer | (() => Iterable<Buffer>);
}): Promise<RawResponse> =>
  new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        host: "127.0.0.1",
        port: options.port,
        method: options.method ?? "POST",
        path: options.path ?? "/mcp",
        headers: options.headers ?? {},
        agent: false,
      },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (text: string) => (body += text));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
        res.on("error", reject);
      },
    );
    req.on("error", reject);
    const body = options.body;
    if (body === undefined) req.end();
    else if (typeof body === "function") {
      const chunks = body()[Symbol.iterator]();
      const pump = (): void => {
        for (let next = chunks.next(); !next.done; next = chunks.next())
          if (!req.write(next.value)) {
            req.once("drain", pump);
            return;
          }
        req.end();
      };
      pump();
    } else req.end(body);
  });
