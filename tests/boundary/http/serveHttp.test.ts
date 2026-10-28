import { afterEach, describe, expect, it } from "vitest";

import { manualClock } from "../../../src/domain/clock.js";
import { HTTP_SESSION_IDLE_MS, MAX_HTTP_MCP_SESSIONS } from "../../../src/server/http/sessionMap.js";
import { MAX_HTTP_REQUEST_BYTES } from "../../../src/server/http/requestBody.js";
import { createGate } from "../../support/frida/gate.js";
import { initializeBody, MCP_ACCEPT } from "../../support/http/httpServerProcess.js";
import { rawRequest, startInProcessHttp, type InProcessHttp } from "../../support/http/inProcessHttp.js";

/**
 * serveHttp in-process over real node:http (DESIGN §5.9, S1 §6.6, D-INT-12, CT-B3, CT-I10): the per-request order
 * Host -> Origin -> path -> bearer -> body limit, the session map's capacity rules and idle eviction (manual clock).
 */
const MiB = 1024 * 1024;
let server: InProcessHttp | undefined;
afterEach(async () => {
  await server?.close();
  server = undefined;
});

const start = async (options: Parameters<typeof startInProcessHttp>[0] = {}): Promise<InProcessHttp> =>
  (server = await startInProcessHttp(options));

const authed = (http: InProcessHttp, extra: Readonly<Record<string, string>> = {}): Record<string, string> => ({
  authorization: `Bearer ${http.token}`,
  "content-type": "application/json",
  accept: MCP_ACCEPT,
  ...extra,
});

const errorMessage = (body: string): string =>
  (JSON.parse(body) as { readonly error: { readonly message: string } }).error.message;

describe("request checks before any body byte is read", () => {
  it("answers 401 with WWW-Authenticate for a missing or wrong bearer token", async () => {
    const http = await start();
    const missing = await rawRequest({ port: http.listener.port, body: initializeBody() });
    expect(missing.status).toBe(401);
    expect(missing.headers["www-authenticate"]).toBe('Bearer realm="bea"');
    const wrong = await rawRequest({
      port: http.listener.port,
      headers: { authorization: `Bearer ${"x".repeat(43)}`, "content-type": "application/json" },
      body: initializeBody(),
    });
    expect(wrong.status).toBe(401);
    const malformed = await rawRequest({
      port: http.listener.port,
      headers: { authorization: http.token },
      body: initializeBody(),
    });
    expect(malformed.status).toBe(401);
    expect(http.listener.sessions.size).toBe(0);
  });

  it("refuses a foreign Host (403) and a foreign Origin (403) even with a valid token, Host first", async () => {
    const http = await start();
    const host = await rawRequest({
      port: http.listener.port,
      headers: { ...authed(http), host: `evil.example:${String(http.listener.port)}` },
      body: initializeBody(),
    });
    expect(host.status).toBe(403);
    const hostNoToken = await rawRequest({ port: http.listener.port, headers: { host: "evil.example" } });
    expect(hostNoToken.status).toBe(403);
    const origin = await rawRequest({
      port: http.listener.port,
      headers: authed(http, { origin: "http://evil.example" }),
      body: initializeBody(),
    });
    expect(origin.status).toBe(403);
    // A loopback Origin passes; then the token decides.
    const localOrigin = await rawRequest({
      port: http.listener.port,
      headers: { origin: `http://localhost:${String(http.listener.port)}` },
      body: initializeBody(),
    });
    expect(localOrigin.status).toBe(401);
    expect(http.listener.sessions.size).toBe(0);
  });

  it("serves only /mcp and /shutdown (404 before the token check), refuses rewritten targets", async () => {
    const http = await start();
    expect((await rawRequest({ port: http.listener.port, path: "/other", method: "GET" })).status).toBe(404);
    expect((await rawRequest({ port: http.listener.port, path: "/mcp/../mcp", method: "GET" })).status).toBe(400);
    const getShutdown = await rawRequest({
      port: http.listener.port,
      path: "/shutdown",
      method: "GET",
      headers: authed(http),
    });
    expect(getShutdown.status).toBe(405);
    expect(http.shutdownRequests()).toBe(0);
  });

  it("answers 404 for an unknown session id and 400 for a session-less GET", async () => {
    const http = await start();
    const unknown = await rawRequest({
      port: http.listener.port,
      headers: authed(http, { "mcp-session-id": "00000000-0000-4000-8000-000000000000" }),
      body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
    });
    expect(unknown.status).toBe(404);
    expect(errorMessage(unknown.body)).toMatch(/Session not found/u);
    const get = await rawRequest({ port: http.listener.port, method: "GET", headers: authed(http) });
    expect(get.status).toBe(400);
  });

  it("answers an authenticated POST /shutdown with 202 and requests shutdown only after the reply", async () => {
    const http = await start();
    const reply = await rawRequest({ port: http.listener.port, path: "/shutdown", headers: authed(http) });
    expect(reply.status).toBe(202);
    expect(JSON.parse(reply.body)).toEqual({ shutting_down: true });
    await expect.poll(() => http.shutdownRequests(), { interval: 25 }).toBe(1);
    const unauthenticated = await rawRequest({ port: http.listener.port, path: "/shutdown" });
    expect(unauthenticated.status).toBe(401);
    expect(http.shutdownRequests()).toBe(1);
  });
});

describe("64 MiB body limit (CT-B3): 413 before parsing", () => {
  const big = (bytes: number): Buffer => Buffer.alloc(bytes, 0x20);

  it("refuses a 65 MiB body with Content-Length, then keeps serving", async () => {
    const http = await start();
    expect(MAX_HTTP_REQUEST_BYTES).toBe(64 * MiB);
    const reply = await rawRequest({ port: http.listener.port, headers: authed(http), body: big(65 * MiB) });
    expect(reply.status).toBe(413);
    expect(errorMessage(reply.body)).toMatch(/exceeds 67108864 bytes/u);
    const { client } = await http.client();
    const status = await client.callTool({ name: "bea_status", arguments: {} });
    expect(status.isError).toBeFalsy();
  });

  it("refuses a streamed (chunked) body as soon as it crosses 64 MiB", async () => {
    const http = await start();
    const chunk = big(MiB);
    let sent = 0;
    const reply = await rawRequest({
      port: http.listener.port,
      headers: authed(http),
      body: function* () {
        for (let i = 0; i < 65; i += 1) {
          sent += chunk.byteLength;
          yield chunk;
        }
      },
    });
    expect(reply.status).toBe(413);
    expect(sent).toBe(65 * MiB);
    expect(http.listener.sessions.size).toBe(0);
  });

  it("checks the token before the size: a 65 MiB unauthenticated body gets 401", async () => {
    const http = await start();
    const reply = await rawRequest({
      port: http.listener.port,
      headers: { "content-type": "application/json" },
      body: big(65 * MiB),
    });
    expect(reply.status).toBe(401);
  });

  it("accepts a body of exactly the limit and refuses one byte more", async () => {
    const http = await start({ maxRequestBytes: 4096 });
    const exact = initializeBody().padEnd(4096, " ");
    const atLimit = await rawRequest({ port: http.listener.port, headers: authed(http), body: exact });
    expect(atLimit.status).toBe(200);
    expect(atLimit.headers["mcp-session-id"]).toBeTypeOf("string");
    const over = await rawRequest({ port: http.listener.port, headers: authed(http), body: `${exact} ` });
    expect(over.status).toBe(413);
  });

  it("lets the transport answer non-JSON bodies itself (400 parse error)", async () => {
    const http = await start();
    const reply = await rawRequest({ port: http.listener.port, headers: authed(http), body: "{not json" });
    expect(reply.status).toBe(400);
    expect(errorMessage(reply.body)).toMatch(/Parse error/u);
  });
});

describe("MCP sessions over one process-owned application", () => {
  it("serves the catalog and bea_status over HTTP; a second initialize opens a second session", async () => {
    const http = await start();
    const { client } = await http.client("one");
    const tools = await client.listTools();
    expect(tools.tools.map((t) => t.name)).toContain("bea_status");
    const status = await client.callTool({ name: "bea_status", arguments: {} });
    expect(status.structuredContent).toMatchObject({ server: { transport: "http", run_id: http.app.run.runId } });
    await http.client("two");
    expect(http.listener.sessions.size).toBe(2);
  });

  it("closes a session on DELETE; its id then gets 404; BEA state survives the reconnect", async () => {
    const http = await start();
    const first = await http.client("first");
    const opened = await first.client.callTool({ name: "http_test_open_session", arguments: {} });
    const fakeSessionId = (opened.structuredContent as { readonly fake_session_id: string }).fake_session_id;
    const oldId = first.transport.sessionId ?? "";
    await first.transport.terminateSession();
    expect(http.listener.sessions.size).toBe(0);
    const stale = await rawRequest({
      port: http.listener.port,
      headers: authed(http, { "mcp-session-id": oldId }),
      body: JSON.stringify({ jsonrpc: "2.0", id: 9, method: "tools/list" }),
    });
    expect(stale.status).toBe(404);
    const second = await http.client("second");
    const found = await second.client.callTool({
      name: "http_test_get_session",
      arguments: { fake_session_id: fakeSessionId },
    });
    expect(found.structuredContent).toMatchObject({ exists: true, open_sessions: 1 });
    expect(http.app.lifecycle.closing).toBe(false);
  });

  it("delivers a client cancellation to the handler's signal and keeps the session usable", async () => {
    const http = await start();
    const { client } = await http.client();
    const abort = new AbortController();
    const pending = client.callTool(
      { name: "http_test_slow", arguments: { ms: 60_000, label: "cancel-me" } },
      { signal: abort.signal },
    );
    await expect.poll(() => http.state.started, { interval: 25 }).toBe(1);
    abort.abort(new Error("user cancelled"));
    await expect(pending).rejects.toThrow();
    await expect
      .poll(() => http.state.lastAbort, { interval: 25 })
      .toEqual({
        label: "cancel-me",
        aborted: true,
        cause: { kind: "client" },
      });
    await client.ping();
    expect(http.listener.sessions.sessions()).toEqual([expect.objectContaining({ inFlight: 0 })]);
  });

  it("at capacity, a new initialize evicts the least recently used idle session (no 503)", async () => {
    const http = await start();
    const clients = [];
    for (let i = 0; i < MAX_HTTP_MCP_SESSIONS; i += 1) clients.push(await http.client(`c${String(i)}`));
    // c0 is the least recently used once c1..c3 have each made a call.
    for (const { client } of clients.slice(1)) await client.callTool({ name: "bea_status", arguments: {} });
    const fifth = await http.client("c4");
    expect(http.listener.sessions.size).toBe(MAX_HTTP_MCP_SESSIONS);
    await expect(clients[0]?.client.callTool({ name: "bea_status", arguments: {} })).rejects.toThrow();
    for (const { client } of [...clients.slice(1), fifth]) {
      const status = await client.callTool({ name: "bea_status", arguments: {} });
      expect(status.isError).toBeFalsy();
    }
  });

  for (const jsonResponse of [false, true])
    it(`answers 503 only when all ${String(MAX_HTTP_MCP_SESSIONS)} sessions have a call in flight (${jsonResponse ? "JSON" : "SSE"} replies)`, async () => {
      const http = await start({ jsonResponse });
      const gate = createGate();
      http.state.gates.set("busy", gate);
      const clients = [];
      for (let i = 0; i < MAX_HTTP_MCP_SESSIONS; i += 1) clients.push(await http.client(`busy${String(i)}`));
      const calls = clients.map(({ client }) =>
        client.callTool({ name: "http_test_slow", arguments: { gate: "busy" } }),
      );
      await expect.poll(() => gate.waiters(), { interval: 25 }).toBe(MAX_HTTP_MCP_SESSIONS);
      expect(http.listener.sessions.sessions().map((s) => s.inFlight)).toEqual([1, 1, 1, 1]);
      const refused = await rawRequest({ port: http.listener.port, headers: authed(http), body: initializeBody() });
      expect(refused.status).toBe(503);
      expect(errorMessage(refused.body)).toMatch(/in flight/u);
      gate.release();
      for (const result of await Promise.all(calls)) expect(result.isError).toBeFalsy();
      await expect
        .poll(() => http.listener.sessions.sessions().every((s) => s.inFlight === 0), { interval: 25 })
        .toBe(true);
      const admitted = await rawRequest({ port: http.listener.port, headers: authed(http), body: initializeBody() });
      expect(admitted.status).toBe(200);
      expect(http.listener.sessions.size).toBe(MAX_HTTP_MCP_SESSIONS);
    });

  it("a session-less non-initialize POST at capacity evicts nobody", async () => {
    const http = await start();
    for (let i = 0; i < MAX_HTTP_MCP_SESSIONS; i += 1) await http.client(`k${String(i)}`);
    const reply = await rawRequest({
      port: http.listener.port,
      headers: authed(http),
      body: JSON.stringify({ jsonrpc: "2.0", id: 3, method: "tools/list" }),
    });
    expect(reply.status).toBe(400);
    expect(http.listener.sessions.size).toBe(MAX_HTTP_MCP_SESSIONS);
  });
});

describe("idle eviction after 5 minutes (manual clock)", () => {
  it("closes sessions idle longer than 5 min, keeps recently used and busy ones", async () => {
    const clock = manualClock();
    const http = await start({ clock });
    const gate = createGate();
    http.state.gates.set("hold", gate);
    const idle = await http.client("idle");
    const active = await http.client("active");
    const busy = await http.client("busy");
    const busyCall = busy.client.callTool({ name: "http_test_slow", arguments: { gate: "hold" } });
    await gate.entered;

    clock.advanceMs(HTTP_SESSION_IDLE_MS - 60_000);
    expect(await http.listener.sessions.evictIdle()).toBe(0);
    await active.client.callTool({ name: "bea_status", arguments: {} });
    clock.advanceMs(60_001);
    expect(await http.listener.sessions.evictIdle()).toBe(1);
    expect(http.listener.sessions.size).toBe(2);
    await expect(idle.client.callTool({ name: "bea_status", arguments: {} })).rejects.toThrow();
    expect((await active.client.callTool({ name: "bea_status", arguments: {} })).isError).toBeFalsy();

    // The busy session is never idle-evicted while its call is in flight, however long it runs.
    clock.advanceMs(10 * HTTP_SESSION_IDLE_MS);
    await active.client.callTool({ name: "bea_status", arguments: {} });
    expect(await http.listener.sessions.evictIdle()).toBe(0);
    gate.release();
    expect((await busyCall).isError).toBeFalsy();
    clock.advanceMs(HTTP_SESSION_IDLE_MS + 1);
    expect(await http.listener.sessions.evictIdle()).toBe(2);
    expect(http.listener.sessions.size).toBe(0);
    expect(http.app.lifecycle.closing).toBe(false);
  });
});
