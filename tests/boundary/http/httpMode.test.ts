import { existsSync } from "node:fs";

import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { afterEach, describe, expect, it } from "vitest";

import { fixtureArtifact, fridaSkip, gccSkip, jobhostSkip, loadFixtures } from "../../support/acceptance/fixtures.js";
import {
  builtHttpUnavailable,
  initializeBody,
  MCP_ACCEPT,
  rpcMessages,
  startHttpServer,
  type HttpServerProcess,
} from "../../support/http/httpServerProcess.js";
import { rawRequest } from "../../support/http/inProcessHttp.js";
import { expectToolSuccess } from "../../support/mcp/parseToolError.js";
import { OwnedPidLedger } from "../../support/process/ownedPidLedger.js";

/**
 * S1 §8 `httpMode.test.ts` (the lab's smoke-http.mjs steps) against a real `bea mcp --http` subprocess: runHttp from
 * the sources with fakeServices() and the WP16 test tools (tests/support/http/serverEntry.ts). 401, bad Host 403,
 * unknown session 404, cancellation reaching the handler, `/shutdown` 202 -> exit 0, connection file removed. The
 * BUILT server (BEA_DIST_DIR) repeats the list on the real stack: with the production services, a real game_sim
 * session, a 65 MiB body (413) and the cancellation of a blocking `wait` on that session.
 */
const BUILD_SKIP = builtHttpUnavailable();
const REAL_SKIP =
  BUILD_SKIP ?? [gccSkip(), fridaSkip(), jobhostSkip()].find((r): r is string => typeof r === "string") ?? null;
const skipNote = (reason: string | null): string => (reason === null ? "" : ` [skipped: ${reason}]`);
const servers: HttpServerProcess[] = [];
afterEach(async () => {
  await Promise.allSettled(servers.splice(0).map((s) => s.stop()));
});

const start = async (args: readonly string[] = []): Promise<HttpServerProcess> => {
  const server = await startHttpServer({ args });
  servers.push(server);
  return server;
};

const connect = async (server: HttpServerProcess) => {
  const client = new Client({ name: "bea-http-mode", version: "1" });
  const transport = new StreamableHTTPClientTransport(new URL(server.connection.url), {
    requestInit: { headers: { authorization: `Bearer ${server.connection.token}` } },
  });
  await client.connect(transport);
  return { client, transport };
};

describe("bea mcp --http subprocess (S1 §8)", () => {
  it("authenticates, routes, cancels and stops via POST /shutdown", async () => {
    const server = await start();
    const { connection, status } = server;
    expect(status).toEqual({ url: connection.url, connection_file: status.connection_file, pid: server.pid });
    expect(connection.pid).toBe(server.pid);
    expect(server.stderr()).not.toContain(connection.token);
    const port = Number(new URL(connection.url).port);

    // 401 without a token, with the challenge header.
    const unauth = await server.fetch({
      auth: false,
      method: "POST",
      headers: { "content-type": "application/json", accept: MCP_ACCEPT },
      body: "{}",
    });
    expect(unauth.status).toBe(401);
    expect(unauth.headers.get("www-authenticate")).toBe('Bearer realm="bea"');

    // 403 for a foreign Host header, even with the token.
    const badHost = await rawRequest({
      port,
      headers: {
        host: "attacker.example",
        authorization: `Bearer ${connection.token}`,
        "content-type": "application/json",
        accept: MCP_ACCEPT,
      },
      body: initializeBody(),
    });
    expect(badHost.status).toBe(403);

    // 404 for an unknown MCP session.
    const unknown = await server.fetch({
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: MCP_ACCEPT,
        "mcp-session-id": "6f1c6c0e-0000-4000-8000-000000000000",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    expect(unknown.status).toBe(404);

    // A real SDK client: catalog, bea_status, cancellation reaching the handler.
    const { client, transport } = await connect(server);
    const names = (await client.listTools()).tools.map((t) => t.name);
    expect(names).toEqual(expect.arrayContaining(["bea_status", "http_test_slow"]));
    const beaStatus = await client.callTool({ name: "bea_status", arguments: {} });
    expect(beaStatus.structuredContent).toMatchObject({ server: { transport: "http", run_id: connection.run_id } });

    const abort = new AbortController();
    const slow = client.callTool(
      { name: "http_test_slow", arguments: { ms: 60_000, label: "subprocess" } },
      { signal: abort.signal },
    );
    const started = async (): Promise<number> =>
      (
        (await client.callTool({ name: "http_test_last_abort", arguments: {} })).structuredContent as {
          readonly started: number;
        }
      ).started;
    await expect.poll(started, { interval: 25, timeout: 10_000 }).toBe(1);
    abort.abort(new Error("user cancelled"));
    await expect(slow).rejects.toThrow();
    await expect
      .poll(async () => (await client.callTool({ name: "http_test_last_abort", arguments: {} })).structuredContent, {
        interval: 25,
        timeout: 10_000,
      })
      .toMatchObject({ label: "subprocess", aborted: true, cause: "client" });
    await client.ping();
    await transport.terminateSession();
    await client.close();

    // Graceful stop: 202 after the body is written, exit 0, connection file removed.
    const shutdown = await server.fetch({ path: "/shutdown", method: "POST" });
    expect(shutdown.status).toBe(202);
    expect(await shutdown.json()).toEqual({ shutting_down: true });
    const exit = await server.exited;
    expect(exit).toEqual({ code: 0, signal: null });
    expect(existsSync(status.connection_file)).toBe(false);
  });

  it("serves single JSON replies with --json-response", async () => {
    const server = await start(["--json-response"]);
    const reply = await server.fetch({
      method: "POST",
      headers: { "content-type": "application/json", accept: MCP_ACCEPT },
      body: initializeBody(),
    });
    expect(reply.status).toBe(200);
    expect(reply.headers.get("content-type")).toMatch(/^application\/json/u);
    const [message] = await rpcMessages(reply);
    expect(message).toMatchObject({ id: 1, result: { serverInfo: { name: expect.any(String) } } });
    expect(await server.stop()).toEqual({ code: 0, signal: null });
  });

  it("exits 1 with a message when the port is already in use", async () => {
    const first = await start();
    const port = new URL(first.connection.url).port;
    await expect(startHttpServer({ args: ["--port", port] })).rejects.toThrow(/cannot listen on 127\.0\.0\.1/u);
  });

  it.skipIf(BUILD_SKIP !== null)(
    `the BUILT server (node <package>/scripts/bea.mjs mcp --http): 401, bea_status, /shutdown -> exit 0${skipNote(BUILD_SKIP)}`,
    async () => {
      const server = await startHttpServer({ mode: "dist" });
      servers.push(server);
      expect(server.connection.pid).toBe(server.pid);
      expect(server.stderr()).not.toContain(server.connection.token);
      const unauth = await server.fetch({ auth: false, method: "POST", body: initializeBody() });
      expect(unauth.status).toBe(401);
      const { client, transport } = await connect(server);
      const beaStatus = await client.callTool({ name: "bea_status", arguments: {} });
      expect(beaStatus.structuredContent).toMatchObject({ server: { transport: "http" } });
      await transport.terminateSession();
      await client.close();
      const shutdown = await server.fetch({ path: "/shutdown", method: "POST" });
      expect(shutdown.status).toBe(202);
      expect(await server.exited).toEqual({ code: 0, signal: null });
      expect(existsSync(server.status.connection_file)).toBe(false);
    },
  );
});

describe("bea mcp --http on the real stack (BUILT server, real Frida session)", () => {
  it.skipIf(REAL_SKIP !== null)(
    `the BUILT server with a real BEA session: 403, 404, 413, a cancelled wait, /shutdown kills the target${skipNote(REAL_SKIP)}`,
    async () => {
      const manifest = await loadFixtures();
      const game = fixtureArtifact(manifest, "game_sim");
      if (game === null) throw new Error(`fixtures unavailable: ${JSON.stringify(manifest)}`);
      const ledger = new OwnedPidLedger(fixtureArtifact(manifest, "pidcheck")?.path ?? null);
      const server = await startHttpServer({ mode: "dist" });
      servers.push(server);
      try {
        const { connection } = server;
        const port = Number(new URL(connection.url).port);
        const authed = { authorization: `Bearer ${connection.token}`, "content-type": "application/json" };
        const badHost = await rawRequest({
          port,
          headers: { ...authed, host: "attacker.example", accept: MCP_ACCEPT },
          body: initializeBody(),
        });
        expect(badHost.status).toBe(403);

        const { client, transport } = await connect(server);
        const spawned = expectToolSuccess(
          await client.callTool({
            name: "spawn_process",
            arguments: { program: game.path, args: ["--no-threads", "--hz", "30"] },
          }),
        );
        const sessionId = spawned["session_id"] as string;
        ledger.recordIdentity(spawned["identity"] as Record<string, unknown>, "game_sim (http)");
        expectToolSuccess(await client.callTool({ name: "resume_process", arguments: { session_id: sessionId } }));

        const unknown = await server.fetch({
          method: "POST",
          headers: { "content-type": "application/json", accept: MCP_ACCEPT, "mcp-session-id": crypto.randomUUID() },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
        });
        expect(unknown.status).toBe(404);

        // 413 on the real stack: the body never reaches the SDK, and the MCP session keeps serving.
        const oversize = await rawRequest({
          port,
          headers: { ...authed, accept: MCP_ACCEPT, "mcp-session-id": transport.sessionId ?? "" },
          body: Buffer.alloc(65 * 1024 * 1024, 0x20),
        });
        expect(oversize.status).toBe(413);

        // A wait that would block up to 60 s on the running target is cancelled by the client: the call settles at
        // once and the same MCP session (and BEA session) keeps working.
        const abort = new AbortController();
        const began = Date.now();
        const blocked = client.callTool(
          { name: "wait", arguments: { session_id: sessionId, until: "exit", timeout_ms: 60_000 } },
          { signal: abort.signal },
        );
        setTimeout(() => abort.abort(new Error("user cancelled")), 500);
        await expect(blocked).rejects.toThrow();
        expect(Date.now() - began).toBeLessThan(10_000);
        const short = expectToolSuccess(
          await client.callTool({ name: "wait", arguments: { session_id: sessionId, until: "exit", timeout_ms: 200 } }),
        );
        expect(short).toMatchObject({ satisfied: false, reason: "timeout", target: { state: "running" } });

        await transport.terminateSession();
        await client.close();
        // The BEA session is still open: POST /shutdown closes it (kills the job tree), exit 0, file removed.
        const shutdown = await server.fetch({ path: "/shutdown", method: "POST" });
        expect(shutdown.status).toBe(202);
        expect(await server.exited).toEqual({ code: 0, signal: null });
        expect(existsSync(server.status.connection_file)).toBe(false);
      } finally {
        await server.stop();
        await ledger.assertClean();
      }
    },
    120_000,
  );
});
