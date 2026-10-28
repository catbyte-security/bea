import { existsSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import type { BeaCore } from "../../../src/application/BeaApplication.js";
import { HTTP_HARD_EXIT_AFTER_MS, runHttp, type HttpRuntime, type HttpRuntimeDeps } from "../../../src/main/mcpHttp.js";
import type { ShutdownSignal } from "../../../src/main/processShutdown.js";
import { httpConnectionSchema } from "../../../src/server/http/connectionFile.js";
import { fakeServices } from "../../support/fakes/fakeServices.js";
import { initializeBody, MCP_ACCEPT } from "../../support/http/httpServerProcess.js";
import { rawRequest } from "../../support/http/inProcessHttp.js";
import { createHttpTestState, HTTP_TEST_CONTRACTS, httpTestHandlers } from "../../support/http/testTools.js";
import { createTempHome, type TempHome } from "../../support/workspace/tempHome.js";

/**
 * runHttp in-process (DESIGN §5.9, S1 §6.6): argument and config refusals, the connection file and status line, the
 * graceful stop through POST /shutdown and through a signal (listener -> lifecycle -> file -> exit code), and the
 * startup failures. Exit codes and hard-exit timers are recorded instead of exiting the test process.
 */
interface Harness {
  readonly home: TempHome;
  readonly stderr: () => string;
  readonly exitCodes: number[];
  readonly hardExits: (readonly [number | null, number])[];
  readonly signal: (signal: ShutdownSignal) => void;
  readonly run: (argv: readonly string[], extra?: Partial<HttpRuntimeDeps>) => Promise<HttpRuntime | undefined>;
}

const homes: TempHome[] = [];
const runtimes: HttpRuntime[] = [];
const blockers: Server[] = [];
afterEach(async () => {
  await Promise.allSettled(runtimes.splice(0).map((r) => r.shutdown("test-cleanup")));
  await Promise.allSettled(blockers.splice(0).map((s) => new Promise((resolve) => s.close(resolve))));
  await Promise.allSettled(homes.splice(0).map((h) => h.cleanup()));
});

const harness = async (env: Readonly<Record<string, string>> = {}): Promise<Harness> => {
  const home = await createTempHome("http-run");
  homes.push(home);
  let stderr = "";
  const exitCodes: number[] = [];
  const hardExits: (readonly [number | null, number])[] = [];
  let handler: ((signal?: ShutdownSignal) => void) | undefined;
  return {
    home,
    stderr: () => stderr,
    exitCodes,
    hardExits,
    signal: (signal) => handler?.(signal),
    run: async (argv, extra = {}) => {
      const state = createHttpTestState();
      const runtime = await runHttp(argv, {
        services: fakeServices(),
        extraContracts: HTTP_TEST_CONTRACTS,
        extraHandlers: httpTestHandlers(state),
        env: { ...home.env, BEA_LOG_LEVEL: "silent", ...env },
        writeStderr: (text) => {
          stderr += text;
        },
        setExitCode: (code) => void exitCodes.push(code),
        forceExitAfterMs: (code, ms) => void hardExits.push([code, ms]),
        registerShutdown: (h) => {
          handler = h;
          return () => {
            handler = undefined;
          };
        },
        profileDir: home.root,
        ...extra,
      });
      if (runtime !== undefined) runtimes.push(runtime);
      return runtime;
    },
  };
};

const portOf = (url: string): number => Number(new URL(url).port);

describe("bea mcp --http startup", () => {
  it("publishes the connection file and a token-free status line; the token authenticates", async () => {
    const h = await harness();
    const runtime = await h.run(["--http", "--port", "0"]);
    expect(runtime).toBeDefined();
    if (runtime === undefined) return;
    expect(runtime.connectionFile).toBe(join(h.home.beaHome, "http", "connection.json"));
    const connection = httpConnectionSchema.parse(JSON.parse(await readFile(runtime.connectionFile, "utf8")));
    expect(connection).toMatchObject({
      schema: "bea.http-connection/1",
      url: runtime.url,
      pid: process.pid,
      run_id: runtime.runId,
    });
    expect(connection.url).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/mcp$/u);
    expect(connection.token).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    const lines = h.stderr().trim().split("\n");
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0] ?? "")).toEqual({
      bea_http: { url: runtime.url, connection_file: runtime.connectionFile, pid: process.pid },
    });
    expect(h.stderr()).not.toContain(connection.token);
    const reply = await rawRequest({
      port: portOf(runtime.url),
      headers: { authorization: `Bearer ${connection.token}`, "content-type": "application/json", accept: MCP_ACCEPT },
      body: initializeBody(),
    });
    expect(reply.status).toBe(200);
    expect(h.exitCodes).toEqual([]);
  });

  it("uses BEA_HTTP_TOKEN and --connection-file when given", async () => {
    const token = "t".repeat(40);
    const h = await harness({ BEA_HTTP_TOKEN: token });
    const file = join(h.home.work, "conn", "c.json");
    const runtime = await h.run(["--http", "--connection-file", file, "--json-response"]);
    expect(runtime?.connectionFile).toBe(file);
    const connection = httpConnectionSchema.parse(JSON.parse(await readFile(file, "utf8")));
    expect(connection.token).toBe(token);
    expect(h.stderr()).not.toContain(token);
    const reply = await rawRequest({
      port: portOf(connection.url),
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json", accept: MCP_ACCEPT },
      body: initializeBody(),
    });
    expect(reply.status).toBe(200);
    expect(reply.headers["content-type"]).toMatch(/^application\/json/u);
  });

  it.each([
    [["--http", "--port", "abc"], /--port must be an integer/u],
    [["--http", "--port", "70000"], /--port must be an integer/u],
    [["--http", "--port", ""], /--port must be an integer/u],
    [["--http", "--host", "0.0.0.0"], /Unknown option '--host'/u],
    [["--http", "extra"], /Unexpected argument 'extra'/u],
  ])("refuses %j with exit code 1", async (argv, message) => {
    const h = await harness();
    expect(await h.run(argv)).toBeUndefined();
    expect(h.stderr()).toMatch(message);
    expect(h.exitCodes).toEqual([1]);
    expect(existsSync(join(h.home.beaHome, "http"))).toBe(false);
  });

  it("refuses an invalid configuration (relative BEA_HOME)", async () => {
    const h = await harness({ BEA_HOME: "relative\\bea" });
    expect(await h.run(["--http"])).toBeUndefined();
    expect(h.stderr()).toMatch(/configuration is invalid\. Run `bea doctor`/u);
    expect(h.exitCodes).toEqual([1]);
  });

  it.runIf(process.platform === "win32")(
    "refuses a connection file outside the user profile on Windows (CT-M7)",
    async () => {
      const h = await harness();
      const profile = join(h.home.root, "profile");
      expect(await h.run(["--http"], { profileDir: profile })).toBeUndefined();
      expect(h.stderr()).toMatch(/outside your user profile/u);
      expect(h.exitCodes).toEqual([1]);
      expect(existsSync(join(h.home.beaHome, "http", "connection.json"))).toBe(false);
    },
  );

  it("fails with exit code 1 when the port is taken, closing the application and writing no file", async () => {
    const blocker = createServer();
    blockers.push(blocker);
    await new Promise<void>((resolve) => blocker.listen(0, "127.0.0.1", resolve));
    const port = (blocker.address() as AddressInfo).port;
    const h = await harness();
    expect(await h.run(["--http", "--port", String(port)])).toBeUndefined();
    expect(h.stderr()).toMatch(new RegExp(`cannot listen on 127\\.0\\.0\\.1:${String(port)}`, "u"));
    expect(h.exitCodes.at(-1)).toBe(1);
    expect(h.hardExits.at(-1)).toEqual([1, 500]);
    expect(existsSync(join(h.home.beaHome, "http", "connection.json"))).toBe(false);
  });
});

describe("bea mcp --http shutdown", () => {
  it("POST /shutdown: 202, then listener closed, lifecycle closed, file removed, exit 0", async () => {
    const h = await harness();
    let closedWith: string | undefined;
    const runtime = await h.run(["--http"], {
      services: async (core: BeaCore) => {
        core.lifecycle.register({
          name: "probe",
          phase: "teardown-targets",
          close: async () => {
            closedWith = "teardown";
          },
        });
        return fakeServices()(core);
      },
    });
    if (runtime === undefined) throw new Error("server did not start");
    const connection = httpConnectionSchema.parse(JSON.parse(await readFile(runtime.connectionFile, "utf8")));
    const reply = await rawRequest({
      port: portOf(runtime.url),
      path: "/shutdown",
      headers: { authorization: `Bearer ${connection.token}` },
    });
    expect(reply.status).toBe(202);
    await expect.poll(() => h.exitCodes.at(-1), { interval: 25, timeout: 10_000 }).toBe(0);
    expect(h.exitCodes).toEqual([1, 0]); // provisional 1 at the trigger, 0 once cleanup proved ok
    expect(h.hardExits).toEqual([
      [null, HTTP_HARD_EXIT_AFTER_MS],
      [0, 500],
    ]);
    expect(closedWith).toBe("teardown");
    expect(existsSync(runtime.connectionFile)).toBe(false);
    await expect(rawRequest({ port: portOf(runtime.url), path: "/shutdown" })).rejects.toThrow();
  });

  it("a signal gives 130/143 and the same cleanup", async () => {
    const h = await harness();
    const runtime = await h.run(["--http"]);
    if (runtime === undefined) throw new Error("server did not start");
    h.signal("SIGTERM");
    await runtime.shutdown("again"); // memoized: resolves when the signal's shutdown finished
    expect(h.exitCodes).toEqual([143, 143]);
    expect(existsSync(runtime.connectionFile)).toBe(false);
  });

  it("keeps a connection file that another server replaced (run_id differs)", async () => {
    const h = await harness();
    const runtime = await h.run(["--http"]);
    if (runtime === undefined) throw new Error("server did not start");
    const connection = JSON.parse(await readFile(runtime.connectionFile, "utf8")) as Record<string, unknown>;
    await writeFile(runtime.connectionFile, JSON.stringify({ ...connection, run_id: "someone-else" }));
    await runtime.shutdown("test");
    expect(existsSync(runtime.connectionFile)).toBe(true);
    expect(h.exitCodes.at(-1)).toBe(0);
  });

  it("exits 1 when a lifecycle closer fails", async () => {
    const h = await harness();
    const runtime = await h.run(["--http"], {
      services: async (core: BeaCore) => {
        core.lifecycle.register({
          name: "broken",
          phase: "finalize-evidence",
          close: async () => {
            throw new Error("disk gone");
          },
        });
        return fakeServices()(core);
      },
    });
    if (runtime === undefined) throw new Error("server did not start");
    await runtime.shutdown("test");
    expect(h.exitCodes).toEqual([1, 1]);
    expect(existsSync(runtime.connectionFile)).toBe(false);
  });
});
