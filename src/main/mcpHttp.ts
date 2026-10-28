import { readFile } from "node:fs/promises";
import { userInfo } from "node:os";
import { join } from "node:path";
import { parseArgs } from "node:util";

import type { McpServer } from "@modelcontextprotocol/server";

import type { BeaApplication, BeaCore } from "../application/BeaApplication.js";
import type { BeaServices } from "../application/services/index.js";
import { createApplication } from "../application/createApplication.js";
import type { ToolHandler } from "../application/handlerContext.js";
import { createToolHandlers } from "../application/handlers/index.js";
import type { HandlerLookup } from "../application/invokeTool.js";
import { TOOL_CONTRACTS } from "../contracts/index.js";
import type { ToolContract } from "../contracts/toolContract.js";
import type { Clock } from "../domain/clock.js";
import { HARD_LIMITS, loadConfig } from "../domain/config.js";
import { projectBeaError } from "../domain/errors/projection.js";
import { createLogger } from "../domain/logger.js";
import type { HostPlatform } from "../domain/paths.js";
import { PRODUCT_IDENTITY } from "../identity.js";
import { createMcpServer } from "../server/createMcpServer.js";
import { Delivery } from "../server/delivery.js";
import { newHttpToken } from "../server/http/auth.js";
import {
  checkConnectionLocation,
  HTTP_CONNECTION_SCHEMA,
  removeConnectionFile,
  writeConnectionFile,
  type HttpConnection,
} from "../server/http/connectionFile.js";
import { LOOPBACK, serveHttp, type HttpListener } from "../server/http/serveHttp.js";
import {
  processExitAfterMs,
  registerProcessShutdown,
  SIGNAL_EXIT_STATUS,
  type ShutdownSignal,
} from "./processShutdown.js";

/**
 * Hard-exit safety timer, armed at the first shutdown trigger (the stdio rule, D-INT-6): the lifecycle budget
 * (≤ 2 s) plus the listener's 500 ms forced close plus a margin. Nothing kills an HTTP server for us, so a hung
 * cleanup must not keep the port and the connection file forever.
 */
export const HTTP_HARD_EXIT_AFTER_MS = HARD_LIMITS.shutdownBudgetMs + 1_000;

const USAGE = "Usage: bea mcp --http [--port N] [--json-response] [--connection-file PATH]";

/** Injection seam for in-process tests; production passes only `services` (mcpHttpEntry.ts). */
export interface HttpRuntimeDeps {
  readonly services: (core: BeaCore) => Promise<BeaServices>;
  /** Extra contracts/handlers (tests only). */
  readonly extraContracts?: readonly ToolContract[];
  readonly extraHandlers?: HandlerLookup;
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly writeStderr?: (text: string) => void;
  readonly setExitCode?: (code: number) => void;
  /** Unref'd hard exit; `code: null` exits with the exit code set so far. Tests pass a recorder. */
  readonly forceExitAfterMs?: (code: number | null, ms: number) => void;
  readonly registerShutdown?: (handler: (signal?: ShutdownSignal) => void) => () => void;
  /** The account's profile directory (connection-file location check). Default: os.userInfo().homedir. */
  readonly profileDir?: string;
  readonly clock?: Clock;
}

/** What a started server exposes to in-process tests. Production ignores it. */
export interface HttpRuntime {
  readonly url: string;
  readonly connectionFile: string;
  readonly runId: string;
  /** Resolves when the shutdown that `reason` (or an earlier trigger) started has finished. */
  readonly shutdown: (reason: string) => Promise<void>;
}

const readOptional = async (path: string): Promise<string | null> => {
  try {
    return await readFile(path, "utf8");
  } catch (cause: unknown) {
    if (typeof cause === "object" && cause !== null && Reflect.get(cause, "code") === "ENOENT") return null;
    throw cause;
  }
};

const messageOf = (cause: unknown): string => (cause instanceof Error ? cause.message : String(cause));

interface HttpArgs {
  readonly port: number;
  readonly jsonResponse: boolean;
  readonly connectionFile: string | undefined;
}

/** `argv` is everything after `mcp` (it includes `--http`). Returns the refusal text on bad arguments. */
export const parseHttpArgs = (argv: readonly string[]): HttpArgs | string => {
  try {
    const { values } = parseArgs({
      args: [...argv],
      options: {
        http: { type: "boolean" },
        port: { type: "string", default: "0" },
        "json-response": { type: "boolean", default: false },
        "connection-file": { type: "string" },
      },
      strict: true,
      allowPositionals: false,
    });
    const port = /^\d{1,5}$/u.test(values.port) ? Number(values.port) : -1;
    if (port < 0 || port > 65_535) return "--port must be an integer from 0 to 65535.";
    return { port, jsonResponse: values["json-response"], connectionFile: values["connection-file"] };
  } catch (cause: unknown) {
    return `${messageOf(cause)}\n${USAGE}`;
  }
};

/** One McpServer view per MCP session. No onServedInstanceClosed: closing an MCP session never closes the application. */
const mcpServerFactory = (app: BeaApplication, deps: HttpRuntimeDeps): (() => McpServer) => {
  const table = createToolHandlers(app) as unknown as Readonly<Record<string, ToolHandler<ToolContract>>>;
  const handlers: HandlerLookup = (name) => table[name] ?? deps.extraHandlers?.(name);
  const contracts = [...TOOL_CONTRACTS, ...(deps.extraContracts ?? [])];
  const delivery = new Delivery(app.config.mcpMaxResponseBytes.value);
  return () => createMcpServer({ core: app, handlers, contracts, delivery });
};

const connectionOf = (url: string, token: string, app: BeaApplication): HttpConnection => ({
  schema: HTTP_CONNECTION_SCHEMA,
  url,
  token,
  pid: process.pid,
  run_id: app.run.runId,
  started_at: app.run.startedAt,
  version: PRODUCT_IDENTITY.packageVersion,
});

/**
 * `bea mcp --http [--port N] [--json-response] [--connection-file PATH]` (S1 §6.6, DESIGN §5.9). 127.0.0.1 only;
 * bearer token; the process (not an MCP session) owns the application, so BEA sessions survive reconnects. Graceful
 * stop: SIGINT/SIGTERM (console Ctrl+C) or authenticated POST /shutdown: close the listener -> lifecycle.closeAll ->
 * remove the connection file if it is still ours -> exit 0 (1 when cleanup failed, 130/143 on a signal). A Windows
 * TerminateProcess skips all of this; owned targets still die through their jobhost (kernel job), the file goes stale.
 * Returns undefined when startup failed (exit code 1, message on stderr).
 */
export const runHttp = async (argv: readonly string[], deps: HttpRuntimeDeps): Promise<HttpRuntime | undefined> => {
  const writeStderr = deps.writeStderr ?? ((text: string) => void process.stderr.write(text));
  const setExitCode =
    deps.setExitCode ??
    ((code: number) => {
      process.exitCode = code;
    });
  const forceExitAfterMs = deps.forceExitAfterMs ?? processExitAfterMs;
  const fail = (message: string): undefined => {
    writeStderr(`bea mcp --http: ${message}\n`);
    setExitCode(1);
    return undefined;
  };

  const args = parseHttpArgs(argv);
  if (typeof args === "string") return fail(args);
  const platform = process.platform as HostPlatform;
  const loaded = await loadConfig({
    env: deps.env ?? process.env,
    platform,
    accountHome: userInfo().homedir,
    readConfigFile: readOptional,
  });
  if (!loaded.ok) return fail(`${projectBeaError(loaded.error).message} Run \`bea doctor\` for details.`);
  const config = loaded.value;
  const connectionFile = args.connectionFile ?? join(config.layout.httpDir, "connection.json");
  const location = checkConnectionLocation(connectionFile, platform, deps.profileDir ?? userInfo().homedir);
  if (!location.ok) return fail(location.message);

  const logger = createLogger({ level: config.logLevel.value });
  const app = await createApplication({
    config,
    logger,
    transport: "http",
    services: deps.services,
    ...(deps.clock === undefined ? {} : { clock: deps.clock }),
  });
  const createServer = mcpServerFactory(app, deps);
  const token = config.httpToken.value ?? newHttpToken();

  // Everything the shutdown closure touches exists before the listener accepts requests.
  let listener: HttpListener | undefined;
  let published = false;
  let unregister = (): void => undefined;
  let shutdown: Promise<void> | undefined;
  let signalStatus: number | undefined;
  let startupFailed = false;
  const requestShutdown = (reason: string, signal?: ShutdownSignal): Promise<void> => {
    if (signal !== undefined) signalStatus ??= SIGNAL_EXIT_STATUS[signal];
    shutdown ??= (async () => {
      // Provisional code until cleanup proves ok; the hard-exit timer reads the code current when it fires.
      setExitCode(signalStatus ?? 1);
      forceExitAfterMs(null, HTTP_HARD_EXIT_AFTER_MS);
      const closed = await Promise.allSettled([listener?.close() ?? Promise.resolve()]);
      const report = await app.lifecycle.closeAll(reason);
      if (published) await removeConnectionFile(connectionFile, app.run.runId).catch(() => false);
      unregister();
      const ok = report.ok && closed.every((r) => r.status === "fulfilled");
      const code = signalStatus ?? (ok && !startupFailed ? 0 : 1);
      if (!ok) logger.error("http shutdown incomplete", { reason, lifecycle_ok: report.ok });
      setExitCode(code);
      forceExitAfterMs(code, 500);
    })();
    return shutdown;
  };
  unregister = (deps.registerShutdown ?? ((h) => registerProcessShutdown(h, { signals: process })))((signal) => {
    // HTTP does not own stdin: only signals trigger shutdown here.
    if (signal !== undefined) void requestShutdown(`signal:${signal}`, signal);
  });

  const abortStartup = async (message: string): Promise<undefined> => {
    startupFailed = true;
    await requestShutdown("http-startup-failed");
    return fail(message);
  };
  try {
    listener = await serveHttp({
      port: args.port,
      token,
      jsonResponse: args.jsonResponse,
      createServer,
      clock: app.clock,
      logger,
      onShutdownRequest: () => void requestShutdown("http-shutdown"),
    });
  } catch (cause: unknown) {
    return abortStartup(`cannot listen on ${LOOPBACK}:${String(args.port)}: ${messageOf(cause)}`);
  }
  try {
    await writeConnectionFile(connectionFile, connectionOf(listener.url, token, app));
    published = true;
  } catch (cause: unknown) {
    return abortStartup(`cannot write the connection file ${connectionFile}: ${messageOf(cause)}`);
  }
  // Status line, independent of log level. The token is never printed.
  writeStderr(
    `${JSON.stringify({ bea_http: { url: listener.url, connection_file: connectionFile, pid: process.pid } })}\n`,
  );
  return {
    url: listener.url,
    connectionFile,
    runId: app.run.runId,
    shutdown: (reason) => requestShutdown(reason),
  };
};
