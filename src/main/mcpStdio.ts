import { readFile } from "node:fs/promises";
import { userInfo } from "node:os";

import type { McpServerFactory } from "@modelcontextprotocol/server";
import {
  serveStdio,
  StdioServerTransport,
  type ServeStdioOptions,
  type StdioServerHandle,
} from "@modelcontextprotocol/server/stdio";

import type { BeaCore } from "../application/BeaApplication.js";
import type { BeaServices } from "../application/services/index.js";
import { createApplication } from "../application/createApplication.js";
import type { ToolHandler } from "../application/handlerContext.js";
import { createToolHandlers } from "../application/handlers/index.js";
import type { HandlerLookup } from "../application/invokeTool.js";
import { TOOL_CONTRACTS } from "../contracts/index.js";
import type { ToolContract } from "../contracts/toolContract.js";
import { HARD_LIMITS, loadConfig } from "../domain/config.js";
import { projectBeaError } from "../domain/errors/projection.js";
import { createLogger } from "../domain/logger.js";
import type { HostPlatform } from "../domain/paths.js";
import { createMcpServer } from "../server/createMcpServer.js";
import { Delivery } from "../server/delivery.js";
import { OwnedMcpServers } from "../server/ownedServers.js";
import {
  processExitAfterMs,
  registerProcessShutdown,
  SIGNAL_EXIT_STATUS,
  type ShutdownSignal,
} from "./processShutdown.js";

/** Injection seam for in-process stdio tests (REA RuntimeDependencies). */
export interface StdioRuntimeDeps {
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly serve: (factory: McpServerFactory, options: ServeStdioOptions) => StdioServerHandle;
  readonly registerShutdown: (handler: (signal?: ShutdownSignal) => void) => () => void;
  readonly setExitCode: (code: number) => void;
  /** CT-B3: the stdio transport (production: StdioServerTransport over process stdio with maxBufferSize 64 MiB). */
  readonly transport: () => NonNullable<ServeStdioOptions["transport"]>;
  readonly writeStderr: (text: string) => void;
  readonly services: (core: BeaCore) => Promise<BeaServices>;
  /**
   * Hard exit (production: processExitAfterMs, ref'd and explicit; review fix LIFE-2). `code: null` exits with the exit
   * code set so far (setExitCode), else 1. Armed twice: at the FIRST shutdown trigger with HARD_LIMITS.hardExitAfterMs
   * (D-INT-6; CT-I3: the SDK client SIGTERMs/TerminateProcess after 2 s), and after cleanup with the code (exit once
   * stdout drained, ≤ 500 ms): BEA never relies on a natural exit. Tests pass a no-op.
   */
  readonly forceExitAfterMs: (code: number | null, ms: number) => void;
}

const readOptional = async (path: string): Promise<string | null> => {
  try {
    return await readFile(path, "utf8");
  } catch (cause: unknown) {
    if (typeof cause === "object" && cause !== null && Reflect.get(cause, "code") === "ENOENT") return null;
    throw cause;
  }
};

export const productionStdioDeps = (services: StdioRuntimeDeps["services"]): StdioRuntimeDeps => ({
  env: process.env,
  serve: serveStdio,
  registerShutdown: (handler) => registerProcessShutdown(handler),
  setExitCode: (code) => {
    process.exitCode = code;
  },
  transport: () =>
    new StdioServerTransport(process.stdin, process.stdout, { maxBufferSize: HARD_LIMITS.maxStdioRequestBytes }),
  writeStderr: (text) => void process.stderr.write(text),
  services,
  forceExitAfterMs: processExitAfterMs,
});

/**
 * `bea mcp` (stdio). Shutdown triggers: SIGINT, SIGTERM, stdin end/close, and
 * the close of an instance that served the client. One memoized shutdown:
 * provisional exit code + hard-exit timer at the first trigger (1.9 s) -> kill-first lifecycle (<=1.8 s) ->
 * close stdio handle and instances -> exit code (0 | 1 cleanup failed | 130 | 143).
 */
export const runStdio = async (deps: StdioRuntimeDeps): Promise<void> => {
  const loaded = await loadConfig({
    env: deps.env,
    platform: process.platform as HostPlatform,
    accountHome: userInfo().homedir,
    readConfigFile: readOptional,
  });
  if (!loaded.ok) {
    deps.writeStderr(`bea: ${projectBeaError(loaded.error).message} Run \`bea doctor\` for details.\n`);
    deps.setExitCode(1);
    return;
  }
  const config = loaded.value;
  const logger = createLogger({ level: config.logLevel.value });
  const app = await createApplication({ config, logger, transport: "stdio", services: deps.services });
  const table = createToolHandlers(app) as unknown as Readonly<Record<string, ToolHandler<ToolContract>>>;
  const handlers: HandlerLookup = (name) => table[name];
  const delivery = new Delivery(config.mcpMaxResponseBytes.value);
  const owned = new OwnedMcpServers<ReturnType<typeof createMcpServer>>();

  let shutdown: Promise<void> | undefined;
  let signalStatus: number | undefined;
  let unregister = (): void => undefined;
  let handle: StdioServerHandle | undefined;

  const requestShutdown = (reason: string, signal?: ShutdownSignal): Promise<void> => {
    if (signal !== undefined) signalStatus ??= SIGNAL_EXIT_STATUS[signal];
    shutdown ??= (async () => {
      // CT-I3: provisional code until cleanup proves ok; the timer reads the code current when it fires.
      deps.setExitCode(signalStatus ?? 1);
      deps.forceExitAfterMs(null, HARD_LIMITS.hardExitAfterMs);
      const report = await app.lifecycle.closeAll(reason);
      const closed = await Promise.allSettled([handle?.close() ?? Promise.resolve(), owned.closeAll()]);
      unregister();
      const ok = report.ok && closed.every((r) => r.status === "fulfilled");
      const code = signalStatus ?? (ok ? 0 : 1);
      deps.setExitCode(code);
      deps.forceExitAfterMs(code, 500);
    })();
    return shutdown;
  };
  // Re-entry guard: closing an instance during shutdown must not await shutdown itself.
  const onServedInstanceClosed = (): Promise<unknown> =>
    shutdown !== undefined ? Promise.resolve() : requestShutdown("connection-closed");

  handle = deps.serve(
    () =>
      owned.create(() =>
        createMcpServer({ core: app, handlers, contracts: TOOL_CONTRACTS, delivery, onServedInstanceClosed }),
      ),
    { onerror: (error) => logger.warn("mcp transport error", { cause: error }), transport: deps.transport() },
  );
  unregister = deps.registerShutdown((signal) => {
    void requestShutdown(signal === undefined ? "stdin-closed" : `signal:${signal}`, signal);
  });
};
