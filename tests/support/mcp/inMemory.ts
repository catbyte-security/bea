import { Client } from "@modelcontextprotocol/client";
import { InMemoryTransport, type McpServer } from "@modelcontextprotocol/server";
import { test as base } from "vitest";

import type { BeaApplication, BeaCore } from "../../../src/application/BeaApplication.js";
import { createApplication } from "../../../src/application/createApplication.js";
import type { ToolHandler } from "../../../src/application/handlerContext.js";
import { createToolHandlers } from "../../../src/application/handlers/index.js";
import type { BeaServices } from "../../../src/application/services/index.js";
import { TOOL_CONTRACTS } from "../../../src/contracts/index.js";
import type { ToolContract } from "../../../src/contracts/toolContract.js";
import type { IdSource } from "../../../src/domain/canonical.js";
import type { Clock } from "../../../src/domain/clock.js";
import { HARD_LIMITS, loadConfig } from "../../../src/domain/config.js";
import { silentLogger, type Logger } from "../../../src/domain/logger.js";
import type { HostPlatform } from "../../../src/domain/paths.js";
import { createMcpServer } from "../../../src/server/createMcpServer.js";
import { Delivery } from "../../../src/server/delivery.js";
import { fakeServices } from "../fakes/fakeServices.js";
import { createTempHome, type TempHome } from "../workspace/tempHome.js";

const DEFAULT_CLIENT = { name: "bea-test", version: "1" } as const;

/** REA mcpFixture (rea-testing §4.1): linked in-memory transports, closed in reverse order, failures surfaced. */
export interface TestMcp {
  readonly connect: (
    server: McpServer,
    identity?: { readonly name: string; readonly version: string },
  ) => Promise<Client>;
  readonly close: () => Promise<void>;
}

export const createTestMcp = (): TestMcp => {
  const connections: { readonly client: Client; readonly server: McpServer }[] = [];
  return {
    connect: async (server, identity = DEFAULT_CLIENT) => {
      const client = new Client({ ...identity });
      const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
      try {
        await server.connect(serverTransport);
        await client.connect(clientTransport);
      } catch (cause) {
        await Promise.allSettled([client.close(), server.close()]);
        throw cause;
      }
      connections.push({ client, server });
      return client;
    },
    close: async () => {
      const results = await Promise.allSettled(
        [...connections].reverse().map(async ({ client, server }) => {
          try {
            await client.close();
          } finally {
            await server.close();
          }
        }),
      );
      connections.length = 0;
      const failure = results.find((r): r is PromiseRejectedResult => r.status === "rejected");
      if (failure !== undefined) throw failure.reason;
    },
  };
};

/** `mcpTest("…", async ({ mcp }) => …)`: a TestMcp closed after the test. */
export const mcpTest = base.extend<{ mcp: TestMcp }>({
  // oxlint-disable-next-line no-empty-pattern -- vitest fixtures require an object pattern
  mcp: async ({}, use) => {
    const mcp = createTestMcp();
    try {
      await use(mcp);
    } finally {
      await mcp.close();
    }
  },
});

export interface InMemoryBeaOptions {
  /** Service slots to override over fakeServices(), or a complete services factory. */
  readonly services?: Partial<BeaServices> | ((core: BeaCore) => Promise<BeaServices>);
  /** Extra environment for loadConfig (gates: BEA_ALLOW_WRITE_MEMORY=1, quotas, …). BEA_HOME is a temp dir. */
  readonly env?: Readonly<Record<string, string>>;
  readonly clock?: Clock;
  readonly ids?: IdSource;
  readonly logger?: Logger;
  readonly transport?: "stdio" | "http";
  readonly maxResponseBytes?: number;
  readonly client?: { readonly name: string; readonly version: string };
}

export interface InMemoryBea {
  readonly client: Client;
  readonly app: BeaApplication;
  readonly server: McpServer;
  readonly home: TempHome;
  /** Closes client and server (which runs the application lifecycle) and removes the temp home. Idempotent. */
  readonly close: () => Promise<void>;
}

/**
 * The production MCP server (createMcpServer + invokeTool + Delivery) over an in-memory transport, backed by
 * fakeServices() plus the given overrides and a fresh temp BEA_HOME. The fast-lane harness for every area.
 */
export const connectInMemoryBea = async (options: InMemoryBeaOptions = {}): Promise<InMemoryBea> => {
  const home = await createTempHome("mcp");
  const loaded = await loadConfig({
    env: { BEA_HOME: home.beaHome, ...options.env },
    platform: process.platform as HostPlatform,
    accountHome: home.home,
    readConfigFile: async () => null,
  });
  if (!loaded.ok) {
    await home.cleanup();
    throw new Error(`connectInMemoryBea: configuration failed: ${JSON.stringify(loaded.error)}`);
  }
  const services = typeof options.services === "function" ? options.services : fakeServices(options.services ?? {});
  const app = await createApplication({
    config: loaded.value,
    logger: options.logger ?? silentLogger,
    transport: options.transport ?? "stdio",
    services,
    ...(options.clock === undefined ? {} : { clock: options.clock }),
    ...(options.ids === undefined ? {} : { ids: options.ids }),
  });
  const table = createToolHandlers(app) as unknown as Readonly<Record<string, ToolHandler<ToolContract>>>;
  const server = createMcpServer({
    core: app,
    handlers: (name) => table[name],
    contracts: TOOL_CONTRACTS,
    delivery: new Delivery(options.maxResponseBytes ?? HARD_LIMITS.defaultResponseBytes),
    onServedInstanceClosed: () => app.lifecycle.closeAll("connection-closed"),
  });
  const mcp = createTestMcp();
  let client: Client;
  try {
    client = await mcp.connect(server, options.client ?? DEFAULT_CLIENT);
  } catch (cause) {
    await app.lifecycle.closeAll("connect-failed");
    await home.cleanup();
    throw cause;
  }
  let closed: Promise<void> | undefined;
  return {
    client,
    app,
    server,
    home,
    close: () =>
      (closed ??= (async () => {
        try {
          await mcp.close();
          await app.lifecycle.closeAll("test-closed");
        } finally {
          await home.cleanup();
        }
      })()),
  };
};
