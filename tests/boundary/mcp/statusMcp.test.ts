import { Client } from "@modelcontextprotocol/client";
import { InMemoryTransport } from "@modelcontextprotocol/server";
import { expect, it } from "vitest";

import { createApplication } from "../../../src/application/createApplication.js";
import type { ToolHandler } from "../../../src/application/handlerContext.js";
import { createToolHandlers } from "../../../src/application/handlers/index.js";
import { TOOL_CONTRACTS } from "../../../src/contracts/index.js";
import type { ToolContract } from "../../../src/contracts/toolContract.js";
import { loadConfig } from "../../../src/domain/config.js";
import { silentLogger } from "../../../src/domain/logger.js";
import { createMcpServer } from "../../../src/server/createMcpServer.js";
import { Delivery } from "../../../src/server/delivery.js";
import { fakeServices } from "../../support/fakes/fakeServices.js";

it("serves bea_status over an in-memory MCP connection and closes the app with the instance", async () => {
  const loaded = await loadConfig({
    env: { BEA_HOME: "C:/bea-test-home", BEA_ALLOW_CALL_ATTACHED: "1" },
    platform: "win32",
    accountHome: "C:/Users/t",
    readConfigFile: async () => null,
  });
  if (!loaded.ok) throw new Error(JSON.stringify(loaded.error));
  const order: string[] = [];
  const app = await createApplication({
    config: loaded.value,
    logger: silentLogger,
    transport: "stdio",
    services: async (core) => {
      core.lifecycle.register({ name: "owned", phase: "teardown-targets", close: async () => void order.push("kill") });
      core.lifecycle.register({ name: "frida", phase: "release-frida", close: async () => void order.push("frida") });
      return fakeServices()(core);
    },
  });
  const table = createToolHandlers(app) as unknown as Record<string, ToolHandler<ToolContract>>;
  const server = createMcpServer({
    core: app,
    handlers: (n) => table[n],
    contracts: TOOL_CONTRACTS,
    delivery: new Delivery(10 * 1024 * 1024),
    onServedInstanceClosed: () => app.lifecycle.closeAll("connection-closed"),
  });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "t", version: "1" });
  await client.connect(clientTransport);
  const result = await client.callTool({ name: "bea_status", arguments: {} });
  expect(result.isError).toBeUndefined();
  expect(result.structuredContent).toMatchObject({
    gates: { call_attached: { enabled: true, source: "env" }, write_memory: { enabled: false } },
    evidence_id: null,
    coverage: { status: "complete" },
  });
  await client.close();
  await server.close();
  expect(order).toEqual(["kill", "frida"]);
  expect(app.lifecycle.closing).toBe(true);
});
