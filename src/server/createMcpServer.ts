import { McpServer, type ServerContext } from "@modelcontextprotocol/server";

import type { BeaCore } from "../application/BeaApplication.js";
import { invokeTool, type HandlerLookup } from "../application/invokeTool.js";
import { effectFlags } from "../contracts/effects.js";
import type { ToolContract } from "../contracts/toolContract.js";
import { PRODUCT_IDENTITY } from "../identity.js";
import { advertisedInputSchema, advertisedOutputSchema } from "./advertisedSchemas.js";
import type { Delivery } from "./delivery.js";
import { SERVER_INSTRUCTIONS } from "./instructions.js";
import { mcpProgressSink } from "./progress.js";

export interface McpServerDeps {
  readonly core: BeaCore;
  readonly handlers: HandlerLookup;
  readonly contracts: readonly ToolContract[];
  readonly delivery: Delivery;
  /**
   * stdio: the instance owns the application lifetime once it has served a
   * client (initialized or ran a tool); its close requests app shutdown.
   * A discarded server/discover probe never served, so its close is ignored.
   * http: undefined (the process owns the application).
   */
  readonly onServedInstanceClosed?: () => Promise<unknown>;
}

/** One thin McpServer view over the shared application. Safe to create many. */
export const createMcpServer = (deps: McpServerDeps): McpServer => {
  const server = new McpServer(
    { name: PRODUCT_IDENTITY.mcpServerKey, version: PRODUCT_IDENTITY.packageVersion },
    { capabilities: {}, instructions: SERVER_INSTRUCTIONS },
  );
  let served = false;
  for (const contract of deps.contracts) {
    server.registerTool(
      contract.name,
      {
        title: contract.title,
        description: contract.description,
        inputSchema: advertisedInputSchema(contract),
        outputSchema: advertisedOutputSchema(contract),
        annotations: contract.annotations,
        _meta: {
          "bea/effects": effectFlags(contract.effects),
          "bea/phase": contract.phase,
          ...(contract.gate === null ? {} : { "bea/gate": contract.gate.id, "bea/gate_scope": contract.gate.scope }),
        },
      },
      async (raw: unknown, ctx: ServerContext) => {
        served = true;
        const result = await invokeTool(deps.core, deps.handlers, contract, raw, {
          surface: "mcp",
          clientSignal: ctx.mcpReq.signal,
          progress: mcpProgressSink(ctx, deps.core.clock),
          requestId: String(ctx.mcpReq.id),
        });
        return deps.delivery.toCallToolResult(result, contract);
      },
    );
  }
  server.server.oninitialized = () => {
    served = true;
  };
  if (deps.onServedInstanceClosed !== undefined) {
    const onServedInstanceClosed = deps.onServedInstanceClosed;
    const previousOnclose = server.server.onclose;
    server.server.onclose = () => {
      previousOnclose?.();
      if (served) void onServedInstanceClosed().catch(() => undefined);
    };
    const closeServer = server.close.bind(server);
    server.close = async () => {
      const results = await Promise.allSettled([closeServer(), served ? onServedInstanceClosed() : Promise.resolve()]);
      const failure = results.find((r): r is PromiseRejectedResult => r.status === "rejected");
      if (failure !== undefined) throw failure.reason;
    };
  }
  return server;
};
