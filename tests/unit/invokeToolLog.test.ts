import { describe, expect, it } from "vitest";

import { createApplication } from "../../src/application/createApplication.js";
import type { ToolHandler } from "../../src/application/handlerContext.js";
import { createToolHandlers } from "../../src/application/handlers/index.js";
import { invokeTool } from "../../src/application/invokeTool.js";
import { TOOL_CONTRACTS } from "../../src/contracts/index.js";
import type { ToolContract } from "../../src/contracts/toolContract.js";
import { loadConfig } from "../../src/domain/config.js";
import { createLogger } from "../../src/domain/logger.js";
import { fakeServices } from "../support/fakes/fakeServices.js";

/**
 * WP18 (S6 §10.9 #4 "the abort reason is recorded"): every invocation's "tool done" line carries the client's
 * cancellation, also when the handler still finished (trace_api / hook_function with wait_ms: the install succeeded,
 * only the blocking wait was cut short, and the client never sees the result).
 */
const appWithLog = async (lines: string[]) => {
  const loaded = await loadConfig({
    env: { BEA_HOME: "C:/bea-test-home" },
    platform: "win32",
    accountHome: "C:/Users/t",
    readConfigFile: async () => null,
  });
  if (!loaded.ok) throw new Error(JSON.stringify(loaded.error));
  return createApplication({
    config: loaded.value,
    logger: createLogger({ level: "info", write: (line) => void lines.push(line) }),
    transport: "cli",
    services: fakeServices({}),
  });
};

const toolDone = (lines: readonly string[]): Record<string, unknown>[] =>
  lines.map((line) => JSON.parse(line) as Record<string, unknown>).filter((entry) => entry["msg"] === "tool done");

describe("invokeTool logs the client's cancellation", () => {
  const contract = TOOL_CONTRACTS.find((c) => c.name === "bea_status") as ToolContract;

  it("a call cancelled while its handler still completed: ok:true with aborted:client", async () => {
    const lines: string[] = [];
    const app = await appWithLog(lines);
    const table = createToolHandlers(app) as unknown as Record<string, ToolHandler<ToolContract>>;
    const client = new AbortController();
    const result = await invokeTool(
      app,
      (name) => async (input, ctx) => {
        const out = await (table[name] as ToolHandler<ToolContract>)(input, ctx);
        client.abort(); // the client gave up while the handler was finishing
        return out;
      },
      contract,
      {},
      { surface: "mcp", clientSignal: client.signal, progress: { report: () => undefined }, requestId: "7" },
    );
    expect(result.ok).toBe(true);
    expect(toolDone(lines)).toEqual([expect.objectContaining({ tool: "bea_status", ok: true, aborted: "client" })]);
  });

  it("an uncancelled call has no aborted field; a call cancelled before it ran is code cancelled", async () => {
    const lines: string[] = [];
    const app = await appWithLog(lines);
    const table = createToolHandlers(app) as unknown as Record<string, ToolHandler<ToolContract>>;
    const options = { surface: "mcp" as const, progress: { report: () => undefined }, requestId: "8" };
    await invokeTool(app, (n) => table[n], contract, {}, { ...options, clientSignal: new AbortController().signal });
    await invokeTool(app, (n) => table[n], contract, {}, { ...options, clientSignal: AbortSignal.abort() });
    const [plain, cancelled] = toolDone(lines);
    expect(plain).toMatchObject({ ok: true });
    expect(plain).not.toHaveProperty("aborted");
    expect(cancelled).toMatchObject({ ok: false, code: "cancelled", aborted: "client" });
  });
});
