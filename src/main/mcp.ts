import { composeServices } from "./composeServices.js";
import { productionStdioDeps, runStdio } from "./mcpStdio.js";

/** `bea mcp` entry (WP0). The HTTP leg is loaded lazily so stdio never imports HTTP code. */
export const runStdioMain = (): Promise<void> => runStdio(productionStdioDeps(composeServices));

export const runHttpMain = async (argv: readonly string[]): Promise<void> => {
  const { runHttpEntry } = await import("./mcpHttpEntry.js");
  await runHttpEntry(argv, composeServices);
};
