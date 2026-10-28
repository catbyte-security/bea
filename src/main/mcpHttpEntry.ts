import type { BeaCore } from "../application/BeaApplication.js";
import type { BeaServices } from "../application/services/index.js";
import { runHttp } from "./mcpHttp.js";

/**
 * `bea mcp --http` entry (WP16-HTTP). Loaded lazily by src/main/mcp.ts so the stdio path never imports HTTP code.
 * `argv` is everything after `mcp` (it includes `--http`); the listener keeps the process alive until shutdown.
 */
export const runHttpEntry = async (
  argv: readonly string[],
  services: (core: BeaCore) => Promise<BeaServices>,
): Promise<void> => {
  await runHttp(argv, { services });
};
