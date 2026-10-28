import { runMcpDoctorCommand } from "../cli/mcpDoctor.js";
import { TOOL_CONTRACTS } from "../contracts/index.js";
import type { CliIo } from "./cli.js";

/**
 * `bea mcp doctor` entry (S1 §7.7). The dispatcher passes its own path, so the doctor checks exactly the build it
 * belongs to; the expected inventory is this build's TOOL_CONTRACTS.
 */
export const runMcpDoctorMain = async (
  argv: readonly string[],
  opts: { readonly dispatcherPath: string; readonly io: CliIo },
): Promise<number> =>
  runMcpDoctorCommand(argv, {
    dispatcherPath: opts.dispatcherPath,
    execPath: process.execPath,
    env: process.env,
    contracts: TOOL_CONTRACTS,
    io: opts.io,
  });
