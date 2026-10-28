import { homedir, userInfo } from "node:os";
import { createInterface } from "node:readline/promises";

import type { BeaCore } from "../application/BeaApplication.js";
import { resolveDistLayout } from "../application/distLayout.js";
import type { ToolHandler } from "../application/handlerContext.js";
import { createToolHandlers } from "../application/handlers/index.js";
import type { HandlerLookup } from "../application/invokeTool.js";
import type { BeaServices } from "../application/services/index.js";
import type { CliDeps, CliIo } from "../cli/io.js";
import { runCli } from "../cli/runCli.js";
import { TOOL_CONTRACTS } from "../contracts/index.js";
import type { ToolContract } from "../contracts/toolContract.js";
import type { HostPlatform } from "../domain/paths.js";
import { createEmulatorProvisioner } from "../providers/emulator/venvProvisioner.js";

export type { CliIo } from "../cli/io.js";

const accountHome = (): string => {
  try {
    return userInfo().homedir;
  } catch {
    return homedir();
  }
};

/** Reads stdin to the end, giving up (null) once it exceeds maxBytes. */
const readStdin = async (maxBytes: number): Promise<Buffer | null> => {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of process.stdin) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
    total += buffer.length;
    if (total > maxBytes) {
      process.stdin.destroy();
      return null;
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks);
};

const prompt = async (question: string): Promise<string> => {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try {
    return await rl.question(question);
  } finally {
    rl.close();
  }
};

/** Production wiring: the real catalog, handlers and services (composed lazily, per command), from `process`. */
export const productionCliDeps = (io: CliIo): CliDeps => ({
  io,
  stderr: (text) => void process.stderr.write(text),
  env: process.env,
  platform: process.platform as HostPlatform,
  arch: process.arch,
  nodeVersion: process.versions.node,
  accountHome: accountHome(),
  cwd: process.cwd(),
  execPath: process.execPath,
  isTty: { stdin: process.stdin.isTTY === true, stderr: process.stderr.isTTY === true },
  readStdin,
  prompt,
  signals: process,
  layout: resolveDistLayout(),
  contracts: TOOL_CONTRACTS,
  createHandlers: (app): HandlerLookup => {
    const table = createToolHandlers(app) as unknown as Readonly<Record<string, ToolHandler<ToolContract>>>;
    return (name) => table[name];
  },
  // Providers load on first use: `bea --help`, `setup` and plain `doctor` never import frida (§5.8).
  services: async (core: BeaCore): Promise<BeaServices> => (await import("./composeServices.js")).composeServices(core),
  provisioner: (config) => createEmulatorProvisioner({ config }),
});

/** `bea <command>` entry (scripts/bea.mjs). Returns the exit code; the dispatcher maps a closed stdout to 141. */
export const runCliMain = async (argv: readonly string[], io: CliIo): Promise<number> =>
  runCli(productionCliDeps(io), argv);
