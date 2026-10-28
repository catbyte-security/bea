import { spawn, type ChildProcess } from "node:child_process";
import { dirname } from "node:path";

import { expect, vi } from "vitest";

import type { BeaApplication } from "../../../../src/application/BeaApplication.js";
import { createApplication } from "../../../../src/application/createApplication.js";
import type { ToolHandler } from "../../../../src/application/handlerContext.js";
import { createToolHandlers } from "../../../../src/application/handlers/index.js";
import { invokeTool } from "../../../../src/application/invokeTool.js";
import { findToolContract } from "../../../../src/contracts/index.js";
import type { ToolContract } from "../../../../src/contracts/toolContract.js";
import { loadConfig, type ConfigFile } from "../../../../src/domain/config.js";
import type { BeaError } from "../../../../src/domain/errors/beaError.js";
import { silentLogger } from "../../../../src/domain/logger.js";
import type { Result } from "../../../../src/domain/result.js";
import { composeServices } from "../../../../src/main/composeServices.js";
import type { LiveSession, OperationContext } from "../../../../src/ports/sessions.js";
import type { OwnedPidLedger } from "../../../support/process/ownedPidLedger.js";
import { createTempHome, type TempHome } from "../../../support/workspace/tempHome.js";

/**
 * The real composition in-process (composeServices: evidence, jobhost, PE, address, recordings, sessions …) driven
 * through the real tool handlers (invokeTool: input parse, admission, output self-check), plus raw LiveSession access
 * for the wave rule (DESIGN §8.4). BEA_DIST_DIR names the snapshot holding the agent bundle and bea-jobhost.
 */
export type Output = Readonly<Record<string, unknown>>;

export interface InProcessBea {
  readonly app: BeaApplication;
  readonly home: TempHome;
  /** One tool call; `signal` is the client's abort signal (cancellation). */
  readonly call: (name: string, args: Output, signal?: AbortSignal) => Promise<Result<Output, BeaError>>;
  /** An exclusive section on one session (raw agent RPCs, waitFor, crash()). */
  readonly raw: <T>(
    id: string,
    fn: (s: LiveSession, op: OperationContext) => Promise<Result<T, BeaError>>,
  ) => Promise<Result<T, BeaError>>;
  readonly close: () => Promise<void>;
}

export interface StartOptions {
  readonly config?: Omit<ConfigFile, "schema">;
  /** extra server environment (on top of the temp home's) */
  readonly env?: Readonly<Record<string, string>>;
  readonly label?: string;
}

export const startInProcessBea = async (options: StartOptions = {}): Promise<InProcessBea> => {
  const home = await createTempHome(options.label ?? "core-inproc");
  const configFile = options.config ?? {};
  const loaded = await loadConfig({
    env: { ...home.env, ...options.env },
    platform: "win32",
    accountHome: home.home,
    readConfigFile: async () =>
      Object.keys(configFile).length === 0 ? null : JSON.stringify({ schema: "bea.config/1", ...configFile }),
  });
  if (!loaded.ok) throw new Error(JSON.stringify(loaded.error));
  const app = await createApplication({
    config: loaded.value,
    logger: silentLogger,
    transport: "stdio",
    services: composeServices,
  });
  const table = createToolHandlers(app) as unknown as Readonly<Record<string, ToolHandler<ToolContract>>>;
  let closed = false;
  return {
    app,
    home,
    call: async (name, args, signal) => {
      const contract = findToolContract(name);
      if (contract === undefined) throw new Error(`no tool ${name}`);
      return invokeTool(app, (n) => table[n], contract, args, {
        surface: "mcp",
        clientSignal: signal ?? new AbortController().signal,
        progress: { report: () => undefined },
        requestId: name,
      });
    },
    raw: (id, fn) =>
      app.services.sessions.admit("acceptance_raw", { timeoutMs: 60_000, sessionId: id }, (op) =>
        app.services.sessions.withSession(id, op, "exclusive", (s) => fn(s, op)),
      ),
    close: async () => {
      if (closed) return;
      closed = true;
      try {
        await app.lifecycle.closeAll("test");
      } finally {
        await home.cleanup();
      }
    },
  };
};

export const value = <T>(result: Result<T, BeaError>): T => {
  if (!result.ok) throw new Error(`expected success, got ${JSON.stringify(result.error)}`);
  return result.value;
};

export const errorOf = (result: Result<unknown, BeaError>): Output => {
  if (result.ok) throw new Error(`expected an error, got ${JSON.stringify(result.value).slice(0, 400)}`);
  return result.error as unknown as Output;
};

/** spawn_process through the tool path (`extra`: further tool input); the identity goes to the owned-PID ledger. */
export const spawnOwned = async (
  target: { readonly bea: InProcessBea; readonly ledger: OwnedPidLedger },
  program: string,
  args: readonly string[],
  extra: Output = {},
): Promise<Output> => {
  const spawned = value(await target.bea.call("spawn_process", { program, args: [...args], ...extra }));
  target.ledger.recordIdentity(spawned["identity"] as Output, `spawn ${program} ${args.join(" ")}`);
  return spawned;
};

export interface ForeignProcess {
  readonly child: ChildProcess;
  readonly out: string[];
}

/**
 * A process the TEST starts (an attach target): recorded in the ledger as an attach target (it must survive every
 * close), stdout drained into `out` so the pipe never fills; resolves once `ready` appears.
 */
export const startForeign = async (
  ledger: OwnedPidLedger,
  exe: string,
  args: readonly string[],
  ready = "READY",
): Promise<ForeignProcess> => {
  const child = spawn(exe, [...args], { cwd: dirname(exe), stdio: ["ignore", "pipe", "ignore"], windowsHide: true });
  const out: string[] = [];
  child.stdout?.on("data", (chunk: Buffer) => out.push(chunk.toString()));
  await vi.waitFor(() => expect(out.join("")).toContain(ready), { interval: 20, timeout: 10_000 });
  ledger.recordAttachTarget(child.pid ?? 0, null, `test-spawned ${exe}`);
  return { child, out };
};
