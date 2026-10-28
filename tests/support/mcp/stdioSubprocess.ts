import type { ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";

import { Client, type CallToolRequestOptions, type CallToolResult, type Tool } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { Ajv2020 } from "ajv/dist/2020.js";

import { distLayoutAt, resolveDistLayout, type DistLayout } from "../../../src/application/distLayout.js";
import { createTempHome, type TempHome } from "../workspace/tempHome.js";

/**
 * The BUILT server over real stdio (rea-testing §4.2): `node <package>/scripts/bea.mjs mcp` from the build named by
 * BEA_DIST_DIR (a snapshot from scripts/snapshot-dist.mjs; default: the repository's dist/), a minimal environment with
 * a temp BEA_HOME, Ajv 2020-12 meta-validation of every advertised schema, and `toolDefinition` on every call so the
 * structuredContent is validated against the advertised output schema.
 */
export interface StdioBeaOptions {
  /** Temp home to use; default: a fresh one, removed on close. */
  readonly home?: TempHome;
  /** Extra environment for the server (gates, quotas, BEA_LOG_LEVEL …). */
  readonly env?: Readonly<Record<string, string>>;
  /** A dist root to run instead of BEA_DIST_DIR / dist/. */
  readonly distDir?: string;
  /** Dispatcher arguments; default ["mcp"]. */
  readonly args?: readonly string[];
  /** Meta-validate every advertised schema at connect (default true). */
  readonly validateSchemas?: boolean;
  readonly clientName?: string;
}

export interface CloseOutcome {
  readonly exitCode: number | null;
  readonly signal: string | null;
  readonly closeMs: number;
}

export interface StdioBea {
  readonly client: Client;
  readonly tools: readonly Tool[];
  readonly pid: number | null;
  readonly home: TempHome;
  readonly layout: DistLayout;
  readonly stderr: () => string;
  /** callTool with the advertised definition; a success is validated against the advertised output schema. */
  readonly call: (
    name: string,
    args?: Readonly<Record<string, unknown>>,
    options?: Pick<CallToolRequestOptions, "signal" | "onprogress" | "timeout">,
  ) => Promise<CallToolResult>;
  /** Close the client (stdin EOF) and wait for the server to exit. Idempotent. */
  readonly close: () => Promise<CloseOutcome>;
}

/** PATH + SystemRoot + the temp home: never the test process's environment (REA cliFixture). */
export const minimalEnv = (home: TempHome, extra: Readonly<Record<string, string>> = {}): Record<string, string> => ({
  PATH: process.env["PATH"] ?? "",
  ...(process.platform === "win32"
    ? {
        SystemRoot: process.env["SystemRoot"] ?? "C:\\Windows",
        SystemDrive: process.env["SystemDrive"] ?? "C:",
        // Standard OS variables some Win32 programs expect (BEA passes allowlisted OS variables on to targets).
        ...Object.fromEntries(
          ["windir", "ComSpec", "PATHEXT", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "OS"]
            .map((name) => [name, process.env[name]] as const)
            .filter((entry): entry is readonly [string, string] => entry[1] !== undefined),
        ),
      }
    : {}),
  ...home.env,
  BEA_LOG_LEVEL: "info",
  ...extra,
});

/** The dist the harness runs: options.distDir, else BEA_DIST_DIR, else the repository's dist/. */
export const harnessLayout = (distDir?: string): DistLayout =>
  distDir === undefined ? resolveDistLayout(process.env) : distLayoutAt(distDir);

const ajv = new Ajv2020({ strict: false, validateFormats: false, allErrors: true });

export const connectStdioBea = async (options: StdioBeaOptions = {}): Promise<StdioBea> => {
  const layout = harnessLayout(options.distDir);
  if (!existsSync(layout.dispatcher) || !existsSync(join(layout.distRoot, "main", "mcp.js")))
    throw new Error(
      `No built server at ${layout.distRoot}. Run \`npm run build\`, then \`node scripts/snapshot-dist.mjs <name>\` and set ` +
        "BEA_DIST_DIR to the printed path (docs/testing.md).",
    );
  const ownHome = options.home === undefined;
  const home = options.home ?? (await createTempHome("stdio"));
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [layout.dispatcher, ...(options.args ?? ["mcp"])],
    env: minimalEnv(home, options.env),
    cwd: home.work,
    stderr: "pipe",
  });
  let stderr = "";
  transport.stderr?.on("data", (chunk: Buffer | string) => {
    stderr += chunk.toString();
  });
  const client = new Client({ name: options.clientName ?? "bea-stdio-test", version: "1" });
  try {
    await client.connect(transport);
  } catch (cause) {
    await transport.close().catch(() => undefined);
    if (ownHome) await home.cleanup();
    throw new Error(`stdio connect failed: ${String(cause)}\nserver stderr:\n${stderr}`);
  }
  // Test-only peek at the child for its exit status (the SDK keeps it private).
  const child = (transport as unknown as { readonly _process?: ChildProcess })._process;
  const exited = new Promise<{ code: number | null; signal: string | null }>((resolve) => {
    if (child === undefined) resolve({ code: null, signal: null });
    else if (child.exitCode !== null || child.signalCode !== null)
      resolve({ code: child.exitCode, signal: child.signalCode });
    else child.once("exit", (code, signal) => resolve({ code, signal }));
  });

  const tools = (await client.listTools()).tools;
  if (options.validateSchemas !== false)
    for (const tool of tools)
      for (const [kind, schema] of [
        ["inputSchema", tool.inputSchema],
        ["outputSchema", tool.outputSchema],
      ] as const)
        if (schema !== undefined && !ajv.validateSchema(schema as object))
          throw new Error(`${tool.name}.${kind} is not a valid JSON Schema 2020-12: ${ajv.errorsText(ajv.errors)}`);
  const definitions = new Map(tools.map((tool) => [tool.name, tool]));
  const validators = new Map<string, ReturnType<typeof ajv.compile>>();

  let closing: Promise<CloseOutcome> | undefined;
  return {
    client,
    tools,
    pid: transport.pid,
    home,
    layout,
    stderr: () => stderr,
    call: async (name, args = {}, callOptions = {}) => {
      const definition = definitions.get(name);
      const result = await client.callTool(
        { name, arguments: { ...args } },
        { ...callOptions, ...(definition === undefined ? {} : { toolDefinition: definition }) },
      );
      if (result.isError !== true && definition?.outputSchema !== undefined && result.structuredContent !== undefined) {
        let validate = validators.get(name);
        if (validate === undefined) {
          validate = ajv.compile(definition.outputSchema as Record<string, unknown>);
          validators.set(name, validate);
        }
        if (!validate(result.structuredContent))
          throw new Error(
            `${name} structuredContent violates its advertised output schema: ${ajv.errorsText(validate.errors)}`,
          );
      }
      return result;
    },
    close: () =>
      (closing ??= (async () => {
        const started = performance.now();
        await client.close();
        const { code, signal } = await exited;
        const outcome = { exitCode: code, signal, closeMs: Math.round(performance.now() - started) };
        if (ownHome) await home.cleanup();
        return outcome;
      })()),
  };
};
