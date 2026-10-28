import { isDeepStrictEqual, parseArgs } from "node:util";

import { Client, type CallToolResult, type Tool } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";

import { effectFlags } from "../contracts/effects.js";
import type { ToolContract } from "../contracts/toolContract.js";
import { inputError } from "../domain/errors/constructors.js";
import { beaErrorEnvelopeSchema } from "../domain/errors/projection.js";
import { PRODUCT_IDENTITY } from "../identity.js";
import type { CliIo, OutputFormat } from "./io.js";
import { EXIT, renderDocument, renderError } from "./output.js";

const DIALECT = "https://json-schema.org/draft/2020-12/schema";
const DEFAULT_DEADLINE_MS = 30_000;
const MAX_DEADLINE_MS = 60_000;
const STDERR_LIMIT = 64 * 1024;
/** The SDK client's kill-first budget: a clean server exits within it after stdin EOF. */
const SHUTDOWN_BUDGET_MS = 2_000;
/** Variables the server needs (PATH, SystemRoot, temp, profile dirs) plus BEA_*; never the whole environment. */
const PASSED_ENV = [
  "PATH",
  "Path",
  "SystemRoot",
  "SystemDrive",
  "TEMP",
  "TMP",
  "USERPROFILE",
  "APPDATA",
  "LOCALAPPDATA",
  "HOME",
];

export interface McpDoctorCheck {
  readonly name: string;
  readonly ok: boolean;
  readonly ms: number;
  readonly detail?: string;
}

export interface McpDoctorReport {
  readonly schema: "bea.mcp-doctor/1";
  readonly ok: boolean;
  readonly checks: readonly McpDoctorCheck[];
  readonly server: {
    readonly name: string | null;
    readonly version: string | null;
    readonly protocol_version: string | null;
  };
  readonly inventory: {
    readonly expected: number;
    readonly advertised: number;
    readonly missing: readonly string[];
    readonly unexpected: readonly string[];
    readonly duplicates: readonly string[];
  };
  readonly stderr: { readonly text: string; readonly bytes: number; readonly truncated: boolean };
}

export interface McpDoctorOptions {
  /** scripts/bea.mjs of the build to check (the dispatcher that invoked us). */
  readonly dispatcherPath: string;
  readonly execPath: string;
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly contracts: readonly ToolContract[];
  readonly deadlineMs?: number;
}

/** S1 §7.7 minimal environment. */
export const doctorEnvironment = (env: Readonly<Record<string, string | undefined>>): Record<string, string> =>
  Object.fromEntries(
    Object.entries(env).filter(
      (entry): entry is [string, string] =>
        entry[1] !== undefined && (PASSED_ENV.includes(entry[0]) || entry[0].startsWith("BEA_")),
    ),
  );

interface ChildView {
  readonly exitCode: number | null;
  readonly signalCode: string | null;
  once(event: "exit", listener: (code: number | null, signal: string | null) => void): unknown;
}

const timed = async (name: string, run: () => Promise<string | null>): Promise<McpDoctorCheck> => {
  const started = performance.now();
  try {
    const failure = await run();
    const ms = Math.round(performance.now() - started);
    return failure === null ? { name, ok: true, ms } : { name, ok: false, ms, detail: failure };
  } catch (cause: unknown) {
    return {
      name,
      ok: false,
      ms: Math.round(performance.now() - started),
      detail: cause instanceof Error ? cause.message : String(cause),
    };
  }
};

const withDeadline = <T>(promise: Promise<T>, signal: AbortSignal): Promise<T> =>
  Promise.race([
    promise,
    new Promise<never>((_resolve, reject) => {
      if (signal.aborted) reject(new Error("overall deadline reached"));
      signal.addEventListener("abort", () => reject(new Error("overall deadline reached")), { once: true });
    }),
  ]);

const duplicatesOf = (names: readonly string[]): string[] => [
  ...new Set(names.filter((n, i) => names.indexOf(n) !== i)),
];

const annotationProblems = (tools: readonly Tool[], contracts: readonly ToolContract[]): string[] => {
  const problems: string[] = [];
  for (const tool of tools) {
    const contract = contracts.find((c) => c.name === tool.name);
    if (contract === undefined) continue;
    const advertised = tool.annotations ?? {};
    for (const [key, value] of Object.entries(contract.annotations))
      if (Reflect.get(advertised, key) !== value) problems.push(`${tool.name}.${key}`);
    if (!isDeepStrictEqual(tool._meta?.["bea/effects"], effectFlags(contract.effects)))
      problems.push(`${tool.name}._meta.bea/effects`);
  }
  return problems;
};

const textOf = (result: CallToolResult): string | null => {
  const first = result.content[0];
  return result.content.length === 1 && first?.type === "text" ? first.text : null;
};

const checkStatus = (result: CallToolResult, contract: ToolContract | undefined): string | null => {
  if (result.isError === true) return `bea_status returned an error: ${textOf(result) ?? ""}`.slice(0, 500);
  if (contract === undefined) return "bea_status is not in the local catalog";
  const parsed = contract.outputSchema.safeParse(result.structuredContent);
  if (!parsed.success)
    return `structuredContent does not match the output schema (${String(parsed.error.issues.length)} issues)`;
  if (textOf(result) !== JSON.stringify(result.structuredContent))
    return "text content differs from JSON(structuredContent)";
  const provenance = (result._meta as { provenance?: { untrusted_content?: unknown } } | undefined)?.provenance;
  if (contract.returnsTargetContent && provenance?.untrusted_content !== true)
    return "the untrusted-content marker is missing";
  return null;
};

const checkInvalid = (result: CallToolResult): string | null => {
  if (result.isError !== true) return "bea_status {bogus:1} did not fail";
  const text = textOf(result);
  if (text === null) return "the error carries no single text item";
  const parsed = beaErrorEnvelopeSchema.safeParse(JSON.parse(text));
  if (!parsed.success) return "the error text is not {error: projection}";
  return parsed.data.error.code === "invalid_request"
    ? null
    : `code ${parsed.data.error.code}, expected invalid_request`;
};

/**
 * `bea mcp doctor` (S1 §7.7; REA runProductionMcpDoctor): spawns the real stdio server through the SDK client with a
 * minimal environment, then checks initialize, inventory, annotations, schema dialect, bea_status, invalid_request and
 * a clean shutdown (exit 0 within 2 s of stdin EOF). Every child it starts is its own and is gone when it returns.
 */
export const runMcpDoctor = async (options: McpDoctorOptions): Promise<McpDoctorReport> => {
  const deadline = AbortSignal.timeout(options.deadlineMs ?? DEFAULT_DEADLINE_MS);
  const checks: McpDoctorCheck[] = [];
  let stderr = "";
  let stderrBytes = 0;
  const transport = new StdioClientTransport({
    command: options.execPath,
    args: [options.dispatcherPath, "mcp"],
    env: doctorEnvironment(options.env),
    stderr: "pipe",
  });
  transport.stderr?.on("data", (chunk: Buffer | string) => {
    const text = chunk.toString();
    stderrBytes += Buffer.byteLength(text);
    if (stderr.length < STDERR_LIMIT) stderr += text.slice(0, STDERR_LIMIT - stderr.length);
  });
  const client = new Client({ name: "bea-mcp-doctor", version: PRODUCT_IDENTITY.packageVersion });
  const server = {
    name: null as string | null,
    version: null as string | null,
    protocol_version: null as string | null,
  };
  let tools: Tool[] = [];
  let connected = false;
  checks.push(
    await timed("spawn-initialize", async () => {
      await withDeadline(client.connect(transport), deadline);
      connected = true;
      const info = client.getServerVersion();
      server.name = info?.name ?? null;
      server.version = info?.version ?? null;
      server.protocol_version = client.getNegotiatedProtocolVersion() ?? null;
      if (info?.name !== PRODUCT_IDENTITY.mcpServerKey || info.version !== PRODUCT_IDENTITY.packageVersion)
        return `serverInfo ${JSON.stringify(info ?? null)}, expected {name: "bea", version: "${PRODUCT_IDENTITY.packageVersion}"}`;
      return (client.getInstructions() ?? "").length > 0 ? null : "the server sent no instructions";
    }),
  );
  // Peek at the child for its exit status (the SDK keeps the process private); type-only, no child_process import.
  const child = (transport as unknown as { readonly _process?: ChildView })._process;
  const exited = new Promise<{ code: number | null; at: number }>((resolve) => {
    if (child === undefined) resolve({ code: null, at: performance.now() });
    else if (child.exitCode !== null || child.signalCode !== null)
      resolve({ code: child.exitCode, at: performance.now() });
    else child.once("exit", (code) => resolve({ code, at: performance.now() }));
  });
  const expected = options.contracts.map((c) => c.name);
  let advertised: string[] = [];
  const skipped = (name: string): McpDoctorCheck => ({
    name,
    ok: false,
    ms: 0,
    detail: "skipped: the server did not initialize",
  });
  if (!connected)
    checks.push(...["inventory", "annotations", "schema-dialect", "bea_status", "invalid-request"].map(skipped));
  else {
    checks.push(
      await timed("inventory", async () => {
        tools = (await withDeadline(client.listTools(), deadline)).tools;
        advertised = tools.map((t) => t.name);
        const missing = expected.filter((n) => !advertised.includes(n));
        const unexpected = advertised.filter((n) => !expected.includes(n));
        const duplicates = duplicatesOf(advertised);
        return missing.length + unexpected.length + duplicates.length === 0
          ? null
          : `missing [${missing.join(", ")}] unexpected [${unexpected.join(", ")}] duplicates [${duplicates.join(", ")}]`;
      }),
      await timed("annotations", async () => {
        const problems = annotationProblems(tools, options.contracts);
        return problems.length === 0 ? null : `mismatched: ${problems.slice(0, 20).join(", ")}`;
      }),
      await timed("schema-dialect", async () => {
        const wrong = tools.filter(
          (t) =>
            t.inputSchema["$schema"] !== DIALECT ||
            (t.outputSchema !== undefined && t.outputSchema["$schema"] !== DIALECT),
        );
        return wrong.length === 0 ? null : `not draft 2020-12: ${wrong.map((t) => t.name).join(", ")}`;
      }),
      await timed("bea_status", async () =>
        checkStatus(
          (await withDeadline(client.callTool({ name: "bea_status", arguments: {} }), deadline)) as CallToolResult,
          options.contracts.find((c) => c.name === "bea_status"),
        ),
      ),
      await timed("invalid-request", async () =>
        checkInvalid(
          (await withDeadline(
            client.callTool({ name: "bea_status", arguments: { bogus: 1 } }),
            deadline,
          )) as CallToolResult,
        ),
      ),
    );
  }
  checks.push(
    await timed("shutdown", async () => {
      const started = performance.now();
      await client.close().catch(() => undefined);
      await transport.close().catch(() => undefined);
      const { code, at } = await exited;
      const ms = Math.round(at - started);
      if (code !== 0) return `the server exited with ${String(code)}`;
      return ms <= SHUTDOWN_BUDGET_MS
        ? null
        : `the server took ${String(ms)} ms to exit (budget ${String(SHUTDOWN_BUDGET_MS)} ms)`;
    }),
  );
  return {
    schema: "bea.mcp-doctor/1",
    ok: checks.every((check) => check.ok),
    checks,
    server,
    inventory: {
      expected: expected.length,
      advertised: advertised.length,
      missing: expected.filter((n) => connected && !advertised.includes(n)),
      unexpected: advertised.filter((n) => !expected.includes(n)),
      duplicates: duplicatesOf(advertised),
    },
    stderr: { text: stderr, bytes: stderrBytes, truncated: stderrBytes > stderr.length },
  };
};

/** `bea mcp doctor [--json] [--timeout-ms N]` → exit 0 iff ok. */
export const runMcpDoctorCommand = async (
  argv: readonly string[],
  options: Omit<McpDoctorOptions, "deadlineMs"> & { readonly io: CliIo },
): Promise<number> => {
  const format: OutputFormat = argv.includes("--json") ? "json" : "toon";
  let deadlineMs = DEFAULT_DEADLINE_MS;
  try {
    const parsed = parseArgs({
      args: [...argv],
      options: { json: { type: "boolean" }, "timeout-ms": { type: "string" } },
      strict: true,
      allowPositionals: false,
    });
    const raw = parsed.values["timeout-ms"];
    if (raw !== undefined) {
      deadlineMs = /^\d+$/u.test(raw) ? Number(raw) : Number.NaN;
      if (!Number.isSafeInteger(deadlineMs) || deadlineMs < 1_000 || deadlineMs > MAX_DEADLINE_MS)
        throw new RangeError("--timeout-ms must be 1000..60000");
    }
  } catch (cause: unknown) {
    options.io.stdout(
      renderError(
        inputError("mcp_doctor", [
          { path: "argv", reason: "invalid_value", message: cause instanceof Error ? cause.message : String(cause) },
        ]),
        format,
        options.io.stdoutIsTty,
      ),
    );
    return EXIT.failed;
  }
  const report = await runMcpDoctor({ ...options, deadlineMs });
  options.io.stdout(renderDocument(report, format, options.io.stdoutIsTty));
  return report.ok ? EXIT.ok : EXIT.failed;
};
