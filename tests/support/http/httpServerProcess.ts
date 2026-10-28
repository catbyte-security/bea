import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { distLayoutAt, resolveDistLayout, type DistLayout } from "../../../src/application/distLayout.js";
import { readConnectionFile, type HttpConnection } from "../../../src/server/http/connectionFile.js";
import { minimalEnv } from "../mcp/stdioSubprocess.js";
import { createTempHome, type TempHome } from "../workspace/tempHome.js";

/**
 * `bea mcp --http` as a real subprocess (S1 §8 `httpServerProcess.ts`).
 * - `source` (default, any OS, no build): the production runHttp from the TypeScript sources through Node's type
 *   transform + scripts/lib/tsHooks.mjs, with fakeServices() and the WP16 test tools (serverEntry.ts).
 * - `dist`: the BUILT server exactly as scripts launch it, `node <package>/scripts/bea.mjs mcp --http`, from
 *   BEA_DIST_DIR (a snapshot) or the repository's dist/ (see builtHttpAvailable()).
 * Minimal environment with a temp BEA_HOME; the status line on stderr gives url, connection file and pid.
 */
export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
export const TS_HOOKS = join(REPO_ROOT, "scripts", "lib", "tsHooks.mjs");
export const SERVER_ENTRY = join(REPO_ROOT, "tests", "support", "http", "serverEntry.ts");

export interface HttpStatusLine {
  readonly url: string;
  readonly connection_file: string;
  readonly pid: number;
}

export interface ExitOutcome {
  readonly code: number | null;
  readonly signal: string | null;
}

export interface HttpServerOptions {
  readonly mode?: "source" | "dist";
  /** Default: a fresh temp home, removed by stop(). */
  readonly home?: TempHome;
  /** Arguments after `--http --port 0` (e.g. --json-response, --connection-file PATH). */
  readonly args?: readonly string[];
  readonly env?: Readonly<Record<string, string>>;
  readonly distDir?: string;
  /** Status-line wait. Default 60 s (the source mode transforms the whole tree on start). */
  readonly startTimeoutMs?: number;
}

export interface HttpServerProcess {
  readonly child: ChildProcess;
  readonly pid: number;
  readonly home: TempHome;
  readonly status: HttpStatusLine;
  readonly connection: HttpConnection;
  readonly stderr: () => string;
  readonly exited: Promise<ExitOutcome>;
  /** fetch with the bearer token (and JSON headers for bodies); `path` defaults to /mcp. */
  readonly fetch: (init?: RequestInit & { readonly path?: string; readonly auth?: boolean }) => Promise<Response>;
  /** POST /shutdown, then wait for exit; falls back to kill() after `timeoutMs`. Removes an owned temp home. */
  readonly stop: (timeoutMs?: number) => Promise<ExitOutcome>;
}

/** The dist the `dist` mode runs. */
export const httpLayout = (distDir?: string): DistLayout =>
  distDir === undefined ? resolveDistLayout(process.env) : distLayoutAt(distDir);

/**
 * Null when a build can serve `bea mcp --http`, else why not (for a named skip). docs/testing.md rule 2: a test of
 * the BUILT server runs only from a snapshot (BEA_DIST_DIR), never from the repository's dist/, which concurrent
 * rebuilds replace under a running test. Also refused: a missing build, or one that predates WP16 (the day-0 stub).
 */
export const builtHttpUnavailable = (distDir?: string): string | null => {
  if (distDir === undefined && (process.env["BEA_DIST_DIR"] ?? "") === "")
    return "BEA_DIST_DIR is not set (node scripts/snapshot-dist.mjs <name>)";
  const layout = httpLayout(distDir);
  const entry = join(layout.distRoot, "main", "mcpHttpEntry.js");
  if (!existsSync(layout.dispatcher) || !existsSync(entry))
    return `no build at ${layout.distRoot} (npm run build; BEA_DIST_DIR=<snapshot>)`;
  if (readFileSync(entry, "utf8").includes("is not implemented in this build"))
    return `the build at ${layout.distRoot} predates WP16 (rebuild)`;
  return null;
};

const commandFor = (options: HttpServerOptions): readonly string[] => {
  const tail = ["--http", "--port", "0", ...(options.args ?? [])];
  if ((options.mode ?? "source") === "dist") return [httpLayout(options.distDir).dispatcher, "mcp", ...tail];
  return [
    "--experimental-transform-types",
    "--disable-warning=ExperimentalWarning",
    "--import",
    pathToFileURL(TS_HOOKS).href,
    SERVER_ENTRY,
    ...tail,
  ];
};

export const startHttpServer = async (options: HttpServerOptions = {}): Promise<HttpServerProcess> => {
  const ownsHome = options.home === undefined;
  const home = options.home ?? (await createTempHome("http"));
  const child = spawn(process.execPath, [...commandFor(options)], {
    cwd: home.work,
    env: minimalEnv(home, options.env),
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  let stderr = "";
  let stdout = "";
  child.stdout?.setEncoding("utf8").on("data", (text: string) => (stdout += text));
  const exited = new Promise<ExitOutcome>((settle) =>
    child.once("exit", (code, signal) => settle({ code, signal: signal === null ? null : String(signal) })),
  );
  const status = await new Promise<HttpStatusLine>((settle, reject) => {
    const timer = setTimeout(
      () =>
        reject(new Error(`no bea_http status line within ${String(options.startTimeoutMs ?? 60_000)} ms:\n${stderr}`)),
      options.startTimeoutMs ?? 60_000,
    );
    child.stderr?.setEncoding("utf8").on("data", (text: string) => {
      stderr += text;
      for (const line of stderr.split(/\r?\n/u)) {
        if (!line.startsWith('{"bea_http"')) continue;
        clearTimeout(timer);
        settle((JSON.parse(line) as { readonly bea_http: HttpStatusLine }).bea_http);
      }
    });
    void exited.then((outcome) => {
      clearTimeout(timer);
      reject(new Error(`server exited before its status line (${JSON.stringify(outcome)}):\n${stderr}${stdout}`));
    });
  }).catch(async (cause: unknown) => {
    child.kill();
    await exited;
    if (ownsHome) await home.cleanup();
    throw cause;
  });
  const connection = await readConnectionFile(status.connection_file);
  if (connection === null) {
    child.kill();
    await exited;
    throw new Error(`unreadable connection file ${status.connection_file}`);
  }
  const base = new URL(connection.url);
  const doFetch: HttpServerProcess["fetch"] = async (init = {}) => {
    const { path, auth, ...rest } = init;
    const headers = new Headers(rest.headers);
    if (auth !== false && !headers.has("authorization")) headers.set("authorization", `Bearer ${connection.token}`);
    return fetch(new URL(path ?? base.pathname, base), { ...rest, headers });
  };
  let stopping: Promise<ExitOutcome> | undefined;
  return {
    child,
    pid: child.pid ?? -1,
    home,
    status,
    connection,
    stderr: () => stderr,
    exited,
    fetch: doFetch,
    stop: (timeoutMs = 10_000) =>
      (stopping ??= (async () => {
        if (child.exitCode === null && child.signalCode === null)
          await doFetch({ path: "/shutdown", method: "POST" })
            .then((r) => r.text())
            .catch(() => undefined);
        const timer = setTimeout(() => child.kill(), timeoutMs);
        const outcome = await exited;
        clearTimeout(timer);
        if (ownsHome) await home.cleanup();
        return outcome;
      })()),
  };
};

/** The JSON-RPC message(s) of a Streamable HTTP reply: a JSON body, or the `data:` lines of an SSE body. */
export const rpcMessages = async (response: Response): Promise<readonly Record<string, unknown>[]> => {
  const text = await response.text();
  if ((response.headers.get("content-type") ?? "").startsWith("text/event-stream"))
    return text
      .split(/\r?\n/u)
      .filter((line) => line.startsWith("data:") && line.slice(5).trim() !== "")
      .map((line) => JSON.parse(line.slice(5)) as Record<string, unknown>);
  if (text === "") return [];
  const parsed = JSON.parse(text) as Record<string, unknown> | Record<string, unknown>[];
  return Array.isArray(parsed) ? parsed : [parsed];
};

export const MCP_ACCEPT = "application/json, text/event-stream";

export const initializeBody = (id = 1, name = "bea-http-test"): string =>
  JSON.stringify({
    jsonrpc: "2.0",
    id,
    method: "initialize",
    params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name, version: "1" } },
  });
