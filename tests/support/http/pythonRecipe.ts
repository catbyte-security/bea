import { spawn, spawnSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { minimalEnv } from "../mcp/stdioSubprocess.js";
import type { TempHome } from "../workspace/tempHome.js";
import { REPO_ROOT } from "./httpServerProcess.js";

/**
 * Runs the Python recipe of docs/http.md (DESIGN §5.9, CT-I10) with the system Python (`python -I`, standard library
 * only): the `<!-- recipe: bea_http.py -->` block is extracted verbatim from the document, and a small driver uses
 * it the way a script would. The driver prints one JSON report on stdout.
 */
export const RECIPE_MARKER = "<!-- recipe: bea_http.py -->";

/**
 * The real Python 3 interpreter, resolved once with the test process's own environment: `sys.executable` of
 * `python -I`. The driver must run this absolute path, never the `python` alias: under a temp home's LOCALAPPDATA the
 * Windows Python install manager's alias would bootstrap (download and install) a fresh Python into that home.
 */
export const resolvePython = (): { readonly executable: string } | { readonly skip: string } => {
  const probe = spawnSync(
    "python",
    ["-I", "-c", "import sys, urllib.request; print(sys.version_info[0]); print(sys.executable)"],
    { encoding: "utf8", windowsHide: true, timeout: 30_000 },
  );
  const [major, executable] = probe.stdout?.trim().split(/\r?\n/u) ?? [];
  return probe.status === 0 && major === "3" && executable !== undefined && executable !== ""
    ? { executable }
    : { skip: "python 3 is not on PATH" };
};

export const extractRecipe = async (): Promise<string> => {
  const doc = await readFile(join(REPO_ROOT, "docs", "http.md"), "utf8");
  const at = doc.indexOf(RECIPE_MARKER);
  if (at < 0) throw new Error(`docs/http.md has no ${RECIPE_MARKER} marker`);
  const match = /```python\r?\n([\s\S]*?)\r?\n```/u.exec(doc.slice(at));
  if (match?.[1] === undefined) throw new Error("no python block after the recipe marker");
  return `${match[1]}\n`;
};

const DRIVER = String.raw`
import importlib.util, json, os, sys, traceback

cfg = json.loads(sys.argv[1])
spec = importlib.util.spec_from_file_location("bea_http", cfg["module"])
bea = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bea)

JSON_HEADERS = {"Content-Type": "application/json", "Accept": bea.ACCEPT}
report = {}


def ok(session, name, arguments=None):
    """A successful tool result's structuredContent; a BEA error raises with its envelope."""
    result = session.call_tool(name, arguments)
    if result.get("isError"):
        raise RuntimeError(f"{name} failed: {result['content'][0]['text']}")
    return result["structuredContent"]


def main():
    proc, conn = bea.start_server(
        cfg["bea_mjs"], node=cfg["node"], connection_file=cfg["connection_file"], launch=cfg["launch"]
    )
    report["pid"] = proc.pid
    report["conn_pid"] = conn["pid"]
    try:
        session_flow(conn)
    finally:
        report["exit_code"] = bea.stop_server(proc, conn)
    report["connection_file_exists"] = os.path.exists(conn["_path"])


def session_flow(conn):
    target = cfg["target"]
    first = bea.McpSession.open(conn)
    stale = first.session_id
    try:
        status = first.call_tool("bea_status")["structuredContent"]["server"]
        report["run_id_1"] = status["run_id"]
        report["transport"] = status["transport"]
        if cfg["fake_session"]:
            opened = first.call_tool("http_test_open_session")["structuredContent"]
            report["fake_session_id"] = opened["fake_session_id"]
        if target is not None:
            # Two real BEA sessions opened in MCP session 1: one is closed with close_session after reconnecting,
            # the other is resumed and left running for POST /shutdown to clean up.
            report["targets"] = {}
            for label in ("closed", "shutdown"):
                spawned = ok(first, "spawn_process", {"program": target["program"], "args": target["args"]})
                report["targets"][label] = {"session_id": spawned["session_id"], "identity": spawned["identity"]}
            ok(first, "resume_process", {"session_id": report["targets"]["shutdown"]["session_id"]})
    finally:
        first.close()
    report["deleted"] = first.session_id is None
    code, _, _ = bea._request(
        conn,
        "POST",
        body={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={**JSON_HEADERS, "mcp-session-id": stale},
    )
    report["stale_status"] = code
    second = bea.McpSession.open(conn)
    try:
        status = ok(second, "bea_status")
        report["run_id_2"] = status["server"]["run_id"]
        if target is not None:
            ids = {t["session_id"] for t in report["targets"].values()}
            report["listed_after_reconnect"] = [
                {key: s[key] for key in ("session_id", "kind", "state", "pid", "ownership")}
                for s in status["sessions"]
                if s["session_id"] in ids
            ]
            closed_id = report["targets"]["closed"]["session_id"]
            before = ok(second, "session_status", {"session_id": closed_id})
            report["status_after_reconnect"] = {"state": before["state"], "pid": before["identity"]["pid"]}
            closed = ok(second, "close_session", {"session_id": closed_id})
            report["close"] = {"target_state": closed["target_state"], "already_closed": closed["already_closed"]}
            report["status_after_close"] = ok(second, "session_status", {"session_id": closed_id})["state"]
            remaining = ok(second, "bea_status")["sessions"]
            report["open_before_shutdown"] = [s["session_id"] for s in remaining if s["state"] != "closed"]
        if cfg["fake_session"]:
            found = second.call_tool(
                "http_test_get_session", {"fake_session_id": report["fake_session_id"], "close": True}
            )
            report["fake_session"] = found["structuredContent"]
        if cfg["oversize"]:
            code, _, _ = bea._request(
                conn,
                "POST",
                body=b" " * (65 * 1024 * 1024),
                headers={**JSON_HEADERS, "mcp-session-id": second.session_id},
            )
            report["oversize_status"] = code
            report["after_oversize_error"] = second.call_tool("bea_status").get("isError", False)
    finally:
        second.close()


# The report is printed even when the flow fails, so the caller can still audit the targets it names.
try:
    main()
except BaseException:
    report["error"] = traceback.format_exc()
    raise
finally:
    print(json.dumps(report))
`;

export interface RecipeConfig {
  /** Absolute scripts/bea.mjs (the recipe's default launch). */
  readonly beaMjs: string;
  /** Replaces `[node, bea_mjs, "mcp"]` (source mode). */
  readonly launch: readonly string[] | null;
  readonly fakeSession: boolean;
  readonly oversize: boolean;
  /**
   * A real fixture spawned twice in MCP session 1 (needs the built server with Frida and the jobhost): one BEA
   * session is closed with close_session after reconnecting, the other is resumed and left for POST /shutdown.
   */
  readonly target?: { readonly program: string; readonly args: readonly string[] } | null;
}

export interface RecipeTarget {
  readonly session_id: string;
  readonly identity: Readonly<Record<string, unknown>> & { readonly pid: number };
}

export interface RecipeReport {
  readonly pid: number;
  readonly conn_pid: number;
  readonly run_id_1: string;
  readonly run_id_2: string;
  readonly transport: string;
  readonly deleted: boolean;
  readonly stale_status: number;
  readonly fake_session_id?: string;
  readonly fake_session?: { readonly exists: boolean; readonly open_sessions: number };
  readonly oversize_status?: number;
  readonly after_oversize_error?: boolean;
  readonly targets?: { readonly closed: RecipeTarget; readonly shutdown: RecipeTarget };
  readonly listed_after_reconnect?: readonly {
    readonly session_id: string;
    readonly kind: string;
    readonly state: string;
    readonly pid: number | null;
    readonly ownership: string;
  }[];
  readonly status_after_reconnect?: { readonly state: string; readonly pid: number };
  readonly close?: { readonly target_state: string; readonly already_closed: boolean };
  readonly status_after_close?: string;
  readonly open_before_shutdown?: readonly string[];
  readonly exit_code: number;
  readonly connection_file_exists: boolean;
  /** Python traceback when the driver failed (the report is then partial). */
  readonly error?: string;
}

/** A failed driver run; `report` is the partial report it printed (null when nothing parseable came out). */
export class RecipeFailure extends Error {
  readonly report: Partial<RecipeReport> | null;

  constructor(message: string, report: Partial<RecipeReport> | null) {
    super(message);
    this.name = "RecipeFailure";
    this.report = report;
  }
}

const lastJsonLine = (stdout: string): Partial<RecipeReport> | null => {
  try {
    return JSON.parse(stdout.trim().split(/\r?\n/u).at(-1) ?? "") as Partial<RecipeReport>;
  } catch {
    return null;
  }
};

export const connectionFileFor = (home: TempHome): string => join(home.work, "recipe", "connection.json");

/**
 * Writes the recipe and the driver into `home.work` and runs the driver with `<python> -I`. The driver is killed
 * after `timeoutMs` (its server is then stopped by the caller from the connection file).
 */
export const runRecipe = async (
  python: string,
  home: TempHome,
  config: RecipeConfig,
  timeoutMs = 90_000,
): Promise<RecipeReport> => {
  const module = join(home.work, "bea_http.py");
  const driver = join(home.work, "driver.py");
  await writeFile(module, await extractRecipe(), "utf8");
  await writeFile(driver, DRIVER, "utf8");
  const cfg = {
    module,
    bea_mjs: config.beaMjs,
    node: process.execPath,
    connection_file: connectionFileFor(home),
    launch: config.launch,
    fake_session: config.fakeSession,
    oversize: config.oversize,
    target: config.target ?? null,
  };
  const child = spawn(python, ["-I", driver, JSON.stringify(cfg)], {
    cwd: home.work,
    env: minimalEnv(home, { BEA_LOG_LEVEL: "warn" }),
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8").on("data", (text: string) => (stdout += text));
  child.stderr.setEncoding("utf8").on("data", (text: string) => (stderr += text));
  const timer = setTimeout(() => child.kill(), timeoutMs);
  const code = await new Promise<number | null>((resolve) => child.once("exit", resolve));
  clearTimeout(timer);
  const report = lastJsonLine(stdout);
  if (code !== 0 || report === null || report.error !== undefined) {
    const log = await readFile(join(home.work, "recipe", "server.log"), "utf8").catch(() => "");
    throw new RecipeFailure(`recipe driver exited ${String(code)}:\n${stderr}\n${stdout}\nserver.log:\n${log}`, report);
  }
  return report as RecipeReport;
};
