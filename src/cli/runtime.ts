import { readFile, rm, rmdir, stat } from "node:fs/promises";

import type { BeaApplication } from "../application/BeaApplication.js";
import { createApplication } from "../application/createApplication.js";
import type { ProgressSink, Surface } from "../application/handlerContext.js";
import { silentProgress } from "../application/handlerContext.js";
import { invokeTool, type HandlerLookup, type ToolOutput } from "../application/invokeTool.js";
import type { CloseReport } from "../application/lifecycle.js";
import type { ToolContract } from "../contracts/toolContract.js";
import { loadConfig, type BeaConfig } from "../domain/config.js";
import type { BeaError, BeaErrorOf } from "../domain/errors/beaError.js";
import { createLogger } from "../domain/logger.js";
import { err, type Result } from "../domain/result.js";
import type { CliDeps, CliHost, CliSignal, OutputFormat } from "./io.js";
import { EXIT, progressLine, renderDocument, renderError } from "./output.js";

const SIGNAL_STATUS: { readonly [S in CliSignal]: number } = { SIGINT: EXIT.sigint, SIGTERM: EXIT.sigterm };

const errorCode = (cause: unknown): string | undefined =>
  typeof cause === "object" && cause !== null ? (Reflect.get(cause, "code") as string | undefined) : undefined;

/** config.json reader for loadConfig: null when absent (doctor and one-shots never create BEA_HOME). */
export const readOptionalText = async (path: string): Promise<string | null> => {
  try {
    return await readFile(path, "utf8");
  } catch (cause: unknown) {
    if (errorCode(cause) === "ENOENT" || errorCode(cause) === "ENOTDIR") return null;
    throw cause;
  }
};

export const loadCliConfig = (host: CliHost): Promise<Result<BeaConfig, BeaErrorOf<"ConfigurationError">>> =>
  loadConfig({
    env: host.env,
    platform: host.platform,
    accountHome: host.accountHome,
    readConfigFile: readOptionalText,
  });

/** The document channel: exactly one document per command (S1 §7.6). */
export const printDocument = (host: CliHost, value: unknown, format: OutputFormat): void =>
  host.io.stdout(renderDocument(value, format, host.io.stdoutIsTty));

export const printError = (host: CliHost, error: BeaError, format: OutputFormat): void =>
  host.io.stdout(renderError(error, format, host.io.stdoutIsTty));

/** `--json` anywhere before `--` selects JSON even when argv parsing fails (the error document honours it). */
export const formatFromArgv = (argv: readonly string[]): OutputFormat => {
  const split = argv.indexOf("--");
  return (split === -1 ? argv : argv.slice(0, split)).includes("--json") ? "json" : "toon";
};

/** --progress / `bea run`: JSON-lines on stderr, at most one per 100 ms unless final. */
export const stderrProgress = (
  host: CliHost,
  tool: string,
  now: () => number = () => performance.now(),
): ProgressSink => {
  let seq = 0;
  let last = Number.NEGATIVE_INFINITY;
  return {
    report: (phase, message, final = false) => {
      const at = now();
      if (!final && at - last < 100) return;
      last = at;
      seq += 1;
      host.stderr(progressLine(tool, seq, phase, message));
    },
  };
};

export const notImplementedTool = (name: string): BeaErrorOf<"CapabilityUnavailable"> => ({
  _tag: "CapabilityUnavailable",
  operation: name,
  capability: "server",
  reason: "not-implemented",
  retryable: false,
});

export type ToolCall = (
  name: string,
  input: Readonly<Record<string, unknown>>,
) => Promise<Result<ToolOutput, BeaError>>;

/** One application for one CLI command (MCP keeps one per process; the CLI builds one per invocation). */
export interface CliRun {
  readonly app: BeaApplication;
  /** Client cancellation: aborted by SIGINT/SIGTERM (and, for scenarios, the total time limit). */
  readonly signal: AbortSignal;
  /** Every step is a public contract through invokeTool (MCP-identical validation and errors). */
  readonly call: ToolCall;
  /**
   * Teardown calls (close_session, export_evidence): a signal that is never the client's, so cleanup still runs after
   * SIGINT (invokeTool refuses work under an aborted client signal).
   */
  readonly cleanupCall: ToolCall;
  /** 130 / 143 once a signal arrived. */
  readonly signalStatus: () => number | undefined;
  readonly findContract: (name: string) => ToolContract | undefined;
  /**
   * lifecycle.closeAll("cli-exit") + signal unregistration, then the ephemeral run directory is deleted unless the run
   * is kept (S2 §9.2). Idempotent.
   */
  readonly close: () => Promise<CloseReport>;
}

/** Keeps the CLI run's evidence directory after exit (S2 §9.2); one-shots and `bea run` accept it. */
export const KEEP_RUN_FLAG = "--keep-run";

export interface OpenRunOptions {
  readonly surface: Surface;
  readonly progress: (tool: string) => ProgressSink;
  /** Extra cancellation sources (scenario total_ms). */
  readonly abortOn?: AbortSignal;
  /** `--keep-run`, or an evidence bundle was requested (it lives in the run's exports): the run directory stays. */
  readonly keepRun?: boolean;
}

const exists = async (path: string): Promise<boolean> => {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
};

/**
 * S2 §9.2: a CLI run (`kind:"cli"`) is deleted at exit unless it is kept. Deletes exactly `<runs>/<this run id>`, after
 * lifecycle.closeAll finalized it; callers skip it when the close failed (the run stays for `bea status` and
 * diagnosis). `pruneIfEmpty` (doctor, which must leave nothing behind) lists directories this command created, deepest
 * first; each is removed only if it is empty again (rmdir never removes a non-empty directory).
 */
export const discardCliRun = async (
  host: Pick<CliHost, "stderr">,
  config: BeaConfig,
  runId: string,
  pruneIfEmpty: readonly string[] = [],
): Promise<void> => {
  const dir = config.layout.runDir(runId);
  try {
    // maxRetries: Windows can report EBUSY/EPERM for a moment after the last handle closed.
    await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  } catch (cause: unknown) {
    host.stderr(`bea: could not delete the run directory ${dir} (${errorCode(cause) ?? "error"}).\n`);
    return;
  }
  for (const path of pruneIfEmpty) {
    try {
      await rmdir(path);
    } catch {
      // not empty (something else lives there) or already gone: leave it
    }
  }
};

/**
 * The BEA_HOME directories a doctor probe may create (runs/ for the probe's evidence, emu/ as the bridge's working
 * directory, cache/), BEA_HOME last, that do not exist yet: doctor prunes them again when they are empty.
 */
export const missingHomeDirs = async (config: BeaConfig): Promise<readonly string[]> => {
  const candidates = [config.layout.runsDir, config.layout.emuDir, config.layout.cacheDir, config.layout.root];
  const present = await Promise.all(candidates.map(exists));
  return candidates.filter((_, index) => present[index] !== true);
};

export const openCliRun = async (deps: CliDeps, config: BeaConfig, options: OpenRunOptions): Promise<CliRun> => {
  const logger = createLogger({ level: config.logLevel.value, write: deps.stderr });
  const app = await createApplication({ config, logger, transport: "cli", services: deps.services });
  const handlers: HandlerLookup = deps.createHandlers(app);
  const byName = new Map(deps.contracts.map((contract) => [contract.name, contract]));
  const client = new AbortController();
  let status: number | undefined;
  const listeners = (["SIGINT", "SIGTERM"] as const).map((signal) => {
    const listener = (): void => {
      status ??= SIGNAL_STATUS[signal];
      client.abort({ kind: "signal", signal });
    };
    deps.signals.on(signal, listener);
    return [signal, listener] as const;
  });
  const onExtra = (): void => client.abort({ kind: "limit" });
  options.abortOn?.addEventListener("abort", onExtra, { once: true });
  if (options.abortOn?.aborted === true) client.abort({ kind: "limit" });
  const cleanupSignal = new AbortController().signal;
  const invoke =
    (signal: AbortSignal, requestId: string): ToolCall =>
    async (name, input) => {
      const contract = byName.get(name);
      if (contract === undefined) return err(notImplementedTool(name));
      return invokeTool(app, handlers, contract, input, {
        surface: options.surface,
        clientSignal: signal,
        progress: options.progress(name),
        requestId,
      });
    };
  let closing: Promise<CloseReport> | undefined;
  return {
    app,
    signal: client.signal,
    call: invoke(client.signal, "cli"),
    cleanupCall: invoke(cleanupSignal, "cli-cleanup"),
    signalStatus: () => status,
    findContract: (name) => byName.get(name),
    close: () =>
      (closing ??= (async () => {
        let report: CloseReport;
        try {
          report = await app.lifecycle.closeAll("cli-exit");
        } finally {
          for (const [signal, listener] of listeners) deps.signals.off(signal, listener);
          options.abortOn?.removeEventListener("abort", onExtra);
        }
        const runDir = config.layout.runDir(app.run.runId);
        if (options.keepRun !== true && report.ok) await discardCliRun(deps, config, app.run.runId);
        else if (await exists(runDir)) deps.stderr(`bea: evidence run kept: ${runDir}\n`);
        return report;
      })()),
  };
};

export const progressFor =
  (host: CliHost, enabled: boolean) =>
  (tool: string): ProgressSink =>
    enabled ? stderrProgress(host, tool) : silentProgress;

/** Input field names of a contract (roots are z.ZodObject; defineTool enforces it). */
export const inputFieldsOf = (contract: ToolContract): ReadonlySet<string> => {
  const shape = Reflect.get(contract.inputSchema, "shape") as Readonly<Record<string, unknown>> | undefined;
  return new Set(Object.keys(shape ?? {}));
};

/** stderr note when cleanup failed after the document was printed. */
export const reportCleanup = (host: CliHost, report: CloseReport): void => {
  if (report.ok) return;
  const failed = report.phases.flatMap((phase) => phase.failed.map((f) => `${phase.phase}/${f.closer}`));
  host.stderr(`bea: cleanup incomplete (${failed.join(", ") || "phase timeout"}); run \`bea status\` to inspect.\n`);
};
