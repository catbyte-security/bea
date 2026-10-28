import type { ToolContract } from "../contracts/toolContract.js";
import { composeSignal } from "../domain/abort.js";
import type { BeaError } from "../domain/errors/beaError.js";
import { isBeaError } from "../domain/errors/beaError.js";
import {
  cancelled,
  inputError,
  inputErrorFromZod,
  internalError,
  providerTimeout,
  serverShuttingDown,
} from "../domain/errors/constructors.js";
import { specFor } from "../domain/errors/errorCatalog.js";
import { err, ok, type Result } from "../domain/result.js";
import type { BeaCore } from "./BeaApplication.js";
import type { AbortCause, HandlerContext, ProgressSink, Surface, ToolHandler } from "./handlerContext.js";

export interface InvokeOptions {
  readonly surface: Surface;
  /** Client cancellation (MCP ctx.mcpReq.signal, CLI SIGINT/SIGTERM controller). */
  readonly clientSignal: AbortSignal;
  readonly progress: ProgressSink;
  readonly requestId: string;
}

export type ToolOutput = Readonly<Record<string, unknown>>;

/** Lookup by name; the HandlerTable guarantees presence at compile time. */
export type HandlerLookup = (name: string) => ToolHandler<ToolContract> | undefined;

/**
 * CT-B3: UTF-8 bytes of the serialized arguments, measured before zod runs (a 60 MB argument object must be refused
 * cheaply, and no accepted input may exceed the stdio read buffer). JSON.stringify of a typical input is microseconds;
 * the measured cost at the call-model maximum is ~0.1 s per 10 MiB (CT M5).
 */
export const inputBytes = (raw: unknown): number => {
  try {
    return Buffer.byteLength(JSON.stringify(raw) ?? "", "utf8");
  } catch {
    return Number.POSITIVE_INFINITY; // cyclic or BigInt-bearing input: never from a JSON transport
  }
};

const mapThrown = (contract: ToolContract, cause: unknown, abort: AbortCause | null): BeaError => {
  if (abort?.kind === "client") return cancelled(contract.name, "client");
  if (abort?.kind === "deadline") return providerTimeout(contract.name, abort.budget_ms, "handler");
  if (abort?.kind === "shutdown") return serverShuttingDown(contract.name);
  if (isBeaError(cause)) return cause;
  return internalError(contract.name, cause);
};

/**
 * The single invocation pipeline (MCP, CLI one-shots, scenario steps):
 * size guard (contract.maxInputBytes) -> parse raw input with the contract (defaults applied here, SDK validation is
 * pass-through) -> "always" gate -> deadline + cancellation (composeSignal, disposed in finally) -> admission ->
 * handler -> output self-check -> log (name, ms, outcome code; never input).
 */
export const invokeTool = async (
  core: BeaCore,
  handlers: HandlerLookup,
  contract: ToolContract,
  raw: unknown,
  options: InvokeOptions,
): Promise<Result<ToolOutput, BeaError>> => {
  const started = core.clock.monoMs();
  const log = core.logger.child({ tool: contract.name, surface: options.surface, request: options.requestId });
  const result = await invokeInner(core, handlers, contract, raw, options, log);
  log.info("tool done", {
    ms: Math.round(core.clock.monoMs() - started),
    ok: result.ok,
    ...(result.ok ? {} : { code: specFor(result.error).code }),
    // S6 §10.9 #4: a client cancellation is on the record even when the handler still finished (an install whose
    // blocking wait was cut short is a successful install the client never saw)
    ...(options.clientSignal.aborted ? { aborted: "client" } : {}),
  });
  if (!result.ok && result.error._tag === "Internal") {
    const cause = result.error.cause;
    log.debug("internal error cause", { cause: cause instanceof Error ? cause : String(cause) });
  }
  return result;
};

const invokeInner = async (
  core: BeaCore,
  handlers: HandlerLookup,
  contract: ToolContract,
  raw: unknown,
  options: InvokeOptions,
  log: BeaCore["logger"],
): Promise<Result<ToolOutput, BeaError>> => {
  const size = inputBytes(raw);
  if (size > contract.maxInputBytes)
    return err(
      inputError(contract.name, [
        {
          path: "$",
          reason: "out_of_range",
          message: `The arguments are ${String(size)} bytes; ${contract.name} accepts at most ${String(contract.maxInputBytes)}. Split the batch (vector_offset), use generate or from_recording, or pass a CLI --input file per chunk.`,
          maximum: contract.maxInputBytes,
        },
      ]),
    );
  const parsed = contract.inputSchema.safeParse(raw);
  if (!parsed.success) return err(inputErrorFromZod(contract.name, raw, parsed.error));
  if (contract.gate?.scope === "always") {
    const gate = core.gates.require(contract.gate.id, contract.name);
    if (!gate.ok) return gate;
  }
  if (options.clientSignal.aborted) return err(cancelled(contract.name, "client"));
  const handler = handlers(contract.name);
  if (handler === undefined)
    return err({
      _tag: "CapabilityUnavailable",
      operation: contract.name,
      capability: "server",
      reason: "not-implemented",
      retryable: false,
    });

  const deadline = new AbortController();
  const deadlineAt = core.clock.monoMs() + contract.maxBlockingMs;
  const timer = setTimeout(() => deadline.abort(), contract.maxBlockingMs);
  const composed = composeSignal([options.clientSignal, deadline.signal, core.lifecycle.shutdownSignal]);
  const signal = composed.signal;
  const abortCause = (): AbortCause | null =>
    options.clientSignal.aborted
      ? { kind: "client" }
      : deadline.signal.aborted
        ? { kind: "deadline", budget_ms: contract.maxBlockingMs }
        : core.lifecycle.shutdownSignal.aborted
          ? { kind: "shutdown" }
          : null;
  const ctx: HandlerContext = {
    operation: contract.name,
    surface: options.surface,
    requestId: options.requestId,
    signal,
    abortCause,
    remainingMs: () => Math.max(0, Math.round(deadlineAt - core.clock.monoMs())),
    progress: options.progress,
    log,
    gates: core.gates,
  };
  try {
    const outcome = await core.admission.run(contract.name, async () => {
      try {
        return await handler(parsed.data, ctx);
      } catch (cause: unknown) {
        return err(mapThrown(contract, cause, abortCause()));
      }
    });
    if (!outcome.ok) return outcome;
    // Self-check: CLI and MCP see the same validated shape; the SDK's own output
    // validation then never produces its text-only error.
    const checked = contract.outputSchema.safeParse(outcome.value);
    if (!checked.success) {
      log.error("handler output violates its contract", { issues: checked.error.issues.length });
      return err({
        _tag: "Internal",
        operation: contract.name,
        diagnostics: { output_issue_count: checked.error.issues.length },
      });
    }
    return ok(checked.data);
  } finally {
    clearTimeout(timer);
    composed.dispose();
  }
};
