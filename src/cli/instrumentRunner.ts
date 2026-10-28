import type { ToolOutput } from "../application/invokeTool.js";
import type { ToolContract } from "../contracts/toolContract.js";
import type { BeaError } from "../domain/errors/beaError.js";
import { cancelled, internalError } from "../domain/errors/constructors.js";
import { projectBeaError } from "../domain/errors/projection.js";
import { isJsonObject } from "../domain/json.js";
import { err, ok, type Result } from "../domain/result.js";
import { inputFieldsOf, type CliRun } from "./runtime.js";

/** After the recording's duration has elapsed the agent still has to end it and flush; give it this long. */
export const INSTRUMENT_GRACE_MS = 5_000;
/** S6 §2.5 default `duration_ms`. */
const DEFAULT_DURATION_MS = 10_000;
/** No input may wait longer than this (S6 §2.5, HARD_LIMITS.maxWaitMs). */
const MAX_WAIT_MS = 60_000;

export type StopReason = "finished" | "target_exited" | "duration" | "signal" | "wait_failed";

/** What one instrument one-shot prints (field names: S6 §8.1 / S1 §7.4). */
export interface InstrumentDocument {
  readonly instrument: ToolOutput;
  readonly stop_reason: StopReason;
  /** The last `wait` answer, `{error}` when the first wait failed, null when none ran. */
  readonly wait: unknown;
  /** `query_events {view:"summary"}`, or `{error}` when it failed. */
  readonly summary: unknown;
  /** `stop_instrumentation`, or `{error}` when it failed. */
  readonly stopped: unknown;
}

export interface InstrumentOutcome {
  readonly result: Result<InstrumentDocument, BeaError>;
  /** true when the document was printed but a follow-up step failed (exit 1). */
  readonly degraded: boolean;
}

/** Adds `session_id` only to contracts that have the field (the scenario injection rule, D-INT-47). */
export const withSession = (
  run: CliRun,
  tool: string,
  input: Readonly<Record<string, unknown>>,
  sessionId: string,
): Readonly<Record<string, unknown>> => {
  const contract = run.findContract(tool);
  if (contract === undefined || !inputFieldsOf(contract).has("session_id") || "session_id" in input) return input;
  return { session_id: sessionId, ...input };
};

const recordingIdOf = (install: ToolOutput): string | null => {
  const instrument = install["instrument"];
  if (!isJsonObject(instrument)) return null;
  const id = instrument["recording_id"];
  return typeof id === "string" ? id : null;
};

const durationOf = (contract: ToolContract, input: Readonly<Record<string, unknown>>): number => {
  const parsed = contract.inputSchema.safeParse(input);
  const value = parsed.success ? parsed.data["duration_ms"] : undefined;
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? value : DEFAULT_DURATION_MS;
};

/** A wait result whose recordings carry no `summary` (printed once by the follow-up query_events). */
const withoutRecordingSummaries = (wait: ToolOutput): ToolOutput => {
  const recordings = wait["recordings"];
  if (!Array.isArray(recordings)) return wait;
  return {
    ...wait,
    recordings: recordings.map((r) => {
      if (!isJsonObject(r)) return r;
      const { summary: _digest, ...rest } = r;
      return rest;
    }),
  };
};

const errorDocument = (error: BeaError): { readonly error: ReturnType<typeof projectBeaError> } => ({
  error: projectBeaError(error),
});

/**
 * instrument-oneshot (S1 §7.4): install (on a spawned target: before its first instruction) → resume if spawned →
 * `wait {until:"done"}` until the recording finished, the target exited, or its duration (which starts at resume,
 * CI-I3) plus a grace period elapsed → `query_events` summary → `stop_instrumentation`. The caller closes the session.
 */
export const runInstrument = async (
  run: CliRun,
  contract: ToolContract,
  input: Readonly<Record<string, unknown>>,
  sessionId: string,
  spawned: boolean,
  now: () => number = () => performance.now(),
): Promise<InstrumentOutcome> => {
  const install = await run.call(contract.name, input);
  if (!install.ok) return { result: install, degraded: false };
  const recordingId = recordingIdOf(install.value);
  if (recordingId === null)
    return {
      result: err(internalError(contract.name, new Error("instrument output carries no instrument.recording_id"))),
      degraded: false,
    };
  if (spawned) {
    const resumed = await run.call("resume_process", withSession(run, "resume_process", {}, sessionId));
    if (!resumed.ok) return { result: resumed, degraded: false };
  }
  const deadline = now() + durationOf(contract, input) + INSTRUMENT_GRACE_MS;
  let last: ToolOutput | null = null;
  let stopReason: StopReason = "duration";
  let waitError: BeaError | null = null;
  while (!run.signal.aborted) {
    const remaining = Math.round(deadline - now());
    if (remaining <= 0) break;
    const waited = await run.call(
      "wait",
      withSession(
        run,
        "wait",
        { until: "done", ids: [recordingId], timeout_ms: Math.min(remaining, MAX_WAIT_MS) },
        sessionId,
      ),
    );
    if (!waited.ok) {
      waitError = waited.error;
      stopReason = "wait_failed";
      break;
    }
    last = waited.value;
    if (waited.value["satisfied"] === true) {
      stopReason = "finished";
      break;
    }
    if (waited.value["reason"] === "target_exited") {
      stopReason = "target_exited";
      break;
    }
  }
  // The session close that follows reverts every hook; a signal skips the follow-up queries.
  if (run.signal.aborted) return { result: err(cancelled(contract.name, "signal")), degraded: false };
  const summary = await run.call(
    "query_events",
    withSession(run, "query_events", { recording_id: recordingId, view: "summary" }, sessionId),
  );
  const stopped = await run.call(
    "stop_instrumentation",
    withSession(run, "stop_instrumentation", { ids: [recordingId] }, sessionId),
  );
  // ONBOARD-7: the digest is printed once (the summary query); the wait result's recordings drop their copy of it
  const waited = summary.ok && last !== null ? withoutRecordingSummaries(last) : last;
  return {
    result: ok({
      instrument: install.value,
      stop_reason: stopReason,
      wait: waited ?? (waitError === null ? null : errorDocument(waitError)),
      summary: summary.ok ? summary.value : errorDocument(summary.error),
      stopped: stopped.ok ? stopped.value : errorDocument(stopped.error),
    }),
    degraded: waitError !== null || !summary.ok || !stopped.ok,
  };
};
