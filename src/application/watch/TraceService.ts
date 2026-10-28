// =================================================================================================
// src/application/watch/TraceService.ts — trace_execution (DESIGN §6.2 #24, D-INT-22, CT-M1; S6 §4.23; WP9-WATCH).
// Threads mode follows the given threads now; on_call follows the calling thread of the next N invocations. Only the
// named modules are recorded and all other loaded modules are Stalker-excluded (DESIGN §6.2; the exclusion is
// process-global and lasts for the session, A-30, so it is reported). The agent records; the host attributes
// functions from the images on disk when the trace finished within wait_ms.
// =================================================================================================
import type { z } from "zod";

import type { WATCH_TOOLS } from "../../contracts/areas/watch.js";
import type { AddressRef } from "../../domain/address/addressRef.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { inputError } from "../../domain/errors/constructors.js";
import { LIMITATIONS } from "../../domain/evidence/limitations.js";
import { formatHex } from "../../domain/hex.js";
import type { JsonObject } from "../../domain/json.js";
import { pathKey } from "../../domain/process/instance.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { LiveSession, OperationContext } from "../../ports/sessions.js";
import type { TraceStartParams, TraceStartResult } from "../../shared/agentProtocol.js";
import type { BeaApplication } from "../BeaApplication.js";
import { functionInterior, notFunctionStart } from "../address/functionStart.js";
import type { HandlerContext } from "../handlerContext.js";
import { liveOp } from "../sessionAccess.js";
import { attributeFunctions, readTraceBlocks } from "./blocks.js";
import type { LegendEntry, TraceDecoders } from "./decoders.js";
import { envelopeOf } from "./envelope.js";
import { completeInstall, waitForEnd, type InstallFlow, type Installed } from "./install.js";
import { CodeLocator } from "./locate.js";
import { moduleLegend } from "./WatchService.js";

type TraceContract = (typeof WATCH_TOOLS)[1];
export type TraceInput = z.output<TraceContract["inputSchema"]>;
export type TraceOutput = z.output<TraceContract["outputSchema"]>;

const AGENT_MODE: { readonly [M in TraceInput["mode"]]: TraceStartParams["mode"] } = {
  coverage: "coverage",
  block_counts: "block_counts",
  calls: "call_summary",
};

const basename = (path: string): string => path.split(/[\\/]/u).pop() ?? path;

/** Resolve the module names against the host's module map ($main = the main module); unknown names are refused. */
const resolveModules = (
  session: LiveSession,
  all: readonly LegendEntry[],
  names: readonly string[],
): { selected: LegendEntry[]; others: LegendEntry[] } | BeaError => {
  if (all.length === 0) return { selected: [], others: [] }; // no host map: the agent resolves the names itself
  const platform = process.platform === "win32" ? "win32" : "linux";
  const mainKey = pathKey(session.identity.image.path, platform);
  const selected: LegendEntry[] = [];
  for (const [i, name] of names.entries()) {
    const found =
      name === "$main"
        ? (all.find((e) => e[3] !== null && pathKey(e[3], platform) === mainKey) ??
          all.find((e) => e[0].toLowerCase() === basename(session.identity.image.path).toLowerCase()))
        : all.find((e) => e[0].toLowerCase() === name.toLowerCase());
    if (found === undefined)
      return inputError("trace_execution", [
        {
          path: `modules[${String(i)}]`,
          reason: "invalid_value",
          message: `Module ${name.slice(0, 64)} is not loaded; use list_modules for the loaded names, or $main.`,
        },
      ]);
    if (!selected.includes(found)) selected.push(found);
  }
  return { selected, others: all.filter((e) => !selected.includes(e)) };
};

/**
 * StalkerBusy with a short retry_after_ms: the thread is still settling after an earlier follow (S4 §12.4; e.g. a
 * list_threads register capture a moment ago). That is waited out once instead of refused; a thread another
 * instrument follows (retry_after_ms 0) is refused at once.
 */
const SETTLE_RETRY_MAX_MS = 1000;
const settlingMs = (e: BeaError): number | null => {
  if (e._tag !== "ResourceConstraint") return null;
  const ms = (e.limits as Readonly<Record<string, unknown>> | undefined)?.["retry_after_ms"];
  return typeof ms === "number" && ms > 0 && ms <= SETTLE_RETRY_MAX_MS ? ms : null;
};
const delay = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

interface TraceInstalled {
  readonly installed: Installed;
  readonly result: TraceStartResult;
  readonly legend: readonly LegendEntry[];
}

/** The resolved on_call function (address and runtime VA), or null in threads mode. */
interface OnCall {
  readonly ref: AddressRef;
  readonly va: bigint;
}

const resolveOnCall = async (
  app: BeaApplication,
  session: LiveSession,
  op: OperationContext,
  input: TraceInput,
): Promise<Result<OnCall | null, BeaError>> => {
  if (input.on_call === undefined) return ok(null);
  const space = { kind: "live", session } as const;
  const resolved = await app.services.address.resolve(space, input.on_call, op, {
    path: "on_call",
  });
  if (!resolved.ok) return resolved;
  // UX-1: on_call brackets the call with an entry/leave listener; inside a function body the leave listener would
  // corrupt the target (and never fire, leaving the thread followed with no events)
  const interior = await functionInterior(app.services.address, space, resolved.value.va);
  if (interior !== null)
    return err(notFunctionStart(op.name, "on_call", interior, " as on_call, or trace the thread in threads mode"));
  return ok({ ref: resolved.value.ref, va: resolved.value.va });
};

const startParams = (
  session: LiveSession,
  input: TraceInput,
  modules: { readonly selected: readonly LegendEntry[]; readonly others: readonly LegendEntry[] },
  onCall: OnCall | null,
): TraceStartParams => ({
  ...(input.thread_ids === undefined ? {} : { threads: [...input.thread_ids] }),
  ...(onCall === null ? {} : { on_call: { target: { va: formatHex(onCall.va) }, invocations: input.invocations } }),
  mode: AGENT_MODE[input.mode],
  modules: modules.selected.length > 0 ? modules.selected.map((e) => e[0]) : [...input.modules],
  exclude_modules: modules.others.map((e) => e[0]),
  lifetime: {
    duration_ms: input.duration_ms,
    max_hits: input.max_events,
    clock: session.paused ? "resume" : "install",
  },
});

/** What the agent started, for the recording, effect, evidence and result builders below. */
interface Started {
  readonly input: TraceInput;
  readonly onCall: OnCall | null;
  readonly legend: readonly LegendEntry[];
  readonly result: TraceStartResult;
}

const decodersOf = (s: Started, instanceId: TraceDecoders["instance_id"]): JsonObject => {
  const decoders: TraceDecoders = {
    v: 1,
    kind: "trace",
    mode: s.input.mode,
    layout: s.result.row_kind,
    on_call: s.onCall === null ? null : formatHex(s.onCall.va),
    invocations: s.input.invocations,
    threads: [...s.result.threads],
    modules: s.legend,
    instance_id: instanceId,
  };
  return { ...decoders, modules: s.legend.map((e) => [...e]) } as unknown as JsonObject;
};

const limitationsOf = (s: Started): string[] => {
  const limitations: string[] = [LIMITATIONS.NOT_OBSERVED_WINDOW, LIMITATIONS.TRACE_DYNAMIC_BLOCKS];
  if (s.onCall !== null) limitations.push(LIMITATIONS.TRACE_ENTRY_SYNTHESIZED);
  if (s.result.excluded.length > 0) limitations.push(LIMITATIONS.TRACE_EXCLUDED_MODULES(s.result.excluded.length));
  return limitations;
};

const effectOf = (s: Started): InstallFlow["effect"] => {
  const target = s.onCall?.ref ?? null;
  return {
    kind: "trace-following",
    target: {
      address:
        target === null
          ? null
          : {
              va: target.va,
              module_map_id: target.module_map_id,
              module_key: target.module?.toLowerCase() ?? null,
              rva: target.rva,
            },
      size: null,
      threads: s.input.thread_ids === undefined ? null : [...s.input.thread_ids],
    },
    parameters: {
      mode: s.input.mode,
      modules: s.legend.map((e) => e[0]),
      invocations: s.onCall === null ? null : s.input.invocations,
      excluded: s.result.excluded.length,
    },
    display:
      target === null
        ? null
        : target.module === null || target.rva === null
          ? target.va
          : `${target.module}+${target.rva}`,
  };
};

const resultOf =
  (s: Started): InstallFlow["result"] =>
  (ids) => ({
    recording_id: ids.recordingId,
    kind: "trace",
    mode: s.input.mode,
    on_call: (s.onCall?.ref ?? null) as unknown as JsonObject | null,
    invocations: s.onCall === null ? null : s.input.invocations,
    followed_threads: [...s.result.threads],
    modules: s.legend.map((e) => e[0]),
    excluded_modules: s.result.excluded.length,
    queue: { ...s.result.queue },
    row_kind: s.result.row_kind,
    stream_id: ids.streamId,
    effect_id: ids.effectId,
    agent: { instrument_id: s.result.instrument_id, stream_id: s.result.stream_id },
  });

const install = async (
  app: BeaApplication,
  session: LiveSession,
  op: OperationContext,
  input: TraceInput,
): Promise<Result<TraceInstalled, BeaError>> => {
  const onCall = await resolveOnCall(app, session, op, input);
  if (!onCall.ok) return onCall;
  const modules = resolveModules(session, moduleLegend(app, session), input.modules);
  if ("_tag" in modules) return { ok: false, error: modules };
  const params = startParams(session, input, modules, onCall.value);
  let started = await session.agent.call("traceStart", params, { op });
  const settling = started.ok ? null : settlingMs(started.error);
  if (settling !== null && op.deadline.remaining() > settling + 1000) {
    await delay(settling + 25);
    started = await session.agent.call("traceStart", params, { op });
  }
  if (!started.ok) return started;
  const s: Started = { input, onCall: onCall.value, legend: modules.selected, result: started.value };
  const installed = await completeInstall(app, session, op, {
    tool: "trace_execution",
    kind: "trace",
    agentInstrumentId: s.result.instrument_id,
    agentStream: s.result.stream_id,
    encoding: {
      kind: "fixed-records",
      row_kind: s.result.row_kind,
      record_bytes: s.result.layout.rec_bytes,
      fields: s.result.layout.fields,
    },
    decoders: decodersOf(s, session.instanceId),
    effect: effectOf(s),
    durationMs: input.duration_ms,
    maxEvents: input.max_events,
    input: input as unknown as JsonObject,
    target: s.onCall === null ? null : { ref: s.onCall.ref, size: null },
    limitations: limitationsOf(s),
    capture: app.services.evidence.instances.capture(session.instanceId),
    result: resultOf(s),
  });
  if (!installed.ok) return installed;
  return ok({ installed: installed.value, result: s.result, legend: s.legend });
};

/** The finished summary with what the host knows best: the installed mode and threads, and functions from disk. */
const enrichSummary = async (
  app: BeaApplication,
  ctx: HandlerContext,
  { input, done, summary }: { input: TraceInput; done: TraceInstalled; summary: JsonObject },
): Promise<{ summary: JsonObject; unresolved: number }> => {
  const base: JsonObject = { ...summary, mode: input.mode, threads: [...done.result.threads] };
  if (input.mode === "calls") return { summary: base, unresolved: 0 };
  let unresolved = 0;
  const functions = await liveOp(
    app,
    ctx,
    input.session_id,
    { mode: "concurrent", need: "host" },
    async (_session, op) => {
      const read = await readTraceBlocks(app.services.recordings, done.installed.recording.id, op);
      if (!read.ok) return read;
      const locator = new CodeLocator(app.services.pe.images, op.signal);
      const attributed = await attributeFunctions(locator, done.legend, read.value.blocks, read.value.firstSeq);
      unresolved = attributed.unresolved;
      return ok(attributed.functions.map((f) => ({ ...f })));
    },
  );
  return { summary: functions.ok ? { ...base, functions: functions.value } : base, unresolved };
};

export const traceExecution = async (
  app: BeaApplication,
  input: TraceInput,
  ctx: HandlerContext,
): Promise<Result<TraceOutput, BeaError>> => {
  const done = await liveOp(app, ctx, input.session_id, { mode: "exclusive", need: "agent" }, (session, op) =>
    install(app, session, op, input),
  );
  if (!done.ok) return done;
  const recording = done.value.installed.recording;
  await waitForEnd(app, ctx, recording, input.wait_ms);
  const view = recording.view();
  const enriched =
    view.summary === undefined
      ? null
      : await enrichSummary(app, ctx, { input, done: done.value, summary: view.summary });
  const limitations =
    enriched !== null && enriched.unresolved > 0 ? [LIMITATIONS.TRACE_FUNCTIONS_UNRESOLVED(enriched.unresolved)] : [];
  const finished = view.state !== "active";
  return ok({
    ...envelopeOf(done.value.installed.evidence, { limitations }),
    instrument: { ...view, ...(enriched === null ? {} : { summary: enriched.summary }) },
    followed_threads: [...done.value.result.threads],
    ...(finished && input.mode !== "calls"
      ? {
          next: [
            {
              tool: "export_coverage",
              arguments: { recording_id: recording.id },
              reason: "Write the recorded blocks as a drcov file for Lighthouse or Cartographer.",
            },
          ],
        }
      : {}),
  } as TraceOutput);
};
