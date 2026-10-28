import type { z } from "zod";

import {
  captureFieldName,
  QUERY_CELL_CHARS,
  QUERY_MAX_COLUMNS,
  type INSTRUMENT_TOOLS,
} from "../../contracts/areas/instrument.js";
import { compactOf } from "../../domain/time.js";
import { Deadline } from "../../domain/deadline.js";
import { COMPLETE, type Coverage, type ReasonCode } from "../../domain/evidence/coverage.js";
import { LIMITATIONS } from "../../domain/evidence/limitations.js";
import type { BeaEvidence } from "../../domain/evidence/record.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { cancelled, inputError, providerTimeout, referenceNotFound } from "../../domain/errors/constructors.js";
import type { EvId, FxId, PiId, StId } from "../../domain/ids.js";
import type { JsonObject, JsonValue } from "../../domain/json.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { AddressSpace } from "../../ports/address.js";
import type { EvidenceRuntime, RecordedEvidence, StreamRecord, StreamSpec } from "../../ports/evidence.js";
import type { HandleKindSpec } from "../../ports/handles.js";
import type { EventField, EventRecord, InstrumentStateView, Recording } from "../../ports/recordings.js";
import type { LiveSession, OperationContext, SessionState, WaitCondition } from "../../ports/sessions.js";
import type { ArgCapture, HookInstallParams, HookInstallResult, ValueType } from "../../shared/agentProtocol.js";
import { BINARY_LAYOUTS } from "../../shared/binaryLayouts.js";
import type { BeaApplication } from "../BeaApplication.js";
import type { HandlerContext, HandlersFor } from "../handlerContext.js";
import { RECORDING_KINDS } from "../instruments/kinds/index.js";
import { hookFieldsOf, parseHookDecoders, type HookDecoders, type HookFieldType } from "../instruments/kinds/hook.js";
import {
  availableFields,
  fieldsOfRow,
  runQuery,
  STREAM_BASE_FIELDS,
  validateQuery,
  type QueryPage,
  type QueryRequest,
} from "../instruments/QueryEngine.js";
import { agentStateError, liveOp } from "../sessionAccess.js";
import { functionInterior, notFunctionStart } from "../address/functionStart.js";
import { abortedAfter, detachedOp, INSTALL_RPC_MS } from "../instruments/installOp.js";

/**
 * Handlers for area instrument (WP7-HOOK): hook_function, wait, stop_instrumentation, query_events (DESIGN §6.2 E).
 * Sessions are reached only through sessionAccess (D-INT-40); recordings through RecordingRegistry (WP1); scan and
 * write handles through HandleRegistry (CI-B6). Agent free text never enters results or errors (CT-M8).
 */
type Tools = typeof INSTRUMENT_TOOLS;
type ToolOf<N extends Tools[number]["name"]> = Extract<Tools[number], { readonly name: N }>;
type In<N extends Tools[number]["name"]> = z.output<ToolOf<N>["inputSchema"]>;
type Out<N extends Tools[number]["name"]> = z.output<ToolOf<N>["outputSchema"]>;

/** Per-session caps (S6 §2.5). */
export const MAX_INSTRUMENTS_PER_SESSION = 16;
const WAIT_SLICE_MS = 250;
const SETTLE_POLL_MS = 25;
/** After the target is gone, how long a done/events wait lets its recordings end (bounded by timeout_ms). */
const EXIT_SETTLE_MS = 2000;

// ---------------------------------------------------------------------------------------------- envelope
const envelopeOf = (record: BeaEvidence) => ({
  evidence_id: record.evidence_id,
  predicate_type: record.predicate_type,
  confidence: record.confidence,
  authority: record.authority,
  coverage: record.coverage,
  limitations: [...record.limitations],
  ...(record.subject?.kind === "process-instance"
    ? {
        instance_id: record.subject.instance_id,
        ...(record.subject.module_map_id !== null ? { module_map_id: record.subject.module_map_id } : {}),
      }
    : {}),
  ...(record.observed_at !== null ? { observed_at: compactOf(record.observed_at) } : {}),
  perturbation: {
    level: record.perturbation.level,
    active_effect_ids: [...record.perturbation.active_effect_ids],
    tainted: record.perturbation.tainted_by.length > 0,
  },
  ...(record.effects.length > 0 ? { effects_applied: [...record.effects] } : {}),
  ...(record.redactions.length > 0 ? { redactions: record.redactions.length } : {}),
});

const FROZEN_PROVIDER = { id: "frida", name: "frida", version: null } as const;

// ---------------------------------------------------------------------------------------------- query parents
/** The newest evidence row matching exact summary filters (rows come in ledger order), or null. */
const latestEvidence = (ev: EvidenceRuntime, filters: JsonObject): EvId | null => {
  const first = ev.query.summary({ entity: "evidence", filters, offset: 0, limit: 1 });
  const matching = first.ok ? first.value["matching"] : undefined;
  if (typeof matching !== "number" || matching < 1) return null;
  const last = ev.query.summary({ entity: "evidence", filters, offset: matching - 1, limit: 1 });
  const rows = last.ok ? last.value["rows"] : undefined;
  const row = Array.isArray(rows) ? rows[0] : undefined;
  const id = typeof row === "object" && row !== null && !Array.isArray(row) ? row["evidence_id"] : undefined;
  return typeof id === "string" && id.startsWith("ev_") ? (id as EvId) : null;
};

/**
 * The parent a derived bea.events.query record cites (S2 §7.1 invariant 6: derived records link their parents;
 * DESIGN §6.2 #21 links the stream manifest). Integrator fix (implement stage, WP9 change request): the record had no
 * link, so the Recorder refused every query. First match wins: the stream's newest bea.stream.manifest (ended or
 * checkpointed streams); the bea.instrument.install that applied the recording's effect (an active instrument whose
 * stream has no manifest yet); the instance's bea.process.instance (built-in recordings); for a host row stream with
 * no process behind it (emu_call batch/sweep, diff_function: no manifest, S5 §11.3) the record that produced it
 * (WP14 change request, option B). Empty when none exists: the record then fails as before.
 */
/** Predicates whose records produce instance-less host row streams (the stream id is in their result). */
const HOST_STREAM_PRODUCERS = ["bea.emu.batch", "bea.emu.sweep", "bea.diff"] as const;

const queryParents = (
  ev: EvidenceRuntime,
  source: { readonly streamId: StId | null; readonly effectId: FxId | null; readonly instanceId: PiId | null },
): EvId[] => {
  const candidates: JsonObject[] = [];
  if (source.streamId !== null) candidates.push({ predicate_type: "bea.stream.manifest", stream_id: source.streamId });
  if (source.effectId !== null)
    candidates.push({ predicate_type: "bea.instrument.install", applied_effect_id: source.effectId });
  if (source.instanceId !== null)
    candidates.push({ predicate_type: "bea.process.instance", instance_id: source.instanceId });
  if (source.streamId !== null)
    for (const producer of HOST_STREAM_PRODUCERS)
      candidates.push({ predicate_type: producer, stream_id: source.streamId });
  for (const filters of candidates) {
    const id = latestEvidence(ev, filters);
    if (id !== null) return [id];
  }
  return [];
};

/** InstrumentStateView → the tool's InstrumentState (summary attached when finished). */
const stateOf = async (app: BeaApplication, rec: Recording, op: OperationContext): Promise<InstrumentStateView> => {
  const view = rec.view();
  if (view.state === "active" || view.summary !== undefined) return view;
  const summary = await app.services.recordings.summary(rec.id, op);
  return summary.ok ? { ...view, summary: summary.value } : view;
};
const publicState = (v: InstrumentStateView) => ({
  recording_id: v.recording_id,
  kind: v.kind,
  state: v.state,
  events: v.events,
  dropped: v.dropped,
  ends_in_ms: v.state === "active" ? v.ends_in_ms : null,
  end_reason: v.end_reason,
  ...(v.summary !== undefined ? { summary: v.summary } : {}),
});

/** InstrumentState without its digest (query_events pages: the digest is view:"summary"'s top-level `summary`). */
const withoutSummary = (state: ReturnType<typeof publicState>): ReturnType<typeof publicState> => {
  const { summary: _digest, ...lean } = state;
  return lean;
};

const delay = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** A recording of this session (rec_ ids are run-unique; another session's id is "not found" here). */
const recordingOf = (
  app: BeaApplication,
  operation: string,
  session: LiveSession,
  id: string,
): Result<Recording, BeaError> => {
  const rec = app.services.recordings.get(id);
  return rec === undefined || rec.create.sessionId !== session.id
    ? err(referenceNotFound(operation, "recording", id))
    : ok(rec);
};
const handleOf = (
  app: BeaApplication,
  operation: string,
  session: LiveSession,
  id: string,
): Result<HandleKindSpec, BeaError> => {
  const spec = app.services.handles.find(id);
  const view = spec?.get(id);
  return spec === undefined || view === undefined || view.sessionId !== session.id
    ? err(referenceNotFound(operation, id.startsWith("scan_") ? "scan" : "effect", id))
    : ok(spec);
};
const isInstrument = (rec: Recording): boolean => rec.create.agentInstrumentId !== null;
const activeInstruments = (app: BeaApplication, session: LiveSession): Recording[] =>
  app.services.recordings.list(session.id).filter((r) => isInstrument(r) && r.view().state === "active");

// ---------------------------------------------------------------------------------------------- hook plan (pure)
const agentType = (t: string): ValueType => (t === "bool" ? "bool8" : (t as ValueType));
const isFloat = (t: string): boolean => t === "f32" || t === "f64";
const isTextOrBytes = (t: string): boolean => t === "utf8" || t === "utf16" || t === "bytes";
const NATIVE_SLOT_INT = ["rcx", "rdx", "r8", "r9"] as const;

/**
 * Tool input → agent HookInstallParams + the recording decoders (pure; unit-tested). `when:"both"` becomes two agent
 * captures (enter and leave). Capture class rule (DESIGN §6.2 #18): an f32/f64 `arg` without deref reads xmm<i> /
 * the stack slot; everything else reads the integer register / stack slot.
 */
export function buildHookPlan(
  input: In<"hook_function">,
  va: bigint,
  paused: boolean,
): { readonly params: HookInstallParams; readonly decoders: HookDecoders } {
  const args: ArgCapture[] = [];
  const cells: { field: string; type: HookFieldType }[] = [];
  const native: HookDecoders["native"][number][] = [];
  for (const c of input.capture) {
    const name = captureFieldName(c);
    const when = c.when;
    const phases: ("enter" | "leave")[] = when === "both" ? ["enter", "leave"] : [when];
    for (const at of phases) {
      const field = at === "leave" ? `${name}@leave` : name;
      const cap: ArgCapture = {
        name: field.slice(0, 32),
        type: agentType(c.type),
        at,
        ...(c.arg !== undefined
          ? { slot: c.arg, class: isFloat(c.type) && c.deref === undefined ? ("float" as const) : ("int" as const) }
          : {}),
        ...(c.reg !== undefined ? { reg: c.reg } : {}),
        ...(c.deref !== undefined ? { deref: [...c.deref] } : {}),
        ...(c.count !== undefined ? (isTextOrBytes(c.type) ? { max_len: c.count } : { count: c.count }) : {}),
      };
      args.push(cap);
      cells.push({ field, type: c.type });
    }
    if (input.engine === "native") {
      const source =
        c.reg !== undefined
          ? c.reg
          : c.arg !== undefined && c.arg >= 4
            ? `s${String(c.arg)}`
            : c.arg !== undefined && isFloat(c.type)
              ? `xmm${String(c.arg)}`
              : NATIVE_SLOT_INT[c.arg ?? 0];
      native.push({ field: name, type: c.type, source: source as HookDecoders["native"][number]["source"] });
    }
  }
  const hasLeave = input.returns !== "void" || input.capture.some((c) => c.when !== "enter");
  const maxHits = Math.min(input.max_events * input.sample_every, 100_000_000);
  const params: HookInstallParams = {
    target: { va: `0x${va.toString(16)}` },
    engine: input.engine,
    relocation: "auto",
    capture: {
      args,
      ret: input.returns === "void" ? null : { type: agentType(input.returns) },
      backtrace: input.backtrace > 0 ? { depth: input.backtrace, max_per_sec: 100 } : null,
      registers: "none",
    },
    emit: hasLeave ? "leave" : "enter",
    probe: input.probe,
    hidden_ret_ptr: false,
    ...(input.thread_id !== undefined ? { filter: { thread_ids: [input.thread_id] } } : {}),
    ...(input.sample_every > 1 ? { sample: { every_n: input.sample_every } } : {}),
    lifetime: { duration_ms: input.duration_ms, max_hits: maxHits, clock: paused ? "resume" : "install" },
    observe_agent_calls: false,
    force_caution: false,
  };
  const decoders: HookDecoders = {
    v: 1,
    engine: input.engine,
    caller: input.caller,
    backtrace: input.backtrace,
    sample_every: input.sample_every,
    cells: input.engine === "js" ? cells : [],
    native,
    ret: input.returns === "void" ? null : input.returns,
    ret_source: input.returns === "void" ? null : isFloat(input.returns) ? "xmm0_ret" : "rax",
  };
  return { params, decoders };
}

const bytesOfHex = (hex: string): Uint8Array => {
  const out = new Uint8Array(Math.floor(hex.length / 2));
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(2 * i, 2 * i + 2), 16) || 0;
  return out;
};

const hookLimitations = (input: In<"hook_function">, r: HookInstallResult): string[] => {
  const out: string[] = [];
  if (r.relocation === "forced") out.push(LIMITATIONS.HOOK_FORCED_RELOCATION);
  if (r.thunk !== null) out.push(LIMITATIONS.HOOK_TARGET_THUNK(r.thunk.to));
  if (input.sample_every > 1) out.push(LIMITATIONS.HOOK_SAMPLED(input.sample_every));
  if (input.backtrace > 0) out.push(LIMITATIONS.HOOK_BACKTRACE_RATE(100));
  if (input.engine === "native") out.push(LIMITATIONS.HOOK_NATIVE_TIER);
  if (r.row_kind === "hook/1" && input.returns === "void" && input.capture.every((c) => c.when === "enter"))
    out.push(LIMITATIONS.HOOK_NO_DURATION);
  return out;
};

// ---------------------------------------------------------------------------------------------- hook_function
async function installHook(
  app: BeaApplication,
  input: In<"hook_function">,
  ctx: HandlerContext,
): Promise<Result<{ readonly out: Out<"hook_function">; readonly rec: Recording }, BeaError>> {
  const ev = app.services.evidence;
  return liveOp(app, ctx, input.session_id, { mode: "exclusive", need: "agent" }, async (session, op) => {
    if (activeInstruments(app, session).length >= MAX_INSTRUMENTS_PER_SESSION)
      return err({
        _tag: "ResourceConstraint",
        operation: ctx.operation,
        resource: "capacity",
        limits: { max_instruments_per_session: MAX_INSTRUMENTS_PER_SESSION },
        retryable: true,
      });
    const space: AddressSpace = { kind: "live", session };
    const resolved = await app.services.address.resolve(space, input.address, op, { path: "address" });
    if (!resolved.ok) return resolved;
    // UX-10 (CI-I10): the target's module and the main image get their preferred bases, so caller frames decode
    // with their pasteable static form
    await app.services.address.prepare(space, [resolved.value.va], op);
    if (!input.probe) {
      // UX-1: an entry hook's leave listener inside a function body corrupts the target; refuse before installing
      const interior = await functionInterior(app.services.address, space, resolved.value.va);
      if (interior !== null)
        return err(
          notFunctionStart(
            ctx.operation,
            "address",
            interior,
            " to hook the function, or keep this address with probe: true (an instruction probe: enter-only, no leave hook)",
          ),
        );
    }
    const literals = ev.literals(undefined);
    if (!literals.ok) return literals;
    const { params, decoders } = buildHookPlan(input, resolved.value.va, session.paused);
    // LIFE-6: the install and its rollback never take the caller's signal (see installOp.ts)
    const internal = detachedOp(op, INSTALL_RPC_MS);
    try {
      const installed = await session.agent.call("hookInstall", params, { op: internal.op });
      if (!installed.ok) return installed;
      const r = installed.value;
      const capture = ev.instances.capture(session.instanceId);

      // From here on the hook is live in the target: every failure stops it again before returning.
      let streamBound = false;
      const effects: FxId[] = [];
      const rollback = async <T>(
        error: Result<T, BeaError> & { readonly ok: false },
      ): Promise<Result<never, BeaError>> => {
        const stopped = await session.agent.call(
          "instrumentStop",
          { id: r.instrument_id, final_flush: false },
          { op: internal.op },
        );
        if (streamBound) await session.streams.end(r.stream_id, "install-failed");
        for (const fx of effects)
          await ev.effects.transition(fx, stopped.ok ? "reverted" : "revert-failed", {
            reason: "revert-error",
            verification: { method: "agent-confirmed", ok: stopped.ok, evidence_id: null },
            residue: [],
          });
        return err(effects.length > 0 ? { ...error.error, effects_applied: [...effects] } : error.error);
      };
      // a cancel or deadline that landed while the agent installed: stop the now-known hook again
      const aborted = abortedAfter(op);
      if (aborted !== null) return await rollback({ ok: false, error: aborted });

      const spec: StreamSpec = {
        source: { kind: "hook", instance_id: session.instanceId, effect_id: null, channel: r.stream_id },
        encoding:
          r.row_kind === "hook/1"
            ? { kind: "json-rows", row_kind: "hook/1" }
            : {
                kind: "fixed-records",
                row_kind: "hook-native/1",
                record_bytes: BINARY_LAYOUTS["hook-native/1"].rec_bytes,
                fields: BINARY_LAYOUTS["hook-native/1"].fields,
              },
        decoders: decoders as unknown as JsonValue,
        literals: literals.value,
      };
      const bound = await session.streams.bind(r.stream_id, spec);
      if (!bound.ok) return rollback(bound);
      streamBound = true;
      const ref = resolved.value.ref;
      const effect = await ev.effects.apply({
        instance_id: session.instanceId,
        kind: "hook-installed",
        target: {
          address: { va: ref.va, module_map_id: ref.module_map_id, module_key: ref.module, rva: ref.rva },
          size: null,
          threads: input.thread_id === undefined ? "all" : [input.thread_id],
        },
        parameters: {
          engine: input.engine,
          probe: input.probe,
          relocation: r.relocation,
          agent_instrument: r.instrument_id,
        },
        ...(r.effect.before[0] !== undefined ? { before: bytesOfHex(r.effect.before[0].hex) } : {}),
        lifetime: { duration_ms: input.duration_ms, max_hits: params.lifetime.max_hits },
        stream_ids: [bound.value.stream_id],
        applied_by: "hook_function",
        display_target: input.address,
        literals: literals.value,
      });
      if (!effect.ok) return rollback(effect);
      effects.push(effect.value.effect_id);
      const rec = app.services.recordings.create({
        sessionId: session.id,
        kind: "hook",
        agentInstrumentId: r.instrument_id,
        agentStream: r.stream_id,
        streamId: bound.value.stream_id,
        effectId: effect.value.effect_id,
        durationMs: input.duration_ms,
        maxEvents: input.max_events,
        startsAtResume: session.paused,
        decoders: decoders as unknown as JsonValue,
      });

      const verified = await app.services.address.verify(space, resolved.value.va, 16, op);
      const bytesMatch = !verified.ok
        ? null
        : verified.value.status === "match"
          ? true
          : verified.value.status === "mismatch"
            ? false
            : null;
      const fn = r.resolved.function;
      const functionStart =
        fn !== null
          ? BigInt(fn.base) === resolved.value.va
          : ref.symbol !== undefined && BigInt(ref.symbol.offset) === 0n;
      const instrument = publicState(rec.view());
      const result = {
        instrument,
        target: ref,
        function_start: functionStart,
        bytes_match_file: bytesMatch,
        relocation: r.relocation,
      };
      const recorded = await ev.recorder.record({
        predicate_type: "bea.instrument.install",
        operation: ctx.operation,
        input: input as unknown as JsonObject,
        subject: { kind: "process-instance", instance_id: session.instanceId },
        capture,
        provider: FROZEN_PROVIDER,
        result: result as unknown as JsonObject,
        coverage: COMPLETE,
        limitations: hookLimitations(input, r),
        locations: [ev.locationOf(ref)],
        effects: [effect.value.effect_id],
        literals: literals.value,
      });
      if (!recorded.ok) return rollback(recorded);
      const delivered = recorded.value.record.result as unknown as typeof result;
      // UX-3: on a paused target nothing records until resume_process, which can itself block until the hook is done
      const block = session.paused
        ? {
            tool: "resume_process",
            arguments: {
              session_id: session.id,
              wait_ms: Math.min(60_000, input.duration_ms + 1_000),
              until: "instruments_done",
            },
            reason: "The target is paused: resume it; until instruments_done blocks until the hook recording finishes.",
          }
        : {
            tool: "wait",
            arguments: { session_id: session.id, ids: [rec.id] },
            reason: "Block until the hook recording finishes.",
          };
      return ok({
        rec,
        out: {
          ...delivered,
          ...envelopeOf(recorded.value.record),
          next: [
            block,
            {
              tool: "query_events",
              arguments: { recording_id: rec.id, view: "summary" },
              reason: "Read the bounded digest of the recorded calls.",
            },
          ],
        } as Out<"hook_function">,
      });
    } finally {
      internal.dispose();
    }
  });
}

/**
 * Review fix UX-3: a wait on the recordings of a paused target (spawned, never resumed) cannot be satisfied: none of
 * the target's code runs and resume-clocked instruments have not even started. Such waits return at once (state as
 * is, with TARGET_PAUSED) instead of running out their whole timeout with nothing recorded.
 */
export const pausedBlocks = (session: LiveSession, recs: readonly Recording[]): boolean =>
  session.paused && recs.length > 0 && recs.every((r) => r.create.startsAtResume && r.view().state === "active");

/** wait_ms on an installing call: block until the recording ends (or the target exits), never consuming. */
async function awaitRecordingEnd(
  app: BeaApplication,
  ctx: HandlerContext,
  sessionId: string,
  rec: Recording,
  waitMs: number,
): Promise<Result<InstrumentStateView, BeaError>> {
  return liveOp(app, ctx, sessionId, { mode: "concurrent", need: "host" }, async (session, op) => {
    if (pausedBlocks(session, [rec])) return ok(await stateOf(app, rec, op));
    const until = performance.now() + Math.min(waitMs, op.deadline.remaining());
    const stream = rec.create.agentStream;
    const cond: WaitCondition =
      stream === null
        ? { kind: "process-exit" }
        : { kind: "any", of: [{ kind: "stream-end", agentStream: stream }, { kind: "process-exit" }] };
    for (;;) {
      if (rec.view().state !== "active" || ctx.signal.aborted) break;
      const left = until - performance.now();
      if (left <= 0) break;
      const outcome = await session.waitFor(cond, op, Math.min(left, WAIT_SLICE_MS));
      if (outcome.satisfied && rec.view().state === "active") await delay(SETTLE_POLL_MS); // registry end in flight
    }
    return ok(await stateOf(app, rec, op));
  });
}

// ---------------------------------------------------------------------------------------------- wait
const VISIBLE: ReadonlySet<string> = new Set([
  "paused",
  "running",
  "exited",
  "detached",
  "closing",
  "cleanup_pending",
  "closed",
]);
const visibleState = (s: SessionState): Out<"wait">["target"]["state"] =>
  (VISIBLE.has(s) ? s : "running") as Out<"wait">["target"]["state"];

const targetFacts = async (session: LiveSession, op: OperationContext): Promise<Out<"wait">["target"]> => {
  const live = session.liveness();
  const exited = live.state === "exited";
  const exit =
    exited && live.exit !== null
      ? { code: live.exit.code, code_hex: live.exit.code_hex, name: live.exit.name, kind: live.exit.kind }
      : null;
  let crash: Out<"wait">["target"]["crash"] = null;
  if (session.lastCrash !== null || exited) {
    const derived = await session.crash(op);
    if (derived.ok && derived.value !== null)
      // DerivedCrash (ports) is structurally the tool's crashReportSchema with plain-string hex fields (CI-I9)
      crash = JSON.parse(JSON.stringify(derived.value)) as NonNullable<Out<"wait">["target"]["crash"]>;
  }
  return { state: visibleState(exited ? "exited" : session.state), exit, crash };
};

/**
 * The session state, not liveness(): Frida's process-terminated detach makes liveness() report "exited" with exit:null
 * a few ms before the jobhost/watcher root-exit carrying the code arrives. The session moves to "exited" only once
 * that report lands (or its grace runs out, EXIT_REPORT_LATE), so `until:"exit"` answers with the exit code and crash.
 */
const isGone = (session: LiveSession): boolean => session.state === "exited" || session.state === "detached";

async function waitHandler(
  app: BeaApplication,
  input: In<"wait">,
  ctx: HandlerContext,
): Promise<Result<Out<"wait">, BeaError>> {
  return liveOp(app, ctx, input.session_id, { mode: "concurrent", need: "host" }, async (session, op) => {
    if (input.until === "output" && (session.ownership !== "owned" || session.output === null))
      return err(
        inputError(ctx.operation, [
          {
            path: "until",
            reason: "invalid_value",
            message: "output is captured only for BEA-spawned targets; wait for events, done or exit instead.",
          },
        ]),
      );
    const recs: Recording[] = [];
    const scans: { readonly id: string; readonly spec: HandleKindSpec }[] = [];
    if (input.ids !== undefined) {
      for (const id of input.ids) {
        if (id.startsWith("rec_")) {
          const rec = recordingOf(app, ctx.operation, session, id);
          if (!rec.ok) return rec;
          recs.push(rec.value);
        } else {
          const spec = handleOf(app, ctx.operation, session, id);
          if (!spec.ok) return spec;
          scans.push({ id, spec: spec.value });
        }
      }
    } else {
      recs.push(...activeInstruments(app, session).slice(0, MAX_INSTRUMENTS_PER_SESSION));
      for (const h of app.services.handles.list(session.id))
        if (h.kind === "scan" && h.state === "running") {
          const spec = app.services.handles.find(h.id);
          if (spec !== undefined) scans.push({ id: h.id, spec });
        }
    }
    const started = performance.now();
    const until = started + Math.min(input.timeout_ms, op.deadline.remaining());
    const scanDone = (s: (typeof scans)[number]): boolean => (s.spec.get(s.id)?.state ?? "released") !== "running";
    const holds = (): boolean => {
      switch (input.until) {
        case "done":
          return recs.every((r) => r.view().state !== "active") && scans.every(scanDone);
        case "events":
          return recs.reduce((n, r) => n + r.view().events, 0) >= (input.min_events ?? 1);
        case "exit":
          return isGone(session);
        case "output":
          return session.output?.contains(input.output_contains ?? "") === true;
      }
    };
    const hints = (): WaitCondition => {
      const of: WaitCondition[] = [{ kind: "process-exit" }, { kind: "detach" }];
      if (input.until === "done") {
        for (const r of recs)
          if (r.create.agentStream !== null && r.view().state === "active")
            of.push({ kind: "stream-end", agentStream: r.create.agentStream });
        for (const s of scans) {
          const c = s.spec.doneCondition(s.id);
          if (c !== null) of.push(c);
        }
      } else if (input.until === "events") {
        const deficit = Math.max(1, (input.min_events ?? 1) - recs.reduce((n, r) => n + r.view().events, 0));
        for (const r of recs)
          if (r.create.agentStream !== null)
            of.push({ kind: "stream-events", agentStream: r.create.agentStream, atLeast: r.view().events + deficit });
      } else if (input.until === "output") of.push({ kind: "output-contains", text: input.output_contains ?? "" });
      return { kind: "any", of };
    };
    let satisfied = holds();
    // UX-3: done/events on a paused target's resume-clocked recordings can never hold before resume_process
    const paused =
      (input.until === "done" || input.until === "events") && scans.length === 0 && pausedBlocks(session, recs);
    while (!satisfied && !paused && !isGone(session)) {
      if (ctx.signal.aborted)
        return err(cancelled(ctx.operation, ctx.abortCause()?.kind === "shutdown" ? "server-shutdown" : "client"));
      const left = until - performance.now();
      if (left <= 0) break;
      const outcome = await session.waitFor(hints(), op, Math.min(left, WAIT_SLICE_MS));
      satisfied = holds();
      if (!satisfied && outcome.satisfied) await delay(SETTLE_POLL_MS); // a hint fired; registry state catches up
    }
    if (!satisfied) satisfied = holds();
    // The target is gone, but the recordings it held end a moment later (the exit-time final batch, then the
    // registry's end with target_exited): let them settle so a done/events wait reports their finished state and
    // summaries instead of "active" (integrator fix, WP18: `bea trace-api --spawn` printed an empty, active summary).
    if (!satisfied && isGone(session) && (input.until === "done" || input.until === "events")) {
      const settleUntil = Math.min(until, performance.now() + EXIT_SETTLE_MS);
      while (recs.some((r) => r.view().state === "active") && performance.now() < settleUntil && !ctx.signal.aborted)
        await delay(SETTLE_POLL_MS);
      satisfied = holds();
    }
    const gone = isGone(session);
    const reason: Out<"wait">["reason"] = satisfied ? "condition" : gone ? "target_exited" : "timeout";
    const recordings = [];
    for (const r of recs) recordings.push(publicState(await stateOf(app, r, op)));
    const scanRows = scans.map((s) => {
      const v = s.spec.get(s.id);
      const count = v?.summary["count"];
      return {
        scan_id: s.id,
        state: v?.state ?? "released",
        count: typeof count === "number" && Number.isInteger(count) && count >= 0 ? count : null,
      };
    });
    return ok({
      satisfied,
      reason,
      waited_ms: Math.max(0, Math.round(performance.now() - started)),
      target: await targetFacts(session, op),
      recordings,
      ...(scanRows.length > 0 ? { scans: scanRows } : {}),
      evidence_id: null,
      coverage: COMPLETE,
      limitations: paused && !satisfied ? [LIMITATIONS.TARGET_PAUSED] : [],
    });
  });
}

// ---------------------------------------------------------------------------------------------- stop_instrumentation
type StopRow = Out<"stop_instrumentation">["stopped"][number];

async function stopRecording(
  app: BeaApplication,
  session: LiveSession,
  rec: Recording,
  op: OperationContext,
  operation: string,
): Promise<Result<{ readonly row: StopRow; readonly fx: FxId | null; readonly reverted: boolean }, BeaError>> {
  const kind = rec.create.kind as StopRow["kind"];
  const view = rec.view();
  const ended = (v: InstrumentStateView, status: StopRow["status"], manifest: string | null): StopRow => ({
    id: rec.id,
    kind,
    status,
    events: v.events,
    dropped: v.dropped,
    manifest_evidence_id: manifest as StopRow["manifest_evidence_id"],
  });
  if (view.state !== "active") return ok({ row: ended(view, "already_ended", null), fx: null, reverted: true });
  if (agentStateError(operation, session) !== null) {
    // the agent is gone: the instrument went with the process; close the books only
    const reason = session.state === "detached" ? "detached" : "target_exited";
    const closed = await app.services.recordings.end(rec.id, reason, op);
    return ok({ row: ended(closed.ok ? closed.value : view, "already_ended", null), fx: null, reverted: true });
  }
  const agentId = rec.create.agentInstrumentId ?? "";
  const stopped = await session.agent.call("instrumentStop", { id: agentId, final_flush: true }, { op });
  if (!stopped.ok) return stopped;
  const summary = stopped.value.stopped.find((s) => s.id === agentId);
  const failed = stopped.value.unreverted.some((u) => u.id === agentId) || summary?.reverted === false;
  const fx = rec.create.effectId;
  if (fx !== null && app.services.evidence.effects.state(fx)?.status === "active") {
    const moved = await app.services.evidence.effects.transition(fx, failed ? "revert-failed" : "reverted", {
      reason: "stop-requested",
      verification: { method: "agent-confirmed", ok: !failed, evidence_id: null },
      residue: failed ? ["the agent could not verify the restored bytes"] : [],
    });
    if (!moved.ok && app.services.evidence.effects.state(fx)?.status === "active") return moved;
  }
  const closed = await app.services.recordings.end(rec.id, "stopped", op);
  let manifest: string | null = null;
  if (rec.create.agentStream !== null) {
    const m = await session.streams.end(rec.create.agentStream, "stopped");
    if (m.ok) manifest = m.value.record.evidence_id;
  }
  return ok({
    row: ended(closed.ok ? closed.value : rec.view(), failed ? "revert-failed" : "reverted", manifest),
    fx,
    reverted: !failed,
  });
}

async function stopHandler(
  app: BeaApplication,
  input: In<"stop_instrumentation">,
  ctx: HandlerContext,
): Promise<Result<Out<"stop_instrumentation">, BeaError>> {
  const ev = app.services.evidence;
  return liveOp(app, ctx, input.session_id, { mode: "exclusive", need: "host" }, async (session, op) => {
    const recs: Recording[] = [];
    const handles: { readonly id: string; readonly spec: HandleKindSpec }[] = [];
    if (input.ids !== undefined) {
      for (const [i, id] of input.ids.entries()) {
        if (id.startsWith("rec_")) {
          const rec = recordingOf(app, ctx.operation, session, id);
          if (!rec.ok) return rec;
          if (!isInstrument(rec.value))
            return err(
              inputError(ctx.operation, [
                {
                  path: `ids[${String(i)}]`,
                  reason: "invalid_value",
                  message: `${id} is a built-in ${rec.value.create.kind} recording; it ends only with the session (close_session).`,
                },
              ]),
            );
          recs.push(rec.value);
        } else {
          const spec = handleOf(app, ctx.operation, session, id);
          if (!spec.ok) return spec;
          handles.push({ id, spec: spec.value });
        }
      }
    } else {
      recs.push(...activeInstruments(app, session));
      for (const h of app.services.handles.list(session.id))
        if (h.state === "running" || h.state === "ready" || h.state === "active") {
          const spec = app.services.handles.find(h.id);
          if (spec !== undefined) handles.push({ id: h.id, spec });
        }
    }
    const literals = ev.literals(undefined);
    if (!literals.ok) return literals;
    const stopped: StopRow[] = [];
    const touched: FxId[] = [];
    const failed: string[] = [];
    for (const rec of recs) {
      const done = await stopRecording(app, session, rec, op, ctx.operation);
      if (!done.ok) return done;
      stopped.push(done.value.row);
      if (done.value.fx !== null && done.value.row.status !== "already_ended") touched.push(done.value.fx);
      if (!done.value.reverted && done.value.fx !== null) failed.push(done.value.fx);
    }
    for (const h of handles) {
      const outcome = await h.spec.stop(session, h.id, op);
      if (!outcome.ok) return outcome;
      stopped.push({
        id: h.id,
        kind: outcome.value.kind,
        status: outcome.value.status,
        events: null,
        dropped: null,
        manifest_evidence_id: null,
      });
      if (h.id.startsWith("fx_")) {
        touched.push(h.id as FxId);
        if (outcome.value.status === "revert-failed") failed.push(h.id);
      }
    }
    const activeRemaining =
      activeInstruments(app, session).length +
      app.services.handles
        .list(session.id)
        .filter((h) => h.state === "running" || h.state === "ready" || h.state === "active").length;
    const result = { stopped: stopped.slice(0, 64), active_remaining: activeRemaining };
    const recorded = await ev.recorder.record({
      predicate_type: "bea.instrument.stop",
      operation: ctx.operation,
      input: input as unknown as JsonObject,
      subject: { kind: "process-instance", instance_id: session.instanceId },
      capture: ev.instances.capture(session.instanceId),
      provider: FROZEN_PROVIDER,
      result: result as unknown as JsonObject,
      coverage: COMPLETE,
      effects: [...new Set(touched)].slice(0, 64),
      literals: literals.value,
    });
    if (!recorded.ok) return recorded;
    if (failed.length > 0)
      return err({
        _tag: "EffectUnreverted",
        operation: ctx.operation,
        effect_ids: failed,
        diagnostics: {
          effects: stopped.map((s) => ({ id: s.id, status: s.status })),
          evidence_id: recorded.value.record.evidence_id,
        },
      });
    return ok({
      ...(recorded.value.record.result as unknown as typeof result),
      ...envelopeOf(recorded.value.record),
    } as Out<"stop_instrumentation">);
  });
}

// ---------------------------------------------------------------------------------------------- query_events
let localOps = 0;
/** query_events reads run-level storage (recordings outlive their session), so it builds its own op context. */
const localOp = (ctx: HandlerContext): { readonly op: OperationContext; readonly dispose: () => void } => {
  const deadline = Deadline.after(ctx.remainingMs());
  return {
    op: { opId: 1_000_000_000 + ++localOps, name: ctx.operation, signal: ctx.signal, deadline },
    dispose: () => deadline.dispose(),
  };
};

async function* rowsOfStream(records: AsyncIterable<StreamRecord>): AsyncIterable<EventRecord> {
  for await (const r of records) {
    const f = r.fields;
    const row: Record<string, JsonValue> =
      typeof f === "object" && f !== null && !Array.isArray(f) ? { ...(f as JsonObject) } : { value: f };
    yield { ...row, seq: r.seq } as EventRecord;
  }
}

const recordingCoverage = (
  view: InstrumentStateView | null,
  page: QueryPage | null,
): { coverage: Coverage; limitations: string[] } => {
  const reasons = new Set<ReasonCode>();
  const limitations: string[] = [];
  let status: Coverage["status"] = "complete";
  let truncated = false;
  let dropped: number | undefined;
  if (view !== null) {
    if (view.state === "active") {
      status = "partial";
      reasons.add("recording_active");
      limitations.push(LIMITATIONS.RECORDING_ACTIVE);
    }
    if (view.dropped > 0) {
      status = "partial";
      truncated = true;
      dropped = view.dropped;
      reasons.add(view.end_reason === "max_events" ? "row_cap" : "agent_buffer_full");
      limitations.push(LIMITATIONS.STREAM_DROPPED(view.dropped));
    }
    limitations.push(LIMITATIONS.NOT_OBSERVED_WINDOW);
  }
  if (page !== null && page.truncatedValues > 0) {
    status = status === "complete" ? "partial" : status;
    truncated = true;
    reasons.add("value_cap");
    limitations.push(LIMITATIONS.QUERY_VALUE_CAP(QUERY_CELL_CHARS));
  }
  if (page?.groupsCapped === true) {
    status = status === "complete" ? "partial" : status;
    truncated = true;
    reasons.add("row_cap");
    limitations.push(LIMITATIONS.QUERY_GROUP_CAP(10_000));
  }
  return {
    coverage: { status, truncated, ...(dropped !== undefined ? { dropped } : {}), reasons: [...reasons].sort() },
    limitations,
  };
};

async function queryHandler(
  app: BeaApplication,
  input: In<"query_events">,
  ctx: HandlerContext,
): Promise<Result<Out<"query_events">, BeaError>> {
  const ev = app.services.evidence;
  const { op, dispose } = localOp(ctx);
  try {
    let source: () => AsyncIterable<EventRecord>;
    let available: readonly EventField[];
    let recording: ReturnType<typeof publicState> | null = null;
    let view: InstrumentStateView | null = null;
    let streamId: StId | null;
    let effectId: FxId | null = null;
    if (input.recording_id !== undefined) {
      const rec = app.services.recordings.get(input.recording_id);
      if (rec === undefined) return err(referenceNotFound(ctx.operation, "recording", input.recording_id));
      const id = rec.id;
      source = () => app.services.recordings.events(id, {}, op);
      const decoders = rec.create.kind === "hook" ? parseHookDecoders(rec.create.decoders) : null;
      available = availableFields(
        decoders !== null ? hookFieldsOf(decoders) : (RECORDING_KINDS[rec.create.kind]?.fields ?? []),
      );
      streamId = rec.create.streamId;
      effectId = rec.create.effectId;
      // UX-2: the recording's digest is not repeated on every rows/group/stats page (it was ~80% of each page);
      // view:"summary" carries it once, at the top level
      view = rec.view();
      recording = withoutSummary(publicState(view));
    } else {
      const sid = (input.stream_id ?? "") as StId;
      const reader = ev.streams.reader(sid);
      if (!reader.ok) return err(referenceNotFound(ctx.operation, "stream", sid));
      source = () => rowsOfStream(reader.value.records({}, op.signal));
      let first: EventRecord | null = null;
      for await (const e of source()) {
        first = e;
        break;
      }
      available = availableFields(first === null ? [] : fieldsOfRow(first), STREAM_BASE_FIELDS);
      streamId = sid;
    }

    let page: QueryPage | null = null;
    let summary: JsonObject | undefined;
    if (input.view === "summary") {
      if (input.recording_id !== undefined) {
        const s =
          view?.summary !== undefined
            ? ok(view.summary)
            : await app.services.recordings.summary(input.recording_id, op);
        if (!s.ok) return s;
        summary = s.value as JsonObject;
      } else {
        let records = 0;
        for await (const _ of source()) records++;
        summary = { records, fields: available.map((f) => f.name) };
      }
    } else {
      const req: QueryRequest = { ...input, view: input.view };
      const issues = validateQuery(req, available);
      if (issues.length > 0) return err(inputError(ctx.operation, issues));
      page = await runQuery(source, available, req, {
        cellChars: QUERY_CELL_CHARS,
        maxColumns: QUERY_MAX_COLUMNS,
        signal: ctx.signal,
      });
    }

    const literals = ev.literals(undefined);
    if (!literals.ok) return literals;
    const { coverage, limitations } = recordingCoverage(view, page);
    const failures = summary?.["read_failures"];
    if (typeof failures === "number" && failures > 0) limitations.push(LIMITATIONS.HOOK_READ_FAILURES(failures));
    const result = {
      recording,
      stream_id: streamId,
      view: input.view,
      columns: page === null ? [] : [...page.columns],
      rows: page === null ? [] : page.rows.map((r) => [...r]),
      page: {
        offset: input.offset,
        limit: input.limit,
        total: page?.total ?? 0,
        next_offset: page?.next_offset ?? null,
      },
      ...(input.offset === 0 ? { fields: available.map((f) => ({ name: f.name, type: f.type })) } : {}),
      ...(page?.stats !== undefined ? { stats: page.stats.map((s) => ({ ...s, top: [...s.top] })) } : {}),
      ...(summary !== undefined ? { summary } : {}),
    };
    const instance =
      streamId === null
        ? null
        : (() => {
            const r = ev.streams.reader(streamId);
            return r.ok ? r.value.spec.source.instance_id : null;
          })();
    const parents = queryParents(ev, { streamId, effectId, instanceId: instance });
    const recorded: Result<RecordedEvidence<JsonObject>, BeaError> = await ev.recorder.record({
      predicate_type: "bea.events.query",
      operation: ctx.operation,
      input: input as unknown as JsonObject,
      subject: instance === null ? null : { kind: "process-instance", instance_id: instance },
      provider: { id: "bea", name: "bea-query", version: null },
      confidence: "derived",
      result: result as unknown as JsonObject,
      coverage,
      limitations,
      ...(parents.length > 0 ? { evidence_links: parents } : {}),
      literals: literals.value,
    });
    if (!recorded.ok) return recorded;
    return ok({
      ...(recorded.value.record.result as unknown as typeof result),
      ...envelopeOf(recorded.value.record),
    } as Out<"query_events">);
  } catch (cause) {
    const why = ctx.abortCause();
    if (why?.kind === "deadline") return err(providerTimeout(ctx.operation, why.budget_ms, "query"));
    if (why !== null) return err(cancelled(ctx.operation, why.kind === "shutdown" ? "server-shutdown" : "client"));
    throw cause;
  } finally {
    dispose();
  }
}

// ---------------------------------------------------------------------------------------------- handlers
export const createInstrumentHandlers = (app: BeaApplication): HandlersFor<typeof INSTRUMENT_TOOLS> => ({
  hook_function: async (input, ctx) => {
    const installed = await installHook(app, input, ctx);
    if (!installed.ok) return installed;
    const { out, rec } = installed.value;
    if (input.wait_ms === 0 || ctx.signal.aborted) return ok(out);
    const waited = await awaitRecordingEnd(app, ctx, input.session_id, rec, input.wait_ms);
    // a failed wait is still a successful install: report the state as of now
    const state = waited.ok ? waited.value : rec.view();
    return ok({ ...out, instrument: publicState(state) });
  },
  wait: (input, ctx) => waitHandler(app, input, ctx),
  stop_instrumentation: (input, ctx) => stopHandler(app, input, ctx),
  query_events: (input, ctx) => queryHandler(app, input, ctx),
});
