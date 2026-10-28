import { createHash } from "node:crypto";

import { HOOK_KIND } from "../../../../src/application/instruments/kinds/hook.js";
import { Deadline } from "../../../../src/domain/deadline.js";
import type { BeaError } from "../../../../src/domain/errors/beaError.js";
import { COMPLETE } from "../../../../src/domain/evidence/coverage.js";
import { NO_PERTURBATION, type BeaEvidence } from "../../../../src/domain/evidence/record.js";
import type { EvId, FxId, PiId, StId } from "../../../../src/domain/ids.js";
import type { JsonObject, JsonValue } from "../../../../src/domain/json.js";
import { err, ok, type Result } from "../../../../src/domain/result.js";
import type { AddressService, ByteVerification } from "../../../../src/ports/address.js";
import type { AgentRpc } from "../../../../src/ports/agentRpc.js";
import type {
  EffectDraft,
  EvidenceDraft,
  EvidenceRuntime,
  RecordedEvidence,
  StreamRecord,
  StreamSpec,
} from "../../../../src/ports/evidence.js";
import type {
  EventRecord,
  InstrumentStateView,
  Recording,
  RecordingCreate,
  RecordingEndReason,
  RecordingRegistry,
} from "../../../../src/ports/recordings.js";
import type {
  DynamicSessionPort,
  LiveSession,
  OperationContext,
  SessionState,
  WaitCondition,
} from "../../../../src/ports/sessions.js";
import type { AgentMethodName, AgentParams, HookInstallResult } from "../../../../src/shared/agentProtocol.js";
import { notImplementedPort } from "../../../../src/application/notImplemented.js";

/**
 * Local fakes for the instrument area's MCP boundary tests (WP7-HOOK). The shared fakes of WP1 (fakeEvidence) and
 * WP4 (fakeSession/fakeAgentRpc) are built in parallel, so this file models only what the four handlers touch:
 * admission + one live session, an agent answering hookInstall/instrumentStop, a stream binder, an address service,
 * an evidence runtime (recorder, effects, instances, streams.reader) and an in-memory RecordingRegistry that decodes
 * through the real hook kind (src/application/instruments/kinds/hook.ts).
 */
export const SESSION_ID = "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b";
export const OTHER_SESSION = "0e9d8c7b-6a5f-4e3d-8c1b-0a9f8e7d6c5b";
export const INSTANCE: PiId = `pi_${"1".repeat(64)}`;
const sha = (s: string): string => createHash("sha256").update(s).digest("hex");

export interface AgentCall {
  readonly method: AgentMethodName;
  readonly params: unknown;
  /** whether the op the call ran under was already aborted (LIFE-6: rollbacks run on a detached op) */
  readonly opAborted?: boolean;
}

export const hookInstallResult = (n: number, overrides: Partial<HookInstallResult> = {}): HookInstallResult => ({
  instrument_id: `h${String(n)}`,
  stream_id: `s${String(n)}`,
  row_kind: "hook/1",
  layout: null,
  resolved: {
    va: "0x140001760",
    module: "game_sim.exe",
    module_base: "0x140000000",
    rva: "0x1760",
    export: null,
    function: { base: "0x140001760", size: 128, source: "pdata" },
    protection: "r-x",
  },
  thunk: null,
  patched_at: ["0x140001760"],
  relocation: "default",
  stalker_invalidated: [],
  arg_map: [],
  effect: {
    kind: "hook-installed",
    reversible: true,
    targets: [{ address: "0x140001760", size: null }],
    thread_ids: null,
    before: [{ address: "0x140001760", hex: "4883ec28".padEnd(64, "90") }],
  },
  ...overrides,
});

/** A recording backed by an in-memory row list (JSON hook rows or arbitrary records). */
export interface FakeRecording extends Recording {
  readonly records: StreamRecord[];
  state: InstrumentStateView["state"];
  endReason: RecordingEndReason | null;
  dropped: number;
}

export class FakeWorld {
  readonly calls: AgentCall[] = [];
  readonly recorded: EvidenceDraft<JsonValue>[] = [];
  /** evidence ids of `recorded`, same order (the fake evidence index behind query.summary) */
  readonly recordedIds: EvId[] = [];
  readonly effects = new Map<FxId, { status: "active" | "reverted" | "revert-failed" }>();
  readonly transitions: { id: FxId; to: string }[] = [];
  readonly boundStreams: { agentStream: string; spec: StreamSpec }[] = [];
  readonly endedStreams: string[] = [];
  readonly recordings = new Map<string, FakeRecording>();
  readonly hostStreams = new Map<StId, StreamRecord[]>();
  state: SessionState = "running";
  ownership: "owned" | "attached" = "owned";
  paused = false;
  exited = false;
  /** false models Frida's process-terminated detach landing before the jobhost root-exit report (exit code unknown) */
  exitReported = true;
  outputText = "";
  /** agent behaviour overrides: return a Result for the method, or undefined for the default */
  agentOverride: (
    method: AgentMethodName,
    params: unknown,
  ) => Result<unknown, BeaError> | Promise<Result<unknown, BeaError>> | undefined = () => undefined;
  bindFails = false;
  verifyStatus: ByteVerification["status"] = "match";
  /** rva of the enclosing .pdata function start describeCode reports for any address (null: no function) */
  functionStartRva: number | null = null;
  #installs = 0;
  #recs = 0;
  #effects = 0;
  #evidence = 0;

  // ------------------------------------------------------------------------------------------ session
  readonly session: LiveSession = (() => {
    const world = this;
    const agent: AgentRpc = {
      health: { state: "ok" },
      call: async <M extends AgentMethodName>(
        method: M,
        params: AgentParams<M>,
        opts?: { readonly op?: { readonly signal: AbortSignal } },
      ) => {
        world.calls.push({ method, params, opAborted: opts?.op?.signal.aborted ?? false });
        const override = world.agentOverride(method, params);
        if (override !== undefined) return (await override) as never;
        if (method === "hookInstall") return ok(hookInstallResult(++world.#installs)) as never;
        if (method === "instrumentStop") {
          const id = (params as { id: string }).id;
          return ok({
            stopped: [{ id, reverted: true, verification: { kind: "bytes", ok: true, detail: "restored" } }],
            not_found: [],
            unreverted: [],
          }) as never;
        }
        return err({ _tag: "Internal", operation: method }) as never;
      },
    };
    return {
      id: SESSION_ID,
      kind: "live",
      get ownership() {
        return world.ownership;
      },
      get state() {
        return world.state;
      },
      instanceId: INSTANCE,
      identity: {} as LiveSession["identity"],
      agent,
      streams: {
        bind: async (agentStream: string, spec: StreamSpec) => {
          if (world.bindFails) return err({ _tag: "Internal", operation: "streams.bind" });
          world.boundStreams.push({ agentStream, spec });
          return ok({ stream_id: `st_${sha(agentStream)}` as StId } as never);
        },
        writer: () => undefined,
        counters: () => null,
        end: async (agentStream: string) => {
          world.endedStreams.push(agentStream);
          return ok({ record: { evidence_id: `ev_${sha(`manifest:${agentStream}`)}` } } as never);
        },
      },
      get output() {
        return world.ownership === "owned"
          ? ({
              contains: (text: string) => world.outputText.includes(text),
              observedBytes: { stdout: 0, stderr: 0 },
              tail: () => "",
              truncated: false,
              eof: { stdout: false, stderr: false },
            } as LiveSession["output"])
          : null;
      },
      lastCrash: null,
      get paused() {
        return world.paused;
      },
      jobs: notImplementedPort("jobs"),
      scripts: notImplementedPort("scripts"),
      liveness: () =>
        world.exited
          ? {
              state: "exited",
              basis: "jobhost-root-exit",
              exit: world.exitReported
                ? { code: 0, code_hex: "0x0", name: null, kind: "normal", source: "jobhost" }
                : null,
              tree: null,
            }
          : { state: "alive", basis: "jobhost" },
      waitFor: async (_cond: WaitCondition, _op: OperationContext, timeoutMs: number) => {
        await new Promise((r) => setTimeout(r, Math.min(timeoutMs, 5)));
        return { satisfied: false, timedOut: true, cancelled: false, state: world.state, waitedMs: 5 };
      },
      crash: async () => ok(null),
    };
  })();

  readonly sessions: DynamicSessionPort = (() => {
    const world = this;
    let ops = 0;
    return {
      ...notImplementedPort<DynamicSessionPort>("sessions"),
      closing: false,
      admit: async (name, req, fn) => {
        const deadline = Deadline.after(req.timeoutMs ?? 30_000);
        try {
          return await fn({ opId: ++ops, name, signal: req.signal ?? new AbortController().signal, deadline });
        } finally {
          deadline.dispose();
        }
      },
      kindOf: (id) => (id === SESSION_ID ? "live" : null),
      withSession: async (_id, _op, _mode, fn) => fn(world.session),
      onSessionEnded: () => () => undefined,
    } as DynamicSessionPort;
  })();

  // ------------------------------------------------------------------------------------------ address
  readonly address: AddressService = {
    resolve: async (_space, expr) =>
      expr.includes("unmapped")
        ? err({ _tag: "AddressUnmapped", operation: "hook_function", address: expr, module_map_id: null })
        : ok({
            ref: {
              va: "0x140001760",
              module: "game_sim.exe",
              rva: "0x1760",
              static_va: "0x140001760",
              static_base: "0x140000000",
              static_base_source: "pe-header",
              module_map_id: `mm_${"2".repeat(64)}`,
              symbol: { name: "physics_step", kind: "export", offset: "0x0", source: "pe-export" },
            },
            moduleMapId: `mm_${"2".repeat(64)}`,
            va: 0x140001760n,
          }),
    validate: () => ok(true),
    describe: () => ({ va: "0x0", at: null, static: null }),
    describeCode: async (_space, va) => ({
      va: `0x${va.toString(16)}`,
      at: `game_sim.exe+0x${(va - 0x140000000n).toString(16)}`,
      static: null,
      func: this.functionStartRva === null ? null : `game_sim.exe+0x${this.functionStartRva.toString(16)}`,
      sym: null,
    }),
    fromFrameRef: async () => ({ va: "0x0", at: null, static: null, func: null, sym: null }),
    prepare: async () => undefined,
    verify: async () =>
      ok({
        status: this.verifyStatus,
        compared: 16,
        equal: 16,
        excluded_loader: 0,
        own_effects_restored: 14,
        differences: [],
      }),
  };

  // ------------------------------------------------------------------------------------------ evidence
  readonly evidence: EvidenceRuntime = (() => {
    const world = this;
    const literals = { count: 0, texts: [], spellings: [] };
    return {
      ...notImplementedPort<EvidenceRuntime>("evidence"),
      literals: () => ok(literals),
      locationOf: (ref: { va: `0x${string}` }) => ({
        kind: "address" as const,
        va: ref.va,
        size: null,
        module_map_id: null,
        module_key: null,
        rva: null,
        image_sha256: null,
      }),
      recorder: {
        record: async <R extends JsonValue>(
          draft: EvidenceDraft<R>,
        ): Promise<Result<RecordedEvidence<R>, BeaError>> => {
          world.recorded.push(draft as EvidenceDraft<JsonValue>);
          const id = `ev_${sha(`ev:${String(++world.#evidence)}`)}` as EvId;
          world.recordedIds.push(id);
          const record: BeaEvidence<R> = {
            schema: "bea.evidence/1",
            evidence_id: id,
            predicate_type: draft.predicate_type,
            operation: draft.operation,
            parameters: draft.input,
            subject:
              draft.subject === null ? null : { kind: "process-instance", instance_id: INSTANCE, module_map_id: null },
            observed_at: null,
            provider: draft.provider,
            agent: null,
            confidence: draft.confidence ?? "observed",
            authority: "live-process",
            perturbation: NO_PERTURBATION,
            result: draft.result,
            raw_result: null,
            blobs: [],
            coverage: draft.coverage,
            limitations: [...(draft.limitations ?? [])],
            locations: [...(draft.locations ?? [])],
            evidence_links: [],
            external_refs: [],
            effects: [...(draft.effects ?? [])],
            redactions: [],
            untrusted: true,
          };
          return ok({ record, outcome: "added" });
        },
      },
      // the exact-filter summary of the evidence index (integrator: query_events cites its parent through it)
      query: {
        ...notImplementedPort("query"),
        summary: (input: JsonObject) => {
          const f = (input["filters"] ?? {}) as Readonly<Record<string, JsonValue>>;
          const rows = world.recorded
            .map((d, i) => ({ d, id: world.recordedIds[i] as EvId }))
            .filter(({ d }) => f["predicate_type"] === undefined || d.predicate_type === f["predicate_type"])
            .filter(
              ({ d }) =>
                f["applied_effect_id"] === undefined || (d.effects ?? []).includes(f["applied_effect_id"] as FxId),
            )
            .filter(
              ({ d }) =>
                f["stream_id"] === undefined ||
                (typeof d.result === "object" &&
                  d.result !== null &&
                  (d.result as JsonObject)["stream_id"] === f["stream_id"]),
            )
            .map(({ d, id }) => ({ kind: "evidence", evidence_id: id, predicate_type: d.predicate_type }));
          const offset = typeof input["offset"] === "number" ? input["offset"] : 0;
          const limit = typeof input["limit"] === "number" ? input["limit"] : 50;
          return ok({
            entity: "evidence",
            total: world.recorded.length,
            matching: rows.length,
            rows: rows.slice(offset, offset + limit),
          });
        },
      } as EvidenceRuntime["query"],
      instances: {
        ...notImplementedPort("instances"),
        capture: () => ({
          anchor: {} as never,
          module_map_id: `mm_${"2".repeat(64)}`,
          perturbation: NO_PERTURBATION,
          tainted_count: 0,
        }),
      } as EvidenceRuntime["instances"],
      effects: {
        ...notImplementedPort("effects"),
        apply: async (draft: EffectDraft) => {
          const id = `fx_${sha(`fx:${String(++world.#effects)}`)}` as FxId;
          world.effects.set(id, { status: "active" });
          return ok({ effect_id: id, kind: draft.kind } as never);
        },
        transition: async (id: FxId, to: string) => {
          world.transitions.push({ id, to });
          const e = world.effects.get(id);
          if (e === undefined) return err({ _tag: "Internal", operation: "effects.transition" });
          e.status = to === "revert-failed" ? "revert-failed" : "reverted";
          return ok({} as never);
        },
        state: (id: FxId) => world.effects.get(id) as never,
      } as EvidenceRuntime["effects"],
      streams: {
        open: async () => err({ _tag: "Internal", operation: "streams.open" }),
        reader: (id: StId) => {
          const rows = world.hostStreams.get(id);
          if (rows === undefined)
            return err({ _tag: "ReferenceNotFound", operation: "streams.reader", reference: { kind: "stream", id } });
          return ok({
            spec: { source: { kind: "emu-batch", instance_id: null, effect_id: null, channel: "emu" } } as StreamSpec,
            verify: async () => ok({ head_chain: "", chunks: 0 }),
            gaps: () => [],
            records: async function* () {
              yield* rows;
            },
          });
        },
      },
    };
  })();

  // ------------------------------------------------------------------------------------------ recordings
  readonly registry: RecordingRegistry = (() => {
    const world = this;
    const view = (r: FakeRecording): InstrumentStateView => ({
      recording_id: r.id,
      kind: r.create.kind,
      state: r.state,
      events: r.records.length,
      dropped: r.dropped,
      ends_in_ms: r.state === "active" ? 5000 : null,
      end_reason: r.endReason,
    });
    const decodeAll = function* (r: FakeRecording): Iterable<EventRecord> {
      for (const rec of r.records)
        yield* (
          HOOK_KIND?.decode(rec, {
            sessionId: r.create.sessionId,
            decoders: r.create.decoders,
            startedAtUs: 1000,
            frame: (f) => ({ at: f.startsWith("0x") ? `game_sim.exe+${f}` : f, static: null }),
          }) ?? []
        );
    };
    const summaryOf = (r: FakeRecording): JsonObject => {
      const b = HOOK_KIND?.summary;
      if (b === undefined) return {};
      const s = b.init();
      for (const e of decodeAll(r)) b.add(s, e);
      return b.finish(s);
    };
    return {
      create: (spec: RecordingCreate) => {
        const id = `rec_${(++world.#recs).toString(16).padStart(8, "0")}`;
        const rec: FakeRecording = {
          id,
          create: spec,
          records: [],
          state: "active",
          endReason: null,
          dropped: 0,
          view: () => view(rec),
        };
        world.recordings.set(id, rec);
        return rec;
      },
      get: (id) => world.recordings.get(id),
      list: (sessionId) => [...world.recordings.values()].filter((r) => r.create.sessionId === sessionId),
      end: async (id, reason) => {
        const r = world.recordings.get(id);
        if (r === undefined)
          return err({ _tag: "ReferenceNotFound", operation: "end", reference: { kind: "recording", id } });
        if (r.state === "active") {
          r.state = "finished";
          r.endReason = reason;
        }
        return ok({ ...view(r), summary: summaryOf(r) });
      },
      events: async function* (id) {
        const r = world.recordings.get(id);
        if (r !== undefined) yield* decodeAll(r);
      },
      summary: async (id) => {
        const r = world.recordings.get(id);
        return r === undefined
          ? err({ _tag: "ReferenceNotFound", operation: "summary", reference: { kind: "recording", id } })
          : ok(summaryOf(r));
      },
      onResumed: () => undefined,
    };
  })();

  /** A finished (or active) hook recording with JSON rows, created as hook_function would. */
  addHookRecording(
    rows: readonly (readonly JsonValue[])[],
    decoders: JsonObject,
    state: InstrumentStateView["state"] = "finished",
  ): FakeRecording {
    const rec = this.registry.create({
      sessionId: SESSION_ID,
      kind: "hook",
      agentInstrumentId: "h99",
      agentStream: "s99",
      streamId: `st_${sha("s99")}` as StId,
      effectId: null,
      durationMs: 1000,
      maxEvents: 1000,
      startsAtResume: false,
      decoders,
    }) as FakeRecording;
    rows.forEach((row, i) => rec.records.push({ seq: i + 1, module_map_epoch: 1, fields: row }));
    rec.state = state;
    if (state !== "active") rec.endReason = "duration";
    return rec;
  }

  services() {
    return {
      sessions: this.sessions,
      address: this.address,
      evidence: this.evidence,
      recordings: this.registry,
    };
  }
}
