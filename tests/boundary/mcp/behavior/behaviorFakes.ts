import type { BeaError } from "../../../../src/domain/errors/beaError.js";
import type { BeaEvidence } from "../../../../src/domain/evidence/record.js";
import type { EvId, FxId, PiId, StId } from "../../../../src/domain/ids.js";
import type { JsonValue } from "../../../../src/domain/json.js";
import { err, ok, type Result } from "../../../../src/domain/result.js";
import type { AgentCallOptions, AgentRpc } from "../../../../src/ports/agentRpc.js";
import type {
  EffectDraft,
  EvidenceDraft,
  EvidenceRuntime,
  StreamSpec,
  StreamWriter,
} from "../../../../src/ports/evidence.js";
import type {
  InstrumentStateView,
  Recording,
  RecordingCreate,
  RecordingRegistry,
} from "../../../../src/ports/recordings.js";
import type {
  DynamicSessionPort,
  LiveSession,
  OperationContext,
  SessionState,
  WaitCondition,
} from "../../../../src/ports/sessions.js";
import type { ProfileInstallParams, ProfileInstallResult } from "../../../../src/shared/agentProtocol.js";

/**
 * Local fakes for the trace_api boundary tests (WP8 owns them; no shared fake is modified). They implement only what
 * TraceApiService touches and record every interaction for assertions.
 */
const hex64 = (n: number): string => n.toString(16).padStart(64, "0");
export const SESSION_ID = "3f2b8c1e-5d4a-4e6b-9c7d-1a2b3c4d5e6f";
export const EMU_SESSION_ID = "11111111-2222-4333-8444-555555555555";
const PI = `pi_${hex64(1)}` as PiId;
const RUN = "run_20261028T000000Z_0123456789abcdef";

export const installResult = (over: Partial<ProfileInstallResult> = {}): ProfileInstallResult => ({
  instrument_id: "p1",
  stream_id: "sp1",
  row_kind: "api/1",
  catalog_minor: 0,
  installed: [
    { api_id: 1, api: "ntdll.dll!NtCreateFile", va: "0x7ffa00001000" },
    { api_id: 2, api: "ntdll.dll!NtOpenFile", va: "0x7ffa00002000" },
  ],
  pending: [{ api: "winhttp.dll!WinHttpConnect", module: "winhttp.dll" }],
  denied: [],
  failed: [
    {
      api: "ntdll.dll!NtDeleteFile",
      error: { _tag: "ExportNotFound", message: "x", module: "ntdll.dll", export: "NtDeleteFile" },
    },
  ],
  memmap_stream: null,
  effect: { kind: "profile-installed", reversible: true, targets: [], thread_ids: null, before: [] },
  ...over,
});

export interface FakeWorld {
  readonly sessions: DynamicSessionPort;
  readonly evidence: EvidenceRuntime;
  readonly recordings: RecordingRegistry;
  readonly agentCalls: { method: string; params: ProfileInstallParams; options: AgentCallOptions }[];
  readonly binds: { agentStream: string; spec: StreamSpec }[];
  readonly effects: EffectDraft[];
  readonly drafts: EvidenceDraft<JsonValue>[];
  readonly created: RecordingCreate[];
  readonly waits: { cond: WaitCondition; timeoutMs: number }[];
  /** the recording view after a wait (e.g. finished with a summary) */
  finishedView: InstrumentStateView | null;
  state: SessionState;
  paused: boolean;
  agentReply: Result<ProfileInstallResult, BeaError>;
  /** failure injection for the host-side setup steps */
  bindError: BeaError | null;
  effectError: BeaError | null;
  readonly ended: { agentStream: string; reason: string }[];
}

/** Evidence runtime fake: literals, instance capture, effects and a Recorder that builds a schema-valid record. */
const fakeEvidence = (world: FakeWorld): EvidenceRuntime => {
  let fx = 0;
  let ev = 0;
  return {
    literals: () => ok({ count: 0, texts: [], spellings: [] }),
    instances: {
      capture: () => ({
        anchor: {
          run_id: RUN,
          seq: 7,
          mono_ns: "1",
          wall: "2026-10-28T00:00:00.000Z",
          effect_epoch: 1,
          module_map_epoch: 2,
        },
        module_map_id: `mm_${hex64(3)}`,
        perturbation: { level: "passive", active_effect_ids: [], tainted_by: [] },
        tainted_count: 0,
      }),
    },
    effects: {
      apply: async (draft: EffectDraft) => {
        world.effects.push(draft);
        if (world.effectError !== null) return err(world.effectError);
        return ok({ effect_id: `fx_${hex64(++fx)}` as FxId });
      },
    },
    recorder: {
      record: async <R extends JsonValue>(draft: EvidenceDraft<R>) => {
        world.drafts.push(draft as EvidenceDraft<JsonValue>);
        const capture = draft.capture;
        const record = {
          schema: "bea.evidence/1",
          evidence_id: `ev_${hex64(++ev)}` as EvId,
          predicate_type: draft.predicate_type,
          operation: draft.operation,
          parameters: draft.input,
          subject: { kind: "process-instance", instance_id: PI, module_map_id: capture?.module_map_id ?? null },
          observed_at: capture?.anchor ?? null,
          provider: draft.provider,
          agent: null,
          confidence: "observed",
          authority: "live-process",
          perturbation: { level: "passive", active_effect_ids: [...(draft.effects ?? [])], tainted_by: [] },
          result: draft.result,
          raw_result: null,
          blobs: [],
          coverage: draft.coverage,
          limitations: [...(draft.limitations ?? [])],
          locations: [],
          evidence_links: [],
          external_refs: [],
          effects: [...(draft.effects ?? [])],
          redactions: [],
          untrusted: true,
        } as unknown as BeaEvidence<R>;
        return ok({ record, outcome: "added" as const });
      },
    },
  } as unknown as EvidenceRuntime;
};

export const createFakeWorld = (): FakeWorld => {
  const world: FakeWorld = {
    agentCalls: [],
    binds: [],
    effects: [],
    drafts: [],
    created: [],
    waits: [],
    finishedView: null,
    state: "paused",
    paused: true,
    agentReply: ok(installResult()),
    bindError: null,
    effectError: null,
    ended: [],
  } as unknown as FakeWorld;

  const agent: AgentRpc = {
    health: { state: "ok" },
    call: (async (method: string, params: ProfileInstallParams, options: AgentCallOptions) => {
      world.agentCalls.push({ method, params, options });
      if (method !== "profileInstall") return ok({ stopped: [], not_found: [], unreverted: [] });
      return world.agentReply;
    }) as unknown as AgentRpc["call"],
  };
  const writer = (n: number): StreamWriter =>
    ({ stream_id: `st_${hex64(n)}` as StId, descriptor_sha256: hex64(n) }) as unknown as StreamWriter;
  const session = (): LiveSession =>
    ({
      id: SESSION_ID,
      kind: "live",
      ownership: "owned",
      state: world.state,
      instanceId: PI,
      paused: world.paused,
      agent,
      streams: {
        bind: async (agentStream: string, spec: StreamSpec) => {
          world.binds.push({ agentStream, spec });
          return world.bindError === null ? ok(writer(world.binds.length)) : err(world.bindError);
        },
        end: async (agentStream: string, reason: string) => {
          world.ended.push({ agentStream, reason });
          return ok({});
        },
      },
      liveness: () => ({ state: "exited", basis: "jobhost-root-exit", exit: null, tree: null }),
      waitFor: async (cond: WaitCondition, _op: OperationContext, timeoutMs: number) => {
        world.waits.push({ cond, timeoutMs });
        return { satisfied: true, timedOut: false, cancelled: false, state: world.state, waitedMs: 5 };
      },
    }) as unknown as LiveSession;
  const op = (signal: AbortSignal | undefined): OperationContext =>
    ({ opId: 1, name: "trace_api", signal: signal ?? new AbortController().signal }) as unknown as OperationContext;

  (world as { sessions: DynamicSessionPort }).sessions = {
    admit: async <T>(
      _name: string,
      req: { signal?: AbortSignal },
      fn: (o: OperationContext) => Promise<Result<T, BeaError>>,
    ) => fn(op(req.signal)),
    kindOf: (id: string) => (id === SESSION_ID ? "live" : id === EMU_SESSION_ID ? "emulation" : null),
    withSession: async <T>(
      _id: string,
      _op: OperationContext,
      _mode: string,
      fn: (s: LiveSession) => Promise<Result<T, BeaError>>,
    ) => fn(session()),
  } as unknown as DynamicSessionPort;

  (world as { evidence: EvidenceRuntime }).evidence = fakeEvidence(world);

  const recordings = new Map<string, Recording>();
  (world as { recordings: RecordingRegistry }).recordings = {
    create: (spec: RecordingCreate) => {
      world.created.push(spec);
      const id = `rec_${(recordings.size + 1).toString(16).padStart(8, "0")}`;
      const rec: Recording = {
        id,
        create: spec,
        view: () =>
          world.finishedView ?? {
            recording_id: id,
            kind: "api",
            state: "active",
            events: 0,
            dropped: 0,
            ends_in_ms: spec.durationMs,
            end_reason: null,
          },
      };
      recordings.set(id, rec);
      return rec;
    },
    get: (id: string) => recordings.get(id),
  } as unknown as RecordingRegistry;
  return world;
};

export const failWith = (error: BeaError): Result<ProfileInstallResult, BeaError> => err(error);
