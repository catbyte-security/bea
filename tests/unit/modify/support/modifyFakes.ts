import type { BeaServices } from "../../../../src/application/services/index.js";
import { notImplementedPort } from "../../../../src/application/notImplemented.js";
import type { AddressRef } from "../../../../src/domain/address/addressRef.js";
import { Deadline } from "../../../../src/domain/deadline.js";
import type { Effect } from "../../../../src/domain/effects/effect.js";
import { isBeaError, type BeaError } from "../../../../src/domain/errors/beaError.js";
import { mapAgentError } from "../../../../src/domain/errors/agentErrorMap.js";
import { COMPLETE } from "../../../../src/domain/evidence/coverage.js";
import type { BeaEvidence, Location } from "../../../../src/domain/evidence/record.js";
import type { EvId, FxId, MmId, PiId, StId } from "../../../../src/domain/ids.js";
import type { JsonValue } from "../../../../src/domain/json.js";
import { err, ok, type Result } from "../../../../src/domain/result.js";
import type { AddressService } from "../../../../src/ports/address.js";
import type { AgentRpc } from "../../../../src/ports/agentRpc.js";
import type {
  EffectDraft,
  EffectRegistry,
  EvidenceDraft,
  EvidenceRuntime,
  SensitiveLiterals,
  StreamSpec,
  StreamWriter,
} from "../../../../src/ports/evidence.js";
import type { RecordingCreate, RecordingRegistry } from "../../../../src/ports/recordings.js";
import type {
  DynamicSessionPort,
  LiveSession,
  OperationContext,
  SessionEndedEvent,
  UserScriptOutcome,
  UserScriptRequest,
} from "../../../../src/ports/sessions.js";
import type { AgentError, AgentMethodName, AgentParams, AgentValue } from "../../../../src/shared/agentProtocol.js";
import { formatHex, parseHex } from "../../../../src/shared/hex.js";

/**
 * WP12-local fakes over the frozen ports (no shared fake fits a full write/override/script flow yet). One FakeWorld =
 * one live session with a scriptable agent, an evidence runtime that records drafts, an address service that maps
 * "module+0xRVA" / "0xVA" text, and counters every assertion can read (agent calls, admissions, effects, records).
 */
export const SESSION_ID = "3f2b8c1e-4d5a-4e6f-9a0b-1c2d3e4f5a6b";
export const INSTANCE_ID = `pi_${"1".repeat(64)}` as PiId;
export const MODULE_MAP_ID = `mm_${"2".repeat(64)}` as MmId;
export const MODULE_BASE = 0x7ff6_0000_0000n;
const RUN_ID = "run_20261028T000000Z_0123456789abcdef";

const id64 = (prefix: string, n: number): string => `${prefix}_${n.toString(16).padStart(64, "0")}`;

export type AgentHandler<M extends AgentMethodName> = (
  params: AgentParams<M>,
) => Result<AgentValue<M>, AgentError | BeaError> | Promise<Result<AgentValue<M>, AgentError | BeaError>>;

export interface FakeWorld {
  readonly session: LiveSession & { paused: boolean; state: LiveSession["state"] };
  readonly agentCalls: { readonly method: AgentMethodName; readonly params: unknown }[];
  readonly handlers: Partial<{ [M in AgentMethodName]: AgentHandler<M> }>;
  readonly effects: { readonly draft: EffectDraft; readonly id: FxId }[];
  readonly transitions: {
    readonly id: FxId;
    readonly to: string;
    readonly ok: boolean | null;
    readonly reason: string;
  }[];
  readonly records: EvidenceDraft<JsonValue>[];
  readonly scripts: UserScriptRequest[];
  scriptOutcome: Result<UserScriptOutcome, BeaError>;
  readonly recordings: RecordingCreate[];
  readonly binds: { readonly agentStream: string; readonly spec: StreamSpec }[];
  readonly streamEnds: string[];
  /** evidence blobs stored (text) */
  readonly blobs: { readonly role: string; readonly text: string }[];
  /** next blob put answers {redacted:true} */
  redactBlobs: boolean;
  readonly endedListeners: ((event: SessionEndedEvent) => void)[];
  admissions: number;
  failEffects: boolean;
  /** VA of the enclosing .pdata function start describeCode reports for every address (null: no function) */
  functionStart: bigint | null;
  readonly services: Partial<BeaServices>;
}

const isAgentError = (e: AgentError | BeaError): e is AgentError => !isBeaError(e);

export const addressRef = (va: bigint): AddressRef => {
  const rva = va - MODULE_BASE;
  const inModule = rva >= 0n && rva < 0x10_0000n;
  return {
    va: formatHex(va),
    module: inModule ? "game_sim.exe" : null,
    rva: inModule ? formatHex(rva) : null,
    static_va: inModule ? formatHex(0x1_4000_0000n + rva) : null,
    static_base: inModule ? "0x140000000" : null,
    static_base_source: inModule ? "pe-header" : null,
    module_map_id: MODULE_MAP_ID,
  };
};

/** "game_sim.exe+0xRVA" | "0xVA" | anything else → address_unmapped-free invalid_request */
const resolveText = (expr: string): bigint | null => {
  const plus = /^game_sim\.exe\+(0x[0-9a-fA-F]+)$/u.exec(expr);
  if (plus?.[1] !== undefined) return MODULE_BASE + parseHex(plus[1]);
  if (/^0x[0-9a-fA-F]{1,16}$/u.test(expr)) return parseHex(expr);
  if (expr === "game_sim.exe!g_world") return MODULE_BASE + 0x5000n;
  return null;
};

const literals: SensitiveLiterals = { count: 0, texts: [], spellings: [] };

interface Counters {
  effect: number;
  evidence: number;
  stream: number;
  recording: number;
}

const fakeAgent = (world: FakeWorld): AgentRpc => {
  return {
    health: { state: "ok" },
    call: async (method, params, opts) => {
      world.agentCalls.push({ method, params });
      const handler = world.handlers[method] as AgentHandler<typeof method> | undefined;
      if (handler === undefined)
        return err(
          mapAgentError(
            { _tag: "Unsupported", message: "fake", feature: method, reason: "not-implemented" },
            { operation: opts.op.name },
          ),
        );
      const reply = await handler(params as never);
      if (reply.ok) return reply as never;
      const error = reply.error;
      return err(isAgentError(error) ? mapAgentError(error, { operation: opts.op.name }) : error);
    },
  };
};

const fakeWriter = (counters: Counters, agentStream: string): StreamWriter => {
  return {
    stream_id: id64("st", ++counters.stream) as StId,
    descriptor_sha256: "0".repeat(64),
    append: () => "accepted",
    noteDropped: () => undefined,
    checkpoint: () => Promise.reject(new Error("unused")),
    end: () => Promise.reject(new Error(`unused ${agentStream}`)),
    counters: { records: 0, dropped: 0, redacted: 0, bytes: 0, state: "live" },
    onQuota: () => undefined,
  } satisfies StreamWriter;
};

const fakeSession = (world: FakeWorld, counters: Counters): FakeWorld["session"] => {
  return {
    id: SESSION_ID,
    kind: "live",
    ownership: "owned",
    state: "running",
    instanceId: INSTANCE_ID,
    identity: {} as LiveSession["identity"],
    agent: fakeAgent(world),
    streams: {
      bind: async (agentStream: string, spec: StreamSpec) => {
        world.binds.push({ agentStream, spec });
        return ok(fakeWriter(counters, agentStream));
      },
      writer: () => undefined,
      counters: () => null,
      end: async (agentStream: string) => {
        world.streamEnds.push(agentStream);
        return err({ _tag: "Internal", operation: "fake.end" } as BeaError);
      },
    },
    output: null,
    lastCrash: null,
    paused: false,
    jobs: notImplementedPort("jobs"),
    scripts: {
      run: async (req: UserScriptRequest) => {
        world.scripts.push(req);
        return world.scriptOutcome;
      },
    },
    liveness: () => ({ state: "alive", basis: "jobhost" }),
    waitFor: () => Promise.reject(new Error("unused")),
    crash: async () => ok(null),
  } as unknown as FakeWorld["session"];
};

const fakeSessions = (world: FakeWorld, session: FakeWorld["session"]): DynamicSessionPort => {
  return {
    admit: async <T>(_name: string, _req: unknown, fn: (op: OperationContext) => Promise<Result<T, BeaError>>) => {
      world.admissions += 1;
      return fn(fakeOp("modify-test"));
    },
    kindOf: (id: string) => (id === SESSION_ID ? "live" : null),
    withSession: async <T>(
      _id: string,
      _op: OperationContext,
      _mode: string,
      fn: (s: LiveSession) => Promise<Result<T, BeaError>>,
    ) => fn(session),
    onSessionEnded: (listener: (event: SessionEndedEvent) => void) => {
      world.endedListeners.push(listener);
      return () => undefined;
    },
  } as unknown as DynamicSessionPort;
};

const fakeAddress = (world: FakeWorld): AddressService => {
  const at = (va: bigint): string => `game_sim.exe+${formatHex(va - MODULE_BASE)}`;
  return {
    describeCode: async (_space: unknown, va: bigint) => ({
      va: formatHex(va),
      at: at(va),
      static: null,
      func: world.functionStart === null ? null : at(world.functionStart),
      sym: null,
    }),
    resolve: async (_space: unknown, expr: string, _op: OperationContext, opts?: { readonly path?: string }) => {
      const va = resolveText(expr);
      if (va === null)
        return err({
          _tag: "InputError",
          operation: "fake.resolve",
          issues: [{ path: opts?.path ?? "address", reason: "invalid_format", message: "unresolvable" }],
        } as BeaError);
      return ok({ ref: addressRef(va), moduleMapId: MODULE_MAP_ID, va });
    },
  } as unknown as AddressService;
};

const fakeEffects = (world: FakeWorld, counters: Counters): EffectRegistry => {
  return {
    apply: async (draft: EffectDraft) => {
      if (world.failEffects) return err({ _tag: "Internal", operation: "fake.effects.apply" } as BeaError);
      const effectId = id64("fx", ++counters.effect) as FxId;
      world.effects.push({ draft, id: effectId });
      return ok({ effect_id: effectId } as Effect);
    },
    transition: async (id: FxId, to: string, detail: { reason: string; verification: { ok: boolean } | null }) => {
      world.transitions.push({ id, to, ok: detail.verification?.ok ?? null, reason: detail.reason });
      return ok({} as never);
    },
  } as unknown as EffectRegistry;
};

const fakeEvidence = (world: FakeWorld, counters: Counters): EvidenceRuntime => {
  return {
    literals: (perCall: readonly string[] | undefined) =>
      perCall?.some((l) => new TextEncoder().encode(l).length < 4) === true
        ? err({
            _tag: "InputError",
            operation: "fake.literals",
            issues: [{ path: "sensitive_values", reason: "invalid_value", message: "too short" }],
          } as BeaError)
        : ok(literals),
    blobs: {
      put: async (src: Uint8Array, meta: { readonly role: string; readonly media_type: string }) => {
        if (world.redactBlobs) return ok({ redacted: true as const });
        const text = new TextDecoder().decode(src);
        world.blobs.push({ role: meta.role, text });
        return ok({ role: meta.role, sha256: "a".repeat(64), bytes: src.length, media_type: meta.media_type });
      },
    },
    locationOf: (ref: AddressRef, size?: number): Location => ({
      kind: "address",
      va: ref.va,
      size: size ?? null,
      module_map_id: ref.module_map_id,
      module_key: ref.module,
      rva: ref.rva,
      image_sha256: null,
    }),
    effects: fakeEffects(world, counters),
    instances: {
      capture: () => ({
        anchor: {
          run_id: RUN_ID,
          seq: 1,
          mono_ns: "1",
          wall: "2026-10-28T00:00:00.000Z",
          effect_epoch: 1,
          module_map_epoch: 1,
        },
        module_map_id: MODULE_MAP_ID,
        perturbation: { level: "intrusive", active_effect_ids: [], tainted_by: [] },
        tainted_count: 0,
      }),
    },
    recorder: {
      record: async <R extends JsonValue>(draft: EvidenceDraft<R>) => {
        world.records.push(draft as EvidenceDraft<JsonValue>);
        const record: BeaEvidence<R> = {
          schema: "bea.evidence/1",
          evidence_id: id64("ev", ++counters.evidence) as EvId,
          predicate_type: draft.predicate_type,
          operation: draft.operation,
          parameters: {},
          subject: { kind: "process-instance", instance_id: INSTANCE_ID, module_map_id: MODULE_MAP_ID },
          observed_at: draft.capture?.anchor ?? null,
          provider: draft.provider,
          agent: null,
          confidence: "observed",
          authority: "live-process",
          perturbation: { level: "intrusive", active_effect_ids: [...(draft.effects ?? [])], tainted_by: [] },
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
        return ok({ record, outcome: "added" as const });
      },
    },
  } as unknown as EvidenceRuntime;
};

const fakeRecordings = (world: FakeWorld, counters: Counters): RecordingRegistry => {
  return {
    create: (spec: RecordingCreate) => {
      world.recordings.push(spec);
      const id = `rec_${(++counters.recording).toString(16).padStart(8, "0")}`;
      return {
        id,
        create: spec,
        view: () => ({
          recording_id: id,
          kind: spec.kind,
          state: "active" as const,
          events: 0,
          dropped: 0,
          ends_in_ms: spec.durationMs,
          end_reason: null,
        }),
      };
    },
  } as unknown as RecordingRegistry;
};

export const createFakeWorld = (): FakeWorld => {
  const counters: Counters = { effect: 0, evidence: 0, stream: 0, recording: 0 };
  const world: FakeWorld = {
    session: undefined as unknown as FakeWorld["session"],
    agentCalls: [],
    handlers: {},
    effects: [],
    transitions: [],
    records: [],
    scripts: [],
    scriptOutcome: ok({ messages: [], errors: [], truncated: false, unloaded: true }),
    recordings: [],
    binds: [],
    streamEnds: [],
    blobs: [],
    redactBlobs: false,
    endedListeners: [],
    admissions: 0,
    failEffects: false,
    functionStart: null,
    services: {},
  };
  const session = fakeSession(world, counters);
  (world as { session: FakeWorld["session"] }).session = session;
  (world as { services: Partial<BeaServices> }).services = {
    sessions: fakeSessions(world, session),
    address: fakeAddress(world),
    evidence: fakeEvidence(world, counters),
    recordings: fakeRecordings(world, counters),
  };
  return world;
};

export const fakeOp = (name: string): OperationContext => {
  const deadline = Deadline.after(30_000);
  return { opId: 1, name, signal: deadline.signal(), deadline };
};

/** Agent replies of a well-behaved agent for a data write at `va` with the given bytes. */
export const installWriteAgent = (
  world: FakeWorld,
  opts: { readonly protection?: string; readonly before?: string; readonly verified?: boolean } = {},
): void => {
  const protection = opts.protection ?? "rw-";
  let current = opts.before;
  world.handlers.describeAddresses = (p) =>
    ok({
      results: p.addresses.map((va) => ({
        va,
        module: "game_sim.exe",
        rva: null,
        function: null,
        range: { base: va, size: 0x1000, protection },
        export_hint: null,
        bea_patched: false,
        bea_guarded: false,
      })),
    });
  let next = 0;
  world.handlers.writeMemory = (p) => {
    const bytes = p.bytes ?? "";
    const before = current ?? "00".repeat(bytes.length / 2);
    current = bytes;
    next += 1;
    return ok({
      write_id: `wr${String(next)}`,
      address: p.address,
      size: bytes.length / 2,
      before,
      after: opts.verified === false ? "ff".repeat(bytes.length / 2) : bytes,
      verified: opts.verified ?? true,
      method: p.mode === "code" ? "patchCode" : protection.includes("w") ? "direct" : "protect-and-restore",
      protection_before: protection,
      protection_after: protection,
      effect: { kind: "memory-written", reversible: true, targets: [], thread_ids: null, before: [] },
    });
  };
};
