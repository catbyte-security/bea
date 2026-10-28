/**
 * Local fakes for the watch-area MCP boundary tests (WP9-WATCH). The shared fakes of WP1 (fakeEvidence) and WP4
 * (fakeSession, fakeAgentRpc) are built in parallel, so this file implements only the port members the watch
 * handlers call, and records every call for assertions. Nothing here touches a process or the file system except
 * the PE fake (none) and the exports directory the tests read back.
 */
import type { AddressRef } from "../../../../src/domain/address/addressRef.js";
import { Deadline } from "../../../../src/domain/deadline.js";
import type { BeaError } from "../../../../src/domain/errors/beaError.js";
import type { BeaEvidence, BlobRef } from "../../../../src/domain/evidence/record.js";
import type { EvId, FxId, StId } from "../../../../src/domain/ids.js";
import type { JsonObject, JsonValue } from "../../../../src/domain/json.js";
import { err, ok, type Result } from "../../../../src/domain/result.js";
import type { AddressService, ResolvedAddress } from "../../../../src/ports/address.js";
import type { EvidenceDraft, EvidenceRuntime, StreamSpec } from "../../../../src/ports/evidence.js";
import type { PeImageCache, FileHashCache } from "../../../../src/ports/pe.js";
import type {
  EventRecord,
  InstrumentStateView,
  Recording,
  RecordingCreate,
  RecordingRegistry,
} from "../../../../src/ports/recordings.js";
import type {
  DynamicSessionPort,
  LiveSession,
  OperationContext,
  WaitCondition,
} from "../../../../src/ports/sessions.js";
import type { BeaServices } from "../../../../src/application/services/index.js";
import type { AgentMethodName } from "../../../../src/shared/agentProtocol.js";

export const SESSION = "00000000-0000-4000-8000-0000000000aa";
const INSTANCE = `pi_${"a".repeat(64)}` as const;
const MAIN_PATH = "C:\\fixtures\\game_sim.exe";
const MAP_ID = `mm_${"b".repeat(64)}` as const;
const hex64 = (n: number): string => n.toString(16).padStart(64, "0");

export interface AgentCall {
  readonly method: AgentMethodName;
  readonly params: unknown;
}
export type AgentScript = (method: AgentMethodName, params: unknown) => Result<unknown, BeaError>;

export interface FakeWorld {
  readonly services: Partial<BeaServices>;
  readonly agentCalls: AgentCall[];
  readonly drafts: EvidenceDraft<JsonValue>[];
  readonly effects: JsonObject[];
  readonly transitions: { id: string; to: string }[];
  readonly binds: { agentStream: string; spec: StreamSpec }[];
  readonly ended: string[];
  readonly recordings: Map<string, FakeRecording>;
  readonly blobs: Map<string, Uint8Array>;
  readonly waits: WaitCondition[];
  /** evidence query results by id */
  readonly evidence: Map<string, JsonObject>;
  agent: AgentScript;
  /** what happens to an active recording during waitFor */
  onWait: ((rec: FakeRecording) => void) | null;
  sessionKind: "live" | "emulation" | "closed" | null;
  /** VA of the enclosing .pdata function start describeCode reports (null: no function) */
  functionStart: bigint | null;
}

export class FakeRecording implements Recording {
  readonly id: string;
  state: InstrumentStateView["state"] = "active";
  end_reason: InstrumentStateView["end_reason"] = null;
  summary: JsonObject | undefined = undefined;
  events: EventRecord[] = [];
  constructor(
    id: string,
    readonly create: RecordingCreate,
  ) {
    this.id = id;
  }
  view(): InstrumentStateView {
    return {
      recording_id: this.id,
      kind: this.create.kind,
      state: this.state,
      events: this.events.length,
      dropped: 0,
      ends_in_ms: this.state === "active" ? (this.create.durationMs ?? 0) : null,
      end_reason: this.end_reason,
      ...(this.summary === undefined ? {} : { summary: this.summary }),
    };
  }
}

const MAIN_BASE = 0x7ff700000000n;
const ref = (va: bigint): AddressRef => {
  const inMain = va >= MAIN_BASE && va < MAIN_BASE + 0x1e000n;
  return {
    va: `0x${va.toString(16)}`,
    module: inMain ? "game_sim.exe" : null,
    rva: inMain ? `0x${(va - MAIN_BASE).toString(16)}` : null,
    static_va: inMain ? `0x${(va - MAIN_BASE + 0x140000000n).toString(16)}` : null,
    static_base: inMain ? "0x140000000" : null,
    static_base_source: inMain ? "pe-header" : null,
    module_map_id: MAP_ID,
  };
};

/** AddrExpr subset: "0x…" (as is) and "game_sim.exe+0x…"/"game_sim.exe!physics_step" (base 0x7ff700000000). */
const resolveExpr = (expr: string): bigint | null => {
  if (/^0x[0-9a-f]+$/iu.test(expr)) return BigInt(expr);
  const rva = /^game_sim\.exe\+(0x[0-9a-f]+)$/iu.exec(expr);
  if (rva?.[1] !== undefined) return MAIN_BASE + BigInt(rva[1]);
  if (expr === "game_sim.exe!physics_step") return 0x7ff7000017a0n;
  return null;
};

const newWorld = (): FakeWorld => ({
  services: {},
  agentCalls: [],
  drafts: [],
  effects: [],
  transitions: [],
  binds: [],
  ended: [],
  recordings: new Map(),
  blobs: new Map(),
  waits: [],
  evidence: new Map(),
  agent: () => err({ _tag: "Internal", operation: "fake-agent" }),
  onWait: null,
  sessionKind: "live",
  functionStart: null,
});

/** The live session: agent calls and stream binds are recorded; waitFor lets the test finish active recordings. */
const fakeSession = (world: FakeWorld): LiveSession =>
  ({
    id: SESSION,
    kind: "live",
    ownership: "owned",
    state: "running",
    instanceId: INSTANCE,
    identity: { image: { path: MAIN_PATH } },
    paused: false,
    agent: {
      health: { state: "ok" },
      call: async (method: AgentMethodName, params: unknown) => {
        world.agentCalls.push({ method, params });
        return world.agent(method, params);
      },
    },
    streams: {
      bind: async (agentStream: string, spec: StreamSpec) => {
        world.binds.push({ agentStream, spec });
        return ok({ stream_id: `st_${hex64(world.binds.length)}` as StId });
      },
      writer: () => undefined,
      counters: () => null,
      end: async (agentStream: string) => {
        world.ended.push(agentStream);
        return err({ _tag: "Internal", operation: "fake-stream-end" });
      },
    },
    liveness: () => ({ state: "alive", basis: "jobhost" }),
    waitFor: async (cond: WaitCondition) => {
      world.waits.push(cond);
      for (const r of world.recordings.values()) if (r.state === "active") world.onWait?.(r);
      return { satisfied: true, timedOut: false, cancelled: false, state: "running", waitedMs: 1 };
    },
  }) as unknown as LiveSession;

const fakeSessions = (world: FakeWorld, session: LiveSession): DynamicSessionPort => {
  let seq = 0;
  const opOf = (name: string, signal?: AbortSignal): OperationContext => ({
    opId: ++seq,
    name,
    signal: signal ?? new AbortController().signal,
    deadline: Deadline.after(30_000),
  });
  return {
    admit: async <T>(
      name: string,
      req: { signal?: AbortSignal },
      fn: (op: OperationContext) => Promise<Result<T, BeaError>>,
    ) => fn(opOf(name, req.signal)),
    kindOf: () => world.sessionKind,
    withSession: async <T>(
      _id: string,
      _op: OperationContext,
      _mode: string,
      fn: (s: LiveSession) => Promise<Result<T, BeaError>>,
    ) => fn(session),
  } as unknown as DynamicSessionPort;
};

const fakeAddress = (world: FakeWorld): AddressService =>
  ({
    describeCode: async (_space: unknown, va: bigint) => ({
      va: `0x${va.toString(16)}`,
      at: `game_sim.exe+0x${(va - 0x7ff700000000n).toString(16)}`,
      static: null,
      func:
        world.functionStart === null ? null : `game_sim.exe+0x${(world.functionStart - 0x7ff700000000n).toString(16)}`,
      sym: null,
    }),
    resolve: async (_space: unknown, expr: string) => {
      const va = resolveExpr(expr);
      if (va === null)
        return err({
          _tag: "AddressUnmapped",
          operation: "watch",
          address: expr.slice(0, 60),
          module_map_id: null,
        } as BeaError);
      return ok({ ref: ref(va), moduleMapId: MAP_ID, va } as ResolvedAddress);
    },
    prepare: async () => undefined,
  }) as unknown as AddressService;

/** recorder.record: keeps the draft and answers the stored record the handlers project into the envelope. */
const fakeRecord = (world: FakeWorld) => async (draft: EvidenceDraft<JsonValue>) => {
  world.drafts.push(draft);
  const record = {
    schema: "bea.evidence/1",
    evidence_id: `ev_${hex64(world.drafts.length)}` as EvId,
    predicate_type: draft.predicate_type,
    operation: draft.operation,
    parameters: {},
    subject:
      draft.subject !== null && "instance_id" in draft.subject
        ? { kind: "process-instance", instance_id: draft.subject.instance_id, module_map_id: MAP_ID }
        : null,
    observed_at:
      draft.capture === undefined
        ? null
        : {
            run_id: "run_20260101T000000Z_0000000000000001",
            seq: 5,
            mono_ns: "1",
            wall: "2026-01-01T00:00:00.000Z",
            effect_epoch: 1,
            module_map_epoch: 1,
          },
    provider: draft.provider,
    agent: null,
    confidence: draft.predicate_type === "bea.coverage.export" ? "derived" : "observed",
    authority: "live-process",
    perturbation: { level: "passive", active_effect_ids: [], tainted_by: [] },
    result: draft.result,
    raw_result: null,
    blobs: draft.blobs ?? [],
    coverage: draft.coverage,
    limitations: [...(draft.limitations ?? [])],
    locations: [...(draft.locations ?? [])],
    evidence_links: [...(draft.evidence_links ?? [])],
    external_refs: [],
    effects: [...(draft.effects ?? [])],
    redactions: [],
    untrusted: true,
  } as unknown as BeaEvidence<JsonValue>;
  return ok({ record, outcome: "added" as const });
};

/** The module map the watch handlers turn into the recording's module legend. */
const MODULE_MAP = {
  epoch: 1,
  map: () => ({
    modules: [
      {
        base: "0x7ff700000000",
        size: 0x1e000,
        path_sha256: "c".repeat(64),
        display: { name: "game_sim.exe", path: MAIN_PATH },
      },
      {
        base: "0x7ffa00000000",
        size: 0x100000,
        path_sha256: "d".repeat(64),
        display: { name: "msvcrt.dll", path: "C:\\Windows\\System32\\msvcrt.dll" },
      },
    ],
  }),
};

const notFound = (operation: string, kind: string, id: string): BeaError =>
  ({ _tag: "ReferenceNotFound", operation, reference: { kind, id } }) as BeaError;

const fakeEvidence = (world: FakeWorld): EvidenceRuntime =>
  ({
    literals: () => ok({ count: 0, texts: [], spellings: [] }),
    effects: {
      apply: async (draft: JsonObject) => {
        world.effects.push(draft);
        return ok({ effect_id: `fx_${hex64(world.effects.length)}` as FxId });
      },
      transition: async (id: string, to: string) => {
        world.transitions.push({ id, to });
        return ok({});
      },
    },
    instances: {
      capture: () => ({ anchor: {}, module_map_id: MAP_ID, perturbation: {}, tainted_count: 0 }),
      get: () => undefined,
    },
    modules: { current: () => MODULE_MAP },
    recorder: { record: fakeRecord(world) },
    locationOf: (a: AddressRef, size?: number) => ({
      kind: "address",
      va: a.va,
      size: size ?? null,
      module_map_id: a.module_map_id,
      module_key: a.module?.toLowerCase() ?? null,
      rva: a.rva,
      image_sha256: null,
    }),
    blobs: {
      put: async (src: Uint8Array) => {
        const sha = hex64(world.blobs.size + 1);
        world.blobs.set(sha, src);
        return ok({ role: "coverage", sha256: sha, bytes: src.length, media_type: "application/json" } as BlobRef);
      },
      read: async (sha: string) => {
        const b = world.blobs.get(sha);
        return b === undefined ? err(notFound("blob", "blob", sha)) : ok(b);
      },
    },
    query: {
      // the production shape (src/providers/evidence/EvidenceQuery.ts complete): {record_kind, origin, value}
      complete: async (id: string) => {
        const e = world.evidence.get(id);
        return e === undefined
          ? err(notFound("get_evidence", "evidence", id))
          : ok({ record_kind: "evidence", origin: "local", value: e });
      },
    },
  }) as unknown as EvidenceRuntime;

const fakeRecordings = (world: FakeWorld): RecordingRegistry => {
  let recSeq = 0;
  return {
    create: (create: RecordingCreate) => {
      const rec = new FakeRecording(`rec_${(++recSeq + 0xa0).toString(16).padStart(8, "0")}`, create);
      world.recordings.set(rec.id, rec);
      return rec;
    },
    get: (id: string) => world.recordings.get(id),
    list: () => [...world.recordings.values()],
    events: async function* (id: string) {
      for (const e of world.recordings.get(id)?.events ?? []) yield e;
    },
  } as unknown as RecordingRegistry;
};

/** No image on disk: function attribution reports the blocks as unresolved. */
const fakePe = () => ({
  images: {
    open: async () =>
      err({
        _tag: "FileOperationFailed",
        operation: "pe",
        file_operation: "read",
        path: "x",
        reason: "missing",
      } as BeaError),
  } as unknown as PeImageCache,
  hashes: { sha256: async () => ok("e".repeat(64)) } as unknown as FileHashCache,
});

export const createWorld = (): FakeWorld => {
  const world = newWorld();
  Object.assign(world.services, {
    sessions: fakeSessions(world, fakeSession(world)),
    address: fakeAddress(world),
    evidence: fakeEvidence(world),
    recordings: fakeRecordings(world),
    pe: fakePe(),
  });
  return world;
};
