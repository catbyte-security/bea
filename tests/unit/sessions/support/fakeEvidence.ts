import { createHash } from "node:crypto";

import { notImplementedPort } from "../../../../src/application/notImplemented.js";
import type { Effect, EffectState, EffectTransition } from "../../../../src/domain/effects/effect.js";
import { EFFECT_KIND_TABLE } from "../../../../src/domain/effects/effect.js";
import type { BeaError } from "../../../../src/domain/errors/beaError.js";
import { COMPLETE } from "../../../../src/domain/evidence/coverage.js";
import type { BeaEvidence, BlobRef } from "../../../../src/domain/evidence/record.js";
import { NO_PERTURBATION } from "../../../../src/domain/evidence/record.js";
import { idOf, type EvId, type FxId, type MmId, type PiId, type StId } from "../../../../src/domain/ids.js";
import type { JsonObject, JsonValue } from "../../../../src/domain/json.js";
import { instanceIdOf, pathDigest, type ProcessInstance } from "../../../../src/domain/process/instance.js";
import { err, ok, type Result } from "../../../../src/domain/result.js";
import type {
  AnchorCapture,
  BlobStore,
  EffectDraft,
  EffectRegistry,
  EvidenceDraft,
  EvidenceRuntime,
  FrameBatchHeader,
  InstanceObservation,
  InstanceRegistry,
  ModuleMapTracker,
  RecordedEvidence,
  SensitiveLiterals,
  StreamEndReason,
  StreamSpec,
  StreamStore,
  StreamWriter,
  AppendOutcome,
} from "../../../../src/ports/evidence.js";
import type {
  InstrumentStateView,
  Recording,
  RecordingCreate,
  RecordingEndReason,
  RecordingRegistry,
} from "../../../../src/ports/recordings.js";

/**
 * Minimal in-memory EvidenceRuntime + RecordingRegistry for WP4's unit tests (local fakes; WP1 owns the shared
 * fakeEvidence). Faithful where the session layer depends on it: ids are content-addressed, instance ids equal
 * instanceIdOf(identity), effects follow the S2 state machine, stream writers keep frames and counters, blobs consume
 * their (async) source and hash it, literals refuse entries under 4 bytes.
 */
const RUN = "run_20261028T000000Z_0000000000000001" as const;
let seq = 0;

const capture = (): AnchorCapture => ({
  anchor: {
    run_id: RUN,
    seq: (seq += 1),
    mono_ns: "1",
    wall: "2026-10-28T00:00:00.000Z",
    effect_epoch: 0,
    module_map_epoch: 1,
  },
  module_map_id: `mm_${"1".repeat(64)}`,
  perturbation: NO_PERTURBATION,
  tainted_count: 0,
});

const recordOf = <R extends JsonValue>(draft: EvidenceDraft<R>): BeaEvidence<R> => {
  const evidenceId = idOf("ev", { predicate: draft.predicate_type, operation: draft.operation, seq: (seq += 1) });
  return {
    schema: "bea.evidence/1",
    evidence_id: evidenceId,
    predicate_type: draft.predicate_type,
    operation: draft.operation,
    parameters: draft.input,
    subject:
      draft.subject === null
        ? null
        : draft.subject.kind === "process-instance"
          ? {
              kind: "process-instance",
              instance_id: draft.subject.instance_id,
              module_map_id: draft.capture?.module_map_id ?? null,
            }
          : draft.subject,
    observed_at: draft.capture?.anchor ?? null,
    provider: draft.provider,
    agent: draft.agent ?? null,
    confidence: draft.confidence ?? "observed",
    authority: draft.authority ?? "live-process",
    perturbation: NO_PERTURBATION,
    result: draft.result,
    raw_result: null,
    blobs: [...(draft.blobs ?? [])],
    coverage: draft.coverage,
    limitations: [...(draft.limitations ?? [])],
    locations: [],
    evidence_links: [...(draft.evidence_links ?? [])],
    external_refs: [],
    effects: [...(draft.effects ?? [])],
    redactions: [],
    untrusted: true,
  };
};

export class FakeStreamWriter implements StreamWriter {
  readonly stream_id: StId;
  readonly descriptor_sha256 = "0".repeat(64);
  readonly spec: StreamSpec;
  readonly frames: { readonly header: FrameBatchHeader; readonly payload: Buffer }[] = [];
  readonly drops: { readonly n: number; readonly reason: string }[] = [];
  nextOutcome: AppendOutcome = "accepted";
  endReason: StreamEndReason | null = null;
  endCalls = 0;
  #quota: (() => void) | null = null;
  readonly #evidence: FakeEvidence;
  readonly counters = { records: 0, dropped: 0, redacted: 0, bytes: 0, state: "live" as "live" | "ended" };

  constructor(evidence: FakeEvidence, spec: StreamSpec, n: number) {
    this.#evidence = evidence;
    this.spec = spec;
    this.stream_id = idOf("st", { channel: spec.source.channel, n });
  }

  append(header: FrameBatchHeader, payload: Uint8Array): AppendOutcome {
    if (this.counters.state === "ended") return "closed";
    const outcome = this.nextOutcome;
    if (outcome === "accepted") {
      this.frames.push({ header, payload: Buffer.from(payload) });
      this.counters.records += header.count;
      this.counters.bytes += payload.length;
    }
    return outcome;
  }

  noteDropped(n: number, reason: string): void {
    this.drops.push({ n, reason });
    this.counters.dropped += n;
  }

  async checkpoint(): Promise<Result<RecordedEvidence<JsonObject>, BeaError>> {
    return this.#manifest("checkpoint");
  }

  async end(reason: StreamEndReason): Promise<Result<RecordedEvidence<JsonObject>, BeaError>> {
    this.endCalls += 1;
    this.endReason = reason;
    this.counters.state = "ended";
    return this.#manifest(reason);
  }

  onQuota(callback: () => void): void {
    this.#quota = callback;
  }

  /** Test helper: the writer hit its quota. */
  triggerQuota(): void {
    this.#quota?.();
  }

  /** NDJSON rows of every accepted frame (JSON streams). */
  rows(): unknown[] {
    return this.frames.flatMap((f) =>
      f.payload
        .toString("utf8")
        .split("\n")
        .filter((line) => line.length > 0)
        .map((line) => JSON.parse(line) as unknown),
    );
  }

  #manifest(reason: string): Result<RecordedEvidence<JsonObject>, BeaError> {
    const record = recordOf({
      predicate_type: "bea.stream.manifest",
      operation: "stream_end",
      input: { stream_id: this.stream_id, reason },
      subject: null,
      provider: { id: "bea", name: "bea", version: null },
      result: { stream_id: this.stream_id, records: this.counters.records },
      coverage: COMPLETE,
      literals: this.#evidence.literals(undefined).ok ? NO_LITERALS : NO_LITERALS,
    });
    this.#evidence.records.push(record);
    return ok({ record, outcome: "added" });
  }
}

export const NO_LITERALS: SensitiveLiterals = { count: 0, texts: [], spellings: [] };

export class FakeEvidence implements EvidenceRuntime {
  readonly run = { id: RUN, dir: "C:/fake/run", kind: "mcp-stdio" as const };
  readonly records: BeaEvidence<JsonValue>[] = [];
  readonly drafts: EvidenceDraft<JsonValue>[] = [];
  readonly instancesById = new Map<PiId, ProcessInstance>();
  readonly instanceUpdates: { readonly id: PiId; readonly change: JsonObject }[] = [];
  readonly effectStates = new Map<FxId, EffectState>();
  readonly writers: FakeStreamWriter[] = [];
  readonly blobsStored: BlobRef[] = [];
  readonly moduleOps: { readonly instance: PiId; readonly op: string; readonly epoch: number }[] = [];
  readonly endAllCalls: { readonly instance: PiId; readonly reason: string }[] = [];
  recordFailure: BeaError | null = null;
  readonly #epochs = new Map<PiId, number>();

  readonly recorder = {
    record: async <R extends JsonValue>(draft: EvidenceDraft<R>): Promise<Result<RecordedEvidence<R>, BeaError>> => {
      if (this.recordFailure !== null) return err(this.recordFailure);
      this.drafts.push(draft as EvidenceDraft<JsonValue>);
      const record = recordOf(draft);
      this.records.push(record as BeaEvidence<JsonValue>);
      return ok({ record, outcome: "added" as const });
    },
  };

  readonly instances: InstanceRegistry = {
    register: async (obs: InstanceObservation) => {
      const identity = {
        t: "bea.pi/1" as const,
        device_id: obs.device_id,
        pid: obs.pid,
        start_time: obs.start_time,
        image_path_sha256: pathDigest(obs.main_module_path, "win32"),
      };
      const instanceId = instanceIdOf(identity);
      const instance: ProcessInstance = {
        instance_id: instanceId,
        identity,
        ownership: obs.ownership,
        image: { display: { path: obs.main_module_path, name: null }, sha256: null, file: null, pe: null },
        environment: obs.environment,
        agent: obs.agent,
        launch: obs.launch ?? null,
        state: obs.ownership === "owned" ? "suspended" : "running",
        exit: null,
      };
      this.instancesById.set(instanceId, instance);
      this.modules.apply(instanceId, {
        op: "snapshot",
        epoch: obs.initial_modules.epoch,
        modules: obs.initial_modules.modules,
      });
      const record = recordOf({
        predicate_type: "bea.process.instance",
        operation: "instance_register",
        input: { pid: obs.pid },
        subject: { kind: "process-instance", instance_id: instanceId },
        capture: capture(),
        provider: { id: "frida", name: "frida", version: "17.23.2" },
        result: { pid: obs.pid },
        coverage: COMPLETE,
        limitations: obs.limitations ?? [],
        literals: obs.literals,
      });
      this.records.push(record);
      return ok({ instance, evidence_id: record.evidence_id as EvId });
    },
    get: (id) => this.instancesById.get(id),
    capture: () => capture(),
    update: async (id, change) => {
      this.instanceUpdates.push({ id, change: JSON.parse(JSON.stringify(change)) as JsonObject });
      return ok(undefined);
    },
    hashImage: async () => err({ _tag: "Internal", operation: "hashImage" }),
  };

  readonly modules: ModuleMapTracker = {
    apply: (instance, ev) => {
      this.moduleOps.push({ instance, op: ev.op, epoch: ev.epoch });
      this.#epochs.set(instance, Math.max(this.#epochs.get(instance) ?? 0, ev.epoch));
    },
    current: (instance) => {
      const epoch = this.#epochs.get(instance);
      return epoch === undefined
        ? undefined
        : {
            epoch,
            map: () => ({
              module_map_id: `mm_${"2".repeat(64)}` as MmId,
              instance_id: instance,
              completeness: "complete",
              modules: [],
            }),
          };
    },
    at: () => undefined,
    ensureRecorded: async (instance, epoch) =>
      ok({ module_map_id: idOf("mm", { instance, epoch }), evidence_id: idOf("ev", { mm: instance, epoch }) }),
  };

  readonly effects: EffectRegistry = {
    apply: async (draft: EffectDraft) => {
      const table = EFFECT_KIND_TABLE[draft.kind];
      const effect = {
        schema: "bea.effect/1",
        effect_id: idOf("fx", { kind: draft.kind, instance: draft.instance_id, seq: (seq += 1) }),
        instance_id: draft.instance_id,
        kind: draft.kind,
        class: table.class,
        reversible: table.reversible === true,
        target: draft.target,
        parameters: draft.parameters,
        before: null,
        after: null,
        lifetime: null,
        stream_ids: [...(draft.stream_ids ?? [])],
        applied_by: draft.applied_by,
        applied_at: capture().anchor,
        display: { target_text: draft.display_target ?? null },
      } as Effect;
      this.effectStates.set(effect.effect_id as FxId, {
        effect,
        status: table.reversible === false ? "permanent" : "active",
        transitions: [],
      });
      return ok(effect);
    },
    transition: async (id, to, detail) => {
      const state = this.effectStates.get(id);
      if (state === undefined)
        return err({ _tag: "ReferenceNotFound", operation: "effect", reference: { kind: "effect", id } });
      const next: EffectState = {
        effect: state.effect,
        status: to,
        transitions: [
          ...state.transitions,
          {
            schema: "bea.effect-transition/1",
            effect_id: id,
            from: state.status === "revert-failed" ? "revert-failed" : "active",
            to,
            at: capture().anchor,
            ...detail,
          } as EffectTransition,
        ],
      };
      this.effectStates.set(id, next);
      return ok(next);
    },
    state: (id) => this.effectStates.get(id),
    active: (instance) =>
      [...this.effectStates.values()].filter(
        (s) => s.effect.instance_id === instance && (s.status === "active" || s.status === "revert-failed"),
      ),
    perturbation: () => NO_PERTURBATION,
    epoch: () => 0,
    originalBytes: () => ({ ranges: [] }),
    endAll: async (instance, reason) => {
      this.endAllCalls.push({ instance, reason });
      for (const [id, state] of this.effectStates)
        if (state.effect.instance_id === instance && (state.status === "active" || state.status === "revert-failed"))
          this.effectStates.set(id, { ...state, status: "implicit-end" });
    },
  };

  readonly streams: StreamStore = {
    open: async (spec) => {
      const writer = new FakeStreamWriter(this, spec, this.writers.length + 1);
      this.writers.push(writer);
      return ok(writer);
    },
    reader: () => err({ _tag: "Internal", operation: "reader" }),
  };

  readonly blobs: BlobStore = {
    put: async (src) => {
      const hash = createHash("sha256");
      let bytes = 0;
      if (src instanceof Uint8Array) {
        hash.update(src);
        bytes = src.length;
      } else
        for await (const chunk of src) {
          hash.update(chunk);
          bytes += chunk.length;
        }
      const ref: BlobRef = {
        role: "agent-blob",
        sha256: hash.digest("hex"),
        bytes,
        media_type: "application/octet-stream",
      };
      this.blobsStored.push(ref);
      return ok(ref);
    },
    has: () => false,
    size: () => undefined,
    open: async () => err({ _tag: "Internal", operation: "blob.open" }),
    read: async () => err({ _tag: "Internal", operation: "blob.read" }),
    verify: async () => ok(true as const),
  };

  readonly unknowns = notImplementedPort<EvidenceRuntime["unknowns"]>("unknowns");
  readonly query = notImplementedPort<EvidenceRuntime["query"]>("query");
  readonly bundles = notImplementedPort<EvidenceRuntime["bundles"]>("bundles");

  literals(perCall: readonly string[] | undefined): Result<SensitiveLiterals, BeaError> {
    const texts = perCall ?? [];
    const short = texts.findIndex((t) => Buffer.byteLength(t, "utf8") < 4);
    if (short >= 0)
      return err({
        _tag: "InputError",
        operation: "literals",
        issues: [
          { path: `redact_literals[${String(short)}]`, reason: "out_of_range", message: "at least 4 UTF-8 bytes" },
        ],
      });
    return ok({ count: texts.length, texts, spellings: texts.map((t) => Buffer.from(t, "utf8")) });
  }

  locationOf(): never {
    throw new Error("not used");
  }

  status(): ReturnType<EvidenceRuntime["status"]> {
    return {
      run_id: RUN,
      home: "C:/fake",
      usage: {
        ledger: { bytes: 0, quota: 1, reserve: 0 },
        blobs: { bytes: 0, quota: 1 },
        streams: { bytes: 0, quota_total: 1, per_stream_quota: 1, live: 0 },
      },
      counts: {
        evidence: this.records.length,
        effects_active: 0,
        unknowns_open: 0,
        instances: this.instancesById.size,
      },
    };
  }

  async finalize(): Promise<Result<void, BeaError>> {
    return ok(undefined);
  }

  writerFor(channel: string): FakeStreamWriter | undefined {
    return this.writers.find((w) => w.spec.source.channel === channel);
  }

  effectsOfKind(kind: string): EffectState[] {
    return [...this.effectStates.values()].filter((s) => s.effect.kind === kind);
  }
}

export class FakeRecordings implements RecordingRegistry {
  readonly all = new Map<string, { readonly create: RecordingCreate; view: InstrumentStateView }>();
  readonly resumed: string[] = [];
  readonly ended: { readonly id: string; readonly reason: RecordingEndReason }[] = [];
  #n = 0;

  create(spec: RecordingCreate): Recording {
    this.#n += 1;
    const id = `rec_${this.#n.toString(16).padStart(8, "0")}`;
    const entry = {
      create: spec,
      view: {
        recording_id: id,
        kind: spec.kind,
        state: "active",
        events: 0,
        dropped: 0,
        ends_in_ms: null,
        end_reason: null,
      } as InstrumentStateView,
    };
    this.all.set(id, entry);
    return this.#recording(id);
  }

  get(id: string): Recording | undefined {
    return this.all.has(id) ? this.#recording(id) : undefined;
  }

  list(sessionId: string): readonly Recording[] {
    return [...this.all.entries()]
      .filter(([, e]) => e.create.sessionId === sessionId)
      .map(([id]) => this.#recording(id));
  }

  async end(id: string, reason: RecordingEndReason): Promise<Result<InstrumentStateView, BeaError>> {
    const entry = this.all.get(id);
    if (entry === undefined)
      return err({ _tag: "ReferenceNotFound", operation: "end", reference: { kind: "recording", id } });
    this.ended.push({ id, reason });
    if (entry.view.state === "active")
      entry.view = { ...entry.view, state: "finished", end_reason: reason, summary: { ended: reason } };
    return ok(entry.view);
  }

  async *events(): AsyncIterable<never> {
    // no events in this fake
  }

  async summary(): Promise<Result<JsonObject, BeaError>> {
    return ok({});
  }

  onResumed(sessionId: string): void {
    this.resumed.push(sessionId);
  }

  #recording(id: string): Recording {
    const entry = this.all.get(id);
    if (entry === undefined) throw new Error(`no recording ${id}`);
    return { id, create: entry.create, view: () => this.all.get(id)?.view ?? entry.view };
  }
}
