import { sha256Hex } from "../../../src/domain/canonical.js";
import {
  EFFECT_EDGES,
  EFFECT_KIND_TABLE,
  type Effect,
  type EffectState,
  type EffectTransition,
} from "../../../src/domain/effects/effect.js";
import type { BeaError } from "../../../src/domain/errors/beaError.js";
import { inputError, invalidState, referenceNotFound } from "../../../src/domain/errors/constructors.js";
import { effectIdOf } from "../../../src/domain/evidence/authenticate.js";
import { buildEvidence } from "../../../src/domain/evidence/build.js";
import { COMPLETE } from "../../../src/domain/evidence/coverage.js";
import { sortedSet } from "../../../src/domain/evidence/invariants.js";
import { LIMITATIONS } from "../../../src/domain/evidence/limitations.js";
import type { BeaEvidence, BlobRef, Perturbation } from "../../../src/domain/evidence/record.js";
import { bytesToHex } from "../../../src/domain/hex.js";
import {
  idOf,
  type EvId,
  type FxId,
  type MmId,
  type PiId,
  type RunId,
  type StId,
  type UnkId,
} from "../../../src/domain/ids.js";
import type { JsonObject, JsonValue } from "../../../src/domain/json.js";
import {
  instanceIdOf,
  moduleMapIdOf,
  pathDigest,
  type ModuleMap,
  type ProcessInstance,
} from "../../../src/domain/process/instance.js";
import { NO_LITERALS, sensitiveLiterals, type SensitiveLiterals } from "../../../src/domain/redaction/literals.js";
import { bytesContainLiteral } from "../../../src/domain/redaction/redact.js";
import { err, ok, type Result } from "../../../src/domain/result.js";
import { nextRevision, scopeOf, unknownIdOf, type ResidualUnknown } from "../../../src/domain/unknowns/unknown.js";
import type {
  AnchorCapture,
  BlobStore,
  EffectDraft,
  EffectRegistry,
  EvidenceDraft,
  EvidenceQuery,
  EvidenceRuntime,
  EvidenceStatus,
  FrameBatchHeader,
  InstanceObservation,
  InstanceRegistry,
  ModuleMapTracker,
  RecordedEvidence,
  StreamEndReason,
  StreamReader,
  StreamRecord,
  StreamSpec,
  StreamStore,
  StreamWriter,
  UnknownInput,
  UnknownRegistry,
} from "../../../src/ports/evidence.js";
import { decodePayload } from "../../../src/providers/evidence/streamFrames.js";
import { manifestCoverage } from "../../../src/providers/evidence/streamManifest.js";

/**
 * WP-EVID test double: an IN-MEMORY EvidenceRuntime for every area's unit tests (DESIGN §8.2). Records go through the
 * same pure pipeline as production (buildEvidence: registry, invariants, redaction, ids), so a malformed draft fails
 * here exactly as it would in the run store. Nothing touches the disk; bundles and blobs.open() answer
 * capability_unavailable. Inspection helpers: `records`, `effectStates()`, `frames(streamId)`, `blobBytes(sha)`,
 * `unknownHead(id)`, `addInstance()`, `failNextRecord(error)`.
 */
export interface FakeEvidence extends EvidenceRuntime {
  readonly records: readonly BeaEvidence[];
  readonly effectStates: () => readonly EffectState[];
  readonly frames: (id: StId) => readonly { readonly header: FrameBatchHeader; readonly payload: Uint8Array }[];
  readonly blobBytes: (sha256: string) => Uint8Array | undefined;
  readonly unknownHead: (id: UnkId) => ResidualUnknown | undefined;
  /** register a live instance with a two-module map (game.exe at 0x140000000, ntdll) */
  readonly addInstance: (pid?: number, ownership?: "owned" | "attached") => Promise<PiId>;
  /** the next Recorder.record call fails with this error (record-before-deliver tests) */
  readonly failNextRecord: (error: BeaError) => void;
}

export interface FakeEvidenceOptions {
  readonly runId?: RunId;
  readonly serverLiterals?: readonly string[];
}

const AGENT = { bundle_sha256: "f".repeat(64), bea_version: "0.1.0", runtime: "qjs" } as const;
const notAvailable = (operation: string): BeaError => ({
  _tag: "CapabilityUnavailable",
  operation,
  capability: "server",
  reason: "not-implemented",
  retryable: false,
});

interface RawModule {
  readonly name: string;
  readonly base: `0x${string}`;
  readonly size: number;
  readonly path: string;
}
interface ModuleState {
  epoch: number;
  list: RawModule[];
  readonly recorded: Map<number, { readonly module_map_id: MmId; readonly evidence_id: EvId }>;
}
interface EffectEntry {
  readonly effect: Effect;
  readonly transitions: EffectTransition[];
  readonly before?: Uint8Array;
}
interface StreamEntry {
  readonly spec: StreamSpec;
  readonly frames: { header: FrameBatchHeader; payload: Uint8Array }[];
  readonly writer: StreamWriter;
}

const fold = (e: { readonly effect: Effect; readonly transitions: readonly EffectTransition[] }): EffectState => ({
  effect: e.effect,
  status: e.transitions.at(-1)?.to ?? (e.effect.reversible ? "active" : "permanent"),
  transitions: [...e.transitions],
});
const isActive = (s: EffectState): boolean => s.status === "active" || s.status === "revert-failed";

class InMemoryEvidence {
  readonly runId: RunId;
  readonly server: SensitiveLiterals;
  seq = 0;
  wall = Date.parse("2026-01-01T00:00:00.000Z");
  failNext: BeaError | undefined;
  fenced = false;
  readonly records: BeaEvidence[] = [];
  readonly byId = new Map<EvId, BeaEvidence>();
  readonly instances = new Map<PiId, ProcessInstance>();
  readonly modules = new Map<PiId, ModuleState>();
  readonly effects = new Map<FxId, EffectEntry>();
  readonly epochs = new Map<PiId, number>();
  readonly blobs = new Map<string, Uint8Array>();
  readonly unknowns = new Map<UnkId, ResidualUnknown[]>();
  readonly streams = new Map<StId, StreamEntry>();

  constructor(options: FakeEvidenceOptions) {
    this.runId = options.runId ?? ("run_20260101T000000Z_00000000000000fe" as RunId);
    const server = sensitiveLiterals(undefined, options.serverLiterals ?? []);
    this.server = server.ok ? server.value : NO_LITERALS;
  }

  nextSeq(): number {
    this.seq += 1;
    return this.seq;
  }

  anchor(instance: PiId) {
    return {
      run_id: this.runId,
      seq: this.nextSeq(),
      mono_ns: String(this.seq * 1000),
      wall: new Date((this.wall += 1)).toISOString(),
      effect_epoch: this.epochs.get(instance) ?? 0,
      module_map_epoch: this.modules.get(instance)?.epoch ?? 0,
    };
  }

  bumpEpoch(instance: PiId): void {
    this.epochs.set(instance, (this.epochs.get(instance) ?? 0) + 1);
  }

  mapOf(instance: PiId): ModuleMap {
    const body: Omit<ModuleMap, "module_map_id"> = {
      instance_id: instance,
      completeness: "complete",
      modules: [...(this.modules.get(instance)?.list ?? [])]
        .sort((a, b) => (BigInt(a.base) < BigInt(b.base) ? -1 : 1))
        .map((m) => ({
          base: m.base,
          size: m.size,
          path_sha256: pathDigest(m.path, "win32"),
          display: { name: m.name, path: m.path },
        })),
    };
    return { module_map_id: moduleMapIdOf(body), ...body };
  }

  effectStatesOf(instance: PiId): EffectState[] {
    return [...this.effects.values()].filter((e) => e.effect.instance_id === instance).map(fold);
  }

  perturbation(instance: PiId): Perturbation {
    const states = this.effectStatesOf(instance);
    const active = states.filter(isActive);
    const tainted = states.filter(
      (s) =>
        (s.status === "permanent" && EFFECT_KIND_TABLE[s.effect.kind].taintsWhenPermanent) ||
        (s.status === "revert-failed" && s.effect.class === "modify"),
    );
    const intrusive =
      active.some((s) => s.effect.class === "modify" || s.effect.class === "execute") || tainted.length > 0;
    const passive = active.some((s) => s.effect.class === "observe");
    return {
      level: intrusive ? "intrusive" : passive ? "passive" : "agent-only",
      active_effect_ids: sortedSet(
        active.filter((s) => s.effect.kind !== "agent-injected").map((s) => s.effect.effect_id),
      ),
      tainted_by: sortedSet(tainted.map((s) => s.effect.effect_id)),
    };
  }

  capture(instance: PiId): AnchorCapture {
    if (!this.modules.has(instance)) throw notAvailable("fakeEvidence.capture(unregistered instance)");
    const p = this.perturbation(instance);
    return {
      anchor: this.anchor(instance),
      module_map_id: this.mapOf(instance).module_map_id,
      perturbation: p,
      tainted_count: p.tainted_by.length,
    };
  }

  async record<R extends JsonValue>(draft: EvidenceDraft<R>): Promise<Result<RecordedEvidence<R>, BeaError>> {
    if (this.failNext !== undefined) {
      const error = this.failNext;
      this.failNext = undefined;
      return err(error);
    }
    if (this.fenced)
      return err({
        _tag: "CapabilityUnavailable",
        operation: draft.operation,
        capability: "server",
        reason: "shutting-down",
        retryable: false,
      });
    const extraLinks: EvId[] = [];
    if (
      draft.capture !== undefined &&
      draft.predicate_type !== "bea.modules.map" &&
      draft.subject?.kind === "process-instance"
    ) {
      const mm = await this.ensureRecorded(
        draft.subject.instance_id,
        draft.capture.anchor.module_map_epoch ?? 0,
        draft.operation,
      );
      if (!mm.ok) return mm;
      if ((draft.locations ?? []).some((l) => l.kind === "address" && l.module_map_id !== null))
        extraLinks.push(mm.value.evidence_id);
    }
    const built = buildEvidence(draft, {
      extraLinks,
      parent: (id) => {
        const r = this.byId.get(id);
        return r === undefined ? undefined : { authority: r.authority, perturbation: r.perturbation };
      },
    });
    if (!built.ok) return built;
    const r = built.value.record;
    for (const link of r.evidence_links)
      if (!this.byId.has(link))
        return err({ _tag: "EvidenceIntegrity", operation: draft.operation, reason: "dangling-link" });
    if (this.byId.has(r.evidence_id)) return ok({ record: r, outcome: "duplicate" });
    this.byId.set(r.evidence_id, r);
    this.records.push(r);
    return ok({ record: r, outcome: "added" });
  }

  async ensureRecorded(
    instance: PiId,
    epoch: number,
    operation: string,
  ): Promise<Result<{ readonly module_map_id: MmId; readonly evidence_id: EvId }, BeaError>> {
    const state = this.modules.get(instance);
    if (state === undefined) return err(notAvailable("fakeEvidence.ensureRecorded(unregistered instance)"));
    const known = state.recorded.get(epoch);
    if (known !== undefined) return ok(known);
    const map = this.mapOf(instance);
    const recorded = await this.record({
      predicate_type: "bea.modules.map",
      operation,
      input: { epoch },
      subject: { kind: "process-instance", instance_id: instance, module_map_id: map.module_map_id },
      capture: { ...this.capture(instance), module_map_id: map.module_map_id },
      provider: { id: "frida", name: "frida", version: null },
      agent: this.instances.get(instance)?.agent ?? AGENT,
      result: {
        epoch,
        module_count: map.modules.length,
        loaded_since_previous_recorded: [],
        unloaded_since_previous_recorded: [],
      },
      coverage: COMPLETE,
      limitations: [LIMITATIONS.AGENT_CLOAKED],
      literals: NO_LITERALS,
    });
    if (!recorded.ok) return recorded;
    const value = { module_map_id: map.module_map_id, evidence_id: recorded.value.record.evidence_id };
    state.recorded.set(epoch, value);
    return ok(value);
  }

  async register(
    obs: InstanceObservation,
  ): Promise<Result<{ readonly instance: ProcessInstance; readonly evidence_id: EvId }, BeaError>> {
    const identity = {
      t: "bea.pi/1" as const,
      device_id: obs.device_id,
      pid: obs.pid,
      start_time: { ...obs.start_time },
      image_path_sha256: pathDigest(obs.main_module_path, "win32"),
    };
    const instance_id = instanceIdOf(identity);
    const instance: ProcessInstance = {
      instance_id,
      identity,
      ownership: obs.ownership,
      image: {
        display: { path: obs.main_module_path, name: obs.main_module_path.split(/[\\/]/u).at(-1) ?? null },
        sha256: null,
        file: null,
        pe: null,
      },
      environment: obs.environment,
      agent: obs.agent,
      launch: obs.launch ?? null,
      state: obs.ownership === "owned" ? "suspended" : "running",
      exit: null,
    };
    this.instances.set(instance_id, instance);
    this.modules.set(instance_id, {
      epoch: obs.initial_modules.epoch,
      list: obs.initial_modules.modules.map((m) => ({ ...m })),
      recorded: new Map(),
    });
    const recorded = await this.record({
      predicate_type: "bea.process.instance",
      operation: obs.ownership === "owned" ? "spawn_process" : "attach_process",
      input: { pid: obs.pid },
      subject: { kind: "process-instance", instance_id },
      capture: this.capture(instance_id),
      provider: { id: "frida", name: "frida", version: null },
      agent: obs.agent,
      result: { pid: obs.pid, ownership: obs.ownership, state: instance.state },
      coverage: COMPLETE,
      ...(obs.limitations === undefined ? {} : { limitations: obs.limitations }),
      literals: obs.literals,
    });
    return recorded.ok ? ok({ instance, evidence_id: recorded.value.record.evidence_id }) : recorded;
  }

  instancesPort(): InstanceRegistry {
    return {
      register: (obs) => this.register(obs),
      get: (id) => this.instances.get(id),
      capture: (id) => this.capture(id),
      update: async (id, change) => {
        const instance = this.instances.get(id);
        if (instance === undefined) return err(referenceNotFound("evidence.instances", "evidence", id));
        if (change.state !== undefined) instance.state = change.state;
        if (change.exit !== undefined) instance.exit = change.exit;
        return ok(undefined);
      },
      hashImage: async (id) =>
        this.instances.has(id) ? ok("d".repeat(64)) : err(referenceNotFound("evidence.hashImage", "evidence", id)),
    };
  }

  modulesPort(): ModuleMapTracker {
    return {
      apply: (instance, ev) => {
        const state: ModuleState = this.modules.get(instance) ?? { epoch: 0, list: [], recorded: new Map() };
        if (ev.op === "snapshot") state.list = ev.modules.map((m) => ({ ...m }));
        else if (ev.op === "load") state.list.push(...ev.modules.map((m) => ({ ...m })));
        else state.list = state.list.filter((m) => !ev.modules.some((u) => u.base === m.base));
        state.epoch = ev.epoch;
        this.modules.set(instance, state);
      },
      current: (instance) => {
        const state = this.modules.get(instance);
        return state === undefined ? undefined : { epoch: state.epoch, map: () => this.mapOf(instance) };
      },
      at: (instance, epoch) => (this.modules.get(instance)?.epoch === epoch ? this.mapOf(instance) : undefined),
      ensureRecorded: (instance, epoch, operation) => this.ensureRecorded(instance, epoch, operation),
    };
  }

  byteState(bytes: Uint8Array | undefined, literals: SensitiveLiterals) {
    if (bytes === undefined) return null;
    if (literals.count > 0 && bytesContainLiteral(bytes, literals))
      return { bytes: bytes.length, sha256: null, hex: null, blob: null, retained: false };
    return {
      bytes: bytes.length,
      sha256: sha256Hex(bytes),
      hex: bytes.length <= 4096 ? bytesToHex(bytes) : null,
      blob: null,
      retained: true,
    };
  }

  async applyEffect(draft: EffectDraft): Promise<Result<Effect, BeaError>> {
    const info = EFFECT_KIND_TABLE[draft.kind];
    this.bumpEpoch(draft.instance_id);
    const body: Omit<Effect, "effect_id"> = {
      schema: "bea.effect/1",
      instance_id: draft.instance_id,
      kind: draft.kind,
      class: info.class,
      reversible: info.reversible === "if-before-retained" ? draft.before !== undefined : info.reversible,
      target: draft.target,
      parameters: draft.parameters,
      before: this.byteState(draft.before, draft.literals),
      after: this.byteState(draft.after, draft.literals),
      lifetime:
        draft.lifetime === undefined
          ? null
          : { duration_ms: draft.lifetime.duration_ms ?? null, max_hits: draft.lifetime.max_hits ?? null },
      stream_ids: sortedSet(draft.stream_ids ?? []),
      applied_by: draft.applied_by,
      applied_at: this.anchor(draft.instance_id),
      display: { target_text: draft.display_target ?? null },
    };
    const effect = { ...body, effect_id: effectIdOf(body) } as Effect;
    this.effects.set(effect.effect_id, {
      effect,
      transitions: [],
      ...(draft.before === undefined ? {} : { before: draft.before }),
    });
    return ok(effect);
  }

  async transition(
    id: FxId,
    to: EffectTransition["to"],
    detail: Pick<EffectTransition, "reason" | "verification" | "residue">,
  ): Promise<Result<EffectState, BeaError>> {
    const entry = this.effects.get(id);
    if (entry === undefined) return err(referenceNotFound("effect.transition", "effect", id));
    const state = fold(entry);
    if ((state.status !== "active" && state.status !== "revert-failed") || !EFFECT_EDGES[state.status].includes(to))
      return err(invalidState("effect.transition", state.status, ["active", "revert-failed"]));
    this.bumpEpoch(entry.effect.instance_id);
    entry.transitions.push({
      schema: "bea.effect-transition/1",
      effect_id: id,
      from: state.status,
      to,
      at: this.anchor(entry.effect.instance_id),
      ...detail,
    });
    return ok(fold(entry));
  }

  originalBytes(instance: PiId, va: bigint, len: number) {
    const end = va + BigInt(len);
    const ranges: { va: bigint; bytes: Uint8Array; fx: FxId }[] = [];
    for (const entry of this.effects.values()) {
      const address = entry.effect.target.address;
      if (
        entry.effect.instance_id !== instance ||
        entry.before === undefined ||
        address === null ||
        !isActive(fold(entry))
      )
        continue;
      const start = BigInt(address.va);
      const stop = start + BigInt(entry.before.length);
      if (stop <= va || start >= end) continue;
      const from = start < va ? va : start;
      const to = stop > end ? end : stop;
      ranges.push({
        va: from,
        bytes: entry.before.subarray(Number(from - start), Number(to - start)),
        fx: entry.effect.effect_id,
      });
    }
    return { ranges };
  }

  effectsPort(): EffectRegistry {
    return {
      apply: (draft) => this.applyEffect(draft),
      transition: (id, to, detail) => this.transition(id, to, detail),
      state: (id) => {
        const entry = this.effects.get(id);
        return entry === undefined ? undefined : fold(entry);
      },
      active: (instance) => this.effectStatesOf(instance).filter(isActive),
      perturbation: (instance) => this.perturbation(instance),
      epoch: (instance) => this.epochs.get(instance) ?? 0,
      originalBytes: (instance, va, len) => this.originalBytes(instance, va, len),
      endAll: async (instance, reason) => {
        for (const state of this.effectStatesOf(instance).filter(isActive))
          await this.transition(state.effect.effect_id, "implicit-end", { reason, verification: null, residue: [] });
      },
    };
  }

  manifest(spec: StreamSpec, stream_id: StId, counters: StreamWriter["counters"], endReason: StreamEndReason | null) {
    const instance = spec.source.instance_id;
    if (instance === null)
      return Promise.resolve(err(invalidState("stream_manifest", "host-stream", ["instance-bound stream"])));
    const { coverage, limitations } = manifestCoverage({
      state: counters.state,
      endReason,
      tailConfirmed: true,
      dropped: counters.dropped,
      redacted: counters.redacted,
      dropReasons: counters.dropped > 0 ? { agent_buffer_full: counters.dropped } : {},
      unattributed: 0,
      quotaMib: null,
      checkpointSeq: this.seq,
    });
    return this.record({
      predicate_type: "bea.stream.manifest",
      operation: "stream_manifest",
      input: { stream_id },
      subject: { kind: "process-instance", instance_id: instance },
      capture: this.capture(instance),
      provider: { id: "frida", name: "frida", version: null },
      agent: this.instances.get(instance)?.agent ?? AGENT,
      result: { stream_id, ...counters, end_reason: endReason },
      coverage,
      limitations,
      literals: NO_LITERALS,
    });
  }

  openStream(spec: StreamSpec): StreamWriter {
    const stream_id = idOf("st", {
      t: "bea.st/1",
      run_id: this.runId,
      seq: this.nextSeq(),
      source: spec.source as unknown as JsonValue,
    });
    const frames: { header: FrameBatchHeader; payload: Uint8Array }[] = [];
    const c = { records: 0, dropped: 0, redacted: 0, bytes: 0, state: "live" as "live" | "ended" };
    let final: Promise<Result<RecordedEvidence<JsonObject>, BeaError>> | undefined;
    const writer: StreamWriter = {
      stream_id,
      descriptor_sha256: sha256Hex(stream_id),
      append: (header, payload) => {
        if (c.state === "ended") return "closed";
        c.dropped += header.dropped_before;
        const redact = spec.literals.count > 0 && bytesContainLiteral(payload, spec.literals);
        frames.push({ header, payload: redact ? new Uint8Array(0) : payload.slice() });
        if (redact) c.redacted += header.count;
        else c.records += header.count;
        c.bytes += redact ? 0 : payload.length;
        return redact ? "redacted" : "accepted";
      },
      noteDropped: (n) => {
        c.dropped += Math.max(0, n);
      },
      checkpoint: async (signal) => {
        if (spec.flush !== undefined) await spec.flush(signal ?? new AbortController().signal);
        return final ?? this.manifest(spec, stream_id, { ...c }, null);
      },
      end: (reason) => {
        c.state = "ended";
        final ??= this.manifest(spec, stream_id, { ...c }, reason);
        return final;
      },
      get counters() {
        return { ...c };
      },
      onQuota: () => undefined,
    };
    this.streams.set(stream_id, { spec, frames, writer });
    return writer;
  }

  reader(stream: StreamEntry): StreamReader {
    return {
      spec: stream.spec,
      verify: async () => ok({ head_chain: sha256Hex(stream.writer.stream_id), chunks: 0 }),
      records: async function* (range: { readonly from_seq?: number; readonly to_seq?: number }) {
        for (const frame of stream.frames) {
          if (frame.payload.length === 0) continue;
          const header = {
            k: "batch" as const,
            first_seq: frame.header.first_seq,
            count: frame.header.count,
            dropped_before: frame.header.dropped_before,
            recv_mono_ns: "0",
            module_map_epoch: frame.header.module_map_epoch,
            layout_rev: 1 as const,
          };
          for (const row of decodePayload(stream.spec.encoding, {
            header,
            payload: frame.payload,
            offset: 0,
            bytes: frame.payload.length,
          })) {
            const seq = frame.header.first_seq + row.index;
            if (seq >= (range.from_seq ?? 1) && seq <= (range.to_seq ?? Number.MAX_SAFE_INTEGER))
              yield { seq, module_map_epoch: frame.header.module_map_epoch, fields: row.fields } satisfies StreamRecord;
          }
        }
      },
      gaps: () => [],
    };
  }

  streamsPort(): StreamStore {
    return {
      open: async (spec) => ok(this.openStream(spec)),
      reader: (id) => {
        const stream = this.streams.get(id);
        return stream === undefined
          ? err(referenceNotFound("evidence.streams", "stream", id))
          : ok(this.reader(stream));
      },
    };
  }

  blobsPort(): BlobStore {
    return {
      put: async (src, meta) => {
        const parts: Uint8Array[] = [];
        if (src instanceof Uint8Array) parts.push(src);
        else for await (const chunk of src) parts.push(chunk);
        const data = Buffer.concat(parts);
        if (meta.literals.count > 0 && bytesContainLiteral(data, meta.literals)) return ok({ redacted: true });
        const sha256 = sha256Hex(data);
        this.blobs.set(sha256, new Uint8Array(data));
        return ok({ role: meta.role, sha256, bytes: data.length, media_type: meta.media_type } satisfies BlobRef);
      },
      has: (sha) => this.blobs.has(sha),
      size: (sha) => this.blobs.get(sha)?.length,
      open: async () => err(notAvailable("fakeEvidence.blobs.open")),
      read: async (sha, offset, length) => {
        const data = this.blobs.get(sha);
        return data === undefined
          ? err(referenceNotFound("evidence.blobs", "blob", sha))
          : ok(data.slice(offset, offset + length));
      },
      verify: async (sha) => (this.blobs.has(sha) ? ok(true) : err(referenceNotFound("evidence.blobs", "blob", sha))),
    };
  }

  async upsert(input: UnknownInput, operation: string) {
    const scope = scopeOf(input.scope_image_sha256, this.runId);
    const head = input.unknown_id === undefined ? undefined : this.unknowns.get(input.unknown_id)?.at(-1);
    if (input.unknown_id !== undefined && head === undefined)
      return err(referenceNotFound(operation, "unknown", input.unknown_id));
    if (head !== undefined && head.revision !== input.expected_revision)
      return err({
        _tag: "RevisionConflict" as const,
        operation,
        unknown_id: head.unknown_id,
        expected_revision: input.expected_revision ?? 0,
        actual_revision: head.revision,
      });
    if (head === undefined && this.unknowns.has(unknownIdOf(input.domain, input.question ?? "", scope)))
      return err(
        inputError(operation, [{ path: "question", reason: "conflicting_arguments", message: "already recorded" }]),
      );
    const fields = {
      scope,
      domain: input.domain,
      question: input.question ?? "",
      status: input.status,
      severity: input.severity,
      supporting: input.supporting,
      contradicting: input.contradicting,
      probes: input.probes,
      resolution: input.resolution,
    };
    const draft = nextRevision(head, fields, `ev_${"0".repeat(64)}`);
    const mutation = await this.record({
      predicate_type: "bea.unknown.mutation",
      operation,
      input: { unknown_id: draft.unknown_id, revision: draft.revision, status: draft.status },
      subject: null,
      provider: { id: "bea", name: "bea", version: null },
      result: { unknown_id: draft.unknown_id, revision: draft.revision, status: draft.status, change: [] },
      coverage: COMPLETE,
      limitations: [LIMITATIONS.UNKNOWN_MUTATION_INTENT],
      evidence_links: [...new Set([...input.supporting, ...input.contradicting])],
      literals: NO_LITERALS,
    });
    if (!mutation.ok) return mutation;
    const revision = nextRevision(head, fields, mutation.value.record.evidence_id);
    this.unknowns.set(revision.unknown_id, [...(this.unknowns.get(revision.unknown_id) ?? []), revision]);
    return ok({
      unknown_id: revision.unknown_id,
      revision: revision.revision,
      status: revision.status,
      evidence_id: mutation.value.record.evidence_id,
    });
  }

  unknownsPort(): UnknownRegistry {
    return {
      upsert: (input, operation) => this.upsert(input, operation),
      autoRecord: async (input, operation) => {
        const head = this.unknowns
          .get(unknownIdOf(input.domain, input.question ?? "", scopeOf(input.scope_image_sha256, this.runId)))
          ?.at(-1);
        if (head !== undefined) return ok({ unknown_id: head.unknown_id, revision: head.revision });
        const created = await this.upsert({ ...input, resolution: null }, operation);
        return created.ok ? ok({ unknown_id: created.value.unknown_id, revision: created.value.revision }) : created;
      },
    };
  }

  queryPort(): EvidenceQuery {
    return {
      summary: (input) => {
        const filters = (input["filters"] ?? {}) as Readonly<Record<string, unknown>>;
        const rows = this.records
          .filter((r) => filters["predicate_type"] === undefined || r.predicate_type === filters["predicate_type"])
          .filter((r) => filters["operation"] === undefined || r.operation === filters["operation"])
          .map((r, i) => ({
            kind: "evidence",
            evidence_id: r.evidence_id,
            n: i + 1,
            predicate_type: r.predicate_type,
            operation: r.operation,
          }));
        return ok({
          entity: "evidence",
          total: this.records.length,
          matching: rows.length,
          rows,
          page: { offset: 0, limit: rows.length, total: rows.length, next_offset: null },
        });
      },
      complete: async (id) => {
        const r = this.byId.get(id as EvId);
        return r === undefined
          ? err(inputError("get_evidence", [{ path: "id", reason: "invalid_value", message: "missing" }]))
          : ok({ record_kind: "evidence", origin: "local", value: r as unknown as JsonObject });
      },
      slice: async () => err(notAvailable("fakeEvidence.query.slice")),
    };
  }

  status(): EvidenceStatus {
    const MiB = 1024 * 1024;
    return {
      run_id: this.runId,
      home: "C:\\fake-bea-home",
      usage: {
        ledger: { bytes: 0, quota: 512 * MiB, reserve: 8 * MiB },
        blobs: { bytes: [...this.blobs.values()].reduce((n, b) => n + b.length, 0), quota: 4096 * MiB },
        streams: {
          bytes: 0,
          quota_total: 4096 * MiB,
          per_stream_quota: 256 * MiB,
          live: [...this.streams.values()].filter((s) => s.writer.counters.state === "live").length,
        },
      },
      counts: {
        evidence: this.records.length,
        effects_active: [...this.effects.values()].filter((e) => fold(e).status === "active").length,
        unknowns_open: this.unknowns.size,
        instances: this.instances.size,
      },
    };
  }

  async addInstance(pid: number, ownership: "owned" | "attached"): Promise<PiId> {
    const registered = await this.register({
      device_id: "local",
      pid,
      ownership,
      start_time: { source: "os-creation-time", value: String(133_000_000_000_000_000 + pid) },
      main_module_path: "C:\\fixtures\\game.exe",
      agent: AGENT,
      environment: { platform: "win32", os_version: "10.0.26200", arch: "x64", pointer_size: 8 },
      initial_modules: {
        epoch: 1,
        modules: [
          { name: "game.exe", base: "0x140000000", size: 0x20000, path: "C:\\fixtures\\game.exe" },
          { name: "ntdll.dll", base: "0x7ffc00000000", size: 0x1f0000, path: "C:\\Windows\\System32\\ntdll.dll" },
        ],
      },
      literals: NO_LITERALS,
    });
    if (!registered.ok) throw new Error(`fakeEvidence.addInstance: ${registered.error._tag}`);
    return registered.value.instance.instance_id;
  }
}

export const fakeEvidence = (options: FakeEvidenceOptions = {}): FakeEvidence => {
  const s = new InMemoryEvidence(options);
  return {
    run: { id: s.runId, dir: `C:\\fake-bea-home\\runs\\${s.runId}`, kind: "mcp-stdio" },
    recorder: { record: (draft) => s.record(draft) },
    instances: s.instancesPort(),
    modules: s.modulesPort(),
    effects: s.effectsPort(),
    streams: s.streamsPort(),
    blobs: s.blobsPort(),
    unknowns: s.unknownsPort(),
    query: s.queryPort(),
    bundles: {
      export: async () => err(notAvailable("fakeEvidence.bundles.export")),
      import: async () => err(notAvailable("fakeEvidence.bundles.import")),
    },
    literals: (perCall) => {
      const built = sensitiveLiterals(perCall, s.server.texts);
      return built.ok ? built : err(inputError("evidence.literals", built.error));
    },
    locationOf: (ref, size) => ({
      kind: "address",
      va: ref.va,
      size: size ?? null,
      module_map_id: ref.module_map_id,
      module_key: ref.module?.toLowerCase() ?? null,
      rva: ref.rva,
      image_sha256: ref.image_sha256 ?? null,
    }),
    status: () => s.status(),
    finalize: async () => {
      for (const stream of s.streams.values())
        if (stream.writer.counters.state === "live") await stream.writer.end("server-shutdown");
      s.fenced = true;
      return ok(undefined);
    },
    records: s.records,
    effectStates: () => [...s.effects.values()].map(fold),
    frames: (id) => s.streams.get(id)?.frames ?? [],
    blobBytes: (sha) => s.blobs.get(sha),
    unknownHead: (id) => s.unknowns.get(id)?.at(-1),
    addInstance: (pid = 4242, ownership = "owned") => s.addInstance(pid, ownership),
    failNextRecord: (error) => {
      s.failNext = error;
    },
  };
};
