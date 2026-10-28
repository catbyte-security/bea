import type { IdSource } from "../../domain/canonical.js";
import type { Clock } from "../../domain/clock.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { referenceNotFound } from "../../domain/errors/constructors.js";
import { staticText } from "../../domain/address/grammar.js";
import type { PiId } from "../../domain/ids.js";
import type { JsonObject, JsonValue } from "../../domain/json.js";
import type { Logger } from "../../domain/logger.js";
import { moduleAt, type ModuleEntry, type ModuleMap } from "../../domain/process/instance.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { EvidenceRuntime, StreamReader } from "../../ports/evidence.js";
import type {
  DecodeContext,
  EventRecord,
  InstrumentStateView,
  Recording,
  RecordingCreate,
  RecordingEndReason,
  RecordingKind,
  RecordingKindSpec,
  RecordingRegistry,
} from "../../ports/recordings.js";
import type { OperationContext, SessionId } from "../../ports/sessions.js";

/**
 * Recordings (S6 §2.5, CI-I3, CI-I13): every instrument is exactly one recording and its `rec_xxxxxxxx` handle IS the
 * recording id. The agent arms `clock:"resume"` duration timers itself; this registry only keeps `ends_in_ms` for
 * display. Events are decoded at query time through the recording kind's spec (RECORDING_KINDS); reading a live
 * stream first runs its StreamSpec.flush barrier so the reader sees every frame the agent had generated.
 */
export interface RecordingRegistryDeps {
  readonly evidence: EvidenceRuntime;
  readonly ids: IdSource;
  readonly clock: Clock;
  readonly logger: Logger;
  readonly kinds: { readonly [K in RecordingKind]: RecordingKindSpec | null };
  /** UX-10: a module's prepared preferred base by path (AddressService.preferredBaseOf; cache only), else null */
  readonly staticBase?: (path: string) => bigint | null;
}

interface Entry {
  readonly id: string;
  readonly create: RecordingCreate;
  startedAtMs: number | null;
  state: "active" | "finished" | "failed";
  events: number;
  dropped: number;
  endReason: RecordingEndReason | null;
  summary: JsonObject | undefined;
  ending: Promise<Result<InstrumentStateView, BeaError>> | undefined;
}

const MAX_HANDLE_ATTEMPTS = 64;

const BARE_VA = /^0x[0-9a-f]{1,16}$/iu;

const FRAME_REF = /^(.+)\+0x([0-9a-f]{1,16})$/iu;

/** A module's prepared preferred base (null: not prepared, or no path). Best effort: decoding never fails on it. */
type StaticBase = (module: ModuleEntry) => bigint | null;

/** "name:0x<preferred base + rva>" (S6 §2.2 static text, pasteable back as an AddrExpr). */
const staticOf = (module: ModuleEntry, name: string, rva: bigint, base: StaticBase): string | null => {
  if (rva < 0n || rva >= BigInt(module.size)) return null;
  const preferred = base(module);
  return preferred === null ? null : staticText(name, preferred + rva);
};

/**
 * Frames in decoded events. An agent FrameRef "<module>+0x<rva>" is already the compact `at` form. A bare VA (the
 * hook row's caller is the raw return address, in both the JSON and the native tier) is placed in the instance's
 * module map of the record's epoch (else the current one), so summaries and rows stay pointer-free (S6 §1.2 "caller
 * game.exe+0x75c0d2"; integrator fix, WP18). Outside every module it stays a bare VA. `static` (review fix UX-10,
 * CI-I10): from the module's preferred base when it was prepared (the hook and watch installs prepare the target's
 * module and the main image); null otherwise (map_address gives it).
 */
const frameOf = (
  frame: string,
  map: ModuleMap | undefined,
  base: StaticBase,
): { readonly at: string | null; readonly static: string | null } => {
  if (!BARE_VA.test(frame)) {
    const at = frame.slice(0, 600);
    const ref = FRAME_REF.exec(frame);
    if (ref === null || map === undefined) return { at, static: null };
    const name = (ref[1] ?? "").toLowerCase();
    const named = map.modules.filter((m) => m.display.name?.toLowerCase() === name);
    const only = named.length === 1 ? named[0] : undefined;
    const onlyName = only?.display.name ?? null;
    return {
      at,
      static:
        only === undefined || onlyName === null ? null : staticOf(only, onlyName, BigInt(`0x${ref[2] ?? "0"}`), base),
    };
  }
  const module = map === undefined ? null : moduleAt(map, BigInt(frame));
  const name = module?.display.name ?? null;
  if (module === null || name === null) return { at: null, static: null };
  const rva = BigInt(frame) - BigInt(module.base);
  return { at: `${name}+0x${rva.toString(16)}`.slice(0, 600), static: staticOf(module, name, rva, base) };
};

const startedAtUsOf = (decoders: JsonValue): number => {
  if (typeof decoders === "object" && decoders !== null && !Array.isArray(decoders)) {
    const value = (decoders as { readonly [k: string]: JsonValue })["started_at_us"];
    if (typeof value === "number" && Number.isFinite(value)) return value;
  }
  return 0;
};

export class LedgerRecordingRegistry implements RecordingRegistry {
  readonly #entries = new Map<string, Entry>();

  constructor(private readonly deps: RecordingRegistryDeps) {}

  #view(entry: Entry): InstrumentStateView {
    let endsIn: number | null = null;
    if (entry.state === "active" && entry.create.durationMs !== null)
      endsIn =
        entry.startedAtMs === null
          ? entry.create.durationMs
          : Math.max(0, Math.round(entry.startedAtMs + entry.create.durationMs - this.deps.clock.monoMs()));
    return {
      recording_id: entry.id,
      kind: entry.create.kind,
      state: entry.state,
      events: entry.events,
      dropped: entry.dropped,
      ends_in_ms: endsIn,
      end_reason: entry.endReason,
      ...(entry.summary === undefined ? {} : { summary: entry.summary }),
    };
  }

  #recording(entry: Entry): Recording {
    return { id: entry.id, create: entry.create, view: () => this.#view(entry) };
  }

  create(spec: RecordingCreate): Recording {
    let id = this.deps.ids.handle("rec");
    for (let attempt = 1; this.#entries.has(id); attempt++) {
      if (attempt >= MAX_HANDLE_ATTEMPTS) throw new Error("recording handle space exhausted");
      id = this.deps.ids.handle("rec");
    }
    const entry: Entry = {
      id,
      create: spec,
      startedAtMs: spec.startsAtResume ? null : this.deps.clock.monoMs(),
      state: "active",
      events: 0,
      dropped: 0,
      endReason: null,
      summary: undefined,
      ending: undefined,
    };
    this.#entries.set(id, entry);
    return this.#recording(entry);
  }

  get(id: string): Recording | undefined {
    const entry = this.#entries.get(id);
    return entry === undefined ? undefined : this.#recording(entry);
  }

  list(sessionId: SessionId): readonly Recording[] {
    return [...this.#entries.values()].filter((e) => e.create.sessionId === sessionId).map((e) => this.#recording(e));
  }

  onResumed(sessionId: SessionId): void {
    const now = this.deps.clock.monoMs();
    for (const entry of this.#entries.values())
      if (entry.create.sessionId === sessionId && entry.state === "active" && entry.startedAtMs === null)
        entry.startedAtMs = now;
  }

  /** The instance's module map at a record's epoch (else the current map), memoized per epoch for one decode pass. */
  #moduleMaps(instance: PiId | null): (epoch: number | null) => ModuleMap | undefined {
    const cache = new Map<number | null, ModuleMap | undefined>();
    return (epoch) => {
      if (instance === null) return undefined;
      if (!cache.has(epoch)) {
        const modules = this.deps.evidence.modules;
        cache.set(
          epoch,
          (epoch === null ? undefined : modules.at(instance, epoch)) ?? modules.current(instance)?.map(),
        );
      }
      return cache.get(epoch);
    };
  }

  #reader(entry: Entry): Result<StreamReader | null, BeaError> {
    if (entry.create.streamId === null) return ok(null);
    return this.deps.evidence.streams.reader(entry.create.streamId);
  }

  async *#decoded(
    entry: Entry,
    reader: StreamReader,
    range: { readonly from_seq?: number; readonly to_seq?: number },
    op: OperationContext,
  ): AsyncGenerator<EventRecord> {
    const spec = this.deps.kinds[entry.create.kind];
    if (spec === null) return;
    const maps = this.#moduleMaps(reader.spec.source.instance_id);
    const staticBase: StaticBase = (module) => {
      const path = module.display.path;
      if (path === null || this.deps.staticBase === undefined) return null;
      try {
        return this.deps.staticBase(path);
      } catch {
        return null;
      }
    };
    let epoch: number | null = null;
    const ctx: DecodeContext = {
      sessionId: entry.create.sessionId,
      decoders: entry.create.decoders,
      startedAtUs: startedAtUsOf(entry.create.decoders),
      frame: (frame) => frameOf(frame, maps(epoch), staticBase),
    };
    for await (const record of reader.records(range, op.signal)) {
      if (op.signal.aborted) return;
      epoch = record.module_map_epoch;
      yield* spec.decode(record, ctx);
    }
  }

  /** CI-I13: a live stream is flushed (agent barrier) before it is read. */
  async #flush(entry: Entry, reader: StreamReader, op: OperationContext): Promise<void> {
    if (entry.state !== "active" || reader.spec.flush === undefined) return;
    try {
      await reader.spec.flush(op.signal);
    } catch (cause) {
      this.deps.logger.debug("recording flush failed; reading what arrived", {
        recording: entry.id,
        cause: cause instanceof Error ? cause : String(cause),
      });
    }
  }

  events(
    id: string,
    range: { readonly from_seq?: number; readonly to_seq?: number },
    op: OperationContext,
  ): AsyncIterable<EventRecord> {
    const entry = this.#entries.get(id);
    const iterate = async function* (
      registry: LedgerRecordingRegistry,
      decoded: (e: Entry, r: StreamReader) => AsyncGenerator<EventRecord>,
    ): AsyncGenerator<EventRecord> {
      if (entry === undefined) throw referenceNotFound(op.name, "recording", id);
      const reader = registry.#reader(entry);
      if (!reader.ok) throw reader.error;
      if (reader.value === null) return;
      await registry.#flush(entry, reader.value, op);
      yield* decoded(entry, reader.value);
    };
    return iterate(this, (e, r) => this.#decoded(e, r, range, op));
  }

  /** One pass over the stored batches: counts + the kind's bounded summary (S6 §5.3). */
  async #summarize(entry: Entry, op: OperationContext): Promise<Result<JsonObject, BeaError>> {
    const spec = this.deps.kinds[entry.create.kind];
    const reader = this.#reader(entry);
    if (!reader.ok) return reader;
    if (reader.value === null) return ok(spec?.summary.finish(spec.summary.init()) ?? {});
    await this.#flush(entry, reader.value, op);
    let events = 0;
    const state = spec?.summary.init();
    if (spec === null)
      for await (const record of reader.value.records({}, op.signal)) events += record === undefined ? 0 : 1;
    else
      for await (const event of this.#decoded(entry, reader.value, {}, op)) {
        events += 1;
        spec.summary.add(state, event);
      }
    const dropped = reader.value.gaps().reduce((n, g) => (g.kind === "dropped" ? n + g.to_seq - g.from_seq + 1 : n), 0);
    entry.events = events;
    entry.dropped = dropped;
    return ok(spec === null ? {} : spec.summary.finish(state));
  }

  async summary(id: string, op: OperationContext): Promise<Result<JsonObject, BeaError>> {
    const entry = this.#entries.get(id);
    if (entry === undefined) return err(referenceNotFound(op.name, "recording", id));
    if (entry.state !== "active" && entry.summary !== undefined) return ok(entry.summary);
    return this.#summarize(entry, op);
  }

  end(id: string, reason: RecordingEndReason, op: OperationContext): Promise<Result<InstrumentStateView, BeaError>> {
    const entry = this.#entries.get(id);
    if (entry === undefined) return Promise.resolve(err(referenceNotFound(op.name, "recording", id)));
    entry.ending ??= (async () => {
      const summary = await this.#summarize(entry, op);
      entry.state = "finished";
      entry.endReason = reason;
      if (summary.ok) entry.summary = summary.value;
      else this.deps.logger.warn("recording summary failed", { recording: id, code: summary.error._tag });
      return ok(this.#view(entry));
    })();
    return entry.ending;
  }
}
