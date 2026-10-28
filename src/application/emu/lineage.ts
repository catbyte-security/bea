import { canonicalDigest } from "../../domain/canonical.js";
import type { EvId } from "../../domain/ids.js";
import type { JsonObject, JsonValue } from "../../domain/json.js";

/**
 * Emulation state lineage and replay identity (S5 §11.2). Every state an emulated call starts from has a digest
 * `es_<sha256(JCS(record))>`: the baseline record names the source (image sha256 + mapped base, or the dump bundle),
 * the normalized open options and the engine; each call or batch derives an `after` record from its start state and
 * the operation (plan, vectors, slice, writes, options, isolation). `current` follows the last operation; named
 * snapshots keep the digest they were saved at; a bridge restart resets `current` to the baseline. The lineage lives
 * in the application (the frozen EmuPort carries no lineage) and is keyed by session id + bridge generation.
 */
export type StateDigest = `es_${string}`;

const stateDigest = (record: JsonValue): StateDigest => `es_${canonicalDigest(record)}`;
/** the bare sha256 of a state digest (evidence subjects take plain sha256 strings) */
export const digestHex = (digest: StateDigest): string => digest.slice(3);

export interface BaselineRecordInput {
  readonly source:
    | { readonly kind: "image"; readonly sha256: string; readonly mappedBase: string }
    | { readonly kind: "dump"; readonly bundleId: string };
  /** normalized emu_open options (no paths, label or timeout) */
  readonly open: JsonObject;
  /** the bridge protocol and version (the version pins the bridge file through the build manifest) */
  readonly bridge: { readonly protocol: string; readonly version: string };
  readonly engines: { readonly unicorn: string; readonly capstone: string; readonly pefile: string };
}

export const baselineDigest = (input: BaselineRecordInput): StateDigest =>
  stateDigest({
    schema: "bea.emu-state/1",
    kind: "baseline",
    source:
      input.source.kind === "image"
        ? { kind: "image", sha256: input.source.sha256, mapped_base: input.source.mappedBase }
        : { kind: "dump", bundle_id: input.source.bundleId },
    open: input.open,
    bridge: { ...input.bridge },
    engines: { ...input.engines },
  });

export interface AfterOp {
  readonly method: "emu.call" | "emu.batch" | "emu.sweep";
  readonly planDigest: string;
  readonly vectorsDigest: string;
  readonly slice: { readonly offset: number; readonly count: number };
  readonly writesDigest: string;
  readonly optionsDigest: string;
  readonly isolation: "snapshot" | "chain";
}

export const afterDigest = (prev: StateDigest, op: AfterOp, runNonce: string | null): StateDigest =>
  stateDigest({
    schema: "bea.emu-state/1",
    kind: "after",
    prev,
    op: {
      method: op.method,
      plan_digest: op.planDigest,
      vectors_digest: op.vectorsDigest,
      slice: { offset: op.slice.offset, count: op.slice.count },
      writes_digest: op.writesDigest,
      options_digest: op.optionsDigest,
      isolation: op.isolation,
    },
    ...(runNonce === null ? {} : { run_nonce: runNonce }),
  });

/** query_id (S5 §11.2; recorded in v0.1, a replay-cache key in v0.2). */
export const queryId = (input: {
  readonly initialState: StateDigest;
  readonly imageSha256: string;
  readonly rva: string | null;
  readonly planDigest: string;
  readonly vectorsDigest: string;
  readonly optionsDigest: string;
}): string =>
  canonicalDigest({
    initial_state_digest: input.initialState,
    target: { image_sha256: input.imageSha256, rva: input.rva },
    plan_digest: input.planDigest,
    vectors_digest: input.vectorsDigest,
    options_digest: input.optionsDigest,
  });

/** Everything the application remembers about one emulation session. */
export interface SessionRecord {
  readonly sessionId: string;
  readonly source: "image" | "dump";
  /** primary image sha256 (dump without file match: the bundle digest) */
  readonly imageSha256: string;
  readonly configDigest: string;
  readonly bundleId: string | null;
  /** dump sessions: the live process instance the bundle was captured from (raw VAs are valid in both legs) */
  readonly producerInstance: string | null;
  readonly sessionEvidence: EvId | null;
  readonly fp: {
    readonly mxcsr: number;
    readonly fpcw: number;
    readonly source: "explicit" | "dump-thread" | "windows-default";
  };
  readonly faultPolicy: "stop" | "map_zero";
  readonly syntheticBase: string | null;
  readonly engineUnvalidated: boolean;
  readonly baseline: StateDigest;
  generation: number;
  current: StateDigest;
  /** the start state of `current` is the baseline itself (no call ran since the open or a restart) */
  currentIsBaseline: boolean;
  readonly named: Map<string, StateDigest>;
}

export class LineageStore {
  readonly #sessions = new Map<string, SessionRecord>();

  add(
    record: Omit<SessionRecord, "generation" | "current" | "currentIsBaseline" | "named">,
    generation: number,
  ): SessionRecord {
    const full: SessionRecord = {
      ...record,
      generation,
      current: record.baseline,
      currentIsBaseline: true,
      named: new Map(),
    };
    this.#sessions.set(record.sessionId, full);
    return full;
  }

  /** The record for the CURRENT bridge generation (a newer generation resets current and the named snapshots). */
  get(sessionId: string, generation: number): SessionRecord | null {
    const record = this.#sessions.get(sessionId);
    if (record === undefined) return null;
    if (record.generation !== generation) {
      record.generation = generation;
      record.current = record.baseline;
      record.currentIsBaseline = true;
      record.named.clear();
    }
    return record;
  }

  /** Forget sessions the emulator no longer knows (closed); called opportunistically. */
  prune(isOpen: (sessionId: string) => boolean): void {
    for (const id of this.#sessions.keys()) if (!isOpen(id)) this.#sessions.delete(id);
  }

  get size(): number {
    return this.#sessions.size;
  }
}
