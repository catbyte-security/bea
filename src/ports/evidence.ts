import type { FileHandle } from "node:fs/promises";

import type { AddressRef } from "../domain/address/addressRef.js";
import type { Effect, EffectKind, EffectState, EffectTransition } from "../domain/effects/effect.js";
import type { BeaError } from "../domain/errors/beaError.js";
import type { Coverage } from "../domain/evidence/coverage.js";
import type { PredicateType } from "../domain/evidence/predicates.js";
import type {
  AgentIdentity,
  Authority,
  BeaEvidence,
  BlobRef,
  Confidence,
  ExternalRef,
  Location,
  Perturbation,
  Subject,
} from "../domain/evidence/record.js";
import type { Hex } from "../domain/hex.js";
import type { EvId, FxId, MmId, PiId, RunId, StId, UnkId } from "../domain/ids.js";
import type { JsonObject, JsonValue } from "../domain/json.js";
import type { ExitInfo, ModuleMap, ProcessInstance, StartTimeSource } from "../domain/process/instance.js";
import type { Result } from "../domain/result.js";
import type { CompactAnchor, TimeAnchor } from "../domain/time.js";
import type { BinaryField, RowKind } from "../shared/agentProtocol.js";

/**
 * Evidence store ports (S2 §21.1, merged with S3 §12.1's stream contract). Implemented by
 * src/providers/evidence/** (WP-EVID). One EvidenceRuntime per run (server process or CLI command).
 * Write order: record-before-reference (fx/pi/mm/blob/stream lines before the ev line citing them) and
 * record-before-deliver (the ev line is appended before the tool returns). fsync only at finalize points.
 */

// ---------------------------------------------------------------- redaction (S2 §15)
export interface SensitiveLiterals {
  readonly count: number;
  readonly texts: readonly string[];
  /** utf8(lit) and utf16le(lit), unique, longest first */
  readonly spellings: readonly Uint8Array[];
}

// ---------------------------------------------------------------- recording (S2 §7.9)
export interface AnchorCapture {
  readonly anchor: TimeAnchor;
  readonly module_map_id: MmId;
  readonly perturbation: Perturbation;
  readonly tainted_count: number;
}
export interface EvidenceDraft<R extends JsonValue> {
  readonly predicate_type: PredicateType;
  readonly operation: string;
  /** raw validated tool input; delivery/handle keys + identityExclude are removed by the Recorder */
  readonly input: JsonObject;
  readonly identityExclude?: readonly string[];
  readonly subject: { readonly kind: "process-instance"; readonly instance_id: PiId } | Subject | null;
  /** from InstanceRegistry.capture(); required for anchored predicates */
  readonly capture?: AnchorCapture;
  readonly provider: {
    readonly id: "frida" | "unicorn" | "bea-pe" | "bea";
    readonly name: string;
    readonly version: string | null;
  };
  readonly agent?: AgentIdentity | null;
  readonly confidence?: Confidence;
  readonly authority?: Authority;
  readonly result: R;
  readonly raw_result?: JsonValue | null;
  readonly blobs?: readonly BlobRef[];
  readonly coverage: Coverage;
  readonly limitations?: readonly string[];
  readonly locations?: readonly Location[];
  readonly evidence_links?: readonly EvId[];
  readonly external_refs?: readonly ExternalRef[];
  readonly effects?: readonly FxId[];
  readonly literals: SensitiveLiterals;
  /**
   * Review fix SEC-3: pointers under /result whose values the producer already withheld because the raw target bytes
   * behind them (typed views, decoded values) contained a sensitive literal the Recorder cannot see in that form.
   * They count as redactions (coverage partial, explicit_sensitive_value) exactly like the Recorder's own.
   */
  readonly pre_redactions?: readonly string[];
}
export interface RecordedEvidence<R extends JsonValue> {
  readonly record: BeaEvidence<R>;
  readonly outcome: "added" | "duplicate";
}
export interface Recorder {
  record<R extends JsonValue>(
    draft: EvidenceDraft<R>,
    opts?: { readonly lifecycle?: boolean },
  ): Promise<Result<RecordedEvidence<R>, BeaError>>;
}

// ---------------------------------------------------------------- instances & module maps (S2 §4–5)
export interface InstanceObservation {
  readonly device_id: "local";
  readonly pid: number;
  readonly ownership: "owned" | "attached";
  readonly start_time: { readonly source: StartTimeSource; readonly value: string };
  readonly main_module_path: string;
  readonly agent: AgentIdentity;
  readonly environment: ProcessInstance["environment"];
  readonly initial_modules: {
    readonly epoch: number;
    readonly modules: readonly {
      readonly name: string;
      readonly base: Hex;
      readonly size: number;
      readonly path: string;
    }[];
  };
  readonly launch?: ProcessInstance["launch"];
  readonly containment?: JsonObject;
  readonly limitations?: readonly string[];
  readonly literals: SensitiveLiterals;
}
export interface InstanceRegistry {
  /** computes pi_, writes the pi line + bea.process.instance (observed, anchored) */
  register(
    obs: InstanceObservation,
  ): Promise<Result<{ readonly instance: ProcessInstance; readonly evidence_id: EvId }, BeaError>>;
  get(id: PiId): ProcessInstance | undefined;
  /** seq + epochs + perturbation; call inside the session's exclusive section right after the agent RPC */
  capture(id: PiId): AnchorCapture;
  update(
    id: PiId,
    change: { readonly state?: ProcessInstance["state"]; readonly exit?: ExitInfo | null },
  ): Promise<Result<void, BeaError>>;
  hashImage(id: PiId, signal?: AbortSignal): Promise<Result<string, BeaError>>;
}
export interface ModuleMapTracker {
  /** agent s:modules rows (module/1) and listModules snapshots; the host mirrors agent epochs, never invents one */
  apply(
    instance: PiId,
    ev: {
      readonly op: "load" | "unload" | "snapshot";
      readonly epoch: number;
      readonly modules: readonly {
        readonly name: string;
        readonly base: Hex;
        readonly size: number;
        readonly path: string;
      }[];
    },
  ): void;
  current(instance: PiId): { readonly epoch: number; readonly map: () => ModuleMap } | undefined;
  at(instance: PiId, epoch: number): ModuleMap | undefined;
  /** materialize-on-reference: writes the mm line + bea.modules.map evidence once per epoch */
  ensureRecorded(
    instance: PiId,
    epoch: number,
    operation: string,
  ): Promise<Result<{ readonly module_map_id: MmId; readonly evidence_id: EvId }, BeaError>>;
}

// ---------------------------------------------------------------- effects (S2 §6.4)
export interface EffectDraft {
  readonly instance_id: PiId;
  readonly kind: EffectKind;
  readonly target: Effect["target"];
  readonly parameters: JsonObject;
  readonly before?: Uint8Array;
  readonly after?: Uint8Array;
  readonly lifetime?: { readonly duration_ms?: number; readonly max_hits?: number };
  readonly stream_ids?: readonly StId[];
  readonly applied_by: string;
  readonly display_target?: string;
  readonly literals: SensitiveLiterals;
}
export interface EffectRegistry {
  /** seq + epoch++ + blob + fx line (record-before-reference) */
  apply(draft: EffectDraft): Promise<Result<Effect, BeaError>>;
  transition(
    id: FxId,
    to: EffectTransition["to"],
    detail: Pick<EffectTransition, "reason" | "verification" | "residue">,
  ): Promise<Result<EffectState, BeaError>>;
  state(id: FxId): EffectState | undefined;
  /** active ∪ revert-failed */
  active(instance: PiId): readonly EffectState[];
  perturbation(instance: PiId): Perturbation;
  epoch(instance: PiId): number;
  /** BEA's own patches, for disassembly over original bytes and byte verification */
  originalBytes(
    instance: PiId,
    va: bigint,
    len: number,
  ): { readonly ranges: readonly { readonly va: bigint; readonly bytes: Uint8Array; readonly fx: FxId }[] };
  endAll(
    instance: PiId,
    reason: "process-exited" | "detached" | "agent-unloaded" | "server-shutdown" | "session-close",
  ): Promise<void>;
}

// ---------------------------------------------------------------- streams (S2 §10 + S3 §12)
export type StreamSourceKind =
  | "hook"
  | "api"
  | "watch"
  | "poll"
  | "trace"
  | "override"
  | "exceptions"
  | "modules"
  | "threads"
  | "memmap"
  | "stdout"
  | "stderr"
  | "emu-batch"
  | "emu-sweep"
  | "diff"
  | "call-batch"; // CI-I6: call_function batches above inline_limit (WP-CALL)
export type StreamEncoding =
  | { readonly kind: "json-rows"; readonly row_kind: RowKind } // payload = NDJSON, one agent row per line
  | {
      readonly kind: "fixed-records";
      readonly row_kind: RowKind;
      readonly record_bytes: number;
      readonly fields: readonly BinaryField[];
    }
  | { readonly kind: "ndjson" } // host-produced rows (emu-batch, emu-sweep, diff)
  | { readonly kind: "bytes" }; // stdout/stderr
export interface StreamSpec {
  readonly source: {
    readonly kind: StreamSourceKind;
    readonly instance_id: PiId | null;
    readonly effect_id: FxId | null;
    readonly channel: string;
  };
  readonly encoding: StreamEncoding;
  /** capture specs, profile catalog minor, string tables needed to decode rows */
  readonly decoders: JsonValue;
  readonly literals: SensitiveLiterals;
  /**
   * CI-I13: agent flush barrier for StreamWriter.checkpoint (S2 §10 checkpoint protocol). Supplied by
   * StreamBinder.bind (WP-SESS: agent `flush({streams:[id]})` + wait for frames up to the returned counts); absent for
   * host-produced streams. WP-EVID never talks to the agent.
   */
  readonly flush?: (signal: AbortSignal) => Promise<void>;
}
export interface FrameBatchHeader {
  /** stream-local record seq of the first record (host-assigned: records + drops so far + 1) */
  readonly first_seq: number;
  readonly count: number;
  /** agent drops immediately before first_seq (sum of the batch's DropCounters delta) */
  readonly dropped_before: number;
  readonly module_map_epoch: number | null;
  readonly final?: boolean;
  /** S4 batch provenance kept in the frame header */
  readonly bseq?: number;
  readonly g0?: number;
  readonly g1?: number;
}
export type AppendOutcome = "accepted" | "queue-full" | "quota-exceeded" | "redacted" | "closed";
export type StreamEndReason =
  | "stopped"
  | "expired"
  | "process-exited"
  | "process-killed"
  | "detached"
  | "quota"
  | "install-failed"
  | "server-shutdown"
  | "agent-error";
/** @public */
export interface StreamManifest {
  readonly stream_id: StId;
  readonly state: "live" | "ended";
  readonly end_reason: StreamEndReason | null;
  readonly records: number;
  readonly dropped: number;
  readonly redacted: number;
  readonly drop_reasons: Readonly<Record<string, number>>;
  readonly first_seq: number | null;
  readonly last_seq: number | null;
  readonly started: CompactAnchor;
  readonly checkpoint: CompactAnchor;
  readonly tail_confirmed: boolean;
  readonly bytes: number;
  readonly head_chain: string;
}
export interface StreamWriter {
  readonly stream_id: StId;
  readonly descriptor_sha256: string;
  /** SYNC enqueue: never blocks, never throws; quota and redaction scan applied */
  append(header: FrameBatchHeader, payload: Uint8Array): AppendOutcome;
  noteDropped(n: number, reason: string): void;
  /** flush barrier (agent flush → frames up to last seq) + seal + manifest evidence */
  checkpoint(signal?: AbortSignal): Promise<Result<RecordedEvidence<JsonObject>, BeaError>>;
  end(reason: StreamEndReason, deadlineMs?: number): Promise<Result<RecordedEvidence<JsonObject>, BeaError>>;
  readonly counters: {
    readonly records: number;
    readonly dropped: number;
    readonly redacted: number;
    readonly bytes: number;
    readonly state: "live" | "ended";
  };
  onQuota(callback: () => void): void;
}
export interface StreamRecord {
  readonly seq: number;
  readonly module_map_epoch: number | null;
  /** decoded per the descriptor: JSON row tuple, binary fields, or a bytes chunk */
  readonly fields: JsonValue;
}
export interface StreamReader {
  /**
   * `included: "manifests-only"` (review fix DATA-4): an imported stream that arrived without its chunk files (a
   * default export); only its descriptor and hash chain are verified, and it has no records to read.
   */
  verify(
    signal?: AbortSignal,
  ): Promise<
    Result<
      { readonly head_chain: string; readonly chunks: number; readonly included?: "all" | "manifests-only" },
      BeaError
    >
  >;
  records(
    range: { readonly from_seq?: number; readonly to_seq?: number },
    signal?: AbortSignal,
  ): AsyncIterable<StreamRecord>;
  gaps(range?: {
    readonly from_seq?: number;
    readonly to_seq?: number;
  }): readonly { readonly from_seq: number; readonly to_seq: number; readonly kind: "dropped" | "redacted" }[];
  readonly spec: StreamSpec;
}
export interface StreamStore {
  open(spec: StreamSpec): Promise<Result<StreamWriter, BeaError>>;
  reader(id: StId): Result<StreamReader, BeaError>;
}

// ---------------------------------------------------------------- blobs (S2 §11)
export interface BlobStore {
  put(
    src: Uint8Array | AsyncIterable<Uint8Array>,
    meta: { readonly role: string; readonly media_type: string; readonly literals: SensitiveLiterals },
    signal?: AbortSignal,
  ): Promise<Result<BlobRef | { readonly redacted: true }, BeaError>>;
  has(sha256: string): boolean;
  size(sha256: string): number | undefined;
  open(sha256: string): Promise<Result<FileHandle, BeaError>>;
  read(sha256: string, offset: number, length: number): Promise<Result<Uint8Array, BeaError>>;
  verify(sha256: string, signal?: AbortSignal): Promise<Result<true, BeaError>>;
}

// ---------------------------------------------------------------- unknowns (S2 §14)
export interface UnknownInput {
  readonly unknown_id?: UnkId;
  readonly expected_revision?: number;
  readonly question?: string;
  readonly domain: string;
  readonly scope_image_sha256: string | null;
  readonly status: "open" | "investigating" | "blocked" | "contradicted" | "resolved";
  readonly severity: "low" | "medium" | "high" | "critical";
  readonly supporting: readonly EvId[];
  readonly contradicting: readonly EvId[];
  readonly probes: readonly string[];
  readonly resolution: string | null;
}
export interface UnknownRegistry {
  /** create (no id) or CAS update (id + expected_revision); records bea.unknown.mutation */
  upsert(
    input: UnknownInput,
    operation: string,
  ): Promise<
    Result<
      { readonly unknown_id: UnkId; readonly revision: number; readonly status: string; readonly evidence_id: EvId },
      BeaError
    >
  >;
  /** auto-unknown with deterministic question text (diff divergences, byte mismatches) */
  autoRecord(
    input: Omit<UnknownInput, "unknown_id" | "expected_revision">,
    operation: string,
  ): Promise<Result<{ readonly unknown_id: UnkId; readonly revision: number }, BeaError>>;
}

// ---------------------------------------------------------------- queries & bundles (S2 §12–13)
export interface EvidenceQuery {
  summary(input: JsonObject): Result<JsonObject, BeaError>;
  complete(id: string): Promise<Result<JsonObject, BeaError>>;
  slice(
    id: EvId,
    pointer: string,
    offset: number,
    limit: number,
    format: "hex" | "base64",
  ): Promise<Result<JsonObject, BeaError>>;
}
export interface BundleService {
  export(input: JsonObject, signal?: AbortSignal): Promise<Result<JsonObject, BeaError>>;
  import(input: JsonObject, signal?: AbortSignal): Promise<Result<JsonObject, BeaError>>;
}

export interface EvidenceStatus {
  readonly run_id: RunId;
  readonly home: string;
  readonly usage: {
    readonly ledger: { readonly bytes: number; readonly quota: number; readonly reserve: number };
    readonly blobs: { readonly bytes: number; readonly quota: number };
    readonly streams: {
      readonly bytes: number;
      readonly quota_total: number;
      readonly per_stream_quota: number;
      readonly live: number;
    };
  };
  readonly counts: {
    readonly evidence: number;
    readonly effects_active: number;
    readonly unknowns_open: number;
    readonly instances: number;
  };
}

export interface EvidenceRuntime {
  readonly run: { readonly id: RunId; readonly dir: string; readonly kind: "mcp-stdio" | "mcp-http" | "cli" };
  readonly recorder: Recorder;
  readonly instances: InstanceRegistry;
  readonly modules: ModuleMapTracker;
  readonly effects: EffectRegistry;
  readonly streams: StreamStore;
  readonly blobs: BlobStore;
  readonly unknowns: UnknownRegistry;
  readonly query: EvidenceQuery;
  readonly bundles: BundleService;
  /** server-level + per-call literals (≥ 4 UTF-8 bytes each, else invalid_request) */
  literals(perCall: readonly string[] | undefined): Result<SensitiveLiterals, BeaError>;
  /** convenience used by every recorded tool: capture + locations for one resolved address */
  locationOf(ref: AddressRef, size?: number): Location;
  status(): EvidenceStatus;
  /** end streams + effects, append {t:"end"}, fsync, run.json closed; idempotent */
  finalize(reason: "shutdown" | "cli-exit"): Promise<Result<void, BeaError>>;
}
