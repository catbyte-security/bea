import type { BeaError } from "../domain/errors/beaError.js";
import type { FxId, StId } from "../domain/ids.js";
import type { JsonObject, JsonValue } from "../domain/json.js";
import type { Result } from "../domain/result.js";
import type { RowKind } from "../shared/agentProtocol.js";
import type { StreamRecord } from "./evidence.js";
import type { OperationContext, SessionId } from "./sessions.js";

/**
 * Recordings (S6 §2.5): every instrument produces exactly one recording and its handle `rec_xxxxxxxx` IS the
 * recording id. Registry implemented by src/application/instruments/RecordingRegistry.ts (WP-EVID). Each
 * recording KIND contributes a RecordingKindSpec from its own file under src/application/instruments/kinds/
 * (pre-wired index by WP0): hook (WP-HOOK), api (WP-BEHAVIOR), watch/poll/trace (WP-WATCH),
 * override (WP-MODIFY), exceptions/modules/output (WP-SESS).
 */
export type RecordingKind =
  | "hook"
  | "api"
  | "watch"
  | "poll"
  | "trace"
  | "override"
  | "exceptions"
  | "output"
  | "modules";
export type RecordingEndReason =
  | "duration"
  | "max_events"
  | "invocations"
  | "stopped"
  | "target_exited"
  | "detached"
  | "quota"
  /** the page-guard rate valve disarmed the watch in its handler (CT-I4, D-INT-20) */
  | "rate-limit";

export interface EventField {
  readonly name: string;
  readonly type: "int" | "float" | "string" | "bool" | "address" | "array" | "object";
}
/** One decoded event: always seq, t_ms (since instrument start), tid (when known) + kind fields (S6 §5.4). */
export type EventRecord = Readonly<Record<string, JsonValue>> & { readonly seq: number };

export interface DecodeContext {
  readonly sessionId: SessionId;
  /** row decoding needs the capture spec / catalog the recording was created with */
  readonly decoders: JsonValue;
  readonly startedAtUs: number;
  /** "module+0xrva" text → compact Loc string forms; supplied by the registry */
  readonly frame: (frameRef: string) => { readonly at: string | null; readonly static: string | null };
}
export interface SummaryBuilder<S> {
  init(): S;
  add(state: S, event: EventRecord): void;
  /** bounded digest (S6 §5.3), every list capped with totals */
  finish(state: S): JsonObject;
}
export interface RecordingKindSpec<S = unknown> {
  readonly kind: RecordingKind;
  readonly rowKinds: readonly (RowKind | "bytes")[];
  readonly fields: readonly EventField[];
  decode(record: StreamRecord, ctx: DecodeContext): Iterable<EventRecord>;
  readonly summary: SummaryBuilder<S>;
}

export interface InstrumentStateView {
  readonly recording_id: string;
  readonly kind: RecordingKind;
  readonly state: "active" | "finished" | "failed";
  readonly events: number;
  readonly dropped: number;
  readonly ends_in_ms: number | null;
  readonly end_reason: RecordingEndReason | null;
  readonly summary?: JsonObject;
}
export interface RecordingCreate {
  readonly sessionId: SessionId;
  readonly kind: RecordingKind;
  /** agent instrument id ("h3", "p1", "w2", "t1", "o1") or null for built-ins */
  readonly agentInstrumentId: string | null;
  readonly agentStream: string | null;
  readonly streamId: StId | null;
  readonly effectId: FxId | null;
  readonly durationMs: number | null;
  readonly maxEvents: number | null;
  /** duration clock starts at resume_process when installed on a paused target (S6 A7) */
  readonly startsAtResume: boolean;
  readonly decoders: JsonValue;
}
export interface Recording {
  readonly id: string;
  readonly create: RecordingCreate;
  view(): InstrumentStateView;
}
export interface RecordingRegistry {
  create(spec: RecordingCreate): Recording;
  get(id: string): Recording | undefined;
  list(sessionId: SessionId): readonly Recording[];
  /** marks ended (agent "instrument ended" message, stop, exit); finalizes the summary */
  end(id: string, reason: RecordingEndReason, op: OperationContext): Promise<Result<InstrumentStateView, BeaError>>;
  /** decoded events for query_events (checkpoints a live stream first) */
  events(
    id: string,
    range: { readonly from_seq?: number; readonly to_seq?: number },
    op: OperationContext,
  ): AsyncIterable<EventRecord>;
  summary(id: string, op: OperationContext): Promise<Result<JsonObject, BeaError>>;
  /** resume_process starts duration clocks of startsAtResume recordings */
  onResumed(sessionId: SessionId): void;
}
