import type { OutLayout } from "../domain/callModel/decode.js";
import type { CallOutcomeColumns, CallPlan, NormalizedVectors } from "../domain/callModel/types.js";
import type {
  BatchParams,
  BatchResult,
  CallResult,
  EngineVersions,
  FunctionRange,
  Insn,
  MemReadResult,
  OpenParams,
  OpenResult,
  RegionInfo,
  RunOptions,
  SessionStateInfo,
  StateWire,
  SweepParams,
  SweepResult,
} from "../domain/emuProtocol.js";
import type { BeaError } from "../domain/errors/beaError.js";
import type { EvId, FxId } from "../domain/ids.js";
import type { Result } from "../domain/result.js";
import type { PlanWire, VectorsWire } from "../shared/callPlan.js";
import type { Hex } from "../shared/hex.js";
import type { LiveSession, OperationContext } from "./sessions.js";

/** Emulator port (S5 §5.6). Implemented by src/providers/emulator/EmuAdapter.ts (WP-EMU). */
export interface EmuSessionHandle {
  readonly sessionId: string;
  readonly generation: number;
}
export interface EmuRequestOptions {
  readonly signal: AbortSignal;
  readonly deadlineAt: number; // performance.now() ms
  readonly onProgress?: (completed: number, total: number | null) => void;
}
export interface PartialBatch {
  readonly kind: "partial";
  readonly reason: "deadline" | "cancelled";
  readonly result: BatchResult;
}
export interface EmuSessionStatusView {
  readonly status: "ready" | "lost" | "failed" | "closed";
  readonly generation: number;
  readonly bridgePid: number | null;
  readonly childPid: number | null;
  readonly namedSnapshots: readonly { readonly name: string; readonly bytes: number }[];
  readonly lostSnapshots: readonly string[];
  readonly calls: number;
  readonly vectors: number;
}
export interface PythonStatus {
  readonly state: "not-resolved" | "available" | "unavailable";
  /** CI-M7: resolution order BEA_PYTHON > config.json `python` > BEA venv > PATH */
  readonly source: "BEA_PYTHON" | "config" | "bea-venv" | "path" | null;
  readonly command: string | null;
  readonly versions: EngineVersions | null;
  readonly pin: "exact" | "compatible" | null;
  readonly reason: string | null;
}
/** CI-B5: one mapped module of an emulation session (from OpenResult.modules; cached, no bridge round trip). */
export interface EmuModuleView {
  readonly name: string;
  readonly path: string | null;
  readonly sha256: string | null;
  readonly base: Hex;
  readonly size: number;
  readonly preferredBase: Hex | null;
  readonly primary: boolean;
}
export interface EmuPort {
  availability(): PythonStatus;
  /** CI-B5: shared-id lookup for tools owned by other WPs (read_memory, disassemble, list_modules, map_address…) */
  lookup(sessionId: string): EmuSessionHandle | null;
  /**
   * Review fix EMU-8: re-open a lost bridge before a call reads its state lineage; the handle of the generation the
   * next request runs in. Optional (fakes without bridges omit it: the handle stands).
   */
  ensureReady?(h: EmuSessionHandle, o: EmuRequestOptions): Promise<Result<EmuSessionHandle, BeaError>>;
  /** CI-B5: module table of the current generation (AddressService emulation space, list_modules) */
  modules(h: EmuSessionHandle): readonly EmuModuleView[];
  /** CI-B5: bridge session.info (session_status detail "complete") */
  info(
    h: EmuSessionHandle,
    o: EmuRequestOptions,
  ): Promise<Result<OpenResult & { readonly state: SessionStateInfo }, BeaError>>;
  open(
    input: OpenParams,
    op: OperationContext,
  ): Promise<Result<{ readonly runtime: EmuSessionHandle; readonly open: OpenResult }, BeaError>>;
  call(
    h: EmuSessionHandle,
    req: {
      readonly plan: PlanWire;
      readonly vectors: VectorsWire;
      readonly state: StateWire;
      readonly options: RunOptions;
    },
    o: EmuRequestOptions,
  ): Promise<Result<CallResult, BeaError>>;
  batch(
    h: EmuSessionHandle,
    req: Omit<BatchParams, "session">,
    o: EmuRequestOptions,
  ): Promise<Result<BatchResult, BeaError | PartialBatch>>;
  sweep(
    h: EmuSessionHandle,
    req: Omit<SweepParams, "session">,
    o: EmuRequestOptions,
  ): Promise<Result<SweepResult, BeaError>>;
  state(
    h: EmuSessionHandle,
    op: { readonly save: string } | { readonly restore: string } | { readonly drop: string } | { readonly list: true },
    o: EmuRequestOptions,
  ): Promise<Result<unknown, BeaError>>;
  readMemory(
    h: EmuSessionHandle,
    address: Hex,
    size: number,
    o: EmuRequestOptions,
  ): Promise<Result<MemReadResult, BeaError>>;
  disassemble(
    h: EmuSessionHandle,
    address: Hex,
    opts: { readonly count?: number; readonly function?: boolean },
    o: EmuRequestOptions,
  ): Promise<Result<{ readonly instructions: readonly Insn[]; readonly function: FunctionRange | null }, BeaError>>;
  regions(
    h: EmuSessionHandle,
    o: EmuRequestOptions,
  ): Promise<Result<{ readonly regions: readonly RegionInfo[]; readonly syntheticBase: Hex }, BeaError>>;
  status(h: EmuSessionHandle): EmuSessionStatusView;
  close(h: EmuSessionHandle): Promise<Result<{ readonly bridgeExit: number | null }, BeaError>>;
}

/** CT-I9: where a call's FP environment came from (recorded in evidence and returned as fp.source). */
export type FpSource = "explicit" | "thread" | "dump-thread" | "windows-default";
export interface ResolvedFpEnv {
  readonly mxcsr: number; // status bits 0..5 cleared
  readonly fpcw: number;
  readonly source: FpSource;
  readonly threadId: number | null;
}

/** What diff_function's live leg and call_function share (S5 §9.4; implemented by WP-CALL). */
export interface OracleBatchRequest {
  readonly target: { readonly va: Hex; readonly module: string | null; readonly rva: Hex | null };
  readonly plan: CallPlan;
  readonly vectors: NormalizedVectors;
  readonly offset: number;
  /** resolved ONCE by the caller (OracleService for call_function, DiffService for both diff legs) */
  readonly fp: ResolvedFpEnv;
  /** CT-I1: "agent" | runOnThread on tid | run inside an onEnter of a temporary hook at `at` (the safe point) */
  readonly thread:
    | "agent"
    | { readonly tid: number; readonly timeoutMs: number }
    | { readonly at: Hex; readonly tid: number | null; readonly timeoutMs: number };
  readonly chunk: number;
  readonly coverage: boolean;
  readonly deadlineAt: number;
  /**
   * Integrator (implement stage, WP11 + WP14 change requests): the declared field layout of the out buffers
   * (domain/callModel/decode.ts outLayout(plan, buffers)); the CallPlan carries only patched fields. Absent: the
   * out buffers decode as raw `<buffer>.__bytes` u8[] fields.
   */
  readonly outLayout?: OutLayout;
}
export interface OracleBatchResult {
  readonly outcome: CallOutcomeColumns;
  readonly completed: number;
  readonly nextOffset: number | null;
  readonly lostTarget: boolean;
  readonly evidence_id: EvId;
  readonly effect_id: FxId;
  readonly coverageBlob: { readonly sha256: string; readonly blocks: number } | null;
  /** CT-B1: see CallFunctionResult */
  readonly exceptionModel: "seh-frame" | "steal";
  readonly calleeExceptions: number;
}
export interface OracleCallPort {
  /** gate call_attached is checked by the caller BEFORE this (attached sessions); records bea.call.oracle + function-called */
  callPlanBatch(
    session: LiveSession,
    req: OracleBatchRequest,
    op: OperationContext,
  ): Promise<Result<OracleBatchResult, BeaError>>;
}
