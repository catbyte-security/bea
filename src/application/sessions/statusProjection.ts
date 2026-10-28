import type { z } from "zod";

import type { SESSION_TOOLS } from "../../contracts/areas/sessions.js";
import type { instrumentStateSchema } from "../../contracts/schemas/shared.js";
import type { EffectState } from "../../domain/effects/effect.js";
import type { FxId, PiId } from "../../domain/ids.js";
import type { ExitInfo } from "../../domain/process/instance.js";
import type { EvidenceRuntime } from "../../ports/evidence.js";
import type { HandleRegistry } from "../../ports/handles.js";
import type { InstrumentStateView, RecordingRegistry } from "../../ports/recordings.js";
import type {
  DerivedCrash,
  LiveSession,
  Liveness,
  SessionId,
  SessionObservation,
  VisibleSessionState,
} from "../../ports/sessions.js";
import { hostFactsOf } from "./hostFacts.js";

/**
 * Projections of host state into the sessions tools' result shapes (S6 §5.3, §5.5; DESIGN §6.2 A). Pure functions over
 * the ports; every list is bounded by its schema's cap.
 */
type Contract<N extends (typeof SESSION_TOOLS)[number]["name"]> = Extract<(typeof SESSION_TOOLS)[number], { name: N }>;
type Out<N extends (typeof SESSION_TOOLS)[number]["name"]> = z.output<Contract<N>["outputSchema"]>;
export type InstrumentState = z.output<typeof instrumentStateSchema>;
export type StartupResult = Pick<
  Out<"spawn_process">,
  | "session_id"
  | "identity"
  | "state"
  | "main_module"
  | "containment"
  | "recordings"
  | "agent"
  | "anti_cheat_signals"
  | "environment"
>;
export type StatusResult = Omit<
  Out<"session_status">,
  | "evidence_id"
  | "predicate_type"
  | "confidence"
  | "authority"
  | "coverage"
  | "limitations"
  | "instance_id"
  | "module_map_id"
  | "observed_at"
  | "perturbation"
  | "effects_applied"
  | "redactions"
  | "next"
>;

const instrumentStateOf = (view: InstrumentStateView, withSummary: boolean): InstrumentState => ({
  recording_id: view.recording_id,
  kind: view.kind,
  state: view.state,
  events: view.events,
  dropped: view.dropped,
  ends_in_ms: view.state === "active" ? view.ends_in_ms : null,
  end_reason: view.end_reason,
  ...(withSummary && view.summary !== undefined ? { summary: view.summary } : {}),
});

/** Every recording of a session (built-ins and instruments), active first, bounded. */
export const sessionInstruments = (
  recordings: RecordingRegistry,
  sessionId: SessionId,
  max: number,
  withSummary: boolean,
): InstrumentState[] => {
  const views = recordings.list(sessionId).map((r) => r.view());
  const ordered = [...views.filter((v) => v.state === "active"), ...views.filter((v) => v.state !== "active")];
  return ordered.slice(0, max).map((v) => instrumentStateOf(v, withSummary));
};

export const startupResult = (obs: SessionObservation, recordings: RecordingRegistry): StartupResult => {
  const main = obs.agent.hello.process.main_module;
  const recordingStates = obs.builtinRecordings
    .map((id) => recordings.get(id)?.view())
    .filter((view): view is InstrumentStateView => view !== undefined)
    .map((view) => {
      const { summary: _summary, ...state } = instrumentStateOf(view, false);
      void _summary;
      return state;
    });
  return {
    session_id: obs.sessionId,
    identity: identityOf(obs.instanceId, obs.identity, obs.ownership),
    state: obs.state,
    main_module: {
      name: main.name.slice(0, 260),
      base: main.base,
      preferred_base: obs.identity.image.preferredBase as `0x${string}` | null,
      size: main.size,
    },
    containment: {
      kind: obs.containment.kind,
      kill_on_close: obs.containment.killOnClose,
      breakaway: false,
      assigned_before_first_instruction: obs.containment.assignedBeforeResume,
      helper_pid: obs.ownership === "owned" ? obs.containment.helperPid : null,
      watch_helper_pid: obs.ownership === "attached" ? obs.containment.helperPid : null,
    },
    recordings: recordingStates,
    agent: {
      version: obs.agent.agentVersion,
      build_id: obs.agent.buildId,
      runtime: "qjs",
      bundle_sha256: obs.agent.bundleSha256,
    },
    anti_cheat_signals: [...obs.antiCheatSignals].slice(0, 32),
    environment:
      obs.environment === null
        ? null
        : {
            mode: obs.environment.mode,
            allowlist_version: 1,
            dropped_keys: obs.environment.droppedKeys,
            caller_keys: obs.environment.callerKeys,
          },
  };
};

export const identityOf = (
  instanceId: PiId,
  identity: LiveSession["identity"],
  ownership: "owned" | "attached",
): StartupResult["identity"] => ({
  instance_id: instanceId,
  pid: identity.pid,
  start_time: { value: identity.startTime.value, source: identity.startTime.source },
  image: { path: identity.image.path.slice(0, 4096), sha256: identity.image.sha256, size: identity.image.size },
  ownership,
});

export const exitOf = (liveness: Liveness): ExitInfo | null =>
  liveness.state === "exited" && liveness.exit !== null
    ? { code: liveness.exit.code, code_hex: liveness.exit.code_hex, kind: liveness.exit.kind, name: liveness.exit.name }
    : null;

/** CrashReport tool shape; xmm registers only with detail "complete" (S6 §5.5). */
export const crashOutput = (crash: DerivedCrash | null, withXmm: boolean): StatusResult["crash"] => {
  if (crash === null) return null;
  const registers = Object.fromEntries(
    Object.entries(crash.registers).filter(([name]) => withXmm || !name.startsWith("xmm")),
  ) as Record<string, `0x${string}`>;
  return {
    type: crash.type.slice(0, 64),
    ntstatus: crash.ntstatus,
    thread_id: crash.thread_id,
    pc: crash.pc,
    insn: crash.insn,
    memory: crash.memory === null ? null : { op: crash.memory.op, address: crash.memory.address as `0x${string}` },
    registers,
    backtrace: crash.backtrace.slice(0, 64),
    first_chance_count: crash.first_chance_count,
    evidence_id: crash.evidence_id,
  };
};

const effectTarget = (state: EffectState): string | null => {
  const display = state.effect.display.target_text;
  if (display !== null) return display.slice(0, 600);
  const address = state.effect.target.address;
  if (address === null) return null;
  return address.module_key !== null && address.rva !== null ? `${address.module_key}+${address.rva}` : address.va;
};

/** Effects of the instance this session knows about: active ∪ revert-failed, the recordings' and the lifecycle ones. */
export const sessionEffects = async (
  evidence: EvidenceRuntime,
  recordings: RecordingRegistry,
  session: LiveSession,
): Promise<StatusResult["effects"]> => {
  const ids = new Set<FxId>(evidence.effects.active(session.instanceId).map((s) => s.effect.effect_id as FxId));
  for (const recording of recordings.list(session.id))
    if (recording.create.effectId !== null) ids.add(recording.create.effectId);
  const facts = hostFactsOf(session);
  if (facts !== null) for (const ref of await facts.lifecycleEffects()) ids.add(ref.id);
  const rows: StatusResult["effects"] = [];
  for (const id of ids) {
    const state = evidence.effects.state(id);
    if (state === undefined) continue;
    rows.push({
      effect: id,
      kind: state.effect.kind,
      target: effectTarget(state),
      status: state.status,
      reversible: state.effect.reversible,
    });
    if (rows.length >= 64) break;
  }
  return rows;
};

export const sessionScans = (handles: HandleRegistry, sessionId: SessionId): StatusResult["scans"] =>
  handles
    .list(sessionId)
    .filter((view) => view.kind === "scan")
    .slice(0, 8)
    .map((view) => ({
      scan_id: view.id,
      value_type: String(view.summary["value_type"] ?? "unknown").slice(0, 16),
      count: typeof view.summary["count"] === "number" ? Math.max(0, Math.floor(view.summary["count"])) : 0,
      iteration: typeof view.summary["iteration"] === "number" ? Math.max(0, Math.floor(view.summary["iteration"])) : 0,
      state: view.state,
    }));

/** stdout tail, then a marked stderr tail, together ≤ 2 KiB (S6 §4.6 output_tail). */
export const outputTail = (session: LiveSession): string | null => {
  const output = session.output;
  if (output === null) return null;
  const stdout = output.tail(1, 2048);
  const stderr = output.observedBytes.stderr > 0 ? output.tail(2, 1024) : "";
  const text = stderr.length > 0 ? `${stdout.slice(-(2048 - stderr.length - 10))}\n[stderr]\n${stderr}` : stdout;
  return text.slice(-2048);
};

export const visibleOf = (state: LiveSession["state"]): VisibleSessionState => {
  switch (state) {
    case "paused":
    case "running":
    case "exited":
    case "detached":
    case "closing":
    case "cleanup_pending":
    case "closed":
      return state;
    default:
      return "closed";
  }
};
