import type { Deadline } from "../../domain/deadline.js";
import type { EffectKind } from "../../domain/effects/effect.js";
import type { AgentIdentity } from "../../domain/evidence/record.js";
import type { EvId, FxId, PiId } from "../../domain/ids.js";
import type { JsonObject, JsonValue } from "../../domain/json.js";
import type { Logger } from "../../domain/logger.js";
import type { ExitInfo } from "../../domain/process/instance.js";
import { COMPLETE } from "../../domain/evidence/coverage.js";
import type { EvidenceRuntime, SensitiveLiterals } from "../../ports/evidence.js";
import type { RecordingRegistry } from "../../ports/recordings.js";
import type { SessionEventSink } from "../../ports/sink.js";
import type { CloseReport, SessionId } from "../../ports/sessions.js";
import type { CrashReport, ExitMessage } from "../../shared/agentProtocol.js";
import type { LifecycleEffectRef } from "./hostFacts.js";

/**
 * Session lifecycle → evidence (S3 §18; port SessionEventSink). The ONE place lifecycle facts become ledger lines:
 * lifecycle effects (process-spawned / -suspended / -resumed / -killed, agent-injected and its end), instance state
 * changes, `bea.exception.report` for crash reports, `bea.process.exit` for the agent's exit report, and effect
 * transitions when the session ends (attached reverts mapped per instrument, everything else implicit-end). Sync
 * methods never throw and queue their work per session (in order); crashReport/exitReport resolve before the host
 * posts the agent's ack (record-before-ack) and honour their deadline; sessionEnded drains the queue first.
 */
export interface SinkSessionBinding {
  readonly sessionId: SessionId;
  readonly instanceId: PiId;
  readonly ownership: "owned" | "attached";
  readonly literals: SensitiveLiterals;
  readonly agent: AgentIdentity | null;
}

export interface SessionEndFacts {
  readonly sessionId: SessionId;
  readonly report: CloseReport;
  readonly deadline: Deadline;
  /** the tool or internal operation that ended the session (effect applied_by) */
  readonly operation?: string;
}

interface SessionLedger {
  readonly binding: SinkSessionBinding;
  readonly effects: LifecycleEffectRef[];
  readonly crashEvidence: Map<string, EvId>;
  queue: Promise<void>;
  ended: boolean;
}

export interface SessionEvidenceSinkDeps {
  readonly evidence: EvidenceRuntime;
  readonly recordings: RecordingRegistry;
  readonly logger: Logger;
  readonly fridaVersion: () => string | null;
}

const opName = (value: unknown, fallback: string): string =>
  typeof value === "string" && /^[a-z][a-z0-9_]{1,63}$/u.test(value) ? value : fallback;

const effectKindFor: Readonly<Record<string, readonly EffectKind[]>> = {
  "process-spawned": ["process-spawned", "process-suspended"],
  "agent-injected": ["agent-injected"],
  "process-resumed": ["process-resumed"],
  "process-killed": ["process-killed"],
};

export class SessionEvidenceSink implements SessionEventSink {
  readonly #deps: SessionEvidenceSinkDeps;
  readonly #sessions = new Map<SessionId, SessionLedger>();
  /** facts that arrived before the session's instance was registered (startup) */
  readonly #early = new Map<SessionId, (() => Promise<void>)[]>();

  constructor(deps: SessionEvidenceSinkDeps) {
    this.#deps = deps;
  }

  /** Called once the session's process instance is registered; replays facts that arrived earlier. */
  bindSession(binding: SinkSessionBinding): void {
    const ledger: SessionLedger = {
      binding,
      effects: [],
      crashEvidence: new Map(),
      queue: Promise.resolve(),
      ended: false,
    };
    this.#sessions.set(binding.sessionId, ledger);
    for (const work of this.#early.get(binding.sessionId) ?? []) this.#enqueue(ledger, work);
    this.#early.delete(binding.sessionId);
  }

  /** Drop facts of a startup that never registered an instance. */
  forget(sessionId: SessionId): void {
    this.#early.delete(sessionId);
    if (this.#sessions.get(sessionId)?.ended === true) this.#sessions.delete(sessionId);
  }

  /** Waits for queued work, then lists the lifecycle effects applied for the session. */
  async lifecycleEffects(sessionId: SessionId): Promise<readonly LifecycleEffectRef[]> {
    const ledger = this.#sessions.get(sessionId);
    if (ledger === undefined) return [];
    await ledger.queue;
    return [...ledger.effects];
  }

  crashEvidenceId(sessionId: SessionId, reportId: string): EvId | null {
    return this.#sessions.get(sessionId)?.crashEvidence.get(reportId) ?? null;
  }

  /** Resolves when the session's queued work has run. */
  async settle(sessionId: SessionId): Promise<void> {
    await this.#sessions.get(sessionId)?.queue;
  }

  // ---------------------------------------------------------------- port: sync facts (queued)
  stateChanged(e: Parameters<SessionEventSink["stateChanged"]>[0]): void {
    this.#deps.logger.debug("session state", { session: e.sessionId, from: e.from, to: e.to, cause: e.cause });
    const state = e.to === "running" ? "running" : null;
    if (state === null) return;
    this.#later(e.sessionId, async (ledger) => {
      await this.#updateInstance(ledger, { state });
    });
  }

  targetEffect(e: Parameters<SessionEventSink["targetEffect"]>[0]): void {
    const kinds = effectKindFor[e.kind];
    const operation = opName(e.facts["operation"], "session_lifecycle");
    if (kinds !== undefined) {
      this.#later(e.sessionId, async (ledger) => {
        for (const kind of kinds) {
          if (kind === "process-killed" && ledger.effects.some((fx) => fx.kind === "process-killed")) continue;
          if (kind === "process-resumed")
            await this.#transitionKind(ledger, "process-suspended", "reverted", "resumed");
          await this.#applyEffect(ledger, kind, operation, e.facts);
        }
      });
      return;
    }
    if (e.kind === "agent-unloaded" || e.kind === "process-detached")
      this.#later(e.sessionId, async (ledger) => {
        await this.#transitionKind(
          ledger,
          "agent-injected",
          e.kind === "agent-unloaded" ? "reverted" : "implicit-end",
          e.kind === "agent-unloaded" ? "agent-unloaded" : "detached",
          ["11 DLLs remain loaded in the target after detach."],
        );
      });
  }

  rootExit(e: Parameters<SessionEventSink["rootExit"]>[0]): void {
    const exit: ExitInfo = { code: e.exit.code, code_hex: e.exit.code_hex, kind: e.exit.kind, name: e.exit.name };
    this.#later(e.sessionId, async (ledger) => {
      await this.#updateInstance(ledger, { state: "exited", exit });
      await this.#deps.evidence.effects.endAll(ledger.binding.instanceId, "process-exited");
    });
  }

  procEvent(e: Parameters<SessionEventSink["procEvent"]>[0]): void {
    this.#deps.logger.debug("job process event", { session: e.sessionId, kind: e.kind, pid: e.pid });
  }

  detached(e: Parameters<SessionEventSink["detached"]>[0]): void {
    if (e.info.requestedByBea || e.info.reason === "process-terminated") return;
    this.#later(e.sessionId, async (ledger) => {
      await this.#updateInstance(ledger, { state: "detached" });
      await this.#deps.evidence.effects.endAll(ledger.binding.instanceId, "detached");
    });
  }

  agentFault(e: Parameters<SessionEventSink["agentFault"]>[0]): void {
    this.#deps.logger.debug("agent fault", { session: e.sessionId, kind: e.fault.kind, text: e.fault.description });
  }

  // ---------------------------------------------------------------- port: record-before-ack
  async crashReport(e: {
    readonly sessionId: SessionId;
    readonly report: CrashReport;
    readonly deadline: Deadline;
  }): Promise<void> {
    const ledger = this.#sessions.get(e.sessionId);
    if (ledger === undefined) return;
    const { report } = e;
    const result: JsonObject = {
      report_id: report.report_id,
      phase: report.phase,
      type: report.type,
      code: report.code,
      thread_id: report.tid,
      address: report.address,
      memory: report.memory === null ? null : { operation: report.memory.operation, address: report.memory.address },
      registers: { ...report.registers },
      eflags: report.eflags,
      mxcsr: report.mxcsr,
      fpcw: report.fpcw,
      instruction:
        report.instruction === null
          ? null
          : { address: report.instruction.address, bytes: report.instruction.bytes, text: report.instruction.text },
      backtrace: report.backtrace.slice(0, 64).map((f) => ({ va: f.va, module: f.module, rva: f.rva })),
      backtrace_source: report.backtrace_source,
      stack: report.stack === null ? null : { address: report.stack.address, hex: report.stack.hex },
      module_map_epoch: report.module_map_epoch,
    };
    const recorded = await withDeadline(
      this.#record(ledger, "bea.exception.report", "agent_crash_report", { report_id: report.report_id }, result),
      e.deadline,
    );
    if (recorded !== null) ledger.crashEvidence.set(report.report_id, recorded);
  }

  async exitReport(e: {
    readonly sessionId: SessionId;
    readonly report: ExitMessage;
    readonly deadline: Deadline;
  }): Promise<void> {
    const ledger = this.#sessions.get(e.sessionId);
    if (ledger === undefined) return;
    const result: JsonObject = {
      source: "agent-exit-hook",
      via: e.report.via,
      exit_code: e.report.exit_code,
      thread_id: e.report.tid,
      flushed: { streams: e.report.flushed.streams, rows: e.report.flushed.rows },
    };
    await withDeadline(
      this.#record(ledger, "bea.process.exit", "agent_exit_report", { via: e.report.via }, result),
      e.deadline,
    );
  }

  /** Port method; `operation` is the provider's addition (who ended the session). */
  async sessionEnded(e: SessionEndFacts): Promise<void> {
    const ledger = this.#sessions.get(e.sessionId);
    this.#early.delete(e.sessionId);
    if (ledger === undefined || ledger.ended) return;
    ledger.ended = true;
    await withDeadline(ledger.queue, e.deadline);
    const work = async (): Promise<void> => {
      const { report } = e;
      const instance = ledger.binding.instanceId;
      const operation = opName(e.operation, "session_close");
      if (report.revert !== null) await this.#applyRevertReport(ledger, report);
      const killed =
        report.targetState === "killed" &&
        report.termination !== null &&
        report.termination.method !== "none" &&
        ledger.binding.ownership === "owned";
      if (killed && !ledger.effects.some((fx) => fx.kind === "process-killed"))
        await this.#applyEffect(ledger, "process-killed", operation, {
          method: report.termination?.method ?? "none",
          settled: report.termination?.settled ?? "unknown",
        });
      if (report.agentUnloaded === true)
        await this.#transitionKind(ledger, "agent-injected", "reverted", "agent-unloaded", [
          "11 DLLs remain loaded in the target after detach.",
        ]);
      const reason =
        report.targetState === "alive-detached"
          ? "detached"
          : report.targetState === "killed"
            ? "session-close"
            : "process-exited";
      await this.#deps.evidence.effects.endAll(instance, operation === "server_shutdown" ? "server-shutdown" : reason);
      const exit = report.exit;
      await this.#updateInstance(ledger, {
        state: report.targetState === "alive-detached" ? "detached" : "exited",
        ...(exit === null
          ? {}
          : { exit: { code: exit.code, code_hex: exit.code_hex, kind: exit.kind, name: exit.name } }),
      });
    };
    await withDeadline(work(), e.deadline);
  }

  // ---------------------------------------------------------------- internals
  #later(sessionId: SessionId, work: (ledger: SessionLedger) => Promise<void>): void {
    const ledger = this.#sessions.get(sessionId);
    if (ledger === undefined) {
      const list = this.#early.get(sessionId) ?? [];
      list.push(async () => {
        const bound = this.#sessions.get(sessionId);
        if (bound !== undefined) await work(bound);
      });
      this.#early.set(sessionId, list);
      return;
    }
    this.#enqueue(ledger, () => work(ledger));
  }

  #enqueue(ledger: SessionLedger, work: () => Promise<void>): void {
    ledger.queue = ledger.queue.then(work).catch((cause: unknown) => {
      this.#deps.logger.warn("session evidence work failed", { cause: cause instanceof Error ? cause : String(cause) });
    });
  }

  async #applyEffect(
    ledger: SessionLedger,
    kind: EffectKind,
    operation: string,
    facts: Readonly<Record<string, JsonValue>>,
  ): Promise<void> {
    const parameters: JsonObject = Object.fromEntries(
      Object.entries(facts).filter(
        ([key, value]) => key !== "operation" && (typeof value !== "string" || value.length <= 64),
      ),
    );
    const applied = await this.#deps.evidence.effects.apply({
      instance_id: ledger.binding.instanceId,
      kind,
      target: { address: null, size: null, threads: null },
      parameters,
      applied_by: operation,
      literals: ledger.binding.literals,
    });
    if (applied.ok) ledger.effects.push({ kind, id: applied.value.effect_id as FxId });
    else this.#deps.logger.warn("lifecycle effect not recorded", { kind, error: applied.error._tag });
  }

  async #transitionKind(
    ledger: SessionLedger,
    kind: EffectKind,
    to: "reverted" | "implicit-end",
    reason: "resumed" | "agent-unloaded" | "detached",
    residue: readonly string[] = [],
  ): Promise<void> {
    for (const ref of ledger.effects.filter((fx) => fx.kind === kind)) {
      const state = this.#deps.evidence.effects.state(ref.id);
      if (state === undefined || (state.status !== "active" && state.status !== "revert-failed")) continue;
      const moved = await this.#deps.evidence.effects.transition(ref.id, to, {
        reason,
        verification: to === "reverted" ? { method: "agent-confirmed", ok: true, evidence_id: null } : null,
        residue: [...residue],
      });
      if (!moved.ok) this.#deps.logger.warn("lifecycle effect transition failed", { kind, error: moved.error._tag });
    }
  }

  /** Attached close: the agent's shutdown report says which instruments were reverted; map them to their effects. */
  async #applyRevertReport(ledger: SessionLedger, report: CloseReport): Promise<void> {
    const revert = report.revert;
    if (revert === null) return;
    const recordings = this.#deps.recordings.list(ledger.binding.sessionId);
    const unreverted = new Set(revert.unreverted.map((u) => u.id));
    for (const stopped of revert.stopped) {
      const recording = recordings.find((r) => r.create.agentInstrumentId === stopped.id);
      const effectId = recording?.create.effectId ?? null;
      if (effectId === null) continue;
      const state = this.#deps.evidence.effects.state(effectId);
      if (state === undefined || (state.status !== "active" && state.status !== "revert-failed")) continue;
      const ok = stopped.reverted && !unreverted.has(stopped.id);
      await this.#deps.evidence.effects.transition(effectId, ok ? "reverted" : "revert-failed", {
        reason: "session-close",
        verification:
          stopped.verification === null
            ? { method: "agent-confirmed", ok, evidence_id: null }
            : {
                method: stopped.verification.kind === "dr7" ? "thread-context" : "read-back",
                ok: stopped.verification.ok,
                evidence_id: null,
              },
        residue: [],
      });
    }
  }

  async #updateInstance(
    ledger: SessionLedger,
    change: { readonly state?: "running" | "exited" | "detached"; readonly exit?: ExitInfo | null },
  ): Promise<void> {
    const updated = await this.#deps.evidence.instances.update(ledger.binding.instanceId, change);
    if (!updated.ok) this.#deps.logger.debug("instance update failed", { error: updated.error._tag });
  }

  async #record(
    ledger: SessionLedger,
    predicate: "bea.exception.report" | "bea.process.exit",
    operation: string,
    input: JsonObject,
    result: JsonObject,
  ): Promise<EvId | null> {
    const { evidence } = this.#deps;
    const recorded = await evidence.recorder.record({
      predicate_type: predicate,
      operation,
      input,
      subject: { kind: "process-instance", instance_id: ledger.binding.instanceId },
      capture: evidence.instances.capture(ledger.binding.instanceId),
      provider: { id: "frida", name: "frida", version: this.#deps.fridaVersion() },
      agent: ledger.binding.agent,
      result,
      coverage: COMPLETE,
      literals: ledger.binding.literals,
    });
    if (!recorded.ok) {
      this.#deps.logger.warn("lifecycle evidence not recorded", { predicate, error: recorded.error._tag });
      return null;
    }
    return recorded.value.record.evidence_id as EvId;
  }
}

/** Resolves with the work's value, or null when the deadline passes first (the work keeps running). */
const withDeadline = async <T>(work: Promise<T>, deadline: Deadline): Promise<T | null> => {
  const left = deadline.remaining();
  if (left <= 0) return null;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      work,
      new Promise<null>((resolve) => {
        timer = setTimeout(() => resolve(null), left);
        timer.unref?.();
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
};
