import { createHash } from "node:crypto";

import type { z } from "zod";

import type { SESSION_TOOLS } from "../../contracts/areas/sessions.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { COMPLETE, type Coverage } from "../../domain/evidence/coverage.js";
import type { PredicateType } from "../../domain/evidence/predicates.js";
import type { EvId, FxId, PiId } from "../../domain/ids.js";
import type { JsonObject } from "../../domain/json.js";
import { ok, type Result } from "../../domain/result.js";
import type { LiveSession, OperationContext, SessionObservation, WaitCondition } from "../../ports/sessions.js";
import type { BeaApplication } from "../BeaApplication.js";
import { envelopeOf } from "./evidenceEnvelope.js";
import { hostFactsOf, type LifecycleEffectRef } from "./hostFacts.js";
import { exitOf, startupResult } from "./statusProjection.js";

/**
 * Helpers of the sessions tool handlers (handlers/sessions.ts): tool evidence, lifecycle-effect lookup, wait
 * conditions, tombstone answers. Like the handlers, they reach sessions directly (this area answers tombstones itself).
 */
type Tools = typeof SESSION_TOOLS;
export type OutOf<N extends Tools[number]["name"]> = z.output<Extract<Tools[number], { name: N }>["outputSchema"]>;

const FRIDA_PROVIDER = { id: "frida", name: "frida", version: "17.23.2" } as const;

/** Evidence for a recorded sessions tool: subject = the instance, anchored, provider frida. */
export const recordTool = async <R extends JsonObject>(
  app: BeaApplication,
  input: {
    readonly predicate: PredicateType;
    readonly operation: string;
    readonly params: JsonObject;
    readonly instanceId: PiId;
    readonly result: R;
    readonly limitations: readonly string[];
    readonly effects: readonly FxId[];
    readonly links?: readonly EvId[];
    readonly literals?: readonly string[];
    /** default complete (review fix UX-5: resume_process marks a still-active recording partial) */
    readonly coverage?: Coverage;
  },
): Promise<Result<ReturnType<typeof envelopeOf>, BeaError>> => {
  const { evidence } = app.services;
  const literals = evidence.literals(input.literals);
  if (!literals.ok) return literals;
  const recorded = await evidence.recorder.record({
    predicate_type: input.predicate,
    operation: input.operation,
    input: input.params,
    subject: { kind: "process-instance", instance_id: input.instanceId },
    capture: evidence.instances.capture(input.instanceId),
    provider: FRIDA_PROVIDER,
    result: input.result,
    coverage: input.coverage ?? COMPLETE,
    limitations: input.limitations,
    effects: input.effects,
    ...(input.links === undefined || input.links.length === 0 ? {} : { evidence_links: input.links }),
    literals: literals.value,
  });
  if (!recorded.ok) return recorded;
  return ok(envelopeOf(recorded.value.record, { effectsApplied: input.effects }));
};

/** Reads the session's host facts (tombstones included) without taking the queue. */
export const peek = <T>(
  app: BeaApplication,
  sessionId: string,
  op: OperationContext,
  fn: (session: LiveSession) => Promise<T>,
): Promise<Result<T, BeaError>> =>
  app.services.sessions.withSession(sessionId, op, "concurrent", async (session) => ok(await fn(session)));

export const lifecycleOf = async (session: LiveSession): Promise<readonly LifecycleEffectRef[]> =>
  (await hostFactsOf(session)?.lifecycleEffects()) ?? [];

export const pick = (refs: readonly LifecycleEffectRef[], kinds: readonly string[]): FxId[] =>
  refs.filter((ref) => kinds.includes(ref.kind)).map((ref) => ref.id);

/** spawn/attach: the result shape + bea.process.instance evidence referencing the startup's lifecycle effects. */
export const startupOutcome = async (
  app: BeaApplication,
  op: OperationContext,
  obs: SessionObservation,
  params: JsonObject,
  literals: readonly string[],
) => {
  const effects = await peek(app, obs.sessionId, op, async (s) =>
    pick(await lifecycleOf(s), ["process-spawned", "process-suspended", "agent-injected"]),
  );
  const result = startupResult(obs, app.services.recordings);
  const envelope = await recordTool(app, {
    predicate: "bea.process.instance",
    operation: op.name,
    params,
    instanceId: obs.instanceId,
    result: result as unknown as JsonObject,
    limitations: obs.limitations,
    effects: effects.ok ? effects.value : [],
    literals,
  });
  if (!envelope.ok) return envelope;
  return ok({ ...result, ...envelope.value, instance_id: obs.instanceId, module_map_id: obs.moduleMapId });
};

export const keyDigest = (keys: readonly string[]): string | null =>
  keys.length === 0
    ? null
    : createHash("sha256")
        .update([...keys].sort().join("\n"))
        .digest("hex");

/** Instruments active at resume time (built-ins never finish while the process runs). */
export const waitConditionFor = (
  until: "any" | "exit" | "instruments_done",
  streams: readonly string[],
): WaitCondition | null => {
  const done: WaitCondition = { kind: "all", of: streams.map((agentStream) => ({ kind: "stream-end", agentStream })) };
  if (until === "exit") return { kind: "process-exit" };
  if (until === "instruments_done") return streams.length === 0 ? null : done;
  return streams.length === 0 ? { kind: "process-exit" } : { kind: "any", of: [{ kind: "process-exit" }, done] };
};

export const pollEnvelope = (limitations: readonly string[] = []) => ({
  evidence_id: null,
  predicate_type: null,
  confidence: null,
  authority: null,
  coverage: COMPLETE,
  limitations: [...limitations],
});

/** withSession(concurrent) whose callback already returns a Result. */
export const peekResult = async <T>(
  app: BeaApplication,
  sessionId: string,
  op: OperationContext,
  fn: (session: LiveSession) => Promise<Result<T, BeaError>>,
): Promise<Result<T, BeaError>> => app.services.sessions.withSession(sessionId, op, "concurrent", fn);

export const visibleEmulation = (state: string): "ready" | "lost" | "closed" | "closing" =>
  state === "lost" ? "lost" : state === "closed" ? "closed" : state === "closing" ? "closing" : "ready";

export const targetStateOf = (state: string): "killed" | "detached-running" | "exited" | "unknown" | "none" => {
  switch (state) {
    case "killed":
      return "killed";
    case "alive-detached":
      return "detached-running";
    case "already-exited":
    case "exited-during-close":
      return "exited";
    case "none":
      return "none";
    default:
      return "unknown";
  }
};

/** close_session on a closed session: the tombstone's final state, idempotent (no evidence). */
export const closedAnswer = async (
  app: BeaApplication,
  sessionId: string,
  op: OperationContext,
): Promise<Result<OutOf<"close_session">, BeaError>> => {
  const driver = app.services.sessions.external(sessionId);
  if (driver !== null)
    return ok({
      session_id: sessionId,
      already_closed: true,
      target_state: "none" as const,
      reverted: [],
      exit: null,
      manifests: [],
      ...pollEnvelope(),
    });
  return peekResult(app, sessionId, op, async (session) => {
    const exit = exitOf(session.liveness());
    const facts = hostFactsOf(session);
    const owned = session.ownership === "owned";
    return ok({
      session_id: sessionId,
      already_closed: true,
      target_state:
        exit !== null && exit.kind !== "bea-kill"
          ? ("exited" as const)
          : owned
            ? ("killed" as const)
            : ("detached-running" as const),
      reverted: [],
      exit,
      manifests: (facts?.manifests() ?? []).slice(0, 64),
      ...pollEnvelope(),
    });
  });
};
