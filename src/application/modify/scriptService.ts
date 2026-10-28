import type { z } from "zod";

import { SCRIPT_INLINE } from "../../contracts/areas/modify.js";
import type { ContractOf } from "../../contracts/index.js";
import { sha256Hex } from "../../domain/canonical.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { withEffects, withPartial } from "../../domain/errors/constructors.js";
import { COMPLETE, type Coverage } from "../../domain/evidence/coverage.js";
import { LIMITATIONS } from "../../domain/evidence/limitations.js";
import type { BlobRef } from "../../domain/evidence/record.js";
import type { FxId } from "../../domain/ids.js";
import type { JsonObject, JsonValue } from "../../domain/json.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { SensitiveLiterals } from "../../ports/evidence.js";
import type { LiveSession, OperationContext, UserScriptOutcome } from "../../ports/sessions.js";
import type { Fingerprint } from "../../shared/agentProtocol.js";
import type { BeaApplication } from "../BeaApplication.js";
import { FRIDA_PROVIDER, withInstance } from "./common.js";
import { recordedEnvelope } from "./envelope.js";
import { fingerprintInterference } from "./fingerprint.js";

type ScriptContract = ContractOf<"run_script">;
export type ScriptInput = z.output<ScriptContract["inputSchema"]>;
export type ScriptOutput = z.output<ScriptContract["outputSchema"]>;

const OPERATION = "run_script";
/** Output bound of errors[] (DESIGN §6.2 #29). */
const MAX_ERRORS = 64;
const MAX_ERROR_TEXT = 1000;

/**
 * The inline part of a capture (the MCP result is bounded by SCRIPT_INLINE; the evidence blob keeps everything):
 * payloads become compact JSON text cut at SCRIPT_INLINE.messageChars (marked with a trailing "…"), at most
 * SCRIPT_INLINE.messages of them; `truncated` means the CAPTURE lost messages (agent/port caps or max_messages).
 */
export const inlineScriptResult = (outcome: UserScriptOutcome, maxMessages: number) => {
  const kept = outcome.messages.slice(0, maxMessages);
  let shortened = kept.length > SCRIPT_INLINE.messages;
  const text = (value: JsonValue, limit: number): string => {
    const json = JSON.stringify(value);
    if (json.length <= limit) return json;
    shortened = true;
    return `${json.slice(0, limit - 1)}…`;
  };
  const messages = kept.slice(0, SCRIPT_INLINE.messages).map((m) => text(m, SCRIPT_INLINE.messageChars));
  const rpcResult = outcome.rpcResult === undefined ? undefined : text(outcome.rpcResult, SCRIPT_INLINE.rpcResultChars);
  const result: {
    messages: string[];
    messages_total: number;
    errors: { description: string; line: number | null }[];
    rpc_result?: string;
    truncated: boolean;
  } = {
    messages,
    messages_total: kept.length,
    errors: outcome.errors.slice(0, MAX_ERRORS).map((e) => ({
      description: e.description.slice(0, MAX_ERROR_TEXT),
      line: e.line !== null && Number.isInteger(e.line) && e.line >= 0 ? e.line : null,
    })),
    ...(rpcResult === undefined ? {} : { rpc_result: rpcResult }),
    truncated: outcome.truncated || outcome.messages.length > kept.length,
  };
  return { result, shortened, errorsCapped: outcome.errors.length > MAX_ERRORS };
};

/**
 * run_script (DESIGN §6.2 #29, S4 §16, CI-B4). The caller's JavaScript runs in its OWN Frida script through
 * `LiveSession.scripts` (never inside the BEA agent); MODIFY keeps the gate (invokeTool, scope always), the agent
 * fingerprint before/after (interference), the `script-run` effect (a permanent taint: the script's side effects are
 * unknown) and the `bea.script.run` evidence. A syntax error rejects createScript (invalid_request) before anything
 * ran, so it applies no effect. An unload failure is reported as effect_unreverted AFTER the evidence is recorded.
 */
export const createScriptService = (app: BeaApplication) => {
  const fingerprint = async (session: LiveSession, op: OperationContext): Promise<Fingerprint | null> => {
    const reply = await session.agent.call("fingerprint", {}, { op });
    return reply.ok ? reply.value : null;
  };

  const applyEffect = async (session: LiveSession, input: ScriptInput): Promise<Result<FxId, BeaError>> => {
    const literals = app.services.evidence.literals(undefined);
    if (!literals.ok) return literals;
    const applied = await app.services.evidence.effects.apply({
      instance_id: session.instanceId,
      kind: "script-run",
      target: { address: null, size: null, threads: "all" },
      parameters: {
        runtime: input.runtime,
        duration_ms: input.duration_ms,
        source_sha256: sha256Hex(input.source),
        rpc_method: input.rpc_method ?? null,
      },
      applied_by: OPERATION,
      literals: literals.value,
    });
    return applied.ok ? ok(applied.value.effect_id) : applied;
  };

  const run = async (
    session: LiveSession,
    input: ScriptInput,
    op: OperationContext,
  ): Promise<Result<ScriptOutput, BeaError>> => {
    const before = await fingerprint(session, op);
    const outcome = await session.scripts.run(
      {
        source: input.source,
        runtime: input.runtime,
        durationMs: input.duration_ms,
        maxMessages: input.max_messages,
        ...(input.rpc_method === undefined ? {} : { rpcMethod: input.rpc_method }),
        rpcArgs: input.rpc_args,
      },
      op,
    );
    if (!outcome.ok) {
      // A rejected createScript never ran; anything else may have run part of the script.
      if (outcome.error._tag === "InputError") return outcome;
      const effect = await applyEffect(session, input);
      const error = withInstance(outcome.error, session);
      return err(effect.ok ? withEffects(error, [effect.value]) : error);
    }
    const after = await fingerprint(session, op);
    const interference = before === null || after === null ? null : fingerprintInterference(before, after);
    const effect = await applyEffect(session, input);
    if (!effect.ok) return effect;
    return record({ session, input, outcome: outcome.value, interference, effectId: effect.value });
  };

  /** The complete capture as an NDJSON blob (one send() payload per line); null when empty or redacted. */
  const storeMessages = async (
    messages: readonly JsonValue[],
    literals: SensitiveLiterals,
  ): Promise<Result<BlobRef | "redacted" | null, BeaError>> => {
    if (messages.length === 0) return ok(null);
    const ndjson = messages.map((m) => `${JSON.stringify(m)}\n`).join("");
    const put = await app.services.evidence.blobs.put(new TextEncoder().encode(ndjson), {
      role: "script.messages",
      media_type: "application/x-ndjson",
      literals,
    });
    if (!put.ok) return put;
    return ok("redacted" in put.value ? "redacted" : put.value);
  };

  const record = async (r: {
    readonly session: LiveSession;
    readonly input: ScriptInput;
    readonly outcome: UserScriptOutcome;
    readonly interference: boolean | null;
    readonly effectId: FxId;
  }): Promise<Result<ScriptOutput, BeaError>> => {
    const { session, input, outcome, interference, effectId } = r;
    const evidence = app.services.evidence;
    const literals = evidence.literals(undefined);
    if (!literals.ok) return err(withEffects(literals.error, [effectId]));
    const inline = inlineScriptResult(outcome, input.max_messages);
    const blob = await storeMessages(outcome.messages.slice(0, input.max_messages), literals.value);
    if (!blob.ok) return err(withEffects(blob.error, [effectId]));
    const result = { ...inline.result, unloaded: outcome.unloaded, interference };
    const limitations: string[] = [LIMITATIONS.SCRIPT_RAN];
    if (interference === true) limitations.push(LIMITATIONS.SCRIPT_INTERFERENCE);
    if (interference === null) limitations.push(LIMITATIONS.SCRIPT_FINGERPRINT_UNAVAILABLE);
    if (!outcome.unloaded) limitations.push(LIMITATIONS.SCRIPT_NOT_UNLOADED);
    if (inline.result.truncated) limitations.push(LIMITATIONS.CAP("message", input.max_messages));
    if (inline.errorsCapped) limitations.push(LIMITATIONS.CAP("script error", MAX_ERRORS));
    if (inline.shortened) limitations.push(LIMITATIONS.SCRIPT_MESSAGES_INLINE);
    if (blob.value === "redacted") limitations.push(LIMITATIONS.REDACTED(1));
    const lost = inline.result.truncated || inline.errorsCapped || blob.value === "redacted";
    const coverage: Coverage = lost
      ? {
          status: "partial",
          truncated: true,
          reasons: blob.value === "redacted" ? ["explicit_sensitive_value", "row_cap"] : ["row_cap"],
        }
      : COMPLETE;
    const recorded = await evidence.recorder.record({
      predicate_type: "bea.script.run",
      operation: OPERATION,
      input: input as unknown as JsonObject,
      subject: { kind: "process-instance", instance_id: session.instanceId },
      capture: evidence.instances.capture(session.instanceId),
      provider: FRIDA_PROVIDER,
      result: result as unknown as JsonObject,
      ...(blob.value === null || blob.value === "redacted" ? {} : { blobs: [blob.value] }),
      coverage,
      limitations,
      effects: [effectId],
      literals: literals.value,
    });
    if (!recorded.ok) return err(withEffects(recorded.error, [effectId]));
    if (!outcome.unloaded) {
      const unreverted: BeaError = {
        _tag: "EffectUnreverted",
        operation: OPERATION,
        instance_id: session.instanceId,
        effect_ids: [effectId],
      };
      return err(withPartial(withEffects(unreverted, [effectId]), recorded.value.record.evidence_id));
    }
    return ok({ ...result, ...recordedEnvelope(recorded.value) });
  };

  return { run };
};

export type ScriptService = ReturnType<typeof createScriptService>;
