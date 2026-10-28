import type { z } from "zod";

import type { ContractOf } from "../../contracts/index.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { withEffects } from "../../domain/errors/constructors.js";
import { COMPLETE } from "../../domain/evidence/coverage.js";
import { LIMITATIONS } from "../../domain/evidence/limitations.js";
import type { FxId, StId } from "../../domain/ids.js";
import type { JsonObject, JsonValue } from "../../domain/json.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { StreamWriter } from "../../ports/evidence.js";
import type { LiveSession, OperationContext } from "../../ports/sessions.js";
import type { OverrideInstallParams, OverrideInstallResult, ScalarInput } from "../../shared/agentProtocol.js";
import { formatHex, hexToBytes } from "../../shared/hex.js";
import { functionInterior, notFunctionStart } from "../address/functionStart.js";
import { abortedAfter, detachedOp, INSTALL_RPC_MS } from "../instruments/installOp.js";
import type { BeaApplication } from "../BeaApplication.js";
import type { ModifyValueType } from "../../contracts/areas/modify.js";
import { displayTarget, FRIDA_PROVIDER, issueError, withInstance } from "./common.js";
import { recordedEnvelope } from "./envelope.js";
import { agentScalarOfBits, agentValueType, bitsOfAddress, isFloatType, parseScalar } from "./values.js";

type OverrideContract = ContractOf<"override_function">;
export type OverrideInput = z.output<OverrideContract["inputSchema"]>;
export type OverrideOutput = z.output<OverrideContract["outputSchema"]>;

const OPERATION = "override_function";

/** Decoder context stored with the recording/stream (the override kind reads `values` to label rows). */
export interface OverrideDecoders {
  readonly schema: "bea.override-decoders/1";
  readonly mode: OverrideInput["mode"];
  readonly returns: OverrideInput["returns"];
  readonly args: readonly { readonly arg: number; readonly type: ModifyValueType }[];
}

/**
 * override_function (DESIGN §6.2 #28, S4 §14, S6 §4.29). Inside the exclusive section: resolve → exact raw bits of
 * every value (ptr values may be AddrExprs) → agent overrideInstall (rewrite args/ret or replace with a pinned
 * NativeCallback; lifetime clock "resume" while the target is still paused, CI-I3) → bind the override/1 stream →
 * effect `override-installed` (before = the patched head the agent saved) → recording (kind override) →
 * `bea.instrument.install` evidence. Any failure after the agent installed stops the agent instrument again.
 */
export const createOverrideService = (app: BeaApplication) => {
  const scalar = async (
    session: LiveSession,
    type: ModifyValueType,
    value: number | string | boolean,
    path: string,
    op: OperationContext,
  ): Promise<Result<ScalarInput, BeaError>> => {
    let parsed = parseScalar(type, value);
    if (parsed.kind === "address") {
      const target = await app.services.address.resolve({ kind: "live", session }, parsed.expr, op, { path });
      if (!target.ok) return target;
      parsed = bitsOfAddress(target.value.va);
    }
    if (parsed.kind === "error")
      return err(issueError(OPERATION, { path, reason: parsed.reason, message: parsed.message }));
    return ok(agentScalarOfBits(type, parsed.bits));
  };

  const buildParams = async (
    session: LiveSession,
    input: OverrideInput,
    va: bigint,
    op: OperationContext,
  ): Promise<Result<OverrideInstallParams, BeaError>> => {
    const lifetime = {
      duration_ms: input.duration_ms,
      max_hits: input.max_events,
      clock: session.paused ? ("resume" as const) : ("install" as const),
    };
    const base = { target: { va: formatHex(va) }, relocation: "auto" as const, lifetime, record: input.record };
    if (input.mode === "args") {
      const args: NonNullable<NonNullable<OverrideInstallParams["rewrite"]>["args"]> = [];
      for (const [i, a] of input.set_args.entries()) {
        const value = await scalar(session, a.type, a.value, `set_args[${String(i)}].value`, op);
        if (!value.ok) return value;
        args.push({
          slot: a.arg,
          class: isFloatType(a.type) ? "float" : "int",
          type: agentValueType(a.type),
          value: value.value,
        });
      }
      return ok({ ...base, mode: "rewrite", rewrite: { args } });
    }
    const returns = input.returns;
    if (returns === "void" || input.return_value === undefined)
      return err(
        issueError(OPERATION, {
          path: "returns",
          reason: "invalid_value",
          message: "returns must be a non-void type.",
        }),
      );
    const value = await scalar(session, returns, input.return_value, "return_value", op);
    if (!value.ok) return value;
    if (input.mode === "return")
      return ok({ ...base, mode: "rewrite", rewrite: { ret: { type: agentValueType(returns), value: value.value } } });
    return ok({
      ...base,
      mode: "replace",
      replace: { ret_type: agentValueType(returns), arg_types: [], returns: value.value },
    });
  };

  const stopAgent = async (session: LiveSession, installed: OverrideInstallResult, op: OperationContext) => {
    // LIFE-6: a rollback never takes the caller's (possibly aborted) signal
    const internal = detachedOp(op, INSTALL_RPC_MS);
    try {
      await session.agent.call(
        "instrumentStop",
        { id: installed.instrument_id, final_flush: false },
        { op: internal.op },
      );
    } finally {
      internal.dispose();
    }
  };

  const install = async (
    session: LiveSession,
    input: OverrideInput,
    op: OperationContext,
  ): Promise<Result<OverrideOutput, BeaError>> => {
    const evidence = app.services.evidence;
    const literals = evidence.literals(undefined);
    if (!literals.ok) return literals;
    const resolved = await app.services.address.resolve({ kind: "live", session }, input.address, op, {
      path: "address",
    });
    if (!resolved.ok) return resolved;
    const { ref, va } = resolved.value;
    // UX-1: rewriting args/ret or replacing inside a function body corrupts the target (the leave listener takes the
    // stack slot of a saved register); refuse before the agent installs anything
    const interior = await functionInterior(app.services.address, { kind: "live", session }, va);
    if (interior !== null)
      return err(notFunctionStart(OPERATION, "address", interior, " (the function entry) instead"));
    const params = await buildParams(session, input, va, op);
    if (!params.ok) return params;
    // LIFE-6: the install is a non-cancellable step; the caller's abort is checked once the agent answered
    const internal = detachedOp(op, INSTALL_RPC_MS);
    const reply = await session.agent.call("overrideInstall", params.value, { op: internal.op }).finally(() => {
      internal.dispose();
    });
    if (!reply.ok) return err(withInstance(reply.error, session));
    const installed = reply.value;
    const aborted = abortedAfter(op);
    if (aborted !== null) {
      await stopAgent(session, installed, op);
      return err(aborted);
    }

    const decoders: OverrideDecoders = {
      schema: "bea.override-decoders/1",
      mode: input.mode,
      returns: input.returns,
      args: input.set_args.map((a) => ({ arg: a.arg, type: a.type })),
    };
    let writer: StreamWriter | null = null;
    if (installed.stream_id !== null) {
      const bound = await session.streams.bind(installed.stream_id, {
        source: { kind: "override", instance_id: session.instanceId, effect_id: null, channel: installed.stream_id },
        encoding: { kind: "json-rows", row_kind: "override/1" },
        decoders: decoders as unknown as JsonValue,
        literals: literals.value,
      });
      if (!bound.ok) {
        await stopAgent(session, installed, op);
        return bound;
      }
      writer = bound.value;
    }
    const streamIds: StId[] = writer === null ? [] : [writer.stream_id];
    const location = evidence.locationOf(ref);
    const head = installed.effect.before[0];
    const applied = await evidence.effects.apply({
      instance_id: session.instanceId,
      kind: "override-installed",
      target: {
        address:
          location.kind === "address"
            ? {
                va: location.va,
                module_map_id: location.module_map_id,
                module_key: location.module_key,
                rva: location.rva,
              }
            : null,
        size: null,
        threads: "all",
      },
      parameters: {
        mode: input.mode,
        returns: input.returns,
        args:
          params.value.rewrite?.args?.map((a) => ({ slot: a.slot, type: a.type, value: a.value as JsonValue })) ?? [],
        return_value: (params.value.rewrite?.ret?.value ?? params.value.replace?.returns ?? null) as JsonValue,
        agent_instrument: installed.instrument_id,
      },
      ...(head === undefined ? {} : { before: hexToBytes(head.hex) }),
      lifetime: { duration_ms: input.duration_ms, max_hits: input.max_events },
      stream_ids: streamIds,
      applied_by: OPERATION,
      display_target: displayTarget(ref),
      literals: literals.value,
    });
    if (!applied.ok) {
      await stopAgent(session, installed, op);
      if (installed.stream_id !== null) await session.streams.end(installed.stream_id, "install-failed");
      return applied;
    }
    const effectId: FxId = applied.value.effect_id;

    const recording = app.services.recordings.create({
      sessionId: session.id,
      kind: "override",
      agentInstrumentId: installed.instrument_id,
      agentStream: installed.stream_id,
      streamId: writer?.stream_id ?? null,
      effectId,
      durationMs: input.duration_ms,
      maxEvents: input.max_events,
      startsAtResume: session.paused,
      decoders: decoders as unknown as JsonValue,
    });
    const instrument = recording.view();
    const limitations: string[] = [LIMITATIONS.OVERRIDE_ACTIVE];
    if (writer === null) limitations.push(LIMITATIONS.OVERRIDE_NOT_RECORDED);
    const result = { instrument, effect_id: effectId, target: ref };
    const recorded = await evidence.recorder.record({
      predicate_type: "bea.instrument.install",
      operation: OPERATION,
      input: input as unknown as JsonObject,
      subject: { kind: "process-instance", instance_id: session.instanceId },
      capture: evidence.instances.capture(session.instanceId),
      provider: FRIDA_PROVIDER,
      result: {
        ...result,
        mode: input.mode,
        relocation: installed.relocation,
        stream_id: writer?.stream_id ?? null,
      } as unknown as JsonObject,
      coverage: COMPLETE,
      limitations,
      locations: [location],
      effects: [effectId],
      literals: literals.value,
    });
    // The override stays installed (and revertible through its recording) even when the record could not be written.
    if (!recorded.ok) return err(withEffects(recorded.error, [effectId]));
    return ok({ ...result, ...recordedEnvelope(recorded.value) });
  };

  return { install };
};

export type OverrideService = ReturnType<typeof createOverrideService>;
