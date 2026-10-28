import type { z } from "zod";

import type { ContractOf } from "../../contracts/index.js";
import type { AddressRef } from "../../domain/address/addressRef.js";
import type { EffectKind } from "../../domain/effects/effect.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { referenceNotFound, withEffects } from "../../domain/errors/constructors.js";
import { COMPLETE } from "../../domain/evidence/coverage.js";
import { LIMITATIONS } from "../../domain/evidence/limitations.js";
import type { Location } from "../../domain/evidence/record.js";
import type { FxId, PiId } from "../../domain/ids.js";
import type { JsonObject } from "../../domain/json.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { Effect } from "../../domain/effects/effect.js";
import type { SensitiveLiterals } from "../../ports/evidence.js";
import type { HandleKindSpec, HandleStopOutcome, HandleView } from "../../ports/handles.js";
import type { LiveSession, OperationContext, SessionId } from "../../ports/sessions.js";
import type { WriteResult } from "../../shared/agentProtocol.js";
import { bytesToHex, formatHex, hexToBytes, type Hex } from "../../shared/hex.js";
import type { BeaApplication } from "../BeaApplication.js";
import { addressUnmapped, displayTarget, FRIDA_PROVIDER, isAgentTag, issueError, withInstance } from "./common.js";
import { recordedEnvelope } from "./envelope.js";
import { bitsOfAddress, bytesOfBits, parseScalar } from "./values.js";

type WriteContract = ContractOf<"write_memory">;
export type WriteInput = z.output<WriteContract["inputSchema"]>;
export type WriteOutput = z.output<WriteContract["outputSchema"]>;

const OPERATION = "write_memory";
const FX_ID_RE = /^fx_[0-9a-f]{64}$/u;

/** One gated write as the host tracks it (CI-B6: the `fx_` id is a `write` handle for stop/wait/status). */
export interface WriteEntry {
  readonly id: FxId;
  readonly sessionId: SessionId;
  readonly instanceId: PiId;
  /** agent write id ("wr<n>") */
  readonly writeId: string;
  readonly kind: Extract<EffectKind, "memory-written" | "code-patched">;
  readonly va: Hex;
  readonly size: number;
  readonly method: WriteResult["method"];
  readonly before: string;
  state: "active" | "reverted" | "revert-failed";
}

export interface WriteService {
  /** registered in HandleRegistry by createModifyHandlers (CI-B6) */
  readonly handleKind: HandleKindSpec;
  write(session: LiveSession, input: WriteInput, op: OperationContext): Promise<Result<WriteOutput, BeaError>>;
  /** test/inspection view */
  entries(sessionId: SessionId): readonly WriteEntry[];
}

const effectTarget = (location: Location, size: number): Effect["target"] => ({
  address:
    location.kind === "address"
      ? { va: location.va, module_map_id: location.module_map_id, module_key: location.module_key, rva: location.rva }
      : null,
  size,
  threads: null,
});

/**
 * write_memory (DESIGN §6.2 #27, S4 §8.3, S6 §4.16). Flow inside the session's exclusive section:
 * literals → resolve address → intended bytes (hex or typed, ptr values may be AddrExprs) → describeAddresses picks
 * the agent mode (executable page → `code`, patchCode; else `data`, direct or protect-and-restore) → writeMemory
 * (read-back verification in the agent) → effect `memory-written`/`code-patched` with the before/after bytes
 * (+ a closed `protection-changed` effect for protect-and-restore) → evidence `bea.memory.write`.
 * Revert: HandleKindSpec.stop (stop_instrumentation {ids:[fx_…]}) → agent revertWrite → effect transition.
 */
export const createWriteService = (app: BeaApplication): WriteService => {
  const entries = new Map<FxId, WriteEntry>();
  let subscribed = false;
  const subscribe = (): void => {
    if (subscribed) return;
    subscribed = true;
    // CI-B6: the session's end reverts or ends every effect (SESS + EVID); the host handles just go away.
    app.services.sessions.onSessionEnded((event) => {
      for (const [id, entry] of entries) if (entry.sessionId === event.sessionId) entries.delete(id);
    });
  };

  const intendedBytes = async (
    session: LiveSession,
    input: WriteInput,
    op: OperationContext,
  ): Promise<Result<Uint8Array, BeaError>> => {
    if (input.hex !== undefined) return ok(hexToBytes(input.hex.toLowerCase()));
    const type = input.type;
    const value = input.value;
    if (type === undefined || value === undefined)
      return err(
        issueError(OPERATION, { path: "type", reason: "missing_argument", message: "type and value go together." }),
      );
    let parsed = parseScalar(type, value);
    if (parsed.kind === "address") {
      const target = await app.services.address.resolve({ kind: "live", session }, parsed.expr, op, { path: "value" });
      if (!target.ok) return target;
      parsed = bitsOfAddress(target.value.va);
    }
    if (parsed.kind === "error")
      return err(issueError(OPERATION, { path: "value", reason: parsed.reason, message: parsed.message }));
    return ok(bytesOfBits(type, parsed.bits));
  };

  const undo = async (session: LiveSession, writeId: string, op: OperationContext): Promise<void> => {
    // Best effort: the effect could not be recorded, so the write must not stay behind unrecorded.
    await session.agent.call("revertWrite", { write_id: writeId, force: true }, { op });
  };

  const applyEffects = async (
    session: LiveSession,
    written: WriteResult,
    ref: AddressRef,
    location: Location,
    literals: SensitiveLiterals,
  ): Promise<Result<readonly FxId[], BeaError>> => {
    const effects = app.services.evidence.effects;
    const target = effectTarget(location, written.size);
    const main = await effects.apply({
      instance_id: session.instanceId,
      kind: written.method === "patchCode" ? "code-patched" : "memory-written",
      target,
      parameters: { method: written.method, size: written.size, write_id: written.write_id },
      before: hexToBytes(written.before),
      after: hexToBytes(written.after),
      applied_by: OPERATION,
      display_target: displayTarget(ref),
      literals,
    });
    if (!main.ok) return main;
    if (written.method !== "protect-and-restore") return ok([main.value.effect_id]);
    // S6 §4.16: the temporary protection change is its own (already closed) effect.
    const protection = await effects.apply({
      instance_id: session.instanceId,
      kind: "protection-changed",
      target,
      parameters: { from: written.protection_before, during: "rw-", restored: written.protection_after },
      applied_by: OPERATION,
      display_target: displayTarget(ref),
      literals,
    });
    if (!protection.ok) return err(withEffects(protection.error, [main.value.effect_id]));
    const closed = await effects.transition(protection.value.effect_id, "reverted", {
      reason: "stop-requested",
      verification: {
        method: "agent-confirmed",
        ok: written.protection_after === written.protection_before,
        evidence_id: null,
      },
      residue: [],
    });
    const ids = [main.value.effect_id, protection.value.effect_id];
    return closed.ok ? ok(ids) : err(withEffects(closed.error, ids));
  };

  const write: WriteService["write"] = async (session, input, op) => {
    const evidence = app.services.evidence;
    const literals = evidence.literals(input.sensitive_values);
    if (!literals.ok) return literals;
    const resolved = await app.services.address.resolve({ kind: "live", session }, input.address, op, {
      path: "address",
    });
    if (!resolved.ok) return resolved;
    const { ref, va } = resolved.value;
    const bytes = await intendedBytes(session, input, op);
    if (!bytes.ok) return bytes;

    const described = await session.agent.call("describeAddresses", { addresses: [formatHex(va)] }, { op });
    if (!described.ok) return err(withInstance(described.error, session));
    const range = described.value.results[0]?.range ?? null;
    if (range === null) return err(addressUnmapped(OPERATION, va, ref));
    const mode = range.protection.includes("x") ? "code" : "data";

    const reply = await session.agent.call(
      "writeMemory",
      { address: formatHex(va), mode, bytes: bytesToHex(bytes.value), allow_protect_change: true },
      { op },
    );
    if (!reply.ok) return err(withInstance(reply.error, session));
    const written = reply.value;

    const location = evidence.locationOf(ref, written.size);
    const applied = await applyEffects(session, written, ref, location, literals.value);
    const register = (mainId: FxId): void => {
      entries.set(mainId, {
        id: mainId,
        sessionId: session.id,
        instanceId: session.instanceId,
        writeId: written.write_id,
        kind: written.method === "patchCode" ? "code-patched" : "memory-written",
        va: formatHex(va),
        size: written.size,
        method: written.method,
        before: written.before,
        state: "active",
      });
      subscribe();
    };
    if (!applied.ok) {
      const recordedMain = applied.error.effects_applied?.[0];
      // The write effect itself is on the ledger: keep it revertible through its fx_ handle.
      if (recordedMain !== undefined) register(recordedMain as FxId);
      else await undo(session, written.write_id, op);
      return applied;
    }
    const effectIds = applied.value;
    const mainId = effectIds[0] as FxId;
    register(mainId);

    const limitations: string[] = [];
    if (!written.verified) limitations.push(LIMITATIONS.WRITE_UNVERIFIED);
    if (written.method === "protect-and-restore") limitations.push(LIMITATIONS.WRITE_PROTECTION_RESTORED);
    if (written.method === "patchCode") limitations.push(LIMITATIONS.WRITE_CODE_PATCH);
    const result = {
      effect_id: mainId,
      address: ref,
      before_hex: written.before,
      after_hex: written.after,
      verified: written.verified,
      method: written.method,
    };
    const recorded = await evidence.recorder.record({
      predicate_type: "bea.memory.write",
      operation: OPERATION,
      input: input as unknown as JsonObject,
      subject: { kind: "process-instance", instance_id: session.instanceId },
      capture: evidence.instances.capture(session.instanceId),
      provider: FRIDA_PROVIDER,
      result: result as unknown as JsonObject,
      coverage: COMPLETE,
      limitations,
      locations: [location],
      effects: effectIds,
      literals: literals.value,
    });
    if (!recorded.ok) return err(withEffects(recorded.error, effectIds));
    return ok({ ...result, ...recordedEnvelope(recorded.value) });
  };

  const view = (entry: WriteEntry): HandleView => ({
    id: entry.id,
    kind: "write",
    sessionId: entry.sessionId,
    state: entry.state === "revert-failed" ? "failed" : entry.state,
    summary: { effect: entry.kind, address: entry.va, size: entry.size, method: entry.method },
  });

  const stop = async (
    session: LiveSession,
    id: string,
    op: OperationContext,
  ): Promise<Result<HandleStopOutcome, BeaError>> => {
    const entry = entries.get(id as FxId);
    if (entry === undefined || entry.sessionId !== session.id) return err(referenceNotFound(op.name, "effect", id));
    const outcome = (status: HandleStopOutcome["status"]): HandleStopOutcome => ({ id, kind: "write", status });
    if (entry.state === "reverted") return ok(outcome("already_ended"));
    const effects = app.services.evidence.effects;
    const reverted = await session.agent.call("revertWrite", { write_id: entry.writeId, force: false }, { op });
    if (!reverted.ok) {
      if (reverted.error._tag === "ReferenceNotFound") {
        // The agent no longer holds the write (reverted by its own shutdown path); nothing is left to undo here.
        entries.delete(entry.id);
        return ok(outcome("already_ended"));
      }
      if (!isAgentTag(reverted.error, "WriteConflict")) return err(withInstance(reverted.error, session));
      entry.state = "revert-failed";
      const failed = await effects.transition(entry.id, "revert-failed", {
        reason: "revert-error",
        verification: { method: "read-back", ok: false, evidence_id: null },
        residue: ["the memory changed after the write; it was left as found"],
      });
      return failed.ok ? ok(outcome("revert-failed")) : failed;
    }
    const verifiedBack = reverted.value.reverted && reverted.value.after === entry.before;
    entry.state = verifiedBack ? "reverted" : "revert-failed";
    const moved = await effects.transition(entry.id, verifiedBack ? "reverted" : "revert-failed", {
      reason: verifiedBack ? "stop-requested" : "revert-error",
      verification: { method: "read-back", ok: verifiedBack, evidence_id: null },
      residue: verifiedBack ? [] : ["the read-back after the revert did not equal the original bytes"],
    });
    if (!moved.ok) return moved;
    return ok(outcome(verifiedBack ? "reverted" : "revert-failed"));
  };

  const handleKind: HandleKindSpec = {
    kind: "write",
    owns: (id) => FX_ID_RE.test(id) && entries.has(id as FxId),
    list: (sessionId) => [...entries.values()].filter((e) => e.sessionId === sessionId).map(view),
    get: (id) => {
      const entry = entries.get(id as FxId);
      return entry === undefined ? undefined : view(entry);
    },
    doneCondition: () => null,
    stop,
  };

  return {
    handleKind,
    write,
    entries: (sessionId) => [...entries.values()].filter((e) => e.sessionId === sessionId),
  };
};
