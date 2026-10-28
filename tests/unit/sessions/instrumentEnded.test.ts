import { describe, expect, it } from "vitest";

import type { FxId } from "../../../src/domain/ids.js";
import { NO_LITERALS } from "../../../src/domain/redaction/literals.js";
import { endedEffectTransition } from "../../../src/providers/frida/SessionRecord.js";
import { createHarness, settle, type Harness } from "./support/harness.js";

/**
 * Agent `instrument ended` messages (S4 §5.7 → DESIGN §5.1 agent channel → S2 §6.3): the recording ends with the
 * mapped reason, and the instrument's effect leaves `active` when the agent removed it on its own — `expired` at its
 * lifetime (duration, max hits), `revert-failed` when the agent could not verify the revert. Requested stops and
 * session ends keep settling their own effects (stop_instrumentation, the revert report, endAll).
 */
const hooked = async (h: Harness) => {
  const spawned = await h.spawn();
  if (!spawned.ok) throw new Error(spawned.error._tag);
  const { sessionId, instanceId } = spawned.value;
  // what an instrument tool does after the agent installed "h7": the effect, then the recording that cites it
  const applied = await h.evidence.effects.apply({
    instance_id: instanceId,
    kind: "hook-installed",
    target: { address: null, size: null, threads: null },
    parameters: {},
    applied_by: "hook_function",
    literals: NO_LITERALS,
  });
  if (!applied.ok) throw new Error(applied.error._tag);
  const effectId = applied.value.effect_id as FxId;
  const recording = h.recordings.create({
    sessionId,
    kind: "hook",
    agentInstrumentId: "h7",
    agentStream: null,
    streamId: null,
    effectId,
    durationMs: 300,
    maxEvents: 50,
    startsAtResume: false,
    decoders: null,
  });
  const ended = async (detail: Readonly<Record<string, unknown>>) => {
    h.fake.agentScript(spawned.value.identity.pid)?.emitPayload({
      bea: "instrument",
      id: "h7",
      event: "ended",
      detail: { id: "h7", kind: "hook", state: "ended", ...detail },
    });
    for (let i = 0; i < 5; i += 1) await settle();
  };
  return { effectId, recording, ended, status: () => h.evidence.effects.state(effectId)?.status };
};

describe("endedEffectTransition (S2 §6.3)", () => {
  it("expires lifetime ends, flags unverified reverts, and leaves requested stops and shutdowns alone", () => {
    expect(endedEffectTransition({ end_reason: "duration", reverted: true })).toMatchObject({
      to: "expired",
      detail: { reason: "lifetime-duration", verification: { method: "agent-confirmed", ok: true } },
    });
    expect(endedEffectTransition({ end_reason: "max_events", reverted: true })?.detail.reason).toBe(
      "lifetime-max-hits",
    );
    // review fix UX-11: an on_call trace that ran its requested invocations expires like a max_hits end
    expect(endedEffectTransition({ end_reason: "invocations", reverted: true })).toMatchObject({
      to: "expired",
      detail: { reason: "lifetime-max-hits" },
    });
    expect(
      endedEffectTransition({ end_reason: "duration", reverted: true, verification: { kind: "dr7", ok: false } }),
    ).toMatchObject({ to: "revert-failed", detail: { verification: { method: "thread-context", ok: false } } });
    expect(endedEffectTransition({ end_reason: "module-unloaded", reverted: false })).toMatchObject({
      to: "revert-failed",
      detail: { reason: "revert-error" },
    });
    expect(endedEffectTransition({ end_reason: "process-exit", reverted: true })).toBeNull();
    expect(endedEffectTransition({ end_reason: "requested", reverted: false })).toBeNull();
    expect(endedEffectTransition({ end_reason: "shutdown", reverted: true })).toBeNull();
  });
});

describe("agent instrument ended → recording and effect", () => {
  it("a duration end expires the effect (agent-confirmed) and ends the recording", async () => {
    const h = createHarness();
    const { effectId, recording, ended, status } = await hooked(h);
    await ended({ end_reason: "duration", reverted: true, verification: { kind: "bytes", ok: true, detail: "" } });
    expect(status()).toBe("expired");
    expect(h.evidence.effects.state(effectId)?.transitions.at(-1)).toMatchObject({
      to: "expired",
      reason: "lifetime-duration",
      verification: { method: "read-back", ok: true },
    });
    expect(h.recordings.ended).toContainEqual({ id: recording.id, reason: "duration" });
    await h.closeAll();
  });

  it("a page-guard valve end keeps its own reason on the recording (CT-I4: end_reason rate-limit)", async () => {
    const h = createHarness();
    const { recording, ended } = await hooked(h);
    await ended({ end_reason: "rate-limit", reverted: true, verification: { kind: "protection", ok: true } });
    expect(h.recordings.ended).toContainEqual({ id: recording.id, reason: "rate-limit" });
    await h.closeAll();
  });

  it("a max-hits end without a verified revert is revert-failed", async () => {
    const h = createHarness();
    const { effectId, ended, status } = await hooked(h);
    await ended({ end_reason: "max_hits", reverted: false, verification: null });
    expect(status()).toBe("revert-failed");
    expect(h.evidence.effects.state(effectId)?.transitions.at(-1)).toMatchObject({
      reason: "lifetime-max-hits",
      verification: { method: "agent-confirmed", ok: false },
    });
    await h.closeAll();
  });

  it("a requested stop or a shutdown leaves the effect to its own path; a settled effect is not moved again", async () => {
    const h = createHarness();
    const requested = await hooked(h);
    await requested.ended({ end_reason: "requested", reverted: true, verification: null });
    expect(requested.status()).toBe("active");
    await h.evidence.effects.transition(requested.effectId, "reverted", {
      reason: "stop-requested",
      verification: null,
      residue: [],
    });
    await requested.ended({ end_reason: "duration", reverted: true, verification: null });
    expect(requested.status()).toBe("reverted");
    await h.closeAll();
  });
});
