import { afterEach, describe, expect, it } from "vitest";

import { EFFECT_EDGES, type EffectKind } from "../../../src/domain/effects/effect.js";
import { effectIdOf } from "../../../src/domain/evidence/authenticate.js";
import type { FxId, PiId } from "../../../src/domain/ids.js";
import { literalsOf, NO_LITERALS } from "../../../src/domain/redaction/literals.js";
import type { EffectDraft } from "../../../src/ports/evidence.js";
import { makeRuntime, observation, readDraft, type RuntimeFixture } from "./support.js";

let fx: RuntimeFixture | undefined;
afterEach(async () => {
  await fx?.cleanup();
  fx = undefined;
});

const setup = async (): Promise<{ fixture: RuntimeFixture; instance: PiId }> => {
  fx = await makeRuntime();
  const r = await fx.runtime.instances.register(await observation(fx.home));
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  return { fixture: fx, instance: r.value.instance.instance_id };
};

const draft = (instance: PiId, kind: EffectKind, extra: Partial<EffectDraft> = {}): EffectDraft => ({
  instance_id: instance,
  kind,
  target: {
    address: { va: "0x140001000", module_map_id: null, module_key: "game_sim.exe", rva: "0x1000" },
    size: 4,
    threads: null,
  },
  parameters: { gate: "write_memory" },
  applied_by: "write_memory",
  literals: NO_LITERALS,
  ...extra,
});

describe("effects (S2 §6, §22 effects)", () => {
  it("creates immutable records whose id authenticates; every create and transition bumps the epoch", async () => {
    const { fixture, instance } = await setup();
    expect(fixture.runtime.effects.epoch(instance)).toBe(0);
    const applied = await fixture.runtime.effects.apply(
      draft(instance, "memory-written", { before: new Uint8Array([1, 2, 3, 4]) }),
    );
    if (!applied.ok) throw new Error(JSON.stringify(applied.error));
    const effect = applied.value;
    expect(effectIdOf(effect)).toBe(effect.effect_id);
    expect(effect).toMatchObject({
      class: "modify",
      reversible: true,
      before: { bytes: 4, hex: "01020304", retained: true },
    });
    expect(effect.applied_at.effect_epoch).toBe(1);
    expect(fixture.runtime.effects.state(effect.effect_id)?.status).toBe("active");
    const moved = await fixture.runtime.effects.transition(effect.effect_id, "reverted", {
      reason: "stop-requested",
      verification: { method: "read-back", ok: true, evidence_id: null },
      residue: [],
    });
    expect(moved.ok && moved.value.status).toBe("reverted");
    expect(fixture.runtime.effects.epoch(instance)).toBe(2);
  });

  it("enforces the state machine: every legal edge succeeds, terminal states refuse", async () => {
    const { fixture, instance } = await setup();
    for (const [from, targets] of Object.entries(EFFECT_EDGES))
      for (const to of targets) {
        const created = await fixture.runtime.effects.apply(draft(instance, "hook-installed"));
        if (!created.ok) throw new Error("apply");
        const id = created.value.effect_id;
        if (from === "revert-failed") {
          const failed = await fixture.runtime.effects.transition(id, "revert-failed", {
            reason: "revert-error",
            verification: null,
            residue: [],
          });
          expect(failed.ok).toBe(true);
        }
        const moved = await fixture.runtime.effects.transition(id, to, {
          reason: "session-close",
          verification: null,
          residue: [],
        });
        expect(moved.ok, `${from} -> ${to}`).toBe(true);
        if (to !== "revert-failed") {
          const again = await fixture.runtime.effects.transition(id, "reverted", {
            reason: "session-close",
            verification: null,
            residue: [],
          });
          expect(again.ok || again.error._tag).toBe("InvalidState");
        }
      }
    const permanent = await fixture.runtime.effects.apply(draft(instance, "function-called"));
    if (!permanent.ok) throw new Error("apply");
    expect(fixture.runtime.effects.state(permanent.value.effect_id)?.status).toBe("permanent");
    const refused = await fixture.runtime.effects.transition(permanent.value.effect_id, "reverted", {
      reason: "stop-requested",
      verification: null,
      residue: [],
    });
    expect(refused.ok || refused.error._tag).toBe("InvalidState");
  });

  it("computes perturbation levels, taint and excludes the agent-injected effect from the list", async () => {
    const { fixture, instance } = await setup();
    const agent = await fixture.runtime.effects.apply(
      draft(instance, "agent-injected", { target: { address: null, size: null, threads: null } }),
    );
    expect(fixture.runtime.effects.perturbation(instance)).toEqual({
      level: "agent-only",
      active_effect_ids: [],
      tainted_by: [],
    });
    const hook = await fixture.runtime.effects.apply(draft(instance, "hook-installed"));
    if (!agent.ok || !hook.ok) throw new Error("apply");
    expect(fixture.runtime.effects.perturbation(instance)).toEqual({
      level: "passive",
      active_effect_ids: [hook.value.effect_id],
      tainted_by: [],
    });
    const call = await fixture.runtime.effects.apply(draft(instance, "function-called"));
    if (!call.ok) throw new Error("apply");
    const p = fixture.runtime.effects.perturbation(instance);
    expect(p).toEqual({
      level: "intrusive",
      active_effect_ids: [hook.value.effect_id],
      tainted_by: [call.value.effect_id],
    });
    const recorded = await fixture.runtime.recorder.record(readDraft(fixture.runtime, instance));
    if (!recorded.ok) throw new Error("record");
    expect(
      recorded.value.record.limitations.some((l) => l.startsWith("Target state was modified by 1 irreversible")),
    ).toBe(true);
    expect(recorded.value.record.perturbation.tainted_by).toEqual([call.value.effect_id]);
  });

  it("keeps original bytes in memory for disassembly even when they were not persisted (literal)", async () => {
    const { fixture, instance } = await setup();
    const before = new TextEncoder().encode("ABpasswordCD");
    const applied = await fixture.runtime.effects.apply(
      draft(instance, "code-patched", {
        before,
        literals: literalsOf(["password"]),
        target: {
          address: { va: "0x140001000", module_map_id: null, module_key: null, rva: null },
          size: 12,
          threads: null,
        },
      }),
    );
    if (!applied.ok) throw new Error("apply");
    expect(applied.value.before).toEqual({ bytes: 12, sha256: null, hex: null, blob: null, retained: false });
    const original = fixture.runtime.effects.originalBytes(instance, 0x140001002n, 4);
    expect(original.ranges).toHaveLength(1);
    expect(original.ranges[0]?.va).toBe(0x140001002n);
    expect(new TextDecoder().decode(original.ranges[0]?.bytes)).toBe("pass");
  });

  it("endAll moves every active effect to implicit-end with the given reason", async () => {
    const { fixture, instance } = await setup();
    const ids: FxId[] = [];
    for (const kind of ["agent-injected", "hook-installed", "watch-armed"] as const) {
      const r = await fixture.runtime.effects.apply(draft(instance, kind));
      if (r.ok) ids.push(r.value.effect_id);
    }
    await fixture.runtime.effects.endAll(instance, "process-exited");
    expect(fixture.runtime.effects.active(instance)).toEqual([]);
    for (const id of ids) {
      const state = fixture.runtime.effects.state(id);
      expect(state?.status).toBe("implicit-end");
      expect(state?.transitions[0]?.reason).toBe("process-exited");
    }
    expect(fixture.runtime.effects.state(ids[0] as FxId)?.transitions[0]?.residue[0]).toMatch(/stay loaded/u);
  });

  it("stores large before bytes as a blob", async () => {
    const { fixture, instance } = await setup();
    const applied = await fixture.runtime.effects.apply(
      draft(instance, "memory-written", { before: new Uint8Array(5000).fill(7) }),
    );
    if (!applied.ok) throw new Error("apply");
    expect(applied.value.before?.hex).toBeNull();
    expect(applied.value.before?.blob).toMatch(/^[0-9a-f]{64}$/u);
    expect(fixture.runtime.blobs.has(applied.value.before?.blob ?? "")).toBe(true);
  });
});
