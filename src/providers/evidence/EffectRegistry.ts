import { sha256Hex } from "../../domain/canonical.js";
import type { Clock, SequenceAllocator } from "../../domain/clock.js";
import {
  EFFECT_EDGES,
  EFFECT_KIND_TABLE,
  effectSchema,
  type Effect,
  type EffectState,
  type EffectTransition,
} from "../../domain/effects/effect.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { invalidState, referenceNotFound } from "../../domain/errors/constructors.js";
import { effectIdOf } from "../../domain/evidence/authenticate.js";
import { sortedSet } from "../../domain/evidence/invariants.js";
import { NO_PERTURBATION, type Perturbation } from "../../domain/evidence/record.js";
import { bytesToHex } from "../../domain/hex.js";
import type { FxId, PiId, RunId } from "../../domain/ids.js";
import type { JsonObject, JsonValue } from "../../domain/json.js";
import type { Logger } from "../../domain/logger.js";
import { bytesContainLiteral, jsonContainsLiteral, textContainsLiteral } from "../../domain/redaction/redact.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { TimeAnchor } from "../../domain/time.js";
import type { EffectDraft, EffectRegistry, SensitiveLiterals } from "../../ports/evidence.js";
import type { FileBlobStore } from "./BlobStore.js";
import { internalError } from "./errors.js";
import type { Ledger } from "./Ledger.js";
import { foldEffect, type LedgerIndex } from "./LedgerIndex.js";

/** Effects (S2 §6): immutable creation records + transition lines; status is a fold; every line bumps the epoch. */
const INLINE_BYTES = 4096;
const MAX_IDS = 256;
const AGENT_RESIDUE = "frida-agent.dll and about 11 system DLLs stay loaded in the target after detach.";

export interface EffectDeps {
  readonly runId: RunId;
  readonly clock: Clock;
  readonly seq: SequenceAllocator;
  readonly ledger: Ledger;
  readonly index: LedgerIndex;
  readonly blobs: FileBlobStore;
  readonly logger: Logger;
  readonly moduleEpoch: (instance: PiId) => number | null;
}

type ByteState = NonNullable<Effect["before"]>;

export class LedgerEffectRegistry implements EffectRegistry {
  readonly #epochs = new Map<PiId, number>();
  readonly #byInstance = new Map<PiId, FxId[]>();
  readonly #memory = new Map<FxId, { readonly before?: Uint8Array; readonly va: bigint | null }>();
  readonly #chains = new Map<FxId, Promise<unknown>>();

  constructor(private readonly deps: EffectDeps) {}

  #anchor(instance: PiId, epoch: number): TimeAnchor {
    return {
      run_id: this.deps.runId,
      seq: this.deps.seq.next(),
      mono_ns: this.deps.clock.monoNs().toString(),
      wall: this.deps.clock.wallIso(),
      effect_epoch: epoch,
      module_map_epoch: this.deps.moduleEpoch(instance) ?? 0,
    };
  }

  #bump(instance: PiId): number {
    const epoch = (this.#epochs.get(instance) ?? 0) + 1;
    this.#epochs.set(instance, epoch);
    return epoch;
  }

  async #byteState(
    bytes: Uint8Array | undefined,
    role: string,
    literals: SensitiveLiterals,
  ): Promise<Result<ByteState | null, BeaError>> {
    if (bytes === undefined) return ok(null);
    const withheld: ByteState = { bytes: bytes.length, sha256: null, hex: null, blob: null, retained: false };
    if (literals.count > 0 && bytesContainLiteral(bytes, literals)) return ok(withheld);
    if (bytes.length <= INLINE_BYTES)
      return ok({ bytes: bytes.length, sha256: sha256Hex(bytes), hex: bytesToHex(bytes), blob: null, retained: true });
    const put = await this.deps.blobs.put(bytes, { role, media_type: "application/octet-stream", literals });
    if (!put.ok) return put;
    if ("redacted" in put.value) return ok(withheld);
    return ok({ bytes: bytes.length, sha256: put.value.sha256, hex: null, blob: put.value.sha256, retained: true });
  }

  async apply(draft: EffectDraft): Promise<Result<Effect, BeaError>> {
    const operation = draft.applied_by;
    const info = EFFECT_KIND_TABLE[draft.kind];
    const before = await this.#byteState(draft.before, "effect.before", draft.literals);
    if (!before.ok) return before;
    const after = await this.#byteState(draft.after, "effect.after", draft.literals);
    if (!after.ok) return after;
    const parameters: Record<string, JsonValue> = {};
    for (const [key, value] of Object.entries(draft.parameters))
      if (!jsonContainsLiteral(key, draft.literals) && !jsonContainsLiteral(value, draft.literals))
        parameters[key] = value;
    const display = draft.display_target ?? null;
    const epoch = this.#bump(draft.instance_id);
    const body: Omit<Effect, "effect_id"> = {
      schema: "bea.effect/1",
      instance_id: draft.instance_id,
      kind: draft.kind,
      class: info.class,
      reversible: info.reversible === "if-before-retained" ? draft.before !== undefined : info.reversible,
      target: draft.target,
      parameters: parameters as JsonObject,
      before: before.value,
      after: after.value,
      lifetime:
        draft.lifetime === undefined
          ? null
          : { duration_ms: draft.lifetime.duration_ms ?? null, max_hits: draft.lifetime.max_hits ?? null },
      stream_ids: sortedSet(draft.stream_ids ?? []),
      applied_by: draft.applied_by,
      applied_at: this.#anchor(draft.instance_id, epoch),
      display: {
        target_text: display === null || textContainsLiteral(display, draft.literals) ? null : display.slice(0, 600),
      },
    };
    const effect = { ...body, effect_id: effectIdOf(body) } as Effect;
    const parsed = effectSchema.safeParse(effect);
    if (!parsed.success)
      return err(internalError(operation, `effect draft invalid: ${parsed.error.issues[0]?.message ?? ""}`));
    const appended = await this.deps.ledger.append({ t: "fx", effect }, { operation });
    if (!appended.ok) return appended;
    this.deps.index.addEffect(effect, appended.value);
    const list = this.#byInstance.get(draft.instance_id);
    if (list === undefined) this.#byInstance.set(draft.instance_id, [effect.effect_id]);
    else list.push(effect.effect_id);
    const va = draft.target.address === null ? null : BigInt(draft.target.address.va);
    this.#memory.set(effect.effect_id, { ...(draft.before === undefined ? {} : { before: draft.before }), va });
    return ok(effect);
  }

  transition(
    id: FxId,
    to: EffectTransition["to"],
    detail: Pick<EffectTransition, "reason" | "verification" | "residue">,
  ): Promise<Result<EffectState, BeaError>> {
    const previous = this.#chains.get(id) ?? Promise.resolve();
    const task = previous.catch(() => undefined).then(() => this.#transition(id, to, detail));
    this.#chains.set(id, task);
    return task;
  }

  async #transition(
    id: FxId,
    to: EffectTransition["to"],
    detail: Pick<EffectTransition, "reason" | "verification" | "residue">,
  ): Promise<Result<EffectState, BeaError>> {
    const operation = "effect.transition";
    const entry = this.deps.index.effects.get(id);
    if (entry === undefined || entry.origin.kind !== "local") return err(referenceNotFound(operation, "effect", id));
    const state = foldEffect(entry);
    if (state.status !== "active" && state.status !== "revert-failed")
      return err(invalidState(operation, state.status, ["active", "revert-failed"]));
    const from = state.status;
    if (!EFFECT_EDGES[from].includes(to))
      return err(invalidState(operation, `${from}->${to}`, [...EFFECT_EDGES[from]]));
    const instance = entry.effect.instance_id;
    const transition: EffectTransition = {
      schema: "bea.effect-transition/1",
      effect_id: id,
      from,
      to,
      at: this.#anchor(instance, this.#bump(instance)),
      reason: detail.reason,
      verification: detail.verification,
      residue: detail.residue.slice(0, 8).map((r) => r.slice(0, 300)),
    };
    const appended = await this.deps.ledger.append({ t: "fxt", transition }, { operation, lifecycle: true });
    if (!appended.ok) return appended;
    this.deps.index.addTransition(transition, appended.value);
    return ok(foldEffect(entry));
  }

  state(id: FxId): EffectState | undefined {
    return this.deps.index.effectState(id);
  }

  #states(instance: PiId): EffectState[] {
    return (this.#byInstance.get(instance) ?? [])
      .map((id) => this.deps.index.effectState(id))
      .filter((s): s is EffectState => s !== undefined);
  }

  active(instance: PiId): readonly EffectState[] {
    return this.#states(instance).filter((s) => s.status === "active" || s.status === "revert-failed");
  }

  /** S2 §6.5: level from the active classes; taint from permanent tainting effects + revert-failed modifies. */
  perturbation(instance: PiId): Perturbation {
    const states = this.#states(instance);
    if (!this.#epochs.has(instance) && states.length === 0) return { ...NO_PERTURBATION, level: "agent-only" };
    const active = states.filter((s) => s.status === "active" || s.status === "revert-failed");
    const tainted = states.filter(
      (s) =>
        (s.status === "permanent" && EFFECT_KIND_TABLE[s.effect.kind].taintsWhenPermanent) ||
        (s.status === "revert-failed" && s.effect.class === "modify"),
    );
    const listed = active.filter((s) => s.effect.kind !== "agent-injected");
    const intrusive =
      active.some((s) => s.effect.class === "modify" || s.effect.class === "execute") || tainted.length > 0;
    const passive = active.some((s) => s.effect.class === "observe");
    return {
      level: intrusive ? "intrusive" : passive ? "passive" : "agent-only",
      active_effect_ids: sortedSet(listed.map((s) => s.effect.effect_id)).slice(0, MAX_IDS),
      tainted_by: sortedSet(tainted.map((s) => s.effect.effect_id)).slice(0, MAX_IDS),
    };
  }

  epoch(instance: PiId): number {
    return this.#epochs.get(instance) ?? 0;
  }

  originalBytes(
    instance: PiId,
    va: bigint,
    len: number,
  ): { readonly ranges: readonly { readonly va: bigint; readonly bytes: Uint8Array; readonly fx: FxId }[] } {
    const end = va + BigInt(len);
    const ranges: { va: bigint; bytes: Uint8Array; fx: FxId }[] = [];
    for (const state of this.active(instance)) {
      const memory = this.#memory.get(state.effect.effect_id);
      if (memory?.before === undefined || memory.va === null) continue;
      const start = memory.va;
      const stop = start + BigInt(memory.before.length);
      if (stop <= va || start >= end) continue;
      const from = start < va ? va : start;
      const to = stop > end ? end : stop;
      ranges.push({
        va: from,
        bytes: memory.before.subarray(Number(from - start), Number(to - start)),
        fx: state.effect.effect_id,
      });
    }
    return { ranges: ranges.sort((a, b) => (a.va < b.va ? -1 : a.va > b.va ? 1 : 0)) };
  }

  async endAll(
    instance: PiId,
    reason: "process-exited" | "detached" | "agent-unloaded" | "server-shutdown" | "session-close",
  ): Promise<void> {
    await Promise.all(
      this.active(instance).map(async (state) => {
        const result = await this.transition(state.effect.effect_id, "implicit-end", {
          reason,
          verification: null,
          residue: state.effect.kind === "agent-injected" ? [AGENT_RESIDUE] : [],
        });
        if (!result.ok)
          this.deps.logger.warn("effect end failed", { effect: state.effect.effect_id, code: result.error._tag });
      }),
    );
  }

  instances(): readonly PiId[] {
    return [...this.#byInstance.keys()];
  }

  /** Effects of `instance` active at any time in [fromSeq, toSeq], except `exclude` and the agent-injected effect. */
  concurrent(instance: PiId, fromSeq: number, toSeq: number, exclude: FxId | null): FxId[] {
    const out: FxId[] = [];
    for (const state of this.#states(instance)) {
      if (state.effect.effect_id === exclude || state.effect.kind === "agent-injected") continue;
      if (state.effect.applied_at.seq > toSeq) continue;
      const ended = state.transitions.findLast((t) => t.to !== "revert-failed");
      if (ended !== undefined && ended.at.seq < fromSeq) continue;
      if (state.status === "permanent") continue;
      out.push(state.effect.effect_id);
    }
    return sortedSet(out).slice(0, MAX_IDS);
  }
}
