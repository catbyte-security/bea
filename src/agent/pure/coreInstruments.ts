// =================================================================================================
// src/agent/pure/coreInstruments.ts — WP3-AGENT pure helpers for the instrument registry (S4 §5.7, CI-I3): instrument
// id prefixes, lifetime normalization (agent defaults only when a field is 0; clamps to the effective limits), and
// the hit/max_hits state machine every listener uses (the hit that reaches max_hits is recorded and schedules the
// stop; later callbacks are not recorded).
// =================================================================================================
import type { AgentLimits, InstrumentInfo, Lifetime } from "../../shared/agentProtocol.js";

export type InstrumentKind = InstrumentInfo["kind"];

export const INSTRUMENT_PREFIX: Readonly<Record<InstrumentKind, string>> = {
  hook: "h",
  profile: "p",
  watch: "w",
  trace: "t",
  override: "o",
};

export const DEFAULT_DURATION_MS = 30_000;
/** Agent defaults for max_hits when the host sends 0 (S4 §5.7). */
export const DEFAULT_MAX_HITS: Readonly<Record<InstrumentKind, number>> = {
  hook: 10_000,
  profile: 10_000,
  watch: 1_000,
  trace: 10_000,
  override: 10_000,
};

export interface NormalizedLifetime {
  readonly durationMs: number;
  readonly maxHits: number;
  readonly clock: "install" | "resume";
}

const positiveInt = (v: unknown): number | null =>
  typeof v === "number" && Number.isFinite(v) && v > 0 ? Math.floor(v) : null;

export const normalizeLifetime = (
  kind: InstrumentKind,
  lifetime: Partial<Lifetime> | undefined,
  limits: Pick<AgentLimits, "max_duration_ms" | "max_hits_cap">,
): NormalizedLifetime => {
  const duration = positiveInt(lifetime?.duration_ms) ?? DEFAULT_DURATION_MS;
  const hits = positiveInt(lifetime?.max_hits) ?? DEFAULT_MAX_HITS[kind];
  return {
    durationMs: Math.min(duration, limits.max_duration_ms),
    maxHits: Math.min(hits, limits.max_hits_cap),
    clock: lifetime?.clock === "resume" ? "resume" : "install",
  };
};

export type HitOutcome = "record" | "record-and-stop" | "ignore";

/**
 * One hit against max_hits. `hitsBefore` is the counter before this hit; `active` is false once the instrument left
 * the active state (detached guard).
 */
export const hitOutcome = (active: boolean, hitsBefore: number, maxHits: number): HitOutcome => {
  if (!active) return "ignore";
  const n = hitsBefore + 1;
  if (n < maxHits) return "record";
  return n === maxHits ? "record-and-stop" : "ignore";
};

/** Reverse creation order (shutdown stops the newest instrument first, S4 §18). */
export const reverseCreationOrder = <T extends { readonly seq: number }>(items: readonly T[]): T[] =>
  [...items].sort((a, b) => b.seq - a.seq);
