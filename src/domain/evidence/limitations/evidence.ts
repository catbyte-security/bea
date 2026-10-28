/** Limitation sentences of area evidence (CI-I5). Owned by WP-EVID.
 *  Fixed BEA-authored text; template parameters are BEA-controlled only (numbers, hex, ids, enum codes). */
export const EVIDENCE_LIMITATIONS = {
  /** every bea.unknown.mutation record (S2 §14.2, REA rea-evidence §3.6) */
  UNKNOWN_MUTATION_INTENT: "Registry mutation evidence records analyst intent, not proof of the answer.",
  /** stream manifests whose agent drops were reported without a per-reason breakdown (WP-EVID accounting rule) */
  STREAM_DROPS_UNATTRIBUTED: (n: number) =>
    `${String(n)} of the dropped events were reported by the agent without a reason and are counted as agent_buffer_full.`,
} as const satisfies Readonly<Record<string, string | ((...args: never[]) => string)>>;
