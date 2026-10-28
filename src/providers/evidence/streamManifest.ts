import { DROP_REASON_CODES, REASONS, type Coverage } from "../../domain/evidence/coverage.js";
import { LIMITATIONS } from "../../domain/evidence/limitations.js";
import type { StreamEndReason } from "../../ports/evidence.js";

/**
 * Manifest coverage (S2 §10.6 table) and drop-reason accounting. Agent drops arrive twice: as `dropped_before` in
 * frame headers (totals) and, optionally, as per-reason `noteDropped` calls; the manifest counts
 * max(header total, attributed) so neither reporting style double-counts, and reports any unattributed remainder as
 * `agent_buffer_full` with a limitation saying so. Host drops (seq gaps, queue, quota) always add.
 */
export interface ManifestFacts {
  readonly state: "live" | "ended";
  readonly endReason: StreamEndReason | null;
  readonly tailConfirmed: boolean;
  readonly dropped: number;
  readonly redacted: number;
  readonly dropReasons: Readonly<Record<string, number>>;
  readonly unattributed: number;
  readonly quotaMib: { readonly kind: string; readonly mib: number } | null;
  readonly checkpointSeq: number;
}

const AGENT_CODES: ReadonlySet<string> = new Set(Object.values(DROP_REASON_CODES));

const ALIASES: Readonly<Record<string, string>> = {
  "seq-gap": "seq_gap",
  "host-queue-full": "host_queue_full",
  "agent-buffer": "agent_buffer_full",
  quota: "stream_quota",
  malformed: "decode_error",
  unbound: "seq_gap",
};

/** Map a reported reason to a registered coverage reason code; agent codes are attribution, not extra drops. */
export const normalizeDropReason = (reason: string): { readonly code: string; readonly agent: boolean } => {
  const fromAgent = (DROP_REASON_CODES as Readonly<Record<string, string>>)[reason];
  const code = fromAgent ?? ALIASES[reason] ?? (Object.hasOwn(REASONS, reason) ? reason : reason.replaceAll("-", "_"));
  const registered = Object.hasOwn(REASONS, code) ? code : "decode_error";
  return { code: registered, agent: AGENT_CODES.has(registered) && registered !== "seq_gap" };
};

const NORMAL_ENDS: ReadonlySet<StreamEndReason> = new Set(["stopped", "expired"]);

export const manifestCoverage = (
  f: ManifestFacts,
): { readonly coverage: Coverage; readonly limitations: readonly string[] } => {
  const reasons = new Set<string>(Object.keys(f.dropReasons).filter((r) => (f.dropReasons[r] ?? 0) > 0));
  if (f.redacted > 0) reasons.add("explicit_sensitive_value");
  const lossy = f.dropped + f.redacted > 0;
  let normal: boolean;
  if (f.state === "live") normal = f.tailConfirmed;
  else if (f.endReason !== null && NORMAL_ENDS.has(f.endReason)) normal = true;
  else normal = f.tailConfirmed && f.endReason !== "quota" && f.endReason !== "agent-error";
  if (f.endReason === "quota") reasons.add(f.quotaMib?.kind === "all-streams" ? "stream_total_quota" : "stream_quota");
  if (!normal && !f.tailConfirmed && f.endReason !== "quota") reasons.add("tail_unconfirmed");
  const unknown = reasons.has("seq_gap") || (f.endReason === "agent-error" && !f.tailConfirmed);
  const status: Coverage["status"] = unknown ? "unknown" : lossy || !normal ? "partial" : "complete";
  const sorted = [...reasons].sort();
  const coverage: Coverage =
    status === "complete"
      ? { status, truncated: false, reasons: [] }
      : {
          status,
          truncated: lossy,
          ...(f.dropped > 0 ? { dropped: f.dropped } : {}),
          reasons: sorted.length > 0 ? sorted : ["unknown_completeness"],
        };
  const limitations: string[] = [LIMITATIONS.NOT_OBSERVED_WINDOW];
  if (f.dropped > 0) limitations.push(LIMITATIONS.STREAM_DROPPED(f.dropped));
  if (f.redacted > 0) limitations.push(LIMITATIONS.REDACTED(f.redacted));
  if (f.unattributed > 0) limitations.push(LIMITATIONS.STREAM_DROPS_UNATTRIBUTED(f.unattributed));
  if (f.quotaMib !== null) limitations.push(LIMITATIONS.QUOTA(f.quotaMib.kind, f.quotaMib.mib));
  if (f.state === "live") limitations.push(LIMITATIONS.RECORDING_ACTIVE);
  return { coverage, limitations };
};
