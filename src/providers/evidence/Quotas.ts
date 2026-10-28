import type { BeaConfig } from "../../domain/config.js";

const MiB = 1024 * 1024;

export interface QuotaLimits {
  readonly ledgerBytes: number;
  readonly ledgerReserveBytes: number;
  readonly streamBytes: number;
  readonly streamTotalBytes: number;
  readonly blobBytes: number;
}

export const quotaLimitsOf = (config: BeaConfig): QuotaLimits => ({
  ledgerBytes: config.quotas.ledgerMb.value * MiB,
  ledgerReserveBytes: config.quotas.ledgerReserveMb.value * MiB,
  streamBytes: config.quotas.streamMb.value * MiB,
  streamTotalBytes: config.quotas.streamTotalMb.value * MiB,
  blobBytes: config.quotas.blobMb.value * MiB,
});

export const mibOf = (bytes: number): number => Math.round(bytes / MiB);

/**
 * Per-run quota accounting (S2 §9.7). Usage counters are reserved synchronously by the caller before the I/O, so
 * concurrent producers cannot overshoot; a failed write releases its reservation. Hitting a quota is never silent:
 * callers turn a refusal into resource_constraint (ledger, blobs) or a counted stream drop + onQuota (streams).
 */
export class QuotaGuard {
  #ledger = 0;
  #blobs = 0;
  #streams = 0;

  constructor(readonly limits: QuotaLimits) {}

  get usage(): { readonly ledger: number; readonly blobs: number; readonly streams: number } {
    return { ledger: this.#ledger, blobs: this.#blobs, streams: this.#streams };
  }

  /** Non-lifecycle lines stop at quota − reserve; lifecycle lines (fxt, close, exit, final manifests) may use it. */
  reserveLedger(bytes: number, lifecycle: boolean): boolean {
    const ceiling = lifecycle ? this.limits.ledgerBytes : this.limits.ledgerBytes - this.limits.ledgerReserveBytes;
    if (this.#ledger + bytes > ceiling) return false;
    this.#ledger += bytes;
    return true;
  }

  /** Existing bytes of a reopened ledger (persisted runs). */
  adoptLedger(bytes: number): void {
    this.#ledger = bytes;
  }

  releaseLedger(bytes: number): void {
    this.#ledger = Math.max(0, this.#ledger - bytes);
  }

  reserveBlob(bytes: number): boolean {
    if (this.#blobs + bytes > this.limits.blobBytes) return false;
    this.#blobs += bytes;
    return true;
  }

  releaseBlob(bytes: number): void {
    this.#blobs = Math.max(0, this.#blobs - bytes);
  }

  /** per-stream usage is the writer's own counter; this checks both the per-stream and the run-wide ceiling */
  reserveStream(streamUsed: number, bytes: number): "ok" | "stream" | "streams" {
    if (streamUsed + bytes > this.limits.streamBytes) return "stream";
    if (this.#streams + bytes > this.limits.streamTotalBytes) return "streams";
    this.#streams += bytes;
    return "ok";
  }

  /**
   * Review fix DATA-5: imported stream chunks count against the run-wide stream total only (the per-stream cap guards
   * live writers); false (nothing reserved) when they do not fit.
   */
  reserveImportedStreams(bytes: number): boolean {
    if (this.#streams + bytes > this.limits.streamTotalBytes) return false;
    this.#streams += bytes;
    return true;
  }

  releaseStream(bytes: number): void {
    this.#streams = Math.max(0, this.#streams - bytes);
  }

  remaining(): { readonly ledger: number; readonly blobs: number; readonly streams: number } {
    return {
      ledger: this.limits.ledgerBytes - this.limits.ledgerReserveBytes - this.#ledger,
      blobs: this.limits.blobBytes - this.#blobs,
      streams: this.limits.streamTotalBytes - this.#streams,
    };
  }
}
