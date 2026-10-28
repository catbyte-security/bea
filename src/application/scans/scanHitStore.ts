import { mkdir, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

import type { TypedOut } from "../../shared/agentProtocol.js";

/**
 * WP10-SCAN host hit store (DESIGN §6.2 #15): `BEA_HOME/runs/<run>/scans/<scan_id>/hits.json`. The candidate arrays
 * live in the target (S4 §9.1); the host keeps the hits of the last iteration when they are few (≤ HOST_STORE_MAX_HITS,
 * which is how CE narrowing ends), so scan_results {values:false} still answers after the target exited. Released with
 * the scan (stop_instrumentation, onSessionEnded).
 */
export const HOST_STORE_MAX_HITS = 4096;

export interface StoredHit {
  readonly address: string;
  readonly stored: TypedOut;
}
interface StoredIteration {
  readonly iteration: number;
  readonly hits: readonly StoredHit[];
}

export interface HitStore {
  save(scanId: string, iteration: number, hits: readonly StoredHit[]): Promise<void>;
  get(scanId: string): StoredIteration | undefined;
  remove(scanId: string): Promise<void>;
}

/** `runDir` null (no evidence runtime) keeps the store in memory only. Disk failures never fail a scan. */
export const createHitStore = (runDir: () => string | null): HitStore => {
  const cache = new Map<string, StoredIteration>();
  const dirOf = (scanId: string): string | null => {
    const run = runDir();
    return run === null ? null : join(run, "scans", scanId);
  };
  return {
    save: async (scanId, iteration, hits) => {
      cache.set(scanId, { iteration, hits });
      const dir = dirOf(scanId);
      if (dir === null) return;
      try {
        await mkdir(dir, { recursive: true });
        const tmp = join(dir, `hits.${String(process.pid)}.tmp`);
        await writeFile(tmp, `${JSON.stringify({ scan_id: scanId, iteration, hits })}\n`, "utf8");
        await rename(tmp, join(dir, "hits.json"));
      } catch {
        // the in-memory copy still serves this run
      }
    },
    get: (scanId) => cache.get(scanId),
    remove: async (scanId) => {
      cache.delete(scanId);
      const dir = dirOf(scanId);
      if (dir !== null) await rm(dir, { recursive: true, force: true }).catch(() => undefined);
    },
  };
};
