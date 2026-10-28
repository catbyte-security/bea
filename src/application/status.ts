import type { z } from "zod";

import type { backendStatusSchema, sessionSummarySchema, storageStatusSchema } from "../contracts/schemas/status.js";
import type { Logger } from "../domain/logger.js";

export type BackendStatus = z.output<typeof backendStatusSchema>;
export type SessionSummary = z.output<typeof sessionSummarySchema>;
export type StorageStatus = z.output<typeof storageStatusSchema>;

/** Areas contribute to bea_status without editing its handler. */
export interface StatusContributor {
  readonly name: string;
  readonly backends?: () => Promise<readonly BackendStatus[]> | readonly BackendStatus[];
  readonly sessions?: () => readonly SessionSummary[];
  /** CI-M17: the evidence runtime only (first non-null wins) */
  readonly storage?: () => StorageStatus | null;
  /** CT-I11 and others: fixed BEA-authored sentences (≤ 300 chars each), never target-derived text */
  readonly notes?: () => readonly string[];
}

export class StatusRegistry {
  readonly #contributors: StatusContributor[] = [];

  constructor(private readonly logger: Logger) {}

  add(contributor: StatusContributor): void {
    this.#contributors.push(contributor);
  }

  /** A failing contributor degrades to a "failed" backend row; status itself never fails. */
  async collect(): Promise<{
    backends: BackendStatus[];
    sessions: SessionSummary[];
    storage: StorageStatus | null;
    notes: string[];
  }> {
    const backends: BackendStatus[] = [];
    const sessions: SessionSummary[] = [];
    let storage: StorageStatus | null = null;
    const notes: string[] = [];
    for (const contributor of this.#contributors) {
      try {
        if (contributor.backends !== undefined) backends.push(...(await contributor.backends()));
        if (contributor.sessions !== undefined) sessions.push(...contributor.sessions());
        if (contributor.storage !== undefined) storage ??= contributor.storage();
        if (contributor.notes !== undefined) notes.push(...contributor.notes().map((note) => note.slice(0, 300)));
      } catch (cause: unknown) {
        this.logger.warn("status contributor failed", {
          contributor: contributor.name,
          cause: cause instanceof Error ? cause : String(cause),
        });
      }
    }
    return { backends, sessions, storage, notes: notes.slice(0, 16) };
  }
}
