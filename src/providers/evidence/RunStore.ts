import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, readdir, readFile, rm, stat } from "node:fs/promises";
import { join } from "node:path";

import {
  runHeaderSchema,
  type RunFinal,
  type RunHeader,
  type RunKind,
} from "../../application/evidence/storeSchemas.js";
import { canonicalJson } from "../../domain/canonical.js";
import { runIdSchema, type RunId } from "../../domain/ids.js";
import type { JsonValue } from "../../domain/json.js";
import { pidAlive, writeFileAtomic, writeFileExclusive } from "./fsio.js";
import type { QuotaLimits } from "./Quotas.js";

/** Run lifecycle (S2 §9.2). One run = one server process or one CLI command; one writer per run. */
export {
  runHeaderSchema,
  type RunFinal,
  type RunHeader,
  type RunKind,
} from "../../application/evidence/storeSchemas.js";

export interface RunPaths {
  readonly dir: string;
  readonly header: string;
  readonly lock: string;
  readonly ledger: string;
  readonly blobs: string;
  readonly streams: string;
  readonly tmp: string;
  readonly exports: string;
}

export const runPaths = (dir: string): RunPaths => ({
  dir,
  header: join(dir, "run.json"),
  lock: join(dir, ".lock"),
  ledger: join(dir, "ledger.jsonl"),
  blobs: join(dir, "blobs"),
  streams: join(dir, "streams"),
  tmp: join(dir, "tmp"),
  exports: join(dir, "exports"),
});

/** Hash the ledger at finalize only when it fits the shutdown budget (~64 MiB at ≥ 1 GB/s). */
const HASH_LEDGER_MAX_BYTES = 64 * 1024 * 1024;

export const sha256File = async (path: string): Promise<string> => {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
  return hash.digest("hex");
};

const headerText = (header: RunHeader): string => `${canonicalJson(header as unknown as JsonValue)}\n`;

export interface RunStoreOptions {
  readonly runId: RunId;
  readonly runsDir: string;
  readonly kind: RunKind;
  readonly beaVersion: string;
  readonly platform: "win32" | "linux" | "darwin";
  readonly startedWall: string;
  readonly quotas: QuotaLimits;
}

export class RunStore {
  readonly paths: RunPaths;
  #header: RunHeader;
  #siblingScan: Promise<void> | undefined;

  constructor(private readonly options: RunStoreOptions) {
    this.paths = runPaths(join(options.runsDir, options.runId));
    this.#header = {
      schema: "bea.run/1",
      run_id: options.runId,
      kind: options.kind,
      bea_version: options.beaVersion,
      node: process.version,
      platform: options.platform,
      pid: process.pid,
      started_wall: options.startedWall,
      ended_wall: null,
      status: "open",
      quotas: {
        ledger_bytes: options.quotas.ledgerBytes,
        ledger_reserve_bytes: options.quotas.ledgerReserveBytes,
        stream_bytes: options.quotas.streamBytes,
        stream_total_bytes: options.quotas.streamTotalBytes,
        blob_bytes: options.quotas.blobBytes,
      },
      final: null,
    };
  }

  get header(): RunHeader {
    return this.#header;
  }

  /** Directories, `.lock` ('wx'), run.json (open). The caller appends the {t:"run"} line. */
  async create(): Promise<void> {
    const p = this.paths;
    await mkdir(p.dir, { recursive: true });
    await Promise.all([p.blobs, p.streams, p.tmp].map((dir) => mkdir(dir, { recursive: true })));
    await writeFileExclusive(
      p.lock,
      `${JSON.stringify({ pid: process.pid, started_wall: this.options.startedWall })}\n`,
    );
    await writeFileAtomic(p.header, headerText(this.#header));
    this.#siblingScan = markCrashedRuns(this.options.runsDir, this.options.runId).then(
      () => undefined,
      () => undefined,
    );
  }

  /** run.json closed + final, lock removed (S2 §9.2 finalize steps 5–6). */
  async close(final: Omit<RunFinal, "ledger_sha256">, endedWall: string): Promise<void> {
    let ledgerSha: string | null = null;
    try {
      const size = (await stat(this.paths.ledger)).size;
      if (size <= HASH_LEDGER_MAX_BYTES) ledgerSha = await sha256File(this.paths.ledger);
    } catch {
      ledgerSha = null;
    }
    this.#header = {
      ...this.#header,
      status: "closed",
      ended_wall: endedWall,
      final: { ...final, ledger_sha256: ledgerSha },
    };
    await writeFileAtomic(this.paths.header, headerText(this.#header), true);
    await rm(this.paths.lock, { force: true });
    await this.#siblingScan;
  }

  /** Awaited by close paths so the background sibling scan never outlives the runtime. */
  async settle(): Promise<void> {
    await this.#siblingScan;
  }
}

/** S2 §9.2: any sibling `open` run whose lock pid is dead becomes `crashed` (run.json only; nothing else changes). */
export const markCrashedRuns = async (runsDir: string, ownRunId: string): Promise<number> => {
  let marked = 0;
  let entries: string[];
  try {
    entries = await readdir(runsDir);
  } catch {
    return 0;
  }
  for (const name of entries) {
    if (name === ownRunId || !runIdSchema.safeParse(name).success) continue;
    const paths = runPaths(join(runsDir, name));
    try {
      const header = runHeaderSchema.safeParse(JSON.parse(await readFile(paths.header, "utf8")));
      if (!header.success || header.data.status !== "open") continue;
      let pid = 0;
      try {
        const lock = JSON.parse(await readFile(paths.lock, "utf8")) as { pid?: unknown };
        pid = typeof lock.pid === "number" ? lock.pid : 0;
      } catch {
        pid = 0;
      }
      if (pidAlive(pid)) continue;
      await writeFileAtomic(paths.header, headerText({ ...header.data, status: "crashed" }));
      marked += 1;
    } catch {
      // unreadable sibling: leave it alone
    }
  }
  return marked;
};
