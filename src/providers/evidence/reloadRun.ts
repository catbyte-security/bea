import { readFile } from "node:fs/promises";
import { join } from "node:path";

import type { BeaConfig } from "../../domain/config.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { evidenceIntegrity } from "../../domain/evidence/authenticate.js";
import type { RunId } from "../../domain/ids.js";
import { sha256Hex } from "../../domain/canonical.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { InstanceRegistry } from "../../ports/evidence.js";
import { FileBlobStore } from "./BlobStore.js";
import { fileError } from "./errors.js";
import { LedgerEvidenceQuery } from "./EvidenceQuery.js";
import { Ledger } from "./Ledger.js";
import { LedgerIndex, LOCAL, type LineRef, type Origin } from "./LedgerIndex.js";
import { decodeLine, type LedgerLine } from "./LedgerLines.js";
import { QuotaGuard, quotaLimitsOf } from "./Quotas.js";
import { runHeaderSchema, runPaths, type RunHeader } from "./RunStore.js";

/**
 * Reload a persisted ledger (S2 §9.2–9.4) read-only: every line is authenticated; a torn final line (no newline,
 * e.g. after a power loss) is reported as `torn_bytes` and ignored, never repaired; lines inside an import bracket
 * without its import-commit are ignored. Used by `bea evidence show --run ID` (WP-CLI) and the reload tests.
 */
export interface ReloadedLedger {
  readonly index: LedgerIndex;
  readonly lines: number;
  readonly tornBytes: number;
  readonly ignoredUncommitted: number;
  readonly bytes: number;
}

export const indexLine = (index: LedgerIndex, line: LedgerLine, ref: LineRef, origin: Origin): void => {
  switch (line.t) {
    case "pi":
      index.addInstance({
        instance_id: line.instance_id,
        identity: line.identity,
        ownership: line.ownership,
        image_name: line.display.image_name,
        ref,
        origin,
      });
      break;
    case "mm":
      index.addModuleMap({ module_map: line.module_map, ref, origin });
      break;
    case "fx":
      index.addEffect(line.effect, ref, origin);
      break;
    case "fxt":
      index.addTransition(line.transition, ref, origin);
      break;
    case "unk":
      index.addUnknown(line.revision, ref, origin);
      break;
    case "ev":
      index.addEvidence(line.record, ref, origin);
      for (const blob of line.record.blobs) index.blobs.set(blob.sha256, blob.bytes);
      break;
    default:
      break;
  }
};

export const reloadLedger = async (
  path: string,
  operation = "evidence.reload",
): Promise<Result<ReloadedLedger, BeaError>> => {
  let buffer: Buffer;
  try {
    buffer = await readFile(path);
  } catch (cause) {
    return err(fileError(operation, "read", path, cause));
  }
  const index = new LedgerIndex();
  let offset = 0;
  let count = 0;
  let ignored = 0;
  let bracket: {
    readonly id: string;
    readonly origin: Origin;
    readonly pending: { line: LedgerLine; ref: LineRef }[];
  } | null = null;
  while (offset < buffer.length) {
    const newline = buffer.indexOf(10, offset);
    if (newline === -1) break; // torn tail
    const text = buffer.toString("utf8", offset, newline);
    const ref: LineRef = { offset, length: newline - offset, sha256: sha256Hex(buffer.subarray(offset, newline)) };
    const decoded = decodeLine(text, operation);
    if (!decoded.ok) return err(evidenceIntegrity(operation, decoded.error.reason, { line: count + 1 }));
    const line = decoded.value;
    count += 1;
    if (line.t === "import-begin") {
      if (bracket !== null) ignored += bracket.pending.length;
      bracket = { id: line.import_id, origin: { kind: "import", bundle_digest: line.bundle_digest }, pending: [] };
    } else if (line.t === "import-commit") {
      if (bracket !== null && bracket.id === line.import_id)
        for (const item of bracket.pending) indexLine(index, item.line, item.ref, bracket.origin);
      bracket = null;
    } else if (bracket !== null) bracket.pending.push({ line, ref });
    else indexLine(index, line, ref, LOCAL);
    offset = newline + 1;
  }
  if (bracket !== null) ignored += bracket.pending.length;
  return ok({ index, lines: count, tornBytes: buffer.length - offset, ignoredUncommitted: ignored, bytes: offset });
};

export interface PersistedRun {
  readonly header: RunHeader | null;
  readonly ledger: ReloadedLedger;
  readonly query: LedgerEvidenceQuery;
  readonly close: () => Promise<void>;
}

const NO_INSTANCES: InstanceRegistry = {
  register: async () =>
    err({ _tag: "InvalidState", operation: "evidence.reload", state: "read-only", expected: ["live run"] }),
  get: () => undefined,
  capture: () => {
    throw new Error("a persisted run has no live instances");
  },
  update: async () =>
    err({ _tag: "InvalidState", operation: "evidence.reload", state: "read-only", expected: ["live run"] }),
  hashImage: async () =>
    err({ _tag: "InvalidState", operation: "evidence.reload", state: "read-only", expected: ["live run"] }),
};

/** Open another run's ledger read-only (crashed runs too); `query` answers get_evidence reads over it. */
export const openPersistedRun = async (config: BeaConfig, runId: RunId): Promise<Result<PersistedRun, BeaError>> => {
  const paths = runPaths(join(config.layout.runsDir, runId));
  let header: RunHeader | null = null;
  try {
    const parsed = runHeaderSchema.safeParse(JSON.parse(await readFile(paths.header, "utf8")));
    header = parsed.success ? parsed.data : null;
  } catch {
    header = null;
  }
  const reloaded = await reloadLedger(paths.ledger);
  if (!reloaded.ok) return reloaded;
  const quotas = new QuotaGuard(quotaLimitsOf(config));
  quotas.adoptLedger(reloaded.value.bytes);
  const ledger = new Ledger(paths.ledger, quotas, { prepare: async () => undefined, initial: () => [] });
  ledger.fence();
  const blobs = new FileBlobStore({ blobs: paths.blobs, tmp: paths.tmp }, reloaded.value.index, quotas, async () =>
    err({ _tag: "InvalidState", operation: "evidence.reload", state: "read-only", expected: ["live run"] }),
  );
  const query = new LedgerEvidenceQuery({ index: reloaded.value.index, ledger, blobs, instances: NO_INSTANCES });
  return ok({ header, ledger: reloaded.value, query, close: () => ledger.close() });
};
