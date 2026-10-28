import type { Clock } from "../../domain/clock.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import type { PiId, RunId } from "../../domain/ids.js";
import type { JsonObject } from "../../domain/json.js";
import type { Logger } from "../../domain/logger.js";
import type { Result } from "../../domain/result.js";
import type { BundleService } from "../../ports/evidence.js";
import type { FileBlobStore } from "./BlobStore.js";
import { exportBundle } from "./BundleExport.js";
import { importBundle } from "./BundleImport.js";
import type { Ledger } from "./Ledger.js";
import type { LedgerIndex } from "./LedgerIndex.js";
import type { QuotaGuard } from "./Quotas.js";
import type { FileStreamStore } from "./StreamStore.js";

/**
 * Bundles (S2 §13): directory or zip. Export inputs arrive already policy-checked by the handler (`out_path` passed
 * checkOutputPath and is absolute); import validates everything before merging. Exports are not Evidence.
 */
export interface BundleDeps {
  readonly runId: RunId;
  readonly beaVersion: string;
  readonly clock: Clock;
  readonly logger: Logger;
  readonly tmpDir: string;
  readonly index: LedgerIndex;
  readonly ledger: Ledger;
  readonly blobs: FileBlobStore;
  readonly streams: FileStreamStore;
  readonly quotas: QuotaGuard;
  readonly ensureStarted: () => Promise<Result<void, BeaError>>;
}

const text = (input: JsonObject, key: string): string | undefined =>
  typeof input[key] === "string" ? (input[key] as string) : undefined;

export class LedgerBundleService implements BundleService {
  constructor(private readonly deps: BundleDeps) {}

  /** input: {out_path, instance_id?, format?, streams?, blobs?, create_parent?} */
  export(input: JsonObject, signal?: AbortSignal): Promise<Result<JsonObject, BeaError>> {
    return exportBundle(
      this.deps,
      {
        out_path: text(input, "out_path") ?? "",
        instance_id: (text(input, "instance_id") as PiId | undefined) ?? null,
        format: input["format"] === "zip" ? "zip" : "directory",
        streams: input["streams"] === "all" ? "all" : "manifests",
        blobs: input["blobs"] !== false,
        create_parent: input["create_parent"] === true,
      },
      signal,
    );
  }

  /** input: {path, validate_only?} */
  import(input: JsonObject, signal?: AbortSignal): Promise<Result<JsonObject, BeaError>> {
    return importBundle(
      this.deps,
      { path: text(input, "path") ?? "", validate_only: input["validate_only"] === true },
      signal,
    );
  }
}
