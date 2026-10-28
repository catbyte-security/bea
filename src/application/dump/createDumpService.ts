import type { BeaError } from "../../domain/errors/beaError.js";
import { PRODUCT_IDENTITY } from "../../identity.js";
import type { Result } from "../../domain/result.js";
import type { AddressService } from "../../ports/address.js";
import type { BundleCaptureRequest, DumpCapturePort } from "../../ports/dumps.js";
import type { EvidenceRuntime } from "../../ports/evidence.js";
import type { FileHashCache, PeImageCache } from "../../ports/pe.js";
import type { LiveSession, OperationContext } from "../../ports/sessions.js";
import type { BeaCore } from "../BeaApplication.js";
import { captureDumpBundle, type DetailedBundleCapture, type DumpBundleRequest } from "./captureBundle.js";
import { outputPolicy } from "./outputFiles.js";

/**
 * DumpCapturePort (CI-B3; WP-DUMP): bea.dump/1 capture shared by dump_memory {format:"bundle"} and WP-EMU's
 * emu_open {live_session_id}. Construction is synchronous and cheap: no target contact, no filesystem writes.
 *
 * `pe` is optional because the frozen composition root (src/main/composeServices.ts) passes only evidence and
 * address today; WP-DUMP's change request adds `pe` there. Without it bundles carry file_sha256/preferred_base null
 * and foreign patches stay live (limitation DUMP_FILE_IMAGE_UNAVAILABLE); BEA's own patches are still restored.
 * The returned result is a DetailedBundleCapture (a BundleCaptureResult plus `detail`), which dump_memory uses for its
 * envelope; port consumers see the port shape. A request may carry `liveBytes` (dump_memory's live_bytes).
 */
export interface DumpService extends DumpCapturePort {
  captureBundle(
    session: LiveSession,
    req: BundleCaptureRequest,
    op: OperationContext,
  ): Promise<Result<DetailedBundleCapture, BeaError>>;
}

const MiB = 1024 * 1024;

export const createDumpService = (
  core: BeaCore,
  deps: {
    readonly evidence: EvidenceRuntime;
    readonly address: AddressService;
    readonly pe?: { readonly images: PeImageCache; readonly hashes: FileHashCache };
  },
): DumpService => {
  const policy = outputPolicy(core.config, core.run.runId, process.env);
  return {
    captureBundle: (session, req: DumpBundleRequest, op) =>
      captureDumpBundle(
        {
          evidence: deps.evidence,
          address: deps.address,
          pe: deps.pe ?? null,
          policy,
          version: PRODUCT_IDENTITY.packageVersion,
          maxTotalBytes: core.config.emu.dumpMaxMb.value * MiB,
          now: () => core.clock.monoMs(),
          wallIso: () => core.clock.wallIso(),
        },
        session,
        req,
        op,
      ),
  };
};
