import type { BeaError } from "../domain/errors/beaError.js";
import type { EvId } from "../domain/ids.js";
import type { Result } from "../domain/result.js";
import type { LiveSession, OperationContext } from "./sessions.js";

/**
 * CI-B3: bea.dump/1 capture shared by dump_memory {format:"bundle"} (WP-DUMP implements) and
 * emu_open {live_session_id} (WP-EMU consumes). Implemented over LiveSession.jobs (dumpStart blobs) and
 * captureThreadState; records bea.dump.capture.
 */
export interface BundleCaptureRequest {
  /** module tokens of the AddrExpr grammar; default ["$main"] */
  readonly modules: readonly string[];
  /** AddrExpr + size (≤ 256 MiB each) */
  readonly regions: readonly { readonly address: string; readonly size: number }[];
  readonly threadId?: number;
  readonly mode: "running" | "suspended";
  /** absolute directory that must not exist; default <run dir>/exports/<bundle_id> */
  readonly outDir?: string;
}

export interface BundleCaptureResult {
  readonly bundlePath: string;
  readonly bundleId: `dump_${string}`;
  /** the bea.dump.capture evidence */
  readonly evidenceId: EvId;
  readonly regions: number;
  readonly modules: number;
  readonly threads: number;
  readonly limitations: readonly string[];
}

export interface DumpCapturePort {
  captureBundle(
    session: LiveSession,
    req: BundleCaptureRequest,
    op: OperationContext,
  ): Promise<Result<BundleCaptureResult, BeaError>>;
}
