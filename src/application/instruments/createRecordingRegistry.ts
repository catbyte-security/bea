import type { BeaCore } from "../BeaApplication.js";
import type { RecordingRegistry } from "../../ports/recordings.js";
import type { EvidenceRuntime } from "../../ports/evidence.js";
import type { AddressService } from "../../ports/address.js";
import { RECORDING_KINDS } from "./kinds/index.js";
import { LedgerRecordingRegistry } from "./RecordingRegistry.js";

/**
 * WP-EVID factory. Synchronous-cheap construction: no target contact, no files, no processes. Frames in decoded
 * events keep the agent's compact "module+0xrva" text; their `static` form comes from the preferred bases `address`
 * has prepared (review fix UX-10: cache only, no I/O while decoding).
 */
export const createRecordingRegistry = (
  core: BeaCore,
  deps: { readonly evidence: EvidenceRuntime; readonly address: AddressService },
): RecordingRegistry => {
  return new LedgerRecordingRegistry({
    evidence: deps.evidence,
    ids: core.ids,
    clock: core.clock,
    logger: core.logger.child({ component: "recordings" }),
    kinds: RECORDING_KINDS,
    staticBase: (path) => deps.address.preferredBaseOf?.(path) ?? null,
  });
};
