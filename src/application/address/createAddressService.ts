import type { BeaCore } from "../BeaApplication.js";
import type { AddressService } from "../../ports/address.js";
import type { EmuPort } from "../../ports/emu.js";
import type { BeaServices } from "../services/index.js";
import type { EvidenceRuntime } from "../../ports/evidence.js";
import { AddressServiceImpl } from "./AddressService.js";

/**
 * WP-ADDR composition (DESIGN §5.5). Synchronous-cheap construction: no target contact, no frida import, no helper
 * spawn, no file access (all lazy). CI-B5: `emulator` is a late-bound getter, called per request and never here;
 * emulation spaces resolve against EmuPort.lookup + EmuPort.modules. The service owns no process or file handle,
 * so it registers no lifecycle closer; caller symbol tables and PE caches are plain memory released with the app.
 */
export const createAddressService = (
  core: BeaCore,
  deps: { readonly evidence: EvidenceRuntime; readonly pe: BeaServices["pe"]; readonly emulator: () => EmuPort },
): AddressService =>
  new AddressServiceImpl({
    evidence: deps.evidence,
    pe: deps.pe,
    emulator: deps.emulator,
    platform: core.config.platform,
  });
