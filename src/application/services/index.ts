import type { AddressService } from "../../ports/address.js";
import type { DumpCapturePort } from "../../ports/dumps.js";
import type { OracleCallPort, EmuPort } from "../../ports/emu.js";
import type { EvidenceRuntime } from "../../ports/evidence.js";
import type { HandleRegistry } from "../../ports/handles.js";
import type { JobHostFactory } from "../../ports/jobhost.js";
import type { FileHashCache, PeImageCache } from "../../ports/pe.js";
import type { RecordingRegistry } from "../../ports/recordings.js";
import type { DynamicSessionPort } from "../../ports/sessions.js";

/**
 * PRE-WIRED service slots (WP0). Every slot is a PORT from src/ports (frozen by WP0). Slots are produced by
 * src/main/composeServices.ts in dependency order; handlers reach them as app.services.<slot>.
 */
export interface BeaServices {
  /** WP-EVID: src/providers/evidence/createEvidenceRuntime.ts */
  readonly evidence: EvidenceRuntime;
  /** WP-PROC: src/providers/process/createJobHostFactory.ts */
  readonly jobhost: JobHostFactory;
  /** WP-ADDR: src/providers/pe/createPeServices.ts */
  readonly pe: { readonly images: PeImageCache; readonly hashes: FileHashCache };
  /** WP-ADDR: src/application/address/createAddressService.ts */
  readonly address: AddressService;
  /** WP-EVID: src/application/instruments/createRecordingRegistry.ts */
  readonly recordings: RecordingRegistry;
  /** WP-SESS: src/providers/frida/createSessionService.ts (FridaHost + SessionManager + agent channel) */
  readonly sessions: DynamicSessionPort;
  /** WP0 (complete): src/application/handles/createHandleRegistry.ts; kinds registered by WP-SCAN and WP-MODIFY */
  readonly handles: HandleRegistry;
  /** WP-CALL: src/application/call/createOracleService.ts */
  readonly oracle: OracleCallPort;
  /** WP-DUMP: src/application/dump/createDumpService.ts */
  readonly dumps: DumpCapturePort;
  /** WP-EMU: src/providers/emulator/createEmulatorService.ts */
  readonly emulator: EmuPort;
}
