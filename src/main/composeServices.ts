import type { BeaCore } from "../application/BeaApplication.js";
import { createAddressService } from "../application/address/createAddressService.js";
import { createOracleService } from "../application/call/createOracleService.js";
import { createDumpService } from "../application/dump/createDumpService.js";
import { createHandleRegistry } from "../application/handles/createHandleRegistry.js";
import { createRecordingRegistry } from "../application/instruments/createRecordingRegistry.js";
import type { BeaServices } from "../application/services/index.js";
import type { EmuPort } from "../ports/emu.js";
import { createEmulatorService } from "../providers/emulator/createEmulatorService.js";
import { createEvidenceRuntime } from "../providers/evidence/createEvidenceRuntime.js";
import { createSessionService } from "../providers/frida/createSessionService.js";
import { createPeServices } from "../providers/pe/createPeServices.js";
import { createJobHostFactory } from "../providers/process/createJobHostFactory.js";

/**
 * PRE-WIRED composition root (WP0; never edited later). Dependency order:
 * evidence → jobhost → pe → address(evidence, pe, emulator: late) → recordings(evidence, address)
 * → sessions(evidence, jobhost, recordings, address) → handles → oracle(evidence, address)
 * → dumps(evidence, address, pe) → emulator(evidence, sessions, pe, dumps). CI-B5: AddressService resolves emulation
 * spaces through a LATE-BOUND EmuPort getter (the emulator is composed after address); calling it during construction
 * throws. Integrator (implement stage, WP13 change request): dumps receive the PE services (file_sha256 /
 * preferred_base in bundles, foreign-patch restore from the on-disk image, D-INT-45).
 */
export const composeServices = async (core: BeaCore): Promise<BeaServices> => {
  let emulatorRef: EmuPort | undefined;
  const emulatorLate = (): EmuPort => {
    if (emulatorRef === undefined) throw new Error("emulator requested before composition finished");
    return emulatorRef;
  };
  const evidence = createEvidenceRuntime(core, {});
  const jobhost = createJobHostFactory(core, {});
  const pe = createPeServices(core);
  const address = createAddressService(core, { evidence, pe, emulator: emulatorLate });
  const recordings = createRecordingRegistry(core, { evidence, address });
  const sessions = createSessionService(core, { evidence, jobhost, recordings, address });
  const handles = createHandleRegistry();
  const oracle = createOracleService(core, { evidence, address });
  const dumps = createDumpService(core, { evidence, address, pe });
  const emulator = createEmulatorService(core, { evidence, sessions, pe, dumps });
  emulatorRef = emulator;
  return { evidence, jobhost, pe, address, recordings, sessions, handles, oracle, dumps, emulator };
};
