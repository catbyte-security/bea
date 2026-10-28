import type { BeaCore } from "../../../src/application/BeaApplication.js";
import { createHandleRegistry } from "../../../src/application/handles/createHandleRegistry.js";
import { notImplementedPort } from "../../../src/application/notImplemented.js";
import type { BeaServices } from "../../../src/application/services/index.js";

/**
 * WP0 test double: every service slot answers capability_unavailable(not-implemented). Area test suites override
 * only the slots they exercise: fakeServices({ sessions: myFakeSessions }).
 */
export const fakeServices =
  (overrides: Partial<BeaServices> = {}) =>
  async (core: BeaCore): Promise<BeaServices> => {
    void core;
    return {
      evidence: notImplementedPort("evidence"),
      jobhost: notImplementedPort("jobhost"),
      pe: { images: notImplementedPort("pe.images"), hashes: notImplementedPort("pe.hashes") },
      address: notImplementedPort("address"),
      recordings: notImplementedPort("recordings"),
      sessions: notImplementedPort("sessions"),
      handles: createHandleRegistry(),
      oracle: notImplementedPort("oracle"),
      dumps: notImplementedPort("dumps"),
      emulator: notImplementedPort("emulator"),
      ...overrides,
    };
  };
