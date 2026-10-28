import type { BeaCore } from "../BeaApplication.js";
import type { OracleCallPort } from "../../ports/emu.js";
import type { EvidenceRuntime } from "../../ports/evidence.js";
import type { AddressService } from "../../ports/address.js";
import { createOracleCallPort } from "./OracleService.js";

/**
 * OracleCallPort factory (WP11-CALL; S5 §9.4): the diff_function live leg's entry into the exact-bits SEH-frame thunk.
 * Synchronous-cheap construction: no target contact, no frida import, no helper spawn; the service keeps no
 * per-session state (agent quarantine and expiry tokens live in the agent, DESIGN §5.3.1 rule 5), so it registers no
 * lifecycle closer and no status contributor.
 */
export const createOracleService = (
  core: BeaCore,
  deps: { readonly evidence: EvidenceRuntime; readonly address: AddressService },
): OracleCallPort => createOracleCallPort(core, deps);
