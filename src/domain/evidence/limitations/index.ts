import { ADDRESS_LIMITATIONS } from "./address.js";
import { BEHAVIOR_LIMITATIONS } from "./behavior.js";
import { CALL_LIMITATIONS } from "./call.js";
import { DUMP_LIMITATIONS } from "./dump.js";
import { EMULATION_LIMITATIONS } from "./emulation.js";
import { EVIDENCE_LIMITATIONS } from "./evidence.js";
import { INSPECT_LIMITATIONS } from "./inspect.js";
import { INSTRUMENT_LIMITATIONS } from "./instrument.js";
import { MODIFY_LIMITATIONS } from "./modify.js";
import { SCAN_LIMITATIONS } from "./scan.js";
import { SESSIONS_LIMITATIONS } from "./sessions.js";
import { WATCH_LIMITATIONS } from "./watch.js";

/**
 * PRE-WIRED (WP0; never edited later; CI-I5). Each area WP appends its fixed sentences to its own file
 * (e.g. WP-BEHAVIOR's six trace_api "always" limitations, WP-SESS's posix-best-effort and crash pc:null texts).
 * A unit test asserts that no key collides with another area or with the core set.
 */
export const AREA_LIMITATIONS = {
  ...SESSIONS_LIMITATIONS,
  ...INSPECT_LIMITATIONS,
  ...ADDRESS_LIMITATIONS,
  ...SCAN_LIMITATIONS,
  ...INSTRUMENT_LIMITATIONS,
  ...BEHAVIOR_LIMITATIONS,
  ...WATCH_LIMITATIONS,
  ...CALL_LIMITATIONS,
  ...MODIFY_LIMITATIONS,
  ...DUMP_LIMITATIONS,
  ...EMULATION_LIMITATIONS,
  ...EVIDENCE_LIMITATIONS,
} as const;
