/** Limitation sentences of area modify (CI-I5). ONLY WP-MODIFY edits this file.
 *  Fixed BEA-authored text; template parameters are BEA-controlled only (numbers, hex, ids, enum codes). */
export const MODIFY_LIMITATIONS = {
  WRITE_UNVERIFIED:
    "The read-back after the write did not equal the intended bytes; another writer may have changed the memory in between.",
  WRITE_PROTECTION_RESTORED:
    "The page was made writable for the write and its original protection was restored afterwards; a protection-changed effect records that window.",
  WRITE_CODE_PATCH:
    "The bytes were written into executable code with a code-safe patch; a thread executing the range during the write may have run a mix of old and new instructions.",
  OVERRIDE_ACTIVE:
    "The function's behavior is overridden while this recording is active; observations of this process in that window reflect the override, not the original code.",
  OVERRIDE_NOT_RECORDED:
    "record was false: individual applications of the override are not logged; only the installation is recorded.",
  SCRIPT_RAN:
    "Caller-written JavaScript ran inside the target; its side effects are unknown to BEA and may affect later observations of this process.",
  SCRIPT_INTERFERENCE:
    "BEA's own instrumentation (patch heads, debug registers, guard pages or followed threads) differed after the script ran; active BEA instruments may be degraded.",
  SCRIPT_FINGERPRINT_UNAVAILABLE:
    "BEA could not compare its instrumentation fingerprint before and after the script; interference with BEA instruments is unknown.",
  SCRIPT_NOT_UNLOADED: "The script could not be unloaded and may still be running inside the target.",
  SCRIPT_MESSAGES_INLINE:
    "Some messages were shortened or left out of the inline result (at most 1,000 messages of 1,024 characters); the complete capture is the evidence blob script.messages.",
} as const satisfies Readonly<Record<string, string | ((...args: never[]) => string)>>;
