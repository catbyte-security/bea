import type { Fingerprint } from "../../shared/agentProtocol.js";

/**
 * run_script interference check (S4 §16): the agent's instrumentation fingerprint before and after a caller script.
 * Interference = any BEA patch head, debug-register sample, guard page or followed-thread set that was intact before
 * and differs after. Timestamps are ignored; entries that were already broken before the script are not blamed on it.
 */
export const fingerprintInterference = (before: Fingerprint, after: Fingerprint): boolean => {
  const patchKey = (p: Fingerprint["patches"][number]): string => `${p.owner}@${p.address}`;
  const afterPatches = new Map(after.patches.map((p) => [patchKey(p), p]));
  for (const p of before.patches) {
    if (!p.ok) continue;
    const now = afterPatches.get(patchKey(p));
    // A patch BEA itself removed in between (instrument expiry) disappears from the list; a still-listed patch whose
    // head changed or went bad was altered by someone else.
    if (now !== undefined && (!now.ok || now.actual_head !== p.actual_head)) return true;
  }
  const afterDr = new Map(after.debug_registers.map((d) => [d.tid, d]));
  for (const d of before.debug_registers) {
    if (!d.ok) continue;
    const now = afterDr.get(d.tid);
    if (now !== undefined && (!now.ok || now.dr7 !== d.dr7)) return true;
  }
  const afterGuards = new Map(after.guard_pages.map((g) => [g.page, g]));
  for (const g of before.guard_pages) {
    if (!g.ok) continue;
    const now = afterGuards.get(g.page);
    if (now !== undefined && (!now.ok || now.guarded !== g.guarded)) return true;
  }
  // Conservative: a followed thread missing afterwards counts, even though a thread exit during the script would
  // also drop it (the fingerprint cannot tell the two apart).
  const followedAfter = new Set(after.stalker_threads);
  return before.stalker_threads.some((tid) => !followedAfter.has(tid));
};
