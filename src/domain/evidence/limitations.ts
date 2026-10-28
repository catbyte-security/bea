import type { Hex } from "../../shared/hex.js";
import type { FxId } from "../ids.js";
import { AREA_LIMITATIONS } from "./limitations/index.js";

/**
 * Fixed limitation sentences / templates (S2 §7.6). Parameters are BEA-controlled only (numbers, hex, ids, enum
 * codes), never target-derived text, so the envelope outside `result` stays trustworthy prose. A unit test pins
 * every sentence; additions are append-only and owned by the WP that introduces the reason.
 * CI-I5: this core set is frozen (WP0); area WPs add theirs in ./limitations/<area>.ts.
 */
export const CORE_LIMITATIONS = {
  SUBJECT_UNAVAILABLE: "Subject identity is unavailable for this observation.",
  PID_REUSE_UNEXCLUDED: "Process start time is not the OS creation time; pid reuse cannot be fully excluded.",
  AGENT_CLOAKED:
    "The BEA agent module (frida-agent.dll) is cloaked and absent from module lists and range attribution.",
  AGENT_FOOTPRINT:
    "Attaching loaded frida-agent.dll and about 24 system DLLs, started 3 ntdll pool threads and patched a few system-DLL functions; 11 DLLs remain loaded after detach.",
  IMAGE_CHANGED_ON_DISK:
    "The module file changed on disk after the process started; the on-disk image may differ from the loaded image.",
  IMAGE_HASH_UNAVAILABLE: "The on-disk image could not be hashed; image identity is unverified.",
  STATIC_UNBOUND:
    "The static address was not bound to an image digest; pass expected_image_sha256 (Ghidra 'Executable SHA256' or the REA subject digest) to verify it refers to this build.",
  IMAGE_MISMATCH:
    "The supplied image digest differs from the loaded module's on-disk digest; the static address may belong to a different build.",
  CALLER_STATIC_BASE: (pe: Hex) =>
    `The static base was supplied by the caller and differs from the PE preferred base ${pe}.`,
  PURE_ARITHMETIC: "No live module map was used; the runtime base was supplied by the caller.",
  BYTES_MISMATCH:
    "Live bytes differ from the on-disk image at the mapped address outside loader-written and BEA-patched ranges.",
  FOREIGN_PATCH: "Live code at the mapped address is patched by the BEA agent or another in-process component.",
  TAINTED: (n: number, ids: readonly FxId[]) =>
    `Target state was modified by ${String(n)} irreversible effect(s) (${ids.slice(0, 3).join(", ")}${n > 3 ? ", …" : ""}); observations may not reflect unperturbed behavior.`,
  STREAM_DROPPED: (n: number) =>
    `${String(n)} events were generated but not recorded; absence of an event in this stream is not evidence of absence.`,
  NOT_OBSERVED_WINDOW:
    "Only the recording window, threads and modules in scope were observed; other activity is unobserved, not absent.",
  RECORDING_ACTIVE: "The recording is still active; later events may change this result.",
  TAIL_UNCONFIRMED:
    "The stream ended without a confirmed final flush; up to one agent batch (about 50 ms) may be missing.",
  QUOTA: (kind: string, mib: number) =>
    `The run's ${kind} quota (${String(mib)} MiB) was reached; later data was not retained. Set it before starting the server (BEA_*_QUOTA_MB or config.json quotas).`,
  REDACTED: (n: number) =>
    `${String(n)} field(s), blob(s) or batch(es) were removed because they contained a caller-declared sensitive value.`,
  CAP: (kind: string, n: number) => `The ${kind} cap (${String(n)}) was reached; the rest was not retained.`,
  UNREADABLE_MEMORY: "Part of the requested memory was unreadable; the read stopped at the first unreadable page.",
  UNREADABLE_RANGES: "Some ranges were unreadable and were skipped.",
  ENDED_EARLY: (reason: string) =>
    `The operation ended early (${reason}); the result covers only what ran before that.`,
  PE_TABLE: (name: string) => `The PE ${name} table was malformed or over its cap; entries from it may be missing.`,
  DEBUGSYMBOL_HINT:
    "Symbol hints from dbghelp are unverified for images without matching PDBs and may name the wrong function or module.",
  PERTURBATION_CAPPED: "More than 256 effects applied; the perturbation list is truncated.",
  MODULE_MAP_PARTIAL: "The module map was only partly known; addresses outside it could not be attributed.",
  COMPLETENESS_UNKNOWN: "The producer cannot assert that this set is complete.",
  BATCH_ERRORS: (n: number) => `${String(n)} item(s) of this batch failed; see the per-item results.`,
  EMU_HLE_IMPORTS: "Some imports ran as high-level models (HLE), not the real library code.",
  EMU_DEVIATION: "The emulator deviated from real hardware or OS behavior for this call; see deviations.",
  EMU_ISA_GUARD: "Execution stopped at an instruction the emulator cannot run faithfully (ISA guard).",
  NOT_REAL_PROCESS: "This is an emulator result, not an observation of the real process.",
  CALLED_BEFORE_INIT: "The target was paused before process initialization; the CRT and loader state were not ready.",
  ANTI_CHEAT_ALLOWED:
    "Anti-cheat signals were present and the user allowed injection anyway; BEA does not support anti-cheat-protected targets.",
  BROKERED_LAUNCH:
    "The program exited within seconds, after a child process it started had already exited; if it was expected to keep running, it may have handed off to a launcher or an already-running process. Ask the user which process to analyze; never pick one yourself.",
} as const;

export const LIMITATIONS = { ...CORE_LIMITATIONS, ...AREA_LIMITATIONS } as const;
