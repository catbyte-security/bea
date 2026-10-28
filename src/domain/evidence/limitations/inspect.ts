import type { Hex } from "../../../shared/hex.js";

/** Limitation sentences of area inspect (CI-I5). WP-INSPECT owns this file.
 *  Fixed BEA-authored text; template parameters are BEA-controlled only (numbers, hex, ids, enum codes). */
export const INSPECT_LIMITATIONS = {
  AGENT_THREADS_CLOAKED:
    "BEA's agent thread and Frida's own threads are cloaked and absent from the thread list; thread state and names are not reported because Windows reports them unreliably.",
  RANGE_KIND_MAPPED_UNDISTINGUISHED:
    "File-mapped views (VirtualQuery MEM_MAPPED) are not distinguished by this agent build and appear as private ranges.",
  HOOKED_BYTES_RESTORED:
    "Bytes under BEA's own hooks are shown as the original bytes saved before patching; live memory differs at those addresses.",
  DISASM_DECODE_STOP: (at: Hex) =>
    `Disassembly stopped at ${at}: the bytes there do not decode as an x64 instruction (data, padding or a misaligned start).`,
  EMU_MODULES_UNRECORDED:
    "Emulation module tables are not recorded again; the bea.emu.session evidence of emu_open holds the session's modules.",
  MAIN_THREAD_UNKNOWN:
    "No thread starts at the main module's entry point, so no thread is marked main (the main thread may have exited or the target started through a launcher stub).",
} as const satisfies Readonly<Record<string, string | ((...args: never[]) => string)>>;
