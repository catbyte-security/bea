/** Limitation sentences of area dump (CI-I5). Day-0 content by WP0 (seeded with the sentences DESIGN requires); ONLY WP-DUMP edits this file.
 *  Fixed BEA-authored text; template parameters are BEA-controlled only (numbers, hex, ids, enum codes). */
export const DUMP_LIMITATIONS = {
  LIVE_PATCHES_RESTORED: (n: number) =>
    `${String(n)} code range(s) patched in memory (BEA hooks or other in-process patches) were replaced with the original bytes; pass live_bytes:true to keep live bytes.`,
  LIVE_BYTES_RAW:
    "The dump keeps live code bytes, including hook patches; patched functions may start with jumps into memory that is not in the dump.",
  // WP-DUMP (DESIGN §6.2 #30, S6 §4.15, S5 §10.2)
  DUMP_GAPS: (n: number) =>
    `${String(n)} unreadable range(s) were zero-filled in the output; see gaps (bundles: unreadable_pages are not mapped by the emulator).`,
  DUMP_IAT_NOT_REBUILT:
    "The import address table holds the runtime-resolved pointers of this process; it was not rebuilt from the import directory.",
  DUMP_REBASE_RUNTIME_WRITES:
    "Relocations were reverted at every on-disk relocation site; a pointer the program rewrote at runtime at such a site is now wrong by the load delta, and pointers the program wrote at runtime anywhere else (e.g. in .data) keep their runtime values.",
  DUMP_MAPPED_NOT_A_PE_FILE:
    "Layout mapped is a raw memory image: load it as raw binary at its base. Its section headers keep the on-disk file offsets, so PE loaders (Ghidra, IDA) read the wrong bytes; use layout pe_realigned for a PE import.",
  DUMP_COFF_SYMBOLS_DROPPED:
    "The module's COFF symbol table could not be read from its on-disk file, so the realigned PE carries none; long section names were shortened to 8 characters.",
  DUMP_FILE_IMAGE_UNAVAILABLE:
    "The module's on-disk image was unavailable, so in-memory patches other than BEA's own could not be restored from it; the dump keeps those live bytes.",
  DUMP_VERIFY_INCOMPLETE: (n: number) =>
    `${String(n)} non-writable section(s) could not be compared with the on-disk image; patches inside them, if any, were kept.`,
  DUMP_RUNNING_TORN:
    "The capture ran while the target's threads kept running; regions were read at slightly different moments and may be mutually inconsistent.",
  DUMP_SUSPENDED_PARTIAL:
    "Module images and large regions were read after the other threads resumed; only thread state and small regions are from the suspended moment.",
  DUMP_THREADS_CAPPED: (n: number) =>
    `Only ${String(n)} threads were captured (the primary thread first); the other threads' state is not in the bundle.`,
  DUMP_TRUNCATED: (mib: number) =>
    `The capture reached the ${String(mib)} MiB dump limit; later regions were not captured.`,
  DUMP_TLS_STATIC_UNRESOLVED:
    "Static TLS blocks are listed only for captured modules; other modules' TLS blocks are captured as memory without a module index.",
} as const satisfies Readonly<Record<string, string | ((...args: never[]) => string)>>;
