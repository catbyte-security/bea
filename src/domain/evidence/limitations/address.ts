/** Limitation sentences of area address (CI-I5; WP-ADDR). The address-model core sentences (STATIC_UNBOUND,
 *  IMAGE_MISMATCH, CALLER_STATIC_BASE, PURE_ARITHMETIC, BYTES_MISMATCH, FOREIGN_PATCH, IMAGE_CHANGED_ON_DISK, …)
 *  are in the frozen core set; these are the area's additions.
 *  Fixed BEA-authored text; template parameters are BEA-controlled only (numbers, hex, ids, enum codes). */
export const ADDRESS_LIMITATIONS = {
  PREFERRED_BASE_ASSUMED:
    "No runtime_base was given with pe_path; runtime addresses assume the image loads at its PE preferred base.",
  EMULATED_IMAGE_SPACE:
    "Addresses were mapped against the emulation session's mapped images, not a live process; bytes were not verified.",
  CALLER_SYMBOL_NAMES:
    "Some names come from a caller-supplied symbol table (Ghidra, REA or analyst), not from the image itself.",
  IMPORTS_NOT_RESOLVED:
    "Import slots were not read from a live process, so the targets they resolve to are not reported.",
  FOOTPRINT_UNAVAILABLE:
    "The in-process patch footprint scan could not run; differing bytes are reported as unexplained.",
} as const satisfies Readonly<Record<string, string | ((...args: never[]) => string)>>;
