import type { BeaError } from "../../domain/errors/beaError.js";
import { ok, type Result } from "../../domain/result.js";
import type { AddressService, AddressSpace } from "../../ports/address.js";
import type { PeImage } from "../../ports/pe.js";
import type { OperationContext } from "../../ports/sessions.js";
import type { DumpRegion } from "../../shared/agentProtocol.js";
import { settle } from "./agentCapture.js";
import { IMAGE_SCN_MEM_WRITE, sectionExtent, type MappedPeSection } from "./PeDumpWriter.js";

/**
 * D-INT-45 / CT-I6: dumped module images carry ORIGINAL code bytes by default. BEA's own patches were already replaced
 * by the agent from its originals overlay (DumpRegion.bea_patches_restored); every other in-memory patch that
 * AddressService.verify classifies `foreign-or-agent-patch` (e.g. Frida's ntdll!LdrLoadDll and kernel32!FatalExit
 * patches) is replaced here by the relocated on-disk bytes (PeImage.imageBytes). `unexplained` differences
 * (self-modifying or unpacked code) are kept: they are what the dump is for. `live_bytes:true` skips both steps.
 */
export interface RestoredPatch {
  readonly rva: number;
  readonly size: number;
  readonly source: "bea-original" | "file-image";
}

const MAX_REPORTED_PATCHES = 256;

/** The agent's bea_patches_restored of one module region, as image RVAs. */
export const beaRestoredPatches = (region: DumpRegion, moduleBase: bigint): RestoredPatch[] => {
  const shift = Number(BigInt(region.base) - moduleBase);
  return region.bea_patches_restored.map((r) => ({ rva: shift + r.offset, size: r.size, source: "bea-original" }));
};

export interface ForeignRestoreInput {
  readonly address: AddressService;
  readonly space: AddressSpace;
  readonly op: OperationContext;
  readonly moduleBase: bigint;
  /** mapped image bytes (modified in place) */
  readonly image: Uint8Array;
  readonly sections: readonly MappedPeSection[];
  /** null: the on-disk image is unavailable (nothing can be restored from it) */
  readonly file: PeImage | null;
}
export interface ForeignRestoreOutcome {
  readonly restored: readonly RestoredPatch[];
  /** sections whose verification failed (left with their live bytes) */
  readonly unchecked: number;
}

/** Non-writable sections with content: code and read-only data, where a difference from the file is a patch. */
const checkedSections = (sections: readonly MappedPeSection[], imageSize: number) =>
  sections
    .filter((s) => (s.characteristics & IMAGE_SCN_MEM_WRITE) === 0)
    .map((s) => sectionExtent(s, imageSize))
    .filter((e) => e.size > 0);

export const restoreForeignPatches = async (
  input: ForeignRestoreInput,
): Promise<Result<ForeignRestoreOutcome, BeaError>> => {
  if (input.file === null) return ok({ restored: [], unchecked: 0 });
  const restored: RestoredPatch[] = [];
  let unchecked = 0;
  for (const extent of checkedSections(input.sections, input.image.length)) {
    if (input.op.signal.aborted) break;
    const verified = await settle(input.op.name, () =>
      input.address.verify(input.space, input.moduleBase + BigInt(extent.rva), extent.size, input.op),
    );
    if (!verified.ok) {
      unchecked++;
      continue;
    }
    for (const diff of verified.value.differences) {
      if (diff.class !== "foreign-or-agent-patch") continue;
      const rva = Number(BigInt(diff.rva));
      if (rva < 0 || rva + diff.size > input.image.length) continue;
      const file = input.file;
      const bytes = await file.imageBytes(rva, diff.size, input.moduleBase).catch(() => null);
      if (bytes === null || bytes.length !== diff.size) continue;
      input.image.set(bytes, rva);
      restored.push({ rva, size: diff.size, source: "file-image" });
    }
  }
  return ok({ restored, unchecked });
};

/** Sorted, de-duplicated list capped at MAX_REPORTED_PATCHES (count reported separately). */
export const reportPatches = (patches: readonly RestoredPatch[]): RestoredPatch[] =>
  [...patches].sort((a, b) => a.rva - b.rva).slice(0, MAX_REPORTED_PATCHES);
