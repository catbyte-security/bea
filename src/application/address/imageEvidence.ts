import type { BeaError } from "../../domain/errors/beaError.js";
import type { Coverage } from "../../domain/evidence/coverage.js";
import { LIMITATIONS } from "../../domain/evidence/limitations.js";
import { formatHex } from "../../domain/hex.js";
import type { EvId } from "../../domain/ids.js";
import type { JsonObject } from "../../domain/json.js";
import { ok, type Result } from "../../domain/result.js";
import { PRODUCT_IDENTITY } from "../../identity.js";
import type { EvidenceRuntime, SensitiveLiterals } from "../../ports/evidence.js";
import type { PeImage } from "../../ports/pe.js";
import type { OperationContext } from "../../ports/sessions.js";
import type { AddressServiceImpl } from "./AddressService.js";
import type { SpaceModule } from "./modules.js";

/**
 * `bea.image.pe` (S2 §7.3, "PE summary (disk mode)"): BEA's own reading of an on-disk image, observed with
 * static-artifact authority and no anchor, so the same image dedups to one record. Derivations outside a live process
 * (map_address over pe_path or an emulation session, list_module_symbols of an emulated module) cite it as their
 * parent: S2 invariant 6 requires a derived record to link the evidence it was computed from, and weakest-parent
 * authority then comes out as static-artifact. The summary holds the header facts the derivations use (bases, sizes,
 * sections), never file paths.
 */
const PROVIDER = { id: "bea-pe", name: "bea-pe-reader", version: PRODUCT_IDENTITY.packageVersion } as const;
const MAX_SECTIONS = 96; // the Windows loader's own section limit
const MAX_SECTION_NAME = 64;

const coverageOf = (image: PeImage): Coverage => {
  const reasons = new Set<string>();
  for (const issue of image.issues)
    reasons.add(issue.reason.includes("cap") ? "pe_table_cap" : "malformed_pe_directory");
  if (image.sections.length > MAX_SECTIONS) reasons.add("pe_table_cap");
  return reasons.size === 0
    ? { status: "complete", truncated: false, reasons: [] }
    : { status: "partial", truncated: image.sections.length > MAX_SECTIONS, reasons: [...reasons].sort() };
};

const summaryOf = (module: SpaceModule, image: PeImage): JsonObject => ({
  name: module.name.slice(0, 260),
  format: image.format,
  machine: image.machine,
  image_base: image.image_base,
  size_of_image: image.size_of_image,
  size_of_headers: image.size_of_headers,
  entry_rva: image.entry_rva === null ? null : formatHex(image.entry_rva),
  time_date_stamp: image.time_date_stamp,
  dll: image.dll,
  subsystem: image.subsystem,
  dll_characteristics: { ...image.dll_characteristics },
  sections: image.sections.slice(0, MAX_SECTIONS).map((s) => ({
    name: s.name.slice(0, MAX_SECTION_NAME),
    rva: formatHex(s.rva),
    virtual_size: s.virtual_size,
    raw_size: s.raw_size,
    perms: s.perms,
  })),
  codeview: image.codeview === null ? null : { guid: image.codeview.guid, age: image.codeview.age },
  signed: image.signed,
  clr: image.clr,
});

/**
 * Record (or find, by dedup) the PE summary of a module's on-disk image. `null` when the module has no readable
 * file or its digest cannot be computed: there is then nothing BEA observed to cite.
 */
export const recordImageSummary = async (
  deps: { readonly svc: AddressServiceImpl; readonly evidence: EvidenceRuntime; readonly literals: SensitiveLiterals },
  module: SpaceModule,
  known: PeImage | null,
  op: OperationContext,
): Promise<Result<EvId | null, BeaError>> => {
  const { svc, evidence, literals } = deps;
  const image = known ?? (await svc.imageOf(module, op.signal));
  if (image === null) return ok(null);
  const sha = await svc.sha256Of(module, op.signal);
  if (sha === null) return ok(null);
  const recorded = await evidence.recorder.record<JsonObject>({
    predicate_type: "bea.image.pe",
    operation: op.name,
    input: { image_sha256: sha },
    subject: { kind: "image", image_sha256: sha, format: "pe32+", machine: image.machine },
    provider: PROVIDER,
    result: summaryOf(module, image),
    coverage: coverageOf(image),
    limitations: image.issues.map((issue) => LIMITATIONS.PE_TABLE(issue.table)),
    literals,
  });
  return recorded.ok ? ok(recorded.value.record.evidence_id) : recorded;
};
