import { sha256Hex } from "../../domain/canonical.js";
import type { BeaError, BeaErrorOf } from "../../domain/errors/beaError.js";
import { COMPLETE, type Coverage } from "../../domain/evidence/coverage.js";
import { CORE_LIMITATIONS } from "../../domain/evidence/limitations.js";
import { DUMP_LIMITATIONS } from "../../domain/evidence/limitations/dump.js";
import type { BlobRef } from "../../domain/evidence/record.js";
import { formatHex, type Hex } from "../../domain/hex.js";
import type { JsonObject } from "../../domain/json.js";
import type { OutputPathPolicy } from "../../domain/outputPaths.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { AddressService, AddressSpace } from "../../ports/address.js";
import type { EvidenceRuntime } from "../../ports/evidence.js";
import type { FileHashCache, PeImage, PeImageCache } from "../../ports/pe.js";
import type { LiveSession, OperationContext } from "../../ports/sessions.js";
import type { DumpRegion } from "../../shared/agentProtocol.js";
import { gapsOf, readRegion, runAgentDump, settle, streamRegion, type AgentDump } from "./agentCapture.js";
import { readCoffSymbolTable } from "./coffSymbols.js";
import { envelopeOf, type RecordedEnvelope } from "./envelope.js";
import {
  checkOutPath,
  defaultOutPath,
  hashFile,
  prepareParent,
  safeStem,
  writeNewFile,
  type WrittenFile,
} from "./outputFiles.js";
import { parseMappedPe, writePeDump, type MappedPe } from "./PeDumpWriter.js";
import { beaRestoredPatches, reportPatches, restoreForeignPatches, type RestoredPatch } from "./patchRestore.js";

/**
 * dump_memory {format:"pe"|"raw"} (DESIGN §6.2 #30; S6 §4.15; WP-DUMP). A module image or an address range from the
 * live process to a NEW file: the agent dump job (agentCapture), D-INT-45 patch restoration, the PE writer, the output
 * path policy (D-INT-42) and one `bea.memory.dump` evidence record that references the file by sha256 (the agent's
 * region blob is referenced as a blob; the output file is not copied into the store).
 */
export interface DumpDeps {
  readonly evidence: EvidenceRuntime;
  readonly address: AddressService;
  /** null: no on-disk PE access (file_sha256 null, no foreign-patch restore, no rebase to preferred) */
  readonly pe: { readonly images: PeImageCache; readonly hashes: FileHashCache } | null;
  readonly policy: OutputPathPolicy;
}

export interface GapOut {
  readonly va: Hex;
  readonly size: number;
}
export interface RestoredPatchOut {
  readonly rva: Hex;
  readonly size: number;
  readonly source: RestoredPatch["source"];
}
interface DumpResult {
  readonly path: string;
  readonly bytes: number;
  readonly sha256: string;
  readonly format: "pe" | "raw" | "bundle";
  readonly base: Hex | null;
  readonly layout: "pe_realigned" | "mapped" | null;
  readonly image_base_in_file: Hex | null;
  readonly module: {
    readonly name: string;
    readonly path: string;
    readonly file_sha256: string | null;
    readonly rebased_to: "runtime" | "preferred";
    readonly relocations_reverted: number | null;
  } | null;
  readonly gaps: GapOut[];
  readonly restored_patches: RestoredPatchOut[];
  readonly bundle: {
    readonly bundle_id: string;
    readonly regions: number;
    readonly modules: number;
    readonly threads: number;
  } | null;
}
export type DumpOutput = DumpResult & RecordedEnvelope;

export interface PeDumpRequest {
  readonly module: string;
  readonly layout: "pe_realigned" | "mapped";
  readonly rebaseTo: "runtime" | "preferred";
  readonly liveBytes: boolean;
  readonly outPath?: string;
  /** the validated tool input (evidence parameters) */
  readonly input: JsonObject;
}
export interface RawDumpRequest {
  readonly address: string;
  readonly size: number;
  readonly outPath?: string;
  readonly input: JsonObject;
}

export const MAX_GAPS = 256;
const MAX_FILE_BYTES = 2 ** 31 - 1;
const PROVIDER = { id: "frida", name: "frida", version: null } as const;

/** The AddrExpr module form `<token>+0x0`; tokens with grammar characters are JSON-quoted. */
export const moduleExpr = (module: string): string =>
  /^[^\s"+!:]+$/u.test(module) ? `${module}+0x0` : `${JSON.stringify(module)}+0x0`;

const sensitiveRefusal = (operation: string): BeaErrorOf<"AccessDenied"> => ({
  _tag: "AccessDenied",
  operation,
  reason: "policy",
  message:
    "The dumped bytes contain a caller-declared sensitive value; BEA does not write them to a file. Remove the value from sensitive_values or dump a different range.",
});

const unreadable = (operation: string, region: DumpRegion): BeaErrorOf<"MemoryAccessFailed"> => ({
  _tag: "MemoryAccessFailed",
  operation,
  address: region.base,
  access: "read",
  size: region.size,
  message: "Nothing in the requested memory was readable.",
});

const fullyUnreadable = (region: DumpRegion): boolean =>
  region.size > 0 && region.holes.reduce((sum, h) => sum + h.size, 0) >= region.size;

/** gaps[] (≤ 256) + coverage/limitations for zero-filled holes. */
const gapReport = (regions: readonly DumpRegion[]): { gaps: GapOut[]; coverage: Coverage; limitations: string[] } => {
  const all = regions.flatMap(gapsOf);
  if (all.length === 0) return { gaps: [], coverage: COMPLETE, limitations: [] };
  const capped = all.length > MAX_GAPS;
  return {
    gaps: all.slice(0, MAX_GAPS).map((g) => ({ va: formatHex(g.va), size: g.size })),
    coverage: {
      status: "partial",
      truncated: capped,
      reasons: capped ? ["row_cap", "unreadable_ranges"] : ["unreadable_ranges"],
    },
    limitations: [
      DUMP_LIMITATIONS.DUMP_GAPS(all.length),
      ...(capped ? [CORE_LIMITATIONS.CAP("gap list", MAX_GAPS)] : []),
    ],
  };
};

const patchesOut = (patches: readonly RestoredPatch[]): RestoredPatchOut[] =>
  reportPatches(patches).map((p) => ({ rva: formatHex(p.rva), size: p.size, source: p.source }));

const concatBytes = (head: Uint8Array, tail: Uint8Array): Uint8Array => {
  const out = new Uint8Array(head.length + tail.length);
  out.set(head, 0);
  out.set(tail, head.length);
  return out;
};

const resolveOutPath = (
  operation: string,
  requested: string | undefined,
  policy: OutputPathPolicy,
  fallbackName: string,
  sha256: string,
): Result<{ readonly path: string; readonly defaulted: boolean; readonly sha256: string }, BeaError> => {
  if (requested === undefined) return ok({ path: defaultOutPath(policy, fallbackName), defaulted: true, sha256 });
  const checked = checkOutPath(operation, requested, policy);
  return checked.ok ? ok({ path: checked.value, defaulted: false, sha256 }) : checked;
};

/**
 * Writes the output. A DEFAULT path is content-named (`…-<sha8>`): when the identical file is already there (the same
 * dump twice) it is reused instead of failing; a caller-chosen out_path must not exist.
 */
const writeOutput = async (
  operation: string,
  target: { readonly path: string; readonly defaulted: boolean; readonly sha256: string },
  policy: OutputPathPolicy,
  content: Uint8Array | AsyncIterable<Uint8Array>,
  signal: AbortSignal,
): Promise<Result<WrittenFile, BeaError>> => {
  const parent = await prepareParent(operation, target.path, policy);
  if (!parent.ok) return parent;
  const written = await writeNewFile(operation, target.path, content, signal);
  if (
    written.ok ||
    !target.defaulted ||
    written.error._tag !== "FileOperationFailed" ||
    written.error.reason !== "exists"
  )
    return written;
  const existing = await hashFile(target.path, signal);
  return existing !== null && existing.sha256 === target.sha256 ? ok({ path: target.path, ...existing }) : written;
};

interface RecordArgs {
  readonly deps: DumpDeps;
  readonly session: LiveSession;
  readonly dump: AgentDump;
  readonly input: JsonObject;
  readonly result: DumpResult;
  readonly coverage: Coverage;
  readonly limitations: readonly string[];
  readonly locations?: Parameters<EvidenceRuntime["recorder"]["record"]>[0]["locations"];
}

const recordDump = async (args: RecordArgs): Promise<Result<DumpOutput, BeaError>> => {
  const literals = args.deps.evidence.literals(undefined);
  if (!literals.ok) return literals;
  const blobs: BlobRef[] = args.dump.blobRefs.slice(0, 64).map((b) => ({ ...b, role: "dump.region" }));
  const recorded = await args.deps.evidence.recorder.record({
    predicate_type: "bea.memory.dump",
    operation: "dump_memory",
    input: args.input,
    subject: { kind: "process-instance", instance_id: args.session.instanceId },
    ...(args.dump.anchor !== null ? { capture: args.dump.anchor } : {}),
    provider: PROVIDER,
    result: args.result as unknown as JsonObject,
    blobs,
    coverage: args.coverage,
    limitations: args.limitations,
    ...(args.locations !== undefined ? { locations: args.locations } : {}),
    literals: literals.value,
  });
  if (!recorded.ok) return recorded;
  return ok({ ...args.result, ...envelopeOf(recorded.value.record) });
};

interface FileImage {
  readonly image: PeImage | null;
  readonly sha256: string | null;
  readonly error: BeaError | null;
}
const openFileImage = async (deps: DumpDeps, path: string, op: OperationContext): Promise<FileImage> => {
  const pe = deps.pe;
  if (pe === null) return { image: null, sha256: null, error: null };
  const [image, hash] = await Promise.all([
    settle(op.name, () => pe.images.open(path, op.signal)),
    settle(op.name, () => pe.hashes.sha256(path, op.signal)),
  ]);
  return {
    image: image.ok ? image.value : null,
    sha256: hash.ok ? hash.value : null,
    error: image.ok ? null : image.error,
  };
};

/** D-INT-45 for one image: BEA originals (already spliced by the agent) + foreign patches from the file. */
const restoreImage = async (
  deps: DumpDeps,
  target: {
    readonly space: AddressSpace;
    readonly base: bigint;
    readonly region: DumpRegion;
    readonly image: Uint8Array;
  },
  pe: MappedPe | null,
  file: PeImage | null,
  op: OperationContext,
): Promise<Result<{ readonly restored: RestoredPatch[]; readonly limitations: string[] }, BeaError>> => {
  const restored = beaRestoredPatches(target.region, target.base);
  const limitations: string[] = [];
  if (pe === null) return ok({ restored, limitations });
  if (file === null) limitations.push(DUMP_LIMITATIONS.DUMP_FILE_IMAGE_UNAVAILABLE);
  const foreign = await restoreForeignPatches({
    address: deps.address,
    space: target.space,
    op,
    moduleBase: target.base,
    image: target.image,
    sections: pe.sections,
    file,
  });
  if (!foreign.ok) return foreign;
  restored.push(...foreign.value.restored);
  if (foreign.value.unchecked > 0) limitations.push(DUMP_LIMITATIONS.DUMP_VERIFY_INCOMPLETE(foreign.value.unchecked));
  return ok({ restored, limitations });
};

const peFormatError = (operation: string, reason: string): BeaErrorOf<"UnsupportedTarget"> => ({
  _tag: "UnsupportedTarget",
  operation,
  reason: "unsupported-format",
  message: `The module's in-memory PE header could not be used (${reason}); dump it with layout "mapped" and rebase_to "runtime".`,
});

/** format "pe": one module image. */
export const dumpModuleImage = async (
  deps: DumpDeps,
  session: LiveSession,
  req: PeDumpRequest,
  op: OperationContext,
): Promise<Result<DumpOutput, BeaError>> => {
  const operation = op.name;
  const space: AddressSpace = { kind: "live", session };
  const resolved = await deps.address.resolve(space, moduleExpr(req.module), op, { path: "module" });
  if (!resolved.ok) return resolved;
  const base = resolved.value.va;
  const dump = await runAgentDump(
    deps.evidence,
    session,
    {
      items: [{ kind: "module", module: formatHex(base) }],
      suspend: "none",
      max_total_bytes: MAX_FILE_BYTES,
      original_bytes: !req.liveBytes,
    },
    op,
  );
  if (!dump.ok) return dump;
  const region = dump.value.manifest.regions.find((r) => r.kind === "module");
  const info = dump.value.manifest.modules[0];
  if (region === undefined || info === undefined)
    return err({
      _tag: "AddressUnmapped",
      operation,
      address: formatHex(base),
      module_map_id: resolved.value.moduleMapId,
    });
  if (fullyUnreadable(region)) return err(unreadable(operation, region));
  const read = await readRegion(deps.evidence, dump.value, region, operation);
  if (!read.ok) return read;
  if (read.value.kind === "redacted") return err(sensitiveRefusal(operation));
  const image = read.value.bytes;
  const parsed = parseMappedPe(image);
  const needsHeader = req.layout === "pe_realigned" || req.rebaseTo === "preferred";
  if (!parsed.ok && needsHeader) return err(peFormatError(operation, parsed.error));
  const pe: MappedPe | null = parsed.ok ? parsed.value : null;
  const file = await openFileImage(deps, info.path, op);
  if (req.rebaseTo === "preferred" && file.image === null)
    return err(
      file.error ?? {
        _tag: "CapabilityUnavailable",
        operation,
        capability: "platform",
        reason: "pe-reader-unavailable",
        retryable: false,
      },
    );
  const restore = req.liveBytes
    ? ok({ restored: [] as RestoredPatch[], limitations: [] as string[] })
    : await restoreImage(deps, { space, base, region, image }, pe, file.image, op);
  if (!restore.ok) return restore;
  const { restored, limitations } = restore.value;
  const holes = region.holes.map((h) => ({ rva: Number(BigInt(region.base) - base) + h.offset, size: h.size }));
  // the realigned file carries the on-disk COFF symbol table (gcc/MinGW long section names) as overlay
  const coffSymbolTable =
    pe !== null && req.layout === "pe_realigned" && pe.pointerToSymbolTable !== 0
      ? await readCoffSymbolTable(info.path, pe)
      : null;
  const outcome =
    pe === null
      ? { imageBaseInFile: base, relocationsReverted: null, trailer: null, coffSymbols: "none" as const }
      : writePeDump(image, pe, {
          layout: req.layout,
          coffSymbolTable,
          sectionNames: new Map((file.image?.sections ?? []).map((s) => [s.rva, s.name] as const)),
          rebase:
            req.rebaseTo === "preferred" && file.image !== null
              ? {
                  preferredBase: BigInt(file.image.image_base),
                  runtimeBase: base,
                  relocations: await file.image.relocations(),
                }
              : null,
          gaps: holes,
        });
  const name = info.name;
  const content = outcome.trailer === null ? image : concatBytes(image, outcome.trailer);
  const sha256 = sha256Hex(content);
  const path = resolveOutPath(
    operation,
    req.outPath,
    deps.policy,
    `${safeStem(name)}-${sha256.slice(0, 8)}.pe`,
    sha256,
  );
  if (!path.ok) return path;
  const written = await writeOutput(operation, path.value, deps.policy, content, op.signal);
  if (!written.ok) return written;
  const gaps = gapReport([region]);
  limitations.push(...gaps.limitations, DUMP_LIMITATIONS.DUMP_IAT_NOT_REBUILT);
  if (outcome.coffSymbols === "dropped") limitations.push(DUMP_LIMITATIONS.DUMP_COFF_SYMBOLS_DROPPED);
  if (req.rebaseTo === "preferred") limitations.push(DUMP_LIMITATIONS.DUMP_REBASE_RUNTIME_WRITES);
  if (req.layout === "mapped") limitations.push(DUMP_LIMITATIONS.DUMP_MAPPED_NOT_A_PE_FILE);
  if (req.liveBytes) limitations.push(DUMP_LIMITATIONS.LIVE_BYTES_RAW);
  else if (restored.length > 0) limitations.push(DUMP_LIMITATIONS.LIVE_PATCHES_RESTORED(restored.length));
  return recordDump({
    deps,
    session,
    dump: dump.value,
    input: req.input,
    coverage: gaps.coverage,
    limitations,
    locations: [deps.evidence.locationOf(resolved.value.ref, Math.max(1, Math.min(info.size, 2 ** 32)))],
    result: {
      path: written.value.path,
      bytes: written.value.bytes,
      sha256: written.value.sha256,
      format: "pe",
      base: formatHex(base),
      layout: req.layout,
      image_base_in_file: formatHex(outcome.imageBaseInFile),
      module: {
        name,
        path: info.path,
        file_sha256: file.sha256,
        rebased_to: req.rebaseTo,
        relocations_reverted: outcome.relocationsReverted,
      },
      gaps: gaps.gaps,
      restored_patches: patchesOut(restored),
      bundle: null,
    },
  });
};

/** format "raw": an address range, bytes as they are in memory (zero-filled holes). */
export const dumpRawRange = async (
  deps: DumpDeps,
  session: LiveSession,
  req: RawDumpRequest,
  op: OperationContext,
): Promise<Result<DumpOutput, BeaError>> => {
  const operation = op.name;
  const resolved = await deps.address.resolve({ kind: "live", session }, req.address, op, { path: "address" });
  if (!resolved.ok) return resolved;
  const va = resolved.value.va;
  const dump = await runAgentDump(
    deps.evidence,
    session,
    {
      items: [{ kind: "range", base: formatHex(va), size: req.size }],
      suspend: "none",
      max_total_bytes: req.size,
      original_bytes: false,
    },
    op,
  );
  if (!dump.ok) return dump;
  const region = dump.value.manifest.regions[0];
  if (region === undefined)
    return err({ _tag: "AddressUnmapped", operation, address: formatHex(va), module_map_id: null });
  if (fullyUnreadable(region)) return err(unreadable(operation, region));
  const source = await streamRegion(deps.evidence, dump.value, region, operation);
  if (!source.ok) return source;
  if (source.value.kind === "redacted") return err(sensitiveRefusal(operation));
  const blobSha = dump.value.blobRefs[0]?.sha256 ?? "";
  const path = resolveOutPath(
    operation,
    req.outPath,
    deps.policy,
    `raw-${formatHex(va).slice(2)}-${blobSha.slice(0, 8)}.bin`,
    blobSha,
  );
  if (!path.ok) return path;
  const content = source.value.kind === "stream" ? source.value.chunks : source.value.bytes;
  const written = await writeOutput(operation, path.value, deps.policy, content, op.signal);
  if (!written.ok) return written;
  const gaps = gapReport([region]);
  return recordDump({
    deps,
    session,
    dump: dump.value,
    input: req.input,
    coverage: gaps.coverage,
    limitations: gaps.limitations,
    locations: [deps.evidence.locationOf(resolved.value.ref, req.size)],
    result: {
      path: written.value.path,
      bytes: written.value.bytes,
      sha256: written.value.sha256,
      format: "raw",
      base: formatHex(va),
      layout: null,
      image_base_in_file: null,
      module: null,
      gaps: gaps.gaps,
      restored_patches: [],
      bundle: null,
    },
  });
};
