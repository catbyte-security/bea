import { release } from "node:os";
import { dirname } from "node:path";

import { KUSER_SHARED_DATA_VA, type DumpManifest } from "../../domain/dumpBundle.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { inputError } from "../../domain/errors/constructors.js";
import { COMPLETE, mergeCoverage, type Coverage } from "../../domain/evidence/coverage.js";
import { CORE_LIMITATIONS } from "../../domain/evidence/limitations.js";
import { DUMP_LIMITATIONS } from "../../domain/evidence/limitations/dump.js";
import type { BlobRef } from "../../domain/evidence/record.js";
import { formatHex, type Hex } from "../../domain/hex.js";
import type { EvId } from "../../domain/ids.js";
import type { JsonObject } from "../../domain/json.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { AddressSpace } from "../../ports/address.js";
import type { BundleCaptureRequest, BundleCaptureResult } from "../../ports/dumps.js";
import type { LiveSession, OperationContext } from "../../ports/sessions.js";
import type { DumpItem, DumpRegion, ModuleInfo, RangeRow, ThreadState } from "../../shared/agentProtocol.js";
import { readRegion, runAgentDump, settle, type AgentDump } from "./agentCapture.js";
import {
  chooseThreads,
  contextOf,
  gapsOfManifest,
  listAllImports,
  listAllRanges,
  mainModuleOf,
  pageAlign,
  staticTlsBlocks,
  tagOf,
  type CapturedBytes,
} from "./bundleSources.js";
import {
  planBundleRegions,
  writeDumpBundle,
  type CapturedRegion,
  type ManifestDraft,
  type MemoryMapRange,
} from "./DumpBundleWriter.js";
import { moduleExpr, type DumpDeps, type GapOut, type RestoredPatchOut } from "./dumpMemory.js";
import { envelopeOf, type RecordedEnvelope } from "./envelope.js";
import { checkOutPath, defaultOutPath, pathIsFree, prepareParent } from "./outputFiles.js";
import { parseMappedPe } from "./PeDumpWriter.js";
import { beaRestoredPatches, reportPatches, restoreForeignPatches, type RestoredPatch } from "./patchRestore.js";

/**
 * bea.dump/1 capture (S5 §10.2 R1–R11; DESIGN §6.2 #30; CI-B3). Shared by dump_memory {format:"bundle"} and WP-EMU's
 * emu_open {live_session_id} through DumpCapturePort.captureBundle. One agent job captures module images (live,
 * BEA originals spliced), the requested ranges, KUSER_SHARED_DATA and the threads (primary: context + TEB + PEB +
 * TLS + 64 KiB of stack; others: context + TEB); `suspended` copies thread state and small regions while the other
 * threads are suspended. The host adds the readable memory map, resolved imports, file digests and preferred bases,
 * restores foreign patches from the relocated on-disk images (D-INT-45), records `bea.dump.capture` (observed,
 * live-process) referencing the agent's region blobs, then writes the bundle whose manifest links back to it.
 */
export interface BundleDeps extends DumpDeps {
  /** BEA version (manifest producer) */
  readonly version: string;
  /** emu.dump_max_mb in bytes */
  readonly maxTotalBytes: number;
  readonly now: () => number;
  readonly wallIso: () => string;
}
/** WP-DUMP's request: the port's request plus dump_memory's live_bytes (EMU passes the port shape: false). */
export interface DumpBundleRequest extends BundleCaptureRequest {
  readonly liveBytes?: boolean;
}
interface BundleCaptureDetail {
  readonly manifest: DumpManifest;
  readonly bytes: number;
  readonly manifestSha256: string;
  readonly gaps: GapOut[];
  readonly restoredPatches: RestoredPatchOut[];
  readonly envelope: RecordedEnvelope;
}
export interface DetailedBundleCapture extends BundleCaptureResult {
  readonly detail: BundleCaptureDetail;
}

const MiB = 1024 * 1024;
const MAX_MODULES = 16;
const MAX_REGIONS = 64;
const MAX_REGION_BYTES = 256 * MiB;
const MAX_THREADS = 64;
const PRIMARY_STACK_BYTES = 64 * 1024;
const PROVIDER = { id: "frida", name: "frida", version: null } as const;

interface Plan {
  readonly items: DumpItem[];
  readonly primary: number;
  readonly threadsCapped: boolean;
  readonly modules: readonly ModuleInfo[];
  readonly requested: readonly ModuleInfo[];
}

const planCapture = async (
  deps: BundleDeps,
  session: LiveSession,
  req: DumpBundleRequest,
  op: OperationContext,
): Promise<Result<Plan, BeaError>> => {
  const space: AddressSpace = { kind: "live", session };
  const listed = await session.agent.call("listModules", { with_pe: true }, { op });
  if (!listed.ok) return listed;
  const modules = listed.value.modules;
  const requested: ModuleInfo[] = [];
  const items: DumpItem[] = [];
  for (const [i, token] of req.modules.entries()) {
    const resolved = await deps.address.resolve(space, moduleExpr(token), op, { path: `bundle.modules[${String(i)}]` });
    if (!resolved.ok) return resolved;
    const info = modules.find((m) => BigInt(m.base) === resolved.value.va);
    if (info === undefined)
      return err({
        _tag: "AddressUnmapped",
        operation: op.name,
        address: formatHex(resolved.value.va),
        module_map_id: resolved.value.moduleMapId,
      });
    if (requested.includes(info)) continue;
    requested.push(info);
    items.push({ kind: "module", module: info.base });
  }
  for (const [i, region] of req.regions.entries()) {
    const resolved = await deps.address.resolve(space, region.address, op, {
      path: `bundle.regions[${String(i)}].address`,
    });
    if (!resolved.ok) return resolved;
    const span = pageAlign(resolved.value.va, region.size);
    items.push({ kind: "range", base: formatHex(span.base), size: span.size });
  }
  items.push({ kind: "range", base: formatHex(KUSER_SHARED_DATA_VA), size: 4096 });
  const threads = await session.agent.call("listThreads", { registers: "none", teb: false, names: false }, { op });
  if (!threads.ok) return threads;
  const chosen = chooseThreads(threads.value.threads, mainModuleOf(modules, session), req.threadId);
  if (!chosen.ok)
    return err(
      inputError(op.name, [{ path: "bundle.thread_id", reason: "invalid_value", message: `${chosen.error}.` }]),
    );
  items.push({
    kind: "thread",
    tid: chosen.value.primary,
    stack_bytes: PRIMARY_STACK_BYTES,
    teb: true,
    tls: true,
    xmm: true,
  });
  const others = chosen.value.others.slice(0, MAX_THREADS - 1);
  for (const tid of others) items.push({ kind: "thread", tid, stack_bytes: 0, teb: true, tls: false, xmm: true });
  return ok({
    items,
    primary: chosen.value.primary,
    threadsCapped: chosen.value.others.length > others.length,
    modules,
    requested,
  });
};

interface Images {
  readonly images: {
    readonly name: string;
    readonly base: bigint;
    readonly bytes: Uint8Array;
    readonly region: DumpRegion;
  }[];
  readonly restored: RestoredPatch[];
  readonly hashes: Map<string, string | null>;
  readonly preferred: Map<string, Hex | null>;
  readonly limitations: string[];
  redacted: number;
}

/** Module images: read, restore patches (D-INT-45), and collect file digests and preferred bases. */
const loadImages = async (
  deps: BundleDeps,
  session: LiveSession,
  dump: AgentDump,
  liveBytes: boolean,
  op: OperationContext,
): Promise<Result<Images, BeaError>> => {
  const out: Images = {
    images: [],
    restored: [],
    hashes: new Map(),
    preferred: new Map(),
    limitations: [],
    redacted: 0,
  };
  let fileUnavailable = false;
  let unchecked = 0;
  for (const region of dump.manifest.regions.filter((r) => r.kind === "module")) {
    const info = dump.manifest.modules.find((m) => m.blob === region.blob);
    if (info === undefined) continue;
    const base = BigInt(region.base);
    const read = await readRegion(deps.evidence, dump, region, op.name);
    if (!read.ok) return read;
    if (read.value.kind === "redacted") {
      out.redacted++;
      continue;
    }
    const bytes = read.value.bytes;
    const pe = deps.pe;
    const image = pe === null ? null : await settle(op.name, () => pe.images.open(info.path, op.signal));
    const hash = pe === null ? null : await settle(op.name, () => pe.hashes.sha256(info.path, op.signal));
    out.hashes.set(region.blob, hash?.ok === true ? hash.value : null);
    out.preferred.set(region.blob, image?.ok === true ? image.value.image_base : null);
    if (!liveBytes) {
      out.restored.push(...beaRestoredPatches(region, base));
      const pe = parseMappedPe(bytes);
      const file = image?.ok === true ? image.value : null;
      if (file === null) fileUnavailable = true;
      if (pe.ok) {
        const foreign = await restoreForeignPatches({
          address: deps.address,
          space: { kind: "live", session },
          op,
          moduleBase: base,
          image: bytes,
          sections: pe.value.sections,
          file,
        });
        if (!foreign.ok) return foreign;
        out.restored.push(...foreign.value.restored);
        unchecked += foreign.value.unchecked;
      }
    }
    out.images.push({ name: info.name, base, bytes, region });
  }
  if (fileUnavailable) out.limitations.push(DUMP_LIMITATIONS.DUMP_FILE_IMAGE_UNAVAILABLE);
  if (unchecked > 0) out.limitations.push(DUMP_LIMITATIONS.DUMP_VERIFY_INCOMPLETE(unchecked));
  return ok(out);
};

const outTarget = async (
  deps: BundleDeps,
  req: DumpBundleRequest,
  operation: string,
): Promise<Result<{ readonly target: string | ((id: string) => string); readonly parent: string }, BeaError>> => {
  if (req.outDir === undefined) {
    const parent = await prepareParent(operation, defaultOutPath(deps.policy, "x"), deps.policy);
    if (!parent.ok) return parent;
    return ok({ target: (id: string) => defaultOutPath(deps.policy, id), parent: deps.policy.exportsDir });
  }
  const checked = checkOutPath(operation, req.outDir, deps.policy);
  if (!checked.ok) return checked;
  if (!(await pathIsFree(checked.value)))
    return err({
      _tag: "FileOperationFailed",
      operation,
      file_operation: "mkdir",
      path: checked.value,
      reason: "exists",
    });
  const parent = await prepareParent(operation, checked.value, deps.policy);
  if (!parent.ok) return parent;
  return ok({ target: checked.value, parent: dirname(checked.value) });
};

const validateRequest = (req: DumpBundleRequest, operation: string): BeaError | null => {
  const problems: { path: string; message: string }[] = [];
  if (req.modules.length > MAX_MODULES)
    problems.push({ path: "bundle.modules", message: `At most ${String(MAX_MODULES)} modules.` });
  if (req.regions.length > MAX_REGIONS)
    problems.push({ path: "bundle.regions", message: `At most ${String(MAX_REGIONS)} regions.` });
  req.regions.forEach((r, i) => {
    if (!Number.isInteger(r.size) || r.size < 1 || r.size > MAX_REGION_BYTES)
      problems.push({ path: `bundle.regions[${String(i)}].size`, message: "size must be 1..268435456 bytes." });
  });
  return problems.length === 0
    ? null
    : inputError(
        operation,
        problems.map((p) => ({ path: p.path, reason: "out_of_range", message: p.message })),
      );
};

export const captureDumpBundle = async (
  deps: BundleDeps,
  session: LiveSession,
  req: DumpBundleRequest,
  op: OperationContext,
): Promise<Result<DetailedBundleCapture, BeaError>> => {
  const operation = op.name;
  const invalid = validateRequest(req, operation);
  if (invalid !== null) return err(invalid);
  const target = await outTarget(deps, req, operation);
  if (!target.ok) return target;
  const t0 = deps.now();
  const plan = await planCapture(deps, session, req, op);
  if (!plan.ok) return plan;
  const liveBytes = req.liveBytes === true;
  const dump = await runAgentDump(
    deps.evidence,
    session,
    {
      items: plan.value.items,
      suspend: req.mode === "suspended" ? "all" : "none",
      max_total_bytes: deps.maxTotalBytes,
      original_bytes: !liveBytes,
    },
    op,
  );
  if (!dump.ok) return dump;
  if (dump.value.manifest.truncated)
    return err({
      _tag: "ResourceConstraint",
      operation,
      resource: "memory",
      limits: { dump_max_mb: Math.floor(deps.maxTotalBytes / MiB), planned_bytes: dump.value.plannedBytes },
      retryable: false,
      message: `The capture exceeds emu.dump_max_mb (${String(Math.floor(deps.maxTotalBytes / MiB))} MiB); request fewer modules or smaller regions.`,
    });
  const mapRows = await listAllRanges(session, op);
  if (!mapRows.ok) return mapRows;
  const images = await loadImages(deps, session, dump.value, liveBytes, op);
  if (!images.ok) return images;
  const imports: DumpManifest["imports"] = [];
  for (const image of images.value.images) {
    const rows = await listAllImports(session, image.name, op);
    if (!rows.ok) return rows;
    for (const row of rows.value)
      if (row.slot !== null && row.resolved !== null && row.from_module !== null)
        imports.push({
          importer: image.name,
          slot: row.slot,
          name: row.name,
          ordinal: row.ordinal,
          dll: row.from_module,
          target: row.resolved,
        });
  }
  return finishCapture({
    deps,
    session,
    req,
    op,
    plan: plan.value,
    dump: dump.value,
    images: images.value,
    mapRows: mapRows.value,
    imports,
    t0,
    target: target.value,
  });
};

interface FinishArgs {
  readonly deps: BundleDeps;
  readonly session: LiveSession;
  readonly req: DumpBundleRequest;
  readonly op: OperationContext;
  readonly plan: Plan;
  readonly dump: AgentDump;
  readonly images: Images;
  readonly mapRows: readonly RangeRow[];
  readonly imports: DumpManifest["imports"];
  readonly t0: number;
  readonly target: { readonly target: string | ((id: string) => string); readonly parent: string };
}

const finishCapture = async (a: FinishArgs): Promise<Result<DetailedBundleCapture, BeaError>> => {
  const { deps, session, req, op, dump, images } = a;
  const operation = op.name;
  const imageByBlob = new Map(images.images.map((i) => [i.region.blob, i]));
  let redacted = images.redacted;
  const captured: CapturedRegion[] = [];
  const small: CapturedBytes[] = [];
  for (const region of dump.manifest.regions) {
    const image = imageByBlob.get(region.blob);
    let bytes: Uint8Array | null = image?.bytes ?? null;
    if (bytes === null && region.kind !== "module") {
      const read = await readRegion(deps.evidence, dump, region, operation);
      if (!read.ok) return read;
      if (read.value.kind === "redacted") redacted++;
      else bytes = read.value.bytes;
    }
    if (bytes === null) continue;
    if (region.kind === "tls") small.push({ base: BigInt(region.base), bytes });
    const loaded = bytes;
    captured.push({
      base: BigInt(region.base),
      size: region.size,
      tag: tagOf(region),
      protection: region.protection,
      module: region.module,
      holes: region.holes,
      load: async () => ok(loaded),
    });
  }
  const memoryMap: MemoryMapRange[] = a.mapRows
    .filter((r) => r.protection.startsWith("r"))
    .map((r) => ({ base: BigInt(r.base), size: r.size, protection: r.protection, module: r.module }));
  const planned = planBundleRegions(captured, memoryMap);
  const threads: DumpManifest["threads"] = dump.manifest.threads
    .filter((s): s is ThreadState & { teb: Hex } => s.teb !== null)
    .map((s) => ({
      tid: s.tid,
      primary: s.tid === a.plan.primary,
      teb: s.teb,
      context: contextOf(s),
      stack: s.stack,
      tls: {
        slots_array: s.tls?.static_tls_array ?? null,
        static_blocks:
          s.tid === a.plan.primary
            ? staticTlsBlocks(
                s.tls?.static_tls_array != null ? BigInt(s.tls.static_tls_array) : null,
                images.images,
                small,
              )
            : [],
      },
    }));
  const limitations: string[] = [...images.limitations];
  if (req.mode === "running") limitations.push(DUMP_LIMITATIONS.DUMP_RUNNING_TORN);
  else limitations.push(DUMP_LIMITATIONS.DUMP_SUSPENDED_PARTIAL);
  if (a.plan.threadsCapped) limitations.push(DUMP_LIMITATIONS.DUMP_THREADS_CAPPED(MAX_THREADS));
  if (images.images.length > 0)
    limitations.push(DUMP_LIMITATIONS.DUMP_TLS_STATIC_UNRESOLVED, DUMP_LIMITATIONS.DUMP_IAT_NOT_REBUILT);
  if (req.liveBytes === true) limitations.push(DUMP_LIMITATIONS.LIVE_BYTES_RAW);
  else if (images.restored.length > 0) limitations.push(DUMP_LIMITATIONS.LIVE_PATCHES_RESTORED(images.restored.length));
  if (redacted > 0) limitations.push(CORE_LIMITATIONS.REDACTED(redacted));
  const unreadablePages = planned.reduce((n, r) => n + r.unreadable.length, 0);
  if (unreadablePages > 0) limitations.push(DUMP_LIMITATIONS.DUMP_GAPS(unreadablePages));
  const coverage: Coverage = mergeCoverage(
    COMPLETE,
    unreadablePages > 0 ? { status: "partial", truncated: false, reasons: ["unreadable_ranges"] } : COMPLETE,
    redacted > 0 ? { status: "partial", truncated: true, reasons: ["explicit_sensitive_value"] } : COMPLETE,
  );
  const restoredOut = reportPatches(images.restored).map((p) => ({
    rva: formatHex(p.rva),
    size: p.size,
    source: p.source,
  }));
  const capturedModules = new Set(images.images.map((i) => i.region.blob));
  const recorded = await recordCapture(
    a,
    {
      mode: req.mode,
      pid: session.identity.pid,
      modules: images.images.map((i) => i.name),
      threads: threads.length,
      regions: planned.length,
      captured_bytes: planned.reduce((n, r) => n + r.size, 0),
      unreadable_pages: unreadablePages,
      restored_patches: restoredOut as unknown as JsonObject[],
      live_bytes: req.liveBytes === true,
    },
    coverage,
    limitations,
  );
  if (!recorded.ok) return recorded;
  const anchor = dump.anchor?.anchor;
  const draft: ManifestDraft = {
    schema: "bea.dump/1",
    created_at: deps.wallIso(),
    producer: {
      tool: "bea",
      version: deps.version,
      operation: "dump_memory",
      evidence_id: recorded.value.evidence_id,
      instance_id: session.instanceId,
    },
    process: {
      pid: session.identity.pid,
      image_path: session.identity.image.path,
      image_sha256: session.identity.image.sha256,
      arch: "x64",
      os: { platform: "windows", version: release().slice(0, 64) },
    },
    capture: {
      mode: req.mode,
      time_anchor:
        anchor !== undefined && anchor.effect_epoch !== null && anchor.module_map_epoch !== null
          ? { seq: anchor.seq, effect_epoch: anchor.effect_epoch, module_map_epoch: anchor.module_map_epoch }
          : null,
      duration_ms: Math.max(0, Math.round(deps.now() - a.t0)),
    },
    modules: a.plan.modules.map((m) => {
      const blob = dump.manifest.modules.find((d) => BigInt(d.base) === BigInt(m.base))?.blob ?? null;
      const region = blob === null ? undefined : dump.manifest.regions.find((r) => r.blob === blob);
      const isCaptured = blob !== null && capturedModules.has(blob);
      return {
        name: m.name,
        path: m.path,
        base: m.base,
        size: m.size,
        file_sha256: blob === null ? null : (images.hashes.get(blob) ?? null),
        preferred_base: blob === null ? null : (images.preferred.get(blob) ?? null),
        timestamp: m.pe?.time_date_stamp ?? null,
        captured: !isCaptured ? "none" : region !== undefined && region.holes.length > 0 ? "partial" : "full",
      };
    }),
    memory_map: memoryMap.map((r) => ({
      base: formatHex(r.base),
      size: r.size,
      protection: r.protection,
      module: r.module,
    })),
    threads,
    peb: dump.manifest.threads.find((t) => t.tid === a.plan.primary)?.peb ?? null,
    imports: a.imports,
    limitations: limitations.slice(0, 64),
  };
  const written = await writeDumpBundle(operation, draft, planned, a.target.target, a.target.parent);
  if (!written.ok) return written;
  const gaps = gapsOfManifest(written.value.manifest);
  return ok({
    bundlePath: written.value.path,
    bundleId: written.value.bundleId,
    evidenceId: recorded.value.evidence_id,
    regions: written.value.manifest.regions.length,
    modules: images.images.length,
    threads: threads.length,
    limitations: recorded.value.limitations,
    detail: {
      manifest: written.value.manifest,
      bytes: written.value.bytes,
      manifestSha256: written.value.manifestSha256,
      gaps: gaps.gaps,
      restoredPatches: restoredOut,
      envelope: recorded.value,
    },
  });
};

const recordCapture = async (
  a: FinishArgs,
  result: JsonObject,
  coverage: Coverage,
  limitations: readonly string[],
): Promise<Result<RecordedEnvelope & { readonly evidence_id: EvId }, BeaError>> => {
  const literals = a.deps.evidence.literals(undefined);
  if (!literals.ok) return literals;
  const blobs: BlobRef[] = a.dump.blobRefs.slice(0, 64).map((b) => ({ ...b, role: "dump.region" }));
  const recorded = await a.deps.evidence.recorder.record({
    predicate_type: "bea.dump.capture",
    operation: "dump_memory",
    input: {
      format: "bundle",
      modules: [...a.req.modules],
      regions: a.req.regions.map((r) => ({ address: r.address, size: r.size })),
      mode: a.req.mode,
      ...(a.req.threadId !== undefined ? { thread_id: a.req.threadId } : {}),
      live_bytes: a.req.liveBytes === true,
    },
    subject: { kind: "process-instance", instance_id: a.session.instanceId },
    ...(a.dump.anchor !== null ? { capture: a.dump.anchor } : {}),
    provider: PROVIDER,
    result,
    blobs,
    coverage,
    limitations,
    literals: literals.value,
  });
  return recorded.ok ? ok(envelopeOf(recorded.value.record)) : recorded;
};
