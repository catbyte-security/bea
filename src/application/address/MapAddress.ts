import type { z } from "zod";

import type { mapAddressInputSchema, mapAddressOutputSchema } from "../../contracts/areas/address.js";
import { atText, parseAddrExpr, parseModuleToken, type ParsedAddress } from "../../domain/address/grammar.js";
import { rvaOfStatic } from "../../domain/address/rebase.js";
import type { CallerSymbol } from "../../domain/address/symbolize.js";
import type { VerifyDetail } from "../../domain/address/verify.js";
import type { BeaError, InputIssue } from "../../domain/errors/beaError.js";
import { projectBeaError } from "../../domain/errors/projection.js";
import type { Coverage } from "../../domain/evidence/coverage.js";
import { LIMITATIONS } from "../../domain/evidence/limitations.js";
import { AUTHORITY_TRUST, type Authority, type Confidence, type Location } from "../../domain/evidence/record.js";
import { canonicalHex, formatHex } from "../../domain/hex.js";
import type { EvId } from "../../domain/ids.js";
import type { JsonObject, JsonValue } from "../../domain/json.js";
import { err, ok, type Result } from "../../domain/result.js";
import { PRODUCT_IDENTITY } from "../../identity.js";
import type { AddressSpace } from "../../ports/address.js";
import type { EvidenceDraft, EvidenceRuntime, SensitiveLiterals } from "../../ports/evidence.js";
import type { PeImage } from "../../ports/pe.js";
import type { OperationContext } from "../../ports/sessions.js";
import type { AddressServiceImpl, Resolution } from "./AddressService.js";
import { notLoadedError } from "./resolveErrors.js";
import { envelopeOf } from "./envelope.js";
import { readLive } from "./FootprintScanner.js";
import { recordImageSummary } from "./imageEvidence.js";
import { isAmbiguous, selectModule, type SpaceModule, type SpaceView } from "./modules.js";

/**
 * map_address (DESIGN §6.2 #14, S2 §18.2 algorithm in the D-INT-32 shape): optional caller symbol registration
 * (bea.symbols.caller first, linked), one resolution per AddrExpr (per-row failures are rows, a grammar error fails
 * the call), S2 §18.3 verification in live sessions, the `modules` legend, and one bea.address.map record.
 */
export type MapAddressInput = z.output<typeof mapAddressInputSchema>;
export type MapAddressOutput = z.output<typeof mapAddressOutputSchema>;
type Row = MapAddressOutput["rows"][number];
type ModuleRow = MapAddressOutput["modules"][number];

const PROVIDER = { id: "bea", name: "bea-address", version: PRODUCT_IDENTITY.packageVersion } as const;

interface RowFacts {
  readonly row: Row;
  readonly resolution: Resolution | null;
  readonly detail: VerifyDetail | null;
  readonly footprintFailed: boolean;
  readonly baseSource: ModuleRow["base_source"] | null;
}

/** Recorded row = output row + per-difference live/expected hex (byte fields of the record). */
const recordedRow = (facts: RowFacts): JsonObject => {
  const { row, detail } = facts;
  if (row.verify === null || detail === null) return row as unknown as JsonObject;
  return {
    ...(row as unknown as JsonObject),
    verify: {
      ...(row.verify as unknown as JsonObject),
      differences: detail.differences.map((d) => ({ ...d })),
    },
  };
};

/** Strip the record-only hex from a recorded row. */
const projectRow = (row: JsonValue): Row => {
  const r = row as unknown as Row;
  if (r.verify === null) return r;
  return {
    ...r,
    verify: {
      ...r.verify,
      differences: r.verify.differences.map(({ rva, size, class: c }) => ({ rva, size, class: c })),
    },
  };
};

const weakest = (authorities: readonly Authority[]): Authority =>
  authorities.reduce((a, b) => (AUTHORITY_TRUST.indexOf(b) > AUTHORITY_TRUST.indexOf(a) ? b : a));

const issueOf = (error: BeaError): { code: string; message: string } => {
  const projection = projectBeaError(error);
  const message =
    error._tag === "InputError" && error.issues[0] !== undefined ? error.issues[0].message : projection.message;
  return { code: projection.code, message: message.slice(0, 600) };
};

/** Everything one map_address call shares between its steps. */
interface MapContext {
  readonly svc: AddressServiceImpl;
  readonly evidence: EvidenceRuntime;
  readonly space: AddressSpace;
  readonly input: MapAddressInput;
  readonly op: OperationContext;
  readonly reaBase: bigint | undefined;
  readonly expected: string | undefined;
  view: SpaceView;
}

/** Grammar first: any bad element fails the whole call, listing every bad index (S6 §4.12 batch semantics). */
const parseAll = (input: MapAddressInput, op: OperationContext): Result<ParsedAddress[], BeaError> => {
  const parsed: ParsedAddress[] = [];
  const issues: InputIssue[] = [];
  input.addresses.forEach((text, i) => {
    const result = parseAddrExpr(text);
    if (result.ok) parsed.push(result.value);
    else
      issues.push({
        path: `addresses[${String(i)}]`,
        reason: result.error.reason,
        message: result.error.message,
        ...(result.error.expected === undefined ? {} : { expected: result.error.expected }),
      });
  });
  return issues.length > 0 ? err({ _tag: "InputError", operation: op.name, issues }) : ok(parsed);
};

const NO_FACTS = { resolution: null, detail: null, footprintFailed: false, baseSource: null } as const;

/** One row: resolve, image check, live verification, enclosing function, region. Session-level failures abort. */
const mapOne = async (ctx: MapContext, index: number, address: ParsedAddress): Promise<Result<RowFacts, BeaError>> => {
  const { svc, space, input, op, view } = ctx;
  const text = input.addresses[index] ?? "";
  const resolved = await svc.resolveParsed(space, view, address, op, {
    path: `addresses[${String(index)}]`,
    ...(ctx.reaBase === undefined ? {} : { reaBase: ctx.reaBase }),
  });
  if (!resolved.ok) {
    if (resolved.error._tag === "Cancelled" || resolved.error._tag === "TargetExited") return resolved;
    return ok({ ...NO_FACTS, row: emptyRow(index, text, "error", null, issueOf(resolved.error)) });
  }
  const r = resolved.value;
  if (r.module === null || r.rva === null) {
    const region = space.kind === "live" ? await liveRegion(space, r.va, op) : null;
    return ok({ ...NO_FACTS, row: { ...emptyRow(index, text, "non-image", r.ref, null), region }, resolution: r });
  }
  const sha = r.ref.image_sha256;
  const imageCheck: Row["image_check"] =
    ctx.expected === undefined || sha === null || sha === undefined
      ? "unchecked"
      : sha === ctx.expected
        ? "match"
        : "mismatch";
  let detail: VerifyDetail | null = null;
  let footprintFailed = false;
  if (space.kind === "live" && input.verify_bytes > 0 && r.image !== null) {
    const checked = await svc.verifyDetailed(space.session, r.module, r.image, r.rva, input.verify_bytes, op);
    if (!checked.ok) return checked;
    detail = checked.value.detail;
    footprintFailed = checked.value.footprintFailed;
  }
  const source = r.ref.static_base_source;
  return ok({
    row: {
      index,
      input: text.slice(0, 600),
      status: "mapped",
      address: r.ref,
      func: r.image === null ? null : await functionOf(svc, view, r.module, r.image, r.rva),
      region: regionOf(r.module, r.image, r.rva),
      image_check: imageCheck,
      verify: detail === null ? null : inlineVerify(detail),
      issue: null,
    },
    resolution: r,
    detail,
    footprintFailed,
    baseSource:
      source === "caller" || source === "rea-evidence"
        ? "caller"
        : view.kind === "emulation"
          ? "emulation"
          : "pe-header",
  });
};

const inlineVerify = (detail: VerifyDetail): NonNullable<Row["verify"]> => ({
  status: detail.status,
  compared: detail.compared,
  equal: detail.equal,
  excluded_loader: detail.excluded_loader,
  own_effects_restored: detail.own_effects_restored,
  differences: detail.differences.map(({ rva, size, class: c }) => ({ rva, size, class: c })),
});

interface Assessment {
  readonly coverage: Coverage;
  readonly confidence: Confidence;
  readonly authority: Authority;
  readonly limitations: string[];
  /** image digest mismatch or unexplained bytes: an auto-unknown is recorded */
  readonly suspicious: "image" | "bytes" | null;
}

const coverageOf = (
  facts: readonly RowFacts[],
): { coverage: Coverage; errors: number; peIssues: PeImage["issues"] } => {
  const errors = facts.filter((f) => f.row.status === "error").length;
  const images = new Set<PeImage>();
  for (const f of facts) if (f.resolution?.image) images.add(f.resolution.image);
  const peIssues = [...images].flatMap((image) => image.issues);
  const reasons = new Set<string>();
  if (errors > 0) reasons.add("entry_errors");
  for (const issue of peIssues) reasons.add(issue.reason.includes("cap") ? "pe_table_cap" : "malformed_pe_directory");
  const coverage: Coverage =
    reasons.size === 0
      ? { status: "complete", truncated: false, reasons: [] }
      : {
          status: "partial",
          truncated: false,
          ...(errors > 0 ? { dropped: errors } : {}),
          reasons: [...reasons].sort(),
        };
  return { coverage, errors, peIssues };
};

/** Coverage, confidence, authority and limitation sentences (S2 §18.2). */
const assess = (ctx: MapContext, facts: readonly RowFacts[], callerEvidence: readonly EvId[]): Assessment => {
  const { coverage, errors, peIssues } = coverageOf(facts);
  const unexplained = facts.some(
    (f) => f.detail?.status === "mismatch" && f.detail.differences.some((d) => d.class === "unexplained"),
  );
  const foreign = facts.some((f) => f.detail?.differences.some((d) => d.class === "foreign-or-agent-patch") ?? false);
  const mismatch = facts.some((f) => f.row.image_check === "mismatch");
  const usedCaller = facts.some((f) => f.row.address?.symbol?.kind === "caller");
  const callerAuthority: Authority = ctx.input.symbols_source === "analyst" ? "analyst-inference" : "imported";
  const { kind } = ctx.space;
  const authority = weakest([
    kind === "live" ? "live-process" : kind === "emulation" ? "emulation" : "static-artifact",
    ...(usedCaller || callerEvidence.length > 0 ? [callerAuthority] : []),
  ]);
  const limitations = new Set<string>();
  const when = (condition: boolean, text: string): void => {
    if (condition) limitations.add(text);
  };
  when(
    facts.some((f) => f.resolution?.staticForm === true && f.row.image_check === "unchecked"),
    LIMITATIONS.STATIC_UNBOUND,
  );
  when(mismatch, LIMITATIONS.IMAGE_MISMATCH);
  when(unexplained, LIMITATIONS.BYTES_MISMATCH);
  when(foreign, LIMITATIONS.FOREIGN_PATCH);
  for (const f of facts) {
    const peBase = f.resolution?.callerBaseDiffers;
    if (peBase !== null && peBase !== undefined) limitations.add(LIMITATIONS.CALLER_STATIC_BASE(formatHex(peBase)));
  }
  if (ctx.view.kind === "file")
    limitations.add(ctx.view.runtimeBaseGiven ? LIMITATIONS.PURE_ARITHMETIC : LIMITATIONS.PREFERRED_BASE_ASSUMED);
  when(ctx.view.kind === "emulation", LIMITATIONS.EMULATED_IMAGE_SPACE);
  when(
    facts.some((f) => f.resolution?.changedOnDisk === true),
    LIMITATIONS.IMAGE_CHANGED_ON_DISK,
  );
  when(
    facts.some((f) => f.resolution?.hashUnavailable === true && f.resolution.module !== null),
    LIMITATIONS.IMAGE_HASH_UNAVAILABLE,
  );
  when(usedCaller, LIMITATIONS.CALLER_SYMBOL_NAMES);
  when(
    facts.some((f) => f.footprintFailed),
    LIMITATIONS.FOOTPRINT_UNAVAILABLE,
  );
  when(errors > 0, LIMITATIONS.BATCH_ERRORS(errors));
  for (const issue of peIssues) limitations.add(LIMITATIONS.PE_TABLE(issue.table));
  return {
    coverage,
    confidence: mismatch || unexplained ? "inferred" : "derived",
    authority,
    limitations: [...limitations],
    suspicious: mismatch ? "image" : unexplained ? "bytes" : null,
  };
};

export const runMapAddress = async (
  svc: AddressServiceImpl,
  evidence: EvidenceRuntime,
  space: AddressSpace,
  input: MapAddressInput,
  op: OperationContext,
): Promise<Result<MapAddressOutput, BeaError>> => {
  const literals = evidence.literals(input.sensitive_values);
  if (!literals.ok) return literals;
  const parsed = parseAll(input, op);
  if (!parsed.ok) return parsed;
  const viewResult = await svc.view(space, op);
  if (!viewResult.ok) return viewResult;
  const imageBase = input.external_ref?.image_base;
  const ctx: MapContext = {
    svc,
    evidence,
    space,
    input,
    op,
    reaBase: imageBase === undefined ? undefined : BigInt(canonicalHex(imageBase)),
    expected: input.expected_image_sha256 ?? input.external_ref?.image_sha256,
    view: viewResult.value,
  };
  // caller symbol registration is recorded first so the rows (and the map record) can cite it
  const callerEvidence: EvId[] = [];
  let symbolsRegistered: number | undefined;
  if (input.symbols !== undefined && input.symbols.length > 0) {
    const registered = await registerSymbols(ctx, literals.value);
    if (!registered.ok) return registered;
    ctx.view = registered.value.view;
    callerEvidence.push(registered.value.evidence_id);
    symbolsRegistered = registered.value.count;
  }
  const facts: RowFacts[] = [];
  for (const [index, address] of parsed.value.entries()) {
    const fact = await mapOne(ctx, index, address);
    if (!fact.ok) return fact;
    facts.push(fact.value);
    const id = fact.value.row.address?.symbol?.evidence_id;
    if (id !== undefined && !callerEvidence.includes(id)) callerEvidence.push(id);
  }
  const modules = await legend(svc, ctx.view, facts);
  const assessment = assess(ctx, facts, callerEvidence);
  const recorded = await recordMap(
    ctx,
    { facts, modules, assessment, callerEvidence, symbolsRegistered },
    literals.value,
  );
  if (!recorded.ok) return recorded;
  if (assessment.suspicious !== null)
    await evidence.unknowns
      .autoRecord(
        {
          domain: assessment.suspicious === "image" ? "address.image-identity" : "address.code-bytes",
          scope_image_sha256: facts.find((f) => f.row.address?.image_sha256)?.row.address?.image_sha256 ?? null,
          status: "open",
          severity: "medium",
          supporting: [recorded.value.record.evidence_id],
          contradicting: [],
          probes: ["disassemble", "dump_memory"],
          resolution: null,
        },
        op.name,
      )
      .catch(() => undefined);
  return ok(
    envelopeOf(recorded.value, (r) => {
      const o = r as unknown as { modules: ModuleRow[]; rows: JsonValue[]; symbols_registered?: number };
      return {
        modules: o.modules,
        rows: o.rows.map(projectRow),
        ...(o.symbols_registered === undefined ? {} : { symbols_registered: o.symbols_registered }),
      };
    }) as MapAddressOutput,
  );
};

/** bea.address.map: anchored iff bytes were read; linked to the module map and the caller tables used. */
const recordMap = async (
  ctx: MapContext,
  outcome: {
    readonly facts: readonly RowFacts[];
    readonly modules: readonly ModuleRow[];
    readonly assessment: Assessment;
    readonly callerEvidence: readonly EvId[];
    readonly symbolsRegistered: number | undefined;
  },
  literals: SensitiveLiterals,
) => {
  const { evidence, space, view, input, op } = ctx;
  const { facts, assessment } = outcome;
  const bytesRead = facts.some((f) => f.detail !== null && f.detail.compared + f.detail.excluded.unreadable > 0);
  const links: EvId[] = [...outcome.callerEvidence];
  if (space.kind === "live" && view.instanceId !== null && view.epoch !== null && view.moduleMapId !== null) {
    const mapEvidence = await evidence.modules.ensureRecorded(view.instanceId, view.epoch, op.name);
    if (!mapEvidence.ok && links.length === 0) return mapEvidence;
    if (mapEvidence.ok) links.unshift(mapEvidence.value.evidence_id);
  }
  if (space.kind !== "live") {
    const parents = await imageParents(ctx, facts, literals);
    if (!parents.ok) return parents;
    links.push(...parents.value);
    if (links.length === 0) return err(noParentError(op.name));
  }
  const locations: Location[] = facts.flatMap((f) =>
    f.row.status === "mapped" && f.row.address !== null
      ? [evidence.locationOf(f.row.address, Math.max(1, input.verify_bytes))]
      : [],
  );
  const draft: EvidenceDraft<JsonObject> = {
    predicate_type: "bea.address.map",
    operation: op.name,
    input: input as unknown as JsonObject,
    subject: await subjectOf(ctx.svc, space, view),
    ...(bytesRead && space.kind === "live" ? { capture: evidence.instances.capture(space.session.instanceId) } : {}),
    provider: PROVIDER,
    confidence: assessment.confidence,
    authority: assessment.authority,
    result: {
      modules: outcome.modules as unknown as JsonValue,
      rows: facts.map(recordedRow),
      ...(outcome.symbolsRegistered === undefined ? {} : { symbols_registered: outcome.symbolsRegistered }),
    },
    coverage: assessment.coverage,
    limitations: assessment.limitations,
    locations,
    evidence_links: links,
    external_refs:
      input.external_ref === undefined
        ? []
        : [
            {
              system: input.external_ref.system,
              id: input.external_ref.id,
              image_sha256: input.external_ref.image_sha256 ?? null,
            },
          ],
    literals,
  };
  return evidence.recorder.record(draft);
};

/** At most this many images are cited by one map (one per distinct module the rows resolved into). */
const MAX_IMAGE_PARENTS = 16;

/**
 * File and emulation spaces: the map is computed from the on-disk images' PE facts, so it cites their bea.image.pe
 * summaries (S2 invariant 6; weakest-parent authority = static-artifact). Every module a row resolved into, else the
 * space's primary module (the pe_path image, or the emulation session's main image) when no row resolved.
 */
const imageParents = async (
  ctx: MapContext,
  facts: readonly RowFacts[],
  literals: SensitiveLiterals,
): Promise<Result<EvId[], BeaError>> => {
  const used = new Map<bigint, { module: SpaceModule; image: PeImage | null }>();
  for (const f of facts) {
    const module = f.resolution?.module;
    if (module !== null && module !== undefined && !used.has(module.base))
      used.set(module.base, { module, image: f.resolution?.image ?? null });
  }
  if (used.size === 0) {
    const primary = ctx.view.modules.find((m) => m.primary) ?? ctx.view.modules[0];
    if (primary !== undefined) used.set(primary.base, { module: primary, image: null });
  }
  const ids: EvId[] = [];
  for (const { module, image } of [...used.values()].slice(0, MAX_IMAGE_PARENTS)) {
    const recorded = await recordImageSummary(
      { svc: ctx.svc, evidence: ctx.evidence, literals },
      module,
      image,
      ctx.op,
    );
    if (!recorded.ok) return recorded;
    if (recorded.value !== null && !ids.includes(recorded.value)) ids.push(recorded.value);
  }
  return ok(ids);
};

/** No module map, caller table or readable image: nothing observed to derive the map from (S2 invariant 6). */
const noParentError = (operation: string): BeaError => ({
  _tag: "CapabilityUnavailable",
  operation,
  capability: "server",
  reason: "module-file-unknown",
  retryable: false,
  message:
    "No module image of this address space could be read from disk, so the mapping has no evidence to derive from. Map against a live session, or pass pe_path.",
});

const emptyRow = (
  index: number,
  input: string,
  status: Row["status"],
  address: Row["address"],
  issue: Row["issue"],
): Row => ({
  index,
  input: input.slice(0, 600),
  status,
  address,
  func: null,
  region: null,
  image_check: null,
  verify: null,
  issue,
});

const regionOf = (module: SpaceModule, image: PeImage | null, rva: number): string => {
  if (image === null) return module.name.slice(0, 300);
  if (rva < image.size_of_headers) return `${module.name}:headers`.slice(0, 300);
  const section = image.sectionOf(rva);
  return `${module.name}:${section?.name ?? "?"}`.slice(0, 300);
};

/** Non-image address in a live process: committed ("private") or not ("unmapped"), by a 1-byte read. */
const liveRegion = async (space: Extract<AddressSpace, { kind: "live" }>, va: bigint, op: OperationContext) => {
  const probe = await readLive(space.session, va, 1, op);
  return probe.ok ? (probe.value.length > 0 ? "private" : "unmapped") : null;
};

/** The enclosing .pdata function: start text, primary-fragment size, export/caller name at the start. */
const functionOf = async (
  svc: AddressServiceImpl,
  view: SpaceView,
  module: SpaceModule,
  image: PeImage,
  rva: number,
): Promise<Row["func"]> => {
  const table = await image.functions();
  const fn = table.lookup(rva);
  if (fn === null) return null;
  const primary = table.lookup(fn.primary_begin);
  const size = primary === null ? fn.end - fn.begin : primary.end - primary.begin;
  const symbol = await svc.symbolOf(module, image, fn.primary_begin);
  const name =
    symbol !== null && symbol.offset === "0x0" && (symbol.kind === "export" || symbol.kind === "caller")
      ? symbol.name
      : null;
  return {
    start: atText(module.name, fn.primary_begin, isAmbiguous(view.modules, module) ? module.base : null),
    size,
    name,
    is_start: rva === fn.primary_begin,
  };
};

const legend = async (svc: AddressServiceImpl, view: SpaceView, facts: readonly RowFacts[]): Promise<ModuleRow[]> => {
  const byBase = new Map<bigint, { module: SpaceModule; facts: RowFacts[] }>();
  for (const f of facts) {
    const module = f.resolution?.module;
    if (module === null || module === undefined) continue;
    const entry = byBase.get(module.base) ?? { module, facts: [] };
    entry.facts.push(f);
    byBase.set(module.base, entry);
  }
  const out: ModuleRow[] = [];
  for (const { module, facts: rows } of byBase.values()) {
    const image = rows.find((f) => f.resolution?.image)?.resolution?.image ?? null;
    const preferred = module.preferredBase ?? (image === null ? module.base : BigInt(image.image_base));
    const verified = rows.map((f) => f.detail?.status).filter((s) => s === "match" || s === "mismatch");
    out.push({
      name: module.name.slice(0, 260),
      path: module.path === null ? null : module.path.slice(0, 4096),
      sha256: rows.find((f) => f.row.address?.image_sha256)?.row.address?.image_sha256 ?? (await svc.sha256Of(module)),
      preferred_base: formatHex(preferred),
      runtime_base: view.kind === "file" && !view.runtimeBaseGiven ? null : formatHex(module.base),
      base_source: rows.some((f) => f.baseSource === "caller")
        ? "caller"
        : view.kind === "emulation"
          ? "emulation"
          : "pe-header",
      runtime_matches_file: verified.length === 0 ? null : verified.every((s) => s === "match"),
    });
  }
  return out.slice(0, 64);
};

const subjectOf = async (
  svc: AddressServiceImpl,
  space: AddressSpace,
  view: SpaceView,
): Promise<EvidenceDraft<JsonObject>["subject"]> => {
  if (space.kind === "live") return { kind: "process-instance", instance_id: space.session.instanceId };
  const main = view.modules.find((m) => m.primary) ?? view.modules[0];
  if (main === undefined) return null;
  const sha = await svc.sha256Of(main);
  if (sha === null) return null;
  const image = await svc.imageOf(main);
  return { kind: "image", image_sha256: sha, format: "pe32+", machine: image?.machine ?? "unknown" };
};

/** S2 §19.3: register caller names for symbols_module's image digest; records bea.symbols.caller. */
const registerSymbols = async (
  ctx: MapContext,
  literals: SensitiveLiterals,
): Promise<Result<{ view: SpaceView; evidence_id: EvId; count: number }, BeaError>> => {
  const { svc, evidence, space, input, reaBase, op } = ctx;
  const token = parseModuleToken(input.symbols_module ?? "$main");
  if (!token.ok)
    return err({
      _tag: "InputError",
      operation: op.name,
      issues: [{ path: "symbols_module", reason: token.error.reason, message: token.error.message }],
    });
  let view = ctx.view;
  let selection = selectModule(view.modules, token.value, svc.platform);
  if (selection.kind === "not_loaded" && space.kind === "live") {
    const refreshed = await svc.view(space, op, true);
    if (refreshed.ok) {
      view = refreshed.value;
      selection = selectModule(view.modules, token.value, svc.platform);
    }
  }
  if (selection.kind === "not_loaded") {
    if (view.kind === "file" || token.value.kind === "main")
      return err({
        _tag: "InputError",
        operation: op.name,
        issues: [
          { path: "symbols_module", reason: "invalid_value", message: "symbols_module names no module of this space." },
        ],
      });
    return err(notLoadedError(op.name, token.value, view.moduleMapId, selection.suggestions));
  }
  if (selection.kind === "ambiguous")
    return err({
      _tag: "InputError",
      operation: op.name,
      issues: [
        {
          path: "symbols_module",
          reason: "invalid_value",
          message: "Several loaded modules share this name; qualify it with @0x<base> or quote the full path.",
        },
      ],
    });
  const module = selection.module;
  const image = await svc.imageResult(module, op);
  if (!image.ok) return image;
  const sha = await svc.sha256Of(module, op.signal);
  if (sha === null)
    return err({
      _tag: "FileOperationFailed",
      operation: op.name,
      file_operation: "read",
      path: (module.path ?? module.name).slice(0, 4096),
      reason: "io",
      message: "The module image could not be hashed, so caller symbols cannot be bound to it.",
    });
  const staticBase = reaBase ?? module.preferredBase ?? BigInt(image.value.image_base);
  const entries: { rva: number; name: string; size: number | null }[] = [];
  const issues: InputIssue[] = [];
  (input.symbols ?? []).forEach((s, i) => {
    let rva: number;
    if (s.rva !== undefined) {
      const value = BigInt(canonicalHex(s.rva));
      if (value >= BigInt(module.size)) {
        issues.push({
          path: `symbols[${String(i)}].rva`,
          reason: "out_of_range",
          message: "The RVA is outside the module image.",
        });
        return;
      }
      rva = Number(value);
    } else {
      const converted = rvaOfStatic(BigInt(canonicalHex(s.static_va ?? "0x0")), staticBase, module.size);
      if (!converted.ok) {
        issues.push({
          path: `symbols[${String(i)}].static_va`,
          reason: "out_of_range",
          message: "The static VA is outside the module image for its static base.",
        });
        return;
      }
      rva = converted.value;
    }
    entries.push({ rva, name: s.name, size: s.size ?? null });
  });
  if (issues.length > 0) return err({ _tag: "InputError", operation: op.name, issues: issues.slice(0, 64) });
  entries.sort((a, b) => a.rva - b.rva);
  const ndjson = entries
    .map((e) => JSON.stringify({ rva: formatHex(e.rva), name: e.name, ...(e.size === null ? {} : { size: e.size }) }))
    .join("\n");
  const blob = await evidence.blobs.put(
    new TextEncoder().encode(`${ndjson}\n`),
    { role: "symbols.caller", media_type: "application/x-ndjson", literals },
    op.signal,
  );
  if (!blob.ok) return blob;
  const tableRef = "redacted" in blob.value ? null : blob.value;
  const source = input.symbols_source ?? "other";
  const recorded = await evidence.recorder.record<JsonObject>({
    predicate_type: "bea.symbols.caller",
    operation: op.name,
    input: {
      symbols_module: input.symbols_module ?? "$main",
      symbols_source: source,
      symbols: entries.map((e) => ({
        rva: formatHex(e.rva),
        name: e.name,
        ...(e.size === null ? {} : { size: e.size }),
      })),
    },
    subject: { kind: "image", image_sha256: sha, format: "pe32+", machine: image.value.machine },
    provider: PROVIDER,
    confidence: "inferred",
    authority: source === "analyst" ? "analyst-inference" : "imported",
    result: { module_key: module.name.toLowerCase().slice(0, 260), count: entries.length, table: tableRef, source },
    ...(tableRef === null ? {} : { blobs: [tableRef] }),
    coverage: { status: "complete", truncated: false, reasons: [] },
    literals,
  });
  if (!recorded.ok) return recorded;
  const evidenceId = recorded.value.record.evidence_id;
  const symbols: CallerSymbol[] = entries.map((e) => ({ ...e, evidence_id: evidenceId }));
  svc.callerSymbols.register(sha, symbols);
  return ok({ view, evidence_id: evidenceId, count: entries.length });
};
