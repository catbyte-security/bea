import type { z } from "zod";

import {
  SYMBOL_ROW_CAPS,
  type listModuleSymbolsInputSchema,
  type listModuleSymbolsOutputSchema,
} from "../../contracts/areas/address.js";
import type { Loc } from "../../domain/address/addressRef.js";
import { parseModuleToken } from "../../domain/address/grammar.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import type { Coverage } from "../../domain/evidence/coverage.js";
import { LIMITATIONS } from "../../domain/evidence/limitations.js";
import { formatHex } from "../../domain/hex.js";
import type { EvId } from "../../domain/ids.js";
import type { JsonObject, JsonValue } from "../../domain/json.js";
import { err, ok, type Result } from "../../domain/result.js";
import { PRODUCT_IDENTITY } from "../../identity.js";
import type { AddressSpace } from "../../ports/address.js";
import type { EvidenceDraft, EvidenceRuntime } from "../../ports/evidence.js";
import type { PeImage } from "../../ports/pe.js";
import type { OperationContext } from "../../ports/sessions.js";
import type { AddressServiceImpl } from "./AddressService.js";
import { moduleAmbiguous, notLoadedError } from "./resolveErrors.js";
import { envelopeOf } from "./envelope.js";
import { readLive } from "./FootprintScanner.js";
import { recordImageSummary } from "./imageEvidence.js";
import { selectModule, type SpaceModule } from "./modules.js";

/**
 * list_module_symbols (DESIGN §6.2 #13, S6 §4.9): exports, imports (IAT slot) or `.pdata` functions of one module,
 * from the live/emulated module's file or a PE on disk. The host PE reader is the only name source; a live session
 * additionally reads the page's IAT slots to report what each import resolves to (as a Loc). Recorded as
 * bea.symbols.module (observed for a file, derived for a session module).
 */
export type ListModuleSymbolsInput = z.output<typeof listModuleSymbolsInputSchema>;
export type ListModuleSymbolsOutput = z.output<typeof listModuleSymbolsOutputSchema>;
type SymbolRow = ListModuleSymbolsOutput["rows"][number];

const PROVIDER = { id: "bea-pe", name: "bea-pe-reader", version: PRODUCT_IDENTITY.packageVersion } as const;

interface Pending {
  readonly row: SymbolRow;
  readonly key: string;
  /** imports: slot rva to read for `resolved` */
  readonly slot?: number;
}

const matches = (filter: string | undefined, key: string): boolean =>
  filter === undefined || key.toLowerCase().includes(filter.toLowerCase());

export const runListModuleSymbols = async (
  svc: AddressServiceImpl,
  evidence: EvidenceRuntime,
  space: AddressSpace,
  input: ListModuleSymbolsInput,
  op: OperationContext,
): Promise<Result<ListModuleSymbolsOutput, BeaError>> => {
  const viewResult = await svc.view(space, op);
  if (!viewResult.ok) return viewResult;
  let view = viewResult.value;
  let module: SpaceModule | undefined;
  if (view.kind === "file") module = view.modules[0];
  else {
    const token = parseModuleToken(input.module);
    if (!token.ok)
      return err({
        _tag: "InputError",
        operation: op.name,
        issues: [{ path: "module", reason: token.error.reason, message: token.error.message }],
      });
    let selection = selectModule(view.modules, token.value, svc.platform);
    if (selection.kind === "not_loaded" && space.kind === "live") {
      const refreshed = await svc.view(space, op, true);
      if (refreshed.ok) {
        view = refreshed.value;
        selection = selectModule(view.modules, token.value, svc.platform);
      }
    }
    if (selection.kind === "not_loaded")
      return err(notLoadedError(op.name, token.value, view.moduleMapId, selection.suggestions));
    if (selection.kind === "ambiguous") return err(moduleAmbiguous(op.name, "module", selection.candidates));
    module = selection.module;
  }
  if (module === undefined) return err({ _tag: "Internal", operation: op.name });
  const image = await svc.imageResult(module, op);
  if (!image.ok) return image;
  const sha = await svc.sha256Of(module, op.signal);
  const runtime = view.kind !== "file";
  const all = await rowsOf(input, image.value, module, runtime);
  const total = all.length;
  const page = all.slice(input.offset, input.offset + input.limit);
  const rows: SymbolRow[] = [];
  const resolvedBySlot =
    space.kind === "live" && input.kind === "imports" ? await readSlots(svc, space, module, page, op) : null;
  for (const pending of page)
    rows.push(
      pending.slot !== undefined && resolvedBySlot !== null
        ? { ...pending.row, resolved: resolvedBySlot.get(pending.slot) ?? null }
        : pending.row,
    );
  // coverage: malformed or capped tables of this image
  const reasons = new Set<string>();
  for (const issue of image.value.issues)
    reasons.add(issue.reason.includes("cap") ? "pe_table_cap" : "malformed_pe_directory");
  const coverage: Coverage =
    reasons.size === 0
      ? { status: "complete", truncated: false, reasons: [] }
      : { status: "partial", truncated: false, reasons: [...reasons].sort() };
  const limitations = image.value.issues.map((issue) => LIMITATIONS.PE_TABLE(issue.table));
  if (input.kind === "imports" && space.kind !== "live") limitations.push(LIMITATIONS.IMPORTS_NOT_RESOLVED);
  const literals = evidence.literals(undefined);
  if (!literals.ok) return literals;
  // derived listings cite their parents (S2 invariant 6): the live module map, or the emulated image's PE summary
  const links: EvId[] = [];
  if (space.kind === "live" && view.instanceId !== null && view.epoch !== null && view.moduleMapId !== null) {
    const mapEvidence = await evidence.modules.ensureRecorded(view.instanceId, view.epoch, op.name);
    if (!mapEvidence.ok) return mapEvidence;
    links.push(mapEvidence.value.evidence_id);
  }
  if (space.kind === "emulation") {
    const summary = await recordImageSummary({ svc, evidence, literals: literals.value }, module, image.value, op);
    if (!summary.ok) return summary;
    if (summary.value !== null) links.push(summary.value);
  }
  const result: JsonObject = {
    module: module.name.slice(0, 260),
    image_sha256: sha,
    preferred_base: image.value.image_base,
    kind: input.kind,
    rows: rows as unknown as JsonValue,
    page: {
      offset: input.offset,
      limit: input.limit,
      total,
      next_offset: input.offset + input.limit < total ? input.offset + input.limit : null,
    },
  };
  const subject: EvidenceDraft<JsonObject>["subject"] =
    space.kind === "live"
      ? { kind: "process-instance", instance_id: space.session.instanceId }
      : sha === null
        ? null
        : { kind: "image", image_sha256: sha, format: "pe32+", machine: image.value.machine };
  const recorded = await evidence.recorder.record<JsonObject>({
    predicate_type: "bea.symbols.module",
    operation: op.name,
    input: input as unknown as JsonObject,
    subject,
    provider: PROVIDER,
    // a listing straight off the file is an observation; runtime VAs make it a derivation over its parents (an
    // emulated module whose digest is unknown has no PE summary to cite: its rows are still BEA's own file reading)
    confidence: space.kind === "file" || (space.kind === "emulation" && links.length === 0) ? "observed" : "derived",
    authority: "static-artifact",
    result,
    coverage,
    limitations: [...new Set(limitations)],
    evidence_links: links,
    literals: literals.value,
  });
  if (!recorded.ok) return recorded;
  return ok(
    envelopeOf(
      recorded.value,
      (r) =>
        r as unknown as Pick<
          ListModuleSymbolsOutput,
          "module" | "image_sha256" | "preferred_base" | "kind" | "rows" | "page"
        >,
    ) as ListModuleSymbolsOutput,
  );
};

/** Every row of the requested kind, filtered, in a stable order (exports: ordinal; imports: slot; functions: rva). */
const rowsOf = async (
  input: ListModuleSymbolsInput,
  image: PeImage,
  module: SpaceModule,
  runtime: boolean,
): Promise<Pending[]> => {
  const va = (rva: number) => (runtime ? formatHex(module.base + BigInt(rva)) : null);
  if (input.kind === "exports") {
    const out: Pending[] = [];
    for (const e of await image.exports()) {
      const key = e.name ?? `#${String(e.ordinal)}`;
      if (!matches(input.filter, key)) continue;
      const code = e.rva === null || (image.sectionOf(e.rva)?.perms.includes("x") ?? false);
      out.push({
        key,
        row: {
          name: e.name === null ? null : e.name.slice(0, SYMBOL_ROW_CAPS.exportName),
          ordinal: e.ordinal,
          rva: e.rva === null ? null : formatHex(e.rva),
          kind: code ? "function" : "data",
          va: e.rva === null ? null : va(e.rva),
          forwarder: e.forwarder === null ? null : e.forwarder.slice(0, SYMBOL_ROW_CAPS.forwarder),
        },
      });
    }
    return out;
  }
  if (input.kind === "imports") {
    const out: Pending[] = [];
    const imports = [...(await image.imports())].sort((a, b) => a.slot_rva - b.slot_rva);
    for (const i of imports) {
      const key = `${i.dll}!${i.name ?? `#${String(i.ordinal ?? 0)}`}`;
      if (!matches(input.filter, key)) continue;
      out.push({
        key,
        slot: i.slot_rva,
        row: {
          module: i.dll.slice(0, SYMBOL_ROW_CAPS.importModule),
          name: i.name === null ? null : i.name.slice(0, SYMBOL_ROW_CAPS.importName),
          ordinal: i.ordinal,
          slot_rva: formatHex(i.slot_rva),
          slot_va: va(i.slot_rva),
          resolved: null,
        },
      });
    }
    return out;
  }
  const exportsAt = new Map<number, string>();
  for (const e of await image.exports())
    if (e.rva !== null && e.name !== null && !exportsAt.has(e.rva)) exportsAt.set(e.rva, e.name);
  const out: Pending[] = [];
  for (const entry of (await image.functions()).entries()) {
    if (entry.primary_begin !== entry.begin) continue;
    const name = exportsAt.get(entry.begin) ?? null;
    if (input.filter !== undefined && (name === null || !matches(input.filter, name))) continue;
    out.push({
      key: name ?? "",
      row: {
        rva: formatHex(entry.begin),
        size: Math.max(0, entry.end - entry.begin),
        name: name === null ? null : name.slice(0, SYMBOL_ROW_CAPS.functionName),
      },
    });
  }
  return out;
};

/** A Loc within the row caps: a text that does not fit is null (never cut, so at/static still parse). */
const fitLoc = (loc: Loc): Loc => {
  const fit = (text: string | null, cap: number) => (text !== null && text.length <= cap ? text : null);
  return {
    va: loc.va,
    at: fit(loc.at, SYMBOL_ROW_CAPS.locText),
    static: fit(loc.static, SYMBOL_ROW_CAPS.locText),
    func: fit(loc.func, SYMBOL_ROW_CAPS.locText),
    sym: fit(loc.sym, SYMBOL_ROW_CAPS.locSym),
  };
};

/** Live: read the page's IAT slots in one span and describe each target as a Loc. */
const readSlots = async (
  svc: AddressServiceImpl,
  space: Extract<AddressSpace, { kind: "live" }>,
  module: SpaceModule,
  page: readonly Pending[],
  op: OperationContext,
): Promise<Map<number, Loc | null>> => {
  const out = new Map<number, Loc | null>();
  const slots = page.flatMap((p) => (p.slot === undefined ? [] : [p.slot]));
  if (slots.length === 0) return out;
  const first = Math.min(...slots);
  const last = Math.max(...slots) + 8;
  if (last - first > 4 * 1024 * 1024) return out;
  const live = await readLive(space.session, module.base + BigInt(first), last - first, op);
  if (!live.ok) return out;
  const view = new DataView(live.value.buffer, live.value.byteOffset, live.value.byteLength);
  for (const slot of slots) {
    const at = slot - first;
    if (at + 8 > live.value.length) {
      out.set(slot, null);
      continue;
    }
    const target = view.getBigUint64(at, true);
    out.set(slot, target === 0n ? null : fitLoc(await svc.describeCode(space, target)));
  }
  return out;
};
