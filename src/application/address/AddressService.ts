import { stat } from "node:fs/promises";

import type { Addr, AddressRef, Loc } from "../../domain/address/addressRef.js";
import {
  formatModuleToken,
  parseAddrExpr,
  type ModuleToken,
  type ParsedAddress,
} from "../../domain/address/grammar.js";
import { compactAddr, rvaInImage, rvaOfStatic, staticOfRva, symText, vaOfRva } from "../../domain/address/rebase.js";
import { symbolize, type ExportEntry, type ImportSlot, type SymbolInfo } from "../../domain/address/symbolize.js";
import {
  compareWindow,
  finishVerification,
  overlayOriginals,
  verificationWithout,
  type VerifyDetail,
} from "../../domain/address/verify.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { formatHex } from "../../domain/hex.js";
import type { HostPlatform } from "../../domain/paths.js";
import { pathKey } from "../../domain/process/instance.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { AddressService, AddressSpace, ByteVerification, ResolvedAddress } from "../../ports/address.js";
import type { EmuPort } from "../../ports/emu.js";
import type { EvidenceRuntime } from "../../ports/evidence.js";
import type { FileHashCache, PeExport, PeImage, PeImageCache } from "../../ports/pe.js";
import type { LiveSession, OperationContext } from "../../ports/sessions.js";
import { CallerSymbolStore } from "./CallerSymbols.js";
import {
  forwarderUnresolved,
  inputIssue,
  issueError,
  moduleAmbiguous,
  notLoadedError,
  rvaOutOfImage,
  staticOutOfImage,
} from "./resolveErrors.js";
import { FootprintScanner, readLive, type LoaderSpan } from "./FootprintScanner.js";
import {
  agentModules,
  emulationModules,
  isAmbiguous,
  keyPlatform,
  liveModules,
  moduleAtVa,
  selectModule,
  similarNames,
  type SpaceModule,
  type SpaceView,
} from "./modules.js";

/**
 * AddressService (S2 §16.3, S6 §2.1–2.2, DESIGN §5.5): resolution of every AddrExpr form over live, emulation and
 * file spaces; compact Addr/Loc outputs; S2 §18.3 byte verification. Emulation spaces are resolved through the
 * LATE-BOUND EmuPort getter (CI-B5: called per request, never during construction). Live tables come from the
 * host module map (EvidenceRuntime.modules), refreshed once with an agent `listModules` snapshot when a module
 * token does not match (the module may have loaded since the last s:modules row).
 */
const MAX_FORWARDER_HOPS = 4;
const API_SET = /^(api|ext)-ms-/iu;

export interface AddressDeps {
  readonly evidence: EvidenceRuntime;
  readonly pe: { readonly images: PeImageCache; readonly hashes: FileHashCache };
  readonly emulator: () => EmuPort;
  readonly platform: HostPlatform;
}

/** A resolved address with the facts map_address reports beside the AddressRef. */
export interface Resolution {
  readonly ref: AddressRef;
  readonly va: bigint;
  readonly module: SpaceModule | null;
  readonly rva: number | null;
  readonly image: PeImage | null;
  /** PE preferred base when the static base was supplied by the caller and differs (CALLER_STATIC_BASE) */
  readonly callerBaseDiffers: bigint | null;
  readonly changedOnDisk: boolean;
  readonly hashUnavailable: boolean;
  readonly staticForm: boolean;
}

export interface ResolveOptions {
  readonly path?: string;
  readonly expectedImageSha256?: string;
  /** external_ref.image_base (S2 §16.3 step 2 "rea-evidence") for static forms without /0xBASE */
  readonly reaBase?: bigint;
}

const SYMBOL_NAME_MAX = 1024;

/** Start time of the process as epoch ms (FILETIME 100 ns decimal or ISO), or null. */
const startMs = (session: LiveSession): number | null => {
  const { source, value } = session.identity.startTime;
  if (source === "os-creation-time" && /^\d+$/u.test(value))
    return Number(BigInt(value) / 10_000n - 11_644_473_600_000n);
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
};

export class AddressServiceImpl implements AddressService {
  readonly callerSymbols = new CallerSymbolStore();
  readonly footprint: FootprintScanner;
  /** prepared preferred bases by path key (CI-I10) */
  readonly #preferred = new Map<string, bigint>();
  /** file spaces seen by view()/prepare(): path key + runtime base → module */
  readonly #fileModules = new Map<string, SpaceModule>();

  constructor(private readonly deps: AddressDeps) {
    this.footprint = new FootprintScanner(deps.evidence.effects);
  }

  get platform(): HostPlatform {
    return this.deps.platform;
  }

  #pathKey(path: string): string {
    return pathKey(path, keyPlatform(this.deps.platform));
  }

  // ================================================================ port

  validate(
    expr: string,
  ): Result<true, { readonly reason: "invalid_format" | "out_of_range"; readonly message: string }> {
    const parsed = parseAddrExpr(expr);
    return parsed.ok ? ok(true) : err({ reason: parsed.error.reason, message: parsed.error.message });
  }

  async resolve(
    space: AddressSpace,
    expr: string,
    op: OperationContext,
    opts: { readonly path?: string; readonly expectedImageSha256?: string } = {},
  ): Promise<Result<ResolvedAddress, BeaError>> {
    const path = opts.path ?? "address";
    const parsed = parseAddrExpr(expr);
    if (!parsed.ok) return err(issueError(op.name, path, parsed.error));
    const view = await this.view(space, op);
    if (!view.ok) return view;
    const resolved = await this.resolveParsed(space, view.value, parsed.value, op, { path });
    if (!resolved.ok) return resolved;
    const { ref } = resolved.value;
    if (
      opts.expectedImageSha256 !== undefined &&
      ref.module !== null &&
      ref.image_sha256 !== undefined &&
      ref.image_sha256 !== null &&
      ref.image_sha256 !== opts.expectedImageSha256
    )
      return err(
        inputIssue(
          op.name,
          path,
          "invalid_value",
          "The module's on-disk image digest differs from expected_image_sha256; the address may belong to a different build.",
          { reason: "image_mismatch", expected: opts.expectedImageSha256, actual: ref.image_sha256 },
        ),
      );
    return ok({ ref, moduleMapId: view.value.moduleMapId, va: resolved.value.va });
  }

  describe(space: AddressSpace, va: bigint): Addr {
    const modules = this.#modulesSync(space);
    const module = moduleAtVa(modules, va);
    if (module === null) return compactAddr(va, null);
    return compactAddr(va, {
      name: module.name,
      base: module.base,
      size: module.size,
      staticBase:
        module.preferredBase ??
        (module.path === null ? null : (this.#preferred.get(this.#pathKey(module.path)) ?? null)),
      ambiguous: isAmbiguous(modules, module),
    });
  }

  async describeCode(space: AddressSpace, va: bigint): Promise<Loc> {
    const modules = this.#modulesSync(space);
    const module = moduleAtVa(modules, va);
    if (module === null) return { ...compactAddr(va, null), func: null, sym: null };
    const image = await this.imageOf(module);
    if (image !== null && module.path !== null && module.preferredBase === null)
      this.#preferred.set(this.#pathKey(module.path), BigInt(image.image_base));
    const addr = this.describe(space, va);
    if (image === null) return { ...addr, func: null, sym: null };
    const rva = Number(va - module.base);
    const fn = (await image.functions()).lookup(rva);
    // DATA-7: Loc.sym is an exact PE export (S6 §2.2). Caller-table names (map_address symbols: analyst or imported)
    // stay in map_address results, which carry their provenance; here they would enter thread lists, crash frames and
    // call faults as observed facts, and could replace or hide real export names
    const symbol = await this.symbolOf(module, image, rva, undefined, false);
    const ambiguous = isAmbiguous(modules, module) ? module.base : null;
    const func =
      fn === null
        ? null
        : `${formatModuleToken({ kind: "name", name: module.name, base: ambiguous })}+${formatHex(fn.primary_begin)}`;
    // sym only for an exact export/caller name at the address or at its function start (never nearest-export)
    const sym =
      symbol !== null &&
      symbol.name !== null &&
      symbol.kind === "export" &&
      (symbol.offset === "0x0" || (fn !== null && symbol.function_start === formatHex(fn.primary_begin)))
        ? symText(symbol.name, Number(BigInt(symbol.offset)))
        : null;
    return { ...addr, func, sym };
  }

  async fromFrameRef(space: AddressSpace, frame: string): Promise<Loc> {
    const unknown: Loc = { va: "0x0", at: frame.slice(0, 600), static: null, func: null, sym: null };
    const parsed = parseAddrExpr(frame);
    if (!parsed.ok) return unknown;
    if (parsed.value.form === "va") return this.describeCode(space, parsed.value.va);
    if (parsed.value.form !== "module-rva") return unknown;
    const selection = selectModule(this.#modulesSync(space), parsed.value.module, this.deps.platform);
    if (selection.kind !== "found" || !rvaInImage(parsed.value.rva, selection.module.size)) return unknown;
    return this.describeCode(space, selection.module.base + BigInt(parsed.value.rva));
  }

  async prepare(space: AddressSpace, vas: readonly bigint[], op: OperationContext): Promise<void> {
    if (space.kind === "file") await this.view(space, op);
    const modules = this.#modulesSync(space);
    const wanted = new Map<string, SpaceModule>();
    // UX-10: the main image too (most callers, writers and faults are there), so recordings decode its static form
    const primary = modules.find((m) => m.primary);
    for (const va of primary === undefined ? vas : [...vas, primary.base]) {
      const module = moduleAtVa(modules, va);
      if (module === null || module.preferredBase !== null || module.path === null) continue;
      const key = this.#pathKey(module.path);
      if (!this.#preferred.has(key)) wanted.set(key, module);
    }
    for (const [key, module] of wanted) {
      if (op.signal.aborted) return;
      const image = await this.imageOf(module, op.signal);
      if (image !== null) this.#preferred.set(key, BigInt(image.image_base));
    }
  }

  preferredBaseOf(path: string): bigint | null {
    return this.#preferred.get(this.#pathKey(path)) ?? null;
  }

  async verify(
    space: AddressSpace,
    va: bigint,
    len: number,
    op: OperationContext,
  ): Promise<Result<ByteVerification, BeaError>> {
    if (space.kind !== "live") return ok(stripDetail(verificationWithout("skipped", "no_session")));
    const view = await this.view(space, op);
    if (!view.ok) return view;
    const module = moduleAtVa(view.value.modules, va);
    if (module === null) return ok(stripDetail(verificationWithout("not-applicable", "not_image")));
    const image = await this.imageResult(module, op);
    if (!image.ok) return image;
    const checked = await this.verifyDetailed(space.session, module, image.value, Number(va - module.base), len, op);
    return checked.ok ? ok(stripDetail(checked.value.detail)) : checked;
  }

  // ================================================================ internals (map_address, list_module_symbols)

  /** The module table of a space (live: host map, else an agent snapshot; emulation: EmuPort; file: the PE). */
  async view(space: AddressSpace, op: OperationContext, refresh = false): Promise<Result<SpaceView, BeaError>> {
    if (space.kind === "emulation") {
      const emulator = this.deps.emulator();
      const handle = emulator.lookup(space.sessionId);
      if (handle === null) return err({ _tag: "SessionNotFound", operation: op.name, session_id: space.sessionId });
      return ok({
        kind: "emulation",
        modules: emulationModules(emulator.modules(handle)),
        moduleMapId: null,
        instanceId: null,
        epoch: null,
        runtimeBaseGiven: false,
      });
    }
    if (space.kind === "file") {
      const image = await this.deps.pe.images.open(space.imagePath, op.signal);
      if (!image.ok) return err({ ...image.error, operation: op.name });
      const module: SpaceModule = {
        name: baseNameOf(space.imagePath),
        path: space.imagePath,
        base: space.runtimeBase ?? BigInt(image.value.image_base),
        size: image.value.size_of_image,
        primary: true,
        preferredBase: BigInt(image.value.image_base),
      };
      this.#fileModules.set(this.#fileKey(space), module);
      return ok({
        kind: "file",
        modules: [module],
        moduleMapId: null,
        instanceId: null,
        epoch: null,
        runtimeBaseGiven: space.runtimeBase !== null,
      });
    }
    const session = space.session;
    const tracker = this.deps.evidence.modules;
    let current = refresh ? undefined : tracker.current(session.instanceId);
    if (current === undefined) {
      const listed = await session.agent.call("listModules", { with_pe: false }, { op });
      if (!listed.ok) return listed;
      tracker.apply(session.instanceId, {
        op: "snapshot",
        epoch: listed.value.module_map_epoch,
        modules: listed.value.modules.map((m) => ({ name: m.name, base: m.base, size: m.size, path: m.path })),
      });
      current = tracker.current(session.instanceId);
      if (current === undefined)
        return ok({
          kind: "live",
          modules: agentModules(listed.value.modules, session.identity.image.path, this.deps.platform),
          moduleMapId: null,
          instanceId: session.instanceId,
          epoch: listed.value.module_map_epoch,
          runtimeBaseGiven: false,
        });
    }
    const map = current.map();
    return ok({
      kind: "live",
      modules: liveModules(map, session.identity.image.path, this.deps.platform),
      moduleMapId: map.module_map_id,
      instanceId: session.instanceId,
      epoch: current.epoch,
      runtimeBaseGiven: false,
    });
  }

  #fileKey(space: Extract<AddressSpace, { kind: "file" }>): string {
    return `${this.#pathKey(space.imagePath)}|${space.runtimeBase?.toString(16) ?? "pref"}`;
  }

  #modulesSync(space: AddressSpace): readonly SpaceModule[] {
    if (space.kind === "file") {
      const module = this.#fileModules.get(this.#fileKey(space));
      return module === undefined ? [] : [module];
    }
    if (space.kind === "emulation") {
      try {
        const emulator = this.deps.emulator();
        const handle = emulator.lookup(space.sessionId);
        return handle === null ? [] : emulationModules(emulator.modules(handle));
      } catch {
        return [];
      }
    }
    const current = this.deps.evidence.modules.current(space.session.instanceId);
    return current === undefined
      ? []
      : liveModules(current.map(), space.session.identity.image.path, this.deps.platform);
  }

  /** The module's on-disk PE (null: no path, or unreadable). */
  async imageOf(module: SpaceModule, signal?: AbortSignal): Promise<PeImage | null> {
    if (module.path === null) return null;
    const image = await this.deps.pe.images.open(module.path, signal);
    return image.ok ? image.value : null;
  }

  async imageResult(module: SpaceModule, op: OperationContext): Promise<Result<PeImage, BeaError>> {
    if (module.path === null)
      return err({
        _tag: "CapabilityUnavailable",
        operation: op.name,
        capability: "server",
        reason: "module-file-unknown",
        retryable: false,
        message: "The module has no file path, so its on-disk image cannot be read.",
      });
    const image = await this.deps.pe.images.open(module.path, op.signal);
    return image.ok ? image : err({ ...image.error, operation: op.name });
  }

  /** image sha256 (emulation: known; else FileHashCache), null when it cannot be hashed. */
  async sha256Of(module: SpaceModule, signal?: AbortSignal): Promise<string | null> {
    if (module.sha256 !== undefined) return module.sha256;
    if (module.path === null) return null;
    const digest = await this.deps.pe.hashes.sha256(module.path, signal);
    return digest.ok ? digest.value : null;
  }

  /**
   * S2 §19.1 for a module-relative address (caller tables keyed by the module's image digest). `callerNames: false`
   * (review fix DATA-7) symbolizes from the PE alone: analyst/imported names never enter observed records' Locs.
   */
  async symbolOf(
    module: SpaceModule,
    image: PeImage,
    rva: number,
    forwardedFrom?: string,
    callerNames = true,
  ): Promise<SymbolInfo | null> {
    const [exports, imports, functions] = await Promise.all([image.exports(), image.imports(), image.functions()]);
    const sha = await this.sha256Of(module);
    const byRva = exportIndex(exports, image);
    const slots = [...imports].sort((a, b) => a.slot_rva - b.slot_rva);
    const importAt = (x: number): ImportSlot | null => {
      let lo = 0;
      let hi = slots.length - 1;
      while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        const s = slots[mid];
        if (s === undefined) return null;
        if (x < s.slot_rva) hi = mid - 1;
        else if (x >= s.slot_rva + 8) lo = mid + 1;
        else return { slot_rva: s.slot_rva, dll: s.dll, name: s.name, ordinal: s.ordinal };
      }
      return null;
    };
    const symbol = symbolize(rva, {
      caller: callerNames ? this.callerSymbols.table(sha) : [],
      exportAt: (x) => byRva.get(x) ?? null,
      importAt,
      functionAt: (x) => functions.lookup(x),
      ...(forwardedFrom === undefined ? {} : { forwardedFrom }),
    });
    return symbol === null || symbol.name === null || symbol.name.length <= SYMBOL_NAME_MAX
      ? symbol
      : { ...symbol, name: symbol.name.slice(0, SYMBOL_NAME_MAX) };
  }

  /** S2 §16.3 for one parsed address over a prepared view. */
  async resolveParsed(
    space: AddressSpace,
    initial: SpaceView,
    parsed: ParsedAddress,
    op: OperationContext,
    opts: ResolveOptions,
  ): Promise<Result<Resolution, BeaError>> {
    const path = opts.path ?? "address";
    if (parsed.form === "va") {
      if (initial.kind === "file" && !initial.runtimeBaseGiven)
        return err(
          inputIssue(op.name, path, "invalid_value", "A runtime VA needs runtime_base together with pe_path.", {
            reason: "no_module_map",
          }),
        );
      const module = moduleAtVa(initial.modules, parsed.va);
      if (module === null) return ok(this.#nonImage(initial, parsed.va));
      return this.#finish(space, initial, module, Number(parsed.va - module.base), op, { staticForm: false });
    }
    const selected = await this.#select(space, initial, parsed.module, op, path);
    if (!selected.ok) return selected;
    const { view, module } = selected.value;
    if (parsed.form === "module-rva") {
      if (!rvaInImage(parsed.rva, module.size)) return err(rvaOutOfImage(op.name, path, module.size));
      return this.#finish(space, view, module, parsed.rva, op, { staticForm: false });
    }
    const image = await this.imageResult(module, op);
    if (!image.ok) return image;
    if (parsed.form === "static") {
      const peBase = BigInt(image.value.image_base);
      const source = parsed.static_base !== null ? "caller" : opts.reaBase !== undefined ? "rea-evidence" : null;
      const staticBase = parsed.static_base ?? opts.reaBase ?? module.preferredBase ?? peBase;
      const rva = rvaOfStatic(parsed.static_va, staticBase, module.size);
      if (!rva.ok) return err(staticOutOfImage(op.name, path, staticBase, module.size));
      return this.#finish(space, view, module, rva.value, op, {
        staticForm: true,
        staticBase,
        staticSource: source,
        callerBaseDiffers: source === "caller" && staticBase !== peBase ? peBase : null,
        image: image.value,
      });
    }
    return this.#resolveExport(space, view, { module, image: image.value }, parsed, op, path);
  }

  /** S2 §16.3 step 1 with one live refresh when the token does not match. */
  async #select(
    space: AddressSpace,
    initial: SpaceView,
    token: ModuleToken,
    op: OperationContext,
    path: string,
  ): Promise<Result<{ readonly view: SpaceView; readonly module: SpaceModule }, BeaError>> {
    let view = initial;
    let selection = selectModule(view.modules, token, this.deps.platform);
    if (selection.kind === "not_loaded" && space.kind === "live") {
      const refreshed = await this.view(space, op, true);
      if (refreshed.ok) {
        view = refreshed.value;
        selection = selectModule(view.modules, token, this.deps.platform);
      }
    }
    if (selection.kind === "found") return ok({ view, module: selection.module });
    if (selection.kind === "ambiguous") return err(moduleAmbiguous(op.name, path, selection.candidates));
    if (view.kind === "file")
      return err(
        inputIssue(
          op.name,
          path,
          "invalid_value",
          "With pe_path the module token must name that file (or use $main / +0x<rva>).",
          {
            reason: "no_module_map",
          },
        ),
      );
    return err(notLoadedError(op.name, token, view.moduleMapId, selection.suggestions));
  }

  /** Export / ordinal with forwarders (≤ 4 hops; API sets through the agent's resolveTargets, A19). */
  async #resolveExport(
    space: AddressSpace,
    view: SpaceView,
    start: { readonly module: SpaceModule; readonly image: PeImage },
    parsed: Extract<ParsedAddress, { form: "export" }>,
    op: OperationContext,
    path: string,
  ): Promise<Result<Resolution, BeaError>> {
    let current = start.module;
    let currentImage = start.image;
    let ref = parsed.export;
    let forwardedFrom: string | undefined;
    const label = ref.kind === "name" ? ref.name : `#${String(ref.ordinal)}`;
    const unresolved = (forwarder: string) => err(forwarderUnresolved(op.name, forwarder, view.moduleMapId));
    const land = (
      module: SpaceModule,
      rva: number,
      image?: PeImage,
    ): Promise<Result<Resolution, BeaError>> | Result<never, BeaError> =>
      rvaInImage(rva, module.size)
        ? this.#finish(space, view, module, rva, op, {
            staticForm: false,
            ...(image === undefined ? {} : { image }),
            ...(forwardedFrom === undefined ? {} : { forwardedFrom }),
          })
        : err(rvaOutOfImage(op.name, path, module.size));
    for (let hop = 0; hop <= MAX_FORWARDER_HOPS; hop++) {
      const exports = await currentImage.exports();
      const wanted = ref;
      const hit = exports.find((e) => (wanted.kind === "name" ? e.name === wanted.name : e.ordinal === wanted.ordinal));
      if (hit === undefined) {
        if (hop > 0) return unresolved(forwardedFrom ?? label);
        return err(
          inputIssue(op.name, path, "invalid_value", "The module has no such export.", {
            reason: "export_not_found",
            module: current.name.slice(0, 260),
            export: label.slice(0, 300),
            similar: wanted.kind === "name" ? similarNames(exportNames(exports), wanted.name) : [],
          }),
        );
      }
      if (hit.forwarder === null && hit.rva !== null) return land(current, hit.rva + parsed.displacement, currentImage);
      const forwarder = hit.forwarder ?? "";
      forwardedFrom ??= `${start.module.name}!${label}`.slice(0, 600);
      const dot = forwarder.lastIndexOf(".");
      if (dot <= 0) return unresolved(forwarder);
      const targetModule = forwarder.slice(0, dot);
      const targetName = forwarder.slice(dot + 1);
      if (API_SET.test(targetModule)) {
        if (space.kind !== "live") return unresolved(forwarder);
        const bound = await this.#agentExport(space.session, current, label, op);
        if (bound === null) return unresolved(forwarder);
        const target = moduleAtVa(view.modules, bound);
        if (target === null) return ok(this.#nonImage(view, bound));
        return land(target, Number(bound - target.base) + parsed.displacement);
      }
      const next = selectModule(view.modules, { kind: "name", name: targetModule, base: null }, this.deps.platform);
      if (next.kind !== "found") return unresolved(forwarder);
      const nextImage = await this.imageOf(next.module, op.signal);
      if (nextImage === null) return unresolved(forwarder);
      current = next.module;
      currentImage = nextImage;
      ref = /^#\d{1,5}$/u.test(targetName)
        ? { kind: "ordinal", ordinal: Number(targetName.slice(1)) }
        : { kind: "name", name: targetName };
    }
    return unresolved(forwardedFrom ?? label);
  }

  async #agentExport(
    session: LiveSession,
    module: SpaceModule,
    name: string,
    op: OperationContext,
  ): Promise<bigint | null> {
    const reply = await session.agent.call(
      "resolveTargets",
      { targets: [{ module: module.name, export: name }] },
      { op },
    );
    if (!reply.ok) return null;
    const first = reply.value.results[0];
    return first !== undefined && first.ok ? BigInt(first.target.va) : null;
  }

  #nonImage(view: SpaceView, va: bigint): Resolution {
    return {
      ref: {
        va: formatHex(va),
        module: null,
        rva: null,
        static_va: null,
        static_base: null,
        static_base_source: null,
        module_map_id: view.moduleMapId,
      },
      va,
      module: null,
      rva: null,
      image: null,
      callerBaseDiffers: null,
      changedOnDisk: false,
      hashUnavailable: false,
      staticForm: false,
    };
  }

  /** Steps 3–6: bounds, va/static arithmetic, digest, changed-on-disk, symbol, section. */
  async #finish(
    space: AddressSpace,
    view: SpaceView,
    module: SpaceModule,
    rva: number,
    op: OperationContext,
    extra: {
      readonly staticForm: boolean;
      readonly staticBase?: bigint;
      readonly staticSource?: "caller" | "rea-evidence" | null;
      readonly callerBaseDiffers?: bigint | null;
      readonly image?: PeImage;
      readonly forwardedFrom?: string;
    },
  ): Promise<Result<Resolution, BeaError>> {
    const va = vaOfRva(module.base, rva);
    if (va === null)
      return err(inputIssue(op.name, "address", "out_of_range", "The mapped address leaves the user-mode range."));
    const image = extra.image ?? (await this.imageOf(module, op.signal));
    const preferred = module.preferredBase ?? (image === null ? null : BigInt(image.image_base));
    if (preferred !== null && module.path !== null) this.#preferred.set(this.#pathKey(module.path), preferred);
    const staticBase = extra.staticBase ?? preferred;
    // The provenance follows the space, not whether the module row carried a preferred base: a pe_path (file) space
    // also fills preferredBase from the PE header, and that base is the header's, not an emulator's.
    const staticSource =
      extra.staticSource ?? (staticBase === null ? null : space.kind === "emulation" ? "emulation" : "pe-header");
    const staticVa = staticBase === null ? null : staticOfRva(staticBase, rva);
    const sha = await this.sha256Of(module, op.signal);
    const symbol = image === null ? null : await this.symbolOf(module, image, rva, extra.forwardedFrom);
    const section = image?.sectionOf(rva) ?? null;
    let changedOnDisk = false;
    if (space.kind === "live" && module.path !== null)
      changedOnDisk = await changedSinceStart(module.path, space.session);
    const ref: AddressRef = {
      va: formatHex(va),
      module: module.name.slice(0, 260),
      rva: formatHex(rva),
      static_va: staticVa === null ? null : formatHex(staticVa),
      static_base: staticVa === null || staticBase === null ? null : formatHex(staticBase),
      static_base_source: staticVa === null ? null : staticSource,
      module_map_id: view.moduleMapId,
      image_sha256: sha,
      ...(symbol === null ? {} : { symbol }),
      ...(section === null ? {} : { section: section.name.slice(0, 16) }),
    };
    return ok({
      ref,
      va,
      module,
      rva,
      image,
      callerBaseDiffers: extra.callerBaseDiffers ?? null,
      changedOnDisk,
      hashUnavailable: sha === null,
      staticForm: extra.staticForm,
    });
  }

  /** S2 §18.3 over a live module address. */
  async verifyDetailed(
    session: LiveSession,
    module: SpaceModule,
    image: PeImage,
    rva: number,
    requested: number,
    op: OperationContext,
  ): Promise<Result<{ readonly detail: VerifyDetail; readonly footprintFailed: boolean }, BeaError>> {
    const without = (detail: VerifyDetail) => ok({ detail, footprintFailed: false });
    if (requested === 0) return without(verificationWithout("skipped", "zero_bytes_requested"));
    const section = image.sectionOf(rva);
    if (section === null && rva >= image.size_of_headers)
      return without(verificationWithout("not-applicable", "not_image"));
    if (section !== null && section.perms.includes("w"))
      return without(verificationWithout("not-applicable", "writable_section"));
    const len = Math.min(requested, module.size - rva);
    const va = module.base + BigInt(rva);
    const live = await readLive(session, va, len, op);
    if (!live.ok) return live;
    const window = new Uint8Array(len);
    window.set(live.value);
    const own = overlayOriginals(
      window.subarray(0, live.value.length),
      va,
      this.deps.evidence.effects.originalBytes(session.instanceId, va, len).ranges,
    );
    const { backed } = await image.readRva(rva, len);
    const expected = await image.imageBytes(rva, len, module.base);
    const loader: LoaderSpan[] = [...(await image.loaderWritten())];
    if (rva < image.size_of_headers) {
      // the loader rewrites OptionalHeader.ImageBase in the mapped header (= the runtime base)
      const lfanew = (await image.readRva(0x3c, 4)).bytes;
      const field = (lfanew[0] ?? 0) | ((lfanew[1] ?? 0) << 8) | ((lfanew[2] ?? 0) << 16) | ((lfanew[3] ?? 0) << 24);
      loader.push({ rva: field + 24 + 24, size: 8, class: "header" });
    }
    const compared = compareWindow({
      rva,
      len,
      live: window.subarray(0, live.value.length),
      ownRestored: own,
      expected,
      backed,
      loader,
    });
    // DATA-2: only modules the agent itself patches have a footprint; in any other module a code difference is
    // never the agent's, so it is `unexplained` (an empty footprint), not scanned from the very state being judged
    const footprint =
      compared.diffs.length === 0
        ? null
        : agentPatchesModule(module.name)
          ? await this.footprint.scan(session, module, image, op)
          : [];
    return ok({
      detail: finishVerification(compared, footprint),
      footprintFailed: compared.diffs.length > 0 && footprint === null,
    });
  }
}

/**
 * Review fix DATA-2: the modules Frida's agent patches on injection (S2 §18.4 VERIFIED: ntdll!LdrLoadDll, one
 * unexported ntdll function, kernel32!FatalExit; kernelbase for its forwarders). The footprint scan compares a module
 * with its file AT SCAN TIME, so it can only stand in for an injection-time baseline in modules whose only expected
 * code changes are the agent's (or another in-process hooker's: the class is foreign-or-agent-patch). In the main
 * module and every other one an inline hook, a trainer patch or decrypted/self-modifying code stays `unexplained`
 * (and dumps keep it).
 */
const AGENT_PATCHED_MODULES: ReadonlySet<string> = new Set(["ntdll.dll", "kernel32.dll", "kernelbase.dll"]);
export const agentPatchesModule = (moduleName: string): boolean =>
  AGENT_PATCHED_MODULES.has(baseNameOf(moduleName).toLowerCase());

const baseNameOf = (path: string): string => {
  const cut = Math.max(path.lastIndexOf("\\"), path.lastIndexOf("/"));
  return cut === -1 ? path : path.slice(cut + 1);
};

const exportNames = function* (exports: readonly PeExport[]): Iterable<string> {
  for (const e of exports) if (e.name !== null) yield e.name;
};

/** rva → first export name (lowest ordinal), with code/data from the section permissions. */
const exportIndex = (exports: readonly PeExport[], image: PeImage): Map<number, ExportEntry> => {
  const out = new Map<number, ExportEntry>();
  for (const e of exports) {
    if (e.rva === null || e.name === null || out.has(e.rva)) continue;
    out.set(e.rva, { rva: e.rva, name: e.name, code: image.sectionOf(e.rva)?.perms.includes("x") ?? false });
  }
  return out;
};

/** IMAGE_CHANGED_ON_DISK: the module file's times post-date the process start (S2 §16.3 step 5). */
const changedSinceStart = async (path: string, session: LiveSession): Promise<boolean> => {
  const started = startMs(session);
  if (started === null) return false;
  try {
    const st = await stat(path);
    return Math.max(st.mtimeMs, st.ctimeMs) > started + 1000;
  } catch {
    return false;
  }
};

const stripDetail = (detail: VerifyDetail): ByteVerification => ({
  status: detail.status,
  compared: detail.compared,
  equal: detail.equal,
  excluded_loader: detail.excluded_loader,
  own_effects_restored: detail.own_effects_restored,
  differences: detail.differences.map((d) => ({ rva: d.rva, size: d.size, class: d.class })),
});
