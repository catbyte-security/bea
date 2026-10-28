// =================================================================================================
// src/agent/inspect.ts — WP3-AGENT inspection RPCs (S4 §8.1, §8.5; core per D-INT-36): processInfo, listModules /
// Exports / Imports / Sections / Functions, findFunction (exact .pdata fragments), listRanges (TTL snapshots, BEA
// guard pages re-inserted with their original protection, CT-I5 [CT-lab E16b]), listThreads (the agent JS thread is
// cloaked and never listed), resolveTargets and describeAddresses (export_hint is the nearest preceding export, a
// HINT only; DebugSymbol is never used for names). In-memory facts only: preferred base, file hashes and long
// section names are host-side.
// =================================================================================================
import type {
  AddressDescription,
  AgentError,
  AgentRpcImpl,
  DescribeAddressesParams,
  ExportRow,
  FindFunctionParams,
  FunctionRange,
  FunctionRow,
  Hex,
  ImportRow,
  ListExportsParams,
  ListFunctionsParams,
  ListImportsParams,
  ListModulesParams,
  ListRangesParams,
  ListRangesResult,
  ListSectionsParams,
  ListThreadsParams,
  ProcessInfo,
  RangeRow,
  ResolvedTarget,
  ResolveTargetsParams,
  SectionRow,
  TargetRef,
  ThreadInfo,
} from "../shared/agentProtocol.js";
import { allRegisters, capturedGprs } from "./capture.js";
import { big, hex, toPtr } from "./encode.js";
import { badParam, fail, mapThrown, notFound, ok } from "./errors.js";
import { hexOfBigint, hexOfNumber, parseHexText } from "./pure/coreHex.js";
import { isChainedUnwind, parseDelayImports } from "./pure/corePe.js";
import { globToRegExp, paginate, reinsertGuardPages, TtlLru, type RangeRec } from "./pure/coreRanges.js";
import { TEB } from "./pure/coreWin64.js";
import type { AgentCore } from "./state.js";

const MAX_TARGETS = 1024;

const isAgentError = (v: object): v is AgentError => "_tag" in v;

const moduleOrError = (c: AgentCore, name: string): Module | AgentError =>
  c.modules.byName(name) ?? { _tag: "ModuleNotFound", message: "module not found", module: name };

const pageLimit = (c: AgentCore, limit: number): number => Math.min(limit, c.limits.list_page_max);

/** PEB of the process (TEB+0x60 of the calling thread). */
const pebOf = (c: AgentCore): Hex | null => {
  try {
    return hex(c.native.currentTeb().add(TEB.peb).readPointer());
  } catch {
    return null;
  }
};

export const processInfo = (c: AgentCore): ProcessInfo => ({
  pid: Process.id,
  arch: "x64",
  platform: Process.platform === "linux" ? "linux" : "windows",
  page_size: Process.pageSize,
  pointer_size: 8,
  main_module: c.modules.info(Process.mainModule, true),
  peb: pebOf(c),
  current_dir: Process.getCurrentDir(),
  debugger_present: Process.isDebuggerAttached(),
  code_signing_policy: Process.codeSigningPolicy,
  frida_heap_bytes: Frida.heapSize,
  js_thread_id: c.jsTid,
  module_map_epoch: c.modules.epoch,
});

const listModules = (c: AgentCore, p: ListModulesParams) => {
  const re = p.name_glob === undefined ? null : globToRegExp(p.name_glob);
  const modules = c.modules
    .list()
    .filter((m) => re === null || re.test(m.name))
    .map((m) => c.modules.info(m, p.with_pe === true));
  return ok({ module_map_epoch: c.modules.epoch, modules });
};

const listExports = (c: AgentCore, p: ListExportsParams) => {
  const m = moduleOrError(c, p.module);
  if (isAgentError(m)) return fail(m);
  const re = p.name_glob === undefined ? null : globToRegExp(p.name_glob);
  const rows: ExportRow[] = c.modules
    .exports(m)
    .filter((e) => (re === null || re.test(e.name)) && (p.kind === undefined || e.kind === p.kind))
    .map((e) => ({ name: e.name, kind: e.kind, va: hexOfBigint(e.va), rva: hexOfBigint(e.va - big(m.base)) }));
  return ok(paginate(rows, p.offset, p.limit, pageLimit(c, p.limit)));
};

const importsOf = (c: AgentCore, m: Module): ImportRow[] => {
  const rows: ImportRow[] = [];
  for (const imp of m.enumerateImports()) {
    const ordinal = imp.name.startsWith("#") ? Number.parseInt(imp.name.slice(1), 10) : null;
    rows.push({
      name: ordinal === null ? imp.name : null,
      ordinal: ordinal !== null && Number.isFinite(ordinal) ? ordinal : null,
      from_module: imp.module ?? null,
      kind: imp.type ?? null,
      slot: imp.slot === undefined ? null : hex(imp.slot),
      resolved: imp.address === undefined ? null : hex(imp.address),
      delay: false,
    });
  }
  const h = c.modules.headers(m);
  if (h === null) return rows;
  const lo = big(m.base);
  const hi = lo + BigInt(m.size);
  for (const d of parseDelayImports(c.modules.reader(m), h)) {
    const slot = m.base.add(d.slotRva);
    let resolved: Hex | null = null;
    try {
      const v = big(slot.readPointer());
      resolved = v !== 0n && (v < lo || v >= hi) ? hexOfBigint(v) : null;
    } catch {
      resolved = null;
    }
    rows.push({
      name: d.name,
      ordinal: d.ordinal,
      from_module: d.dll,
      kind: "function",
      slot: hex(slot),
      resolved,
      delay: true,
    });
  }
  return rows;
};

const listImports = (c: AgentCore, p: ListImportsParams) => {
  const m = moduleOrError(c, p.module);
  if (isAgentError(m)) return fail(m);
  const re = p.name_glob === undefined ? null : globToRegExp(p.name_glob);
  const rows = importsOf(c, m).filter((r) => re === null || (r.name !== null && re.test(r.name)));
  return ok(paginate(rows, p.offset, p.limit, pageLimit(c, p.limit)));
};

const listSections = (c: AgentCore, p: ListSectionsParams) => {
  const m = moduleOrError(c, p.module);
  if (isAgentError(m)) return fail(m);
  const sections: SectionRow[] = c.modules.sections(m).map((s) => {
    const va = m.base.add(s.rva);
    return {
      raw_name: s.rawName,
      va: hex(va),
      rva: hexOfNumber(s.rva),
      virtual_size: s.virtualSize,
      characteristics: s.characteristics,
      protection: protectionAt(c, va),
    };
  });
  return ok({ sections });
};

const listFunctions = (c: AgentCore, p: ListFunctionsParams) => {
  const m = moduleOrError(c, p.module);
  if (isAgentError(m)) return fail(m);
  const t = c.modules.pdata(m);
  const lo = p.rva_min === undefined ? 0 : Number(parseHexText(p.rva_min) ?? 0n);
  const hi = p.rva_max === undefined ? Number.MAX_SAFE_INTEGER : Number(parseHexText(p.rva_max) ?? 0n);
  const read = c.modules.reader(m);
  const rows: FunctionRow[] = [];
  for (let i = 0; i < t.begins.length; i++) {
    const begin = t.begins[i]!;
    if (begin < lo || begin > hi) continue;
    rows.push({
      begin_rva: hexOfNumber(begin),
      end_rva: hexOfNumber(t.ends[i]!),
      unwind_rva: hexOfNumber(t.unwinds[i]!),
      chained: false,
    });
  }
  const page = paginate(rows, p.offset, p.limit, pageLimit(c, p.limit));
  for (const row of page.items) row.chained = isChainedUnwind(read, Number(parseHexText(row.unwind_rva) ?? 0n));
  return ok(page);
};

/** Exact function fragment: the module's .pdata, else a dynamic function table via Frida (non-module code). */
export const functionRangeOf = (c: AgentCore, address: NativePointer): FunctionRange | null => {
  const fr = c.modules.functionRange(address);
  if (fr !== null) return { base: hex(fr.base), size: fr.size, source: "pdata" };
  if (c.modules.find(address) !== null) return null;
  const dyn = Process.findFunctionRange(address);
  return dyn === null ? null : { base: hex(dyn.base), size: dyn.size, source: "pdata" };
};

const findFunction = (c: AgentCore, p: FindFunctionParams) => ok(functionRangeOf(c, toPtr(p.address)));

/** Protection at an address; BEA-guarded pages report their original protection (Frida omits them). */
const protectionAt = (c: AgentCore, address: NativePointer): string | null => {
  const g = c.guards.find(address);
  if (g !== null) return c.guards.listingPages().find((r) => r.base === big(g.base))?.protection ?? null;
  return Process.findRangeByAddress(address)?.protection ?? null;
};

const rangeOf = (c: AgentCore, address: NativePointer): AddressDescription["range"] => {
  const g = c.guards.find(address);
  if (g !== null) return { base: hex(g.base), size: Process.pageSize, protection: protectionAt(c, address) ?? "---" };
  const r = Process.findRangeByAddress(address);
  return r === null ? null : { base: hex(r.base), size: r.size, protection: r.protection };
};

interface Snapshot {
  readonly rows: RangeRow[];
  readonly takenT: number;
}

const snapshots = new Map<string, TtlLru<Snapshot>>();
let snapshotSeq = 0;

const snapshotStore = (c: AgentCore): TtlLru<Snapshot> => {
  const key = `${c.limits.snapshot_ttl_ms}/${c.limits.max_snapshots}`;
  let store = snapshots.get(key);
  if (store === undefined) {
    store = new TtlLru<Snapshot>(c.limits.snapshot_ttl_ms, c.limits.max_snapshots);
    snapshots.clear();
    snapshots.set(key, store);
  }
  return store;
};

const takeRanges = (c: AgentCore, p: ListRangesParams): RangeRow[] => {
  if (p.kind === "malloc")
    return Process.enumerateMallocRanges().map((r) => ({
      base: hex(r.base),
      size: r.size,
      protection: r.protection ?? "rw-",
      module: c.modules.find(r.base)?.name ?? null,
      kind: "malloc" as const,
    }));
  const live: RangeRec[] = Process.enumerateRanges({
    protection: p.protection as PageProtection,
    coalesce: p.coalesce,
  }).map((r) => ({ base: big(r.base), size: r.size, protection: r.protection }));
  const merged = reinsertGuardPages(live, c.guards.listingPages(), p.protection, p.coalesce);
  const wantModule = p.module?.toLowerCase();
  const rows: RangeRow[] = [];
  for (const r of merged) {
    const base = ptr(hexOfBigint(r.base));
    const m = c.modules.find(base);
    const kind = m === null ? "private" : "module";
    if (p.kind !== "all" && p.kind !== kind) continue;
    if (wantModule !== undefined && m?.name.toLowerCase() !== wantModule) continue;
    rows.push({ base: hex(base), size: r.size, protection: r.protection, module: m?.name ?? null, kind });
  }
  return rows;
};

const listRanges = (c: AgentCore, p: ListRangesParams) => {
  if (!/^[r-][w-][x-]$/u.test(p.protection ?? ""))
    return fail(badParam("protection", 'a protection filter like "rw-"'));
  const store = snapshotStore(c);
  const now = Date.now();
  let id = p.snapshot;
  let snap: Snapshot | null = null;
  if (id !== undefined) {
    snap = store.get(id, now);
    if (snap === null) return fail(notFound("snapshot", id));
  } else {
    id = `ss${++snapshotSeq}`;
    snap = { rows: takeRanges(c, p), takenT: c.native.nowUs() };
    store.put(id, snap, now);
  }
  const page = paginate(snap.rows, p.offset, p.limit, pageLimit(c, p.limit));
  const result: ListRangesResult = { ...page, snapshot: id, taken_t: snap.takenT };
  return ok(result);
};

const listThreads = (c: AgentCore, p: ListThreadsParams) => {
  const threads: ThreadInfo[] = c.threads.enumerate().map((t) => {
    const teb = p.teb ? c.threads.teb(t.id) : null;
    return {
      id: t.id,
      state: t.state,
      entry: t.entrypoint === undefined ? null : hex(t.entrypoint.routine),
      teb: teb === null ? null : hex(teb),
      stack: p.teb ? c.threads.stack(t.id) : null,
      name: p.names ? c.threads.name(t.id) : null,
      regs: p.registers === "none" ? null : p.registers === "all" ? allRegisters(t.context) : capturedGprs(t.context),
      bea_role: t.id === c.jsTid ? "agent" : null,
    };
  });
  return ok({ threads });
};

const resolvedAt = (c: AgentCore, va: NativePointer, exportName: string | null): ResolvedTarget => {
  const m = c.modules.find(va);
  return {
    va: hex(va),
    module: m?.name ?? null,
    module_base: m === null ? null : hex(m.base),
    rva: m === null ? null : hex(va.sub(m.base)),
    export: exportName ?? (m === null ? null : c.modules.exportAt(m, big(va))),
    function: functionRangeOf(c, va),
    protection: protectionAt(c, va),
  };
};

export const resolveTarget = (c: AgentCore, t: TargetRef): ResolvedTarget | AgentError => {
  if ("va" in t) return resolvedAt(c, toPtr(t.va), null);
  const m = moduleOrError(c, t.module);
  if (isAgentError(m)) return m;
  if ("export" in t) {
    const va = m.findExportByName(t.export);
    return va === null
      ? { _tag: "ExportNotFound", message: "export not found", module: m.name, export: t.export }
      : resolvedAt(c, va, t.export);
  }
  const rva = parseHexText(t.rva);
  if (rva === null || rva >= BigInt(m.size)) return badParam("rva", `outside ${m.name} (size ${m.size})`);
  return resolvedAt(c, m.base.add(hexOfBigint(rva)), null);
};

const resolveTargets = (c: AgentCore, p: ResolveTargetsParams) => {
  if (!Array.isArray(p.targets) || p.targets.length > MAX_TARGETS)
    return fail(badParam("targets", `1..${MAX_TARGETS} targets`));
  const results = p.targets.map((t) => {
    try {
      const r = resolveTarget(c, t);
      return isAgentError(r) ? { ok: false as const, error: r } : { ok: true as const, target: r };
    } catch (e) {
      return { ok: false as const, error: mapThrown(e, "resolveTargets") };
    }
  });
  return ok({ results });
};

const describeAddresses = (c: AgentCore, p: DescribeAddressesParams) => {
  if (!Array.isArray(p.addresses) || p.addresses.length > MAX_TARGETS)
    return fail(badParam("addresses", `1..${MAX_TARGETS} addresses`));
  const results: AddressDescription[] = p.addresses.map((a) => {
    const va = toPtr(a);
    const m = c.modules.find(va);
    return {
      va: hex(va),
      module: m?.name ?? null,
      rva: m === null ? null : hex(va.sub(m.base)),
      function: functionRangeOf(c, va),
      range: rangeOf(c, va),
      export_hint: m === null ? null : c.modules.exportHint(m, big(va)),
      bea_patched: c.originals.isPatched(va, 1),
      bea_guarded: c.guards.ownsPage(va),
    };
  });
  return ok({ results });
};

let bound: AgentCore | null = null;
const core = (): AgentCore => {
  if (bound === null) throw new Error("inspect.init() has not run");
  return bound;
};

/** Feature contract: index.ts calls init(core) before spreading `rpc`. */
export function init(c: AgentCore): void {
  bound = c;
}

export const rpc = {
  processInfo: () => ok(processInfo(core())),
  listModules: (p) => listModules(core(), p),
  listExports: (p) => listExports(core(), p),
  listImports: (p) => listImports(core(), p),
  listSections: (p) => listSections(core(), p),
  listFunctions: (p) => listFunctions(core(), p),
  findFunction: (p) => findFunction(core(), p),
  listRanges: (p) => listRanges(core(), p),
  listThreads: (p) => listThreads(core(), p),
  resolveTargets: (p) => resolveTargets(core(), p),
  describeAddresses: (p) => describeAddresses(core(), p),
} satisfies Partial<AgentRpcImpl>;
