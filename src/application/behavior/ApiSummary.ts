import type { JsonObject, JsonValue } from "../../domain/json.js";
import type { EventRecord, SummaryBuilder } from "../../ports/recordings.js";

/**
 * ApiSummary (S6 §5.3 / §6.8): the bounded digest of an api recording, built from decoded events
 * (./apiEvents.ts). Each list keeps ≤ 50 rows in first-seen order plus a `distinct`/totals count; `truncated` is
 * true when any list hit its cap. Aggregation rules (S6 §6): \Device\Afd plumbing is not a file row; registry values
 * ≤ 8 names per key; memory allocs are individual only when executable, ≥ 1 MiB or remote (else aggregated); frees
 * are aggregated only; local thread creation is counted, remote threads are rows; a NtCreateUserProcess nested in a
 * CreateProcessInternalW row is not a second spawn.
 */
export const API_SUMMARY_LIST_CAP = 50;
const VALUES_PER_KEY = 8;
const LARGE_ALLOC = 1024 * 1024;

interface FileRow {
  path: string;
  kind: string;
  ops: string[];
  ok: number;
  failed: number;
  read_bytes: number;
  write_bytes: number;
  reads: number;
  writes: number;
  first_status: string | null;
}
interface KeyRow {
  key: string;
  ops: string[];
  values: string[];
  ok: number;
  failed: number;
}
interface Endpoint {
  endpoint: string;
  ops: string[];
  sent: number;
  received: number;
  failed: number;
}
interface ProcessRow {
  op: string;
  image?: string;
  cmdline?: string;
  pid?: number;
  access?: string[];
  ok: boolean;
  /** spawn rows: cross-process writes CreateProcess made into the new child itself (parameters, PEB pointer) */
  setup_writes?: number;
  setup_write_bytes?: number;
}
interface MemRow {
  op: string;
  va: string;
  size: number;
  from?: string;
  to: string;
  flags: string[];
}

export interface ApiSummaryState {
  readonly files: Map<string, FileRow>;
  readonly keys: Map<string, KeyRow>;
  readonly endpoints: Map<string, Endpoint>;
  readonly dns: Map<string, { name: string; ok: boolean; addresses: Set<string> }>;
  readonly http: { method: string; host: string; path: string }[];
  readonly processes: ProcessRow[];
  readonly loaded: Map<string, { path: string; base: string; size: number }>;
  readonly loadFailed: Map<string, { name: string; status: string }>;
  readonly resolved: Map<string, number>;
  /** flagged rows (wx, x_added, x, remote) are kept ahead of plain ones when the list is capped */
  readonly memory: MemRow[];
  readonly memoryPlain: MemRow[];
  readonly aggregated: { allocs: number; alloc_bytes: number; protects: number; frees: number };
  readonly totals: Map<string, number>;
  /** g of CreateProcessInternalW rows, and NtCreateUserProcess rows waiting for their parent (S6 §6.5 dedupe) */
  readonly spawnG: Set<number>;
  readonly nestedSpawns: Map<number, ProcessRow>;
  /**
   * Review fix ONBOARD-1: cross-process ops (write/read_process_memory, remote create_thread) nested in another API
   * call, waiting for that parent (inner calls leave first). A CreateProcess parent folds them into its spawn row;
   * any other parent keeps them as rows (a real injector's writes are never dropped).
   */
  readonly deferred: Map<number, { readonly row: ProcessRow; readonly bytes: number }[]>;
  readonly profiles: Set<string>;
  localThreads: number;
  truncated: boolean;
}

const str = (e: EventRecord, k: string): string | null => (typeof e[k] === "string" ? (e[k] as string) : null);
const int = (e: EventRecord, k: string): number | null => (typeof e[k] === "number" ? (e[k] as number) : null);
const detailOf = (e: EventRecord): JsonObject => {
  const d = e.detail;
  return typeof d === "object" && d !== null && !Array.isArray(d) ? (d as JsonObject) : {};
};
const stringsOf = (v: JsonValue | undefined): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];

const addOp = (ops: string[], op: string): void => {
  if (!ops.includes(op)) ops.push(op);
};

const bump = (m: Map<string, number>, k: string, by = 1): void => {
  m.set(k, (m.get(k) ?? 0) + by);
};

/** Get-or-create in a first-seen map, respecting the list cap (over-cap keys mark truncated and return null). */
const row = <T>(state: ApiSummaryState, map: Map<string, T>, key: string, make: () => T): T | null => {
  const existing = map.get(key);
  if (existing !== undefined) return existing;
  if (map.size >= API_SUMMARY_LIST_CAP) {
    state.truncated = true;
    return null;
  }
  const created = make();
  map.set(key, created);
  return created;
};

const pushCapped = <T>(state: ApiSummaryState, list: T[], item: T): void => {
  if (list.length >= API_SUMMARY_LIST_CAP) state.truncated = true;
  else list.push(item);
};

const addFile = (state: ApiSummaryState, e: EventRecord): void => {
  const kind = str(e, "kind") ?? "unknown";
  if (kind === "afd") return; // network plumbing (S6 §6.2)
  const path = str(e, "target") ?? "";
  const op = str(e, "op") ?? "?";
  const ok = e.ok === true;
  const r = row(state, state.files, path.toLowerCase(), () => ({
    path,
    kind,
    ops: [],
    ok: 0,
    failed: 0,
    read_bytes: 0,
    write_bytes: 0,
    reads: 0,
    writes: 0,
    first_status: null,
  }));
  if (r === null) return;
  if (r.kind === "unknown" || (r.kind === "file" && kind === "dir")) r.kind = kind;
  addOp(r.ops, op);
  if (ok) r.ok++;
  else {
    r.failed++;
    r.first_status ??= str(e, "status");
  }
  const bytes = int(e, "bytes");
  if (op === "read" && bytes !== null) {
    r.read_bytes += bytes;
    r.reads++;
  }
  if (op === "write" && bytes !== null) {
    r.write_bytes += bytes;
    r.writes++;
  }
  const to = detailOf(e).to;
  if (op === "rename" && ok && typeof to === "string") {
    const dest = row(state, state.files, to.toLowerCase(), () => ({
      path: to,
      kind: r.kind,
      ops: [],
      ok: 0,
      failed: 0,
      read_bytes: 0,
      write_bytes: 0,
      reads: 0,
      writes: 0,
      first_status: null,
    }));
    if (dest !== null) {
      addOp(dest.ops, "rename_dest");
      dest.ok++;
    }
  }
};

const addKey = (state: ApiSummaryState, e: EventRecord): void => {
  const key = str(e, "target") ?? "";
  const r = row(state, state.keys, key.toLowerCase(), () => ({ key, ops: [], values: [], ok: 0, failed: 0 }));
  if (r === null) return;
  addOp(r.ops, str(e, "op") ?? "?");
  if (e.ok === true) r.ok++;
  else r.failed++;
  const value = detailOf(e).value;
  if (typeof value === "string" && !r.values.includes(value)) {
    if (r.values.length < VALUES_PER_KEY) r.values.push(value);
    else state.truncated = true;
  }
};

const addNetwork = (state: ApiSummaryState, e: EventRecord): void => {
  const op = str(e, "op") ?? "?";
  const target = str(e, "target") ?? "";
  const ok = e.ok === true;
  const d = detailOf(e);
  if (op === "dns") {
    const r = state.dns.get(target.toLowerCase()) ?? { name: target, ok: false, addresses: new Set<string>() };
    if (!state.dns.has(target.toLowerCase())) {
      if (state.dns.size >= API_SUMMARY_LIST_CAP) {
        state.truncated = true;
        return;
      }
      state.dns.set(target.toLowerCase(), r);
    }
    r.ok ||= ok;
    for (const a of stringsOf(d.addresses)) r.addresses.add(a);
    return;
  }
  if (op === "http_request") {
    const method = typeof d.method === "string" ? d.method : "GET";
    const slash = target.search(/[/\\]/u);
    const scheme = /^[a-z]+:\/\//iu.exec(target);
    const rest = scheme === null ? target : target.slice(scheme[0].length);
    const cut = rest.indexOf("/");
    const host = scheme === null ? (slash < 0 ? target : target.slice(0, slash)) : cut < 0 ? rest : rest.slice(0, cut);
    const path = scheme === null ? (slash < 0 ? "/" : target.slice(slash)) : cut < 0 ? "/" : rest.slice(cut);
    pushCapped(state, state.http, { method, host, path });
    return;
  }
  if (op === "socket" || target.startsWith("<socket ")) return; // no endpoint known yet
  const r = row(state, state.endpoints, target, () => ({ endpoint: target, ops: [], sent: 0, received: 0, failed: 0 }));
  if (r === null) return;
  addOp(r.ops, op);
  const bytes = int(e, "bytes") ?? 0;
  if (!ok) r.failed++;
  else if (op === "send" || op === "sendto") r.sent += bytes;
  else if (op === "recv" || op === "recvfrom") r.received += bytes;
};

const addProcess = (state: ApiSummaryState, e: EventRecord): void => {
  const op = str(e, "op") ?? "?";
  const d = detailOf(e);
  const g = int(e, "g") ?? 0;
  const parent = int(e, "parent") ?? 0;
  const spawnParent = op === "spawn" && str(e, "api") === "kernelbase!CreateProcessInternalW";
  if (spawnParent) {
    state.spawnG.add(g);
    state.nestedSpawns.delete(g); // its NtCreateUserProcess (emitted first: inner calls leave first) is the same spawn
  }
  if (op === "create_thread" && d.remote !== true) {
    state.localThreads++;
    return;
  }
  const crossProcess = op === "write_process_memory" || op === "read_process_memory" || op === "create_thread";
  const r: ProcessRow = { op, ok: e.ok === true };
  const target = str(e, "target");
  if (op === "spawn" && target !== null) r.image = target;
  if (typeof d.cmdline === "string") r.cmdline = d.cmdline;
  if (typeof d.pid === "number") r.pid = d.pid;
  if (op === "open_process" && target !== null && target.startsWith("pid:")) r.pid = Number(target.slice(4));
  if (Array.isArray(d.access)) r.access = stringsOf(d.access);
  if (op !== "spawn" && op !== "open_process" && target !== null) r.image = target;
  if (op === "spawn" && str(e, "api") === "ntdll!NtCreateUserProcess" && parent !== 0) {
    if (!state.spawnG.has(parent)) state.nestedSpawns.set(parent, r); // kept unless its parent is a spawn row
    return;
  }
  if (crossProcess && parent !== 0 && !state.spawnG.has(parent)) {
    const waiting = state.deferred.get(parent) ?? [];
    waiting.push({ row: r, bytes: int(e, "size") ?? (typeof d.size === "number" ? d.size : 0) });
    state.deferred.set(parent, waiting);
    return;
  }
  if (spawnParent) {
    // ONBOARD-1: CreateProcess writes the child's process parameters and PEB pointer itself: not an injection
    const nested = state.deferred.get(g) ?? [];
    state.deferred.delete(g);
    const writes = nested.filter((n) => n.row.op === "write_process_memory");
    if (writes.length > 0) {
      r.setup_writes = writes.length;
      r.setup_write_bytes = writes.reduce((sum, n) => sum + n.bytes, 0);
    }
    for (const other of nested)
      if (other.row.op !== "write_process_memory") pushCapped(state, state.processes, other.row);
  }
  pushCapped(state, state.processes, r);
};

const addModule = (state: ApiSummaryState, e: EventRecord): void => {
  const op = str(e, "op") ?? "?";
  const target = str(e, "target") ?? "";
  const d = detailOf(e);
  if (op === "loaded") {
    row(state, state.loaded, `${target.toLowerCase()}@${String(d.base)}`, () => ({
      path: target,
      base: typeof d.base === "string" ? d.base : "0x0",
      size: typeof d.size === "number" ? d.size : 0,
    }));
  } else if (op === "load_request" && e.ok !== true) {
    row(state, state.loadFailed, target.toLowerCase(), () => ({ name: target, status: str(e, "status") ?? "failed" }));
  } else if (op === "resolve" && e.ok === true) {
    if (state.resolved.has(target) || state.resolved.size < API_SUMMARY_LIST_CAP) bump(state.resolved, target);
    else state.truncated = true;
  }
};

const addMemory = (state: ApiSummaryState, e: EventRecord): void => {
  const op = str(e, "op") ?? "?";
  const d = detailOf(e);
  const flags = stringsOf(d.flags);
  const size = typeof d.size === "number" ? d.size : 0;
  const ok = e.ok === true;
  if (op === "free") {
    if (ok) state.aggregated.frees++;
    if (str(e, "api") !== "bea!memmap") return;
  }
  if (op === "protect" && ok && str(e, "api") !== "bea!memmap") state.aggregated.protects++;
  if (op === "alloc" && ok && str(e, "api") !== "bea!memmap") {
    state.aggregated.allocs++;
    state.aggregated.alloc_bytes += size;
    const individual = flags.includes("wx") || flags.includes("x") || flags.includes("remote") || size >= LARGE_ALLOC;
    if (!individual) return;
  }
  if (!ok) return;
  const r: MemRow = { op, va: str(e, "target") ?? "0x0", size, to: typeof d.to === "string" ? d.to : "", flags };
  if (typeof d.from === "string") r.from = d.from;
  if (flags.some((f) => f !== "sampled" && f !== "seen_at_free")) pushCapped(state, state.memory, r);
  else pushCapped(state, state.memoryPlain, r);
};

const finishList = <T>(m: Map<string, T>): T[] => [...m.values()];

export const apiSummaryBuilder: SummaryBuilder<ApiSummaryState> = {
  init: () => ({
    files: new Map(),
    keys: new Map(),
    endpoints: new Map(),
    dns: new Map(),
    http: [],
    processes: [],
    loaded: new Map(),
    loadFailed: new Map(),
    resolved: new Map(),
    memory: [],
    memoryPlain: [],
    aggregated: { allocs: 0, alloc_bytes: 0, protects: 0, frees: 0 },
    totals: new Map(),
    spawnG: new Set(),
    nestedSpawns: new Map(),
    deferred: new Map(),
    profiles: new Set(),
    localThreads: 0,
    truncated: false,
  }),
  add: (state, e) => {
    const profile = str(e, "profile");
    if (profile === null) return;
    state.profiles.add(profile);
    bump(state.totals, profile);
    if (e.ok !== true) bump(state.totals, "failed");
    switch (profile) {
      case "file":
        return addFile(state, e);
      case "registry":
        return addKey(state, e);
      case "network":
        return addNetwork(state, e);
      case "process":
        return addProcess(state, e);
      case "module_load":
        return addModule(state, e);
      case "memory_protection":
        return addMemory(state, e);
      default:
        return;
    }
  },
  finish: (state) => {
    const out: Record<string, JsonValue> = {};
    if (state.profiles.has("file"))
      out.file = {
        distinct: state.files.size,
        rows: finishList(state.files).map((r) => ({
          path: r.path,
          kind: r.kind,
          ops: r.ops,
          ok: r.ok,
          failed: r.failed,
          ...(r.reads > 0 ? { read_bytes: r.read_bytes } : {}),
          ...(r.writes > 0 ? { write_bytes: r.write_bytes } : {}),
          ...(r.first_status !== null ? { first_status: r.first_status } : {}),
        })),
      };
    if (state.profiles.has("registry"))
      out.registry = {
        distinct: state.keys.size,
        rows: finishList(state.keys).map((r) => ({ ...r })),
      };
    if (state.profiles.has("network")) {
      const hostByAddr = new Map<string, string>();
      for (const d of state.dns.values()) for (const a of d.addresses) hostByAddr.set(a, d.name);
      out.network = {
        endpoints: finishList(state.endpoints).map((r) => {
          const addr = /^\[?([^\]]*?)\]?:\d+\//u.exec(r.endpoint)?.[1];
          const host = addr === undefined ? undefined : hostByAddr.get(addr);
          return { ...r, ...(host !== undefined ? { host } : {}) };
        }),
        dns: [...state.dns.values()].map((d) => ({ name: d.name, ok: d.ok })),
        http: state.http,
      };
    }
    if (state.profiles.has("process")) {
      // deferred rows whose parent was no spawn are kept (a real injector's writes inside its own wrapper)
      const leftover = [...state.deferred.values()].flat().map((n) => n.row);
      const rows = [...state.processes, ...state.nestedSpawns.values(), ...leftover];
      if (rows.length > API_SUMMARY_LIST_CAP) state.truncated = true;
      out.process = { rows: rows.slice(0, API_SUMMARY_LIST_CAP).map((r) => ({ ...r })) };
    }
    if (state.profiles.has("module_load"))
      out.module_load = {
        loaded: finishList(state.loaded),
        failed: finishList(state.loadFailed),
        resolved: [...state.resolved].map(([name, count]) => ({ name, count })),
      };
    if (state.profiles.has("memory_protection"))
      out.memory_protection = {
        rows: [...state.memory, ...state.memoryPlain].slice(0, API_SUMMARY_LIST_CAP).map((r) => ({ ...r })),
        aggregated: {
          allocs: state.aggregated.allocs,
          alloc_bytes: state.aggregated.alloc_bytes,
          protects: state.aggregated.protects,
        },
      };
    const totals: Record<string, number> = Object.fromEntries(state.totals);
    if (state.localThreads > 0) totals.local_threads = state.localThreads;
    if (state.aggregated.frees > 0) totals.frees = state.aggregated.frees;
    out.totals = totals;
    out.truncated = state.truncated || state.memory.length + state.memoryPlain.length > API_SUMMARY_LIST_CAP;
    return out;
  },
};
