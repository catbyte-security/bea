// The generic profile listener logic (S4 §10.6 "Generic listener"): filters, sequence/time stamps, parent tracking,
// enter/leave decoding, handle-cache maintenance and ApiRow emission. Pure and generic over the pointer type P; the
// GumJS glue (src/agent/profiles.ts) does the Cloak/agent-call filtering and calls enter()/leave() from Interceptor.
import type { ApiRow, DropReason, ValueCell } from "../../shared/agentProtocol.js";
import type { ApiSpec } from "../../shared/apiProfiles.js";
import type { Hex } from "../../shared/hex.js";
import {
  callSucceeded,
  captureRaw,
  cellText,
  decodeEnter,
  decodeLeave,
  endpointText,
  openedName,
  retCell,
  type DecodeEnv,
  type SockName,
} from "./profileDecode.js";
import type { Cells } from "./profileTypes.js";

export interface EngineOptions {
  /** per-API row cap (ProfileOptions.per_api_max_events) */
  readonly perApiMax: number;
  /** instrument row cap (Lifetime.max_hits) */
  readonly maxHits: number;
  /** null = all threads */
  readonly threadIds: ReadonlySet<number> | null;
}

export interface EngineSink<P> {
  nextG(): number;
  nowUs(): number;
  emit(row: ApiRow): void;
  /** called once when maxHits rows were recorded (the glue schedules the stop; never detach inside a callback) */
  onMaxHits(): void;
  /** getsockname for sockets bound to port 0 (agent only); null when unavailable */
  localEndpoint(socket: P): SockName | null;
}

export interface CallCtx<P> {
  readonly tid: number;
  /** Interceptor depth (F4): 0 = outermost hooked call on this thread */
  readonly depth: number;
  readonly args: (index: number) => P;
  /** first caller outside system modules (computed lazily, only for rows) */
  readonly caller: () => Hex;
}

export interface CallState<P> {
  readonly spec: ApiSpec;
  readonly g: number;
  readonly t: number;
  readonly tid: number;
  readonly depth: number;
  readonly parent: number;
  readonly raw: readonly P[];
  readonly cells: Cells;
  readonly caller: Hex;
}

export interface EngineCounters {
  hits: number;
  recorded: number;
  filtered: number;
  errors: number;
  unreturned: number;
  dropped: Partial<Record<DropReason, number>>;
}

const STACK_MAX = 64;
const WSAEWOULDBLOCK = 10035;

export class ProfileEngine<P> {
  readonly counters: EngineCounters = { hits: 0, recorded: 0, filtered: 0, errors: 0, unreturned: 0, dropped: {} };
  /** the detached guard (S4 §10.2): false from the first stop step on */
  active = true;
  private readonly perApi = new Map<number, number>();
  private readonly stacks = new Map<number, number[]>();
  private capReported = false;

  constructor(
    private readonly env: DecodeEnv<P>,
    private readonly sink: EngineSink<P>,
    private readonly options: EngineOptions,
  ) {}

  drop(reason: DropReason): void {
    this.counters.dropped[reason] = (this.counters.dropped[reason] ?? 0) + 1;
  }

  /** onEnter. Returns the per-call state for onLeave, or null when the call produces nothing at leave. */
  enter(spec: ApiSpec, ctx: CallCtx<P>): CallState<P> | null {
    if (!this.active) return null;
    if (this.options.threadIds !== null && !this.options.threadIds.has(ctx.tid)) {
      this.counters.filtered++;
      return null;
    }
    const raw = captureRaw(ctx.args, spec);
    if (!spec.rows) return this.maintenanceState(spec, ctx, raw);
    if (spec.emit_when !== undefined && !this.compare(spec, raw, spec.emit_when)) {
      this.counters.filtered++;
      return null;
    }
    this.counters.hits++;
    const seen = (this.perApi.get(spec.id) ?? 0) + 1;
    this.perApi.set(spec.id, seen);
    if (seen > this.options.perApiMax) {
      this.drop("per_api_cap");
      return null;
    }
    const g = this.sink.nextG();
    const t = this.sink.nowUs();
    const stack = this.stackOf(ctx.tid, ctx.depth);
    const parent = stack.length > 0 ? (stack[stack.length - 1] ?? 0) : 0;
    stack.push(g);
    let cells: Cells;
    try {
      cells = decodeEnter(this.env, spec, raw);
    } catch {
      this.counters.errors++;
      cells = {};
    }
    const state: CallState<P> = {
      spec,
      g,
      t,
      tid: ctx.tid,
      depth: ctx.depth,
      parent,
      raw,
      cells,
      caller: safeCaller(ctx.caller),
    };
    if (spec.noreturn_when !== undefined && this.compare(spec, raw, spec.noreturn_when)) {
      this.pop(state);
      this.record([g, t, ctx.tid, ctx.depth, parent, spec.id, cells, null, state.caller]);
      return null;
    }
    return state;
  }

  /** onLeave: leave decoders, cache maintenance, then the row. */
  leave(state: CallState<P>, ret: P, lastError: number): void {
    const { spec } = state;
    const mem = this.env.mem;
    let ok = false;
    try {
      ok = callSucceeded(mem, spec, ret);
    } catch {
      this.counters.errors++;
    }
    if (!spec.rows) {
      if (ok) this.evict(state.raw);
      return;
    }
    this.pop(state);
    const cells = state.cells;
    try {
      decodeLeave(this.env, spec, state.raw, ret, ok, cells);
      if (!ok && (spec.ret === "i32" || spec.ret === "socket" || spec.ret === "bool32" || spec.ret === "handle"))
        cells.last_error = lastError;
      this.maintainCache(spec, state, ret, ok, lastError);
    } catch {
      this.counters.errors++;
    }
    if (!this.active) {
      this.drop("stopped");
      return;
    }
    let retValue: ValueCell = null;
    try {
      retValue = retCell(mem, spec, ret);
    } catch {
      this.counters.errors++;
    }
    this.record([state.g, state.t, state.tid, state.depth, state.parent, spec.id, cells, retValue, state.caller]);
  }

  /** A row produced by an agent observer (memmap watcher, module observer) on the same stream. */
  emitPseudo(apiId: number, tid: number, cells: Cells): void {
    if (!this.active) return;
    this.counters.hits++;
    this.record([this.sink.nextG(), this.sink.nowUs(), tid, 0, 0, apiId, cells, null, "0x0"]);
  }

  private record(row: ApiRow): void {
    if (this.counters.recorded >= this.options.maxHits) {
      this.drop("instrument_cap");
      return;
    }
    this.counters.recorded++;
    this.sink.emit(row);
    if (this.counters.recorded >= this.options.maxHits && !this.capReported) {
      this.capReported = true;
      this.active = false;
      this.sink.onMaxHits();
    }
  }

  private maintenanceState(spec: ApiSpec, ctx: CallCtx<P>, raw: readonly P[]): CallState<P> {
    return { spec, g: 0, t: 0, tid: ctx.tid, depth: ctx.depth, parent: 0, raw, cells: {}, caller: "0x0" };
  }

  /** NtClose (rows:false): the closed handle leaves the cache. */
  private evict(raw: readonly P[]): void {
    const first = raw[0];
    if (first !== undefined) this.env.cache.delete(this.env.mem.hex(first));
  }

  private compare(spec: ApiSpec, raw: readonly P[], rule: { arg: string; op: "eq" | "ne"; value: Hex }): boolean {
    const arg = spec.args.find((a) => a.name === rule.arg);
    const v = arg === undefined ? undefined : raw[arg.slot];
    if (v === undefined) return rule.op === "ne";
    const equal = this.env.mem.hex(v) === rule.value;
    return rule.op === "eq" ? equal : !equal;
  }

  /** Per-thread parent stack. An outermost call (depth 0) starts a fresh stack: earlier unbalanced frames
   *  (leave never seen: longjmp/unwind) are counted as unreturned and discarded. */
  private stackOf(tid: number, depth: number): number[] {
    let stack = this.stacks.get(tid);
    if (stack === undefined) {
      stack = [];
      this.stacks.set(tid, stack);
    } else if (depth === 0 && stack.length > 0) {
      this.counters.unreturned += stack.length;
      stack.length = 0;
    } else if (stack.length >= STACK_MAX) {
      this.counters.unreturned += stack.length - STACK_MAX + 1;
      stack.splice(0, stack.length - STACK_MAX + 1);
    }
    return stack;
  }

  private pop(state: CallState<P>): void {
    const stack = this.stacks.get(state.tid);
    if (stack === undefined) return;
    const i = stack.lastIndexOf(state.g);
    if (i >= 0) {
      this.counters.unreturned += stack.length - i - 1;
      stack.length = i;
    }
  }

  /** Handle-cache inserts/updates/evictions after a call (S4 §10.6 "Handle cache"). */
  private maintainCache(spec: ApiSpec, state: CallState<P>, ret: P, ok: boolean, lastError: number): void {
    const { mem, cache } = this.env;
    const cells = state.cells;
    if (ok) {
      for (const arg of spec.args) {
        if (arg.d.k !== "out_handle") continue;
        const h = cells[arg.name];
        if (typeof h === "string") cache.set(h, { kind: arg.d.kind, name: openedName(spec, cells, arg.d.kind) });
      }
    }
    const socketArg = spec.args.find((a) => a.d.k === "handle" && a.d.kind === "socket");
    const socketHex = socketArg === undefined ? null : mem.hex(state.raw[socketArg.slot] as P);
    switch (spec.op) {
      case "socket":
        if (ok) cache.set(mem.hex(ret), { kind: "socket", name: null, proto: protoOf(cells.type) });
        return;
      case "bind": {
        if (!ok || socketHex === null) return;
        const entry = cache.get(socketHex) ?? { kind: "socket", name: null };
        let name = sockCellText(cells, "local");
        if (name !== null && name.endsWith(":0")) {
          const actual = this.sink.localEndpoint(state.raw[socketArg?.slot ?? 0] as P);
          if (actual !== null) {
            name = endpointText(actual);
            cells.local_bound = { s: name };
          }
        }
        cache.set(socketHex, { ...entry, name });
        return;
      }
      case "connect": {
        if ((!ok && lastError !== WSAEWOULDBLOCK) || socketHex === null) return;
        const entry = cache.get(socketHex) ?? { kind: "socket", name: null };
        cache.set(socketHex, { ...entry, name: sockCellText(cells, "remote") });
        return;
      }
      case "accept": {
        if (!ok || socketHex === null) return;
        const listener = cache.get(socketHex);
        const entry: { kind: string; name: string | null; proto?: string } = {
          kind: "socket",
          name: listener?.name ?? null,
        };
        if (listener?.proto !== undefined) entry.proto = listener.proto;
        cache.set(mem.hex(ret), entry);
        return;
      }
      case "close":
        if (ok && socketHex !== null) cache.delete(socketHex);
        return;
      case "load_request": {
        // LdrLoadDll(…, DllName, *DllHandle): the module handle is its base; later resolve/unload rows name it
        const base = cells.base;
        const name = cellText(cells.name);
        if (ok && typeof base === "string" && name !== null)
          cache.set(base, { kind: "module", name: name.slice(name.lastIndexOf("\\") + 1) });
        return;
      }
      case "http_connect":
        if (ok) {
          const server = cellText(cells.server) ?? "";
          const port = typeof cells.port === "number" ? cells.port : 0;
          cache.set(mem.hex(ret), { kind: "inet", name: `${server}:${String(port)}` });
        }
        return;
      case "http_request": {
        if (!ok || spec.export === "InternetOpenUrlW") return;
        const conn = cellText(cells.connection_name);
        cache.set(mem.hex(ret), { kind: "inet", name: conn });
        return;
      }
      default:
        return;
    }
  }
}

const safeCaller = (f: () => Hex): Hex => {
  try {
    return f();
  } catch {
    return "0x0";
  }
};

const protoOf = (type: ValueCell | undefined): string =>
  type === 1 ? "tcp" : type === 2 ? "udp" : type === 3 ? "raw" : "unknown";

const sockCellText = (cells: Cells, name: string): string | null => {
  const addr = cellText(cells[`${name}_addr`]);
  const port = cells[`${name}_port`];
  const family = cells[`${name}_family`];
  if (addr === null || typeof port !== "number") return null;
  return endpointText({ family: typeof family === "number" ? family : 2, addr, port });
};
