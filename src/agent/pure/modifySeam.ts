// Agent pure helper of WP12-MODIFY: the narrow seam memwrite.ts / override.ts use to reach WP3's core services.
//
// The feature files bind to the core STRUCTURALLY at init (no GumJS here; `P` is the pointer type): each service is
// looked up under its S4 §5.1 name on the core object and adapted when it has WP3's methods (originals.save(site,
// n, owner) / release(site, owner) / isPatched / markPatched, guards.intersecting, stalkerCo.invalidateAll,
// instruments.register(spec) → Instrument{id, hit(), active, counters}, streams.open/emit/close with native.nextG/nowUs,
// calls.bypassesOverrides, hooks.onDispose[]). A missing service degrades to the local fallback documented on each
// member, so the features also work against the day-0 core (and in the raw-agent acceptance harness).
import type {
  AgentError,
  EndReason,
  Hex,
  InstrumentCounters,
  InstrumentSummary,
  Lifetime,
  ThreadId,
} from "../../shared/agentProtocol.js";

/** S4 §8.4 OriginalBytes, owner-keyed (the adapter remembers each owner's site). */
export interface OriginalsService<P> {
  save(owner: string, site: P, size: number): void;
  /** after the patch is in place: the expected patched head for fingerprint() */
  markPatched(owner: string): void;
  release(owner: string): void;
  /** true when [address, address+size) overlaps any BEA patch (any owner) */
  isPatched(address: P, size: number): boolean;
}

/** What the instrument registry runs to stop an override (S4 §5.7 step 2 + verification). */
export interface RevertResult {
  readonly reverted: boolean;
  readonly verification: InstrumentSummary["verification"];
  readonly detail?: string;
}
export interface OverrideRegistration<P> {
  readonly label: string | null;
  readonly lifetime: Lifetime;
  readonly targets: readonly Hex[];
  readonly sites: readonly P[];
  /** open an override/1 stream for this instrument */
  readonly record: boolean;
  readonly revert: (reason: EndReason) => Promise<RevertResult>;
}
/** One registered override: the registry owns id, lifetime (duration, resume clock), max_hits, stop and messages. */
export interface RegisteredOverride {
  readonly id: string;
  readonly streamId: string | null;
  /** detached guard: false once stopping */
  readonly active: boolean;
  readonly counters: InstrumentCounters;
  /** one application against max_hits; false = ignore (past the limit or no longer active) */
  hit(): boolean;
  /** one override/1 row WITHOUT the leading [g, t] (the core stamps them); no-op without a stream */
  emit(tail: readonly unknown[]): void;
  /** install failed after registration: stop it again */
  discard(): void;
}
export interface InstrumentsService<P> {
  register(reg: OverrideRegistration<P>): RegisteredOverride | AgentError;
}

export interface ModifyCoreSeam<P> {
  readonly originals: OriginalsService<P> | null;
  /** CT-I5 guard table: the range overlaps a BEA guard page */
  readonly isGuarded: ((address: P, size: number) => boolean) | null;
  /** S4 §12.1: re-compile followed threads' blocks after a code change */
  readonly invalidate: ((sites: P[]) => void) | null;
  /** WP3 registry adapter; null = the feature's local registry (local ids, timers, ended message, no rows) */
  readonly instruments: InstrumentsService<P> | null;
  /** S4 §13.4: a BEA oracle call on this thread asked to bypass overrides (default: overrides apply) */
  readonly bypass: (tid: ThreadId) => boolean;
  /** register a synchronous disarm for rpc.exports.dispose */
  readonly onDispose: ((fn: () => void) => void) | null;
}

type Fn = (...args: never[]) => unknown;
const fnOf = (value: unknown, name: string): Fn | null => {
  if (typeof value !== "object" || value === null) return null;
  const member = (value as Record<string, unknown>)[name];
  return typeof member === "function" ? (member as Fn).bind(value) : null;
};
const has = (value: unknown, names: readonly string[]): boolean => names.every((n) => fnOf(value, n) !== null);

const isAgentError = (value: unknown): value is AgentError =>
  typeof value === "object" && value !== null && typeof (value as { _tag?: unknown })._tag === "string";

/**
 * WP3's OriginalBytes takes the S4 form `save(site, n, owner)` (src/agent/originals.ts): the size BEFORE the owner. The
 * adapter passed (site, owner, size), which the real class read as "32 bytes, owner agent" for every write (review fix
 * AGENT-9: a 4-byte write then refused writes to its untouched neighbours, and a code write over 32 bytes was covered
 * for only 32 bytes in the original-bytes overlay of dumps and disassembly).
 */
const bindOriginals = <P>(originals: unknown): OriginalsService<P> | null => {
  if (!has(originals, ["save", "release", "isPatched", "markPatched"])) return null;
  const o = originals as {
    save(site: P, n: number, owner: string): unknown;
    release(site: P, owner: string): unknown;
    isPatched(address: P, size: number): boolean;
    markPatched(site: P): void;
  };
  const sites = new Map<string, P>();
  return {
    save: (owner, site, size) => {
      sites.set(owner, site);
      o.save(site, size, owner);
    },
    markPatched: (owner) => {
      const site = sites.get(owner);
      if (site !== undefined) o.markPatched(site);
    },
    release: (owner) => {
      const site = sites.get(owner);
      if (site === undefined) return;
      sites.delete(owner);
      o.release(site, owner);
    },
    isPatched: (address, size) => o.isPatched(address, size),
  };
};

interface CoreInstrument {
  readonly id: string;
  readonly active: boolean;
  readonly counters: InstrumentCounters;
  hit(): "record" | "record-and-stop" | "ignore";
}

const bindInstruments = <P>(core: Record<string, unknown>): InstrumentsService<P> | null => {
  const instruments = core["instruments"];
  const streams = core["streams"];
  const native = core["native"];
  if (!has(instruments, ["register", "stop"]) || !has(streams, ["open", "emit", "close"])) return null;
  if (!has(native, ["nextG", "nowUs"])) return null;
  const reg = instruments as {
    register(spec: unknown): CoreInstrument | AgentError;
    stop(inst: CoreInstrument, reason: EndReason): Promise<unknown>;
  };
  const st = streams as {
    open(spec: unknown): { readonly id: string } | AgentError;
    emit(stream: unknown, row: unknown[]): boolean;
    close(stream: unknown): unknown;
  };
  const clock = native as { nextG(): number; nowUs(): number };
  return {
    register: (r) => {
      // The stream is announced with the RPC reply (S4 §6.1); its batches carry instrument null, the host binds by id.
      let stream: { readonly id: string } | null = null;
      if (r.record) {
        const opened = st.open({ instrument: null, kind: "override/1", enc: "json" });
        if (isAgentError(opened)) return opened;
        stream = opened;
      }
      const inst = reg.register({
        kind: "override",
        label: r.label,
        lifetime: r.lifetime,
        targets: r.targets,
        stream,
        sites: r.sites,
        revert: (_inst: unknown, reason: EndReason) => r.revert(reason),
      });
      if (isAgentError(inst)) {
        if (stream !== null) st.close(stream);
        return inst;
      }
      return {
        id: inst.id,
        streamId: stream?.id ?? null,
        get active() {
          return inst.active;
        },
        counters: inst.counters,
        hit: () => inst.hit() !== "ignore",
        emit: (tail) => {
          if (stream !== null) st.emit(stream, [clock.nextG(), clock.nowUs(), ...tail]);
        },
        discard: () => void reg.stop(inst, "error"),
      };
    },
  };
};

/** Structural binding to WP3's AgentCore (S4 §5.1 names); every member degrades independently. */
export const bindModifySeam = <P>(core: object): ModifyCoreSeam<P> => {
  const c = core as Record<string, unknown>;
  const intersecting = fnOf(c["guards"], "intersecting") as ((base: P, size: number) => readonly unknown[]) | null;
  const invalidateAll = fnOf(c["stalkerCo"], "invalidateAll") as ((sites: P[]) => unknown) | null;
  const bypasses = fnOf(c["calls"], "bypassesOverrides") as ((tid: ThreadId) => boolean) | null;
  const hooks = c["hooks"];
  const disposers =
    typeof hooks === "object" && hooks !== null ? (hooks as Record<string, unknown>)["onDispose"] : undefined;
  return {
    originals: bindOriginals<P>(c["originals"]),
    isGuarded: intersecting === null ? null : (address, size) => intersecting(address, size).length > 0,
    invalidate: invalidateAll === null ? null : (sites) => void invalidateAll(sites),
    instruments: bindInstruments<P>(c),
    bypass: bypasses ?? (() => false),
    onDispose: Array.isArray(disposers) ? (fn) => void (disposers as (() => void)[]).push(fn) : null,
  };
};

/** Local instrument ids when the core registry is absent (never reused within the agent). */
export class LocalIds {
  private next = 1;
  constructor(private readonly prefix: string) {}
  allocate(): string {
    const id = `${this.prefix}${String(this.next)}`;
    this.next += 1;
    return id;
  }
}
