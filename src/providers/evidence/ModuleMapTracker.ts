import { basename, win32 } from "node:path";

import type { BeaError } from "../../domain/errors/beaError.js";
import { COMPLETE } from "../../domain/evidence/coverage.js";
import { LIMITATIONS } from "../../domain/evidence/limitations.js";
import { canonicalHex, type Hex } from "../../domain/hex.js";
import type { EvId, MmId, PiId } from "../../domain/ids.js";
import { moduleMapIdOf, pathDigest, type ModuleEntry, type ModuleMap } from "../../domain/process/instance.js";
import { textContainsLiteral } from "../../domain/redaction/redact.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { AnchorCapture, ModuleMapTracker, Recorder, SensitiveLiterals } from "../../ports/evidence.js";
import { internalError } from "./errors.js";
import type { Ledger } from "./Ledger.js";
import type { LedgerIndex } from "./LedgerIndex.js";

/**
 * Module maps and epochs (S2 §5). The agent owns the epoch counter; the host mirrors it and never invents one. Maps
 * are hashed lazily (memoized per epoch) and written to the ledger only when something references them
 * (materialize-on-reference): the {t:"mm"} line + one `bea.modules.map` evidence per epoch.
 */
interface RawModule {
  readonly name: string;
  readonly base: Hex;
  readonly size: number;
  readonly path: string;
}
interface InstanceModules {
  epoch: number;
  current: Map<Hex, RawModule>;
  readonly history: Map<number, readonly RawModule[]>;
  readonly maps: Map<number, ModuleMap>;
  readonly recorded: Map<
    number,
    Promise<Result<{ readonly module_map_id: MmId; readonly evidence_id: EvId }, BeaError>>
  >;
  lastRecordedNames: readonly string[] | null;
}

/** Retention cap: epochs kept per instance (referenced and current epochs are always kept). */
const MAX_EPOCHS = 4096;
const MAX_NAME_LIST = 256;

export interface ModuleMapDeps {
  readonly platform: "win32" | "linux";
  readonly ledger: Ledger;
  readonly index: LedgerIndex;
  readonly recorder: () => Recorder;
  /** anchor for materialization at `epoch` (seq + effect epoch + perturbation of the instance) */
  readonly captureAt: (instance: PiId, epoch: number, moduleMapId: MmId) => AnchorCapture;
  readonly serverLiterals: () => SensitiveLiterals;
  readonly agentOf: (
    instance: PiId,
  ) => { readonly bundle_sha256: string; readonly bea_version: string; readonly runtime: "qjs" | "v8" } | null;
}

export class EpochModuleMapTracker implements ModuleMapTracker {
  readonly #instances = new Map<PiId, InstanceModules>();

  constructor(private readonly deps: ModuleMapDeps) {}

  #state(instance: PiId): InstanceModules {
    let state = this.#instances.get(instance);
    if (state === undefined) {
      state = {
        epoch: 0,
        current: new Map(),
        history: new Map(),
        maps: new Map(),
        recorded: new Map(),
        lastRecordedNames: null,
      };
      this.#instances.set(instance, state);
    }
    return state;
  }

  apply(
    instance: PiId,
    ev: {
      readonly op: "load" | "unload" | "snapshot";
      readonly epoch: number;
      readonly modules: readonly {
        readonly name: string;
        readonly base: Hex;
        readonly size: number;
        readonly path: string;
      }[];
    },
  ): void {
    const state = this.#state(instance);
    const normalized = ev.modules.map((m) => ({ ...m, base: canonicalHex(m.base) }));
    if (ev.op === "snapshot") state.current = new Map(normalized.map((m) => [m.base, m]));
    else if (ev.op === "load") for (const m of normalized) state.current.set(m.base, m);
    else for (const m of normalized) state.current.delete(m.base);
    state.epoch = ev.epoch;
    state.history.set(ev.epoch, [...state.current.values()]);
    state.maps.delete(ev.epoch);
    if (state.history.size > MAX_EPOCHS)
      for (const epoch of state.history.keys()) {
        if (state.history.size <= MAX_EPOCHS) break;
        if (epoch !== state.epoch && !state.recorded.has(epoch)) {
          state.history.delete(epoch);
          state.maps.delete(epoch);
        }
      }
  }

  #mapOf(instance: PiId, state: InstanceModules, epoch: number): ModuleMap | undefined {
    const memo = state.maps.get(epoch);
    if (memo !== undefined) return memo;
    const raw = state.history.get(epoch);
    if (raw === undefined) return undefined;
    const literals = this.deps.serverLiterals();
    const display = (text: string): string | null => (textContainsLiteral(text, literals) ? null : text);
    const pathName = (path: string): string => (this.deps.platform === "win32" ? win32.basename(path) : basename(path));
    const modules: ModuleEntry[] = [...raw]
      .sort((a, b) => (BigInt(a.base) < BigInt(b.base) ? -1 : BigInt(a.base) > BigInt(b.base) ? 1 : 0))
      .map((m) => ({
        base: m.base,
        size: m.size,
        path_sha256: pathDigest(m.path, this.deps.platform),
        display: { name: display(m.name.length > 0 ? m.name : pathName(m.path)), path: display(m.path) },
      }));
    const body: Omit<ModuleMap, "module_map_id"> = { instance_id: instance, completeness: "complete", modules };
    const map: ModuleMap = { module_map_id: moduleMapIdOf(body), ...body };
    state.maps.set(epoch, map);
    return map;
  }

  current(instance: PiId): { readonly epoch: number; readonly map: () => ModuleMap } | undefined {
    const state = this.#instances.get(instance);
    if (state === undefined) return undefined;
    const epoch = state.epoch;
    return {
      epoch,
      map: () =>
        this.#mapOf(instance, state, epoch) ?? {
          module_map_id: moduleMapIdOf({ instance_id: instance, completeness: "complete", modules: [] }),
          instance_id: instance,
          completeness: "complete",
          modules: [],
        },
    };
  }

  at(instance: PiId, epoch: number): ModuleMap | undefined {
    const state = this.#instances.get(instance);
    return state === undefined ? undefined : this.#mapOf(instance, state, epoch);
  }

  ensureRecorded(
    instance: PiId,
    epoch: number,
    operation: string,
  ): Promise<Result<{ readonly module_map_id: MmId; readonly evidence_id: EvId }, BeaError>> {
    const state = this.#instances.get(instance);
    if (state === undefined) return Promise.resolve(err(internalError(operation, "module map of an unknown instance")));
    const existing = state.recorded.get(epoch);
    if (existing !== undefined) return existing;
    const task = this.#record(instance, state, epoch, operation);
    state.recorded.set(epoch, task);
    void task.then((r) => {
      if (!r.ok) state.recorded.delete(epoch);
    });
    return task;
  }

  async #record(
    instance: PiId,
    state: InstanceModules,
    epoch: number,
    operation: string,
  ): Promise<Result<{ readonly module_map_id: MmId; readonly evidence_id: EvId }, BeaError>> {
    const map = this.#mapOf(instance, state, epoch);
    if (map === undefined) return err(internalError(operation, `module map epoch ${String(epoch)} is not retained`));
    if (!this.deps.index.moduleMaps.has(map.module_map_id)) {
      const appended = await this.deps.ledger.append({ t: "mm", module_map: map }, { operation });
      if (!appended.ok) return appended;
      this.deps.index.addModuleMap({ module_map: map, ref: appended.value, origin: { kind: "local" } });
    }
    const names = map.modules.map((m) => m.display.name ?? "").filter((n) => n.length > 0);
    const previous = new Set(state.lastRecordedNames ?? []);
    const now = new Set(names);
    const loaded = state.lastRecordedNames === null ? [] : names.filter((n) => !previous.has(n));
    const unloaded = [...previous].filter((n) => !now.has(n));
    const recorded = await this.deps.recorder().record({
      predicate_type: "bea.modules.map",
      operation,
      input: { epoch },
      subject: { kind: "process-instance", instance_id: instance, module_map_id: map.module_map_id },
      capture: this.deps.captureAt(instance, epoch, map.module_map_id),
      provider: { id: "frida", name: "frida", version: null },
      agent: this.deps.agentOf(instance),
      result: {
        epoch,
        module_count: map.modules.length,
        loaded_since_previous_recorded: loaded.slice(0, MAX_NAME_LIST),
        unloaded_since_previous_recorded: unloaded.slice(0, MAX_NAME_LIST),
      },
      coverage: COMPLETE,
      limitations: [LIMITATIONS.AGENT_CLOAKED],
      literals: this.deps.serverLiterals(),
    });
    if (!recorded.ok) return recorded;
    state.lastRecordedNames = names;
    return ok({ module_map_id: map.module_map_id, evidence_id: recorded.value.record.evidence_id });
  }

  /** Recorded module-map evidence of an epoch, if materialized already (sync peek). */
  hasInstance(instance: PiId): boolean {
    return this.#instances.has(instance);
  }
}
