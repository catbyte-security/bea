import { createHash } from "node:crypto";

import { Deadline } from "../../../../src/domain/deadline.js";
import { evidenceIntegrity } from "../../../../src/domain/evidence/authenticate.js";
import { buildEvidence, type ParentFacts } from "../../../../src/domain/evidence/build.js";
import { NO_PERTURBATION, type BeaEvidence, type Perturbation } from "../../../../src/domain/evidence/record.js";
import { formatHex, type Hex } from "../../../../src/domain/hex.js";
import type { EvId, MmId, PiId } from "../../../../src/domain/ids.js";
import type { JsonObject, JsonValue } from "../../../../src/domain/json.js";
import { moduleMapIdOf, pathDigest, type ModuleMap } from "../../../../src/domain/process/instance.js";
import { err, ok } from "../../../../src/domain/result.js";
import type { AgentRpc } from "../../../../src/ports/agentRpc.js";
import type { EmuModuleView, EmuPort, EmuSessionHandle } from "../../../../src/ports/emu.js";
import type {
  BlobStore,
  EffectRegistry,
  EvidenceDraft,
  EvidenceRuntime,
  InstanceRegistry,
  ModuleMapTracker,
  UnknownRegistry,
} from "../../../../src/ports/evidence.js";
import type { PeImage, PeImageCache } from "../../../../src/ports/pe.js";
import type { LiveSession, OperationContext } from "../../../../src/ports/sessions.js";

/**
 * Minimal fakes of the ports WP-ADDR consumes (EvidenceRuntime, LiveSession + agent RPCs, EmuPort), local to the
 * address tests. Process memory is modelled from the REAL on-disk images relocated to the fake bases, so byte
 * verification runs against true file bytes; tests then patch it.
 */
const stub = <T extends object>(name: string, impl: Partial<T>): T =>
  new Proxy(impl as T, {
    get: (target, prop) => {
      if (prop in target) return Reflect.get(target, prop);
      if (prop === "then" || typeof prop !== "string") return undefined;
      return () => {
        throw new Error(`fake ${name}.${prop} not implemented`);
      };
    },
  });

export const testOp = (name = "map_address"): OperationContext => ({
  opId: 1,
  name,
  signal: new AbortController().signal,
  deadline: Deadline.after(60_000),
});

// ---------------------------------------------------------------- evidence

export interface FakeEvidence {
  readonly runtime: EvidenceRuntime;
  readonly drafts: EvidenceDraft<JsonValue>[];
  /** every record the pipeline accepted, in order (a duplicate is listed again) */
  readonly records: BeaEvidence[];
  readonly blobs: Uint8Array[];
  /** BEA's own patches: va → original bytes (EffectRegistry.originalBytes) */
  readonly originals: Map<bigint, Uint8Array>;
  readonly autoUnknowns: JsonObject[];
  map: ModuleMap | null;
  epoch: number;
  readonly applied: unknown[];
}

/** The bea.modules.map evidence the fake ModuleMapTracker hands out (a known live-process parent). */
const FAKE_MODULE_MAP_EVIDENCE = `ev_${"9".repeat(64)}` as EvId;
const AGENT_ONLY: Perturbation = { level: "agent-only", active_effect_ids: [], tainted_by: [] };

export const fakeEvidence = (instance: PiId = `pi_${"1".repeat(64)}`): FakeEvidence => {
  const state: Omit<FakeEvidence, "runtime"> = {
    drafts: [],
    records: [],
    blobs: [],
    originals: new Map(),
    autoUnknowns: [],
    map: null,
    epoch: 1,
    applied: [],
  };
  let seq = 0;
  // The production record pipeline (registry, invariants, weakest-parent authority, id) with the real Recorder's
  // reference closure: a draft the real Recorder refuses fails here too (WP1's EvidenceRecorder, S2 §7.1).
  const parents = new Map<EvId, ParentFacts>([
    [FAKE_MODULE_MAP_EVIDENCE, { authority: "live-process", perturbation: AGENT_ONLY }],
  ]);
  const record = async <R extends JsonValue>(draft: EvidenceDraft<R>) => {
    state.drafts.push(draft as unknown as EvidenceDraft<JsonValue>);
    const built = buildEvidence(draft, { parent: (id) => parents.get(id) });
    if (!built.ok) return built;
    const rec: BeaEvidence<R> = built.value.record;
    for (const link of rec.evidence_links)
      if (!parents.has(link)) return err(evidenceIntegrity(draft.operation, "dangling-link", { evidence_id: link }));
    parents.set(rec.evidence_id, { authority: rec.authority, perturbation: rec.perturbation });
    state.records.push(rec as unknown as BeaEvidence);
    return ok({ record: rec, outcome: "added" as const });
  };
  const runtime = stub<EvidenceRuntime>("evidence", {
    recorder: { record },
    literals: (perCall) =>
      perCall?.some((t) => Buffer.byteLength(t) < 4) === true
        ? err({
            _tag: "InputError",
            operation: "literals",
            issues: [{ path: "sensitive_values", reason: "invalid_value", message: "too short" }],
          })
        : ok({ count: perCall?.length ?? 0, texts: [...(perCall ?? [])], spellings: [] }),
    locationOf: (ref, size) => ({
      kind: "address",
      va: ref.va,
      size: size ?? null,
      module_map_id: ref.module_map_id,
      module_key: ref.module?.toLowerCase() ?? null,
      rva: ref.rva,
      image_sha256: ref.image_sha256 ?? null,
    }),
    modules: stub<ModuleMapTracker>("modules", {
      current: (id: PiId) => {
        const map = state.map;
        return id === instance && map !== null ? { epoch: state.epoch, map: () => map } : undefined;
      },
      apply: (_id: PiId, ev: unknown) => void state.applied.push(ev),
      ensureRecorded: async () =>
        ok({
          module_map_id: state.map?.module_map_id ?? (`mm_${"0".repeat(64)}` as MmId),
          evidence_id: FAKE_MODULE_MAP_EVIDENCE,
        }),
    }),
    effects: stub<EffectRegistry>("effects", {
      originalBytes: (_id: PiId, va: bigint, len: number) => ({
        ranges: [...state.originals]
          .filter(([at, bytes]) => at < va + BigInt(len) && va < at + BigInt(bytes.length))
          .map(([at, bytes]) => ({ va: at, bytes, fx: `fx_${"f".repeat(64)}` as const })),
      }),
    }),
    instances: stub<InstanceRegistry>("instances", {
      capture: () => ({
        anchor: {
          run_id: "run_20261028T000000Z_0000000000000000",
          seq: ++seq,
          mono_ns: "1",
          wall: "2026-10-28T00:00:00.000Z",
          effect_epoch: 0,
          module_map_epoch: state.epoch,
        },
        module_map_id: state.map?.module_map_id ?? (`mm_${"0".repeat(64)}` as MmId),
        perturbation: NO_PERTURBATION,
        tainted_count: 0,
      }),
    }),
    blobs: stub<BlobStore>("blobs", {
      put: async (src: Uint8Array | AsyncIterable<Uint8Array>, meta: { role: string; media_type: string }) => {
        const bytes = src as Uint8Array;
        state.blobs.push(bytes);
        return ok({
          role: meta.role,
          sha256: createHash("sha256").update(bytes).digest("hex"),
          bytes: bytes.length,
          media_type: meta.media_type,
        });
      },
    }),
    unknowns: stub<UnknownRegistry>("unknowns", {
      autoRecord: async (input: unknown) => {
        state.autoUnknowns.push(input as JsonObject);
        return ok({ unknown_id: `unk_${"2".repeat(64)}` as const, revision: 1 });
      },
    }),
  });
  return Object.assign(state, { runtime }) as FakeEvidence;
};

// ---------------------------------------------------------------- live process model

export interface FakeModule {
  readonly path: string;
  readonly base: bigint;
  /** display name (default: basename of path) */
  readonly name?: string;
}

export interface FakeProcess {
  readonly session: LiveSession;
  /** writes into the modelled memory (foreign patches, IAT values …) */
  write(va: bigint, bytes: Uint8Array): void;
  readonly calls: { method: string; params: unknown }[];
  /** API-set resolution answers for resolveTargets {module, export} */
  readonly exportsByName: Map<string, bigint>;
  readonly modules: readonly (FakeModule & { readonly size: number; readonly name: string })[];
  /** marks [va, va+len) unreadable */
  unreadable(va: bigint, len: number): void;
}

/** A host module map (S2 §5) over loaded modules, as the ModuleMapTracker would hold it. */
export const moduleMapOf = (
  instance: PiId,
  modules: readonly { readonly path: string; readonly base: bigint; readonly size: number; readonly name: string }[],
): ModuleMap => {
  const entries = [...modules]
    .sort((a, b) => (a.base < b.base ? -1 : 1))
    .map((m) => ({
      base: formatHex(m.base),
      size: m.size,
      path_sha256: pathDigest(m.path, "win32"),
      display: { name: m.name, path: m.path },
    }));
  return {
    module_map_id: moduleMapIdOf({ instance_id: instance, completeness: "complete", modules: entries }),
    instance_id: instance,
    completeness: "complete",
    modules: entries,
  };
};

const baseName = (path: string): string => path.slice(Math.max(path.lastIndexOf("\\"), path.lastIndexOf("/")) + 1);

export const fakeProcess = async (
  images: PeImageCache,
  modules: readonly FakeModule[],
  evidence: FakeEvidence,
  instance: PiId = `pi_${"1".repeat(64)}`,
): Promise<FakeProcess> => {
  const loaded: (FakeModule & { size: number; name: string; bytes: Uint8Array; image: PeImage })[] = [];
  for (const m of modules) {
    const image = await images.open(m.path);
    if (!image.ok) throw new Error(`fake process: ${m.path}: ${JSON.stringify(image.error)}`);
    const size = image.value.size_of_image;
    const bytes = new Uint8Array(await image.value.imageBytes(0, size, m.base));
    // the loader rewrites OptionalHeader.ImageBase in the mapped header
    const lfanew = Buffer.from(bytes).readUInt32LE(0x3c);
    Buffer.from(bytes.buffer, bytes.byteOffset).writeBigUInt64LE(m.base, lfanew + 24 + 24);
    // the loader fills IAT slots with resolved pointers
    for (const imp of await image.value.imports())
      Buffer.from(bytes.buffer, bytes.byteOffset).writeBigUInt64LE(
        0x7ffa_0000_1000n + BigInt(imp.slot_rva),
        imp.slot_rva,
      );
    loaded.push({ ...m, size, name: m.name ?? baseName(m.path), bytes, image: image.value });
  }
  loaded.sort((a, b) => (a.base < b.base ? -1 : 1));
  const holes: { va: bigint; len: number }[] = [];
  const mainPath = modules[0]?.path ?? "";
  evidence.map = moduleMapOf(instance, loaded);
  const calls: { method: string; params: unknown }[] = [];
  const exportsByName = new Map<string, bigint>();
  const readByte = (va: bigint): number | null => {
    if (holes.some((h) => va >= h.va && va < h.va + BigInt(h.len))) return null;
    const m = loaded.find((x) => va >= x.base && va < x.base + BigInt(x.size));
    if (m !== undefined) return m.bytes[Number(va - m.base)] ?? 0;
    // a private committed page at 0x10000000 (heap-like)
    return va >= 0x1000_0000n && va < 0x1001_0000n ? 0xab : null;
  };
  const agent: AgentRpc = {
    health: { state: "ok" },
    call: (async (method: string, params: Record<string, unknown>) => {
      calls.push({ method, params });
      if (method === "readMemory") {
        const address = BigInt(params["address"] as string);
        const size = params["size"] as number;
        const out: number[] = [];
        for (let i = 0; i < size; i++) {
          const b = readByte(address + BigInt(i));
          if (b === null) break;
          out.push(b);
        }
        return ok({
          value: {
            address: params["address"] as Hex,
            requested: size,
            returned: out.length,
            complete: out.length === size,
            stop: out.length === size ? null : { reason: "unmapped", at: formatHex(address + BigInt(out.length)) },
            bea_guard_suspended: [],
          },
          data: Buffer.from(out),
        });
      }
      if (method === "listModules")
        return ok({
          module_map_epoch: evidence.epoch,
          modules: loaded.map((m) => ({ name: m.name, path: m.path, base: formatHex(m.base), size: m.size, pe: null })),
        });
      if (method === "resolveTargets") {
        const targets = params["targets"] as { module: string; export: string }[];
        return ok({
          results: targets.map((t) => {
            const va = exportsByName.get(`${baseName(t.module).toLowerCase()}!${t.export}`);
            return va === undefined
              ? { ok: false, error: { code: "not_found" } }
              : {
                  ok: true,
                  target: {
                    va: formatHex(va),
                    module: null,
                    module_base: null,
                    rva: null,
                    export: t.export,
                    function: null,
                    protection: null,
                  },
                };
          }),
        });
      }
      return err({
        _tag: "CapabilityUnavailable",
        operation: method,
        capability: "agent",
        reason: "fake",
        retryable: false,
      });
    }) as AgentRpc["call"],
  };
  const session = stub<LiveSession>("session", {
    id: "3f2b8c1e-5d4a-4b6f-9a7e-1c2d3e4f5a6b",
    kind: "live",
    ownership: "owned",
    state: "running",
    instanceId: instance,
    identity: {
      deviceId: "local",
      pid: 4242,
      startTime: { source: "os-creation-time", value: String((BigInt(Date.now()) + 11_644_473_600_000n) * 10_000n) },
      image: { path: mainPath, sha256: null, size: null, machine: "x64", peTimestamp: null, preferredBase: null },
      parentPid: null,
      osSessionId: null,
      integrity: "medium",
      launchedByBea: true,
    },
    agent,
    paused: false,
    lastCrash: null,
    output: null,
  });
  return {
    session,
    calls,
    exportsByName,
    modules: loaded,
    write: (va, bytes) => {
      const m = loaded.find((x) => va >= x.base && va < x.base + BigInt(x.size));
      if (m === undefined) throw new Error("write outside modules");
      m.bytes.set(bytes, Number(va - m.base));
    },
    unreadable: (va, len) => void holes.push({ va, len }),
  };
};

// ---------------------------------------------------------------- emulation

export const fakeEmu = (sessionId: string, modules: readonly EmuModuleView[]): EmuPort => {
  const handle: EmuSessionHandle = { sessionId, generation: 1 };
  return stub<EmuPort>("emulator", {
    lookup: (id: string) => (id === sessionId ? handle : null),
    modules: () => modules,
  });
};
