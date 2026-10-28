import type { AddressRef, Loc } from "../../../../src/domain/address/addressRef.js";
import { canonicalDigest } from "../../../../src/domain/canonical.js";
import { Deadline } from "../../../../src/domain/deadline.js";
import type { Insn, MemReadResult, RegionInfo } from "../../../../src/domain/emuProtocol.js";
import type { BeaError } from "../../../../src/domain/errors/beaError.js";
import { inputError, sessionNotFound } from "../../../../src/domain/errors/constructors.js";
import { NO_PERTURBATION, type BeaEvidence } from "../../../../src/domain/evidence/record.js";
import { mergeCoverage } from "../../../../src/domain/evidence/coverage.js";
import { PREDICATES } from "../../../../src/domain/evidence/predicates.js";
import { redactJsonPayload } from "../../../../src/domain/redaction/redact.js";
import type { EvId, MmId, PiId } from "../../../../src/domain/ids.js";
import type { JsonObject, JsonValue } from "../../../../src/domain/json.js";
import { err, ok, type Result } from "../../../../src/domain/result.js";
import { notImplementedError } from "../../../../src/application/notImplemented.js";
import type { AddressService, AddressSpace } from "../../../../src/ports/address.js";
import type { AgentRpc } from "../../../../src/ports/agentRpc.js";
import type { EmuModuleView, EmuPort, EmuSessionHandle } from "../../../../src/ports/emu.js";
import type {
  AnchorCapture,
  EvidenceDraft,
  EvidenceRuntime,
  RecordedEvidence,
  InstanceRegistry,
  ModuleMapTracker,
} from "../../../../src/ports/evidence.js";
import type { FileHashCache, PeImage, PeImageCache } from "../../../../src/ports/pe.js";
import type {
  DynamicSessionPort,
  LiveSession,
  OperationContext,
  SessionState,
} from "../../../../src/ports/sessions.js";
import type { AgentMethodName, AgentParams } from "../../../../src/shared/agentProtocol.js";
import { formatHex, type Hex } from "../../../../src/shared/hex.js";

/**
 * Minimal WP6-local fakes of the frozen ports the inspect services use (sessions + agent RPC, evidence, address,
 * PE, emulator). The shared area fakes (fakeSession/fakeAgentRpc of WP4, fakeEvidence of WP1, …) do not exist yet in
 * this wave; these implement only what inspect touches and throw capability_unavailable(not-implemented) elsewhere.
 */
const partialPort = <T extends object>(name: string, impl: Partial<T>): T =>
  new Proxy(impl as T, {
    get: (target, prop) => {
      if (typeof prop !== "string" || prop === "then") return undefined;
      if (prop in target) return Reflect.get(target, prop);
      return () => {
        throw notImplementedError(`${name}.${prop}`);
      };
    },
  });

// ---------------------------------------------------------------- target memory + modules
export interface FakeModule {
  readonly name: string;
  readonly base: bigint;
  readonly size: number;
  readonly path: string;
  readonly preferredBase: bigint;
  readonly exports: Readonly<Record<string, number>>;
  readonly timestamp: number;
}
export const PI: PiId = `pi_${"a".repeat(64)}`;
export const MM: MmId = `mm_${"b".repeat(64)}`;
export const LIVE_ID = "11111111-1111-4111-8111-111111111111";
export const EMU_ID = "22222222-2222-4222-8222-222222222222";
export const UNKNOWN_ID = "33333333-3333-4333-8333-333333333333";

export const GAME: FakeModule = {
  name: "game.exe",
  base: 0x7ff6_a000_0000n,
  size: 0x20000,
  path: "C:\\games\\game.exe",
  preferredBase: 0x1_4000_0000n,
  exports: { g_world: 0x10000, g_marker: 0x11000, physics_step: 0x1760 },
  timestamp: 0x5f000000,
};
export const NTDLL: FakeModule = {
  name: "ntdll.dll",
  base: 0x7ffd_0000_0000n,
  size: 0x1f0000,
  path: "C:\\Windows\\System32\\ntdll.dll",
  preferredBase: 0x1_8000_0000n,
  exports: {},
  timestamp: 0x60000000,
};

/** Sparse memory: readable regions only; a read stops at the first byte outside them. */
export class FakeMemory {
  readonly regions: { base: bigint; bytes: Uint8Array; prot: string; module: string | null }[] = [];
  map(base: bigint, bytes: Uint8Array, prot = "rw-", module: string | null = null): void {
    this.regions.push({ base, bytes, prot, module });
  }
  write(at: bigint, bytes: Uint8Array): void {
    const r = this.regions.find((x) => at >= x.base && at + BigInt(bytes.length) <= x.base + BigInt(x.bytes.length));
    if (r === undefined) throw new Error("write outside mapped memory");
    r.bytes.set(bytes, Number(at - r.base));
  }
  writeU64(at: bigint, value: bigint): void {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, value, true);
    this.write(at, b);
  }
  regionAt(va: bigint) {
    return this.regions.find((r) => va >= r.base && va < r.base + BigInt(r.bytes.length));
  }
  read(va: bigint, size: number): Uint8Array {
    const out: number[] = [];
    for (let i = 0; i < size; i++) {
      const r = this.regionAt(va + BigInt(i));
      if (r === undefined) break;
      out.push(r.bytes[Number(va + BigInt(i) - r.base)] ?? 0);
    }
    return new Uint8Array(out);
  }
}

// ---------------------------------------------------------------- agent RPC
export type AgentHandler = (params: never) => Result<unknown, BeaError> | Promise<Result<unknown, BeaError>>;
export class FakeAgent implements AgentRpc {
  readonly health = { state: "ok" } as const;
  readonly calls: { method: AgentMethodName; params: unknown }[] = [];
  constructor(readonly handlers: Partial<Record<AgentMethodName, AgentHandler>>) {}
  async call<M extends AgentMethodName>(method: M, params: AgentParams<M>): Promise<Result<never, BeaError>> {
    this.calls.push({ method, params });
    const handler = this.handlers[method];
    if (handler === undefined)
      return err({ _tag: "UnsupportedTarget", operation: method, reason: "unsupported-feature" });
    return (await handler(params as never)) as Result<never, BeaError>;
  }
  count(method: AgentMethodName): number {
    return this.calls.filter((c) => c.method === method).length;
  }
}

/** readMemory/describeAddresses over a FakeMemory (the agent returns the readable prefix or AccessViolation). */
export const memoryHandlers = (memory: FakeMemory): Partial<Record<AgentMethodName, AgentHandler>> => ({
  readMemory: ((p: { address: Hex; size: number }) => {
    const bytes = memory.read(BigInt(p.address), p.size);
    if (bytes.length === 0)
      return err({ _tag: "MemoryAccessFailed", operation: "read_memory", address: p.address, access: "read", size: 0 });
    return ok({
      value: {
        address: p.address,
        requested: p.size,
        returned: bytes.length,
        complete: bytes.length === p.size,
        stop:
          bytes.length === p.size
            ? null
            : { reason: "unmapped", at: formatHex(BigInt(p.address) + BigInt(bytes.length)) },
        bea_guard_suspended: [],
      },
      data: Buffer.from(bytes),
    });
  }) as AgentHandler,
  describeAddresses: ((p: { addresses: Hex[] }) =>
    ok({
      results: p.addresses.map((a) => {
        const r = memory.regionAt(BigInt(a));
        return {
          va: a,
          module: r?.module ?? null,
          rva: null,
          function: null,
          range: r === undefined ? null : { base: formatHex(r.base), size: r.bytes.length, protection: r.prot },
          export_hint: null,
          bea_patched: false,
          bea_guarded: false,
        };
      }),
    })) as AgentHandler,
});

// ---------------------------------------------------------------- sessions
export interface FakeLive {
  readonly session: LiveSession;
  readonly agent: FakeAgent;
  state: SessionState;
}
export const fakeLiveSession = (agent: FakeAgent, state: SessionState = "running"): FakeLive => {
  const holder = { state } as { state: SessionState };
  const session = {
    id: LIVE_ID,
    kind: "live",
    ownership: "owned",
    get state() {
      return holder.state;
    },
    instanceId: PI,
    identity: {
      deviceId: "local",
      pid: 4242,
      startTime: { source: "os-creation-time", value: "1" },
      image: { path: GAME.path, sha256: null, size: null, machine: "x64", peTimestamp: null, preferredBase: null },
      parentPid: null,
      osSessionId: null,
      integrity: "medium",
      launchedByBea: true,
    },
    agent,
    liveness: () =>
      holder.state === "exited"
        ? {
            state: "exited",
            basis: "jobhost-root-exit",
            exit: { code: 0, code_hex: "0x0", kind: "normal", name: null, source: "jobhost" },
            tree: null,
          }
        : { state: "alive", basis: "jobhost" },
  } as unknown as LiveSession;
  return {
    session,
    agent,
    get state() {
      return holder.state;
    },
    set state(next: SessionState) {
      holder.state = next;
    },
  };
};

export const fakeSessions = (live: FakeLive | null, emulationIds: readonly string[] = []): DynamicSessionPort =>
  partialPort<DynamicSessionPort>("sessions", {
    closing: false,
    admit: async (name, _req, fn) => {
      const deadline = Deadline.after(10_000);
      const op: OperationContext = { opId: 1, name, signal: new AbortController().signal, deadline };
      try {
        return await fn(op);
      } finally {
        deadline.dispose();
      }
    },
    kindOf: (id) => (live !== null && id === live.session.id ? "live" : emulationIds.includes(id) ? "emulation" : null),
    withSession: async (id, op, _mode, fn) =>
      live !== null && id === live.session.id ? fn(live.session) : err(sessionNotFound(op.name, id)),
  });

// ---------------------------------------------------------------- evidence
export interface FakeEvidenceLog {
  readonly drafts: EvidenceDraft<JsonValue>[];
  readonly applied: { op: string; epoch: number }[];
  captures: number;
}
const LITERAL_MIN_BYTES = 4;
export const fakeEvidence = (log: FakeEvidenceLog): EvidenceRuntime =>
  partialPort<EvidenceRuntime>("evidence", {
    literals: (perCall) => {
      const texts = [...(perCall ?? [])];
      const short = texts.findIndex((t) => Buffer.byteLength(t, "utf8") < LITERAL_MIN_BYTES);
      if (short >= 0)
        return err(
          inputError("literals", [
            {
              path: `sensitive_values[${short}]`,
              reason: "out_of_range",
              message: "A sensitive value needs ≥ 4 bytes.",
            },
          ]),
        );
      return ok({ count: texts.length, texts, spellings: texts.map((t) => new Uint8Array(Buffer.from(t))) });
    },
    instances: partialPort<InstanceRegistry>("instances", {
      capture: (): AnchorCapture => {
        log.captures += 1;
        return {
          anchor: {
            run_id: "run_20261028T000000Z_0123456789abcdef",
            seq: log.captures,
            mono_ns: "1",
            wall: "2026-10-28T00:00:00.000Z",
            effect_epoch: 0,
            module_map_epoch: 3,
          },
          module_map_id: MM,
          perturbation: NO_PERTURBATION,
          tainted_count: 0,
        };
      },
      get: () => undefined,
    }),
    modules: partialPort<ModuleMapTracker>("modules", {
      apply: (_instance, ev) => void log.applied.push({ op: ev.op, epoch: ev.epoch }),
    }),
    recorder: {
      record: async <R extends JsonValue>(draft: EvidenceDraft<R>): Promise<Result<RecordedEvidence<R>, BeaError>> => {
        log.drafts.push(draft as EvidenceDraft<JsonValue>);
        const spec = PREDICATES[draft.predicate_type];
        // redaction (S2 §15) exactly as the real builder does it (review fix SEC-4: the fake used to delete the key,
        // which hid that the real builder nulls it): the producer's withheld pointers, then text and byte fields
        const redacted = redactJsonPayload(draft.result, draft.literals, "/result", spec.byteFields);
        const result = redacted.value;
        const redactions: BeaEvidence["redactions"] = [
          ...(draft.pre_redactions ?? []).map((pointer) => ({
            pointer,
            reason: "explicit-sensitive-value" as const,
            scope: "value" as const,
          })),
          ...redacted.redactions,
        ];
        const subject =
          draft.subject === null
            ? null
            : draft.subject.kind === "process-instance"
              ? {
                  kind: "process-instance" as const,
                  instance_id: draft.subject.instance_id,
                  module_map_id: draft.capture?.module_map_id ?? null,
                }
              : (draft.subject as BeaEvidence["subject"]);
        const record = {
          schema: "bea.evidence/1",
          evidence_id:
            `ev_${canonicalDigest({ p: draft.predicate_type, r: result, n: log.drafts.length } as JsonObject)}` as EvId,
          predicate_type: draft.predicate_type,
          operation: draft.operation,
          parameters: draft.input,
          subject,
          observed_at: draft.capture?.anchor ?? null,
          provider: draft.provider,
          agent: draft.agent ?? null,
          confidence: spec.confidence === "per-call" ? (draft.confidence ?? "observed") : spec.confidence,
          authority:
            spec.authority === "per-call" || spec.authority === "weakest-parent"
              ? (draft.authority ?? "live-process")
              : spec.authority,
          perturbation: draft.capture?.perturbation ?? NO_PERTURBATION,
          result: result as R,
          raw_result: null,
          blobs: [],
          coverage:
            redactions.length === 0
              ? draft.coverage
              : mergeCoverage(draft.coverage, {
                  status: "partial",
                  truncated: true,
                  reasons: ["explicit_sensitive_value"],
                }),
          limitations: [...new Set(draft.limitations ?? [])].sort(),
          locations: [],
          evidence_links: [],
          external_refs: [],
          effects: [],
          redactions,
          untrusted: spec.untrusted,
        } as BeaEvidence<R>;
        return ok({ record, outcome: "added" });
      },
    },
  });

// ---------------------------------------------------------------- address
const moduleOf = (mods: readonly FakeModule[], va: bigint) =>
  mods.find((m) => va >= m.base && va < m.base + BigInt(m.size));
export interface FakeAddressLog {
  prepared: bigint[];
}
export const fakeAddress = (mods: readonly FakeModule[], log: FakeAddressLog = { prepared: [] }): AddressService => {
  const describe = (_space: AddressSpace, va: bigint) => {
    const m = moduleOf(mods, va);
    if (m === undefined) return { va: formatHex(va), at: null, static: null };
    const rva = va - m.base;
    return {
      va: formatHex(va),
      at: `${m.name}+${formatHex(rva)}`,
      static: `${m.name}:${formatHex(m.preferredBase + rva)}`,
    };
  };
  const refOf = (va: bigint): AddressRef => {
    const m = moduleOf(mods, va);
    return {
      va: formatHex(va),
      module: m?.name ?? null,
      rva: m === undefined ? null : formatHex(va - m.base),
      static_va: m === undefined ? null : formatHex(m.preferredBase + (va - m.base)),
      static_base: m === undefined ? null : formatHex(m.preferredBase),
      static_base_source: m === undefined ? null : "pe-header",
      module_map_id: m === undefined ? null : MM,
    };
  };
  return partialPort<AddressService>("address", {
    resolve: async (_space, expr, op, opts) => {
      const path = opts?.path ?? "address";
      let va: bigint | null = null;
      const plus = /^([^+!]+)\+(0x[0-9a-f]+)$/iu.exec(expr);
      const bang = /^([^+!]+)!([A-Za-z_]\w*)$/u.exec(expr);
      if (/^0x[0-9a-f]+$/iu.test(expr)) va = BigInt(expr);
      else if (plus !== null) {
        const m = mods.find((x) => x.name === plus[1]);
        if (m === undefined)
          return err({ _tag: "AddressUnmapped", operation: op.name, address: expr.slice(0, 64), module_map_id: MM });
        va = m.base + BigInt(plus[2] ?? "0");
      } else if (bang !== null) {
        const m = mods.find((x) => x.name === bang[1]);
        const rva = m?.exports[bang[2] ?? ""];
        if (m !== undefined && rva !== undefined) va = m.base + BigInt(rva);
      }
      if (va === null)
        return err(inputError(op.name, [{ path, reason: "invalid_format", message: "Not an address expression." }]));
      return ok({ ref: refOf(va), moduleMapId: MM, va });
    },
    prepare: async (_space, vas) => void log.prepared.push(...vas),
    describe,
    describeCode: async (space, va): Promise<Loc> => {
      const a = describe(space, va);
      return { ...a, func: a.at, sym: null };
    },
  });
};

// ---------------------------------------------------------------- PE
export const fakePe = (mods: readonly FakeModule[]): { images: PeImageCache; hashes: FileHashCache } => ({
  images: partialPort<PeImageCache>("pe.images", {
    open: async (path) => {
      const m = mods.find((x) => x.path === path);
      return m === undefined
        ? err({ _tag: "FileOperationFailed", operation: "pe.open", file_operation: "read", path, reason: "missing" })
        : ok({ image_base: formatHex(m.preferredBase), time_date_stamp: m.timestamp } as unknown as PeImage);
    },
  }),
  hashes: partialPort<FileHashCache>("pe.hashes", {
    sha256: async (path) =>
      mods.some((x) => x.path === path)
        ? ok(canonicalDigest({ path } as JsonObject))
        : err({ _tag: "FileOperationFailed", operation: "hash", file_operation: "read", path, reason: "missing" }),
  }),
});

// ---------------------------------------------------------------- emulator
export interface FakeEmuOptions {
  readonly modules: readonly EmuModuleView[];
  readonly memory: FakeMemory;
  readonly insns?: readonly Insn[];
  readonly fn?: { module: string; beginRva: Hex; endRva: Hex; source: "pdata" } | null;
}
export const EMU_SHA = "c".repeat(64);
export const fakeEmulator = (o: FakeEmuOptions): EmuPort =>
  partialPort<EmuPort>("emulator", {
    lookup: (id): EmuSessionHandle | null => (id === EMU_ID ? { sessionId: EMU_ID, generation: 2 } : null),
    modules: () => o.modules,
    availability: () => ({
      state: "available",
      source: "path",
      command: "python",
      versions: { python: "3.14.6", unicorn: "2.1.4", unicornCore: "2.1.4", capstone: "5.0.9", pefile: "2024.8.26" },
      pin: "exact",
      reason: null,
    }),
    readMemory: async (_h, address, size) => {
      const bytes = o.memory.read(BigInt(address), size);
      if (bytes.length === 0)
        return err({ _tag: "AddressUnmapped", operation: "mem.read", address, module_map_id: null });
      const r: MemReadResult = {
        address,
        size: bytes.length,
        region: { region: "image", kind: "image" },
        data: Buffer.from(bytes).toString("base64"),
        encoding: "base64",
        overlayRestored: 0,
      };
      return ok(r);
    },
    regions: async () =>
      ok({
        regions: o.memory.regions.map((r): RegionInfo => ({
          start: formatHex(r.base),
          end: formatHex(r.base + BigInt(r.bytes.length)),
          name: r.module ?? "heap",
          kind: r.module === null ? "heap" : "image",
          perms: r.prot,
          ...(r.module === null ? {} : { module: r.module }),
        })),
        syntheticBase: "0x10000",
      }),
    disassemble: async () => ok({ instructions: [...(o.insns ?? [])], function: o.fn ?? null }),
  });

export const newEvidenceLog = (): FakeEvidenceLog => ({ drafts: [], applied: [], captures: 0 });
