import { mkdtemp, open, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { AddressRef } from "../../../src/domain/address/addressRef.js";
import { canonicalDigest, sha256Hex } from "../../../src/domain/canonical.js";
import { Deadline } from "../../../src/domain/deadline.js";
import type { BeaError } from "../../../src/domain/errors/beaError.js";
import { sessionNotFound } from "../../../src/domain/errors/constructors.js";
import { PREDICATES } from "../../../src/domain/evidence/predicates.js";
import { NO_PERTURBATION, type BeaEvidence, type BlobRef } from "../../../src/domain/evidence/record.js";
import type { EvId, MmId, PiId } from "../../../src/domain/ids.js";
import type { JsonObject, JsonValue } from "../../../src/domain/json.js";
import { err, ok, type Result } from "../../../src/domain/result.js";
import { notImplementedError } from "../../../src/application/notImplemented.js";
import type { AddressService, ByteVerification } from "../../../src/ports/address.js";
import type { AgentRpc } from "../../../src/ports/agentRpc.js";
import type {
  AnchorCapture,
  BlobStore,
  EvidenceDraft,
  EvidenceRuntime,
  InstanceRegistry,
  RecordedEvidence,
} from "../../../src/ports/evidence.js";
import type { FileHashCache, PeImage, PeImageCache } from "../../../src/ports/pe.js";
import type {
  AgentJobOutcome,
  DynamicSessionPort,
  LiveSession,
  OperationContext,
} from "../../../src/ports/sessions.js";
import type {
  AgentMethodName,
  AgentParams,
  DumpItem,
  DumpManifest,
  DumpRegion,
  DumpStartParams,
  ImportRow,
  ModuleInfo,
  RangeRow,
  ThreadInfo,
  ThreadState,
} from "../../../src/shared/agentProtocol.js";
import { formatHex, type Hex } from "../../../src/shared/hex.js";
import { buildPe, mapPe, SCN_CODE, SCN_DATA, SCN_RDATA, type BuiltPe } from "./peBuilder.js";

/**
 * WP13-local fakes of the frozen ports the dump code uses: a fake target (sparse memory, modules, threads, BEA patch
 * originals) behind a fake agent that answers dumpStart / listModules / listRanges / listThreads / listImports like
 * src/agent/dump.ts and the core inspect RPCs would; LiveSession.jobs; an in-memory EvidenceRuntime (blob store,
 * recorder, anchor capture); AddressService (resolve + verify with configured patch classes) and the PE ports.
 * The shared area fakes of WP1/WP4/WP5 do not exist yet in this wave.
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

export const PI: PiId = `pi_${"a".repeat(64)}`;
const MM: MmId = `mm_${"b".repeat(64)}`;
export const LIVE_ID = "11111111-1111-4111-8111-111111111111";
export const GAME_BASE = 0x7ff6_a000_0000n;
const GAME_PATH = "C:\\games\\game_sim.exe";
export const TEB = 0x20000n;
const PEB = 0x50000n;
const SLOTS = 0x30000n;
export const TLS_BLOCK = 0x31000n;
export const HEAP = 0x60000n;
const PAGE = 0x1000;

/** game_sim-like image: .text, .rdata (with a TLS directory), .data (TLS index), relocations. */
const gameImage = (): BuiltPe =>
  buildPe({
    preferredBase: 0x1_4000_0000n,
    sections: [
      {
        name: ".text",
        rva: 0x1000,
        data: new Uint8Array(0x1800).map((_, i) => (i * 7 + 3) & 0xff),
        characteristics: SCN_CODE,
      },
      { name: ".rdata", rva: 0x3000, data: new Uint8Array(0x400), characteristics: SCN_RDATA },
      {
        name: ".data",
        rva: 0x4000,
        data: new Uint8Array(0x300).fill(0x11),
        virtualSize: 0x1200,
        characteristics: SCN_DATA,
      },
    ],
    pointerSites: [
      { rva: 0x1100, target: 0x1760 },
      { rva: 0x3010, target: 0x4000 },
      { rva: 0x4008, target: 0x1000 },
    ],
    debug: { entryRva: 0x3100, dataRva: 0x3200, dataSize: 0x20 },
  });

interface MemRegion {
  base: bigint;
  bytes: Uint8Array;
  prot: string;
  module: string | null;
}

export class FakeTarget {
  readonly pe = gameImage();
  readonly regions: MemRegion[] = [];
  readonly modules: ModuleInfo[];
  /** BEA's originals overlay (what the agent splices with original_bytes) */
  readonly beaPatches: { address: bigint; original: Uint8Array }[] = [];
  readonly threads: ThreadInfo[] = [];
  readonly states = new Map<number, ThreadState>();
  readonly imports: ImportRow[] = [];
  constructor() {
    const image = mapPe(this.pe.file, GAME_BASE);
    // TLS directory in .rdata (mapped image only), index variable in .data = 1, slots[1] = TLS_BLOCK
    const v = new DataView(image.buffer);
    v.setUint32(0x98 + 112 + 8 * 9, 0x3300, true);
    v.setUint32(0x98 + 112 + 8 * 9 + 4, 0x28, true);
    v.setBigUint64(0x3300, GAME_BASE + 0x4100n, true);
    v.setBigUint64(0x3308, GAME_BASE + 0x4110n, true);
    v.setBigUint64(0x3310, GAME_BASE + 0x4200n, true);
    v.setUint32(0x3320, 0x10, true);
    v.setUint32(0x4200, 1, true);
    // readable module ranges: headers r--, .text r-x, .rdata r--, .data rw- (0x5000 page unmapped: a gap), .reloc r--
    this.map(GAME_BASE, image.subarray(0, 0x1000), "r--", "game_sim.exe");
    this.map(GAME_BASE + 0x1000n, image.subarray(0x1000, 0x3000), "r-x", "game_sim.exe");
    this.map(GAME_BASE + 0x3000n, image.subarray(0x3000, 0x4000), "r--", "game_sim.exe");
    this.map(GAME_BASE + 0x4000n, image.subarray(0x4000, 0x5000), "rw-", "game_sim.exe");
    this.map(GAME_BASE + 0x6000n, image.subarray(0x6000, 0x7000), "r--", "game_sim.exe");
    this.modules = [
      {
        name: "game_sim.exe",
        path: GAME_PATH,
        base: formatHex(GAME_BASE),
        size: this.pe.sizeOfImage,
        pe: {
          machine: 0x8664,
          time_date_stamp: 0,
          size_of_image: this.pe.sizeOfImage,
          checksum: 0,
          entry_rva: "0x1000",
          subsystem: 3,
          dll_characteristics: 0x160,
          mapped_image_base: formatHex(GAME_BASE),
          section_count: 4,
          codeview: null,
          tls_callbacks: [],
          pdata_entries: 0,
        },
      },
      { name: "ntdll.dll", path: "C:\\Windows\\System32\\ntdll.dll", base: "0x7ffd00000000", size: 0x1f0000, pe: null },
    ];
    const teb = new Uint8Array(0x2000);
    const tv = new DataView(teb.buffer);
    tv.setBigUint64(0x08, 0x200000n, true);
    tv.setBigUint64(0x10, 0x1f0000n, true);
    tv.setBigUint64(0x58, SLOTS, true);
    tv.setBigUint64(0x60, PEB, true);
    this.map(TEB, teb, "rw-", null);
    this.map(PEB, new Uint8Array(PAGE).fill(0x50), "rw-", null);
    const slots = new Uint8Array(PAGE);
    new DataView(slots.buffer).setBigUint64(8, TLS_BLOCK, true);
    this.map(SLOTS, slots, "rw-", null);
    this.map(TLS_BLOCK, new Uint8Array(PAGE).fill(0x77), "rw-", null);
    this.map(0x1f8000n, new Uint8Array(0x8000).fill(0x5a), "rw-", null);
    this.map(0x7ffe0000n, new Uint8Array(PAGE).fill(0x7f), "r--", null);
    this.map(
      HEAP,
      new Uint8Array(0x2000).map((_, i) => i & 0xff),
      "rw-",
      null,
    );
    this.threads.push(
      {
        id: 100,
        state: "running",
        entry: formatHex(GAME_BASE + 0x1000n),
        teb: null,
        stack: null,
        name: null,
        regs: null,
        bea_role: null,
      },
      {
        id: 200,
        state: "waiting",
        entry: "0x7ffd00001000",
        teb: null,
        stack: null,
        name: null,
        regs: null,
        bea_role: null,
      },
      { id: 300, state: "waiting", entry: null, teb: null, stack: null, name: null, regs: null, bea_role: "agent" },
    );
    const regs = Object.fromEntries(
      [
        "rip",
        "rsp",
        "rbp",
        "rax",
        "rbx",
        "rcx",
        "rdx",
        "rsi",
        "rdi",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
      ].map((k, i) => [k, formatHex(0x1000 + i)]),
    ) as Record<string, Hex>;
    regs["rsp"] = "0x1f8100";
    for (const tid of [100, 200])
      this.states.set(tid, {
        tid,
        registers: regs,
        eflags: "0x246",
        mxcsr: "0x1fa0",
        fpcw: "0x37f",
        xmm: Array.from({ length: 16 }, (_, i) => formatHex(i)),
        teb: formatHex(TEB + BigInt(tid === 100 ? 0 : 0x2000)),
        peb: formatHex(PEB),
        stack: { base: "0x200000", limit: "0x1f0000" },
        tls: { static_tls_array: formatHex(SLOTS), tls_slots: [] },
      });
    this.map(TEB + 0x2000n, new Uint8Array(0x2000), "rw-", null);
    this.imports.push(
      {
        name: "Sleep",
        ordinal: null,
        from_module: "KERNEL32.dll",
        kind: "function",
        slot: formatHex(GAME_BASE + 0x3080n),
        resolved: "0x7ffd00012340",
        delay: false,
      },
      { name: null, ordinal: 7, from_module: null, kind: null, slot: null, resolved: null, delay: false },
    );
  }
  map(base: bigint, bytes: Uint8Array, prot: string, module: string | null): void {
    this.regions.push({ base, bytes: bytes.slice(), prot, module });
    this.regions.sort((a, b) => (a.base < b.base ? -1 : 1));
  }
  regionAt(va: bigint): MemRegion | undefined {
    return this.regions.find((r) => va >= r.base && va < r.base + BigInt(r.bytes.length));
  }
  write(va: bigint, bytes: Uint8Array): void {
    const r = this.regionAt(va);
    if (r === undefined) throw new Error("write outside memory");
    r.bytes.set(bytes, Number(va - r.base));
  }
  /** A BEA hook: live bytes become a jmp; the agent's originals overlay keeps the old bytes. */
  hook(va: bigint): void {
    const r = this.regionAt(va);
    if (r === undefined) throw new Error("hook outside memory");
    const off = Number(va - r.base);
    this.beaPatches.push({ address: va, original: r.bytes.slice(off, off + 5) });
    r.bytes.set([0xe9, 0x01, 0x02, 0x03, 0x04], off);
  }
  /** bytes + page holes of [base, base+size) */
  read(base: bigint, size: number): { bytes: Uint8Array; holes: { offset: number; size: number }[] } {
    const bytes = new Uint8Array(size);
    const holes: { offset: number; size: number }[] = [];
    for (let off = 0; off < size;) {
      const va = base + BigInt(off);
      const r = this.regionAt(va);
      const pageLeft = PAGE - Number(va % BigInt(PAGE));
      const n = Math.min(pageLeft, size - off);
      if (r === undefined) {
        const last = holes[holes.length - 1];
        if (last !== undefined && last.offset + last.size === off) last.size += n;
        else holes.push({ offset: off, size: n });
      } else {
        const src = Number(va - r.base);
        bytes.set(r.bytes.subarray(src, src + n), off);
      }
      off += n;
    }
    return { bytes, holes };
  }
  ranges(): RangeRow[] {
    return this.regions.map((r) => ({
      base: formatHex(r.base),
      size: r.bytes.length,
      protection: r.prot,
      module: r.module,
      kind: r.module === null ? "private" : "module",
    }));
  }
}

// ---------------------------------------------------------------- evidence (in-memory)
export interface EvidenceLog {
  readonly drafts: EvidenceDraft<JsonValue>[];
  readonly blobs: Map<string, Uint8Array>;
  readonly redactLiteral: Uint8Array | null;
  readonly dir: string;
}
export const createEvidenceLog = async (redactLiteral: string | null = null): Promise<EvidenceLog> => ({
  drafts: [],
  blobs: new Map(),
  redactLiteral: redactLiteral === null ? null : new Uint8Array(Buffer.from(redactLiteral)),
  dir: await mkdtemp(join(tmpdir(), "bea-wp13-blobs-")),
});
export const disposeEvidenceLog = (log: EvidenceLog) => rm(log.dir, { recursive: true, force: true });

const contains = (hay: Uint8Array, needle: Uint8Array): boolean => Buffer.from(hay).includes(Buffer.from(needle));

const putBlob = (log: EvidenceLog, bytes: Uint8Array): BlobRef | { redacted: true } => {
  if (log.redactLiteral !== null && contains(bytes, log.redactLiteral)) return { redacted: true };
  const sha256 = sha256Hex(bytes);
  log.blobs.set(sha256, bytes);
  return { role: "agent.blob", sha256, bytes: bytes.length, media_type: "application/octet-stream" };
};

export const fakeEvidence = (log: EvidenceLog): EvidenceRuntime =>
  partialPort<EvidenceRuntime>("evidence", {
    literals: () => ok({ count: 0, texts: [], spellings: [] }),
    instances: partialPort<InstanceRegistry>("instances", {
      capture: (): AnchorCapture => ({
        anchor: {
          run_id: "run_20261028T000000Z_0123456789abcdef",
          seq: 9,
          mono_ns: "1",
          wall: "2026-10-28T00:00:00.000Z",
          effect_epoch: 2,
          module_map_epoch: 3,
        },
        module_map_id: MM,
        perturbation: NO_PERTURBATION,
        tainted_count: 0,
      }),
    }),
    locationOf: (ref: AddressRef, size?: number) => ({
      kind: "address",
      va: ref.va,
      size: size ?? null,
      module_map_id: ref.module_map_id,
      module_key: null,
      rva: ref.rva,
      image_sha256: null,
    }),
    blobs: partialPort<BlobStore>("blobs", {
      read: async (sha256: string, offset: number, length: number) => {
        const bytes = log.blobs.get(sha256);
        return bytes === undefined
          ? err({ _tag: "ReferenceNotFound", operation: "blobs.read", reference: { kind: "blob", id: sha256 } })
          : ok(bytes.slice(offset, offset + length));
      },
      open: async (sha256: string) => {
        const bytes = log.blobs.get(sha256);
        if (bytes === undefined)
          return err({ _tag: "ReferenceNotFound", operation: "blobs.open", reference: { kind: "blob", id: sha256 } });
        const file = join(log.dir, sha256);
        await writeFile(file, bytes);
        return ok(await open(file, "r"));
      },
    }),
    recorder: {
      record: async <R extends JsonValue>(draft: EvidenceDraft<R>): Promise<Result<RecordedEvidence<R>, BeaError>> => {
        log.drafts.push(draft as EvidenceDraft<JsonValue>);
        const spec = PREDICATES[draft.predicate_type];
        const record: BeaEvidence<R> = {
          schema: "bea.evidence/1",
          evidence_id: `ev_${canonicalDigest({ n: log.drafts.length, r: draft.result } as JsonObject)}` as EvId,
          predicate_type: draft.predicate_type,
          operation: draft.operation,
          parameters: draft.input,
          subject:
            draft.subject !== null && draft.subject.kind === "process-instance"
              ? {
                  kind: "process-instance",
                  instance_id: draft.subject.instance_id,
                  module_map_id: draft.capture?.module_map_id ?? null,
                }
              : null,
          observed_at: draft.capture?.anchor ?? null,
          provider: draft.provider,
          agent: null,
          confidence: spec.confidence === "per-call" ? "observed" : spec.confidence,
          authority: "live-process",
          perturbation: draft.capture?.perturbation ?? NO_PERTURBATION,
          result: draft.result,
          raw_result: null,
          blobs: [...(draft.blobs ?? [])],
          coverage: draft.coverage,
          limitations: [...(draft.limitations ?? [])],
          locations: [...(draft.locations ?? [])],
          evidence_links: [],
          external_refs: [],
          effects: [],
          redactions: [],
          untrusted: true,
        };
        return ok({ record, outcome: "added" });
      },
    },
  });

// ---------------------------------------------------------------- agent + jobs + session
type Handler = (params: never) => Result<unknown, BeaError> | Promise<Result<unknown, BeaError>>;

/** The fake agent's dumpStart: plans items like src/agent/dump.ts, "sends" every blob into the evidence log. */
const fakeDumpAgent = (target: FakeTarget, log: EvidenceLog) => {
  const jobs = new Map<string, AgentJobOutcome>();
  const calls: { method: AgentMethodName; params: unknown }[] = [];
  let next = 1;
  const dumpStart = (p: DumpStartParams): Result<unknown, BeaError> => {
    const regions: DumpRegion[] = [];
    const modules: DumpManifest["modules"] = [];
    const threads: ThreadState[] = [];
    const blobs = new Map<string, AgentJobOutcome["blobs"] extends ReadonlyMap<string, infer V> ? V : never>();
    const add = (kind: DumpRegion["kind"], base: bigint, size: number, module: string | null): string => {
      const blob = `b${String(next++)}`;
      const { bytes, holes } = target.read(base, size);
      const restored: { offset: number; size: number }[] = [];
      if (kind === "module" && p.original_bytes)
        for (const patch of target.beaPatches) {
          const off = Number(patch.address - base);
          if (off >= 0 && off + patch.original.length <= size) {
            bytes.set(patch.original, off);
            restored.push({ offset: off, size: patch.original.length });
          }
        }
      regions.push({
        blob,
        kind,
        base: formatHex(base),
        size,
        protection: target.regionAt(base)?.prot ?? "---",
        module,
        holes: holes.map((h) => ({ ...h, reason: "unreadable" })),
        bea_patches_restored: restored,
        sha256: null,
      });
      blobs.set(blob, putBlob(log, bytes));
      return blob;
    };
    for (const item of p.items as DumpItem[]) {
      if (item.kind === "module") {
        const m = target.modules.find((x) => BigInt(x.base) === BigInt(item.module) || x.name === item.module);
        if (m === undefined)
          return err({ _tag: "AddressUnmapped", operation: "dumpStart", address: item.module, module_map_id: null });
        modules.push({
          name: m.name,
          path: m.path,
          base: m.base,
          size: m.size,
          blob: add("module", BigInt(m.base), m.size, m.name),
        });
      } else if (item.kind === "range") add("range", BigInt(item.base), item.size, null);
      else if (item.kind === "thread") {
        const state = target.states.get(item.tid);
        if (state === undefined) continue;
        threads.push(state);
        if (item.teb && state.teb !== null) add("teb", BigInt(state.teb), 0x2000, null);
        add("peb", PEB, PAGE, null);
        if (item.stack_bytes > 0) add("stack", 0x1f8000n, Math.min(item.stack_bytes, 0x8000), null);
        if (item.tls) {
          add("tls", SLOTS, PAGE, null);
          add("tls", TLS_BLOCK, PAGE, "game_sim.exe");
        }
      }
    }
    const total = regions.reduce((n, r) => n + r.size, 0);
    const job = `j${String(next++)}`;
    jobs.set(job, {
      info: {
        job_id: job,
        kind: "dump",
        state: "done",
        progress: { done: total, total, unit: "bytes" },
        started_t: 0,
        ended_t: 1,
        error: null,
      },
      result: {
        format: "bea-dump/1",
        pid: 4242,
        taken: { t0: 0, t1: 1, suspended: p.suspend === "all" },
        modules,
        regions,
        threads,
        module_map_epoch: 3,
        truncated: total > p.max_total_bytes,
      },
      error: null,
      blobs,
    });
    return ok({ job_id: job, planned_bytes: total, planned_blobs: regions.length });
  };
  const handlers: Partial<Record<AgentMethodName, Handler>> = {
    dumpStart: dumpStart as Handler,
    listModules: (() => ok({ module_map_epoch: 3, modules: target.modules })) as Handler,
    listThreads: (() => ok({ threads: target.threads })) as Handler,
    listRanges: ((p: { offset: number; limit: number }) => {
      const rows = target.ranges().filter((r) => r.protection.startsWith("r"));
      const items = rows.slice(p.offset, p.offset + p.limit);
      const nextOffset = p.offset + items.length < rows.length ? p.offset + items.length : null;
      return ok({ total: rows.length, offset: p.offset, items, next_offset: nextOffset, snapshot: "ss1", taken_t: 0 });
    }) as Handler,
    listImports: ((p: { offset: number }) =>
      ok({ total: target.imports.length, offset: p.offset, items: target.imports, next_offset: null })) as Handler,
  };
  const agent: AgentRpc & { calls: typeof calls } = {
    health: { state: "ok" },
    calls,
    call: async <M extends AgentMethodName>(method: M, params: AgentParams<M>) => {
      calls.push({ method, params });
      const handler = handlers[method];
      if (handler === undefined) return err(notImplementedError(`agent.${method}`)) as never;
      return (await handler(params as never)) as never;
    },
  };
  const jobsPort = {
    await: async (jobId: string) => {
      const outcome = jobs.get(jobId);
      return outcome === undefined
        ? err({ _tag: "ReferenceNotFound", operation: "jobs.await", reference: { kind: "job", id: jobId } } as BeaError)
        : ok(outcome);
    },
  };
  return { agent, jobs: jobsPort, handlers };
};

export const fakeLiveSession = (target: FakeTarget, log: EvidenceLog) => {
  const { agent, jobs, handlers } = fakeDumpAgent(target, log);
  const session = {
    id: LIVE_ID,
    kind: "live",
    ownership: "owned",
    state: "running",
    instanceId: PI,
    identity: {
      deviceId: "local",
      pid: 4242,
      startTime: { source: "os-creation-time", value: "1" },
      image: {
        path: GAME_PATH,
        sha256: "c".repeat(64),
        size: null,
        machine: "x64",
        peTimestamp: null,
        preferredBase: null,
      },
      parentPid: null,
      osSessionId: null,
      integrity: "medium",
      launchedByBea: true,
    },
    agent,
    jobs,
    paused: false,
    lastCrash: null,
    liveness: () => ({ state: "alive", basis: "jobhost" }),
  } as unknown as LiveSession;
  return { session, agent, handlers };
};

export const testOp = (name = "dump_memory"): OperationContext => ({
  opId: 1,
  name,
  signal: new AbortController().signal,
  deadline: Deadline.after(60_000),
});

export const fakeSessions = (session: LiveSession): DynamicSessionPort =>
  partialPort<DynamicSessionPort>("sessions", {
    closing: false,
    admit: async (name, _req, fn) => fn(testOp(name)),
    kindOf: (id) => (id === session.id ? "live" : null),
    withSession: async (id, op, _mode, fn) => (id === session.id ? fn(session) : err(sessionNotFound(op.name, id))),
  });

// ---------------------------------------------------------------- address + PE
export interface AddressConfig {
  /** differences verify() reports, as module RVAs */
  readonly patches: readonly {
    readonly rva: number;
    readonly size: number;
    readonly class: "foreign-or-agent-patch" | "unexplained";
  }[];
}
export const fakeAddress = (
  target: FakeTarget,
  config: AddressConfig,
): AddressService & { verified: { va: bigint; len: number }[] } => {
  const verified: { va: bigint; len: number }[] = [];
  const service = partialPort<AddressService>("address", {
    resolve: async (_space, expr, op, opts) => {
      const m = /^(?:"([^"]+)"|([^+"]+))\+0x([0-9a-f]+)$/iu.exec(expr);
      let va: bigint;
      let module: ModuleInfo | undefined;
      if (m !== null) {
        const name = (m[1] ?? m[2] ?? "").toLowerCase();
        module = name === "$main" ? target.modules[0] : target.modules.find((x) => x.name.toLowerCase() === name);
        if (module === undefined)
          return err({
            _tag: "AddressUnmapped",
            operation: op.name,
            address: expr,
            module_map_id: MM,
            diagnostics: { path: opts?.path ?? "" },
          });
        va = BigInt(module.base) + BigInt(`0x${m[3] ?? "0"}`);
      } else if (/^0x[0-9a-f]+$/iu.test(expr)) va = BigInt(expr);
      else
        return err({
          _tag: "InputError",
          operation: op.name,
          issues: [{ path: opts?.path ?? "address", reason: "invalid_format", message: "bad AddrExpr" }],
        });
      const ref: AddressRef = {
        va: formatHex(va),
        module: module?.name ?? null,
        rva: module === undefined ? null : formatHex(va - BigInt(module.base)),
        static_va: null,
        static_base: null,
        static_base_source: null,
        module_map_id: MM,
      };
      return ok({ ref, moduleMapId: MM, va });
    },
    verify: async (_space, va, len): Promise<Result<ByteVerification, BeaError>> => {
      verified.push({ va, len });
      const rva0 = Number(va - GAME_BASE);
      const differences = config.patches
        .filter((p) => p.rva >= rva0 && p.rva < rva0 + len)
        .map((p) => ({ rva: formatHex(p.rva), size: p.size, class: p.class }));
      return ok({
        status: differences.length > 0 ? "mismatch" : "match",
        compared: len,
        equal: len,
        excluded_loader: 0,
        own_effects_restored: 0,
        differences,
      });
    },
  });
  return Object.assign(service, { verified });
};

export const fakePe = (target: FakeTarget): { images: PeImageCache; hashes: FileHashCache } => ({
  images: {
    open: async (path) => {
      if (path !== GAME_PATH)
        return err({
          _tag: "FileOperationFailed",
          operation: "pe.open",
          file_operation: "read",
          path,
          reason: "missing",
        });
      return ok(
        partialPort<PeImage>("peImage", {
          image_base: formatHex(target.pe.preferredBase),
          sections: target.pe.sections.map((s) => ({
            name: s.name,
            short_name: s.name.slice(0, 8),
            rva: s.rva,
            virtual_size: s.virtualSize,
            raw_offset: s.rawOffset,
            raw_size: s.rawSize,
            characteristics: s.characteristics,
            perms: `r${(s.characteristics & 0x80000000) !== 0 ? "w" : "-"}${(s.characteristics & 0x20000000) !== 0 ? "x" : "-"}`,
          })),
          relocations: async () => target.pe.relocations,
          imageBytes: async (rva: number, len: number, actualBase: bigint) =>
            mapPe(target.pe.file, actualBase).slice(rva, rva + len),
        }),
      );
    },
  },
  hashes: {
    sha256: async (path) => (path === GAME_PATH ? ok(sha256Hex(target.pe.file)) : err(notImplementedError("hash"))),
  },
});
