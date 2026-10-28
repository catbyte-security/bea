import { materializeBuffer, registerFile } from "../../../../../src/agent/pure/callMaterialize.js";
import { notImplementedPort } from "../../../../../src/application/notImplemented.js";
import type { AddressRef } from "../../../../../src/domain/address/addressRef.js";
import { Deadline } from "../../../../../src/domain/deadline.js";
import type { BeaError } from "../../../../../src/domain/errors/beaError.js";
import { mapAgentError } from "../../../../../src/domain/errors/agentErrorMap.js";
import { COMPLETE } from "../../../../../src/domain/evidence/coverage.js";
import { NO_PERTURBATION, type BeaEvidence } from "../../../../../src/domain/evidence/record.js";
import { idOf, type EvId, type FxId, type MmId, type PiId, type StId } from "../../../../../src/domain/ids.js";
import type { JsonObject, JsonValue } from "../../../../../src/domain/json.js";
import type { ModuleMap } from "../../../../../src/domain/process/instance.js";
import { err, ok, type Result } from "../../../../../src/domain/result.js";
import type { AddressService, ResolvedAddress } from "../../../../../src/ports/address.js";
import type { AgentRpc } from "../../../../../src/ports/agentRpc.js";
import type {
  EvidenceDraft,
  EvidenceRuntime,
  EffectDraft,
  RecordedEvidence,
  SensitiveLiterals,
  StreamSpec,
} from "../../../../../src/ports/evidence.js";
import type { DynamicSessionPort, LiveSession, OperationContext } from "../../../../../src/ports/sessions.js";
import type {
  AgentError,
  CallFunctionParams,
  CallFunctionResult,
  FaultInfo,
} from "../../../../../src/shared/agentProtocol.js";
import type { StatusCode } from "../../../../../src/shared/callPlan.js";

/**
 * WP11 boundary fakes (owned by WP11; the shared fakes of WP1/WP4 are not used so these tests do not depend on their
 * progress). The fake agent EXECUTES lowered plans with the real executor helpers (src/agent/pure/callMaterialize.ts),
 * so the host lowering and the executor contract are tested together; target functions are small JS models.
 */
export const BASE = 0x7ff6_0000_0000n;
export const SESSION_ID = "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b";
export const ATTACHED_ID = "7a2b3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c8d";
export const RVAS = { add_ints: 0x1500n, four_floats: 0x1600n, touch_counter: 0x1700n, bump_speed: 0x1800n } as const;
const PI = idOf("pi", { t: "fake-pi" }) as PiId;
const MM = idOf("mm", { t: "fake-mm" }) as MmId;

const hex = (v: bigint): `0x${string}` => `0x${BigInt.asUintN(64, v).toString(16)}`;
const f32 = (bits: bigint): number => new Float32Array(new Uint32Array([Number(bits & 0xffffffffn)]).buffer)[0] ?? 0;
const f32bits = (x: number): bigint => BigInt(new Uint32Array(new Float32Array([x]).buffer)[0] ?? 0);

type Model = (
  regs: { gpr: bigint[]; xmm: bigint[] },
  memory: Map<bigint, Uint8Array>,
) => { rax?: bigint; xmm0?: bigint } | { fault: Omit<FaultInfo, "index" | "registers"> };

/** JS models of fixture-like functions, by VA. */
const MODELS: ReadonlyMap<bigint, Model> = new Map<bigint, Model>([
  [BASE + RVAS.add_ints, ({ gpr }) => ({ rax: BigInt.asUintN(32, (gpr[0] ?? 0n) + (gpr[1] ?? 0n)) })],
  [
    BASE + RVAS.four_floats,
    ({ xmm }) => ({
      xmm0: f32bits(
        Math.fround(
          Math.fround(f32(xmm[0] ?? 0n) * 1000) +
            Math.fround(f32(xmm[1] ?? 0n) * 100) +
            Math.fround(f32(xmm[2] ?? 0n) * 10) +
            f32(xmm[3] ?? 0n),
        ),
      ),
    }),
  ],
  [
    BASE + RVAS.touch_counter,
    ({ gpr }) =>
      gpr[0] === 0n
        ? {
            fault: {
              type: "access-violation",
              address: hex(BASE + RVAS.touch_counter + 4n),
              memory: { operation: "write", address: "0x4" },
              code: "0xc0000005",
              information: ["0x1", "0x4"],
              module: "live_fixture.exe",
              rva: hex(RVAS.touch_counter + 4n),
            },
          }
        : { rax: 0n },
  ],
  [
    // float bump_speed(Car*): speed (+0) += 1.0f, returns the new speed
    BASE + RVAS.bump_speed,
    ({ gpr }, memory) => {
      const bytes = memory.get(gpr[0] ?? 0n);
      if (bytes === undefined)
        return {
          fault: {
            type: "access-violation",
            address: hex(BASE + RVAS.bump_speed),
            memory: { operation: "read", address: hex(gpr[0] ?? 0n) },
            code: "0xc0000005",
            information: [],
            module: "live_fixture.exe",
            rva: hex(RVAS.bump_speed),
          },
        };
      const view = new DataView(bytes.buffer, bytes.byteOffset);
      const speed = Math.fround(view.getFloat32(0, true) + 1);
      view.setFloat32(0, speed, true);
      return { xmm0: f32bits(speed) };
    },
  ],
]);

export interface FakeAgentOptions {
  /** vectors completed per callFunction RPC before next_offset (time-slice model) */
  perRpc?: number;
  /** reply for the n-th callFunction RPC (1-based) instead of running it */
  failOnRpc?: { readonly n: number; readonly error: AgentError };
  /** fake memory for readMemory (address -> bytes) */
  memory?: Map<bigint, Uint8Array>;
  /** thread FP environments for captureThreadState */
  threads?: Map<number, { mxcsr: string; fpcw: string }>;
  /** called after each callFunction RPC (e.g. to advance a manual clock) */
  afterRpc?: () => void;
  exceptionModel?: "seh-frame" | "steal";
}

export interface FakeAgent extends AgentRpc {
  readonly calls: { readonly method: string; readonly params: unknown }[];
}

const runPlan = (p: CallFunctionParams, options: FakeAgentOptions): CallFunctionResult => {
  const status: StatusCode[] = [];
  const rax: `0x${string}`[] = [];
  const xmm0lo: `0x${string}`[] = [];
  const out: Record<string, string[]> = {};
  const faults: FaultInfo[] = [];
  const limit = Math.min(p.vectors.count, options.perRpc ?? p.vectors.count);
  const addresses = new Map(p.plan.buffers.map((b, i) => [b.name, 0x10_0000n + BigInt(i) * 0x1_0000n]));
  for (let i = 0; i < limit; i++) {
    const addressOf = (name: string): bigint => addresses.get(name) ?? 0n;
    const images = new Map(p.plan.buffers.map((b) => [b.name, materializeBuffer(b, p.vectors, i, addressOf)]));
    const memory = new Map([...images].map(([name, bytes]) => [addressOf(name), bytes]));
    const regs = registerFile(p.plan, p.vectors, i, addressOf, (name) => images.get(name) ?? new Uint8Array());
    const model = MODELS.get(BigInt(p.plan.target));
    const r = model === undefined ? { rax: 0n } : model(regs, memory);
    if ("fault" in r) {
      status.push("fault");
      faults.push({ ...r.fault, index: p.vectors.offset + i, registers: { rip: r.fault.address, rsp: "0x1000" } });
      rax.push("0x0");
      xmm0lo.push("0x0");
    } else {
      status.push("ok");
      rax.push(hex(r.rax ?? 0n));
      xmm0lo.push(hex(r.xmm0 ?? 0n));
    }
    for (const b of p.plan.buffers)
      if (b.out) (out[b.name] ??= []).push(Buffer.from(images.get(b.name) ?? new Uint8Array()).toString("hex"));
  }
  return {
    raw: {
      completed: limit,
      status,
      rax,
      xmm0lo,
      out,
      mxcsrOut: status.map(() => hex(BigInt(p.fp.mxcsr))),
      fpcwOut: status.map(() => hex(BigInt(p.fp.fpcw))),
    },
    next_offset: limit < p.vectors.count ? p.vectors.offset + limit : null,
    thread_id: p.thread.kind === "thread" ? p.thread.tid : 4242,
    faults,
    lost_target: false,
    exception_model: options.exceptionModel ?? "seh-frame",
    callee_exceptions: 0,
    bea_traps_during_call: 0,
    coverage:
      p.coverage.mode === "blocks"
        ? status.map((_, i) => ({
            index: p.vectors.offset + i,
            blocks: [
              [p.plan.target, 16],
              [hex(BigInt(p.plan.target) + 0x20n), 8],
            ] as [`0x${string}`, number][],
            truncated: false,
          }))
        : null,
    resolved: {
      va: p.plan.target,
      module: "live_fixture.exe",
      module_base: hex(BASE),
      rva: hex(BigInt(p.plan.target) - BASE),
      export: null,
      function: null,
      protection: "r-x",
    },
    perturbation: { target_instruments: [], overrides_bypassed: p.overrides === "bypass", hooks_suppressed: 0 },
    effect: {
      kind: "function-called",
      reversible: false,
      targets: [
        { address: p.plan.target, size: null },
        ...p.plan.buffers.map((b) => ({ address: hex(addresses.get(b.name) ?? 0n), size: b.size })),
      ],
      thread_ids: [4242],
      before: [],
    },
  };
};

export const createFakeAgent = (options: FakeAgentOptions = {}): FakeAgent => {
  const calls: { method: string; params: unknown }[] = [];
  let callRpcs = 0;
  const reply = (method: string, error: AgentError, op: OperationContext): Result<never, BeaError> => {
    void method;
    return err(mapAgentError(error, { operation: op.name }));
  };
  return {
    calls,
    health: { state: "ok" },
    call: (async (method: string, params: unknown, opts: { op: OperationContext }) => {
      calls.push({ method, params });
      if (method === "callFunction") {
        callRpcs += 1;
        const failure = options.failOnRpc;
        const result =
          failure !== undefined && failure.n === callRpcs
            ? reply(method, failure.error, opts.op)
            : ok(runPlan(params as CallFunctionParams, options));
        options.afterRpc?.();
        return result;
      }
      if (method === "readMemory") {
        const { address, size } = params as { address: string; size: number };
        const bytes = options.memory?.get(BigInt(address));
        if (bytes === undefined)
          return ok({
            value: {
              address,
              requested: size,
              returned: 0,
              complete: false,
              stop: { reason: "unmapped", at: address },
              bea_guard_suspended: [],
            },
            data: Buffer.alloc(0),
          });
        return ok({
          value: { address, requested: size, returned: size, complete: true, stop: null, bea_guard_suspended: [] },
          data: Buffer.from(bytes.subarray(0, size)),
        });
      }
      if (method === "captureThreadState") {
        const { tid } = params as { tid: number };
        const env = options.threads?.get(tid);
        if (env === undefined)
          return reply(method, { _tag: "NotFound", message: "no thread", what: "thread", id: String(tid) }, opts.op);
        return ok({
          tid,
          registers: {},
          eflags: "0x202",
          mxcsr: env.mxcsr,
          fpcw: env.fpcw,
          xmm: null,
          teb: null,
          peb: null,
          stack: null,
          tls: null,
        });
      }
      return reply(method, { _tag: "Unsupported", message: "fake", feature: method, reason: "fake" }, opts.op);
    }) as AgentRpc["call"],
  };
};

export const fakeLiveSession = (agent: AgentRpc, over: Partial<LiveSession> = {}): LiveSession =>
  ({
    id: SESSION_ID,
    kind: "live",
    ownership: "owned",
    state: "running",
    instanceId: PI,
    identity: {
      deviceId: "local",
      pid: 1234,
      startTime: { source: "os-creation-time", value: "1" },
      image: {
        path: "C:\\fx\\live_fixture.exe",
        sha256: null,
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
    streams: notImplementedPort("streams"),
    output: null,
    lastCrash: null,
    paused: false,
    jobs: notImplementedPort("jobs"),
    scripts: notImplementedPort("scripts"),
    liveness: () => ({ state: "alive", basis: "jobhost" }),
    waitFor: () => Promise.reject(new Error("not used")),
    crash: async () => ok(null),
    ...over,
  }) as LiveSession;

/** DynamicSessionPort subset sessionAccess.liveOp uses (admit, kindOf, withSession). */
export const fakeSessions = (sessions: readonly LiveSession[]): DynamicSessionPort => {
  const base = notImplementedPort<DynamicSessionPort>("sessions");
  let opId = 0;
  return Object.assign(Object.create(base) as DynamicSessionPort, {
    admit: async <T>(
      name: string,
      req: { signal?: AbortSignal; timeoutMs?: number },
      fn: (op: OperationContext) => Promise<Result<T, BeaError>>,
    ) =>
      fn({
        opId: ++opId,
        name,
        signal: req.signal ?? new AbortController().signal,
        deadline: Deadline.after(req.timeoutMs ?? 30_000),
      }),
    kindOf: (id: string) => (sessions.some((s) => s.id === id) ? "live" : null),
    withSession: async <T>(
      id: string,
      _op: OperationContext,
      _mode: string,
      fn: (s: LiveSession) => Promise<Result<T, BeaError>>,
    ) => {
      const s = sessions.find((x) => x.id === id);
      if (s === undefined) throw new Error("unknown session");
      return fn(s);
    },
    closing: false,
  });
};

const ref = (va: bigint, module: string | null): AddressRef => ({
  va: hex(va),
  module,
  rva: module === null ? null : hex(va - BASE),
  static_va: null,
  static_base: null,
  static_base_source: null,
  module_map_id: MM,
});

export interface FakeAddress extends AddressService {
  readonly resolved: string[];
}
export const fakeAddress = (): FakeAddress => {
  const resolved: string[] = [];
  const base = notImplementedPort<AddressService>("address");
  return Object.assign(Object.create(base) as AddressService, {
    resolved,
    resolve: async (
      _space: unknown,
      expr: string,
      op: OperationContext,
    ): Promise<Result<ResolvedAddress, BeaError>> => {
      resolved.push(expr);
      const exported = /^live_fixture\.exe!(\w+)$/u.exec(expr);
      if (exported?.[1] !== undefined && exported[1] in RVAS) {
        const va = BASE + RVAS[exported[1] as keyof typeof RVAS];
        return ok({ ref: ref(va, "live_fixture.exe"), moduleMapId: MM, va });
      }
      if (/^0x[0-9a-f]+$/iu.test(expr)) return ok({ ref: ref(BigInt(expr), null), moduleMapId: MM, va: BigInt(expr) });
      return err({ _tag: "AddressUnmapped", operation: op.name, address: expr.slice(0, 64), module_map_id: MM });
    },
    describeCode: async (_space: unknown, va: bigint) => ({
      va: hex(va),
      at: `live_fixture.exe+${hex(va - BASE)}`,
      static: null,
      func: `live_fixture.exe+${hex((va - BASE) & ~0xffn)}`,
      sym: null,
    }),
    prepare: async () => undefined,
  }) as FakeAddress;
};

export interface FakeEvidence extends EvidenceRuntime {
  readonly records: BeaEvidence<JsonValue>[];
  readonly effectDrafts: EffectDraft[];
  readonly streamsOpened: { spec: StreamSpec; rows: JsonValue[]; ended: boolean }[];
}

const LITERALS: SensitiveLiterals = { count: 0, texts: [], spellings: [] };

export const fakeEvidence = (): FakeEvidence => {
  const records: BeaEvidence<JsonValue>[] = [];
  const effectDrafts: EffectDraft[] = [];
  const streamsOpened: { spec: StreamSpec; rows: JsonValue[]; ended: boolean }[] = [];
  let seq = 0;
  const map: ModuleMap = {
    module_map_id: MM,
    instance_id: PI,
    completeness: "complete",
    modules: [
      {
        base: hex(BASE),
        size: 0x10000,
        path_sha256: "0".repeat(64),
        display: { name: "live_fixture.exe", path: null },
      },
    ],
  };
  const base = notImplementedPort<EvidenceRuntime>("evidence");
  const runtime = {
    records,
    effectDrafts,
    streamsOpened,
    literals: (perCall: readonly string[] | undefined) =>
      (perCall ?? []).some((t) => Buffer.byteLength(t) < 4)
        ? err({
            _tag: "InputError",
            operation: "literals",
            issues: [{ path: "sensitive_values", reason: "invalid_value", message: "too short" }],
          })
        : ok({ ...LITERALS, count: perCall?.length ?? 0, texts: [...(perCall ?? [])] }),
    instances: {
      capture: () => ({
        anchor: {
          run_id: "run_20260101T000000Z_0000000000000000",
          seq: ++seq,
          mono_ns: "1",
          wall: "2026-01-01T00:00:00.000Z",
          effect_epoch: 0,
          module_map_epoch: 1,
        },
        module_map_id: MM,
        perturbation: NO_PERTURBATION,
        tainted_count: 0,
      }),
      get: () => undefined,
    },
    modules: { current: () => ({ epoch: 1, map: () => map }) },
    effects: {
      apply: async (draft: EffectDraft) => {
        effectDrafts.push(draft);
        return ok({ effect_id: idOf("fx", { t: "fake-fx", n: effectDrafts.length }) as FxId });
      },
    },
    streams: {
      open: async (spec: StreamSpec) => {
        const entry = { spec, rows: [] as JsonValue[], ended: false };
        streamsOpened.push(entry);
        return ok({
          stream_id: idOf("st", { t: "fake-st", n: streamsOpened.length }) as StId,
          descriptor_sha256: "0".repeat(64),
          append: (_h: unknown, payload: Uint8Array) => {
            for (const line of Buffer.from(payload).toString("utf8").split("\n"))
              if (line.length > 0) entry.rows.push(JSON.parse(line) as JsonValue);
            return "accepted" as const;
          },
          noteDropped: () => undefined,
          end: async () => {
            entry.ended = true;
            return ok({
              record: { evidence_id: idOf("ev", { t: "fake-manifest", n: streamsOpened.length }) as EvId },
              outcome: "added",
            } as unknown as RecordedEvidence<JsonObject>);
          },
          counters: { records: 0, dropped: 0, redacted: 0, bytes: 0, state: "live" as const },
          onQuota: () => undefined,
        });
      },
    },
    blobs: {
      put: async (src: Uint8Array, meta: { role: string; media_type: string }) =>
        ok({
          role: meta.role,
          sha256: Buffer.from(src.subarray(0, 32)).toString("hex").padEnd(64, "0").slice(0, 64),
          bytes: src.length,
          media_type: meta.media_type,
        }),
    },
    recorder: {
      record: async <R extends JsonValue>(draft: EvidenceDraft<R>): Promise<Result<RecordedEvidence<R>, BeaError>> => {
        const record = {
          schema: "bea.evidence/1",
          evidence_id: idOf("ev", { t: "fake-ev", n: records.length + 1 }) as EvId,
          predicate_type: draft.predicate_type,
          operation: draft.operation,
          parameters: draft.input,
          subject: { kind: "process-instance", instance_id: PI, module_map_id: MM },
          observed_at: draft.capture?.anchor ?? null,
          provider: draft.provider,
          agent: draft.agent ?? null,
          confidence: "observed",
          authority: draft.authority ?? "live-process",
          perturbation: NO_PERTURBATION,
          result: draft.result,
          raw_result: draft.raw_result ?? null,
          blobs: [...(draft.blobs ?? [])],
          coverage: draft.coverage ?? COMPLETE,
          limitations: [...new Set(draft.limitations ?? [])].sort(),
          locations: [],
          evidence_links: [...(draft.evidence_links ?? [])],
          external_refs: [],
          effects: [...(draft.effects ?? [])],
          redactions: [],
          untrusted: true,
        } as unknown as BeaEvidence<R>;
        records.push(record as BeaEvidence<JsonValue>);
        return ok({ record, outcome: "added" });
      },
    },
  };
  return Object.assign(Object.create(base) as EvidenceRuntime, runtime) as FakeEvidence;
};
