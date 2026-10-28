import { spawn as nodeSpawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { distLayoutAt, type DistLayout } from "../../../src/application/distLayout.js";
import { notImplementedPort } from "../../../src/application/notImplemented.js";
import { decodeOutcome, rawOutLayout } from "../../../src/domain/callModel/decode.js";
import type { AddressRef } from "../../../src/domain/address/addressRef.js";
import { Deadline } from "../../../src/domain/deadline.js";
import type { BeaError } from "../../../src/domain/errors/beaError.js";
import { sessionNotFound } from "../../../src/domain/errors/constructors.js";
import type { EvId, FxId, PiId } from "../../../src/domain/ids.js";
import { err, ok, type Result } from "../../../src/domain/result.js";
import type { AddressService, AddressSpace, ResolvedAddress } from "../../../src/ports/address.js";
import type { EmuPort, OracleBatchRequest, OracleBatchResult, OracleCallPort } from "../../../src/ports/emu.js";
import type { EvidenceRuntime } from "../../../src/ports/evidence.js";
import type {
  CloseReport,
  DynamicSessionPort,
  ExternalSessionDriver,
  ExternalSessionFactory,
  LiveSession,
  OperationContext,
  SessionEndedEvent,
  SessionSummary,
} from "../../../src/ports/sessions.js";
import type { SpawnFn } from "../../../src/providers/emulator/EmuBridge.js";
import type { RawBatchColumns, StatusCode } from "../../../src/shared/callPlan.js";
import { formatHex, type Hex } from "../../../src/shared/hex.js";

/**
 * WP14-EMU test support: the fake bridge (./fakeBridge.mjs) launched in place of Python, a scenario writer, and the
 * minimal port fakes the emulation services need (sessions with registerExternal, an AddressService for emulation and
 * live spaces, an OracleCallPort computing the same behaviours as the fake bridge). No real process other than the
 * fake bridge (node) is ever started.
 */
export const FAKE_BRIDGE = fileURLToPath(new URL("./fakeBridge.mjs", import.meta.url));

/** Runs the fake bridge with node whatever interpreter the client asks for (args after the command are kept). */
export const fakeSpawn: SpawnFn = (_command, args, options) =>
  nodeSpawn(process.execPath, [FAKE_BRIDGE, ...args], options);

/** The interpreter command that starts the fake bridge directly (EmuBridge.start tests). */
export const nodeAsPython = { command: process.execPath, prefixArgs: [FAKE_BRIDGE] } as const;

export interface FakeScenario {
  readonly sha256?: string;
  readonly version?: string;
  readonly protocol?: string;
  readonly ready?: "ok" | "fatal" | "none" | "garbage" | "exit";
  readonly readyDelayMs?: number;
  readonly ignoreCancel?: boolean;
  readonly crash?: { readonly method: string; readonly marker?: string };
  readonly functions?: Readonly<Record<string, string>>;
  readonly deviations?: Readonly<Record<string, readonly { kind: string; note: string; count?: number }[]>>;
  readonly open?: Readonly<Record<string, unknown>>;
  readonly openError?: { readonly code: string; readonly message: string };
  readonly openDelayMs?: number;
  readonly spinMs?: number;
  readonly memory?: string;
  readonly imageSha256?: string;
  readonly imagePath?: string;
  readonly probe?: Readonly<Record<string, unknown>>;
  readonly probeExit?: number;
  readonly delays?: Readonly<Record<string, number>>;
  readonly imports?: Readonly<Record<string, { calls: number; model: string }>>;
}

export interface ScenarioFile {
  readonly path: string;
  /** sha256 of the file: what the fake reports as its bridge sha256 (like the real bridge's own digest) */
  readonly sha256: string;
}

export const writeScenario = async (
  dir: string,
  scenario: FakeScenario,
  name = "bridge.json",
): Promise<ScenarioFile> => {
  const path = join(dir, name);
  const text = JSON.stringify(scenario);
  await writeFile(path, text, "utf8");
  return { path, sha256: createHash("sha256").update(text).digest("hex") };
};

export interface TempDir {
  readonly dir: string;
  readonly cleanup: () => Promise<void>;
}
export const tempDir = async (label: string): Promise<TempDir> => {
  const dir = await mkdtemp(join(tmpdir(), `bea-emu-${label}-`));
  return { dir, cleanup: () => rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }) };
};

/** A from-source dist layout whose bridge is the scenario file (no manifest: the digest is computed). */
export const scenarioLayout = (dir: string, scenario: ScenarioFile): DistLayout => ({
  ...distLayoutAt(join(dir, "dist"), true),
  bridgeScript: scenario.path,
  bridgeManifest: join(dir, "dist", "bridge-manifest.json"),
  bridgeRequirements: join(dir, "requirements.lock"),
});

// ================================================================ sessions
const opFor = (name: string, signal?: AbortSignal, timeoutMs = 120_000): OperationContext => ({
  opId: 1,
  name,
  signal: signal ?? new AbortController().signal,
  deadline: Deadline.after(timeoutMs),
});

/** DynamicSessionPort fake: emulation sessions through registerExternal, optional live sessions, tombstones. */
export class FakeSessionPort {
  readonly externals = new Map<string, ExternalSessionDriver>();
  readonly lives = new Map<string, LiveSession>();
  readonly tombstones = new Set<string>();
  readonly ended: SessionEndedEvent[] = [];
  #listeners = new Set<(event: SessionEndedEvent) => void>();
  #counter = 0;
  closing = false;

  port(): DynamicSessionPort {
    const stub = notImplementedPort<DynamicSessionPort>("sessions");
    return new Proxy(stub, {
      get: (target, prop) => {
        switch (prop) {
          case "admit":
            return <T>(
              name: string,
              req: { signal?: AbortSignal; timeoutMs?: number },
              fn: (op: OperationContext) => Promise<Result<T, BeaError>>,
            ) => fn(opFor(name, req.signal, req.timeoutMs));
          case "registerExternal":
            return (kind: "emulation", factory: ExternalSessionFactory, op: OperationContext) =>
              this.registerExternal(kind, factory, op);
          case "kindOf":
            return (id: string) => this.kindOf(id);
          case "external":
            return (id: string) => this.externals.get(id) ?? null;
          case "withSession":
            return <T>(
              id: string,
              op: OperationContext,
              _mode: string,
              fn: (s: LiveSession) => Promise<Result<T, BeaError>>,
            ) => {
              const live = this.lives.get(id);
              return live === undefined ? Promise.resolve(err(sessionNotFound(op.name, id))) : fn(live);
            };
          case "close":
            return (id: string, _options: unknown, op: OperationContext) => this.close(id, op);
          case "list":
            return () => this.summaries();
          case "onSessionEnded":
            return (listener: (event: SessionEndedEvent) => void) => {
              this.#listeners.add(listener);
              return () => this.#listeners.delete(listener);
            };
          case "closing":
            return this.closing;
          default:
            return Reflect.get(target, prop);
        }
      },
    });
  }

  async registerExternal(
    _kind: "emulation",
    factory: ExternalSessionFactory,
    op: OperationContext,
  ): Promise<Result<string, BeaError>> {
    this.#counter += 1;
    const id = `00000000-0000-4000-8000-${this.#counter.toString(16).padStart(12, "0")}`;
    const driver = await factory(id, op);
    if (!driver.ok) return driver;
    this.externals.set(id, driver.value);
    return ok(id);
  }

  kindOf(id: string): "live" | "emulation" | "closed" | null {
    if (this.externals.has(id)) return "emulation";
    if (this.lives.has(id)) return "live";
    return this.tombstones.has(id) ? "closed" : null;
  }

  async close(id: string, op: OperationContext): Promise<Result<CloseReport, BeaError>> {
    const driver = this.externals.get(id);
    if (driver === undefined) return err(sessionNotFound(op.name, id));
    const report = await driver.close(Deadline.after(2_000));
    this.externals.delete(id);
    this.tombstones.add(id);
    const event: SessionEndedEvent = { sessionId: id, kind: "emulation", reason: "closed" };
    this.ended.push(event);
    for (const listener of this.#listeners) listener(event);
    return report;
  }

  summaries(): SessionSummary[] {
    return [...this.externals.values()].map((d) => d.summary());
  }

  async closeAll(): Promise<void> {
    for (const id of Array.from(this.externals.keys())) await this.close(id, opFor("close_all"));
  }
}

// ================================================================ addresses
export interface FakeModule {
  readonly name: string;
  readonly base: bigint;
  readonly size: number;
  readonly sha256: string | null;
  readonly preferredBase: bigint | null;
  readonly primary?: boolean;
}

const unmapped = (operation: string, address: string): BeaError => ({
  _tag: "AddressUnmapped",
  operation,
  address,
  module_map_id: null,
});

/** AddressService fake: 0x…, module+0xRVA, +0xRVA and module!export over emulation (EmuPort.modules) or live tables. */
export class FakeAddressService {
  constructor(
    private readonly deps: {
      readonly emulator: () => EmuPort;
      readonly live?: readonly FakeModule[];
      /** "module!export" (lowercase module) -> rva */
      readonly exports?: Readonly<Record<string, number>>;
    },
  ) {}

  modulesOf(space: AddressSpace): FakeModule[] {
    if (space.kind === "emulation") {
      const emulator = this.deps.emulator();
      const handle = emulator.lookup(space.sessionId);
      if (handle === null) return [];
      return emulator.modules(handle).map((m) => ({
        name: m.name,
        base: BigInt(m.base),
        size: m.size,
        sha256: m.sha256,
        preferredBase: m.preferredBase === null ? null : BigInt(m.preferredBase),
        primary: m.primary,
      }));
    }
    return [...(this.deps.live ?? [])];
  }

  port(): AddressService {
    const stub = notImplementedPort<AddressService>("address");
    return new Proxy(stub, {
      get: (target, prop) =>
        prop === "resolve"
          ? (space: AddressSpace, expr: string, op: OperationContext) =>
              Promise.resolve(this.resolve(space, expr, op.name))
          : Reflect.get(target, prop),
    });
  }

  resolve(space: AddressSpace, expr: string, operation: string): Result<ResolvedAddress, BeaError> {
    const modules = this.modulesOf(space);
    const text = expr.trim();
    let va: bigint | null = null;
    const raw = /^0[xX]([0-9a-fA-F]{1,16})$/u.exec(text);
    const rel = /^([^+!]*)\+0[xX]([0-9a-fA-F]{1,16})$/u.exec(text);
    const exp = /^([^+!]+)!(.+)$/u.exec(text);
    if (raw?.[1] !== undefined) va = BigInt(`0x${raw[1]}`);
    else if (rel !== null) {
      const name = rel[1] ?? "";
      const module =
        name === ""
          ? (modules.find((m) => m.primary) ?? modules[0])
          : modules.find((m) => m.name.toLowerCase() === name.toLowerCase());
      if (module === undefined)
        return err({
          _tag: "InputError",
          operation,
          issues: [{ path: "address", reason: "invalid_value", message: `no module ${name}` }],
        });
      va = module.base + BigInt(`0x${rel[2] ?? "0"}`);
    } else if (exp !== null) {
      const name = (exp[1] ?? "").toLowerCase();
      const module = modules.find((m) => m.name.toLowerCase() === name);
      const rva = this.deps.exports?.[`${name}!${exp[2] ?? ""}`];
      if (module === undefined || rva === undefined)
        return err({
          _tag: "InputError",
          operation,
          issues: [{ path: "address", reason: "invalid_value", message: `unknown symbol ${text}` }],
        });
      va = module.base + BigInt(rva);
    } else
      return err({
        _tag: "InputError",
        operation,
        issues: [{ path: "address", reason: "invalid_format", message: "bad AddrExpr" }],
      });
    const module = modules.find((m) => va !== null && va >= m.base && va < m.base + BigInt(m.size)) ?? null;
    if (module === null && raw === null) return err(unmapped(operation, formatHex(va)));
    const ref: AddressRef = {
      va: formatHex(va),
      module: module?.name ?? null,
      rva: module === null ? null : formatHex(va - module.base),
      static_va:
        module === null || module.preferredBase === null ? null : formatHex(module.preferredBase + (va - module.base)),
      static_base: module?.preferredBase === null || module === null ? null : formatHex(module.preferredBase),
      static_base_source: module?.preferredBase === null || module === null ? null : "pe-header",
      module_map_id: null,
      image_sha256: module?.sha256 ?? null,
    };
    return ok({ ref, moduleMapId: null, va });
  }
}

// ================================================================ live leg
const F32 = new DataView(new ArrayBuffer(4));
const f32Of = (hex: string): number => {
  F32.setUint32(0, Number(BigInt(hex) & 0xffff_ffffn), true);
  return F32.getFloat32(0, true);
};
const bitsOf = (v: number): Hex => {
  F32.setFloat32(0, v, true);
  return formatHex(F32.getUint32(0, true));
};

/**
 * OracleCallPort fake computing the fake bridge's behaviours (keyed by the target RVA in `functions`), so live and
 * emulation legs agree unless a test makes them differ; records a real bea.call.oracle record and a function-called
 * effect in the (fake) evidence runtime.
 */
export class FakeOracle implements OracleCallPort {
  readonly calls: OracleBatchRequest[] = [];
  constructor(
    private readonly deps: {
      readonly evidence: EvidenceRuntime;
      readonly instance: PiId;
      /** module-relative rva ("0x1000") -> behaviour */
      readonly functions: Readonly<Record<string, string>>;
      readonly steal?: boolean;
    },
  ) {}

  async callPlanBatch(
    session: LiveSession,
    req: OracleBatchRequest,
    op: OperationContext,
  ): Promise<Result<OracleBatchResult, BeaError>> {
    this.calls.push(req);
    const behaviour = this.deps.functions[req.target.rva ?? ""] ?? "first";
    const count = req.vectors.count;
    const raw: { -readonly [K in keyof RawBatchColumns]: RawBatchColumns[K] } = {
      completed: count,
      status: [],
      rax: [],
      xmm0lo: [],
      out: {},
      mxcsrOut: [],
      fpcwOut: [],
    };
    const faults: { index: number; type: string; module: string | null; rva: Hex | null }[] = [];
    for (let i = 0; i < count; i++) {
      const lanes = req.plan.slots.map((slot) =>
        slot.source.kind === "column"
          ? String((req.vectors.columns[slot.source.column] as Hex[] | undefined)?.[i] ?? "0x0")
          : slot.source.kind === "const"
            ? formatHex(slot.source.bits)
            : "0x0",
      );
      let status: StatusCode = "ok";
      let rax: Hex = "0x0";
      let xmm: Hex = "0x0";
      if (behaviour === "sum_f32") {
        const sum = req.plan.slots.reduce(
          (acc, slot, k) => (slot.reg.startsWith("xmm") ? Math.fround(acc + f32Of(lanes[k] ?? "0x0")) : acc),
          0,
        );
        xmm = bitsOf(sum);
      } else if (behaviour === "fault_if_zero" && BigInt(lanes[0] ?? "0x0") === 0n) {
        status = "fault";
        faults.push({ index: req.offset + i, type: "access-violation", module: req.target.module, rva: "0x1010" });
      } else if (behaviour === "plus_one_f32") xmm = bitsOf(Math.fround(f32Of(lanes[0] ?? "0x0") + 1));
      else {
        rax = (lanes[0] ?? "0x0") as Hex;
        xmm = (lanes[0] ?? "0x0") as Hex;
      }
      raw.status.push(status);
      raw.rax.push(rax);
      raw.xmm0lo.push(xmm);
      raw.mxcsrOut.push("0x1f80");
      raw.fpcwOut.push("0x27f");
    }
    const layout =
      (req as OracleBatchRequest & { outLayout?: ReturnType<typeof rawOutLayout> }).outLayout ?? rawOutLayout(req.plan);
    const outcome = decodeOutcome(req.plan, raw, req.offset, layout, faults);
    const literals = this.deps.evidence.literals(undefined);
    if (!literals.ok) return literals;
    const effect = await this.deps.evidence.effects.apply({
      instance_id: this.deps.instance,
      kind: "function-called",
      target: {
        address: { va: req.target.va, module_map_id: null, module_key: req.target.module, rva: req.target.rva },
        size: null,
        threads: null,
      },
      parameters: { vectors: count },
      applied_by: op.name,
      literals: literals.value,
    });
    if (!effect.ok) return effect;
    const capture = this.deps.evidence.instances.capture(this.deps.instance);
    const recorded = await this.deps.evidence.recorder.record({
      predicate_type: "bea.call.oracle",
      operation: op.name,
      input: { vectors_digest: req.vectors.digest, offset: req.offset, nonce: randomUUID() },
      subject: { kind: "process-instance", instance_id: this.deps.instance },
      capture,
      provider: { id: "frida", name: "frida", version: null },
      result: { completed: count },
      coverage: { status: "complete", truncated: false, reasons: [] },
      effects: [effect.value.effect_id as FxId],
      literals: literals.value,
    });
    if (!recorded.ok) return recorded;
    void session;
    return ok({
      outcome,
      completed: count,
      nextOffset: null,
      lostTarget: false,
      evidence_id: recorded.value.record.evidence_id as EvId,
      effect_id: effect.value.effect_id as FxId,
      coverageBlob: null,
      exceptionModel: this.deps.steal === true ? "steal" : "seh-frame",
      calleeExceptions: 0,
    });
  }
}

/** A running owned (or attached) live session whose agent answers readMemory and captureThreadState. */
export const fakeLiveSession = (
  id: string,
  instance: PiId,
  options: { readonly ownership?: "owned" | "attached"; readonly memory?: Uint8Array } = {},
): LiveSession => {
  const memory = options.memory ?? new Uint8Array(0);
  const agent = {
    health: { state: "ok" as const },
    call: async (method: string, params: Record<string, unknown>) => {
      if (method === "readMemory") {
        const size = Number(params["size"]);
        const data = Buffer.alloc(size);
        Buffer.from(memory).copy(data, 0, 0, Math.min(size, memory.length));
        return ok({
          value: {
            address: params["address"],
            requested: size,
            returned: size,
            complete: true,
            stop: null,
            bea_guard_suspended: [],
          },
          data,
        });
      }
      if (method === "captureThreadState")
        return ok({
          tid: params["tid"],
          registers: {},
          eflags: "0x202",
          mxcsr: "0x9fc0",
          fpcw: "0x37f",
          xmm: null,
          teb: null,
          peb: null,
          stack: null,
          tls: null,
        });
      return err({
        _tag: "CapabilityUnavailable",
        operation: method,
        capability: "agent",
        reason: "not-implemented",
        retryable: false,
      } as BeaError);
    },
  };
  return {
    id,
    kind: "live",
    ownership: options.ownership ?? "owned",
    state: "running",
    instanceId: instance,
    identity: { image: { path: "C:\\lab\\live_fixture.exe" } },
    agent,
    liveness: () => ({ state: "alive", basis: "jobhost" }),
  } as unknown as LiveSession;
};
