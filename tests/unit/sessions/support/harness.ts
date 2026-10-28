import { SessionEvidenceSink } from "../../../../src/application/sessions/SessionEvidenceSink.js";
import { notImplementedPort } from "../../../../src/application/notImplemented.js";
import { sequentialIdSource } from "../../../../src/domain/canonical.js";
import { systemClock } from "../../../../src/domain/clock.js";
import type { BeaConfig } from "../../../../src/domain/config.js";
import { Deadline } from "../../../../src/domain/deadline.js";
import type { BeaError } from "../../../../src/domain/errors/beaError.js";
import { silentLogger } from "../../../../src/domain/logger.js";
import { ok, type Result } from "../../../../src/domain/result.js";
import type { AddressService } from "../../../../src/ports/address.js";
import type { OperationContext, SessionObservation, SpawnInput } from "../../../../src/ports/sessions.js";
import { FridaHost } from "../../../../src/providers/frida/FridaHost.js";
import { hostLimitsFrom, type HostLimits } from "../../../../src/providers/frida/hostLimits.js";
import type { PeHeaderFacts } from "../../../../src/providers/frida/peHeader.js";
import { SessionManager } from "../../../../src/providers/frida/SessionManager.js";
import { FakeFrida, FakeJobHostFactory } from "../../../support/frida/fakeFrida.js";
import { FakeEvidence, FakeRecordings } from "./fakeEvidence.js";

/**
 * A SessionManager over the fake Frida binding, the fake jobhost, the local fake evidence runtime and recordings
 * (S3 §21 fast lane). Everything is real except the boundaries: admission, queues, startup paths, the agent channel,
 * the RPC client, the stream binder, crash protocol, close and closeAll.
 */
export interface Harness {
  readonly fake: FakeFrida;
  readonly jobhost: FakeJobHostFactory;
  readonly evidence: FakeEvidence;
  readonly recordings: FakeRecordings;
  readonly sink: SessionEvidenceSink;
  readonly host: FridaHost;
  readonly manager: SessionManager;
  readonly limits: HostLimits;
  readonly lifecycle: AbortController;
  readonly pe: Map<string, Result<PeHeaderFacts, BeaError>>;
  readonly neighbourhood: Map<string, readonly string[]>;
  /** an op admitted directly through the manager */
  run<T>(
    name: string,
    fn: (op: OperationContext) => Promise<Result<T, BeaError>>,
    options?: { readonly signal?: AbortSignal; readonly sessionId?: string; readonly timeoutMs?: number },
  ): Promise<Result<T, BeaError>>;
  spawn(
    input?: Partial<SpawnInput>,
    options?: { readonly signal?: AbortSignal },
  ): Promise<Result<SessionObservation, BeaError>>;
  attach(pid: number, options?: { readonly signal?: AbortSignal }): Promise<Result<SessionObservation, BeaError>>;
  closeAll(): ReturnType<SessionManager["closeAll"]>;
}

export const PROGRAM = "C:\\fixtures\\game_sim.exe";
const PE_OK: PeHeaderFacts = {
  machine: 0x8664,
  imageBase: "0x140000000",
  sizeOfImage: 0x40000,
  timeDateStamp: 1,
  fileSize: 4096,
  imports: ["KERNEL32.dll", "msvcrt.dll"],
  importsComplete: true,
  versionNames: [],
};

export interface HarnessOptions {
  readonly maxLiveSessions?: number;
  readonly policy?: Partial<ConstructorParameters<typeof SessionManager>[0]["policy"]>;
  readonly serverEnv?: Readonly<Record<string, string | undefined>>;
  readonly address?: AddressService;
  readonly limits?: (limits: HostLimits) => HostLimits;
  /** SEC-2: what a spawn cwd resolves to (default: every cwd is a local directory) */
  readonly inspectDirectory?: (path: string) => Promise<"directory" | "network" | "missing" | "not-directory">;
  /** LIFE-3: the directory Frida's first injection extracts into (default: the user's TEMP) */
  readonly fridaTempDir?: () => string | null;
  /** LIFE-5: the final path a program spelling resolves to (default: none, the spelling itself) */
  readonly realPath?: (path: string) => Promise<string | null>;
}

export const createHarness = (options: HarnessOptions = {}): Harness => {
  const fake = new FakeFrida();
  const jobhost = new FakeJobHostFactory(fake);
  const evidence = new FakeEvidence();
  const recordings = new FakeRecordings();
  const baseLimits = hostLimitsFrom({
    limits: {
      maxLiveSessions: { value: options.maxLiveSessions ?? 4, source: "default" },
      rpcDefaultTimeoutMs: { value: 10_000, source: "default" },
    },
  } as unknown as BeaConfig);
  const limits = options.limits?.(baseLimits) ?? baseLimits;
  const lifecycle = new AbortController();
  const host = new FridaHost({
    logger: silentLogger,
    loadModule: async () => fake.module(),
    loadAgentBundle: async () =>
      ok({
        source: "// fake agent bundle",
        sha256: "a".repeat(64),
        bytes: 20,
        protocol: "bea-agent/1",
        protocolMinor: 0,
        agentVersion: "0.1.0",
        buildId: fake.buildId,
        fridaVersion: "17.23.2",
        runtime: "qjs",
      }),
    now: () => systemClock.monoMs(),
    orphanOutputBytes: limits.capture.orphanOutputBytes,
    orphanOutputTtlMs: limits.capture.orphanOutputTtlMs,
  });
  const sink = new SessionEvidenceSink({ evidence, recordings, logger: silentLogger, fridaVersion: () => "17.23.2" });
  const pe = new Map<string, Result<PeHeaderFacts, BeaError>>();
  const neighbourhood = new Map<string, readonly string[]>();
  const manager = new SessionManager({
    host,
    jobhost,
    evidence,
    recordings,
    address: options.address ?? notImplementedPort<AddressService>("address"),
    sink,
    limits,
    logger: silentLogger,
    clock: systemClock,
    ids: sequentialIdSource(),
    lifecycleShutdown: lifecycle.signal,
    serverEnv: options.serverEnv ?? {
      SystemRoot: "C:\\Windows",
      PATH: "C:\\Windows",
      SECRET_TOKEN: "s3cret",
      BEA_HOME: "C:\\bea",
    },
    selfPid: process.pid,
    selfPpid: 1,
    hostPlatform: "win32",
    beaVersion: "0.1.0",
    gates: { writeMemory: false, overrideFunction: false, callAttached: false },
    policy: {
      envMode: "allowlist",
      allowInterpreters: false,
      allowAntiCheat: false,
      allowAntiCheatImages: [],
      allowSession0: false,
      extraDenylist: [],
      ...options.policy,
    },
    maxEmulationSessions: 4,
    files: {
      hashFile: async () => ({ sha256: "ab".repeat(32), size: 4096 }),
      listNeighbourhood: async (path) => neighbourhood.get(path) ?? ["game_sim.exe", "data"],
      readPe: async (path) => pe.get(path) ?? ok(PE_OK),
      ...(options.inspectDirectory === undefined ? {} : { inspectDirectory: options.inspectDirectory }),
      ...(options.fridaTempDir === undefined ? {} : { fridaTempDir: options.fridaTempDir }),
      ...(options.realPath === undefined ? {} : { realPath: options.realPath }),
    },
    systemRoot: "C:\\Windows",
  });
  const run: Harness["run"] = (name, fn, runOptions = {}) =>
    manager.admit(
      name,
      {
        ...(runOptions.signal === undefined ? {} : { signal: runOptions.signal }),
        ...(runOptions.sessionId === undefined ? {} : { sessionId: runOptions.sessionId }),
        timeoutMs: runOptions.timeoutMs ?? 30_000,
      },
      fn,
    );
  return {
    fake,
    jobhost,
    evidence,
    recordings,
    sink,
    host,
    manager,
    limits,
    lifecycle,
    pe,
    neighbourhood,
    run,
    spawn: (input = {}, spawnOptions = {}) =>
      run(
        "spawn_process",
        (op) =>
          manager.spawn(
            { program: PROGRAM, argv: [], captureOutput: true, resume: false, redactLiterals: [], env: {}, ...input },
            op,
          ),
        spawnOptions,
      ),
    attach: (pid, attachOptions = {}) =>
      run("attach_process", (op) => manager.attach({ pid, redactLiterals: [] }, op), attachOptions),
    closeAll: () => manager.closeAll("test", Deadline.after(1_300)),
  };
};

/** Test-spawned "foreign" process the attach tests target. */
export const addForeign = (
  h: Harness,
  pid: number,
  name = "game_sim.exe",
  extra: { readonly ppid?: number } = {},
): void =>
  h.fake.addProcess({
    pid,
    name,
    path: `C:\\games\\${name}`,
    ppid: extra.ppid ?? 77,
    started: "2026-10-28T09:00:00.000001Z",
    user: "me",
  });

export const errTag = <T>(result: Result<T, BeaError>): string => (result.ok ? "ok" : result.error._tag);

export const settle = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));
