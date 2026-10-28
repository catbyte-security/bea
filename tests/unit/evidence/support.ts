import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { SequenceAllocator, systemClock, type Clock } from "../../../src/domain/clock.js";
import { sequentialIdSource } from "../../../src/domain/canonical.js";
import { loadConfig, type BeaConfig } from "../../../src/domain/config.js";
import { COMPLETE } from "../../../src/domain/evidence/coverage.js";
import type { PiId, RunId } from "../../../src/domain/ids.js";
import { silentLogger } from "../../../src/domain/logger.js";
import type { HostPlatform } from "../../../src/domain/paths.js";
import { NO_LITERALS } from "../../../src/domain/redaction/literals.js";
import type { EvidenceDraft, InstanceObservation } from "../../../src/ports/evidence.js";
import { LedgerEvidenceRuntime } from "../../../src/providers/evidence/EvidenceRuntimeImpl.js";
import type { RunKind } from "../../../src/providers/evidence/RunStore.js";
import { createTempHome, type TempHome } from "../../support/workspace/tempHome.js";

/** WP1 test support: a real LedgerEvidenceRuntime on a throwaway BEA_HOME. */
export interface RuntimeFixture {
  readonly runtime: LedgerEvidenceRuntime;
  readonly home: TempHome;
  readonly config: BeaConfig;
  readonly runId: RunId;
  readonly seq: SequenceAllocator;
  /** a second runtime (new run) on the same home */
  readonly another: (kind?: RunKind) => LedgerEvidenceRuntime;
  readonly cleanup: () => Promise<void>;
}

export const AGENT = { bundle_sha256: "a".repeat(64), bea_version: "0.1.0", runtime: "qjs" } as const;

export const makeRuntime = async (
  options: { readonly env?: Readonly<Record<string, string>>; readonly clock?: Clock; readonly home?: TempHome } = {},
): Promise<RuntimeFixture> => {
  const home = options.home ?? (await createTempHome("evid"));
  const loaded = await loadConfig({
    env: { BEA_HOME: home.beaHome, ...options.env },
    platform: process.platform as HostPlatform,
    accountHome: home.home,
    readConfigFile: async () => null,
  });
  if (!loaded.ok) throw new Error(JSON.stringify(loaded.error));
  const ids = sequentialIdSource();
  const make = (
    kind: RunKind = "mcp-stdio",
  ): { runtime: LedgerEvidenceRuntime; runId: RunId; seq: SequenceAllocator } => {
    const runId = ids.runId(new Date()) as RunId;
    const seq = new SequenceAllocator();
    const runtime = new LedgerEvidenceRuntime({
      config: loaded.value,
      runId,
      kind,
      startedWall: new Date().toISOString(),
      clock: options.clock ?? systemClock,
      seq,
      logger: silentLogger,
    });
    return { runtime, runId, seq };
  };
  const first = make();
  const others: LedgerEvidenceRuntime[] = [];
  return {
    runtime: first.runtime,
    home,
    config: loaded.value,
    runId: first.runId,
    seq: first.seq,
    another: (kind) => {
      const next = make(kind).runtime;
      others.push(next);
      return next;
    },
    cleanup: async () => {
      await Promise.allSettled([first.runtime, ...others].map((r) => r.finalize("shutdown")));
      if (options.home === undefined) await home.cleanup();
    },
  };
};

export const observation = async (home: TempHome, pid = 4242, name = "game_sim.exe"): Promise<InstanceObservation> => {
  const path = join(home.work, name);
  await writeFile(path, `MZ fake image for ${name}`);
  return {
    device_id: "local",
    pid,
    ownership: "owned",
    start_time: { source: "os-creation-time", value: "133000000000000000" },
    main_module_path: path,
    agent: AGENT,
    environment: { platform: "win32", os_version: "10.0.26200", arch: "x64", pointer_size: 8 },
    initial_modules: {
      epoch: 1,
      modules: [
        { name, base: "0x140000000", size: 0x20000, path },
        { name: "ntdll.dll", base: "0x7ffc00000000", size: 0x1f0000, path: "C:\\Windows\\System32\\ntdll.dll" },
      ],
    },
    literals: NO_LITERALS,
  };
};

/** A live observation draft (read_memory-like) about `instance`. */
export const readDraft = (
  runtime: LedgerEvidenceRuntime,
  instance: PiId,
  data = "554889e5",
  extra: Partial<EvidenceDraft<{ readonly data: string; readonly note: string }>> = {},
): EvidenceDraft<{ readonly data: string; readonly note: string }> => ({
  predicate_type: "bea.memory.read",
  operation: "read_memory",
  input: { session_id: "00000000-0000-4000-8000-000000000001", address: "0x140001000", size: data.length / 2 },
  subject: { kind: "process-instance", instance_id: instance },
  capture: runtime.instances.capture(instance),
  provider: { id: "frida", name: "frida", version: "17.23.2" },
  agent: AGENT,
  result: { data, note: "plain" },
  coverage: COMPLETE,
  literals: NO_LITERALS,
  ...extra,
});
