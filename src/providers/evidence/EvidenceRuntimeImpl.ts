import { readFileSync } from "node:fs";

import type { Clock, SequenceAllocator } from "../../domain/clock.js";
import type { BeaConfig } from "../../domain/config.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { inputError } from "../../domain/errors/constructors.js";
import type { AddressRef } from "../../domain/address/addressRef.js";
import type { Location } from "../../domain/evidence/record.js";
import type { PiId, RunId } from "../../domain/ids.js";
import type { Logger } from "../../domain/logger.js";
import { NO_LITERALS, parseLiteralsFile, sensitiveLiterals } from "../../domain/redaction/literals.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { Coverage } from "../../domain/evidence/coverage.js";
import type { JsonObject } from "../../domain/json.js";
import type { EvidenceRuntime, EvidenceStatus, RecordedEvidence, SensitiveLiterals } from "../../ports/evidence.js";
import { BEA_VERSION } from "../../application/evidence/version.js";
import { FileBlobStore } from "./BlobStore.js";
import { LedgerBundleService } from "./Bundle.js";
import { LedgerEffectRegistry } from "./EffectRegistry.js";
import { internalError } from "./errors.js";
import { LedgerEvidenceQuery } from "./EvidenceQuery.js";
import { LedgerInstanceRegistry } from "./InstanceRegistry.js";
import { finalizeScope, Ledger } from "./Ledger.js";
import { LedgerIndex } from "./LedgerIndex.js";
import { EpochModuleMapTracker } from "./ModuleMapTracker.js";
import { QuotaGuard, quotaLimitsOf } from "./Quotas.js";
import { EvidenceRecorder } from "./Recorder.js";
import { RunStore, type RunKind } from "./RunStore.js";
import { FileStreamStore } from "./StreamStore.js";
import { LedgerUnknownRegistry } from "./UnknownRegistry.js";

const MiB = 1024 * 1024;

export interface RuntimeOptions {
  readonly config: BeaConfig;
  readonly runId: RunId;
  readonly kind: RunKind;
  readonly startedWall: string;
  readonly clock: Clock;
  readonly seq: SequenceAllocator;
  readonly logger: Logger;
}

/**
 * One EvidenceRuntime per run (S2 §21.1). Construction touches nothing on disk (CI-M20): the run directory, lock,
 * run.json and the first ledger line are created by the first write. finalize() is fenced first (CT-M6).
 */
export class LedgerEvidenceRuntime implements EvidenceRuntime {
  readonly run: { readonly id: RunId; readonly dir: string; readonly kind: RunKind };
  readonly recorder: EvidenceRecorder;
  readonly instances: LedgerInstanceRegistry;
  readonly modules: EpochModuleMapTracker;
  readonly effects: LedgerEffectRegistry;
  readonly streams: FileStreamStore;
  readonly blobs: FileBlobStore;
  readonly unknowns: LedgerUnknownRegistry;
  readonly query: LedgerEvidenceQuery;
  readonly bundles: LedgerBundleService;
  readonly index = new LedgerIndex();
  readonly quotas: QuotaGuard;
  readonly ledger: Ledger;
  readonly store: RunStore;
  readonly #options: RuntimeOptions;
  #serverLiterals: Result<readonly string[], BeaError> | undefined;
  #serverSet: SensitiveLiterals | undefined;
  #finalized: Promise<Result<void, BeaError>> | undefined;

  constructor(options: RuntimeOptions) {
    this.#options = options;
    const platform = options.config.platform;
    this.quotas = new QuotaGuard(quotaLimitsOf(options.config));
    this.store = new RunStore({
      runId: options.runId,
      runsDir: options.config.layout.runsDir,
      kind: options.kind,
      beaVersion: BEA_VERSION,
      platform,
      startedWall: options.startedWall,
      quotas: this.quotas.limits,
    });
    const paths = this.store.paths;
    this.run = { id: options.runId, dir: paths.dir, kind: options.kind };
    this.ledger = new Ledger(paths.ledger, this.quotas, {
      prepare: () => this.store.create(),
      initial: () => [{ t: "run", run_id: options.runId, bea_version: BEA_VERSION, started_wall: options.startedWall }],
    });
    const ensureStarted = (): Promise<Result<void, BeaError>> => this.ledger.start("evidence.start");
    const serverLiterals = (): SensitiveLiterals => this.#server();
    const hostPlatform = platform === "win32" ? "win32" : "linux";
    this.blobs = new FileBlobStore({ blobs: paths.blobs, tmp: paths.tmp }, this.index, this.quotas, ensureStarted);
    this.recorder = new EvidenceRecorder({
      index: this.index,
      ledger: this.ledger,
      ensureModuleMap: (instance, epoch, operation) => this.modules.ensureRecorded(instance, epoch, operation),
    });
    this.effects = new LedgerEffectRegistry({
      runId: options.runId,
      clock: options.clock,
      seq: options.seq,
      ledger: this.ledger,
      index: this.index,
      blobs: this.blobs,
      logger: options.logger,
      moduleEpoch: (instance) => this.modules.current(instance)?.epoch ?? null,
    });
    this.modules = new EpochModuleMapTracker({
      platform: hostPlatform,
      ledger: this.ledger,
      index: this.index,
      recorder: () => this.recorder,
      captureAt: (instance, epoch, mm) => this.instances.captureAt(instance, epoch, mm),
      serverLiterals,
      agentOf: (instance) => this.instances.get(instance)?.agent ?? null,
    });
    this.instances = new LedgerInstanceRegistry({
      runId: options.runId,
      clock: options.clock,
      seq: options.seq,
      platform: hostPlatform,
      ledger: this.ledger,
      index: this.index,
      recorder: () => this.recorder,
      modules: this.modules,
      effects: this.effects,
      serverLiterals,
    });
    this.streams = new FileStreamStore({
      runId: options.runId,
      streamsDir: paths.streams,
      quotas: this.quotas,
      index: this.index,
      clock: options.clock,
      seq: options.seq,
      logger: options.logger,
      ensureStarted,
      epochs: (instance) =>
        instance === null || this.modules.current(instance) === undefined
          ? { effect_epoch: null, module_map_epoch: null }
          : {
              effect_epoch: this.effects.epoch(instance),
              module_map_epoch: this.modules.current(instance)?.epoch ?? 0,
            },
      concurrentEffects: (instance, from, to, exclude) => this.effects.concurrent(instance, from, to, exclude),
      recordManifest: (spec, result, facts) => this.#recordManifest(spec.source.instance_id, result, facts),
      syncLedger: () => this.ledger.sync(),
    });
    this.unknowns = new LedgerUnknownRegistry({
      runId: options.runId,
      ledger: this.ledger,
      index: this.index,
      recorder: () => this.recorder,
      serverLiterals,
    });
    this.query = new LedgerEvidenceQuery({
      index: this.index,
      ledger: this.ledger,
      blobs: this.blobs,
      instances: this.instances,
    });
    this.bundles = new LedgerBundleService({
      runId: options.runId,
      beaVersion: BEA_VERSION,
      clock: options.clock,
      logger: options.logger,
      tmpDir: paths.tmp,
      index: this.index,
      ledger: this.ledger,
      blobs: this.blobs,
      streams: this.streams,
      quotas: this.quotas,
      ensureStarted,
    });
  }

  async #recordManifest(
    instance: PiId | null,
    result: JsonObject,
    facts: { readonly coverage: Coverage; readonly limitations: readonly string[]; readonly lifecycle: boolean },
  ): Promise<Result<RecordedEvidence<JsonObject>, BeaError>> {
    if (instance === null || this.modules.current(instance) === undefined)
      return err({
        _tag: "InvalidState",
        operation: "stream_manifest",
        state: "host-stream",
        expected: ["instance-bound stream"],
        message: "Host row streams have no bea.stream.manifest evidence; their chunks are sealed and hash-chained.",
      });
    return this.recorder.record(
      {
        predicate_type: "bea.stream.manifest",
        operation: "stream_manifest",
        input: { stream_id: result["stream_id"] ?? null },
        subject: { kind: "process-instance", instance_id: instance },
        capture: this.instances.capture(instance),
        provider: { id: "frida", name: "frida", version: null },
        agent: this.instances.get(instance)?.agent ?? null,
        result,
        coverage: facts.coverage,
        limitations: facts.limitations,
        literals: NO_LITERALS,
      },
      { lifecycle: facts.lifecycle },
    );
  }

  #loadServerLiterals(): Result<readonly string[], BeaError> {
    const setting = this.#options.config.sensitiveValuesFile;
    if (setting.value === null) return ok([]);
    try {
      const parsed = parseLiteralsFile(readFileSync(setting.value, "utf8"));
      return parsed.ok
        ? parsed
        : err({
            _tag: "ConfigurationError",
            operation: "evidence.literals",
            settings: [
              {
                setting: "sensitive_values_file",
                constraint: parsed.error,
                source: setting.source === "env" ? "env" : "config-file",
              },
            ],
          });
    } catch (cause) {
      return err({
        _tag: "ConfigurationError",
        operation: "evidence.literals",
        settings: [
          {
            setting: "sensitive_values_file",
            constraint: "the file could not be read",
            source: setting.source === "env" ? "env" : "config-file",
          },
        ],
        cause,
      });
    }
  }

  #server(): SensitiveLiterals {
    if (this.#serverSet === undefined) {
      this.#serverLiterals ??= this.#loadServerLiterals();
      const built = this.#serverLiterals.ok ? sensitiveLiterals(undefined, this.#serverLiterals.value) : undefined;
      if (!this.#serverLiterals.ok)
        this.#options.logger.warn("sensitive values file unusable; tools that need literals will refuse", {});
      this.#serverSet = built?.ok === true ? built.value : NO_LITERALS;
    }
    return this.#serverSet;
  }

  literals(perCall: readonly string[] | undefined): Result<SensitiveLiterals, BeaError> {
    this.#serverLiterals ??= this.#loadServerLiterals();
    if (!this.#serverLiterals.ok) return this.#serverLiterals;
    const built = sensitiveLiterals(perCall, this.#serverLiterals.value);
    return built.ok ? built : err(inputError("evidence.literals", built.error));
  }

  locationOf(ref: AddressRef, size?: number): Location {
    return {
      kind: "address",
      va: ref.va,
      size: size ?? null,
      module_map_id: ref.module_map_id,
      module_key: ref.module === null ? null : ref.module.toLowerCase().slice(0, 260),
      rva: ref.rva,
      image_sha256: ref.image_sha256 ?? null,
    };
  }

  status(): EvidenceStatus {
    const usage = this.quotas.usage;
    const limits = this.quotas.limits;
    return {
      run_id: this.run.id,
      home: this.#options.config.home.value,
      usage: {
        ledger: { bytes: usage.ledger, quota: limits.ledgerBytes, reserve: limits.ledgerReserveBytes },
        blobs: { bytes: usage.blobs, quota: limits.blobBytes },
        streams: {
          bytes: usage.streams,
          quota_total: limits.streamTotalBytes,
          per_stream_quota: limits.streamBytes,
          live: this.streams.live().length,
        },
      },
      counts: {
        evidence: this.index.rows.length,
        effects_active: this.effects.instances().reduce((n, id) => n + this.effects.active(id).length, 0),
        unknowns_open: [...this.index.unknowns.values()].filter(
          (u) => u.revisions.at(-1)?.revision.status !== "resolved",
        ).length,
        instances: this.index.instances.size,
      },
    };
  }

  /** CI-M17: the bea_status `storage` row (MiB rounded up so any use shows as ≥ 1). */
  storageStatus(): {
    readonly run_dir: string;
    readonly usage_mb: { readonly ledger: number; readonly streams: number; readonly blobs: number };
  } {
    const usage = this.quotas.usage;
    const mb = (bytes: number): number => Math.ceil(bytes / MiB);
    return {
      run_dir: this.run.dir,
      usage_mb: { ledger: mb(usage.ledger), streams: mb(usage.streams), blobs: mb(usage.blobs) },
    };
  }

  finalize(reason: "shutdown" | "cli-exit"): Promise<Result<void, BeaError>> {
    this.#finalized ??= finalizeScope.run(true, () => this.#finalize(reason));
    return this.#finalized;
  }

  async #finalize(reason: "shutdown" | "cli-exit"): Promise<Result<void, BeaError>> {
    this.ledger.fence();
    if (!this.ledger.started) {
      await this.ledger.close();
      return ok(undefined);
    }
    let failure: BeaError | undefined;
    for (const writer of this.streams.live()) {
      const ended = await writer.end("server-shutdown");
      if (!ended.ok && ended.error._tag !== "InvalidState") failure ??= ended.error;
    }
    for (const instance of this.effects.instances()) await this.effects.endAll(instance, "server-shutdown");
    const endedWall = this.#options.clock.wallIso();
    const counts = {
      lines: this.ledger.lines,
      evidence: this.index.rows.length,
      effects: this.index.effects.size,
      unknowns: this.index.unknowns.size,
      instances: this.index.instances.size,
      late_appends: this.ledger.lateAppends,
    };
    const end = await this.ledger.append(
      { t: "end", ended_wall: endedWall, counts },
      { operation: "evidence.finalize", lifecycle: true, privileged: true },
    );
    if (!end.ok) failure ??= end.error;
    try {
      await this.ledger.sync();
      await this.blobs.syncFresh();
      await this.store.close(
        {
          ledger_bytes: this.ledger.bytes,
          lines: this.ledger.lines,
          evidence: this.index.rows.length,
          effects: this.index.effects.size,
          blobs: this.index.blobs.size,
          blob_bytes: this.quotas.usage.blobs,
          streams: this.index.streams.size,
          late_appends: this.ledger.lateAppends,
        },
        endedWall,
      );
    } catch (cause) {
      failure ??= internalError("evidence.finalize", "run close failed", cause);
    } finally {
      await this.ledger.close();
    }
    this.#options.logger.info("evidence finalized", {
      reason,
      late_appends: this.ledger.lateAppends,
      ok: failure === undefined,
    });
    return failure === undefined ? ok(undefined) : err(failure);
  }
}
