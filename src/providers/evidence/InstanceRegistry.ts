import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { basename, win32 } from "node:path";

import type { Clock, SequenceAllocator } from "../../domain/clock.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { cancelled, referenceNotFound } from "../../domain/errors/constructors.js";
import { COMPLETE } from "../../domain/evidence/coverage.js";
import { LIMITATIONS } from "../../domain/evidence/limitations.js";
import type { EvId, MmId, PiId, RunId } from "../../domain/ids.js";
import type { JsonObject, JsonValue } from "../../domain/json.js";
import {
  instanceIdOf,
  pathDigest,
  type ExitInfo,
  type ProcessIdentity,
  type ProcessInstance,
} from "../../domain/process/instance.js";
import { textContainsLiteral } from "../../domain/redaction/redact.js";
import { err, ok, type Result } from "../../domain/result.js";
import type {
  AnchorCapture,
  InstanceObservation,
  InstanceRegistry,
  Recorder,
  SensitiveLiterals,
} from "../../ports/evidence.js";
import type { LedgerEffectRegistry } from "./EffectRegistry.js";
import { fileError, internalError } from "./errors.js";
import type { Ledger } from "./Ledger.js";
import type { LedgerIndex } from "./LedgerIndex.js";
import type { EpochModuleMapTracker } from "./ModuleMapTracker.js";

/** Live process instances (S2 §4): identity → `pi_`, anchors, state snapshots recorded as bea.process.instance. */
export interface InstanceDeps {
  readonly runId: RunId;
  readonly clock: Clock;
  readonly seq: SequenceAllocator;
  readonly platform: "win32" | "linux";
  readonly ledger: Ledger;
  readonly index: LedgerIndex;
  readonly recorder: () => Recorder;
  readonly modules: EpochModuleMapTracker;
  readonly effects: LedgerEffectRegistry;
  readonly serverLiterals: () => SensitiveLiterals;
}

interface Live {
  instance: ProcessInstance;
  readonly path: string;
  readonly containment: JsonObject | null;
  readonly literals: SensitiveLiterals;
  hash: Promise<Result<string, BeaError>> | undefined;
}

export class LedgerInstanceRegistry implements InstanceRegistry {
  readonly #live = new Map<PiId, Live>();

  constructor(private readonly deps: InstanceDeps) {}

  get(id: PiId): ProcessInstance | undefined {
    return this.#live.get(id)?.instance;
  }

  all(): readonly ProcessInstance[] {
    return [...this.#live.values()].map((l) => l.instance);
  }

  /** Anchor at `epoch` (module-map materialization and ordinary captures share it). */
  captureAt(id: PiId, epoch: number, moduleMapId: MmId): AnchorCapture {
    const perturbation = this.deps.effects.perturbation(id);
    return {
      anchor: {
        run_id: this.deps.runId,
        seq: this.deps.seq.next(),
        mono_ns: this.deps.clock.monoNs().toString(),
        wall: this.deps.clock.wallIso(),
        effect_epoch: this.deps.effects.epoch(id),
        module_map_epoch: epoch,
      },
      module_map_id: moduleMapId,
      perturbation,
      tainted_count: perturbation.tainted_by.length,
    };
  }

  /** seq + epochs + perturbation; call inside the session's exclusive section right after the agent RPC. */
  capture(id: PiId): AnchorCapture {
    const current = this.deps.modules.current(id);
    if (current === undefined) throw internalError("evidence.capture", "capture of an unregistered instance");
    return this.captureAt(id, current.epoch, current.map().module_map_id);
  }

  async register(
    obs: InstanceObservation,
  ): Promise<Result<{ readonly instance: ProcessInstance; readonly evidence_id: EvId }, BeaError>> {
    const identity: ProcessIdentity = {
      t: "bea.pi/1",
      device_id: obs.device_id,
      pid: obs.pid,
      start_time: { source: obs.start_time.source, value: obs.start_time.value },
      image_path_sha256: pathDigest(obs.main_module_path, this.deps.platform),
    };
    const instance_id = instanceIdOf(identity);
    const literals = obs.literals;
    const hidden = (text: string): string | null => (textContainsLiteral(text, literals) ? null : text);
    const name = this.deps.platform === "win32" ? win32.basename(obs.main_module_path) : basename(obs.main_module_path);
    const instance: ProcessInstance = {
      instance_id,
      identity,
      ownership: obs.ownership,
      image: {
        display: { path: hidden(obs.main_module_path), name: hidden(name) },
        sha256: null,
        file: null,
        pe: null,
      },
      environment: obs.environment,
      agent: obs.agent,
      launch: obs.launch ?? null,
      state: obs.ownership === "owned" ? "suspended" : "running",
      exit: null,
    };
    const previous = this.#live.get(instance_id);
    this.#live.set(instance_id, {
      instance,
      path: obs.main_module_path,
      containment: obs.containment ?? null,
      literals,
      hash: previous?.hash,
    });
    if (!this.deps.index.instances.has(instance_id)) {
      const appended = await this.deps.ledger.append(
        {
          t: "pi",
          instance_id,
          identity,
          ownership: obs.ownership,
          display: { image_name: instance.image.display.name },
        },
        { operation: "evidence.instances" },
      );
      if (!appended.ok) return appended;
      this.deps.index.addInstance({
        instance_id,
        identity,
        ownership: obs.ownership,
        image_name: instance.image.display.name,
        ref: appended.value,
        origin: { kind: "local" },
      });
    }
    this.deps.modules.apply(instance_id, { op: "snapshot", ...obs.initial_modules });
    const limitations = [...(obs.limitations ?? [])];
    if (obs.start_time.source !== "os-creation-time") limitations.push(LIMITATIONS.PID_REUSE_UNEXCLUDED);
    const recorded = await this.#snapshot(instance_id, "register", limitations, false);
    return recorded.ok ? ok({ instance, evidence_id: recorded.value }) : recorded;
  }

  async #snapshot(
    id: PiId,
    operation: string,
    limitations: readonly string[],
    lifecycle: boolean,
  ): Promise<Result<EvId, BeaError>> {
    const live = this.#live.get(id);
    if (live === undefined) return err(referenceNotFound(operation, "evidence", id));
    const i = live.instance;
    const result: JsonObject = {
      pid: i.identity.pid,
      ownership: i.ownership,
      state: i.state,
      start_time: { ...i.identity.start_time },
      image: { name: i.image.display.name, path: live.path, sha256: i.image.sha256 },
      environment: { ...i.environment },
      launch: i.launch === null ? null : ({ ...i.launch } as JsonObject),
      containment: live.containment,
      exit: i.exit === null ? null : ({ ...i.exit } as unknown as JsonValue),
    };
    const recorded = await this.deps.recorder().record(
      {
        predicate_type: "bea.process.instance",
        operation:
          operation === "register" ? (i.ownership === "owned" ? "spawn_process" : "attach_process") : operation,
        input: { pid: i.identity.pid },
        subject: { kind: "process-instance", instance_id: id },
        capture: this.capture(id),
        provider: { id: "frida", name: "frida", version: null },
        agent: i.agent,
        result,
        coverage: COMPLETE,
        limitations,
        literals: live.literals,
      },
      { lifecycle },
    );
    return recorded.ok ? ok(recorded.value.record.evidence_id) : recorded;
  }

  async update(
    id: PiId,
    change: { readonly state?: ProcessInstance["state"]; readonly exit?: ExitInfo | null },
  ): Promise<Result<void, BeaError>> {
    const live = this.#live.get(id);
    if (live === undefined) return err(referenceNotFound("evidence.instances", "evidence", id));
    if (change.state !== undefined) live.instance.state = change.state;
    if (change.exit !== undefined) live.instance.exit = change.exit;
    const recorded = await this.#snapshot(id, "session_status", [], true);
    return recorded.ok ? ok(undefined) : recorded;
  }

  hashImage(id: PiId, signal?: AbortSignal): Promise<Result<string, BeaError>> {
    const live = this.#live.get(id);
    if (live === undefined) return Promise.resolve(err(referenceNotFound("evidence.hashImage", "evidence", id)));
    live.hash ??= (async (): Promise<Result<string, BeaError>> => {
      try {
        const hash = createHash("sha256");
        for await (const chunk of createReadStream(live.path)) {
          if (signal?.aborted === true) return err(cancelled("evidence.hashImage", "signal"));
          hash.update(chunk as Buffer);
        }
        const sha256 = hash.digest("hex");
        live.instance = { ...live.instance, image: { ...live.instance.image, sha256 } };
        return ok(sha256);
      } catch (cause) {
        return err(fileError("evidence.hashImage", "read", live.path, cause));
      }
    })();
    const task = live.hash;
    void task.then((r) => {
      if (!r.ok && live.hash === task) live.hash = undefined;
    });
    return task;
  }
}
