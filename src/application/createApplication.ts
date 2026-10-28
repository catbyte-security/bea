import { systemIdSource, type IdSource } from "../domain/canonical.js";
import { SequenceAllocator, systemClock, type Clock } from "../domain/clock.js";
import type { BeaConfig } from "../domain/config.js";
import type { Logger } from "../domain/logger.js";
import { Admission } from "./admission.js";
import { DoctorRegistry } from "./doctor.js";
import type { BeaApplication, BeaCore, RunInfo } from "./BeaApplication.js";
import type { BeaServices } from "./services/index.js";
import { createGateEvaluator } from "./gatePolicy.js";
import { Lifecycle } from "./lifecycle.js";
import { StatusRegistry } from "./status.js";

export interface CreateApplicationInput {
  readonly config: BeaConfig;
  readonly logger: Logger;
  readonly transport: RunInfo["transport"];
  readonly clock?: Clock;
  readonly ids?: IdSource;
  /**
   * Area services. Production passes composeServices (src/main/composeServices.ts,
   * pre-wired); tests pass fakes. Factories register lifecycle closers and status contributors.
   */
  readonly services: (core: BeaCore) => Promise<BeaServices>;
}

/** Composition root shared by MCP (one per process) and CLI (one per command). Never imports frida. */
export const createApplication = async (input: CreateApplicationInput): Promise<BeaApplication> => {
  const clock = input.clock ?? systemClock;
  const ids = input.ids ?? systemIdSource;
  const lifecycle = new Lifecycle(clock, input.logger);
  const core: BeaCore = {
    config: input.config,
    run: { runId: ids.runId(new Date()), startedAt: clock.wallIso(), transport: input.transport, pid: process.pid },
    clock,
    ids,
    seq: new SequenceAllocator(),
    logger: input.logger,
    lifecycle,
    admission: new Admission(lifecycle),
    gates: createGateEvaluator(input.config),
    status: new StatusRegistry(input.logger),
    doctor: new DoctorRegistry(),
  };
  return { ...core, services: await input.services(core) };
};
