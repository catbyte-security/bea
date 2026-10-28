import type { IdSource } from "../domain/canonical.js";
import type { Clock, SequenceAllocator } from "../domain/clock.js";
import type { BeaConfig } from "../domain/config.js";
import type { Logger } from "../domain/logger.js";
import type { Admission } from "./admission.js";
import type { DoctorRegistry } from "./doctor.js";
import type { GateEvaluator } from "./handlerContext.js";
import type { Lifecycle } from "./lifecycle.js";
import type { BeaServices } from "./services/index.js";
import type { StatusRegistry } from "./status.js";

export interface RunInfo {
  readonly runId: string;
  readonly startedAt: string;
  readonly transport: "stdio" | "http" | "cli";
  readonly pid: number;
}

/** S1-owned core every service and handler receives. */
export interface BeaCore {
  readonly config: BeaConfig;
  readonly run: RunInfo;
  readonly clock: Clock;
  readonly ids: IdSource;
  readonly seq: SequenceAllocator;
  readonly logger: Logger;
  readonly lifecycle: Lifecycle;
  readonly admission: Admission;
  readonly gates: GateEvaluator;
  readonly status: StatusRegistry;
  /** runtime-registered doctor checks (WP0 addition; see src/application/doctor.ts) */
  readonly doctor: DoctorRegistry;
}

export interface BeaApplication extends BeaCore {
  readonly services: BeaServices;
}
