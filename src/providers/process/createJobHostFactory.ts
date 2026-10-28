import type { BeaCore } from "../../application/BeaApplication.js";
import type { JobHostFactory } from "../../ports/jobhost.js";
import { JobHostService, type JobHostFactoryDeps } from "./JobHostService.js";

export type { JobHostFactoryDeps } from "./JobHostService.js";

/**
 * WP-PROC service factory (composeServices calls it with `{}`). Contract: synchronous-cheap construction, no target
 * contact, no frida import, no helper spawn and no file access (all lazy); it registers the shutdown backstop closer,
 * the `jobhost` status row and, on Windows, the doctor checks `jobhost:binary`, `jobhost:probe` and `host:elevation`
 * (DESIGN §5.2, §5.8, CI-I7). Tests pass `deps` to point at a snapshot's helper or to inject a fake launcher.
 */
export const createJobHostFactory = (core: BeaCore, deps: JobHostFactoryDeps = {}): JobHostFactory => {
  const service = new JobHostService(core, deps);
  core.lifecycle.register({
    name: "jobhost:helpers",
    phase: "teardown-targets",
    close: (signal) => service.closeAll(signal),
  });
  core.status.add({ name: "jobhost", backends: async () => [await service.statusRow()] });
  if ((deps.platform ?? core.config.platform) === "win32") {
    core.doctor.add({ name: "jobhost:binary", scope: "backend:frida", run: (signal) => service.checkBinary(signal) });
    core.doctor.add({ name: "jobhost:probe", scope: "backend:frida", run: (signal) => service.checkProbe(signal) });
    core.doctor.add({
      name: "host:elevation",
      scope: "informational",
      run: (signal) => service.checkElevation(signal),
    });
  }
  return service;
};
