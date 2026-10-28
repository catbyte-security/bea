import type { SCAN_TOOLS } from "../../contracts/areas/scan.js";
import type { BeaApplication } from "../BeaApplication.js";
import type { HandlersFor } from "../handlerContext.js";
import { createHitStore } from "../scans/scanHitStore.js";
import { ScanService } from "../scans/ScanService.js";
import { scanMemory, scanNext, scanResults, type ScanToolDeps } from "../scans/scanTools.js";

/**
 * Handlers for area scan (WP10-SCAN). The ScanService is created once per application (handler factories may run
 * more than once for one app in tests) and registers the `scan` HandleKindSpec there (CI-B6, §9.1 rule 9).
 */
const perApp = new WeakMap<BeaApplication, ScanToolDeps>();

/** The run directory for the host hit store; null while the evidence runtime is not available (day-0 fakes). */
const runDirOf = (app: BeaApplication): string | null => {
  try {
    const dir: unknown = app.services.evidence.run.dir;
    return typeof dir === "string" ? dir : null;
  } catch {
    return null;
  }
};

export const scanToolDeps = (app: BeaApplication): ScanToolDeps => {
  let deps = perApp.get(app);
  if (deps === undefined) {
    const store = createHitStore(() => runDirOf(app));
    const service = new ScanService({
      clock: app.clock,
      ids: app.ids,
      sessions: app.services.sessions,
      handles: app.services.handles,
      store,
      logger: app.logger.child({ area: "scan" }),
    });
    deps = { app, service, store };
    perApp.set(app, deps);
  }
  return deps;
};

export const createScanHandlers = (app: BeaApplication): HandlersFor<typeof SCAN_TOOLS> => {
  const deps = scanToolDeps(app);
  return {
    scan_memory: (input, ctx) => scanMemory(deps, input, ctx),
    scan_next: (input, ctx) => scanNext(deps, input, ctx),
    scan_results: (input, ctx) => scanResults(deps, input, ctx),
  };
};
