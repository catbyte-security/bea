import type { WATCH_TOOLS } from "../../contracts/areas/watch.js";
import type { BeaApplication } from "../BeaApplication.js";
import type { HandlersFor } from "../handlerContext.js";
import { exportCoverage } from "../watch/ExportCoverage.js";
import { traceExecution } from "../watch/TraceService.js";
import { watchMemory } from "../watch/WatchService.js";

/** Handlers for area watch (WP9-WATCH): sessions are reached only through sessionAccess.ts (D-INT-40). */
export const createWatchHandlers = (app: BeaApplication): HandlersFor<typeof WATCH_TOOLS> => ({
  watch_memory: (input, ctx) => watchMemory(app, input, ctx),
  trace_execution: (input, ctx) => traceExecution(app, input, ctx),
  export_coverage: (input, ctx) => exportCoverage(app, input, ctx),
});
