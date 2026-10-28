import type { BEHAVIOR_TOOLS } from "../../contracts/areas/behavior.js";
import type { BeaApplication } from "../BeaApplication.js";
import { traceApi } from "../behavior/TraceApiService.js";
import type { HandlersFor } from "../handlerContext.js";

/** Handlers for area behavior (WP-BEHAVIOR): trace_api. */
export const createBehaviorHandlers = (app: BeaApplication): HandlersFor<typeof BEHAVIOR_TOOLS> => ({
  trace_api: (input, ctx) => traceApi(app, input, ctx),
});
