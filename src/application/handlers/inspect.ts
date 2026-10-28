import type { INSPECT_TOOLS } from "../../contracts/areas/inspect.js";
import type { BeaApplication } from "../BeaApplication.js";
import type { HandlersFor } from "../handlerContext.js";
import { disassemble } from "../inspect/disassemble.js";
import { listMemoryRanges } from "../inspect/listMemoryRanges.js";
import { listModules } from "../inspect/listModules.js";
import { listThreads } from "../inspect/listThreads.js";
import { readMemory } from "../inspect/readMemory.js";

/**
 * Handlers for area inspect (WP-INSPECT). Each delegates to its service in src/application/inspect/, which reaches
 * the session only through sessionAccess (liveOp / anySessionOp) and records one evidence line per call.
 */
export const createInspectHandlers = (app: BeaApplication): HandlersFor<typeof INSPECT_TOOLS> => ({
  list_modules: (input, ctx) => listModules(app, input, ctx),
  list_memory_ranges: (input, ctx) => listMemoryRanges(app, input, ctx),
  list_threads: (input, ctx) => listThreads(app, input, ctx),
  read_memory: (input, ctx) => readMemory(app, input, ctx),
  disassemble: (input, ctx) => disassemble(app, input, ctx),
});
