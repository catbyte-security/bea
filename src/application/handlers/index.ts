import type { TOOL_CONTRACTS } from "../../contracts/index.js";
import type { BeaApplication } from "../BeaApplication.js";
import type { HandlersFor } from "../handlerContext.js";
import { createAddressHandlers } from "./address.js";
import { createBehaviorHandlers } from "./behavior.js";
import { createCallHandlers } from "./call.js";
import { createDumpHandlers } from "./dump.js";
import { createEmulationHandlers } from "./emulation.js";
import { createEvidenceHandlers } from "./evidence.js";
import { createInspectHandlers } from "./inspect.js";
import { createInstrumentHandlers } from "./instrument.js";
import { createModifyHandlers } from "./modify.js";
import { createScanHandlers } from "./scan.js";
import { createSessionHandlers } from "./sessions.js";
import { createWatchHandlers } from "./watch.js";

/** Exhaustive: a contract without a handler is a compile error here. */
export type HandlerTable = HandlersFor<typeof TOOL_CONTRACTS>;

/** PRE-WIRED REGISTRY: areas fill their own factory; nobody edits this file. */
export const createToolHandlers = (app: BeaApplication): HandlerTable => ({
  ...createSessionHandlers(app),
  ...createInspectHandlers(app),
  ...createAddressHandlers(app),
  ...createScanHandlers(app),
  ...createInstrumentHandlers(app),
  ...createBehaviorHandlers(app),
  ...createWatchHandlers(app),
  ...createCallHandlers(app),
  ...createModifyHandlers(app),
  ...createDumpHandlers(app),
  ...createEmulationHandlers(app),
  ...createEvidenceHandlers(app),
});
